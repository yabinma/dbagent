package gwserver

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/pem"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	tcwait "github.com/testcontainers/testcontainers-go/wait"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	rcaprobev1 "github.com/yabinma/dbagent/gen/go/rcaprobe/v1"
	"github.com/yabinma/dbagent/internal/bootstrapca"
	"github.com/yabinma/dbagent/services/probe-gateway/internal/registry"
)

// fakeProbe drives the client side of the Session bidi stream in tests
// (design.md Section 14.2: "Probes via in-process gRPC (bufconn)").
type fakeProbe struct {
	t        *testing.T
	stream   rcaprobev1.ProbeGateway_SessionClient
	received chan *rcaprobev1.GatewayMessage
}

func newFakeProbe(t *testing.T, client rcaprobev1.ProbeGatewayClient) *fakeProbe {
	t.Helper()
	stream, err := client.Session(context.Background())
	if err != nil {
		t.Fatalf("open session: %v", err)
	}
	fp := &fakeProbe{t: t, stream: stream, received: make(chan *rcaprobev1.GatewayMessage, 32)}
	go func() {
		for {
			msg, err := stream.Recv()
			if err != nil {
				close(fp.received)
				return
			}
			fp.received <- msg
		}
	}()
	return fp
}

func (fp *fakeProbe) register(platformKey string) {
	fp.t.Helper()
	if err := fp.stream.Send(&rcaprobev1.ProbeMessage{Msg: &rcaprobev1.ProbeMessage_Register{
		Register: &rcaprobev1.Register{PlatformKey: platformKey, ProbeVersion: "0.1.0"},
	}}); err != nil {
		fp.t.Fatalf("send register: %v", err)
	}
}

func (fp *fakeProbe) registerWithAuth(platformKey string, auth *rcaprobev1.AuthStatus) {
	fp.t.Helper()
	if err := fp.stream.Send(&rcaprobev1.ProbeMessage{Msg: &rcaprobev1.ProbeMessage_Register{
		Register: &rcaprobev1.Register{
			PlatformKey: platformKey, ProbeVersion: "0.1.0",
			Capabilities: &rcaprobev1.Capabilities{PlatformType: "presto", Deployment: "k8s", Auth: auth},
		},
	}}); err != nil {
		fp.t.Fatalf("send register: %v", err)
	}
}

func (fp *fakeProbe) heartbeat() {
	fp.t.Helper()
	if err := fp.stream.Send(&rcaprobev1.ProbeMessage{Msg: &rcaprobev1.ProbeMessage_Heartbeat{
		Heartbeat: &rcaprobev1.Heartbeat{Status: "ok"},
	}}); err != nil {
		fp.t.Fatalf("send heartbeat: %v", err)
	}
}

func (fp *fakeProbe) sendChunk(taskID string, seq uint32, data []byte, last bool) {
	fp.t.Helper()
	if err := fp.stream.Send(&rcaprobev1.ProbeMessage{Msg: &rcaprobev1.ProbeMessage_Chunk{
		Chunk: &rcaprobev1.TaskOutputChunk{TaskId: taskID, Seq: seq, Data: data, Last: last},
	}}); err != nil {
		fp.t.Fatalf("send chunk: %v", err)
	}
}

func (fp *fakeProbe) sendResult(taskID string, exitCode int32, chunkCount uint32) {
	fp.t.Helper()
	if err := fp.stream.Send(&rcaprobev1.ProbeMessage{Msg: &rcaprobev1.ProbeMessage_Result{
		Result: &rcaprobev1.TaskResult{TaskId: taskID, ExitCode: exitCode, ChunkCount: chunkCount},
	}}); err != nil {
		fp.t.Fatalf("send result: %v", err)
	}
}

func (fp *fakeProbe) expectAck(timeout time.Duration) *rcaprobev1.RegisterAck {
	fp.t.Helper()
	select {
	case msg := <-fp.received:
		ack := msg.GetAck()
		if ack == nil {
			fp.t.Fatalf("expected RegisterAck, got %+v", msg)
		}
		return ack
	case <-time.After(timeout):
		fp.t.Fatalf("timed out waiting for RegisterAck")
	}
	return nil
}

func (fp *fakeProbe) expectMessage(timeout time.Duration) *rcaprobev1.GatewayMessage {
	fp.t.Helper()
	select {
	case msg := <-fp.received:
		return msg
	case <-time.After(timeout):
		fp.t.Fatalf("timed out waiting for a message")
	}
	return nil
}

// testServer wires up a gwserver.Server behind a bufconn listener and
// returns a connected ProbeGatewayClient plus the Server/Registry for
// assertions.
func testServer(t *testing.T) (rcaprobev1.ProbeGatewayClient, *Server, registry.Registry) {
	t.Helper()
	reg := registry.NewFake()
	client, srv := testServerWithRegistry(t, reg)
	return client, srv, reg
}

// testServerWithRegistry is testServer with a caller-supplied Registry
// (used by F16 to pass a real *registry.PG so AuditDB can share reg.DB).
func testServerWithRegistry(t *testing.T, reg registry.Registry) (rcaprobev1.ProbeGatewayClient, *Server) {
	t.Helper()
	srv := New(reg, []byte("fake-signing-public-key-32-bytes"), "replica-1")
	srv.HeartbeatTimeout = 200 * time.Millisecond

	lis := bufconn.Listen(1024 * 1024)
	grpcServer := grpc.NewServer()
	rcaprobev1.RegisterProbeGatewayServer(grpcServer, srv)
	go func() { _ = grpcServer.Serve(lis) }()
	t.Cleanup(grpcServer.Stop)

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	return rcaprobev1.NewProbeGatewayClient(conn), srv
}

func seedPlatform(t *testing.T, reg registry.Registry, platformKey string) {
	t.Helper()
	// Idempotent: the composed F16 Python path may already have inserted this
	// key (f16-plat) before invoking the Go test (review C2). CreatePlatform
	// is a plain INSERT on PG and would PK-fail on the second seed.
	if _, err := reg.GetPlatform(context.Background(), platformKey); err == nil {
		return
	}
	if err := reg.CreatePlatform(context.Background(), registry.Platform{PlatformKey: platformKey}, "tok"); err != nil {
		// Lost a race or concurrent insert: treat "already present" as success.
		if _, gerr := reg.GetPlatform(context.Background(), platformKey); gerr == nil {
			return
		}
		t.Fatalf("seed platform: %v", err)
	}
}

func TestSession_RegisterSuccess(t *testing.T) {
	client, _, reg := testServer(t)
	seedPlatform(t, reg, "presto-us1")

	fp := newFakeProbe(t, client)
	fp.register("presto-us1")

	ack := fp.expectAck(2 * time.Second)
	if !ack.GetAccepted() {
		t.Fatalf("expected accepted=true, got %+v", ack)
	}
	if ack.GetProbeId() == "" {
		t.Fatalf("expected a probe_id")
	}
	if string(ack.GetSigningPublicKey()) != "fake-signing-public-key-32-bytes" {
		t.Fatalf("expected signing public key to be echoed in RegisterAck")
	}
}

func TestSession_RegisterFullAccessMarksPlatformOnline(t *testing.T) {
	client, _, reg := testServer(t)
	seedPlatform(t, reg, "presto-us1")
	fp := newFakeProbe(t, client)
	fp.registerWithAuth("presto-us1", &rcaprobev1.AuthStatus{Scheme: "NONE", Access: "full"})
	fp.expectAck(2 * time.Second)

	waitForCondition(t, 2*time.Second, func() bool {
		p, err := reg.GetPlatform(context.Background(), "presto-us1")
		return err == nil && p.Status == registry.PlatformOnline
	})
}

func TestSession_RegisterMissingCredentialsMarksPendingCredentials(t *testing.T) {
	client, _, reg := testServer(t)
	seedPlatform(t, reg, "presto-us1")
	fp := newFakeProbe(t, client)
	fp.registerWithAuth("presto-us1", &rcaprobev1.AuthStatus{
		Scheme: "PASSWORD", Access: "unauthenticated", Missing: []string{"credentials"},
	})
	fp.expectAck(2 * time.Second)

	waitForCondition(t, 2*time.Second, func() bool {
		p, err := reg.GetPlatform(context.Background(), "presto-us1")
		return err == nil && p.Status == registry.PlatformPendingCredentials
	})
}

func TestSession_RegisterUnsupportedAuthMarksDegraded(t *testing.T) {
	client, _, reg := testServer(t)
	seedPlatform(t, reg, "presto-us1")
	fp := newFakeProbe(t, client)
	fp.registerWithAuth("presto-us1", &rcaprobev1.AuthStatus{Scheme: "KERBEROS", Access: "unsupported"})
	fp.expectAck(2 * time.Second)

	waitForCondition(t, 2*time.Second, func() bool {
		p, err := reg.GetPlatform(context.Background(), "presto-us1")
		return err == nil && p.Status == registry.PlatformDegraded
	})
}

func TestSession_RegisterPersistsCapabilitiesOnProbe(t *testing.T) {
	client, _, reg := testServer(t)
	seedPlatform(t, reg, "presto-us1")
	fp := newFakeProbe(t, client)
	fp.registerWithAuth("presto-us1", &rcaprobev1.AuthStatus{Scheme: "NONE", Access: "full"})
	ack := fp.expectAck(2 * time.Second)

	waitForCondition(t, 2*time.Second, func() bool {
		p, err := reg.GetProbe(context.Background(), ack.GetProbeId())
		if err != nil {
			return false
		}
		return p.Capabilities["platform_type"] == "presto"
	})
}

func TestPlatformStatusFromAuth(t *testing.T) {
	cases := []struct {
		name string
		auth *rcaprobev1.AuthStatus
		want registry.PlatformStatus
	}{
		{"nil auth", nil, registry.PlatformDegraded},
		{"full access", &rcaprobev1.AuthStatus{Access: "full"}, registry.PlatformOnline},
		{"missing credentials", &rcaprobev1.AuthStatus{Access: "unauthenticated", Missing: []string{"credentials"}}, registry.PlatformPendingCredentials},
		{"missing tls_ca", &rcaprobev1.AuthStatus{Access: "unauthenticated", Missing: []string{"tls_ca"}}, registry.PlatformPendingCredentials},
		{"connectivity failure", &rcaprobev1.AuthStatus{Access: "unauthenticated", Missing: []string{"connectivity"}}, registry.PlatformDegraded},
		{"unsupported", &rcaprobev1.AuthStatus{Access: "unsupported"}, registry.PlatformDegraded},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := platformStatusFromAuth(c.auth)
			if got != c.want {
				t.Errorf("platformStatusFromAuth(%+v) = %s, want %s", c.auth, got, c.want)
			}
		})
	}
}

func TestCapabilitiesToMap(t *testing.T) {
	caps := &rcaprobev1.Capabilities{
		PlatformType: "presto", Deployment: "k8s", EngineVersion: "0.298",
		Tools:    []*rcaprobev1.ToolDescriptor{{Name: "presto_cluster_info", Category: "engine", ParamsSchemaJson: "{}"}},
		WriteOps: []string{"presto_kill_query"},
		Auth:     &rcaprobev1.AuthStatus{Scheme: "NONE", Access: "full"},
	}
	m := capabilitiesToMap(caps)
	if m["platform_type"] != "presto" || m["engine_version"] != "0.298" {
		t.Fatalf("unexpected map: %+v", m)
	}
	tools := m["tools"].([]map[string]any)
	if len(tools) != 1 || tools[0]["name"] != "presto_cluster_info" {
		t.Fatalf("unexpected tools: %+v", tools)
	}
}

func TestCapabilitiesToMap_Nil(t *testing.T) {
	m := capabilitiesToMap(nil)
	if len(m) != 0 {
		t.Fatalf("expected empty map for nil capabilities, got %+v", m)
	}
}

func TestSetSigningPublicKey_AffectsFutureRegisterAcks(t *testing.T) {
	client, srv, reg := testServer(t)
	seedPlatform(t, reg, "presto-us1")

	srv.SetSigningPublicKey([]byte("rotated-key-0123456789012345678"))

	fp := newFakeProbe(t, client)
	fp.register("presto-us1")
	ack := fp.expectAck(2 * time.Second)
	if string(ack.GetSigningPublicKey()) != "rotated-key-0123456789012345678" {
		t.Fatalf("expected rotated signing key in RegisterAck, got %q", ack.GetSigningPublicKey())
	}
}

func TestSession_UnknownPlatformRejected(t *testing.T) {
	client, _, _ := testServer(t)
	fp := newFakeProbe(t, client)
	fp.register("does-not-exist")

	ack := fp.expectAck(2 * time.Second)
	if ack.GetAccepted() {
		t.Fatalf("expected accepted=false for unknown platform")
	}
}

func TestSession_HeartbeatUpdatesRegistry(t *testing.T) {
	client, srv, reg := testServer(t)
	seedPlatform(t, reg, "presto-us1")
	fp := newFakeProbe(t, client)
	fp.register("presto-us1")
	ack := fp.expectAck(2 * time.Second)

	fp.heartbeat()
	waitForCondition(t, 2*time.Second, func() bool {
		p, err := reg.GetProbe(context.Background(), ack.GetProbeId())
		return err == nil && !p.LastHeartbeat.IsZero()
	})
	_ = srv
}

func TestDispatch_ReassemblesMultipleChunksInOrder(t *testing.T) {
	client, srv, reg := testServer(t)
	seedPlatform(t, reg, "presto-us1")
	fp := newFakeProbe(t, client)
	fp.register("presto-us1")
	fp.expectAck(2 * time.Second)
	waitForSession(t, srv, "presto-us1")

	go func() {
		msg := fp.expectMessage(2 * time.Second)
		task := msg.GetTask()
		if task == nil {
			t.Errorf("expected TaskRequest")
			return
		}
		fp.sendChunk(task.GetTaskId(), 1, []byte("world"), false) // out of order on purpose
		fp.sendChunk(task.GetTaskId(), 0, []byte("hello "), false)
		fp.sendResult(task.GetTaskId(), 0, 2)
	}()

	result, data, err := srv.Dispatch(context.Background(), "presto-us1", &rcaprobev1.TaskRequest{
		TaskId: "task-1", TimeoutSeconds: 5,
		Kind: &rcaprobev1.TaskRequest_Tool{Tool: &rcaprobev1.ToolCall{ToolName: "presto_cluster_info"}},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.GetExitCode() != 0 {
		t.Fatalf("unexpected result: %+v", result)
	}
	if string(data) != "hello world" {
		t.Fatalf("unexpected reassembled data: %q", data)
	}
}

func TestDispatch_ChunkCountMismatchIsSurfacedAsError(t *testing.T) {
	client, srv, reg := testServer(t)
	seedPlatform(t, reg, "presto-us1")
	fp := newFakeProbe(t, client)
	fp.register("presto-us1")
	fp.expectAck(2 * time.Second)
	waitForSession(t, srv, "presto-us1")

	go func() {
		msg := fp.expectMessage(2 * time.Second)
		task := msg.GetTask()
		fp.sendChunk(task.GetTaskId(), 0, []byte("only one"), true)
		fp.sendResult(task.GetTaskId(), 0, 2) // claims 2 chunks, only 1 sent
	}()

	_, _, err := srv.Dispatch(context.Background(), "presto-us1", &rcaprobev1.TaskRequest{
		TaskId: "task-2", TimeoutSeconds: 5,
		Kind: &rcaprobev1.TaskRequest_Tool{Tool: &rcaprobev1.ToolCall{ToolName: "x"}},
	})
	if err == nil {
		t.Fatalf("expected chunk integrity error")
	}
}

func TestDispatch_MissingChunkSeqIsSurfacedAsError(t *testing.T) {
	client, srv, reg := testServer(t)
	seedPlatform(t, reg, "presto-us1")
	fp := newFakeProbe(t, client)
	fp.register("presto-us1")
	fp.expectAck(2 * time.Second)
	waitForSession(t, srv, "presto-us1")

	go func() {
		msg := fp.expectMessage(2 * time.Second)
		task := msg.GetTask()
		fp.sendChunk(task.GetTaskId(), 0, []byte("a"), false)
		fp.sendChunk(task.GetTaskId(), 2, []byte("c"), true) // seq 1 missing
		fp.sendResult(task.GetTaskId(), 0, 2)
	}()

	_, _, err := srv.Dispatch(context.Background(), "presto-us1", &rcaprobev1.TaskRequest{
		TaskId: "task-3", TimeoutSeconds: 5,
		Kind: &rcaprobev1.TaskRequest_Tool{Tool: &rcaprobev1.ToolCall{ToolName: "x"}},
	})
	if err == nil {
		t.Fatalf("expected error for missing chunk seq")
	}
}

func TestDispatch_ProbeNotConnected(t *testing.T) {
	_, srv, _ := testServer(t)
	_, _, err := srv.Dispatch(context.Background(), "presto-nowhere", &rcaprobev1.TaskRequest{TaskId: "t1"})
	if err != ErrProbeNotConnected {
		t.Fatalf("expected ErrProbeNotConnected, got %v", err)
	}
}

func TestDispatch_TimesOutWhenProbeDoesNotReply(t *testing.T) {
	client, srv, reg := testServer(t)
	seedPlatform(t, reg, "presto-us1")
	fp := newFakeProbe(t, client)
	fp.register("presto-us1")
	fp.expectAck(2 * time.Second)
	waitForSession(t, srv, "presto-us1")

	_, _, err := srv.Dispatch(context.Background(), "presto-us1", &rcaprobev1.TaskRequest{
		TaskId: "task-timeout", TimeoutSeconds: 1,
		Kind: &rcaprobev1.TaskRequest_Tool{Tool: &rcaprobev1.ToolCall{ToolName: "x"}},
	})
	if err != ErrTaskTimeout {
		t.Fatalf("expected ErrTaskTimeout, got %v", err)
	}
}

func TestTaskRouting_ByPlatformKey(t *testing.T) {
	client, srv, reg := testServer(t)
	seedPlatform(t, reg, "presto-a")
	seedPlatform(t, reg, "presto-b")

	fpA := newFakeProbe(t, client)
	fpA.register("presto-a")
	fpA.expectAck(2 * time.Second)

	fpB := newFakeProbe(t, client)
	fpB.register("presto-b")
	fpB.expectAck(2 * time.Second)

	waitForSession(t, srv, "presto-a")
	waitForSession(t, srv, "presto-b")

	go func() {
		msg := fpA.expectMessage(2 * time.Second)
		task := msg.GetTask()
		fpA.sendChunk(task.GetTaskId(), 0, []byte("from-a"), true)
		fpA.sendResult(task.GetTaskId(), 0, 1)
	}()

	_, data, err := srv.Dispatch(context.Background(), "presto-a", &rcaprobev1.TaskRequest{
		TaskId: "task-route", TimeoutSeconds: 5,
		Kind: &rcaprobev1.TaskRequest_Tool{Tool: &rcaprobev1.ToolCall{ToolName: "x"}},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(data) != "from-a" {
		t.Fatalf("unexpected data: %q", data)
	}

	select {
	case msg := <-fpB.received:
		t.Fatalf("probe B should not have received a task, got %+v", msg)
	case <-time.After(200 * time.Millisecond):
	}
}

func TestCancelTask_DeliversCancelFrame(t *testing.T) {
	client, srv, reg := testServer(t)
	seedPlatform(t, reg, "presto-us1")
	fp := newFakeProbe(t, client)
	fp.register("presto-us1")
	fp.expectAck(2 * time.Second)
	waitForSession(t, srv, "presto-us1")

	if err := srv.CancelTask("presto-us1", "task-x"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	msg := fp.expectMessage(2 * time.Second)
	if msg.GetCancel() == nil || msg.GetCancel().GetTaskId() != "task-x" {
		t.Fatalf("expected CancelTask frame, got %+v", msg)
	}
}

func TestCancelTask_ProbeNotConnected(t *testing.T) {
	_, srv, _ := testServer(t)
	if err := srv.CancelTask("presto-nowhere", "task-x"); err != ErrProbeNotConnected {
		t.Fatalf("expected ErrProbeNotConnected, got %v", err)
	}
}

func TestManifestRefresh_SingleProbe(t *testing.T) {
	client, srv, reg := testServer(t)
	seedPlatform(t, reg, "presto-us1")
	fp := newFakeProbe(t, client)
	fp.register("presto-us1")
	fp.expectAck(2 * time.Second)
	waitForSession(t, srv, "presto-us1")

	if err := srv.RefreshManifest("presto-us1"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	msg := fp.expectMessage(2 * time.Second)
	if msg.GetRefresh() == nil {
		t.Fatalf("expected ManifestRefresh, got %+v", msg)
	}
}

func TestManifestRefresh_Broadcast(t *testing.T) {
	client, srv, reg := testServer(t)
	seedPlatform(t, reg, "presto-a")
	seedPlatform(t, reg, "presto-b")

	fpA := newFakeProbe(t, client)
	fpA.register("presto-a")
	fpA.expectAck(2 * time.Second)
	fpB := newFakeProbe(t, client)
	fpB.register("presto-b")
	fpB.expectAck(2 * time.Second)

	waitForSession(t, srv, "presto-a")
	waitForSession(t, srv, "presto-b")

	srv.BroadcastManifestRefresh()

	if fpA.expectMessage(2*time.Second).GetRefresh() == nil {
		t.Fatalf("expected probe A to receive ManifestRefresh")
	}
	if fpB.expectMessage(2*time.Second).GetRefresh() == nil {
		t.Fatalf("expected probe B to receive ManifestRefresh")
	}
}

func TestSession_DisconnectMarksProbeOfflineImmediately(t *testing.T) {
	client, srv, reg := testServer(t)
	seedPlatform(t, reg, "presto-us1")
	fp := newFakeProbe(t, client)
	fp.register("presto-us1")
	ack := fp.expectAck(2 * time.Second)
	waitForSession(t, srv, "presto-us1")

	// Simulate the probe's connection dropping (crash/network partition),
	// not a graceful stream close: cancel the client's stream context.
	if closer, ok := fp.stream.(interface{ CloseSend() error }); ok {
		_ = closer.CloseSend()
	}

	waitForCondition(t, 2*time.Second, func() bool {
		p, err := reg.GetProbe(context.Background(), ack.GetProbeId())
		return err == nil && p.Status == registry.ProbeOffline
	})
}

func TestCheckStaleProbes_MarksOfflineAfterTimeout(t *testing.T) {
	client, srv, reg := testServer(t)
	seedPlatform(t, reg, "presto-us1")
	fp := newFakeProbe(t, client)
	fp.register("presto-us1")
	ack := fp.expectAck(2 * time.Second)
	waitForSession(t, srv, "presto-us1")

	baseline := time.Now().UTC()
	srv.CheckStaleProbes(context.Background(), baseline) // fresh; should not mark offline
	p, _ := reg.GetProbe(context.Background(), ack.GetProbeId())
	if p.Status == registry.ProbeOffline {
		t.Fatalf("did not expect probe to be marked offline yet")
	}

	// Simulate 60s+ passing with no heartbeat by checking far in the future.
	future := baseline.Add(srv.HeartbeatTimeout + time.Second)
	srv.CheckStaleProbes(context.Background(), future)
	p, _ = reg.GetProbe(context.Background(), ack.GetProbeId())
	if p.Status != registry.ProbeOffline {
		t.Fatalf("expected probe to be marked offline after heartbeat timeout, got %s", p.Status)
	}
}

// --- design.md Section 8.4a: identity binding (required M3 fix) -------------------
//
// The tests above all use a plaintext bufconn connection (testServer),
// which carries no TLS peer info at all -- verifyClientCertCN() no-ops in
// that case (see its doc comment: the real Session listener always
// requires and verifies a client cert at the transport layer, so that
// case cannot occur in production). These tests instead stand up a real
// TLS-secured (RequireAndVerifyClientCert) bufconn listener, modeling
// production's tls.Config, to exercise the actual CN-binding check.

func issueClientCert(t *testing.T, ca *bootstrapca.CA, cn string) (certPEM, keyPEM []byte) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}, PublicKey: pub}, priv)
	if err != nil {
		t.Fatalf("create csr: %v", err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	certPEM, err = ca.SignCSR(csrPEM, cn)
	if err != nil {
		t.Fatalf("sign csr: %v", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM
}

// testServerMTLS is testServer's real-TLS counterpart: it wires up a
// gwserver.Server behind a bufconn listener secured exactly like
// production's runSessionListener (tls.RequireAndVerifyClientCert), and
// returns a dial function that connects using a given client cert/key
// pair instead of a single shared plaintext client.
func testServerMTLS(t *testing.T) (dial func(certPEM, keyPEM []byte) rcaprobev1.ProbeGatewayClient, srv *Server, reg registry.Registry, ca *bootstrapca.CA) {
	t.Helper()
	reg = registry.NewFake()
	srv = New(reg, []byte("fake-signing-public-key-32-bytes"), "replica-1")
	srv.HeartbeatTimeout = 200 * time.Millisecond

	dir := t.TempDir()
	var err error
	ca, err = bootstrapca.Bootstrap(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"))
	if err != nil {
		t.Fatalf("bootstrap ca: %v", err)
	}

	lis := bufconn.Listen(1024 * 1024)
	serverCert, err := ca.IssueServerCertificate([]string{"127.0.0.1"})
	if err != nil {
		t.Fatalf("issue server cert: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca.CACertPEM())
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
	}
	grpcServer := grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsConfig)))
	rcaprobev1.RegisterProbeGatewayServer(grpcServer, srv)
	go func() { _ = grpcServer.Serve(lis) }()
	t.Cleanup(grpcServer.Stop)

	dial = func(certPEM, keyPEM []byte) rcaprobev1.ProbeGatewayClient {
		t.Helper()
		clientCert, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			t.Fatalf("load client keypair: %v", err)
		}
		clientTLS := &tls.Config{Certificates: []tls.Certificate{clientCert}, RootCAs: pool, ServerName: "127.0.0.1"}
		conn, err := grpc.NewClient("passthrough:///bufnet",
			grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
			grpc.WithTransportCredentials(credentials.NewTLS(clientTLS)),
		)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		return rcaprobev1.NewProbeGatewayClient(conn)
	}
	return dial, srv, reg, ca
}

func TestSession_ClientCertCNMatchesPlatformKey_Accepted(t *testing.T) {
	dial, _, reg, ca := testServerMTLS(t)
	seedPlatform(t, reg, "presto-us1")
	certPEM, keyPEM := issueClientCert(t, ca, "presto-us1")

	fp := newFakeProbe(t, dial(certPEM, keyPEM))
	fp.register("presto-us1")

	ack := fp.expectAck(2 * time.Second)
	if !ack.GetAccepted() {
		t.Fatalf("expected accepted=true when cert CN matches platform_key, got %+v", ack)
	}
}

func TestSession_ClientCertCNMismatch_Rejected(t *testing.T) {
	dial, srv, reg, ca := testServerMTLS(t)
	seedPlatform(t, reg, "presto-a")
	seedPlatform(t, reg, "presto-b")

	// Certificate authenticates as presto-a; the Register frame claims
	// presto-b -- design.md Section 8.4a: "probe-gateway MUST reject a
	// Session registration whose Register.platform_key differs from the
	// CN of the verified client certificate."
	certPEM, keyPEM := issueClientCert(t, ca, "presto-a")
	fp := newFakeProbe(t, dial(certPEM, keyPEM))
	fp.register("presto-b")

	ack := fp.expectAck(2 * time.Second)
	if ack.GetAccepted() {
		t.Fatalf("expected accepted=false for a CN/platform_key mismatch")
	}
	if ack.GetReason() == "" {
		t.Fatalf("expected a clear rejection reason, got empty string")
	}

	// No session/probe row should have been created for the falsely-claimed platform.
	for _, k := range srv.ConnectedPlatforms() {
		if k == "presto-b" {
			t.Fatalf("expected presto-b to never become a connected session")
		}
	}
	if _, found, _ := reg.FindProbeByPlatform(context.Background(), "presto-b"); found {
		t.Fatalf("expected no probe to be registered for presto-b")
	}
}

func TestSession_ClientCertCNMismatch_DoesNotAffectClaimedPlatformStatus(t *testing.T) {
	dial, _, reg, ca := testServerMTLS(t)
	seedPlatform(t, reg, "presto-a")
	seedPlatform(t, reg, "presto-b")
	certPEM, keyPEM := issueClientCert(t, ca, "presto-a")

	fp := newFakeProbe(t, dial(certPEM, keyPEM))
	fp.registerWithAuth("presto-b", &rcaprobev1.AuthStatus{Scheme: "NONE", Access: "full"})
	fp.expectAck(2 * time.Second)

	time.Sleep(200 * time.Millisecond) // let any (incorrect) status update land, if it were going to
	p, err := reg.GetPlatform(context.Background(), "presto-b")
	if err != nil {
		t.Fatalf("get platform: %v", err)
	}
	if p.Status == registry.PlatformOnline {
		t.Fatalf("presto-b must not be marked online via a certificate issued for a different platform")
	}
}

func waitForCondition(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("condition not met within %s", timeout)
}

func waitForSession(t *testing.T, srv *Server, platformKey string) {
	t.Helper()
	waitForCondition(t, 2*time.Second, func() bool {
		for _, k := range srv.ConnectedPlatforms() {
			if k == platformKey {
				return true
			}
		}
		return false
	})
}

func TestEmitCredentialAudits_NilDBNoOp(t *testing.T) {
	s := New(registry.NewFake(), nil, "gw-0")
	// Must not panic with nil AuditDB.
	s.emitCredentialAudits(context.Background(), "pid", "pk", nil, &rcaprobev1.AuthStatus{
		Scheme: "PASSWORD", Access: "full",
	})
	s.emitCredentialAudits(context.Background(), "pid", "pk", nil, nil)
}

func TestEmitCredentialAudits_TransitionFromPrevCaps(t *testing.T) {
	s := New(registry.NewFake(), nil, "gw-0")
	// With nil DB still exercises transition parsing paths.
	prev := map[string]any{
		"auth": map[string]any{
			"scheme":  "PASSWORD",
			"access":  "unauthenticated",
			"missing": []any{"credentials"},
		},
	}
	s.emitCredentialAudits(context.Background(), "pid", "pk", prev, &rcaprobev1.AuthStatus{
		Scheme: "PASSWORD", Access: "full",
	})
	// missing as []string branch
	prev2 := map[string]any{
		"auth": map[string]any{
			"scheme":  "PASSWORD",
			"access":  "full",
			"missing": []string{},
		},
	}
	s.emitCredentialAudits(context.Background(), "pid", "pk", prev2, &rcaprobev1.AuthStatus{
		Scheme: "PASSWORD", Access: "full",
	})
}

func TestHandleMidSessionRegister(t *testing.T) {
	reg := registry.NewFake()
	seedPlatform(t, reg, "presto-us1")
	// Seed an existing probe so prevCaps path is hit.
	_ = reg.UpsertProbe(context.Background(), registry.Probe{
		ProbeID:     "probe-1",
		PlatformKey: "presto-us1",
		Capabilities: map[string]any{
			"auth": map[string]any{"scheme": "PASSWORD", "access": "unauthenticated", "missing": []any{"credentials"}},
		},
		Status: registry.ProbeOnline,
	})
	s := New(reg, nil, "gw-0")
	s.handleMidSessionRegister(context.Background(), "probe-1", "presto-us1", &rcaprobev1.Register{
		PlatformKey:  "presto-us1",
		ProbeVersion: "1.0",
		Capabilities: &rcaprobev1.Capabilities{
			PlatformType: "presto",
			Auth:         &rcaprobev1.AuthStatus{Scheme: "PASSWORD", Access: "full"},
		},
	})
	p, err := reg.GetPlatform(context.Background(), "presto-us1")
	if err != nil {
		t.Fatal(err)
	}
	if p.Status != registry.PlatformOnline {
		t.Fatalf("status=%s", p.Status)
	}
	// nil register is no-op
	s.handleMidSessionRegister(context.Background(), "probe-1", "presto-us1", nil)
}

func TestSession_MidSessionReRegisterUpdatesStatus(t *testing.T) {
	client, _, reg := testServer(t)
	seedPlatform(t, reg, "presto-us1")
	fp := newFakeProbe(t, client)
	fp.registerWithAuth("presto-us1", &rcaprobev1.AuthStatus{
		Scheme: "PASSWORD", Access: "unauthenticated", Missing: []string{"credentials"},
	})
	fp.expectAck(2 * time.Second)
	waitForCondition(t, 2*time.Second, func() bool {
		p, err := reg.GetPlatform(context.Background(), "presto-us1")
		return err == nil && p.Status == registry.PlatformPendingCredentials
	})
	// Mid-session re-register with full access (ManifestRefresh path).
	fp.registerWithAuth("presto-us1", &rcaprobev1.AuthStatus{Scheme: "PASSWORD", Access: "full"})
	waitForCondition(t, 2*time.Second, func() bool {
		p, err := reg.GetPlatform(context.Background(), "presto-us1")
		return err == nil && p.Status == registry.PlatformOnline
	})
}

func TestEmitCredentialAudits_WritesRows(t *testing.T) {
	if testing.Short() {
		t.Skip("docker")
	}
	// Reuse registry's migrated postgres helper pattern inline.
	ctx := context.Background()
	pgContainer, err := postgres.Run(ctx, "postgres:16-alpine",
		postgres.WithDatabase("dbagent"),
		postgres.WithUsername("dbagent"),
		postgres.WithPassword("dbagent"),
		testcontainers.WithWaitStrategy(
			tcwait.ForLog("database system is ready to accept connections").WithOccurrence(2).WithStartupTimeout(60*time.Second),
		),
	)
	if err != nil {
		t.Fatalf("pg: %v", err)
	}
	t.Cleanup(func() { _ = pgContainer.Terminate(ctx) })
	dsn, err := pgContainer.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	// migrate
	_, file, _, _ := runtime.Caller(0)
	repo := filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", "..", ".."))
	rca := filepath.Join(repo, "libs", "py", "rca_common")
	py := filepath.Join(rca, ".venv", "bin", "python")
	alembicDSN := strings.Replace(dsn, "postgres://", "postgresql+psycopg2://", 1)
	cmd := exec.Command(py, "-m", "alembic", "upgrade", "head")
	cmd.Dir = rca
	cmd.Env = append(os.Environ(), "DBAGENT_PG_DSN="+alembicDSN)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("migrate: %v\n%s", err, out)
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	s := New(registry.NewFake(), nil, "gw-0")
	s.AuditDB = db
	s.emitCredentialAudits(ctx, "probe-1", "pk1", nil, &rcaprobev1.AuthStatus{
		Scheme: "PASSWORD", Access: "full",
	})
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM audit_log WHERE action IN ('credentials_detected','credentials_verified')`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n < 2 {
		t.Fatalf("expected credentials_* rows, got %d", n)
	}
}

func TestReapStaleProbes_RunsOnce(t *testing.T) {
	s := New(registry.NewFake(), nil, "gw-0")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		s.ReapStaleProbes(ctx, 20*time.Millisecond)
		close(done)
	}()
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("reaper did not stop")
	}
}
