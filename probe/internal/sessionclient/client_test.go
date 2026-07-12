package sessionclient

import (
	"context"
	"encoding/json"
	"net"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	rcaprobev1 "github.com/yabinma/dbagent/gen/go/rcaprobe/v1"
	"github.com/yabinma/dbagent/probe/internal/platform"
)

// fakeGatewayServer is a minimal hand-rolled ProbeGatewayServer standing
// in for the real gwserver.Server (services/probe-gateway/internal/gwserver
// is not importable here -- Go internal-package boundaries, same
// reasoning as bootstrapclient_test.go). It records every ProbeMessage it
// receives and lets the test script GatewayMessages back.
type fakeGatewayServer struct {
	rcaprobev1.UnimplementedProbeGatewayServer
	received chan *rcaprobev1.ProbeMessage
	toSend   chan *rcaprobev1.GatewayMessage
}

func newFakeGatewayServer() *fakeGatewayServer {
	return &fakeGatewayServer{
		received: make(chan *rcaprobev1.ProbeMessage, 64),
		toSend:   make(chan *rcaprobev1.GatewayMessage, 64),
	}
}

func (s *fakeGatewayServer) Session(stream rcaprobev1.ProbeGateway_SessionServer) error {
	errCh := make(chan error, 2)
	go func() {
		for {
			msg, err := stream.Recv()
			if err != nil {
				errCh <- err
				return
			}
			s.received <- msg
		}
	}()
	go func() {
		for msg := range s.toSend {
			if err := stream.Send(msg); err != nil {
				errCh <- err
				return
			}
		}
	}()
	return <-errCh
}

func dialFakeGateway(t *testing.T, srv *fakeGatewayServer) rcaprobev1.ProbeGateway_SessionClient {
	t.Helper()
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

	stream, err := rcaprobev1.NewProbeGatewayClient(conn).Session(context.Background())
	if err != nil {
		t.Fatalf("open session: %v", err)
	}
	return stream
}

func expectFromGateway(t *testing.T, srv *fakeGatewayServer, timeout time.Duration) *rcaprobev1.ProbeMessage {
	t.Helper()
	select {
	case msg := <-srv.received:
		return msg
	case <-time.After(timeout):
		t.Fatalf("timed out waiting for a message from the probe")
	}
	return nil
}

func TestClient_RegistersAndReceivesAck(t *testing.T) {
	srv := newFakeGatewayServer()
	stream := dialFakeGateway(t, srv)

	adapter := &fakeAdapter{}
	client := New(stream, adapter, nil, "presto-us1", "0.1.0", false)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	runErr := make(chan error, 1)
	go func() { runErr <- client.Run(ctx) }()

	regMsg := expectFromGateway(t, srv, 2*time.Second)
	reg := regMsg.GetRegister()
	if reg == nil || reg.GetPlatformKey() != "presto-us1" {
		t.Fatalf("expected Register frame, got %+v", regMsg)
	}

	srv.toSend <- &rcaprobev1.GatewayMessage{Msg: &rcaprobev1.GatewayMessage_Ack{
		Ack: &rcaprobev1.RegisterAck{ProbeId: "probe-1", Accepted: true, SigningPublicKey: []byte("key")},
	}}

	// Give Run a moment to process the ack and store client state.
	time.Sleep(100 * time.Millisecond)
	client.mu.Lock()
	probeID := client.probeID
	client.mu.Unlock()
	if probeID != "probe-1" {
		t.Fatalf("expected probeID to be set from RegisterAck, got %q", probeID)
	}
}

func TestClient_RegistrationRejectedReturnsError(t *testing.T) {
	srv := newFakeGatewayServer()
	stream := dialFakeGateway(t, srv)
	adapter := &fakeAdapter{}
	client := New(stream, adapter, nil, "presto-us1", "0.1.0", false)

	runErr := make(chan error, 1)
	go func() { runErr <- client.Run(context.Background()) }()

	expectFromGateway(t, srv, 2*time.Second) // Register frame
	srv.toSend <- &rcaprobev1.GatewayMessage{Msg: &rcaprobev1.GatewayMessage_Ack{
		Ack: &rcaprobev1.RegisterAck{Accepted: false, Reason: "unknown platform_key"},
	}}

	select {
	case err := <-runErr:
		if err == nil {
			t.Fatalf("expected an error when registration is rejected")
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("expected Run to return promptly after rejection")
	}
}

func TestClient_SendsHeartbeats(t *testing.T) {
	srv := newFakeGatewayServer()
	stream := dialFakeGateway(t, srv)
	adapter := &fakeAdapter{}
	client := New(stream, adapter, nil, "presto-us1", "0.1.0", false)
	client.HeartbeatInterval = 50 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go client.Run(ctx)

	expectFromGateway(t, srv, 2*time.Second) // Register
	srv.toSend <- &rcaprobev1.GatewayMessage{Msg: &rcaprobev1.GatewayMessage_Ack{
		Ack: &rcaprobev1.RegisterAck{ProbeId: "probe-1", Accepted: true},
	}}

	msg := expectFromGateway(t, srv, 2*time.Second)
	if msg.GetHeartbeat() == nil {
		t.Fatalf("expected a heartbeat frame, got %+v", msg)
	}
}

func TestClient_DispatchesTaskAndSendsChunkedResult(t *testing.T) {
	srv := newFakeGatewayServer()
	stream := dialFakeGateway(t, srv)
	adapter := &fakeAdapter{executeResult: platform.ToolResult{Tool: "presto_cluster_info", Data: map[string]any{"version": "0.298"}}}
	client := New(stream, adapter, nil, "presto-us1", "0.1.0", false)
	client.HeartbeatInterval = time.Hour // avoid heartbeat noise in this test

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go client.Run(ctx)

	expectFromGateway(t, srv, 2*time.Second) // Register
	srv.toSend <- &rcaprobev1.GatewayMessage{Msg: &rcaprobev1.GatewayMessage_Ack{
		Ack: &rcaprobev1.RegisterAck{ProbeId: "probe-1", Accepted: true},
	}}

	srv.toSend <- &rcaprobev1.GatewayMessage{Msg: &rcaprobev1.GatewayMessage_Task{
		Task: &rcaprobev1.TaskRequest{
			TaskId: "task-1",
			Kind:   &rcaprobev1.TaskRequest_Tool{Tool: &rcaprobev1.ToolCall{ToolName: "presto_cluster_info"}},
		},
	}}

	chunkMsg := expectFromGateway(t, srv, 2*time.Second)
	chunk := chunkMsg.GetChunk()
	if chunk == nil || chunk.GetTaskId() != "task-1" || !chunk.GetLast() {
		t.Fatalf("expected a single last chunk, got %+v", chunkMsg)
	}

	resultMsg := expectFromGateway(t, srv, 2*time.Second)
	result := resultMsg.GetResult()
	if result == nil || result.GetTaskId() != "task-1" || result.GetChunkCount() != 1 {
		t.Fatalf("expected TaskResult with chunk_count=1, got %+v", resultMsg)
	}

	var decoded map[string]any
	if err := json.Unmarshal(chunk.GetData(), &decoded); err != nil {
		t.Fatalf("chunk data not valid JSON: %v", err)
	}
	if decoded["tool"] != "presto_cluster_info" {
		t.Fatalf("unexpected envelope: %+v", decoded)
	}
}

func TestClient_CancelTaskCancelsContext(t *testing.T) {
	srv := newFakeGatewayServer()
	stream := dialFakeGateway(t, srv)

	blockCh := make(chan struct{})
	adapter := &blockingAdapter{unblock: blockCh, sawCancel: make(chan struct{})}
	client := New(stream, adapter, nil, "presto-us1", "0.1.0", false)
	client.HeartbeatInterval = time.Hour

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go client.Run(ctx)

	expectFromGateway(t, srv, 2*time.Second) // Register
	srv.toSend <- &rcaprobev1.GatewayMessage{Msg: &rcaprobev1.GatewayMessage_Ack{
		Ack: &rcaprobev1.RegisterAck{ProbeId: "probe-1", Accepted: true},
	}}
	srv.toSend <- &rcaprobev1.GatewayMessage{Msg: &rcaprobev1.GatewayMessage_Task{
		Task: &rcaprobev1.TaskRequest{TaskId: "task-cancel", Kind: &rcaprobev1.TaskRequest_Tool{Tool: &rcaprobev1.ToolCall{ToolName: "x"}}},
	}}

	// Give the task handler a moment to register its cancel func.
	time.Sleep(100 * time.Millisecond)
	srv.toSend <- &rcaprobev1.GatewayMessage{Msg: &rcaprobev1.GatewayMessage_Cancel{
		Cancel: &rcaprobev1.CancelTask{TaskId: "task-cancel"},
	}}

	select {
	case <-adapter.sawCancel:
	case <-time.After(2 * time.Second):
		t.Fatalf("expected the task's context to be cancelled")
	}
	close(blockCh)
}

// blockingAdapter blocks in Execute until its context is cancelled, to
// test CancelTask delivery.
type blockingAdapter struct {
	fakeAdapter
	unblock   chan struct{}
	sawCancel chan struct{}
}

func (a *blockingAdapter) Execute(ctx context.Context, call platform.ToolCall) (platform.ToolResult, error) {
	select {
	case <-ctx.Done():
		close(a.sawCancel)
		return platform.ToolResult{}, ctx.Err()
	case <-a.unblock:
		return platform.ToolResult{}, nil
	}
}

func TestManifestToCapabilities_FullManifest(t *testing.T) {
	manifest := platform.Manifest{
		PlatformType:  "presto",
		Deployment:    "k8s",
		EngineVersion: "0.298",
		Tools: []platform.ToolDescriptor{
			{Name: "presto_cluster_info", ParamsSchemaJSON: "{}", Category: "engine"},
		},
		WriteOps: []string{"presto_kill_query"},
		Auth: platform.AuthStatus{
			Scheme: "PASSWORD", HTTPS: true, Access: "full", Missing: []string{"tls_ca"},
		},
	}
	caps := manifestToCapabilities(manifest)
	if caps.GetPlatformType() != "presto" || caps.GetDeployment() != "k8s" || caps.GetEngineVersion() != "0.298" {
		t.Fatalf("unexpected capabilities: %+v", caps)
	}
	if len(caps.GetTools()) != 1 || caps.GetTools()[0].GetName() != "presto_cluster_info" {
		t.Fatalf("unexpected tools: %+v", caps.GetTools())
	}
	if len(caps.GetWriteOps()) != 1 || caps.GetWriteOps()[0] != "presto_kill_query" {
		t.Fatalf("unexpected write_ops: %+v", caps.GetWriteOps())
	}
	if caps.GetAuth().GetScheme() != "PASSWORD" || !caps.GetAuth().GetHttps() || caps.GetAuth().GetAccess() != "full" {
		t.Fatalf("unexpected auth: %+v", caps.GetAuth())
	}
	if len(caps.GetAuth().GetMissing()) != 1 || caps.GetAuth().GetMissing()[0] != "tls_ca" {
		t.Fatalf("unexpected missing: %+v", caps.GetAuth().GetMissing())
	}
}

func TestClient_RefreshManifest_LogsDetectError(t *testing.T) {
	srv := newFakeGatewayServer()
	stream := dialFakeGateway(t, srv)
	adapter := &erroringDetectAdapter{}
	client := New(stream, adapter, nil, "presto-us1", "0.1.0", false)
	client.HeartbeatInterval = time.Hour

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go client.Run(ctx)

	expectFromGateway(t, srv, 2*time.Second) // Register (first Detect call, returns error -- Run should still proceed to send Register)
	srv.toSend <- &rcaprobev1.GatewayMessage{Msg: &rcaprobev1.GatewayMessage_Ack{
		Ack: &rcaprobev1.RegisterAck{ProbeId: "probe-1", Accepted: true},
	}}
	srv.toSend <- &rcaprobev1.GatewayMessage{Msg: &rcaprobev1.GatewayMessage_Refresh{Refresh: &rcaprobev1.ManifestRefresh{}}}

	// refreshManifest's error path just logs; the important assertion is
	// that it doesn't crash the client and Detect is invoked again.
	waitForCondition(t, 2*time.Second, func() bool { return adapter.detectCallsAtomic() >= 2 })
}

type erroringDetectAdapter struct {
	fakeAdapter
	mu    sync.Mutex
	calls int
}

func (a *erroringDetectAdapter) Detect(ctx context.Context, env platform.RuntimeEnv) (platform.Manifest, error) {
	a.mu.Lock()
	a.calls++
	n := a.calls
	a.mu.Unlock()
	if n == 1 {
		// Run()'s initial Detect must succeed so Register gets sent;
		// only the refresh-triggered re-Detect (call 2+) fails, to
		// exercise refreshManifest's error-logging path.
		return platform.Manifest{}, nil
	}
	return platform.Manifest{}, errBoom
}

func (a *erroringDetectAdapter) detectCallsAtomic() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.calls
}

func TestClient_ManifestRefreshReRunsDetect(t *testing.T) {
	srv := newFakeGatewayServer()
	stream := dialFakeGateway(t, srv)
	adapter := &countingDetectAdapter{}
	client := New(stream, adapter, nil, "presto-us1", "0.1.0", false)
	client.HeartbeatInterval = time.Hour

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go client.Run(ctx)

	expectFromGateway(t, srv, 2*time.Second) // Register
	srv.toSend <- &rcaprobev1.GatewayMessage{Msg: &rcaprobev1.GatewayMessage_Ack{
		Ack: &rcaprobev1.RegisterAck{ProbeId: "probe-1", Accepted: true},
	}}
	srv.toSend <- &rcaprobev1.GatewayMessage{Msg: &rcaprobev1.GatewayMessage_Refresh{Refresh: &rcaprobev1.ManifestRefresh{}}}

	waitForCondition(t, 2*time.Second, func() bool { return adapter.detectCalls() >= 2 })
}

type countingDetectAdapter struct {
	fakeAdapter
	calls int
	mu    sync.Mutex
}

func (a *countingDetectAdapter) Detect(ctx context.Context, env platform.RuntimeEnv) (platform.Manifest, error) {
	a.mu.Lock()
	a.calls++
	a.mu.Unlock()
	return platform.Manifest{}, nil
}

func (a *countingDetectAdapter) detectCalls() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.calls
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
