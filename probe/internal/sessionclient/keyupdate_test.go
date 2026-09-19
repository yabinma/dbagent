package sessionclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/structpb"

	rcaprobev1 "github.com/yabinma/dbagent/gen/go/rcaprobe/v1"
	"github.com/yabinma/dbagent/probe/internal/platform"
	"github.com/yabinma/dbagent/probe/internal/writeops"
)

func krKey(b byte) []byte { return bytes.Repeat([]byte{b}, ed25519.PublicKeySize) }

// recordingWriteAdapter records ExecuteWrite calls for key-rotation FPs.
type recordingWriteAdapter struct {
	fakeAdapter
	mu    sync.Mutex
	calls []platform.RemediationStep
}

func (a *recordingWriteAdapter) ExecuteWrite(ctx context.Context, step platform.RemediationStep) (platform.WriteResult, error) {
	a.mu.Lock()
	a.calls = append(a.calls, step)
	a.mu.Unlock()
	return platform.WriteResult{OK: true}, nil
}

func (a *recordingWriteAdapter) callCount() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.calls)
}

func waitRingCurrent(t *testing.T, store *writeops.KeyStore, want []byte, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if bytes.Equal(store.Ring().Current, want) {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("store Current never became expected key; got %v", store.Ring().Current)
}

func startClientWithAck(t *testing.T, store *writeops.KeyStore, firstKey []byte, writeEnabled bool, adapter platform.PlatformAdapter) (*Client, *fakeGatewayServer, context.CancelFunc) {
	t.Helper()
	srv := newFakeGatewayServer()
	stream := dialFakeGateway(t, srv)
	if adapter == nil {
		adapter = &fakeAdapter{}
	}
	client := New(stream, adapter, nil, "presto-us1", "0.1.0", writeEnabled, store)
	client.HeartbeatInterval = time.Hour // silence heartbeats unless a test overrides
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = client.Run(ctx) }()

	// Wait for Register, then send first ack.
	deadline := time.Now().Add(2 * time.Second)
	for {
		select {
		case msg := <-srv.received:
			if msg.GetRegister() != nil {
				srv.toSend <- &rcaprobev1.GatewayMessage{Msg: &rcaprobev1.GatewayMessage_Ack{
					Ack: &rcaprobev1.RegisterAck{
						ProbeId: "probe-1", Accepted: true, SigningPublicKey: firstKey,
					},
				}}
				if firstKey != nil {
					waitRingCurrent(t, store, firstKey, 2*time.Second)
				}
				return client, srv, cancel
			}
		case <-time.After(time.Until(deadline)):
			t.Fatal("timed out waiting for Register")
		}
	}
}

// FP-KR-6
func TestClient_InstallsKeyFromFirstRegisterAck(t *testing.T) {
	store := writeops.NewKeyStore(writeops.DefaultGraceWindow)
	a := krKey('a')
	client, _, cancel := startClientWithAck(t, store, a, false, nil)
	defer cancel()

	if client.KeyStore() != store {
		t.Fatal("client must hold the injected store pointer")
	}
	ring := store.Ring()
	if !bytes.Equal(ring.Current, a) {
		t.Fatalf("Current = %v, want A", ring.Current)
	}
	if ring.Previous != nil {
		t.Fatalf("Previous must be nil after first ack, got %v", ring.Previous)
	}
}

// FP-KR-7
func TestClient_MidSessionAckRotatesKeysWithoutDisturbingSession(t *testing.T) {
	store := writeops.NewKeyStore(writeops.DefaultGraceWindow)
	a, b, c := krKey('a'), krKey('b'), krKey('c')
	srv := newFakeGatewayServer()
	stream := dialFakeGateway(t, srv)
	client := New(stream, &fakeAdapter{}, nil, "presto-us1", "0.1.0", false, store)
	client.HeartbeatInterval = time.Hour
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runDone := make(chan error, 1)
	go func() { runDone <- client.Run(ctx) }()

	// Wait for Register, then send first ack with A.
	deadline := time.Now().Add(2 * time.Second)
	for {
		select {
		case msg := <-srv.received:
			if msg.GetRegister() != nil {
				srv.toSend <- &rcaprobev1.GatewayMessage{Msg: &rcaprobev1.GatewayMessage_Ack{
					Ack: &rcaprobev1.RegisterAck{
						ProbeId: "probe-1", Accepted: true, SigningPublicKey: a,
					},
				}}
				waitRingCurrent(t, store, a, 2*time.Second)
				goto running
			}
		case err := <-runDone:
			t.Fatalf("Client.Run returned before first ack: %v", err)
		case <-time.After(time.Until(deadline)):
			t.Fatal("timed out waiting for Register")
		}
	}
running:

	// Mid-session key update A→B.
	srv.toSend <- &rcaprobev1.GatewayMessage{Msg: &rcaprobev1.GatewayMessage_Ack{
		Ack: &rcaprobev1.RegisterAck{ProbeId: "probe-1", Accepted: true, SigningPublicKey: b},
	}}
	waitRingCurrent(t, store, b, 2*time.Second)

	ring := store.Ring()
	if !bytes.Equal(ring.Current, b) || !bytes.Equal(ring.Previous, a) {
		t.Fatalf("after mid-session update ring={%v,%v}", ring.Current, ring.Previous)
	}
	// Session still alive: client still points at same store; no second Register was sent
	// for the key update (readerLoop does not re-register).
	if client.KeyStore() != store {
		t.Fatal("store pointer changed mid-session")
	}
	select {
	case msg := <-srv.received:
		if msg.GetRegister() != nil {
			t.Fatalf("mid-session key update must not re-Register; got %+v", msg)
		}
	case <-time.After(50 * time.Millisecond):
		// expected silence for Register
	}

	// Subsequent frame after the key update must still be handled, and Run must
	// still be running (session not ended/restarted by the mid-session ack).
	srv.toSend <- &rcaprobev1.GatewayMessage{Msg: &rcaprobev1.GatewayMessage_Ack{
		Ack: &rcaprobev1.RegisterAck{ProbeId: "probe-1", Accepted: true, SigningPublicKey: c},
	}}
	waitRingCurrent(t, store, c, 2*time.Second)
	select {
	case err := <-runDone:
		t.Fatalf("Client.Run returned after mid-session key update (session must stay RUNNING): %v", err)
	default:
		// still running — contract satisfied
	}
}

// FP-KR-8
func TestClient_MidSessionAckIgnoredWhenRejectedOrForAnotherProbe(t *testing.T) {
	store := writeops.NewKeyStore(writeops.DefaultGraceWindow)
	a := krKey('a')
	_, srv, cancel := startClientWithAck(t, store, a, false, nil)
	defer cancel()

	// rejected
	srv.toSend <- &rcaprobev1.GatewayMessage{Msg: &rcaprobev1.GatewayMessage_Ack{
		Ack: &rcaprobev1.RegisterAck{ProbeId: "probe-1", Accepted: false, SigningPublicKey: krKey('b')},
	}}
	// foreign probe_id
	srv.toSend <- &rcaprobev1.GatewayMessage{Msg: &rcaprobev1.GatewayMessage_Ack{
		Ack: &rcaprobev1.RegisterAck{ProbeId: "other-probe", Accepted: true, SigningPublicKey: krKey('c')},
	}}
	time.Sleep(50 * time.Millisecond)

	ring := store.Ring()
	if !bytes.Equal(ring.Current, a) || ring.Previous != nil {
		t.Fatalf("store changed after ignored acks: {%v, %v}", ring.Current, ring.Previous)
	}
}

func signWriteStep(t *testing.T, priv ed25519.PrivateKey, executionID, playbookID string, stepIndex uint32, op string, params map[string]any) []byte {
	t.Helper()
	hash, err := writeops.CanonicalStepHash(executionID, playbookID, stepIndex, op, params)
	if err != nil {
		t.Fatalf("canonical hash: %v", err)
	}
	return ed25519.Sign(priv, hash)
}

func writeTask(executionID, playbookID string, stepIndex uint32, op string, params map[string]any, sig []byte) *rcaprobev1.TaskRequest {
	st, _ := structpb.NewStruct(params)
	return &rcaprobev1.TaskRequest{
		TaskId: "task-" + executionID,
		Kind: &rcaprobev1.TaskRequest_Write{
			Write: &rcaprobev1.RemediationStep{
				ExecutionId:           executionID,
				PlaybookId:            playbookID,
				StepIndex:             stepIndex,
				Op:                    op,
				Params:                st,
				ControlPlaneSignature: sig,
			},
		},
	}
}

// FP-KR-9
func TestClient_ExecutesWriteSignedWithRotatedKey(t *testing.T) {
	pubB, privB, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	store := writeops.NewKeyStore(writeops.DefaultGraceWindow)
	adapter := &recordingWriteAdapter{}
	client, srv, cancel := startClientWithAck(t, store, krKey('a'), true, adapter)
	defer cancel()

	srv.toSend <- &rcaprobev1.GatewayMessage{Msg: &rcaprobev1.GatewayMessage_Ack{
		Ack: &rcaprobev1.RegisterAck{ProbeId: "probe-1", Accepted: true, SigningPublicKey: pubB},
	}}
	waitRingCurrent(t, store, pubB, 2*time.Second)

	params := map[string]any{"query_id": "q-new"}
	sig := signWriteStep(t, privB, "exec-new", "pb", 0, "presto_kill_query", params)
	task := writeTask("exec-new", "pb", 0, "presto_kill_query", params, sig)

	// Drive through HandleTask with the live Ring so KeyMatched is asserted.
	ring := client.KeyStore().Ring()
	vr := writeops.VerifyStep(ring, true, "exec-new", "pb", 0, "presto_kill_query", params, sig)
	if !vr.OK || vr.KeyMatched != "current" {
		t.Fatalf("verify with new key: ok=%v matched=%q reason=%q", vr.OK, vr.KeyMatched, vr.Reason)
	}
	outcome := HandleTask(context.Background(), adapter, nil, ring, true, task)
	if outcome.ExitCode != 0 {
		t.Fatalf("execute write exit=%d err=%s", outcome.ExitCode, outcome.Error)
	}
	if adapter.callCount() != 1 {
		t.Fatalf("ExecuteWrite calls=%d want 1", adapter.callCount())
	}
}

// Shared FP-KR-10 / FP-KR-11 fixture: ONE deterministic key A, ONE byte-identical
// signed step, ONE signature. The only difference between the two named tests is
// whether A is still inside the grace window (design.md §9.6.7).
const (
	kr10kr11ExecID    = "exec-old"
	kr10kr11Playbook  = "pb"
	kr10kr11StepIndex = uint32(0)
	kr10kr11Op        = "presto_kill_query"
)

func kr10kr11Params() map[string]any {
	return map[string]any{"query_id": "q-old"}
}

// kr10kr11Keys returns deterministic ed25519 keypairs for A (signing) and B
// (rotation target). Seeds are fixed so both named tests share the same key A.
func kr10kr11Keys(t *testing.T) (pubA ed25519.PublicKey, privA ed25519.PrivateKey, pubB ed25519.PublicKey) {
	t.Helper()
	// Fixed seeds — not random — so FP-KR-10 and FP-KR-11 exercise identical key A.
	seedA := bytes.Repeat([]byte{0xa1}, ed25519.SeedSize)
	seedB := bytes.Repeat([]byte{0xb2}, ed25519.SeedSize)
	privA = ed25519.NewKeyFromSeed(seedA)
	pubA = privA.Public().(ed25519.PublicKey)
	privB := ed25519.NewKeyFromSeed(seedB)
	pubB = privB.Public().(ed25519.PublicKey)
	return pubA, privA, pubB
}

// kr10kr11SignedStep builds the single shared signed step used by FP-KR-10 and
// FP-KR-11. Both tests must pass the same params/sig bytes.
func kr10kr11SignedStep(t *testing.T, privA ed25519.PrivateKey) (params map[string]any, sig []byte) {
	t.Helper()
	params = kr10kr11Params()
	sig = signWriteStep(t, privA, kr10kr11ExecID, kr10kr11Playbook, kr10kr11StepIndex, kr10kr11Op, params)
	return params, sig
}

// FP-KR-10
func TestClient_AcceptsWriteSignedWithPreviousKeyInsideGrace(t *testing.T) {
	pubA, privA, pubB := kr10kr11Keys(t)
	// Long grace so "inside window" is structural.
	store := writeops.NewKeyStore(time.Hour)
	adapter := &recordingWriteAdapter{}
	client, srv, cancel := startClientWithAck(t, store, pubA, true, adapter)
	defer cancel()

	srv.toSend <- &rcaprobev1.GatewayMessage{Msg: &rcaprobev1.GatewayMessage_Ack{
		Ack: &rcaprobev1.RegisterAck{ProbeId: "probe-1", Accepted: true, SigningPublicKey: pubB},
	}}
	waitRingCurrent(t, store, pubB, 2*time.Second)

	params, sig := kr10kr11SignedStep(t, privA)
	ring := client.KeyStore().Ring()
	if ring.Previous == nil {
		t.Fatal("Previous must be present inside grace")
	}
	vr := writeops.VerifyStep(ring, true, kr10kr11ExecID, kr10kr11Playbook, kr10kr11StepIndex, kr10kr11Op, params, sig)
	if !vr.OK || vr.KeyMatched != "previous" {
		t.Fatalf("verify with old key inside grace: ok=%v matched=%q reason=%q", vr.OK, vr.KeyMatched, vr.Reason)
	}
	task := writeTask(kr10kr11ExecID, kr10kr11Playbook, kr10kr11StepIndex, kr10kr11Op, params, sig)
	outcome := HandleTask(context.Background(), adapter, nil, ring, true, task)
	if outcome.ExitCode != 0 {
		t.Fatalf("execute exit=%d err=%s", outcome.ExitCode, outcome.Error)
	}
	if adapter.callCount() != 1 {
		t.Fatalf("ExecuteWrite calls=%d want 1", adapter.callCount())
	}
}

// FP-KR-11
func TestClient_RejectsWriteSignedWithPreviousKeyAfterGraceExpiry(t *testing.T) {
	pubA, privA, pubB := kr10kr11Keys(t)
	// Zero grace = "window has already passed" by construction.
	// Same key A + same signed step bytes + same signature as FP-KR-10.
	store := writeops.NewKeyStore(0)
	adapter := &recordingWriteAdapter{}
	// First install A, then rotate to B with zero grace → Previous never in Ring.
	store.Install(pubA)
	store.Install(pubB)
	ring := store.Ring()
	if ring.Previous != nil {
		t.Fatal("zero-grace store must drop Previous")
	}

	params, sig := kr10kr11SignedStep(t, privA)
	task := writeTask(kr10kr11ExecID, kr10kr11Playbook, kr10kr11StepIndex, kr10kr11Op, params, sig)
	outcome := HandleTask(context.Background(), adapter, nil, ring, true, task)
	if outcome.ExitCode == 0 {
		t.Fatal("expected rejection after grace expiry")
	}
	if !strings.Contains(outcome.Error, "signature verification failed") {
		t.Fatalf("expected signature verification failed, got %q", outcome.Error)
	}
	if adapter.callCount() != 0 {
		t.Fatalf("ExecuteWrite must not be called; got %d", adapter.callCount())
	}
}
