package gwserver

import (
	"bytes"
	"crypto/ed25519"
	"sync"
	"testing"
	"time"

	rcaprobev1 "github.com/yabinma/dbagent/gen/go/rcaprobe/v1"
	"github.com/yabinma/dbagent/services/probe-gateway/internal/registry"
)

func krA() []byte { return bytes.Repeat([]byte("a"), ed25519.PublicKeySize) }
func krB() []byte { return bytes.Repeat([]byte("b"), ed25519.PublicKeySize) }
func krC() []byte { return bytes.Repeat([]byte("c"), ed25519.PublicKeySize) }

func drainOutbound(h *sessionHandle) []*rcaprobev1.GatewayMessage {
	var out []*rcaprobev1.GatewayMessage
	for {
		select {
		case msg := <-h.outbound:
			out = append(out, msg)
		default:
			return out
		}
	}
}

// FP-KR-12
func TestPropagateSigningKey_SendsKeyUpdateToConnectedSession(t *testing.T) {
	a, b := krA(), krB()
	s := New(registry.NewFake(), a, "replica-1")
	h := newSessionHandle("probe-1", "presto-us1")
	s.admitSession("presto-us1", h, "probe-1")
	// Consume admission ack.
	_ = drainOutbound(h)

	s.SetSigningPublicKey(b)
	p := s.PropagateSigningKey()
	if p.Sent != 1 || p.UpToDate != 0 || p.Dropped != 0 {
		t.Fatalf("propagation = %+v, want Sent=1", p)
	}
	frames := drainOutbound(h)
	if len(frames) != 1 {
		t.Fatalf("expected 1 frame, got %d", len(frames))
	}
	ack := frames[0].GetAck()
	if ack == nil || !ack.GetAccepted() || ack.GetProbeId() != "probe-1" {
		t.Fatalf("bad A.2 frame: %+v", frames[0])
	}
	if !bytes.Equal(ack.GetSigningPublicKey(), b) {
		t.Fatalf("signing key = %v, want B", ack.GetSigningPublicKey())
	}
}

// FP-KR-13
func TestPropagateSigningKey_NoFrameWhenSessionAlreadyHasCurrentKey(t *testing.T) {
	a := krA()
	s := New(registry.NewFake(), a, "replica-1")
	h := newSessionHandle("probe-1", "presto-us1")
	s.admitSession("presto-us1", h, "probe-1")
	_ = drainOutbound(h)

	p := s.PropagateSigningKey()
	if p.UpToDate != 1 || p.Sent != 0 || p.Dropped != 0 {
		t.Fatalf("propagation = %+v, want UpToDate=1", p)
	}
	if frames := drainOutbound(h); len(frames) != 0 {
		t.Fatalf("expected no frames, got %d", len(frames))
	}
}

// FP-KR-14
func TestPropagateSigningKey_NoOpWithoutAValidCurrentKey(t *testing.T) {
	s := New(registry.NewFake(), nil, "replica-1")
	h := newSessionHandle("probe-1", "presto-us1")
	// Manually publish so there is a session, but key is invalid.
	s.mu.Lock()
	s.sessionsByPlatform["presto-us1"] = h
	s.mu.Unlock()
	h.recordKeySent(krA())

	p := s.PropagateSigningKey()
	if p != (SigningKeyPropagation{}) {
		t.Fatalf("expected zero propagation, got %+v", p)
	}

	s.SetSigningPublicKey(bytes.Repeat([]byte("x"), 31))
	p = s.PropagateSigningKey()
	if p != (SigningKeyPropagation{}) {
		t.Fatalf("expected zero for wrong-length key, got %+v", p)
	}
	if frames := drainOutbound(h); len(frames) != 0 {
		t.Fatalf("expected no frames, got %d", len(frames))
	}
}

// FP-KR-15
func TestPropagateSigningKey_SessionAdmittedAfterRotationIsAlreadyConverged(t *testing.T) {
	a, b := krA(), krB()
	s := New(registry.NewFake(), a, "replica-1")
	s.SetSigningPublicKey(b)

	h := newSessionHandle("probe-1", "presto-us1")
	s.admitSession("presto-us1", h, "probe-1")
	frames := drainOutbound(h)
	if len(frames) != 1 || !bytes.Equal(frames[0].GetAck().GetSigningPublicKey(), b) {
		t.Fatalf("admission ack must carry B, got %+v", frames)
	}

	p := s.PropagateSigningKey()
	if p.UpToDate != 1 || p.Sent != 0 {
		t.Fatalf("already converged session: %+v", p)
	}
	if more := drainOutbound(h); len(more) != 0 {
		t.Fatalf("next pass must send nothing, got %d frames", len(more))
	}
}

// FP-KR-16
func TestPropagateSigningKey_DropsWhenOutboundFullAndRetriesNextPass(t *testing.T) {
	a, b := krA(), krB()
	s := New(registry.NewFake(), a, "replica-1")

	full := newSessionHandle("probe-full", "presto-full")
	ok := newSessionHandle("probe-ok", "presto-ok")
	s.admitSession("presto-full", full, "probe-full")
	s.admitSession("presto-ok", ok, "probe-ok")
	// Drain admission acks so we start from a known state.
	_ = drainOutbound(full)
	_ = drainOutbound(ok)

	// Fill full's outbound buffer completely.
	for i := 0; i < outboundBufferSize; i++ {
		full.outbound <- &rcaprobev1.GatewayMessage{Msg: &rcaprobev1.GatewayMessage_Refresh{
			Refresh: &rcaprobev1.ManifestRefresh{},
		}}
	}
	// Stale recorded key so both need an update.
	full.recordKeySent(a)
	ok.recordKeySent(a)

	s.SetSigningPublicKey(b)
	p := s.PropagateSigningKey()
	if p.Dropped < 1 {
		t.Fatalf("expected at least one drop, got %+v", p)
	}
	if p.Sent < 1 {
		t.Fatalf("other session must still be served, got %+v", p)
	}
	// Full session keeps stale key.
	if !bytes.Equal(full.keySent(), a) {
		t.Fatalf("dropped session must keep stale key, got %v", full.keySent())
	}
	if !bytes.Equal(ok.keySent(), b) {
		t.Fatalf("ok session must converge to B, got %v", ok.keySent())
	}

	// Drain full buffer so next pass can succeed.
	_ = drainOutbound(full)
	p2 := s.PropagateSigningKey()
	if p2.Sent != 1 {
		t.Fatalf("retry pass should send to full session: %+v", p2)
	}
	if !bytes.Equal(full.keySent(), b) {
		t.Fatalf("full session should now hold B")
	}
}

// FP-KR-26
func TestAdmitSession_RotationDuringAdmissionCannotRegressTheSessionKey(t *testing.T) {
	a, b := krA(), krB()
	s := New(registry.NewFake(), a, "replica-1")
	h := newSessionHandle("probe-1", "presto-us1")

	hookEntered := make(chan struct{})
	releaseHook := make(chan struct{})
	admitDone := make(chan struct{})
	rotationStarted := make(chan struct{})
	rotationDone := make(chan struct{})
	release := sync.OnceFunc(func() { close(releaseHook) })

	s.admitHook = func() { close(hookEntered); <-releaseHook }

	go func() {
		s.admitSession("presto-us1", h, "probe-1")
		close(admitDone)
	}()
	t.Cleanup(func() {
		release()
		select {
		case <-admitDone:
		case <-time.After(2 * time.Second):
			t.Errorf("admitSession did not return")
		}
		s.admitHook = nil
		h.close()
	})

	select {
	case <-hookEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("admitHook never entered")
	}

	// Prove s.mu is held at the hook.
	if s.mu.TryLock() {
		s.mu.Unlock()
		t.Fatal("admitSession is not holding s.mu at admitHook: the atomicity assertion below would prove nothing")
	}

	var p SigningKeyPropagation
	go func() {
		close(rotationStarted)
		s.SetSigningPublicKey(b)
		p = s.PropagateSigningKey()
		close(rotationDone)
	}()
	select {
	case <-rotationStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("rotation never started")
	}

	select {
	case <-rotationDone:
		t.Fatal("rotation completed while admission held s.mu — admitSession is not atomic")
	case <-time.After(250 * time.Millisecond):
		// pass: blocked on lock
	}

	release()
	select {
	case <-admitDone:
	case <-time.After(2 * time.Second):
		t.Fatal("admitSession did not finish after release")
	}
	select {
	case <-rotationDone:
	case <-time.After(2 * time.Second):
		t.Fatal("rotation did not finish after admit released")
	}

	frames := drainOutbound(h)
	if len(frames) != 2 {
		t.Fatalf("expected 2 frames (A then B), got %d: %+v", len(frames), frames)
	}
	if !bytes.Equal(frames[0].GetAck().GetSigningPublicKey(), a) {
		t.Fatalf("first frame must be admission A, got %v", frames[0].GetAck().GetSigningPublicKey())
	}
	if !bytes.Equal(frames[1].GetAck().GetSigningPublicKey(), b) {
		t.Fatalf("second frame must be propagation B, got %v", frames[1].GetAck().GetSigningPublicKey())
	}
	if !bytes.Equal(h.keySent(), b) {
		t.Fatalf("lastKeySent = %v, want B", h.keySent())
	}
	if p.Sent != 1 {
		t.Fatalf("propagation Sent = %d, want 1", p.Sent)
	}
}
