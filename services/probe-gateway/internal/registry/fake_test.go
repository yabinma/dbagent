package registry

import (
	"context"
	"testing"
	"time"
)

func TestFake_CreateAndGetPlatform(t *testing.T) {
	r := NewFake()
	err := r.CreatePlatform(context.Background(), Platform{PlatformKey: "presto-us1", PlatformType: "presto", Deployment: "k8s"}, "tok-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	p, err := r.GetPlatform(context.Background(), "presto-us1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.Status != PlatformCreated {
		t.Fatalf("expected default status 'created', got %s", p.Status)
	}
}

func TestFake_CreatePlatform_DuplicateRejected(t *testing.T) {
	r := NewFake()
	_ = r.CreatePlatform(context.Background(), Platform{PlatformKey: "presto-us1"}, "tok-1")
	err := r.CreatePlatform(context.Background(), Platform{PlatformKey: "presto-us1"}, "tok-2")
	if err != ErrPlatformExists {
		t.Fatalf("expected ErrPlatformExists, got %v", err)
	}
}

func TestFake_GetPlatform_NotFound(t *testing.T) {
	r := NewFake()
	_, err := r.GetPlatform(context.Background(), "missing")
	if err != ErrPlatformNotFound {
		t.Fatalf("expected ErrPlatformNotFound, got %v", err)
	}
}

func TestFake_ConsumeBootstrapToken_Success(t *testing.T) {
	r := NewFake()
	_ = r.CreatePlatform(context.Background(), Platform{PlatformKey: "presto-us1"}, "tok-1")

	p, err := r.ConsumeBootstrapToken(context.Background(), "presto-us1", "tok-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.PlatformKey != "presto-us1" {
		t.Fatalf("unexpected platform: %+v", p)
	}
}

func TestFake_ConsumeBootstrapToken_SingleUse(t *testing.T) {
	r := NewFake()
	_ = r.CreatePlatform(context.Background(), Platform{PlatformKey: "presto-us1"}, "tok-1")

	if _, err := r.ConsumeBootstrapToken(context.Background(), "presto-us1", "tok-1"); err != nil {
		t.Fatalf("first consume failed: %v", err)
	}
	_, err := r.ConsumeBootstrapToken(context.Background(), "presto-us1", "tok-1")
	if err != ErrInvalidToken {
		t.Fatalf("expected ErrInvalidToken on second use, got %v", err)
	}
}

func TestFake_ConsumeBootstrapToken_WrongToken(t *testing.T) {
	r := NewFake()
	_ = r.CreatePlatform(context.Background(), Platform{PlatformKey: "presto-us1"}, "tok-1")

	_, err := r.ConsumeBootstrapToken(context.Background(), "presto-us1", "wrong-token")
	if err != ErrInvalidToken {
		t.Fatalf("expected ErrInvalidToken, got %v", err)
	}
}

func TestFake_ConsumeBootstrapToken_UnknownPlatform(t *testing.T) {
	r := NewFake()
	_, err := r.ConsumeBootstrapToken(context.Background(), "missing", "tok-1")
	if err != ErrPlatformNotFound {
		t.Fatalf("expected ErrPlatformNotFound, got %v", err)
	}
}

func TestFake_UpdatePlatformStatus(t *testing.T) {
	r := NewFake()
	_ = r.CreatePlatform(context.Background(), Platform{PlatformKey: "presto-us1"}, "tok-1")

	if err := r.UpdatePlatformStatus(context.Background(), "presto-us1", PlatformOnline); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	p, _ := r.GetPlatform(context.Background(), "presto-us1")
	if p.Status != PlatformOnline {
		t.Fatalf("expected online status, got %s", p.Status)
	}
}

func TestFake_UpdatePlatformStatus_NotFound(t *testing.T) {
	r := NewFake()
	err := r.UpdatePlatformStatus(context.Background(), "missing", PlatformOnline)
	if err != ErrPlatformNotFound {
		t.Fatalf("expected ErrPlatformNotFound, got %v", err)
	}
}

func TestFake_UpsertProbe_CreateThenUpdate(t *testing.T) {
	r := NewFake()
	err := r.UpsertProbe(context.Background(), Probe{ProbeID: "probe-1", PlatformKey: "presto-us1", Version: "1.0"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	first, _ := r.GetProbe(context.Background(), "probe-1")

	err = r.UpsertProbe(context.Background(), Probe{ProbeID: "probe-1", PlatformKey: "presto-us1", Version: "1.1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	second, _ := r.GetProbe(context.Background(), "probe-1")

	if second.Version != "1.1" {
		t.Fatalf("expected version to update, got %s", second.Version)
	}
	if !second.RegisteredAt.Equal(first.RegisteredAt) {
		t.Fatalf("expected registered_at to be preserved across re-registration")
	}
}

func TestFake_GetProbe_NotFound(t *testing.T) {
	r := NewFake()
	_, err := r.GetProbe(context.Background(), "missing")
	if err != ErrProbeNotFound {
		t.Fatalf("expected ErrProbeNotFound, got %v", err)
	}
}

func TestFake_FindProbeByPlatform(t *testing.T) {
	r := NewFake()
	_, found, err := r.FindProbeByPlatform(context.Background(), "presto-us1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if found {
		t.Fatalf("expected no probe to be found yet")
	}

	_ = r.UpsertProbe(context.Background(), Probe{ProbeID: "probe-1", PlatformKey: "presto-us1"})
	p, found, err := r.FindProbeByPlatform(context.Background(), "presto-us1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !found || p.ProbeID != "probe-1" {
		t.Fatalf("expected to find probe-1, got %+v found=%v", p, found)
	}
}

func TestFake_UpdateProbeHeartbeat(t *testing.T) {
	r := NewFake()
	_ = r.UpsertProbe(context.Background(), Probe{ProbeID: "probe-1", Status: ProbeOffline})

	now := time.Now().UTC()
	if err := r.UpdateProbeHeartbeat(context.Background(), "probe-1", now); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	p, _ := r.GetProbe(context.Background(), "probe-1")
	if !p.LastHeartbeat.Equal(now) {
		t.Fatalf("unexpected last_heartbeat: %v", p.LastHeartbeat)
	}
	if p.Status != ProbeOnline {
		t.Fatalf("expected heartbeat to mark probe online, got %s", p.Status)
	}
}

func TestFake_UpdateProbeHeartbeat_NotFound(t *testing.T) {
	r := NewFake()
	err := r.UpdateProbeHeartbeat(context.Background(), "missing", time.Now())
	if err != ErrProbeNotFound {
		t.Fatalf("expected ErrProbeNotFound, got %v", err)
	}
}

func TestFake_UpdateProbeStatus(t *testing.T) {
	r := NewFake()
	_ = r.UpsertProbe(context.Background(), Probe{ProbeID: "probe-1"})

	if err := r.UpdateProbeStatus(context.Background(), "probe-1", ProbeDegraded); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	p, _ := r.GetProbe(context.Background(), "probe-1")
	if p.Status != ProbeDegraded {
		t.Fatalf("expected degraded status, got %s", p.Status)
	}
}

func TestFake_ListStaleProbes(t *testing.T) {
	r := NewFake()
	now := time.Now().UTC()
	_ = r.UpsertProbe(context.Background(), Probe{ProbeID: "fresh", Status: ProbeOnline})
	_ = r.UpdateProbeHeartbeat(context.Background(), "fresh", now)

	_ = r.UpsertProbe(context.Background(), Probe{ProbeID: "stale", Status: ProbeOnline})
	_ = r.UpdateProbeHeartbeat(context.Background(), "stale", now.Add(-2*time.Minute))

	_ = r.UpsertProbe(context.Background(), Probe{ProbeID: "already-offline", Status: ProbeOffline})
	_ = r.UpdateProbeHeartbeat(context.Background(), "already-offline", now.Add(-10*time.Minute))
	_ = r.UpdateProbeStatus(context.Background(), "already-offline", ProbeOffline)

	stale, err := r.ListStaleProbes(context.Background(), now.Add(-60*time.Second))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(stale) != 1 || stale[0].ProbeID != "stale" {
		t.Fatalf("unexpected stale probes: %+v", stale)
	}
}
