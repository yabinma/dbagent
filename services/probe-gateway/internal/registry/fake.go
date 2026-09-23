package registry

import (
	"context"
	"errors"
	"sync"
	"time"
)

var (
	ErrPlatformExists   = errors.New("registry: platform already exists")
	ErrPlatformNotFound = errors.New("registry: platform not found")
	ErrProbeNotFound    = errors.New("registry: probe not found")
	ErrInvalidToken     = errors.New("registry: bootstrap token invalid or already consumed")
)

// Fake is an in-memory Registry for unit tests (design.md Section 14.2's
// "standard mocks" convention).
type Fake struct {
	mu        sync.Mutex
	platforms map[string]*platformRecord
	probes    map[string]*Probe
}

type platformRecord struct {
	platform       Platform
	bootstrapToken string
	consumed       bool
}

func NewFake() *Fake {
	return &Fake{
		platforms: map[string]*platformRecord{},
		probes:    map[string]*Probe{},
	}
}

func (f *Fake) CreatePlatform(ctx context.Context, p Platform, bootstrapToken string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, exists := f.platforms[p.PlatformKey]; exists {
		return ErrPlatformExists
	}
	if p.Status == "" {
		p.Status = PlatformCreated
	}
	if p.Config == nil {
		p.Config = map[string]any{}
	}
	if p.CreatedAt.IsZero() {
		p.CreatedAt = time.Now().UTC()
	}
	f.platforms[p.PlatformKey] = &platformRecord{platform: p, bootstrapToken: bootstrapToken}
	return nil
}

func (f *Fake) GetPlatform(ctx context.Context, platformKey string) (Platform, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	rec, ok := f.platforms[platformKey]
	if !ok {
		return Platform{}, ErrPlatformNotFound
	}
	return rec.platform, nil
}

func (f *Fake) ConsumeBootstrapToken(ctx context.Context, platformKey, token string) (Platform, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	rec, ok := f.platforms[platformKey]
	if !ok {
		return Platform{}, ErrPlatformNotFound
	}
	// design.md Section 8.4a (v1.5): constant-time token comparison.
	if rec.consumed || rec.bootstrapToken == "" || !tokenEqual(rec.bootstrapToken, token) {
		return Platform{}, ErrInvalidToken
	}
	rec.consumed = true
	return rec.platform, nil
}

func (f *Fake) UpdatePlatformStatus(ctx context.Context, platformKey string, status PlatformStatus) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	rec, ok := f.platforms[platformKey]
	if !ok {
		return ErrPlatformNotFound
	}
	rec.platform.Status = status
	return nil
}

func (f *Fake) UpsertProbe(ctx context.Context, p Probe) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if p.RegisteredAt.IsZero() {
		if existing, ok := f.probes[p.ProbeID]; ok {
			p.RegisteredAt = existing.RegisteredAt
		} else {
			p.RegisteredAt = time.Now().UTC()
		}
	}
	cp := p
	f.probes[p.ProbeID] = &cp
	return nil
}

func (f *Fake) GetProbe(ctx context.Context, probeID string) (Probe, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p, ok := f.probes[probeID]
	if !ok {
		return Probe{}, ErrProbeNotFound
	}
	return *p, nil
}

func (f *Fake) FindProbeByPlatform(ctx context.Context, platformKey string) (Probe, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, p := range f.probes {
		if p.PlatformKey == platformKey {
			return *p, true, nil
		}
	}
	return Probe{}, false, nil
}

func (f *Fake) UpdateProbeHeartbeat(ctx context.Context, probeID string, at time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	p, ok := f.probes[probeID]
	if !ok {
		return ErrProbeNotFound
	}
	p.LastHeartbeat = at
	if p.Status != ProbeOnline {
		p.Status = ProbeOnline
	}
	return nil
}

func (f *Fake) UpdateProbeStatus(ctx context.Context, probeID string, status ProbeStatus) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	p, ok := f.probes[probeID]
	if !ok {
		return ErrProbeNotFound
	}
	p.Status = status
	return nil
}

func (f *Fake) ListStaleProbes(ctx context.Context, cutoff time.Time) ([]Probe, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []Probe
	for _, p := range f.probes {
		if p.Status != ProbeOffline && p.LastHeartbeat.Before(cutoff) {
			out = append(out, *p)
		}
	}
	return out, nil
}
