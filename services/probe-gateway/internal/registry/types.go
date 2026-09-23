// Package registry is probe-gateway's "heartbeat/registry maintenance"
// responsibility (design.md Section 3.2), backed by the same `platforms`/
// `probes` Postgres tables the M1 `rca_common` migration created
// (design.md Section 4.3) -- so both the Go and Python halves of the
// control plane share one schema, no duplication.
//
// Bootstrap tokens (design.md Section 8.4 step 1: "one-time bootstrap
// token") have no dedicated column in the Section 4.3 `platforms` DDL
// (that table is treated as normative/verbatim, matching the M1
// session's approach); this package stores them inside the existing
// `platforms.config` JSONB column instead (`bootstrap_token` /
// `bootstrap_token_consumed` keys) -- a documented, reversible M2
// decision rather than a schema change. See impl-progress.md.
//
// Creating a platform + issuing its bootstrap token is normally
// dashboard-api's job (design.md Section 8.4 step 1), which is M4 scope;
// `CreatePlatform` exists now so M2's own tests (and later dashboard-api)
// share one implementation rather than M2 inventing a throwaway seeding
// path.
package registry

import (
	"context"
	"crypto/subtle"
	"time"
)

// tokenEqual compares a stored bootstrap token against a caller-presented
// one in constant time (design.md Section 8.4a v1.5: "Token comparison
// MUST be constant-time (crypto/subtle)"), removing the timing
// side-channel a naive `==`/`!=` string comparison exposes. Shared by
// both Registry implementations (Fake and PG) so the security property
// holds in tests and production alike, not just production.
func tokenEqual(stored, presented string) bool {
	// subtle.ConstantTimeCompare requires equal-length inputs to avoid an
	// early, length-revealing return; a length mismatch alone (safe to
	// leak -- it doesn't help an attacker distinguish *content*) short-
	// circuits to false without calling it on mismatched-length slices.
	if len(stored) != len(presented) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(stored), []byte(presented)) == 1
}

type PlatformStatus string

const (
	PlatformCreated            PlatformStatus = "created"
	PlatformPendingCredentials PlatformStatus = "pending_credentials"
	PlatformDegraded           PlatformStatus = "degraded"
	PlatformOnline             PlatformStatus = "online"
	PlatformOffline            PlatformStatus = "offline"
)

type ProbeStatus string

const (
	ProbeOffline  ProbeStatus = "offline"
	ProbeOnline   ProbeStatus = "online"
	ProbeDegraded ProbeStatus = "degraded"
)

type Platform struct {
	PlatformKey  string
	PlatformType string
	Deployment   string
	DisplayName  string
	Status       PlatformStatus
	Config       map[string]any
	CreatedAt    time.Time
}

type Probe struct {
	ProbeID        string
	PlatformKey    string
	Version        string
	Capabilities   map[string]any
	Status         ProbeStatus
	GatewayReplica string
	LastHeartbeat  time.Time
	RegisteredAt   time.Time
}

// Registry is probe-gateway's platform/probe persistence interface.
// Implementations: Fake (in-memory, unit tests) and PG (real Postgres,
// production + functional tests).
type Registry interface {
	// CreatePlatform creates a platform row with a bootstrap token
	// (design.md Section 8.4 step 1). Errors if platformKey already exists.
	CreatePlatform(ctx context.Context, p Platform, bootstrapToken string) error

	GetPlatform(ctx context.Context, platformKey string) (Platform, error)

	// ConsumeBootstrapToken validates token against the stored,
	// not-yet-consumed token for platformKey, marks it consumed, and
	// returns the platform (design.md Section 8.4 step 3 + F8 checkpoint
	// "bootstrap token single-use"). Returns ErrInvalidToken if the token
	// doesn't match or was already consumed.
	ConsumeBootstrapToken(ctx context.Context, platformKey, token string) (Platform, error)

	UpdatePlatformStatus(ctx context.Context, platformKey string, status PlatformStatus) error

	// UpsertProbe creates or updates a probe row (design.md Section 8.4:
	// re-registration on every reconnect uses the same probe_id once
	// assigned, or a fresh one on genuinely first contact).
	UpsertProbe(ctx context.Context, p Probe) error

	GetProbe(ctx context.Context, probeID string) (Probe, error)

	// FindProbeByPlatform returns the probe currently associated with
	// platformKey, if any (design.md D11: "one probe per Presto
	// cluster"). found=false (not an error) when none exists yet -- used
	// by the session layer to decide whether to reuse the existing
	// probe_id on reconnect or mint a fresh UUID on first contact
	// (probes.probe_id is a UUID column, design.md Section 4.3).
	FindProbeByPlatform(ctx context.Context, platformKey string) (probe Probe, found bool, err error)

	UpdateProbeHeartbeat(ctx context.Context, probeID string, at time.Time) error

	UpdateProbeStatus(ctx context.Context, probeID string, status ProbeStatus) error

	// ListStaleProbes returns probes whose last_heartbeat is older than
	// cutoff and not already marked offline (design.md Appendix A
	// transport conventions: "the gateway marks a probe offline after
	// 60s without a heartbeat").
	ListStaleProbes(ctx context.Context, cutoff time.Time) ([]Probe, error)
}
