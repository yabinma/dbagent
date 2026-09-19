// F16 / FP-M6-25: credentials_* emitted at real Session registration and
// mid-session re-register after ManifestRefresh — not by calling
// Transitions/Write or emitCredentialAudits directly (code review round 7, C6;
// round 8, C3: real ManifestRefresh + production AuditDB wiring).
package gwserver

import (
	"context"
	"os"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	rcaprobev1 "github.com/yabinma/dbagent/gen/go/rcaprobe/v1"
	"github.com/yabinma/dbagent/services/probe-gateway/internal/registry"
)

// TestF16_CredentialsEmittedAtRegistrationAndRefresh drives the production
// Session registration path, then a real ManifestRefresh that triggers a
// mid-session re-Register with changed AuthStatus, against a real Postgres
// registry whose *sql.DB is wired into AuditDB exactly as main.go does
// (gw.AuditDB = reg.DB).
func TestF16_CredentialsEmittedAtRegistrationAndRefresh(t *testing.T) {
	dsn := os.Getenv("F16_AUDIT_DSN")
	if dsn == "" {
		t.Skip("F16_AUDIT_DSN not set (invoked from test_m6_audit_completeness)")
	}

	// Production registry + audit wiring (same as cmd/probe-gateway/main.go):
	// reg, err := registry.Open(...); gw.AuditDB = reg.DB
	reg, err := registry.Open(dsn)
	if err != nil {
		t.Fatalf("registry.Open: %v", err)
	}
	t.Cleanup(func() { _ = reg.DB.Close() })
	if err := reg.DB.Ping(); err != nil {
		t.Fatalf("ping: %v", err)
	}

	client, srv := testServerWithRegistry(t, reg)
	// Production audit-database wiring (must match main.go).
	srv.AuditDB = reg.DB
	if srv.AuditDB == nil {
		t.Fatal("AuditDB not wired to registry.PG.DB")
	}
	// Deleting main.go's gw.AuditDB = reg.DB is separately gated by
	// TestMainWiresAuditDBFromRegistry in cmd/probe-gateway.

	platformKey := "f16-plat"
	seedPlatform(t, reg, platformKey)

	// 1) Initial registration with full access → credentials_detected +
	// credentials_verified via the real Session path (server.go registration).
	fp := newFakeProbe(t, client)
	fp.registerWithAuth(platformKey, &rcaprobev1.AuthStatus{
		Scheme: "PASSWORD", Access: "full",
	})
	ack := fp.expectAck(2 * time.Second)
	if !ack.GetAccepted() {
		t.Fatalf("expected accepted RegisterAck, got %+v", ack)
	}
	probeID := ack.GetProbeId()
	if probeID == "" {
		t.Fatal("empty probe_id")
	}
	waitForSession(t, srv, platformKey)
	// Scope every audit query by this test's unique platform_key (review C4).
	platFilter := `detail->>'platform_key' = $1`
	waitForCondition(t, 3*time.Second, func() bool {
		var n int
		_ = reg.DB.QueryRow(
			`SELECT count(DISTINCT action) FROM audit_log WHERE action IN ('credentials_detected','credentials_verified') AND `+platFilter,
			platformKey,
		).Scan(&n)
		return n >= 2
	})

	// 2) Real ManifestRefresh path: gateway sends ManifestRefresh; the probe
	// re-Registers with failed access (what sessionclient.refreshManifest
	// enqueues after re-Detect). handleMidSessionRegister must emit
	// credentials_test_failed into the production AuditDB.
	if err := srv.RefreshManifest(platformKey); err != nil {
		t.Fatalf("RefreshManifest: %v", err)
	}
	refreshMsg := fp.expectMessage(2 * time.Second)
	if refreshMsg.GetRefresh() == nil {
		t.Fatalf("expected ManifestRefresh from server, got %+v", refreshMsg)
	}
	fp.registerWithAuth(platformKey, &rcaprobev1.AuthStatus{
		Scheme:  "PASSWORD",
		Access:  "unauthenticated",
		Missing: []string{"connectivity"},
	})
	waitForCondition(t, 3*time.Second, func() bool {
		var n int
		_ = reg.DB.QueryRow(
			`SELECT count(*) FROM audit_log WHERE action = 'credentials_test_failed' AND `+platFilter,
			platformKey,
		).Scan(&n)
		return n >= 1
	})

	var detected, verified, failed int
	if err := reg.DB.QueryRow(
		`SELECT count(*) FROM audit_log WHERE action='credentials_detected' AND `+platFilter, platformKey,
	).Scan(&detected); err != nil {
		t.Fatal(err)
	}
	if err := reg.DB.QueryRow(
		`SELECT count(*) FROM audit_log WHERE action='credentials_verified' AND `+platFilter, platformKey,
	).Scan(&verified); err != nil {
		t.Fatal(err)
	}
	if err := reg.DB.QueryRow(
		`SELECT count(*) FROM audit_log WHERE action='credentials_test_failed' AND `+platFilter, platformKey,
	).Scan(&failed); err != nil {
		t.Fatal(err)
	}
	if detected < 1 || verified < 1 || failed < 1 {
		t.Fatalf("credentials rows: detected=%d verified=%d failed=%d", detected, verified, failed)
	}

	// Assert actors for both required registration actions (review C4).
	// action=$1 and platform=$2 — platFilter above reuses $1 alone and cannot
	// be concatenated when a second bind is already present.
	wantActor := "probe:" + probeID
	for _, action := range []string{"credentials_detected", "credentials_verified"} {
		var actorOut string
		if err := reg.DB.QueryRow(
			`SELECT actor FROM audit_log WHERE action=$1 AND detail->>'platform_key' = $2 ORDER BY seq DESC LIMIT 1`,
			action, platformKey,
		).Scan(&actorOut); err != nil {
			t.Fatalf("actor query for %s: %v", action, err)
		}
		if actorOut != wantActor {
			t.Fatalf("%s actor=%q want %q", action, actorOut, wantActor)
		}
	}

	// Platform must still be present (registration used the real registry path).
	p, err := reg.GetPlatform(context.Background(), platformKey)
	if err != nil {
		t.Fatal(err)
	}
	if p.PlatformKey != platformKey {
		t.Fatalf("platform=%q", p.PlatformKey)
	}

	// Sanity: AuditDB is the same pool the registry uses (production wiring).
	if srv.AuditDB != reg.DB {
		t.Fatal("AuditDB must be registry.PG.DB (production main.go wiring)")
	}
}
