package registry

// PG is tested against a real ephemeral Postgres (via testcontainers-go),
// migrated with the exact same alembic migration
// libs/py/rca_common/migrations/versions/0001_initial_schema.py already
// verified in M1 -- so there is zero drift risk between the schema the Go
// probe-gateway writes to and the schema `rca_common`'s Python code
// expects. This is co-located with the rest of the package's tests per
// design.md Section 11 ("Unit tests live next to the code they test ...
// `_test.go` files per language convention"); it is the one slice of this
// package's tests that needs real infrastructure (Docker), same as how
// M1's PGTraceStore was proven against a real Postgres in the functional
// tier -- Go's tooling doesn't distinguish unit/functional tiers via
// separate directories the way the Python side does, so this lives right
// next to registry/fake_test.go instead.

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	tcwait "github.com/testcontainers/testcontainers-go/wait"
)

// repoRoot walks up from this test file's own path to the monorepo root
// (four levels: registry -> internal -> probe-gateway -> services -> root).
func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatalf("runtime.Caller failed")
	}
	// .../services/probe-gateway/internal/registry/pg_test.go
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", "..", ".."))
}

func startMigratedPostgres(t *testing.T) string {
	t.Helper()
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
		t.Fatalf("start postgres container: %v", err)
	}
	t.Cleanup(func() { _ = pgContainer.Terminate(ctx) })

	dsn, err := pgContainer.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatalf("connection string: %v", err)
	}

	root := repoRoot(t)
	rcaCommonDir := filepath.Join(root, "libs", "py", "rca_common")
	pythonBin := filepath.Join(rcaCommonDir, ".venv", "bin", "python")

	// testcontainers-go's postgres module returns a bare "postgres://"
	// scheme; SQLAlchemy (used by alembic, Python side) requires the
	// "postgresql+psycopg2://" dialect+driver form. pgx (this package's
	// own driver) accepts the bare "postgres://" scheme directly, so only
	// the DSN handed to alembic needs rewriting.
	alembicDSN := strings.Replace(dsn, "postgres://", "postgresql+psycopg2://", 1)

	cmd := exec.Command(pythonBin, "-m", "alembic", "upgrade", "head")
	cmd.Dir = rcaCommonDir
	cmd.Env = append(os.Environ(), "DBAGENT_PG_DSN="+alembicDSN)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("alembic upgrade head failed: %v\n%s", err, out)
	}

	return dsn
}

func TestPG_CreateAndGetPlatform(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping real-Postgres test in -short mode")
	}
	dsn := startMigratedPostgres(t)
	reg, err := Open(dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer reg.DB.Close()

	err = reg.CreatePlatform(context.Background(), Platform{
		PlatformKey: "presto-us1", PlatformType: "presto", Deployment: "k8s", DisplayName: "US1",
	}, "tok-1")
	if err != nil {
		t.Fatalf("create platform: %v", err)
	}

	p, err := reg.GetPlatform(context.Background(), "presto-us1")
	if err != nil {
		t.Fatalf("get platform: %v", err)
	}
	if p.Status != PlatformCreated || p.PlatformType != "presto" || p.DisplayName != "US1" {
		t.Fatalf("unexpected platform: %+v", p)
	}
}

func TestPG_ConsumeBootstrapToken_SingleUse(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping real-Postgres test in -short mode")
	}
	dsn := startMigratedPostgres(t)
	reg, err := Open(dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer reg.DB.Close()

	_ = reg.CreatePlatform(context.Background(), Platform{PlatformKey: "presto-us1", PlatformType: "presto", Deployment: "k8s"}, "tok-1")

	if _, err := reg.ConsumeBootstrapToken(context.Background(), "presto-us1", "tok-1"); err != nil {
		t.Fatalf("first consume failed: %v", err)
	}
	if _, err := reg.ConsumeBootstrapToken(context.Background(), "presto-us1", "tok-1"); err != ErrInvalidToken {
		t.Fatalf("expected ErrInvalidToken on reuse, got %v", err)
	}
}

func TestPG_UpdatePlatformStatus(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping real-Postgres test in -short mode")
	}
	dsn := startMigratedPostgres(t)
	reg, err := Open(dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer reg.DB.Close()

	_ = reg.CreatePlatform(context.Background(), Platform{PlatformKey: "presto-us1", PlatformType: "presto", Deployment: "k8s"}, "tok-1")
	if err := reg.UpdatePlatformStatus(context.Background(), "presto-us1", PlatformOnline); err != nil {
		t.Fatalf("update status: %v", err)
	}
	p, _ := reg.GetPlatform(context.Background(), "presto-us1")
	if p.Status != PlatformOnline {
		t.Fatalf("expected online, got %s", p.Status)
	}

	if err := reg.UpdatePlatformStatus(context.Background(), "missing", PlatformOnline); err != ErrPlatformNotFound {
		t.Fatalf("expected ErrPlatformNotFound, got %v", err)
	}
}

func TestPG_UpsertProbeAndHeartbeat(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping real-Postgres test in -short mode")
	}
	dsn := startMigratedPostgres(t)
	reg, err := Open(dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer reg.DB.Close()

	_ = reg.CreatePlatform(context.Background(), Platform{PlatformKey: "presto-us1", PlatformType: "presto", Deployment: "k8s"}, "tok-1")

	probeID := uuid.NewString()
	err = reg.UpsertProbe(context.Background(), Probe{
		ProbeID: probeID, PlatformKey: "presto-us1", Version: "0.1.0",
		Capabilities: map[string]any{"platform_type": "presto"}, Status: ProbeOnline,
	})
	if err != nil {
		t.Fatalf("upsert probe: %v", err)
	}

	probe, err := reg.GetProbe(context.Background(), probeID)
	if err != nil {
		t.Fatalf("get probe: %v", err)
	}
	if probe.Version != "0.1.0" || probe.Capabilities["platform_type"] != "presto" {
		t.Fatalf("unexpected probe: %+v", probe)
	}

	now := time.Now().UTC().Truncate(time.Millisecond)
	if err := reg.UpdateProbeHeartbeat(context.Background(), probeID, now); err != nil {
		t.Fatalf("update heartbeat: %v", err)
	}
	probe, _ = reg.GetProbe(context.Background(), probeID)
	if probe.Status != ProbeOnline {
		t.Fatalf("expected online after heartbeat, got %s", probe.Status)
	}

	if err := reg.UpdateProbeStatus(context.Background(), probeID, ProbeOffline); err != nil {
		t.Fatalf("update probe status: %v", err)
	}
	probe, _ = reg.GetProbe(context.Background(), probeID)
	if probe.Status != ProbeOffline {
		t.Fatalf("expected offline, got %s", probe.Status)
	}
}

func TestPG_FindProbeByPlatform(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping real-Postgres test in -short mode")
	}
	dsn := startMigratedPostgres(t)
	reg, err := Open(dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer reg.DB.Close()

	_ = reg.CreatePlatform(context.Background(), Platform{PlatformKey: "presto-us1", PlatformType: "presto", Deployment: "k8s"}, "tok-1")

	_, found, err := reg.FindProbeByPlatform(context.Background(), "presto-us1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if found {
		t.Fatalf("expected no probe to be found yet")
	}

	probeID := uuid.NewString()
	_ = reg.UpsertProbe(context.Background(), Probe{ProbeID: probeID, PlatformKey: "presto-us1"})

	p, found, err := reg.FindProbeByPlatform(context.Background(), "presto-us1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !found || p.ProbeID != probeID {
		t.Fatalf("expected to find probe %s, got %+v found=%v", probeID, p, found)
	}
}

func TestPG_UpsertProbe_ReRegistrationUpdatesInPlace(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping real-Postgres test in -short mode")
	}
	dsn := startMigratedPostgres(t)
	reg, err := Open(dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer reg.DB.Close()

	_ = reg.CreatePlatform(context.Background(), Platform{PlatformKey: "presto-us1", PlatformType: "presto", Deployment: "k8s"}, "tok-1")
	probeID := uuid.NewString()
	_ = reg.UpsertProbe(context.Background(), Probe{ProbeID: probeID, PlatformKey: "presto-us1", Version: "1.0"})
	_ = reg.UpsertProbe(context.Background(), Probe{ProbeID: probeID, PlatformKey: "presto-us1", Version: "1.1"})

	probe, err := reg.GetProbe(context.Background(), probeID)
	if err != nil {
		t.Fatalf("get probe: %v", err)
	}
	if probe.Version != "1.1" {
		t.Fatalf("expected version 1.1 after re-registration, got %s", probe.Version)
	}
}

func TestPG_ListStaleProbes(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping real-Postgres test in -short mode")
	}
	dsn := startMigratedPostgres(t)
	reg, err := Open(dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer reg.DB.Close()

	_ = reg.CreatePlatform(context.Background(), Platform{PlatformKey: "presto-us1", PlatformType: "presto", Deployment: "k8s"}, "tok-1")
	freshID, staleID := uuid.NewString(), uuid.NewString()
	_ = reg.UpsertProbe(context.Background(), Probe{ProbeID: freshID, PlatformKey: "presto-us1", Status: ProbeOnline})
	_ = reg.UpdateProbeHeartbeat(context.Background(), freshID, time.Now().UTC())

	_ = reg.UpsertProbe(context.Background(), Probe{ProbeID: staleID, PlatformKey: "presto-us1", Status: ProbeOnline})
	_ = reg.UpdateProbeHeartbeat(context.Background(), staleID, time.Now().UTC().Add(-5*time.Minute))

	stale, err := reg.ListStaleProbes(context.Background(), time.Now().UTC().Add(-60*time.Second))
	if err != nil {
		t.Fatalf("list stale probes: %v", err)
	}
	if len(stale) != 1 || stale[0].ProbeID != staleID {
		t.Fatalf("unexpected stale probes: %+v", stale)
	}
}

func TestPG_GetPlatform_NotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping real-Postgres test in -short mode")
	}
	dsn := startMigratedPostgres(t)
	reg, err := Open(dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer reg.DB.Close()

	_, err = reg.GetPlatform(context.Background(), "missing")
	if err != ErrPlatformNotFound {
		t.Fatalf("expected ErrPlatformNotFound, got %v", err)
	}
}
