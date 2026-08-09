package audit

import (
	"context"
	"database/sql"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	tcwait "github.com/testcontainers/testcontainers-go/wait"
)

func TestWrite_NilDBIsNoOp(t *testing.T) {
	if err := Write(context.Background(), nil, "credentials_detected", "probe:p1", "pk", map[string]any{"x": 1}); err != nil {
		t.Fatalf("nil db should be no-op: %v", err)
	}
}

func TestHasCredentials(t *testing.T) {
	a := AuthSnapshot{Missing: nil}
	if !a.HasCredentials() {
		t.Fatal("nil missing should mean has credentials")
	}
	a = AuthSnapshot{Missing: []string{"tls_ca"}}
	if !a.HasCredentials() {
		t.Fatal("tls_ca only should still mean has credentials")
	}
	a = AuthSnapshot{Missing: []string{"credentials"}}
	if a.HasCredentials() {
		t.Fatal("credentials in missing should mean no credentials")
	}
}

func TestTransitions_FirstRegistrationWithCredentials(t *testing.T) {
	got := Transitions(nil, AuthSnapshot{Scheme: "PASSWORD", Access: "full", Missing: nil})
	want := []string{"credentials_detected", "credentials_verified"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestTransitions_FirstRegistrationMissingCredentials(t *testing.T) {
	got := Transitions(nil, AuthSnapshot{Access: "unauthenticated", Missing: []string{"credentials"}})
	if len(got) != 0 {
		t.Fatalf("expected no credential audits, got %v", got)
	}
}

func TestTransitions_PresentButNotFull(t *testing.T) {
	got := Transitions(nil, AuthSnapshot{Access: "unauthenticated", Missing: []string{"connectivity"}})
	want := []string{"credentials_detected", "credentials_test_failed"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestTransitions_ReconnectStormNoSpam(t *testing.T) {
	prev := &AuthSnapshot{Access: "full", Missing: nil}
	got := Transitions(prev, AuthSnapshot{Access: "full", Missing: nil})
	if len(got) != 0 {
		t.Fatalf("same state should not re-fire: %v", got)
	}
}

func TestTransitions_AbsentToPresent(t *testing.T) {
	prev := &AuthSnapshot{Access: "unauthenticated", Missing: []string{"credentials"}}
	got := Transitions(prev, AuthSnapshot{Access: "full", Missing: nil})
	want := []string{"credentials_detected", "credentials_verified"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestTransitions_FullToFailed(t *testing.T) {
	prev := &AuthSnapshot{Access: "full", Missing: nil}
	got := Transitions(prev, AuthSnapshot{Access: "unauthenticated", Missing: []string{"connectivity"}})
	want := []string{"credentials_test_failed"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestWrite_InsertsRow(t *testing.T) {
	// Real Postgres so all Write branches (map merge, nil detail, non-map, marshal error) run.
	if testing.Short() {
		t.Skip("docker")
	}
	ctx := context.Background()
	pg, err := postgres.Run(ctx, "postgres:16-alpine",
		postgres.WithDatabase("rca_agent"),
		postgres.WithUsername("rca_agent"),
		postgres.WithPassword("rca_agent"),
		testcontainers.WithWaitStrategy(
			tcwait.ForLog("database system is ready to accept connections").WithOccurrence(2).WithStartupTimeout(60*time.Second),
		),
	)
	if err != nil {
		t.Fatalf("pg: %v", err)
	}
	t.Cleanup(func() { _ = pg.Terminate(ctx) })
	dsn, err := pg.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	_, thisFile, _, _ := runtime.Caller(0)
	root := filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", "..", "..", ".."))
	rca := filepath.Join(root, "libs", "py", "rca_common")
	py := filepath.Join(rca, ".venv", "bin", "python")
	if _, err := os.Stat(py); err != nil {
		py = "python3"
	}
	alembicDSN := strings.Replace(dsn, "postgres://", "postgresql+psycopg2://", 1)
	cmd := exec.Command(py, "-m", "alembic", "upgrade", "head")
	cmd.Dir = rca
	cmd.Env = append(os.Environ(), "RCA_PG_DSN="+alembicDSN)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("migrate: %v\n%s", err, out)
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	// map detail without platform_key → merged
	if err := Write(ctx, db, "credentials_detected", "probe:p1", "pk-merge", map[string]any{"access": "full"}); err != nil {
		t.Fatal(err)
	}
	var detail string
	if err := db.QueryRow(`SELECT detail::text FROM audit_log WHERE action='credentials_detected' ORDER BY seq DESC LIMIT 1`).Scan(&detail); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(detail, "pk-merge") {
		t.Fatalf("platform_key not merged into detail: %s", detail)
	}

	// map detail that already has platform_key → not overwritten
	if err := Write(ctx, db, "credentials_verified", "probe:p1", "ignored", map[string]any{"platform_key": "kept"}); err != nil {
		t.Fatal(err)
	}

	// nil detail
	if err := Write(ctx, db, "credentials_test_failed", "probe:p1", "pk-nil", nil); err != nil {
		t.Fatal(err)
	}

	// non-map detail (slice) marshals as JSON array
	if err := Write(ctx, db, "credentials_detected", "probe:p1", "pk", []string{"a", "b"}); err != nil {
		t.Fatal(err)
	}

	// marshal error on non-map path (channel)
	if err := Write(ctx, db, "credentials_verified", "probe:p1", "pk", make(chan int)); err == nil {
		t.Fatal("expected marshal error")
	}
}

func TestTransitions_SameNonFullNoSpam(t *testing.T) {
	prev := &AuthSnapshot{Access: "unauthenticated", Missing: []string{"connectivity"}}
	got := Transitions(prev, AuthSnapshot{Access: "unauthenticated", Missing: []string{"connectivity"}})
	if len(got) != 0 {
		t.Fatalf("expected no re-fire: %v", got)
	}
}

func TestTransitions_AccessChangeNonFull(t *testing.T) {
	prev := &AuthSnapshot{Access: "unauthenticated", Missing: []string{"connectivity"}}
	got := Transitions(prev, AuthSnapshot{Access: "degraded", Missing: []string{"connectivity"}})
	// credentials still present, access changed → credentials_test_failed
	if len(got) != 1 || got[0] != "credentials_test_failed" {
		t.Fatalf("got %v", got)
	}
}

func TestWrite_AgainstRealPostgres(t *testing.T) {
	if testing.Short() {
		t.Skip("docker")
	}
	ctx := context.Background()
	pg, err := postgres.Run(ctx, "postgres:16-alpine",
		postgres.WithDatabase("rca_agent"),
		postgres.WithUsername("rca_agent"),
		postgres.WithPassword("rca_agent"),
		testcontainers.WithWaitStrategy(
			tcwait.ForLog("database system is ready to accept connections").WithOccurrence(2).WithStartupTimeout(60*time.Second),
		),
	)
	if err != nil {
		t.Fatalf("pg: %v", err)
	}
	t.Cleanup(func() { _ = pg.Terminate(ctx) })
	dsn, err := pg.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	_, thisFile, _, _ := runtime.Caller(0)
	root := filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", "..", "..", ".."))
	rca := filepath.Join(root, "libs", "py", "rca_common")
	py := filepath.Join(rca, ".venv", "bin", "python")
	alembicDSN := strings.Replace(dsn, "postgres://", "postgresql+psycopg2://", 1)
	cmd := exec.Command(py, "-m", "alembic", "upgrade", "head")
	cmd.Dir = rca
	cmd.Env = append(os.Environ(), "RCA_PG_DSN="+alembicDSN)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("migrate: %v\n%s", err, out)
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	err = Write(ctx, db, "credentials_detected", "probe:p1", "pk", map[string]any{
		"platform_key": "pk", "auth_scheme": "PASSWORD", "access": "full", "missing": []string{},
	})
	if err != nil {
		t.Fatal(err)
	}
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM audit_log WHERE action='credentials_detected'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("rows=%d", n)
	}

	// marshal error path
	if err := Write(ctx, db, "credentials_verified", "probe:p1", "pk", make(chan int)); err == nil {
		t.Fatal("expected marshal error")
	}
}
