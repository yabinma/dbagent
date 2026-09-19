package credentials

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRead_AllPresent(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, dir, UsernameFile, "svc")
	mustWrite(t, dir, PasswordFile, "hunter2")
	mustWrite(t, dir, CAFile, "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----")

	c, err := Read(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !c.HasUsername || !c.HasPassword || !c.HasCA {
		t.Fatalf("expected all present: %+v", c)
	}
	if c.Username != "svc" || c.Password != "hunter2" {
		t.Fatalf("unexpected values: %+v", c)
	}
}

func TestRead_NoneAbsentDirectory(t *testing.T) {
	c, err := Read(filepath.Join(t.TempDir(), "does-not-exist"))
	if err != nil {
		t.Fatalf("expected no error for missing mount dir, got: %v", err)
	}
	if c.HasUsername || c.HasPassword || c.HasCA {
		t.Fatalf("expected nothing present: %+v", c)
	}
}

func TestRead_PartialCredentials(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, dir, UsernameFile, "svc")
	// password absent

	c, err := Read(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !c.HasUsername || c.HasPassword {
		t.Fatalf("unexpected state: %+v", c)
	}
}

func TestMissing_CredentialsOnly(t *testing.T) {
	c := Credentials{}
	missing := c.Missing(false, false)
	if len(missing) != 1 || missing[0] != "credentials" {
		t.Fatalf("unexpected missing: %v", missing)
	}
}

func TestMissing_CredentialsAndTLSCA(t *testing.T) {
	c := Credentials{}
	missing := c.Missing(true, false)
	if len(missing) != 2 || missing[0] != "credentials" || missing[1] != "tls_ca" {
		t.Fatalf("unexpected missing: %v", missing)
	}
}

func TestMissing_NoneWhenComplete(t *testing.T) {
	c := Credentials{HasUsername: true, HasPassword: true, HasCA: true}
	missing := c.Missing(true, false)
	if len(missing) != 0 {
		t.Fatalf("expected no missing items, got %v", missing)
	}
}

func TestMissing_TLSCAResolvedElsewhere(t *testing.T) {
	c := Credentials{HasUsername: true, HasPassword: true}
	missing := c.Missing(true, true) // haveCAFromElsewhere = deployment-param CA
	if len(missing) != 0 {
		t.Fatalf("expected no missing items when CA resolved via deployment param, got %v", missing)
	}
}

func TestWatcher_FiresOnChangeWhenCredentialsAppear(t *testing.T) {
	dir := t.TempDir()
	fired := make(chan struct{}, 1)
	w := NewWatcher(dir, time.Hour, func() { fired <- struct{}{} })

	w.checkOnce() // establishes baseline (absent), should NOT fire
	select {
	case <-fired:
		t.Fatalf("onChange should not fire on the initial baseline check")
	default:
	}

	mustWrite(t, dir, UsernameFile, "svc")
	mustWrite(t, dir, PasswordFile, "hunter2")
	w.checkOnce()

	select {
	case <-fired:
	default:
		t.Fatalf("expected onChange to fire after credentials appeared")
	}
}

func TestWatcher_DoesNotFireWhenNothingChanges(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, dir, UsernameFile, "svc")
	fired := make(chan struct{}, 1)
	w := NewWatcher(dir, time.Hour, func() { fired <- struct{}{} })

	w.checkOnce()
	w.checkOnce()
	w.checkOnce()

	select {
	case <-fired:
		t.Fatalf("onChange should not fire when nothing changed")
	default:
	}
}

func TestWatcher_StartPollsUntilContextCancelled(t *testing.T) {
	dir := t.TempDir()
	fired := make(chan struct{}, 4)
	w := NewWatcher(dir, 20*time.Millisecond, func() {
		select {
		case fired <- struct{}{}:
		default:
		}
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		w.Start(ctx)
		close(done)
	}()

	// Baseline tick happens immediately (no fire); then write credentials
	// so the next poll tick detects a change and fires.
	time.Sleep(10 * time.Millisecond)
	mustWrite(t, dir, UsernameFile, "svc")
	mustWrite(t, dir, PasswordFile, "hunter2")

	select {
	case <-fired:
	case <-time.After(2 * time.Second):
		t.Fatalf("expected onChange to fire via the Start() polling loop")
	}

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("expected Start to return promptly after context cancellation")
	}
}

func mustWrite(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}
