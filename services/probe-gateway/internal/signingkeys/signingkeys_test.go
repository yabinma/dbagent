package signingkeys

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeKey(t *testing.T, path string, raw []byte) {
	t.Helper()
	if err := os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(raw)), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func TestLoad_ReadsAndDecodesKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ed25519.key.pub")
	writeKey(t, path, []byte("0123456789012345678901234567890123456789"[:32]))

	r := NewReader(path, 10*time.Minute)
	if err := r.Load(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(r.Current()) != 32 {
		t.Fatalf("expected 32-byte key, got %d", len(r.Current()))
	}
}

func TestLoad_MissingFile(t *testing.T) {
	r := NewReader(filepath.Join(t.TempDir(), "missing.pub"), time.Minute)
	if err := r.Load(); err == nil {
		t.Fatalf("expected error for missing file")
	}
}

func TestLoad_InvalidBase64(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.pub")
	os.WriteFile(path, []byte("not base64!!!"), 0o644)

	r := NewReader(path, time.Minute)
	if err := r.Load(); err == nil {
		t.Fatalf("expected decode error")
	}
}

func TestLoad_RotationTracksPreviousWithinGraceWindow(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ed25519.key.pub")
	keyA := []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	keyB := []byte("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")

	writeKey(t, path, keyA)
	r := NewReader(path, time.Hour)
	if err := r.Load(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Previous() != nil {
		t.Fatalf("expected no previous key before any rotation")
	}

	writeKey(t, path, keyB)
	if err := r.Load(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(r.Current()) != string(keyB) {
		t.Fatalf("expected current to be the new key")
	}
	if string(r.Previous()) != string(keyA) {
		t.Fatalf("expected previous to be the old key within the grace window")
	}
}

func TestLoad_PreviousExpiresAfterGraceWindow(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ed25519.key.pub")
	keyA := []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	keyB := []byte("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")

	writeKey(t, path, keyA)
	r := NewReader(path, 1*time.Millisecond)
	_ = r.Load()

	writeKey(t, path, keyB)
	_ = r.Load()

	time.Sleep(10 * time.Millisecond)
	if r.Previous() != nil {
		t.Fatalf("expected previous key to expire after the grace window")
	}
}

func TestLoad_NoRotationWhenKeyUnchanged(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ed25519.key.pub")
	keyA := []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	writeKey(t, path, keyA)

	r := NewReader(path, time.Hour)
	_ = r.Load()
	_ = r.Load() // same content again

	if r.Previous() != nil {
		t.Fatalf("expected no rotation when key content is unchanged")
	}
}

// FP-KR-18: malformed load while a rotation deadline is already live must leave
// Current, Previous and rotated exactly as they were.
func TestLoad_RejectsWrongLengthKeyAndKeepsCurrent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ed25519.key.pub")
	keyA := []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	keyB := []byte("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	keyC := []byte("cccccccccccccccccccccccccccccccc")

	r := NewReader(path, time.Hour)
	writeKey(t, path, keyA)
	if err := r.Load(); err != nil {
		t.Fatalf("load A: %v", err)
	}
	writeKey(t, path, keyB)
	if err := r.Load(); err != nil {
		t.Fatalf("load B: %v", err)
	}
	r.mu.RLock()
	rotatedBefore := r.rotated
	r.mu.RUnlock()
	if rotatedBefore.IsZero() {
		t.Fatal("expected a live rotation deadline after A→B")
	}

	// Four distinct malformed fixtures. empty-file is a truly empty file;
	// zero-decoded is non-empty whitespace-only content that trims to the
	// empty string (valid base64 of zero bytes) — distinct from empty-file.
	malformed := []struct {
		name    string
		writeFn func(path string) error
	}{
		{"31-byte", func(path string) error {
			return os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString([]byte("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"))), 0o644)
		}},
		{"33-byte", func(path string) error {
			return os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString([]byte("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"))), 0o644)
		}},
		{"empty-file", func(path string) error {
			return os.WriteFile(path, []byte(""), 0o644)
		}},
		{"zero-decoded", func(path string) error {
			// Non-empty, whitespace-only: TrimSpace → "" → base64 decode → 0 bytes.
			return os.WriteFile(path, []byte("   \n\t  \n"), 0o644)
		}},
	}
	for _, m := range malformed {
		if err := m.writeFn(path); err != nil {
			t.Fatal(err)
		}
		err := r.Load()
		if err == nil {
			t.Fatalf("%s: expected Load error", m.name)
		}
		if string(r.Current()) != string(keyB) {
			t.Fatalf("%s: Current changed to %v", m.name, r.Current())
		}
		if string(r.Previous()) != string(keyA) {
			t.Fatalf("%s: Previous changed to %v", m.name, r.Previous())
		}
		r.mu.RLock()
		rotatedAfter := r.rotated
		r.mu.RUnlock()
		if !rotatedAfter.Equal(rotatedBefore) {
			t.Fatalf("%s: rotated changed from %v to %v", m.name, rotatedBefore, rotatedAfter)
		}
	}

	// Valid C still works afterwards.
	writeKey(t, path, keyC)
	if err := r.Load(); err != nil {
		t.Fatalf("load C: %v", err)
	}
	if string(r.Current()) != string(keyC) || string(r.Previous()) != string(keyB) {
		t.Fatalf("after C: current=%v previous=%v", r.Current(), r.Previous())
	}
	r.mu.RLock()
	rotatedAfterC := r.rotated
	r.mu.RUnlock()
	if !rotatedAfterC.After(rotatedBefore) {
		t.Fatalf("rotated must move on valid C")
	}
}
