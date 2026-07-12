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
