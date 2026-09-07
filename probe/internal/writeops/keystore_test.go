package writeops

import (
	"bytes"
	"crypto/ed25519"
	"testing"
	"time"
)

func keyA() ed25519.PublicKey { return bytes.Repeat([]byte("a"), ed25519.PublicKeySize) }
func keyB() ed25519.PublicKey { return bytes.Repeat([]byte("b"), ed25519.PublicKeySize) }
func keyC() ed25519.PublicKey { return bytes.Repeat([]byte("c"), ed25519.PublicKeySize) }

// FP-KR-1
func TestKeyStore_FirstInstallSetsCurrentOnly(t *testing.T) {
	s := NewKeyStore(DefaultGraceWindow)
	a := keyA()
	rotated := s.Install(a)
	if rotated {
		t.Fatal("first install must report rotated=false")
	}
	ring := s.Ring()
	if !bytes.Equal(ring.Current, a) {
		t.Fatalf("Current = %v, want A", ring.Current)
	}
	if ring.Previous != nil {
		t.Fatalf("Previous must be nil on first install, got %v", ring.Previous)
	}
}

// FP-KR-2
func TestKeyStore_ReinstallSameKeyDoesNotRotateOrRestartGrace(t *testing.T) {
	fixed := time.Unix(1_700_000_000, 0)
	s := NewKeyStore(time.Hour)
	s.now = func() time.Time { return fixed }

	s.Install(keyA())
	s.Install(keyB()) // rotation at fixed
	if s.rotatedAt != fixed {
		t.Fatalf("rotatedAt after B install = %v, want %v", s.rotatedAt, fixed)
	}
	// Advance clock; reinstall B must not restart the deadline.
	later := fixed.Add(30 * time.Minute)
	s.now = func() time.Time { return later }
	rotated := s.Install(keyB())
	if rotated {
		t.Fatal("reinstall of identical key must report rotated=false")
	}
	if s.rotatedAt != fixed {
		t.Fatalf("grace deadline restarted: rotatedAt=%v want %v", s.rotatedAt, fixed)
	}
	ring := s.Ring()
	if !bytes.Equal(ring.Current, keyB()) || !bytes.Equal(ring.Previous, keyA()) {
		t.Fatalf("ring after reinstall = {%v, %v}", ring.Current, ring.Previous)
	}
}

// FP-KR-3
func TestKeyStore_InstallRotatesCurrentIntoPrevious(t *testing.T) {
	fixed := time.Unix(1_700_000_000, 0)
	s := NewKeyStore(DefaultGraceWindow)
	s.now = func() time.Time { return fixed }

	s.Install(keyA())
	rotated := s.Install(keyB())
	if !rotated {
		t.Fatal("install of different key must report rotated=true")
	}
	if s.rotatedAt != fixed {
		t.Fatalf("rotatedAt = %v, want %v", s.rotatedAt, fixed)
	}
	ring := s.Ring()
	if !bytes.Equal(ring.Current, keyB()) {
		t.Fatalf("Current = %v, want B", ring.Current)
	}
	if !bytes.Equal(ring.Previous, keyA()) {
		t.Fatalf("Previous = %v, want A", ring.Previous)
	}
}

// FP-KR-4
func TestKeyStore_RingDropsPreviousAfterGraceWindow(t *testing.T) {
	start := time.Unix(1_700_000_000, 0)
	now := start
	s := NewKeyStore(10 * time.Minute)
	s.now = func() time.Time { return now }

	s.Install(keyA())
	s.Install(keyB())

	// Inside window (exactly at grace boundary still includes Previous: <= grace).
	now = start.Add(10 * time.Minute)
	ring := s.Ring()
	if !bytes.Equal(ring.Previous, keyA()) {
		t.Fatalf("Previous must be present at grace boundary, got %v", ring.Previous)
	}
	if !bytes.Equal(ring.Current, keyB()) {
		t.Fatalf("Current must stay B, got %v", ring.Current)
	}

	// Past window.
	now = start.Add(10*time.Minute + time.Nanosecond)
	ring = s.Ring()
	if ring.Previous != nil {
		t.Fatalf("Previous must be nil after grace, got %v", ring.Previous)
	}
	if !bytes.Equal(ring.Current, keyB()) {
		t.Fatalf("Current must stay B after grace, got %v", ring.Current)
	}
}

// FP-KR-5
func TestKeyStore_RejectsMalformedKeyAndKeepsCurrent(t *testing.T) {
	s := NewKeyStore(DefaultGraceWindow)
	s.Install(keyA())

	for _, bad := range [][]byte{nil, {}, bytes.Repeat([]byte("x"), 31), bytes.Repeat([]byte("x"), 33)} {
		rotated := s.Install(bad)
		if rotated {
			t.Fatalf("malformed key %v reported rotated=true", bad)
		}
		ring := s.Ring()
		if !bytes.Equal(ring.Current, keyA()) {
			t.Fatalf("Current changed after malformed install: %v", ring.Current)
		}
		if ring.Previous != nil {
			t.Fatalf("Previous must stay nil, got %v", ring.Previous)
		}
	}

	// After a live rotation, malformed must not blank Previous either.
	s.Install(keyB())
	s.Install(bytes.Repeat([]byte("z"), 31))
	ring := s.Ring()
	if !bytes.Equal(ring.Current, keyB()) || !bytes.Equal(ring.Previous, keyA()) {
		t.Fatalf("malformed wiped rotation state: {%v, %v}", ring.Current, ring.Previous)
	}
	_ = keyC // keep helper available for other packages / future cases
}
