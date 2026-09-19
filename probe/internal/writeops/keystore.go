package writeops

import (
	"bytes"
	"crypto/ed25519"
	"sync"
	"time"
)

// DefaultGraceWindow is D14's "10-minute grace window".
const DefaultGraceWindow = 10 * time.Minute

// KeyStore holds the control-plane signing public key the probe currently
// trusts and, for GraceWindow after a rotation, the one it previously
// trusted. Safe for concurrent use. Lifetime is the probe process, not a
// single session (design.md §9.6.4a / Appendix A.2 rule 8).
type KeyStore struct {
	grace     time.Duration
	now       func() time.Time // test seam; nil means time.Now
	mu        sync.RWMutex
	current   ed25519.PublicKey
	previous  ed25519.PublicKey
	rotatedAt time.Time
}

// NewKeyStore builds a store with the given grace window. A window of 0
// means "no grace at all" (Previous is never returned from Ring).
func NewKeyStore(grace time.Duration) *KeyStore {
	return &KeyStore{grace: grace}
}

// GraceWindow returns the configured rotation grace duration.
func (s *KeyStore) GraceWindow() time.Duration {
	return s.grace
}

func (s *KeyStore) clock() time.Time {
	if s.now != nil {
		return s.now()
	}
	return time.Now()
}

// Install applies a signing public key according to design.md §9.6.4:
//
//  1. wrong length (incl. nil/empty) → reject, store unchanged, rotated=false
//  2. byte-identical to Current → no-op, do not restart grace, rotated=false
//  3. first install (Current nil) → set Current, Previous stays nil, rotated=false
//  4. otherwise → Previous=old Current, Current=key, grace starts, rotated=true
//
// Slices are replaced, never mutated in place.
func (s *KeyStore) Install(key []byte) (rotated bool) {
	if len(key) != ed25519.PublicKeySize {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if bytes.Equal(s.current, key) {
		return false
	}
	copied := append(ed25519.PublicKey(nil), key...)
	if s.current == nil {
		s.current = copied
		return false
	}
	s.previous = s.current
	s.current = copied
	s.rotatedAt = s.clock()
	return true
}

// Ring returns a KeyRing snapshot with Current always set (when present)
// and Previous only while still inside the grace window — the same
// boundary signingkeys.Reader.Previous uses (`> grace` → nil).
func (s *KeyStore) Ring() KeyRing {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ring := KeyRing{}
	if s.current != nil {
		ring.Current = append(ed25519.PublicKey(nil), s.current...)
	}
	if s.previous != nil && s.grace > 0 && s.clock().Sub(s.rotatedAt) <= s.grace {
		ring.Previous = append(ed25519.PublicKey(nil), s.previous...)
	}
	return ring
}
