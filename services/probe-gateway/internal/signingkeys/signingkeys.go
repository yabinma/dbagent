// Package signingkeys reads the control-plane's write-channel signing
// public key (design.md D14: "The public key reaches probes in
// RegisterAck") from the `{key_path}.pub` sidecar file
// `rca_common.signing.signer.bootstrap_signing_key` (Python, M1)
// (re-)writes next to the private key on every run. probe-gateway is
// never given the private key -- deploy manifests are expected to mount
// only the `.pub` file read-only (M6 concern); this package just does the
// base64-decode + hold-old-key-for-rotation-grace-window bookkeeping.
package signingkeys

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

// Reader tracks the current + previous (grace-window) public key,
// refreshed by polling the `.pub` sidecar. This reader picks the rotated
// key up from the file; pollSigningKey publishes it with SetSigningPublicKey
// and pushes it to every connected session with PropagateSigningKey
// (design.md §9.6, Appendix A.2), and probes hold old + new for the grace
// window — while this type keeps the same old+new bookkeeping so
// probe-gateway itself serves the right key in RegisterAck during that
// window.
type Reader struct {
	Path        string
	GraceWindow time.Duration

	mu       sync.RWMutex
	current  []byte
	previous []byte
	rotated  time.Time
}

func NewReader(path string, graceWindow time.Duration) *Reader {
	return &Reader{Path: path, GraceWindow: graceWindow}
}

// Load reads the current public key from disk. If the on-disk key has
// changed since the last successful Load, the previously-held key
// becomes Previous (grace window starts now). A decoded value whose
// length is not ed25519.PublicKeySize is refused without touching
// current/previous/rotated (design.md §9.6.5).
func (r *Reader) Load() error {
	raw, err := os.ReadFile(r.Path)
	if err != nil {
		return fmt.Errorf("signingkeys: read %s: %w", r.Path, err)
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		return fmt.Errorf("signingkeys: decode %s: %w", r.Path, err)
	}
	// Validate before taking r.mu so a bad sidecar never blanks a working key.
	if len(decoded) != ed25519.PublicKeySize {
		return fmt.Errorf("signingkeys: %s: expected a %d-byte ed25519 public key, got %d",
			r.Path, ed25519.PublicKeySize, len(decoded))
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if r.current != nil && string(r.current) != string(decoded) {
		r.previous = r.current
		r.rotated = time.Now()
	}
	r.current = decoded
	return nil
}

// Current returns the current signing public key (nil if Load has never
// succeeded).
func (r *Reader) Current() []byte {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.current
}

// Previous returns the pre-rotation public key, but only while still
// inside the grace window (nil afterwards or if no rotation occurred).
func (r *Reader) Previous() []byte {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.previous == nil {
		return nil
	}
	if time.Since(r.rotated) > r.GraceWindow {
		return nil
	}
	return r.previous
}
