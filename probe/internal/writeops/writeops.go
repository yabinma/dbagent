// Package writeops implements the probe-side half of the write-channel
// signing contract (design.md Section 9.3 / D14 / Appendix A
// RemediationStep): canonical step-hash computation (byte-for-byte
// identical to the control plane's
// `rca_common.signing.signer.canonical_step_hash` -- cross-checked in
// `writeops_test.go`'s TestCanonicalStepHash_MatchesPythonReferenceVector
// against a hash value independently computed by that Python function),
// ed25519 signature verification against the current/previous
// (grace-window) public key, and the final `write_enabled` gate. Full
// write-op *execution* is M5 scope (design.md Section 9); this package
// only implements and tests the "should this RemediationStep be trusted
// at all" decision, which is exactly what design.md Section 14.2 lists as
// an M2 probe unit-test target ("ed25519 signature verify (valid /
// tampered / wrong key / grace-window old key / write_enabled=false)").
package writeops

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/gowebpki/jcs"
)

// CanonicalStepHash reproduces
// `rca_common.signing.signer.canonical_step_hash` exactly:
//
//	sha256(execution_id | playbook_id | step_index | op | RFC8785-canonical-json(params))
//
// with "|" as a literal separator between (not around) the five parts.
func CanonicalStepHash(executionID, playbookID string, stepIndex uint32, op string, params map[string]any) ([]byte, error) {
	canonicalParams, err := canonicalizeParams(params)
	if err != nil {
		return nil, fmt.Errorf("writeops: canonicalize params: %w", err)
	}
	parts := [][]byte{
		[]byte(executionID),
		[]byte(playbookID),
		[]byte(strconv.FormatUint(uint64(stepIndex), 10)),
		[]byte(op),
		canonicalParams,
	}
	h := sha256.New()
	for i, part := range parts {
		if i > 0 {
			h.Write([]byte("|"))
		}
		h.Write(part)
	}
	return h.Sum(nil), nil
}

func canonicalizeParams(params map[string]any) ([]byte, error) {
	if params == nil {
		params = map[string]any{}
	}
	raw, err := json.Marshal(params)
	if err != nil {
		return nil, err
	}
	return jcs.Transform(raw)
}

// KeyRing holds the current signing public key and, during a rotation
// grace window, the previous one too (design.md D14: "probes hold old +
// new public keys for a 10-minute grace window").
type KeyRing struct {
	Current  ed25519.PublicKey
	Previous ed25519.PublicKey // nil when no rotation is in progress
}

// Verify checks a RemediationStep's signature against the hash of its
// fields, trying the current key first and falling back to Previous
// (design.md D14 rotation grace window). Returns which key matched
// ("current" | "previous" | "" on failure) for observability.
func (k KeyRing) Verify(message, signature []byte) (matched string, ok bool) {
	if len(k.Current) == ed25519.PublicKeySize && ed25519.Verify(k.Current, message, signature) {
		return "current", true
	}
	if len(k.Previous) == ed25519.PublicKeySize && ed25519.Verify(k.Previous, message, signature) {
		return "previous", true
	}
	return "", false
}

// VerifyResult is the outcome of VerifyStep -- the full probe-side write
// gate (design.md Section 9.3: "The probe executes a RemediationStep
// only if the signature verifies AND write_enabled=true in its
// deployment.").
type VerifyResult struct {
	OK         bool
	KeyMatched string // "current" | "previous" | ""
	Reason     string // populated when !OK
}

// VerifyStep is the single entry point the session/dispatch layer calls
// before ever invoking PlatformAdapter.ExecuteWrite.
func VerifyStep(keys KeyRing, writeEnabled bool, executionID, playbookID string, stepIndex uint32, op string, params map[string]any, signature []byte) VerifyResult {
	if !writeEnabled {
		return VerifyResult{OK: false, Reason: "write_enabled=false for this deployment"}
	}
	hash, err := CanonicalStepHash(executionID, playbookID, stepIndex, op, params)
	if err != nil {
		return VerifyResult{OK: false, Reason: fmt.Sprintf("canonicalization failed: %v", err)}
	}
	matched, ok := keys.Verify(hash, signature)
	if !ok {
		return VerifyResult{OK: false, Reason: "signature verification failed"}
	}
	return VerifyResult{OK: true, KeyMatched: matched}
}

// MemoryConfigWhitelist enforces design.md Appendix B.5's
// `presto.adjust_memory_config` probe-side parameter whitelist: only
// these keys are ever accepted, regardless of what the control plane
// sends -- defense in depth against a compromised/buggy control plane.
func MemoryConfigWhitelist(patchKeys []string, whitelist []string) error {
	allowed := make(map[string]bool, len(whitelist))
	for _, k := range whitelist {
		allowed[k] = true
	}
	for _, k := range patchKeys {
		if !allowed[k] {
			return fmt.Errorf("writeops: memory config key %q is not in the whitelist", k)
		}
	}
	return nil
}
