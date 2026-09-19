package writeops

import (
	"crypto/ed25519"
	"encoding/hex"
	"testing"
)

// TestCanonicalStepHash_MatchesPythonReferenceVector cross-checks this
// package's hash against a value independently computed by
// `rca_common.signing.signer.canonical_step_hash` (the control-plane
// implementation, libs/py/rca_common/rca_common/signing/signer.py) for
// the exact same inputs:
//
//	python3 -c "
//	from rca_common.signing.signer import canonical_step_hash
//	h = canonical_step_hash('exec-123', 'presto.kill_query', 0, 'presto_kill_query', {'query_id': 'q1'})
//	print(h.hex())"
//
// This is the byte-layout compatibility this whole package exists to
// guarantee (design.md D14: the probe's Go verifier must reproduce the
// control plane's signing hash exactly).
func TestCanonicalStepHash_MatchesPythonReferenceVector(t *testing.T) {
	const wantHex = "7ea23e3e85f3f9fa1b747f74f83ddf8be777f9d24fd16a1be8c34893a80e80c4"

	got, err := CanonicalStepHash("exec-123", "presto.kill_query", 0, "presto_kill_query", map[string]any{"query_id": "q1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hex.EncodeToString(got) != wantHex {
		t.Fatalf("hash mismatch with Python reference vector:\n got  %s\n want %s", hex.EncodeToString(got), wantHex)
	}
}

func TestCanonicalStepHash_KeyOrderIndependent(t *testing.T) {
	h1, err := CanonicalStepHash("e1", "p1", 2, "op", map[string]any{"a": 1, "b": "x"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	h2, err := CanonicalStepHash("e1", "p1", 2, "op", map[string]any{"b": "x", "a": 1})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hex.EncodeToString(h1) != hex.EncodeToString(h2) {
		t.Fatalf("expected key-order-independent hash")
	}
}

func TestCanonicalStepHash_SensitiveToEveryField(t *testing.T) {
	base := func() ([]byte, error) {
		return CanonicalStepHash("exec-1", "pb-1", 0, "op", map[string]any{"a": 1})
	}
	baseHash, _ := base()

	cases := map[string]func() ([]byte, error){
		"execution_id": func() ([]byte, error) { return CanonicalStepHash("exec-2", "pb-1", 0, "op", map[string]any{"a": 1}) },
		"playbook_id":  func() ([]byte, error) { return CanonicalStepHash("exec-1", "pb-2", 0, "op", map[string]any{"a": 1}) },
		"step_index":   func() ([]byte, error) { return CanonicalStepHash("exec-1", "pb-1", 1, "op", map[string]any{"a": 1}) },
		"op":           func() ([]byte, error) { return CanonicalStepHash("exec-1", "pb-1", 0, "op2", map[string]any{"a": 1}) },
		"params":       func() ([]byte, error) { return CanonicalStepHash("exec-1", "pb-1", 0, "op", map[string]any{"a": 2}) },
	}
	for field, fn := range cases {
		h, err := fn()
		if err != nil {
			t.Fatalf("%s: unexpected error: %v", field, err)
		}
		if hex.EncodeToString(h) == hex.EncodeToString(baseHash) {
			t.Errorf("expected hash to change when %s changes", field)
		}
	}
}

func TestCanonicalStepHash_NilParamsTreatedAsEmptyObject(t *testing.T) {
	h1, err := CanonicalStepHash("e", "p", 0, "op", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	h2, err := CanonicalStepHash("e", "p", 0, "op", map[string]any{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hex.EncodeToString(h1) != hex.EncodeToString(h2) {
		t.Fatalf("expected nil params to hash the same as an empty map")
	}
}

func genKeyPair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return pub, priv
}

func TestKeyRing_VerifyWithCurrentKey(t *testing.T) {
	pub, priv := genKeyPair(t)
	msg := []byte("hello")
	sig := ed25519.Sign(priv, msg)

	ring := KeyRing{Current: pub}
	matched, ok := ring.Verify(msg, sig)
	if !ok || matched != "current" {
		t.Fatalf("expected match on current key, got matched=%q ok=%v", matched, ok)
	}
}

func TestKeyRing_VerifyWithPreviousKeyDuringGraceWindow(t *testing.T) {
	oldPub, oldPriv := genKeyPair(t)
	newPub, _ := genKeyPair(t)
	msg := []byte("hello")
	sig := ed25519.Sign(oldPriv, msg)

	ring := KeyRing{Current: newPub, Previous: oldPub}
	matched, ok := ring.Verify(msg, sig)
	if !ok || matched != "previous" {
		t.Fatalf("expected match on previous key, got matched=%q ok=%v", matched, ok)
	}
}

func TestKeyRing_VerifyFailsWithWrongKey(t *testing.T) {
	_, priv := genKeyPair(t)
	otherPub, _ := genKeyPair(t)
	msg := []byte("hello")
	sig := ed25519.Sign(priv, msg)

	ring := KeyRing{Current: otherPub}
	_, ok := ring.Verify(msg, sig)
	if ok {
		t.Fatalf("expected verification to fail with the wrong key")
	}
}

func TestKeyRing_VerifyFailsAfterGraceWindowExpires(t *testing.T) {
	_, oldPriv := genKeyPair(t)
	newPub, _ := genKeyPair(t)
	msg := []byte("hello")
	sig := ed25519.Sign(oldPriv, msg)

	// Grace window expired: Previous is no longer held.
	ring := KeyRing{Current: newPub, Previous: nil}
	_, ok := ring.Verify(msg, sig)
	if ok {
		t.Fatalf("expected verification to fail once the old key is no longer held")
	}
}

func TestVerifyStep_TamperedMessageFails(t *testing.T) {
	pub, priv := genKeyPair(t)
	hash, _ := CanonicalStepHash("exec-1", "pb-1", 0, "presto_kill_query", map[string]any{"query_id": "q1"})
	sig := ed25519.Sign(priv, hash)

	result := VerifyStep(KeyRing{Current: pub}, true, "exec-1", "pb-1", 0, "presto_kill_query",
		map[string]any{"query_id": "q2"}, // tampered param after signing
		sig,
	)
	if result.OK {
		t.Fatalf("expected tampered step to fail verification")
	}
}

func TestVerifyStep_WriteDisabledShortCircuits(t *testing.T) {
	pub, priv := genKeyPair(t)
	hash, _ := CanonicalStepHash("exec-1", "pb-1", 0, "presto_kill_query", map[string]any{"query_id": "q1"})
	sig := ed25519.Sign(priv, hash)

	result := VerifyStep(KeyRing{Current: pub}, false, "exec-1", "pb-1", 0, "presto_kill_query",
		map[string]any{"query_id": "q1"}, sig)
	if result.OK {
		t.Fatalf("expected write_enabled=false to reject regardless of signature validity")
	}
	if result.Reason == "" {
		t.Fatalf("expected a reason to be populated")
	}
}

func TestVerifyStep_ValidSignatureAndWriteEnabled(t *testing.T) {
	pub, priv := genKeyPair(t)
	params := map[string]any{"query_id": "q1"}
	hash, _ := CanonicalStepHash("exec-1", "pb-1", 3, "presto_kill_query", params)
	sig := ed25519.Sign(priv, hash)

	result := VerifyStep(KeyRing{Current: pub}, true, "exec-1", "pb-1", 3, "presto_kill_query", params, sig)
	if !result.OK || result.KeyMatched != "current" {
		t.Fatalf("expected successful verification, got %+v", result)
	}
}

func TestVerifyStep_GraceWindowOldKeyAccepted(t *testing.T) {
	oldPub, oldPriv := genKeyPair(t)
	newPub, _ := genKeyPair(t)
	params := map[string]any{"query_id": "q1"}
	hash, _ := CanonicalStepHash("exec-1", "pb-1", 0, "presto_kill_query", params)
	sig := ed25519.Sign(oldPriv, hash)

	result := VerifyStep(KeyRing{Current: newPub, Previous: oldPub}, true, "exec-1", "pb-1", 0, "presto_kill_query", params, sig)
	if !result.OK || result.KeyMatched != "previous" {
		t.Fatalf("expected grace-window success on previous key, got %+v", result)
	}
}

func TestMemoryConfigWhitelist_AllowsWhitelistedKeys(t *testing.T) {
	whitelist := []string{"query.max-memory", "memory.heap-headroom-per-node"}
	err := MemoryConfigWhitelist([]string{"query.max-memory"}, whitelist)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestMemoryConfigWhitelist_RejectsNonWhitelistedKey(t *testing.T) {
	whitelist := []string{"query.max-memory"}
	err := MemoryConfigWhitelist([]string{"query.max-memory", "some.other.key"}, whitelist)
	if err == nil {
		t.Fatalf("expected error for non-whitelisted key")
	}
}
