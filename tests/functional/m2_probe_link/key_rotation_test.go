package m2_probe_link

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// FP-KR-23 — real probe + real probe-gateway over real mTLS; mid-session
// rotation via .pub sidecar; new key works, old key graced then rejected.
func TestKR_MidSessionRotation_NewKeyAcceptedOldKeyGracedThenRejected(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping cross-service subprocess test in -short mode")
	}
	dsn, probeBin, gatewayBin := setupSharedInfra(t)
	root, err := filepath.Abs(findRepoRoot())
	if err != nil {
		t.Fatalf("repo root: %v", err)
	}

	// Key A: real Python bootstrap; leave private key in place for post-rotation
	// signatures with A.
	keyDirA := t.TempDir()
	keyPathA := filepath.Join(keyDirA, "ed25519.key")
	bootstrapPythonSigningKey(t, root, keyPathA)
	pubPath := keyPathA + ".pub"

	// Key B elsewhere (A's private key file stays put).
	keyDirB := t.TempDir()
	keyPathB := filepath.Join(keyDirB, "ed25519.key")
	bootstrapPythonSigningKey(t, root, keyPathB)
	pubB, err := os.ReadFile(keyPathB + ".pub")
	if err != nil {
		t.Fatalf("read B.pub: %v", err)
	}

	fp := startFakePrestoWithKill(t)
	docker := startFakeDockerAPI(t, "node.environment=production")

	gw := startGatewaySubprocessOpts(t, gatewayBin, dsn, gatewayStartOpts{
		SigningPubKeyPath:      pubPath,
		EnableInternalHTTP:     true,
		SigningKeyPollInterval: "200ms",
	})
	const platformKey = "presto-kr-rotate"
	const token = "tok-kr-rotate"
	seedPlatform(t, dsn, platformKey, token)

	_, probeLog := startProbeSubprocessWithLog(t, probeBin, probeConfig{
		PlatformKey:           platformKey,
		GatewayAddr:           gw.sessionAddr,
		BootstrapAddr:         gw.bootstrapAddr,
		BootstrapToken:        token,
		PrestoURL:             fp.Server.URL,
		DockerAPIURL:          docker.URL,
		WriteEnabled:          true,
		SigningKeyGraceWindow: "30s",
	})
	waitForPlatformStatus(t, dsn, platformKey, "online", 30*time.Second)

	// Sign S_old with A *before* rotating.
	paramsOld := map[string]any{"query_id": "q-old-before"}
	sigOld := pythonSignStep(t, root, keyPathA, "exec-old", "pb-kr", 0, "presto_kill_query", paramsOld)

	// Atomic sidecar replace with B.
	tmp := pubPath + ".tmp"
	if err := os.WriteFile(tmp, pubB, 0o644); err != nil {
		t.Fatalf("write tmp pub: %v", err)
	}
	if err := os.Rename(tmp, pubPath); err != nil {
		t.Fatalf("rename pub: %v", err)
	}

	// Wait for mid-session install log line (sync point).
	deadline := time.Now().Add(10 * time.Second)
	var installedAt time.Time
	for time.Now().Before(deadline) {
		content, err := os.ReadFile(probeLog)
		if err == nil && strings.Contains(string(content), "installed rotated signing public key") {
			installedAt = time.Now()
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if installedAt.IsZero() {
		content, _ := os.ReadFile(probeLog)
		t.Fatalf("probe never logged mid-session key install; log:\n%s", content)
	}
	tInstall := installedAt // T_i

	// (i) new key works.
	paramsNew := map[string]any{"query_id": "q-new-b"}
	sigNew := pythonSignStep(t, root, keyPathB, "exec-new", "pb-kr", 0, "presto_kill_query", paramsNew)
	out := postExecuteWrite(t, gw.internalAddr, platformKey, "task-new", "pb-kr", 0,
		"presto_kill_query", paramsNew, "exec-new", sigNew)
	if out.ExitCode != 0 {
		t.Fatalf("(i) new key write failed: exit=%d err=%s data=%v", out.ExitCode, out.Error, out.Data)
	}
	if !containsID(fp.deletedIDs(), "q-new-b") {
		t.Fatalf("(i) fake Presto did not record q-new-b; deleted=%v", fp.deletedIDs())
	}

	// (ii-a) signature made before rotation still works.
	out = postExecuteWrite(t, gw.internalAddr, platformKey, "task-old", "pb-kr", 0,
		"presto_kill_query", paramsOld, "exec-old", sigOld)
	if out.ExitCode != 0 {
		t.Fatalf("(ii-a) pre-rotation signature failed: exit=%d err=%s", out.ExitCode, out.Error)
	}
	if !containsID(fp.deletedIDs(), "q-old-before") {
		t.Fatalf("(ii-a) missing q-old-before; deleted=%v", fp.deletedIDs())
	}

	// (ii-b) fresh step signed with A after rotation still works (Previous).
	paramsGrace := map[string]any{"query_id": "q-grace-a"}
	sigGrace := pythonSignStep(t, root, keyPathA, "exec-grace", "pb-kr", 0, "presto_kill_query", paramsGrace)
	out = postExecuteWrite(t, gw.internalAddr, platformKey, "task-grace", "pb-kr", 0,
		"presto_kill_query", paramsGrace, "exec-grace", sigGrace)
	if out.ExitCode != 0 {
		t.Fatalf("(ii-b) grace signature failed: exit=%d err=%s", out.ExitCode, out.Error)
	}
	if !containsID(fp.deletedIDs(), "q-grace-a") {
		t.Fatalf("(ii-b) missing q-grace-a; deleted=%v", fp.deletedIDs())
	}

	// (iii) after window, same construction with A is refused for grace expiry alone.
	paramsExp := map[string]any{"query_id": "q-expired-a"}
	sigExp := pythonSignStep(t, root, keyPathA, "exec-exp", "pb-kr", 0, "presto_kill_query", paramsExp)
	time.Sleep(time.Until(tInstall.Add(31 * time.Second)))
	out = postExecuteWrite(t, gw.internalAddr, platformKey, "task-exp", "pb-kr", 0,
		"presto_kill_query", paramsExp, "exec-exp", sigExp)
	if out.ExitCode == 0 {
		t.Fatal("(iii) expected rejection after grace expiry")
	}
	if !strings.Contains(out.Error, "signature verification failed") {
		t.Fatalf("(iii) expected signature verification failed, got %q", out.Error)
	}
	if containsID(fp.deletedIDs(), "q-expired-a") {
		t.Fatal("(iii) fake Presto must not record DELETE for expired step")
	}

	// (iv) write path still healthy with B.
	paramsOk := map[string]any{"query_id": "q-still-ok-b"}
	sigOk := pythonSignStep(t, root, keyPathB, "exec-ok", "pb-kr", 0, "presto_kill_query", paramsOk)
	out = postExecuteWrite(t, gw.internalAddr, platformKey, "task-ok", "pb-kr", 0,
		"presto_kill_query", paramsOk, "exec-ok", sigOk)
	if out.ExitCode != 0 {
		t.Fatalf("(iv) post-expiry B write failed: exit=%d err=%s", out.ExitCode, out.Error)
	}
	if !containsID(fp.deletedIDs(), "q-still-ok-b") {
		t.Fatalf("(iv) missing q-still-ok-b; deleted=%v", fp.deletedIDs())
	}

	// Mid-session: no reconnect.
	content, _ := os.ReadFile(probeLog)
	if strings.Contains(string(content), "probe: reconnecting to") {
		t.Fatal("probe reconnected during mid-session rotation test")
	}
}

func containsID(ids []string, want string) bool {
	for _, id := range ids {
		if id == want {
			return true
		}
	}
	return false
}
