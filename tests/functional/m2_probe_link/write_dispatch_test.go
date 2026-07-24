// M5 closed-loop cross-process write path (design.md §9.5.5 FP-M5-1 /
// FP-M5-2 / FP-M5-12): real compiled probe + probe-gateway binaries as OS
// subprocesses over real mTLS, with a real Python-signed RemediationStep
// posted to the gateway's internal HTTP ExecuteTool API
// (POST /internal/v1/execute kind=write). Platform externals (Presto REST,
// Docker Engine API) stay httptest-faked per Section 14.1.
//
// This is the M2 F8/F9 subprocess pattern applied to the write channel —
// the tractable sign-off bar from review W3: one signed presto_kill_query
// that (a) passes writeops.VerifyStep on the real probe, (b) hits the fake
// Presto DELETE, and (c) returns WriteResult OK=true. A second subtest
// asserts signature rejection (FP-M5-2) on the same wire.
package m2_probe_link

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// startFakePrestoWithKill extends startFakePresto with DELETE /v1/query/{id}
// recording so we can assert the write primitive landed on Presto.
type fakePrestoKill struct {
	Server  *httptest.Server
	mu      sync.Mutex
	Deleted []string
}

func startFakePrestoWithKill(t *testing.T) *fakePrestoKill {
	t.Helper()
	fp := &fakePrestoKill{}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/info", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"nodeVersion":{"version":"0.298"},"coordinator":true}`))
	})
	mux.HandleFunc("/v1/statement", func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]any{
			"columns": []map[string]string{{"name": "node_id"}},
			"data":    [][]any{{"n1"}},
			"stats":   map[string]string{"state": "FINISHED"},
		}
		enc, _ := json.Marshal(resp)
		w.Write(enc)
	})
	mux.HandleFunc("/v1/query/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		id := strings.TrimPrefix(r.URL.Path, "/v1/query/")
		fp.mu.Lock()
		fp.Deleted = append(fp.Deleted, id)
		fp.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	})
	fp.Server = httptest.NewServer(mux)
	t.Cleanup(fp.Server.Close)
	return fp
}

func (fp *fakePrestoKill) deletedIDs() []string {
	fp.mu.Lock()
	defer fp.mu.Unlock()
	out := make([]string, len(fp.Deleted))
	copy(out, fp.Deleted)
	return out
}

// bootstrapPythonSigningKey runs the real control-plane D14 bootstrap
// (rca_common.signing.signer.bootstrap_signing_key) so the private key and
// `{path}.pub` sidecar match production. Returns the private-key path; the
// public sidecar is path+".pub".
func bootstrapPythonSigningKey(t *testing.T, root, keyPath string) {
	t.Helper()
	pythonBin := filepath.Join(root, "libs", "py", "rca_common", ".venv", "bin", "python")
	script := `
import sys
from rca_common.signing.signer import bootstrap_signing_key
bootstrap_signing_key(sys.argv[1])
print("ok")
`
	cmd := exec.Command(pythonBin, "-c", script, keyPath)
	cmd.Dir = filepath.Join(root, "libs", "py", "rca_common")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("bootstrap_signing_key via Python: %v\n%s", err, out)
	}
}

// pythonSignStep signs a RemediationStep with the real Python control-plane
// signer (canonical_step_hash + ed25519). Returns standard base64 of the
// 64-byte signature — the exact wire form HTTPProbeGatewayClient sends as
// control_plane_signature.
func pythonSignStep(t *testing.T, root, keyPath, executionID, playbookID string, stepIndex int, op string, params map[string]any) string {
	t.Helper()
	pythonBin := filepath.Join(root, "libs", "py", "rca_common", ".venv", "bin", "python")
	paramsJSON, err := json.Marshal(params)
	if err != nil {
		t.Fatalf("marshal params: %v", err)
	}
	script := `
import base64, json, sys
from rca_common.signing.signer import MountedEd25519Signer, canonical_step_hash
key_path, execution_id, playbook_id, step_index, op, params_json = sys.argv[1:7]
signer = MountedEd25519Signer.load(key_path)
params = json.loads(params_json)
msg = canonical_step_hash(execution_id, playbook_id, int(step_index), op, params)
sig = signer.sign(msg)
print(base64.b64encode(sig).decode())
`
	cmd := exec.Command(pythonBin, "-c", script,
		keyPath, executionID, playbookID, fmt.Sprintf("%d", stepIndex), op, string(paramsJSON),
	)
	cmd.Dir = filepath.Join(root, "libs", "py", "rca_common")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("python sign step: %v\n%s", err, out)
	}
	return strings.TrimSpace(string(out))
}

type executeWriteResponse struct {
	TaskID   string         `json:"task_id"`
	ExitCode int32          `json:"exit_code"`
	Data     map[string]any `json:"data"`
	Error    string         `json:"error"`
}

// postExecuteWrite POSTs kind=write to the real probe-gateway internal
// HTTP surface (same body shape as worker.probeclient.HTTPProbeGatewayClient).
func postExecuteWrite(t *testing.T, internalAddr, platformKey, taskID, playbookID string, stepIndex int, op string, params map[string]any, executionID, sigB64 string) executeWriteResponse {
	t.Helper()
	body := map[string]any{
		"platform_key":             platformKey,
		"task_id":                  taskID,
		"kind":                     "write",
		"timeout_seconds":          30,
		"playbook_id":              playbookID,
		"step_index":               stepIndex,
		"op":                       op,
		"params":                   params,
		"execution_id":             executionID,
		"control_plane_signature":  sigB64,
	}
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal execute body: %v", err)
	}
	url := "http://" + internalAddr + "/internal/v1/execute"
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 20 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST execute: %v", err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("execute HTTP %d: %s", resp.StatusCode, respBody)
	}
	var out executeWriteResponse
	if err := json.Unmarshal(respBody, &out); err != nil {
		t.Fatalf("decode response %s: %v", respBody, err)
	}
	return out
}

// TestM5_CrossProcessSignedWrite_KillQuery is the M5 write-path acceptance
// bar (review W3 / design.md §9.5.5 FP-M5-1+2+12):
//
//	Python control-plane signer
//	  → real probe-gateway POST /internal/v1/execute kind=write
//	  → real probe writeops.VerifyStep + ExecuteWrite(presto_kill_query)
//	  → httptest Presto DELETE /v1/query/{id}
func TestM5_CrossProcessSignedWrite_KillQuery(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping cross-service subprocess test in -short mode")
	}
	dsn, probeBin, gatewayBin := setupSharedInfra(t)
	root, err := filepath.Abs(findRepoRoot())
	if err != nil {
		t.Fatalf("repo root: %v", err)
	}

	// Real D14 keypair via the Python control-plane bootstrap (not a
	// hand-rolled Go key) so the signature is produced by the exact same
	// library production workers use.
	keyDir := t.TempDir()
	keyPath := filepath.Join(keyDir, "ed25519.key")
	bootstrapPythonSigningKey(t, root, keyPath)
	pubPath := keyPath + ".pub"
	if _, err := os.Stat(pubPath); err != nil {
		t.Fatalf("expected public key sidecar at %s: %v", pubPath, err)
	}

	gw := startGatewaySubprocessOpts(t, gatewayBin, dsn, gatewayStartOpts{
		SigningPubKeyPath:  pubPath,
		EnableInternalHTTP: true,
	})
	if gw.internalAddr == "" {
		t.Fatal("expected internal HTTP listener address")
	}

	presto := startFakePrestoWithKill(t)
	docker := startFakeDockerAPI(t, "http-server.authentication.type=NONE\n")

	const platformKey = "presto-m5-write-kill"
	const token = "tok-m5-write-kill"
	seedPlatform(t, dsn, platformKey, token)

	startProbeSubprocess(t, probeBin, probeConfig{
		PlatformKey: platformKey, GatewayAddr: gw.sessionAddr, BootstrapAddr: gw.bootstrapAddr,
		BootstrapToken: token, PrestoURL: presto.Server.URL, DockerAPIURL: docker.URL,
		WriteEnabled: true,
	})
	waitForPlatformStatus(t, dsn, platformKey, "online", 20*time.Second)

	// Give the session a beat to finish RegisterAck key install before the
	// first write dispatch (Detect+Register is async relative to platform
	// status flip in the registry).
	time.Sleep(500 * time.Millisecond)

	const (
		executionID = "exec-m5-cross-process-1"
		playbookID  = "presto.kill_query"
		op          = "presto_kill_query"
		queryID     = "20260724_cross_process_q1"
	)
	params := map[string]any{"query_id": queryID}
	sigB64 := pythonSignStep(t, root, keyPath, executionID, playbookID, 0, op, params)

	// Sanity: signature is valid base64 of 64 bytes (ed25519 sig size).
	sigRaw, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil || len(sigRaw) != 64 {
		t.Fatalf("expected 64-byte base64 signature, got len=%d err=%v", len(sigRaw), err)
	}

	out := postExecuteWrite(t, gw.internalAddr, platformKey, "task-m5-write-1",
		playbookID, 0, op, params, executionID, sigB64)

	if out.ExitCode != 0 {
		t.Fatalf("expected exit_code=0 for signed kill_query, got %d error=%q data=%v",
			out.ExitCode, out.Error, out.Data)
	}
	if out.Error != "" {
		t.Fatalf("unexpected error field: %q", out.Error)
	}
	// platform.WriteResult has no json tags → "OK"/"Detail"/"Error".
	ok, _ := out.Data["OK"].(bool)
	if !ok {
		t.Fatalf("expected WriteResult.OK=true, data=%v", out.Data)
	}

	deleted := presto.deletedIDs()
	if len(deleted) != 1 || deleted[0] != queryID {
		t.Fatalf("expected fake Presto DELETE for %q, got %v", queryID, deleted)
	}
}

// TestM5_CrossProcessWrite_RejectsBadSignature asserts the real probe's
// writeops.VerifyStep rejects a tampered signature over the same wire
// (FP-M5-2 cross-process).
func TestM5_CrossProcessWrite_RejectsBadSignature(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping cross-service subprocess test in -short mode")
	}
	dsn, probeBin, gatewayBin := setupSharedInfra(t)
	root, err := filepath.Abs(findRepoRoot())
	if err != nil {
		t.Fatalf("repo root: %v", err)
	}

	keyDir := t.TempDir()
	keyPath := filepath.Join(keyDir, "ed25519.key")
	bootstrapPythonSigningKey(t, root, keyPath)

	gw := startGatewaySubprocessOpts(t, gatewayBin, dsn, gatewayStartOpts{
		SigningPubKeyPath:  keyPath + ".pub",
		EnableInternalHTTP: true,
	})

	presto := startFakePrestoWithKill(t)
	docker := startFakeDockerAPI(t, "http-server.authentication.type=NONE\n")

	const platformKey = "presto-m5-write-badsig"
	const token = "tok-m5-write-badsig"
	seedPlatform(t, dsn, platformKey, token)

	startProbeSubprocess(t, probeBin, probeConfig{
		PlatformKey: platformKey, GatewayAddr: gw.sessionAddr, BootstrapAddr: gw.bootstrapAddr,
		BootstrapToken: token, PrestoURL: presto.Server.URL, DockerAPIURL: docker.URL,
		WriteEnabled: true,
	})
	waitForPlatformStatus(t, dsn, platformKey, "online", 20*time.Second)
	time.Sleep(500 * time.Millisecond)

	// 64 zero bytes, valid base64 length, invalid signature.
	badSig := base64.StdEncoding.EncodeToString(make([]byte, 64))
	out := postExecuteWrite(t, gw.internalAddr, platformKey, "task-m5-badsig",
		"presto.kill_query", 0, "presto_kill_query",
		map[string]any{"query_id": "should-not-delete"},
		"exec-m5-badsig", badSig)

	if out.ExitCode == 0 {
		t.Fatalf("expected non-zero exit for bad signature, got %d data=%v", out.ExitCode, out.Data)
	}
	if !strings.Contains(strings.ToLower(out.Error), "write rejected") &&
		!strings.Contains(strings.ToLower(out.Error), "signature") {
		t.Fatalf("expected signature-rejection error, got %q", out.Error)
	}
	if len(presto.deletedIDs()) != 0 {
		t.Fatalf("presto must not see DELETE on rejected write, got %v", presto.deletedIDs())
	}
}

// TestM5_CrossProcessWrite_RejectsWhenWriteDisabled asserts write_enabled=false
// on the real probe rejects before ExecuteWrite (FP-M5-2).
func TestM5_CrossProcessWrite_RejectsWhenWriteDisabled(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping cross-service subprocess test in -short mode")
	}
	dsn, probeBin, gatewayBin := setupSharedInfra(t)
	root, err := filepath.Abs(findRepoRoot())
	if err != nil {
		t.Fatalf("repo root: %v", err)
	}

	keyDir := t.TempDir()
	keyPath := filepath.Join(keyDir, "ed25519.key")
	bootstrapPythonSigningKey(t, root, keyPath)

	gw := startGatewaySubprocessOpts(t, gatewayBin, dsn, gatewayStartOpts{
		SigningPubKeyPath:  keyPath + ".pub",
		EnableInternalHTTP: true,
	})

	presto := startFakePrestoWithKill(t)
	docker := startFakeDockerAPI(t, "http-server.authentication.type=NONE\n")

	const platformKey = "presto-m5-write-disabled"
	const token = "tok-m5-write-disabled"
	seedPlatform(t, dsn, platformKey, token)

	// WriteEnabled deliberately false (default).
	startProbeSubprocess(t, probeBin, probeConfig{
		PlatformKey: platformKey, GatewayAddr: gw.sessionAddr, BootstrapAddr: gw.bootstrapAddr,
		BootstrapToken: token, PrestoURL: presto.Server.URL, DockerAPIURL: docker.URL,
		WriteEnabled: false,
	})
	waitForPlatformStatus(t, dsn, platformKey, "online", 20*time.Second)
	time.Sleep(500 * time.Millisecond)

	params := map[string]any{"query_id": "nope"}
	sigB64 := pythonSignStep(t, root, keyPath, "exec-disabled", "presto.kill_query", 0, "presto_kill_query", params)
	out := postExecuteWrite(t, gw.internalAddr, platformKey, "task-m5-disabled",
		"presto.kill_query", 0, "presto_kill_query", params, "exec-disabled", sigB64)

	if out.ExitCode == 0 {
		t.Fatalf("expected non-zero exit when write_enabled=false, got %d data=%v", out.ExitCode, out.Data)
	}
	if !strings.Contains(out.Error, "write_enabled=false") && !strings.Contains(out.Error, "write rejected") {
		t.Fatalf("expected write_enabled rejection, got %q", out.Error)
	}
	if len(presto.deletedIDs()) != 0 {
		t.Fatalf("presto must not see DELETE when write disabled, got %v", presto.deletedIDs())
	}
}
