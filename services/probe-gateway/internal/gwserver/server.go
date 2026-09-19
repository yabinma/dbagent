// Package gwserver implements the `ProbeGateway.Session` bidirectional
// stream (proto/rcaprobe/v1/probe.proto, design.md Appendix A/Section
// 8.4): registration, heartbeat tracking (+ offline-after-60s detection),
// task dispatch with chunked-result reassembly, `CancelTask`, and
// `ManifestRefresh` broadcast. This is probe-gateway's "heartbeat/
// registry maintenance" + connection-termination responsibility (design.md
// Section 3.2).
package gwserver

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"

	rcaprobev1 "github.com/yabinma/dbagent/gen/go/rcaprobe/v1"
	"github.com/yabinma/dbagent/services/probe-gateway/internal/audit"
	"github.com/yabinma/dbagent/services/probe-gateway/internal/registry"
)

var (
	ErrProbeNotConnected = errors.New("gwserver: no active session for platform")
	ErrTaskTimeout       = errors.New("gwserver: task dispatch timed out")
	ErrChunkIntegrity    = errors.New("gwserver: chunk_count mismatch on reassembly")
)

const (
	DefaultHeartbeatTimeout = 60 * time.Second
	outboundBufferSize      = 32
)

type taskOutcome struct {
	result *rcaprobev1.TaskResult
	data   []byte
	err    error
}

type sessionHandle struct {
	probeID     string
	platformKey string
	outbound    chan *rcaprobev1.GatewayMessage
	closeOnce   sync.Once
	done        chan struct{}

	mu            sync.Mutex
	lastHeartbeat time.Time
	pending       map[string]chan taskOutcome
	chunks        map[string]map[uint32][]byte
	lastKeySent   []byte // key last handed in RegisterAck / key-update (§9.6.5)
}

func newSessionHandle(probeID, platformKey string) *sessionHandle {
	return &sessionHandle{
		probeID:     probeID,
		platformKey: platformKey,
		outbound:    make(chan *rcaprobev1.GatewayMessage, outboundBufferSize),
		done:        make(chan struct{}),
		pending:     map[string]chan taskOutcome{},
		chunks:      map[string]map[uint32][]byte{},
	}
}

func (h *sessionHandle) close() {
	h.closeOnce.Do(func() { close(h.done) })
}

func (h *sessionHandle) touchHeartbeat(at time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.lastHeartbeat = at
}

func (h *sessionHandle) getHeartbeat() time.Time {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.lastHeartbeat
}

func (h *sessionHandle) registerPending(taskID string) chan taskOutcome {
	ch := make(chan taskOutcome, 1)
	h.mu.Lock()
	h.pending[taskID] = ch
	h.mu.Unlock()
	return ch
}

func (h *sessionHandle) unregisterPending(taskID string) {
	h.mu.Lock()
	delete(h.pending, taskID)
	delete(h.chunks, taskID)
	h.mu.Unlock()
}

func (h *sessionHandle) receiveChunk(chunk *rcaprobev1.TaskOutputChunk) {
	h.mu.Lock()
	defer h.mu.Unlock()
	m, ok := h.chunks[chunk.GetTaskId()]
	if !ok {
		m = map[uint32][]byte{}
		h.chunks[chunk.GetTaskId()] = m
	}
	m[chunk.GetSeq()] = chunk.GetData()
}

func (h *sessionHandle) receiveResult(result *rcaprobev1.TaskResult) {
	h.mu.Lock()
	ch, ok := h.pending[result.GetTaskId()]
	chunkMap := h.chunks[result.GetTaskId()]
	h.mu.Unlock()
	if !ok {
		return // no one waiting (e.g. dispatcher timed out already)
	}

	data, err := reassembleChunks(chunkMap, result.GetChunkCount())
	ch <- taskOutcome{result: result, data: data, err: err}
}

func reassembleChunks(chunkMap map[uint32][]byte, expectedCount uint32) ([]byte, error) {
	if uint32(len(chunkMap)) != expectedCount {
		return nil, fmt.Errorf("%w: got %d chunks, expected %d", ErrChunkIntegrity, len(chunkMap), expectedCount)
	}
	seqs := make([]uint32, 0, len(chunkMap))
	for seq := range chunkMap {
		seqs = append(seqs, seq)
	}
	sort.Slice(seqs, func(i, j int) bool { return seqs[i] < seqs[j] })
	for i, seq := range seqs {
		if uint32(i) != seq {
			return nil, fmt.Errorf("%w: missing chunk seq %d", ErrChunkIntegrity, i)
		}
	}
	var out []byte
	for _, seq := range seqs {
		out = append(out, chunkMap[seq]...)
	}
	return out, nil
}

// platformStatusFromAuth maps a reported AuthStatus (design.md Appendix A
// Capabilities.AuthStatus, computed probe-side by the PlatformAdapter's
// Detect()) onto the platforms.status enum (design.md Section 4.3:
// "created|pending_credentials|degraded|online|offline") -- this mapping
// is the actual substance of registration flow steps 5a/5b/6/8 (Section
// 8.4): "full" access means the connectivity test passed, so the platform
// is usable (ONLINE); missing credentials/CA means the operator still has
// setup to do (PENDING_CREDENTIALS, so the dashboard can render guidance);
// anything else (KERBEROS "unsupported", or a live connectivity failure
// despite credentials being present) is DEGRADED rather than either
// extreme.
func platformStatusFromAuth(auth *rcaprobev1.AuthStatus) registry.PlatformStatus {
	if auth == nil {
		return registry.PlatformDegraded
	}
	if auth.GetAccess() == "full" {
		return registry.PlatformOnline
	}
	for _, missing := range auth.GetMissing() {
		if missing == "credentials" || missing == "tls_ca" {
			return registry.PlatformPendingCredentials
		}
	}
	return registry.PlatformDegraded
}

// capabilitiesToMap converts the wire Capabilities message into the plain
// map persisted in probes.capabilities (design.md Section 4.3: "manifest
// incl. AuthStatus").
func capabilitiesToMap(caps *rcaprobev1.Capabilities) map[string]any {
	if caps == nil {
		return map[string]any{}
	}
	tools := make([]map[string]any, 0, len(caps.GetTools()))
	for _, t := range caps.GetTools() {
		tools = append(tools, map[string]any{
			"name": t.GetName(), "category": t.GetCategory(), "params_schema_json": t.GetParamsSchemaJson(),
		})
	}
	auth := map[string]any{}
	if a := caps.GetAuth(); a != nil {
		auth = map[string]any{
			"scheme": a.GetScheme(), "https": a.GetHttps(), "access": a.GetAccess(), "missing": a.GetMissing(),
		}
	}
	return map[string]any{
		"platform_type":  caps.GetPlatformType(),
		"deployment":     caps.GetDeployment(),
		"engine_version": caps.GetEngineVersion(),
		"tools":          tools,
		"write_ops":      caps.GetWriteOps(),
		"auth":           auth,
	}
}

// Server implements rcaprobev1.ProbeGatewayServer.
type Server struct {
	rcaprobev1.UnimplementedProbeGatewayServer

	Registry         registry.Registry
	GatewayReplica   string
	HeartbeatTimeout time.Duration

	// AuditDB is the optional Postgres handle used for credentials_* audit
	// rows (FP-M6-25). Nil means "auditing not wired" — a silent no-op used
	// by every Fake-registry unit test. Set from main via registry.PG.DB.
	AuditDB *sql.DB

	mu                 sync.Mutex
	sessionsByPlatform map[string]*sessionHandle
	signingPublicKey   []byte // control-plane's current ed25519 public key (D14, embedded in RegisterAck)

	// admitHook, when non-nil, is called by admitSession while it still holds
	// s.mu, after the key this session will be admitted with has been captured
	// and before that key has been recorded or its RegisterAck enqueued. It is
	// nil in production and exists for exactly one reason: the atomicity of this
	// function is a property of an *interleaving*, and an interleaving the
	// implementation is required to make impossible cannot be produced by a real
	// race — a test that merely spawned a rotation goroutine and hoped for the
	// right ordering would pass against a non-atomic implementation whenever the
	// scheduler was kind, which is most of the time (design.md §9.6.7, FP-KR-26).
	admitHook func()
}

func New(reg registry.Registry, signingPublicKey []byte, gatewayReplica string) *Server {
	return &Server{
		Registry:           reg,
		signingPublicKey:   signingPublicKey,
		GatewayReplica:     gatewayReplica,
		HeartbeatTimeout:   DefaultHeartbeatTimeout,
		sessionsByPlatform: map[string]*sessionHandle{},
	}
}

// SetSigningPublicKey publishes the key future admission RegisterAcks carry.
// A rotation reaches already-connected sessions when pollSigningKey calls
// this setter and then PropagateSigningKey (§9.6.5), which pushes the new
// key to each connected session as a mid-session RegisterAck (Appendix A.2).
// Safe for concurrent use with Session().
func (s *Server) SetSigningPublicKey(key []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.signingPublicKey = key
}

func (s *Server) getSigningPublicKey() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.signingPublicKey
}

// verifyClientCertCN enforces design.md Section 8.4a's identity binding:
// a Session registration's Register.platform_key MUST equal the CN of
// the mTLS client certificate that authenticated this connection --
// otherwise a certificate issued for one platform could be used to
// register (or, via Bootstrap.Enroll's renewal path on this same
// listener, renew) as another. Returns nil (no-op) when the connection
// carries no TLS peer info at all: the production Session listener
// (services/probe-gateway/cmd/probe-gateway's runSessionListener) always
// configures tls.RequireAndVerifyClientCert, so a connection without a
// verified client certificate can never reach this handler in practice;
// this makes the check a pure no-op rather than a false rejection for
// this package's own plaintext-bufconn unit tests that exercise
// unrelated business logic.
func verifyClientCertCN(ctx context.Context, platformKey string) error {
	p, ok := peer.FromContext(ctx)
	if !ok || p.AuthInfo == nil {
		return nil
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok || len(tlsInfo.State.PeerCertificates) == 0 {
		return nil
	}
	cn := tlsInfo.State.PeerCertificates[0].Subject.CommonName
	if cn != platformKey {
		return fmt.Errorf("client certificate CN %q does not match claimed platform_key %q", cn, platformKey)
	}
	return nil
}

// Session implements the single bidi-stream RPC (design.md Appendix A:
// "The probe initiates one outbound bidirectional stream ... and keeps
// it open. All task dispatch and results flow over this session.").
func (s *Server) Session(stream rcaprobev1.ProbeGateway_SessionServer) error {
	first, err := stream.Recv()
	if err != nil {
		return err
	}
	reg := first.GetRegister()
	if reg == nil {
		return fmt.Errorf("gwserver: first frame must be Register")
	}

	// design.md Section 8.4a identity binding (required M3 fix): a
	// certificate issued for one platform must never be able to register
	// (or renew) as another. Reject with a clear reason rather than
	// silently mismatching.
	if err := verifyClientCertCN(stream.Context(), reg.GetPlatformKey()); err != nil {
		ack := &rcaprobev1.GatewayMessage{Msg: &rcaprobev1.GatewayMessage_Ack{
			Ack: &rcaprobev1.RegisterAck{Accepted: false, Reason: err.Error()},
		}}
		_ = stream.Send(ack)
		return fmt.Errorf("gwserver: %w", err)
	}

	platform, err := s.Registry.GetPlatform(stream.Context(), reg.GetPlatformKey())
	if err != nil {
		ack := &rcaprobev1.GatewayMessage{Msg: &rcaprobev1.GatewayMessage_Ack{
			Ack: &rcaprobev1.RegisterAck{Accepted: false, Reason: "unknown platform_key"},
		}}
		_ = stream.Send(ack)
		return fmt.Errorf("gwserver: unknown platform_key %q: %w", reg.GetPlatformKey(), err)
	}

	// probes.probe_id is a UUID column (design.md Section 4.3); reuse the
	// existing probe's UUID on reconnect rather than minting a new one
	// every time (design.md D11: "one probe per Presto cluster").
	probeID := ""
	var prevCaps map[string]any
	if existing, found, ferr := s.Registry.FindProbeByPlatform(stream.Context(), platform.PlatformKey); ferr == nil && found {
		probeID = existing.ProbeID
		prevCaps = existing.Capabilities
	} else {
		probeID = uuid.NewString()
	}
	handle := newSessionHandle(probeID, platform.PlatformKey)

	newCaps := capabilitiesToMap(reg.GetCapabilities())
	if err := s.Registry.UpsertProbe(stream.Context(), registry.Probe{
		ProbeID:        probeID,
		PlatformKey:    platform.PlatformKey,
		Version:        reg.GetProbeVersion(),
		Capabilities:   newCaps,
		Status:         registry.ProbeOnline,
		GatewayReplica: s.GatewayReplica,
		LastHeartbeat:  time.Now().UTC(),
	}); err != nil {
		return fmt.Errorf("gwserver: upsert probe: %w", err)
	}
	handle.touchHeartbeat(time.Now().UTC())

	// design.md Section 8.4 steps 4-8: the manifest's AuthStatus is what
	// actually drives the platform's ONLINE/PENDING_CREDENTIALS/DEGRADED
	// state -- computing and persisting it here (not just the probe's own
	// online/offline status above) is the whole point of the registration
	// flow. Non-fatal on failure: the session still proceeds (a transient
	// registry error here shouldn't drop an otherwise-good connection).
	newStatus := platformStatusFromAuth(reg.GetCapabilities().GetAuth())
	if err := s.Registry.UpdatePlatformStatus(stream.Context(), platform.PlatformKey, newStatus); err != nil {
		log.Printf("gwserver: update platform status for %s: %v", platform.PlatformKey, err)
	}
	// FP-M6-25: emit credentials_* audit rows on AuthStatus transitions.
	s.emitCredentialAudits(stream.Context(), probeID, platform.PlatformKey, prevCaps, reg.GetCapabilities().GetAuth())

	writerErr := make(chan error, 1)
	go func() {
		for {
			select {
			case <-handle.done:
				writerErr <- nil
				return
			case msg, ok := <-handle.outbound:
				if !ok {
					writerErr <- nil
					return
				}
				if err := stream.Send(msg); err != nil {
					writerErr <- err
					return
				}
			}
		}
	}()

	// admitSession publishes the handle and enqueues the first RegisterAck
	// under one s.mu hold so a concurrent rotation cannot regress the key
	// sequence (design.md §9.6.5 / Appendix A.2 rule 9).
	s.admitSession(platform.PlatformKey, handle, probeID)
	defer func() {
		s.mu.Lock()
		if s.sessionsByPlatform[platform.PlatformKey] == handle {
			delete(s.sessionsByPlatform, platform.PlatformKey)
		}
		s.mu.Unlock()
		handle.close()

		// The TCP/mTLS connection is now definitely gone (whether from a
		// clean shutdown or a crash/network partition) -- mark the probe
		// offline immediately rather than waiting for the heartbeat-timeout
		// reaper (CheckStaleProbes), which only catches the rarer case of a
		// session that's still technically connected but has gone silent.
		// Use context.Background() since stream.Context() is already
		// cancelled/done at this point.
		if err := s.Registry.UpdateProbeStatus(context.Background(), probeID, registry.ProbeOffline); err != nil {
			log.Printf("gwserver: mark probe %s offline on disconnect: %v", probeID, err)
		}
	}()

	for {
		msg, err := stream.Recv()
		if err != nil {
			handle.close()
			if err == io.EOF || stream.Context().Err() != nil {
				return nil
			}
			return err
		}
		switch m := msg.Msg.(type) {
		case *rcaprobev1.ProbeMessage_Heartbeat:
			handle.touchHeartbeat(time.Now().UTC())
			if uerr := s.Registry.UpdateProbeHeartbeat(stream.Context(), probeID, time.Now().UTC()); uerr != nil {
				log.Printf("gwserver: update heartbeat for %s: %v", probeID, uerr)
			}
		case *rcaprobev1.ProbeMessage_Chunk:
			handle.receiveChunk(m.Chunk)
		case *rcaprobev1.ProbeMessage_Result:
			handle.receiveResult(m.Result)
		case *rcaprobev1.ProbeMessage_Register:
			// Re-registration mid-session (e.g. after a ManifestRefresh
			// re-Detect): update capabilities + platform status + credential
			// audits; no new RegisterAck needed.
			s.handleMidSessionRegister(stream.Context(), probeID, platform.PlatformKey, m.Register)
		}
	}
}

// handleMidSessionRegister updates capabilities/status and fires credential
// audits when a probe re-Detects after ManifestRefresh (FP-M6-25). No new
// RegisterAck is sent: key delivery is the gateway-push path
// (PropagateSigningKey / Appendix A.2), never a reply to re-registration
// (design.md §9.6.2 leaves this deliberate; A.2 rule 7).
func (s *Server) handleMidSessionRegister(ctx context.Context, probeID, platformKey string, reg *rcaprobev1.Register) {
	if reg == nil {
		return
	}
	var prevCaps map[string]any
	if existing, found, err := s.Registry.FindProbeByPlatform(ctx, platformKey); err == nil && found {
		prevCaps = existing.Capabilities
	}
	newCaps := capabilitiesToMap(reg.GetCapabilities())
	if err := s.Registry.UpsertProbe(ctx, registry.Probe{
		ProbeID:        probeID,
		PlatformKey:    platformKey,
		Version:        reg.GetProbeVersion(),
		Capabilities:   newCaps,
		Status:         registry.ProbeOnline,
		GatewayReplica: s.GatewayReplica,
		LastHeartbeat:  time.Now().UTC(),
	}); err != nil {
		log.Printf("gwserver: mid-session upsert probe %s: %v", probeID, err)
	}
	newStatus := platformStatusFromAuth(reg.GetCapabilities().GetAuth())
	if err := s.Registry.UpdatePlatformStatus(ctx, platformKey, newStatus); err != nil {
		log.Printf("gwserver: mid-session update platform status for %s: %v", platformKey, err)
	}
	s.emitCredentialAudits(ctx, probeID, platformKey, prevCaps, reg.GetCapabilities().GetAuth())
}

// emitCredentialAudits writes transition-driven credentials_* audit rows.
// Non-fatal on error (same posture as UpdatePlatformStatus).
func (s *Server) emitCredentialAudits(ctx context.Context, probeID, platformKey string, prevCaps map[string]any, auth *rcaprobev1.AuthStatus) {
	if s.AuditDB == nil || auth == nil {
		return
	}
	curr := audit.AuthSnapshot{
		Scheme:  auth.GetScheme(),
		Access:  auth.GetAccess(),
		Missing: auth.GetMissing(),
	}
	var prev *audit.AuthSnapshot
	if prevCaps != nil {
		if a, ok := prevCaps["auth"].(map[string]any); ok {
			ps := audit.AuthSnapshot{}
			if v, ok := a["scheme"].(string); ok {
				ps.Scheme = v
			}
			if v, ok := a["access"].(string); ok {
				ps.Access = v
			}
			if raw, ok := a["missing"].([]any); ok {
				for _, m := range raw {
					if s, ok := m.(string); ok {
						ps.Missing = append(ps.Missing, s)
					}
				}
			} else if raw, ok := a["missing"].([]string); ok {
				ps.Missing = raw
			}
			prev = &ps
		}
	}
	detail := map[string]any{
		"platform_key": platformKey,
		"auth_scheme":  curr.Scheme,
		"access":       curr.Access,
		"missing":      curr.Missing,
	}
	actor := "probe:" + probeID
	for _, action := range audit.Transitions(prev, curr) {
		if err := audit.Write(ctx, s.AuditDB, action, actor, platformKey, detail); err != nil {
			log.Printf("gwserver: audit %s for %s: %v", action, platformKey, err)
		}
	}
}

// Dispatch sends a TaskRequest to the probe currently connected for
// platformKey and waits for its (possibly chunked) TaskResult. This is
// probe-gateway's internal "ExecuteTool" capability (design.md Section
// 3.2); wiring it up as a cross-language API temporal-worker Activities
// can call is M3 scope (see services/probe-gateway/internal/dispatch and
// impl-progress.md) since no Activity exists yet to call it.
func (s *Server) Dispatch(ctx context.Context, platformKey string, task *rcaprobev1.TaskRequest) (*rcaprobev1.TaskResult, []byte, error) {
	handle := s.lookup(platformKey)
	if handle == nil {
		return nil, nil, ErrProbeNotConnected
	}

	outcomeCh := handle.registerPending(task.GetTaskId())
	defer handle.unregisterPending(task.GetTaskId())

	select {
	case handle.outbound <- &rcaprobev1.GatewayMessage{Msg: &rcaprobev1.GatewayMessage_Task{Task: task}}:
	case <-handle.done:
		return nil, nil, ErrProbeNotConnected
	}

	timeout := time.Duration(task.GetTimeoutSeconds()) * time.Second
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case outcome := <-outcomeCh:
		return outcome.result, outcome.data, outcome.err
	case <-handle.done:
		return nil, nil, ErrProbeNotConnected
	case <-ctx.Done():
		if err := s.CancelTask(platformKey, task.GetTaskId()); err != nil && !errors.Is(err, ErrProbeNotConnected) {
			log.Printf("gwserver: CancelTask after context done: %v", err)
		}
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return &rcaprobev1.TaskResult{
				TaskId:   task.GetTaskId(),
				ExitCode: 1,
				Error:    ErrTaskTimeout.Error(),
			}, nil, nil
		}
		return nil, nil, ctx.Err()
	case <-timer.C:
		if err := s.CancelTask(platformKey, task.GetTaskId()); err != nil && !errors.Is(err, ErrProbeNotConnected) {
			log.Printf("gwserver: CancelTask after dispatch timeout: %v", err)
		}
		return &rcaprobev1.TaskResult{
			TaskId:   task.GetTaskId(),
			ExitCode: 1,
			Error:    ErrTaskTimeout.Error(),
		}, nil, nil
	}
}

// CancelTask sends a CancelTask frame to the probe connected for
// platformKey (design.md Appendix A CancelTask).
func (s *Server) CancelTask(platformKey, taskID string) error {
	handle := s.lookup(platformKey)
	if handle == nil {
		return ErrProbeNotConnected
	}
	select {
	case handle.outbound <- &rcaprobev1.GatewayMessage{Msg: &rcaprobev1.GatewayMessage_Cancel{Cancel: &rcaprobev1.CancelTask{TaskId: taskID}}}:
		return nil
	case <-handle.done:
		return ErrProbeNotConnected
	}
}

// RefreshManifest sends ManifestRefresh to the probe connected for
// platformKey (design.md Section 8.4: "the gateway can force a re-run
// via ManifestRefresh").
func (s *Server) RefreshManifest(platformKey string) error {
	handle := s.lookup(platformKey)
	if handle == nil {
		return ErrProbeNotConnected
	}
	select {
	case handle.outbound <- &rcaprobev1.GatewayMessage{Msg: &rcaprobev1.GatewayMessage_Refresh{Refresh: &rcaprobev1.ManifestRefresh{}}}:
		return nil
	case <-handle.done:
		return ErrProbeNotConnected
	}
}

// BroadcastManifestRefresh sends ManifestRefresh to every connected probe.
func (s *Server) BroadcastManifestRefresh() {
	s.mu.Lock()
	platforms := make([]string, 0, len(s.sessionsByPlatform))
	for k := range s.sessionsByPlatform {
		platforms = append(platforms, k)
	}
	s.mu.Unlock()
	for _, k := range platforms {
		_ = s.RefreshManifest(k)
	}
}

func (s *Server) lookup(platformKey string) *sessionHandle {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sessionsByPlatform[platformKey]
}

// ConnectedPlatforms returns the platform_keys with an active session
// (used by tests and by ReapStaleProbes).
func (s *Server) ConnectedPlatforms() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.sessionsByPlatform))
	for k := range s.sessionsByPlatform {
		out = append(out, k)
	}
	return out
}

// CheckStaleProbes marks any probe whose last heartbeat is older than
// now-HeartbeatTimeout as offline in the registry (design.md Appendix A:
// "the gateway marks a probe offline after 60s without a heartbeat").
// Split out from a ticker loop (ReapStaleProbes) for deterministic unit
// testing, mirroring probe/internal/credentials.Watcher's checkOnce
// pattern.
func (s *Server) CheckStaleProbes(ctx context.Context, now time.Time) {
	s.mu.Lock()
	handles := make([]*sessionHandle, 0, len(s.sessionsByPlatform))
	for _, h := range s.sessionsByPlatform {
		handles = append(handles, h)
	}
	s.mu.Unlock()

	cutoff := now.Add(-s.HeartbeatTimeout)
	for _, h := range handles {
		if h.getHeartbeat().Before(cutoff) {
			if err := s.Registry.UpdateProbeStatus(ctx, h.probeID, registry.ProbeOffline); err != nil {
				log.Printf("gwserver: mark probe %s offline: %v", h.probeID, err)
			}
		}
	}
}

// ReapStaleProbes runs CheckStaleProbes on a ticker until ctx is done.
func (s *Server) ReapStaleProbes(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			s.CheckStaleProbes(ctx, now)
		}
	}
}
