// Package presto implements platform.PlatformAdapter for prestodb
// (design.md Section 8.3: "Presto is the first implementation").
package presto

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"time"

	"github.com/yabinma/dbagent/probe/internal/credentials"
	"github.com/yabinma/dbagent/probe/internal/platform"
	"github.com/yabinma/dbagent/probe/internal/prestoclient"
	"github.com/yabinma/dbagent/probe/internal/toolpack"
)

// Config is the adapter's own (probe-local) configuration -- distinct
// from RuntimeEnv, which is passed into Detect() per design.md Section
// 8.3's interface signature.
type Config struct {
	PlatformKey           string
	CredentialsMountPath  string // default /etc/rca-probe/platform-credentials (D15)
	DeploymentCAPEM       []byte // deployment parameter CA (Section 8.4 TLS resolution order)
	InsecureSkipVerify    bool   // test environments only (Section 8.4 TLS notes)
	HealthQuery           string // per-platform configured health_query (Appendix E)
	EngineVersionOverride string // "else from config" fallback (Section 8.4 step 4), when live detection fails
	WriteEnabled          bool   // deployment flag (Section 8.1); gates WriteOps()/ExecuteWrite()
	ContainerName         string // in-pod/in-task container name for Exec (default "presto")
}

func (c Config) mountPath() string {
	if c.CredentialsMountPath != "" {
		return c.CredentialsMountPath
	}
	return "/etc/rca-probe/platform-credentials"
}

type Adapter struct {
	Cfg Config

	env    platform.RuntimeEnv
	presto *prestoclient.Client

	registry *toolpack.Registry
	funcs    map[string]toolFunc

	lastAuth platform.AuthStatus
	probeID  string
}

func New(cfg Config) *Adapter {
	if cfg.ContainerName == "" {
		cfg.ContainerName = "presto"
	}
	return &Adapter{
		Cfg:      cfg,
		registry: toolpack.NewRegistry(),
		funcs:    map[string]toolFunc{},
	}
}

// SetProbeID records the probe_id assigned by RegisterAck, used to stamp
// ToolResult.ProbeID in the envelope (Section 8.5).
func (a *Adapter) SetProbeID(id string) { a.probeID = id }

// Detect implements platform.PlatformAdapter (design.md Section 8.3/8.4
// step 4): environment + auth-scheme detection, and registers the
// deployment-appropriate tool set.
func (a *Adapter) Detect(ctx context.Context, env platform.RuntimeEnv) (platform.Manifest, error) {
	a.env = env

	configText, err := env.ReadConfig(ctx, "coordinator", "config", "")
	if err != nil {
		return platform.Manifest{}, fmt.Errorf("presto: detect: read coordinator config: %w", err)
	}
	scheme, https := parseAuthConfig(configText)

	baseURL, err := env.CoordinatorBaseURL(ctx)
	if err != nil {
		return platform.Manifest{}, fmt.Errorf("presto: detect: resolve coordinator url: %w", err)
	}

	creds, err := credentials.Read(a.Cfg.mountPath())
	if err != nil {
		return platform.Manifest{}, fmt.Errorf("presto: detect: read credentials: %w", err)
	}

	authStatus := platform.AuthStatus{Scheme: scheme, HTTPS: https}

	tlsConfig := buildTLSConfig(https, resolveCA(a.Cfg.DeploymentCAPEM, creds.CACertPEM, creds.HasCA), a.Cfg.InsecureSkipVerify)
	httpClient := &http.Client{
		Timeout:   30 * time.Second,
		Transport: &http.Transport{TLSClientConfig: tlsConfig},
	}
	a.presto = prestoclient.New(baseURL, httpClient)

	switch scheme {
	case "NONE":
		if err := a.testConnectivity(ctx, false); err == nil {
			authStatus.Access = "full"
		} else {
			authStatus.Access = "unauthenticated"
			authStatus.Missing = []string{"connectivity"}
		}
	case "KERBEROS":
		authStatus.Access = "unsupported"
	case "PASSWORD", "LDAP":
		haveCAFromElsewhere := len(a.Cfg.DeploymentCAPEM) > 0
		missing := creds.Missing(https, haveCAFromElsewhere)
		if len(missing) > 0 {
			authStatus.Access = "unauthenticated"
			authStatus.Missing = missing
			break
		}
		a.presto.Username = creds.Username
		a.presto.Password = creds.Password
		if err := a.testConnectivity(ctx, true); err == nil {
			authStatus.Access = "full"
		} else {
			authStatus.Access = "unauthenticated"
			authStatus.Missing = []string{"connectivity"}
		}
	default:
		authStatus.Access = "unsupported"
	}
	a.lastAuth = authStatus

	version := ""
	if authStatus.Access == "full" {
		if info, err := a.presto.GetJSON(ctx, "/v1/info"); err == nil {
			if m, ok := info.(map[string]any); ok {
				version = extractVersion(m)
			}
		}
	}
	if version == "" {
		version = a.Cfg.EngineVersionOverride
	}

	a.registerTools(env.Kind())

	return platform.Manifest{
		PlatformType:  "presto",
		Deployment:    string(env.Kind()),
		EngineVersion: version,
		Tools:         toolDescriptors(a.registry.List()),
		WriteOps:      writeOpNames(a.WriteOps()),
		Auth:          authStatus,
	}, nil
}

// testConnectivity implements Section 8.4 5a/5b's connectivity test:
// `/v1/info` always, plus one `system.runtime` SQL query when auth is
// required (verifies the SQL/auth channel, not just plain reachability).
func (a *Adapter) testConnectivity(ctx context.Context, alsoTestSQL bool) error {
	if _, err := a.presto.GetJSON(ctx, "/v1/info"); err != nil {
		return err
	}
	if !alsoTestSQL {
		return nil
	}
	res, err := a.presto.Query(ctx, "SELECT node_id FROM system.runtime.nodes LIMIT 1")
	if err != nil {
		return err
	}
	if res.Error != nil {
		return fmt.Errorf("sql channel test failed: %s", res.Error.Message)
	}
	return nil
}

func buildTLSConfig(https bool, caPEM []byte, insecureSkipVerify bool) *tls.Config {
	if !https {
		return nil
	}
	cfg := &tls.Config{InsecureSkipVerify: insecureSkipVerify}
	if len(caPEM) > 0 {
		pool := newCertPoolFromPEM(caPEM)
		if pool != nil {
			cfg.RootCAs = pool
		}
	}
	return cfg
}

func (a *Adapter) registerTools(kind platform.EnvKind) {
	engineTools, _, _ := toolpack.LoadCategory("engine")
	runtimeTools, _, _ := toolpack.LoadCategory("runtime")
	hostTools, _, _ := toolpack.LoadCategory("host")

	a.funcs = map[string]toolFunc{}
	register := func(name, category string, schema map[string]map[string]any, fn toolFunc) {
		a.registry.Register(toolpack.Spec{Name: name, Category: category, ParamsSchema: schema[name]})
		a.funcs[name] = fn
	}

	register("presto_cluster_info", "engine", engineTools, toolPrestoClusterInfo)
	register("presto_nodes", "engine", engineTools, toolPrestoNodes)
	register("presto_list_queries", "engine", engineTools, toolPrestoListQueries)
	register("presto_query_detail", "engine", engineTools, toolPrestoQueryDetail)
	register("presto_query_json_section", "engine", engineTools, toolPrestoQueryJSONSection)
	register("presto_config", "engine", engineTools, toolPrestoConfig)
	register("presto_session_properties", "engine", engineTools, toolPrestoSessionProperties)
	register("presto_jmx", "engine", engineTools, toolPrestoJMX)

	register("resource_usage", "runtime", runtimeTools, toolResourceUsage)
	register("jvm_thread_dump", "host", hostTools, toolJVMThreadDump)
	register("jvm_heap_histo", "host", hostTools, toolJVMHeapHisto)

	if kind == platform.EnvKindSwarm {
		register("container_logs", "runtime", runtimeTools, toolPodOrContainerLogs)
		register("swarm_tasks", "runtime", runtimeTools, toolPodsOrTasks)
		register("docker_inspect", "runtime", runtimeTools, toolDescribeOrInspect)
		register("docker_events", "runtime", runtimeTools, toolEventsK8sOrDocker)
	} else {
		register("pod_logs", "runtime", runtimeTools, toolPodOrContainerLogs)
		register("k8s_pods", "runtime", runtimeTools, toolPodsOrTasks)
		register("k8s_describe", "runtime", runtimeTools, toolDescribeOrInspect)
		register("k8s_events", "runtime", runtimeTools, toolEventsK8sOrDocker)
	}
}

func toolDescriptors(specs []toolpack.Spec) []platform.ToolDescriptor {
	out := make([]platform.ToolDescriptor, 0, len(specs))
	for _, s := range specs {
		schemaJSON, _ := marshalSchema(s.ParamsSchema)
		out = append(out, platform.ToolDescriptor{
			Name:             s.Name,
			ParamsSchemaJSON: schemaJSON,
			Category:         s.Category,
		})
	}
	return out
}

// Tools implements platform.PlatformAdapter. Must be called after Detect
// (design.md Section 8.4: Detect runs before the manifest is reported).
func (a *Adapter) Tools() []platform.ToolSpec {
	specs := a.registry.List()
	out := make([]platform.ToolSpec, 0, len(specs))
	for _, s := range specs {
		out = append(out, platform.ToolSpec{Name: s.Name, Category: s.Category, ParamsSchema: s.ParamsSchema})
	}
	return out
}

// Execute implements platform.PlatformAdapter (design.md Section 8.3/8.5).
func (a *Adapter) Execute(ctx context.Context, call platform.ToolCall) (platform.ToolResult, error) {
	spec, ok := a.registry.Get(call.ToolName)
	if !ok {
		return toolpack.BuildEnvelope(call.ToolName, call.Args, a.Cfg.PlatformKey, a.probeID, 1, nil,
			fmt.Errorf("unknown tool %q", call.ToolName)), nil
	}
	if spec.ParamsSchema != nil {
		if err := toolpack.ValidateParams(spec.ParamsSchema, call.Args); err != nil {
			return toolpack.BuildEnvelope(call.ToolName, call.Args, a.Cfg.PlatformKey, a.probeID, 1, nil, err), nil
		}
	}
	fn, ok := a.funcs[call.ToolName]
	if !ok {
		return toolpack.BuildEnvelope(call.ToolName, call.Args, a.Cfg.PlatformKey, a.probeID, 1, nil,
			fmt.Errorf("tool %q has no implementation", call.ToolName)), nil
	}

	result, err := fn(ctx, a, call.Args)
	envelope := toolpack.BuildEnvelope(call.ToolName, call.Args, a.Cfg.PlatformKey, a.probeID, 0, result.Data, err)
	envelope.Redacted = result.Redacted
	return envelope, nil
}

// HealthCheck implements platform.PlatformAdapter (design.md Section
// 9.2: "Canary query: built-in SELECT 1 plus the per-platform configured
// health_query").
func (a *Adapter) HealthCheck(ctx context.Context, spec platform.HealthSpec) (platform.HealthResult, error) {
	if spec.WaitSeconds > 0 {
		select {
		case <-ctx.Done():
			return platform.HealthResult{}, ctx.Err()
		case <-time.After(time.Duration(spec.WaitSeconds) * time.Second):
		}
	}

	var details []string
	ok := true

	if spec.BuiltinProbe {
		if res, err := a.presto.Query(ctx, "SELECT 1"); err != nil || res.Error != nil {
			ok = false
			details = append(details, "builtin SELECT 1 failed")
		} else {
			details = append(details, "builtin SELECT 1 ok")
		}
	}

	customQuery := spec.CustomQuery
	if customQuery == "" {
		customQuery = a.Cfg.HealthQuery
	}
	if customQuery != "" {
		if res, err := a.presto.Query(ctx, customQuery); err != nil || res.Error != nil {
			ok = false
			details = append(details, "health_query failed")
		} else {
			details = append(details, "health_query ok")
		}
	}

	return platform.HealthResult{OK: ok, Detail: joinDetails(details), CheckedAt: time.Now().UTC()}, nil
}

func joinDetails(details []string) string {
	out := ""
	for i, d := range details {
		if i > 0 {
			out += "; "
		}
		out += d
	}
	return out
}

// WriteOps implements platform.PlatformAdapter (design.md Section 8.1:
// "a read-only deployment carries no write permissions at all" -- the
// catalog is empty unless write_enabled).
func (a *Adapter) WriteOps() []platform.WriteOpSpec {
	if !a.Cfg.WriteEnabled {
		return nil
	}
	_, ops, _ := toolpack.LoadCategory("writeops")
	out := make([]platform.WriteOpSpec, 0, len(ops))
	for name, schema := range ops {
		out = append(out, platform.WriteOpSpec{Name: name, ParamsSchema: schema})
	}
	return out
}

// ExecuteWrite is implemented in writeops.go (M5, design.md Section 9.5.3).

func writeOpNames(specs []platform.WriteOpSpec) []string {
	out := make([]string, 0, len(specs))
	for _, s := range specs {
		out = append(out, s.Name)
	}
	return out
}
