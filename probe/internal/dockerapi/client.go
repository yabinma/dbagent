// Package dockerapi is a minimal, dependency-free client for the subset
// of the Docker Engine REST API the Swarm RuntimeEnv needs (design.md
// Section 8.1: "Docker Swarm: a service on a manager node, mounting
// /var/run/docker.sock"). Implemented directly against the documented
// REST endpoints (rather than the official `docker/docker` SDK) so it is
// trivially mockable with `httptest` in unit tests (design.md Section
// 14.2: "Docker via API mock") without pulling in that module's large,
// version-coupled dependency graph.
package dockerapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type Client struct {
	// BaseURL is the Docker Engine API base, e.g. "http://docker" when
	// HTTP is a Transport dialing /var/run/docker.sock, or an
	// httptest.Server URL in tests.
	BaseURL string
	HTTP    *http.Client
}

func New(baseURL string, httpClient *http.Client) *Client {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return &Client{BaseURL: baseURL, HTTP: httpClient}
}

// unixScheme is the only form that dials a socket; the other two keep the
// plain transport (design.md §11.2.3 B).
const (
	unixScheme  = "unix://"
	httpScheme  = "http://"
	httpsScheme = "https://"

	// dummyAuthority is the authority Docker's own SDK uses when the
	// transport dials a unix socket. It is only correct because a dialer
	// backs it -- the shipped probe used to carry the authority without the
	// dialer, which is the defect FP-SW-2 fixes.
	dummyAuthority = "http://docker"
)

// NewForBaseURL builds a Client from a deployment-supplied base URL
// (design.md §11.2.3 B, FP-SW-2/FP-SW-3).
//
//	unix:///var/run/docker.sock -> unix-socket transport (default)
//	http://host:port | https://host:port -> plain transport (tests; an
//	operator-run socket proxy)
//
// Any other scheme, or a unix path that is missing or not a socket, is an
// error -- the caller treats it as fatal.
//
// For unix:// URLs, NewForBaseURL also issues a real GET /_ping against the
// Engine API. Stat alone cannot detect a non-root probe lacking the host
// docker group (typical root:docker 0660 socket); without this preflight the
// single-use bootstrap token would already be spent by the time the first
// real Docker call failed. http(s):// stays lazy so tests and operator
// proxies can construct a client without a live endpoint.
func NewForBaseURL(baseURL string) (*Client, error) {
	switch {
	case strings.HasPrefix(baseURL, unixScheme):
		socketPath := strings.TrimPrefix(baseURL, unixScheme)
		// Preflight order matters: an *existing* relative socket must be
		// rejected for being relative, not accepted for existing.
		if !filepath.IsAbs(socketPath) {
			return nil, fmt.Errorf("dockerapi: docker socket path %q must be absolute (use unix:///var/run/docker.sock)", socketPath)
		}
		info, err := os.Stat(socketPath)
		if err != nil {
			if os.IsNotExist(err) {
				return nil, fmt.Errorf("dockerapi: docker socket %s not found (mount /var/run/docker.sock into the probe container)", socketPath)
			}
			return nil, fmt.Errorf("dockerapi: docker socket %s: %w", socketPath, err)
		}
		if info.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("dockerapi: %s is not a unix socket", socketPath)
		}
		transport := &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
			},
		}
		// No client-level Timeout: every request already carries a context
		// (http.NewRequestWithContext throughout this file), and a timeout
		// here would truncate long Exec streams.
		client := New(dummyAuthority, &http.Client{Transport: transport})
		if err := client.ping(socketPath); err != nil {
			return nil, err
		}
		return client, nil
	case strings.HasPrefix(baseURL, httpScheme), strings.HasPrefix(baseURL, httpsScheme):
		return New(baseURL, nil), nil
	default:
		return nil, fmt.Errorf("dockerapi: unsupported docker_api_base_url scheme %q (want unix://, http:// or https://)", baseURL)
	}
}

// pingDeadline bounds the construction-time connectivity check so a hung
// socket cannot stall probe startup indefinitely.
const pingDeadline = 5 * time.Second

// ping issues GET /_ping so permission and connectivity failures surface
// during client construction (before enrollment spends the bootstrap token).
func (c *Client) ping(socketPath string) error {
	ctx, cancel := context.WithTimeout(context.Background(), pingDeadline)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+"/_ping", nil)
	if err != nil {
		return fmt.Errorf("dockerapi: docker socket %s: build ping: %w", socketPath, err)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("dockerapi: cannot reach docker via %s: %w (mount the socket and add the host docker group GID via DOCKER_SOCKET_GID — group_add on Compose, user: \"uid:gid\" on Swarm; see docs/deployment/swarm.md)", socketPath, err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode >= 400 {
		return fmt.Errorf("dockerapi: docker socket %s: GET /_ping status %d", socketPath, resp.StatusCode)
	}
	return nil
}

// --- Swarm tasks -------------------------------------------------------------------

type Task struct {
	ID           string `json:"ID"`
	ServiceID    string `json:"ServiceID"`
	Slot         int    `json:"Slot"`
	NodeID       string `json:"NodeID"`
	DesiredState string `json:"DesiredState"`
	Status       struct {
		Timestamp       string `json:"Timestamp"`
		State           string `json:"State"`
		Message         string `json:"Message"`
		Err             string `json:"Err"`
		ContainerStatus struct {
			ContainerID string `json:"ContainerID"`
		} `json:"ContainerStatus"`
	} `json:"Status"`
}

// ListTasks lists Swarm tasks, optionally filtered (e.g.
// {"service": {"presto-worker": true}} per the Docker filters convention).
func (c *Client) ListTasks(ctx context.Context, filters map[string]map[string]bool) ([]Task, error) {
	q := url.Values{}
	if len(filters) > 0 {
		enc, err := json.Marshal(filters)
		if err != nil {
			return nil, err
		}
		q.Set("filters", string(enc))
	}
	var tasks []Task
	if err := c.getJSON(ctx, "/tasks?"+q.Encode(), &tasks); err != nil {
		return nil, err
	}
	return tasks, nil
}

// --- Container inspect / logs / stats -----------------------------------------------

func (c *Client) ContainerInspect(ctx context.Context, containerID string) (map[string]any, error) {
	var out map[string]any
	if err := c.getJSON(ctx, "/containers/"+containerID+"/json", &out); err != nil {
		return nil, err
	}
	return out, nil
}

type LogsOptions struct {
	Since    string // Unix timestamp or duration-relative caller resolves
	Tail     int
	Previous bool // maps to Docker's per-restart log semantics via `since`/log rotation; see runtimeenv/dockerenv
}

// ContainerLogs fetches and demultiplexes container logs (Docker's
// non-TTY log stream is framed: 1 byte stream type, 3 bytes reserved,
// 4-byte big-endian length, then payload -- demuxed here so callers get
// plain lines regardless of stdout/stderr).
func (c *Client) ContainerLogs(ctx context.Context, containerID string, opts LogsOptions) ([]string, error) {
	q := url.Values{}
	q.Set("stdout", "1")
	q.Set("stderr", "1")
	q.Set("timestamps", "0")
	if opts.Since != "" {
		q.Set("since", opts.Since)
	}
	if opts.Tail > 0 {
		q.Set("tail", strconv.Itoa(opts.Tail))
	}
	body, err := c.get(ctx, "/containers/"+containerID+"/logs?"+q.Encode())
	if err != nil {
		return nil, err
	}
	return demuxLines(body), nil
}

// --- Events ------------------------------------------------------------------------

type Event struct {
	Type   string `json:"Type"`
	Action string `json:"Action"`
	Actor  struct {
		ID         string            `json:"ID"`
		Attributes map[string]string `json:"Attributes"`
	} `json:"Actor"`
	Time int64 `json:"time"`
}

// Events fetches events in [since, until) -- both required so the
// (otherwise indefinitely-streaming) /events endpoint returns a bounded,
// newline-delimited-JSON response.
func (c *Client) Events(ctx context.Context, since, until string, typeFilter string) ([]Event, error) {
	q := url.Values{}
	q.Set("since", since)
	q.Set("until", until)
	if typeFilter != "" && typeFilter != "all" {
		filters := map[string]map[string]bool{"type": {typeFilter: true}}
		enc, _ := json.Marshal(filters)
		q.Set("filters", string(enc))
	}
	body, err := c.get(ctx, "/events?"+q.Encode())
	if err != nil {
		return nil, err
	}
	var events []Event
	dec := json.NewDecoder(bytes.NewReader(body))
	for dec.More() {
		var e Event
		if err := dec.Decode(&e); err != nil {
			break
		}
		events = append(events, e)
	}
	return events, nil
}

// --- Stats -------------------------------------------------------------------------

type Stats struct {
	CPUStats struct {
		CPUUsage struct {
			TotalUsage uint64 `json:"total_usage"`
		} `json:"cpu_usage"`
		SystemUsage uint64 `json:"system_cpu_usage"`
		OnlineCPUs  uint64 `json:"online_cpus"`
	} `json:"cpu_stats"`
	PreCPUStats struct {
		CPUUsage struct {
			TotalUsage uint64 `json:"total_usage"`
		} `json:"cpu_usage"`
		SystemUsage uint64 `json:"system_cpu_usage"`
	} `json:"precpu_stats"`
	MemoryStats struct {
		Usage uint64 `json:"usage"`
		Limit uint64 `json:"limit"`
	} `json:"memory_stats"`
}

func (c *Client) ContainerStats(ctx context.Context, containerID string) (*Stats, error) {
	var s Stats
	if err := c.getJSON(ctx, "/containers/"+containerID+"/stats?stream=false", &s); err != nil {
		return nil, err
	}
	return &s, nil
}

// --- Exec --------------------------------------------------------------------------

// Exec runs cmd inside containerID via the standard Docker two-step exec
// protocol (create, then start) and returns demultiplexed stdout/stderr
// plus the exit code (fetched via exec inspect after the stream ends).
func (c *Client) Exec(ctx context.Context, containerID string, cmd []string) (stdout, stderr string, exitCode int, err error) {
	createBody, _ := json.Marshal(map[string]any{
		"AttachStdout": true,
		"AttachStderr": true,
		"Tty":          false,
		"Cmd":          cmd,
	})
	var created struct {
		ID string `json:"Id"`
	}
	if err = c.postJSON(ctx, "/containers/"+containerID+"/exec", createBody, &created); err != nil {
		return "", "", 0, err
	}

	startBody, _ := json.Marshal(map[string]any{"Detach": false, "Tty": false})
	streamBody, err := c.post(ctx, "/exec/"+created.ID+"/start", startBody)
	if err != nil {
		return "", "", 0, err
	}
	stdoutLines, stderrLines := demuxStreams(streamBody)
	stdout = joinLines(stdoutLines)
	stderr = joinLines(stderrLines)

	var inspect struct {
		ExitCode int `json:"ExitCode"`
	}
	if err = c.getJSON(ctx, "/exec/"+created.ID+"/json", &inspect); err != nil {
		return stdout, stderr, 0, err
	}
	return stdout, stderr, inspect.ExitCode, nil
}

// --- Swarm services (M5 write ops) ---------------------------------------------------

// Service is the subset of Docker Engine Service JSON the write ops need
// (ServiceInspect / ServiceUpdate).
type Service struct {
	ID      string         `json:"ID"`
	Version ServiceVersion `json:"Version"`
	Spec    ServiceSpec    `json:"Spec"`
}

type ServiceVersion struct {
	Index uint64 `json:"Index"`
}

type ServiceSpec struct {
	Name         string            `json:"Name,omitempty"`
	Labels       map[string]string `json:"Labels,omitempty"`
	TaskTemplate TaskSpec          `json:"TaskTemplate"`
	Mode         any               `json:"Mode,omitempty"`
	// Preserve unknown top-level fields the Engine returns so a round-trip
	// ServiceUpdate does not strip them.
	EndpointSpec any `json:"EndpointSpec,omitempty"`
	UpdateConfig any `json:"UpdateConfig,omitempty"`
}

type TaskSpec struct {
	ContainerSpec ContainerSpec `json:"ContainerSpec"`
	// ForceUpdate bumps to force task recreation (swarm_restart_service).
	ForceUpdate   uint64 `json:"ForceUpdate,omitempty"`
	Resources     any    `json:"Resources,omitempty"`
	RestartPolicy any    `json:"RestartPolicy,omitempty"`
	Placement     any    `json:"Placement,omitempty"`
	Networks      any    `json:"Networks,omitempty"`
}

type ContainerSpec struct {
	Image  string            `json:"Image,omitempty"`
	Env    []string          `json:"Env,omitempty"`
	Labels map[string]string `json:"Labels,omitempty"`
	// Preserve fields we do not mutate.
	Command    any `json:"Command,omitempty"`
	Args       any `json:"Args,omitempty"`
	Hostname   any `json:"Hostname,omitempty"`
	Mounts     any `json:"Mounts,omitempty"`
	Secrets    any `json:"Secrets,omitempty"`
	Configs    any `json:"Configs,omitempty"`
	User       any `json:"User,omitempty"`
	Dir        any `json:"Dir,omitempty"`
	Privileges any `json:"Privileges,omitempty"`
}

// ServiceInspect returns a Swarm service by name or ID
// (GET /services/{id}).
func (c *Client) ServiceInspect(ctx context.Context, idOrName string) (*Service, error) {
	var svc Service
	if err := c.getJSON(ctx, "/services/"+url.PathEscape(idOrName), &svc); err != nil {
		return nil, err
	}
	return &svc, nil
}

// ServiceUpdate applies a new ServiceSpec at the given version
// (POST /services/{id}/update?version=N).
func (c *Client) ServiceUpdate(ctx context.Context, id string, version uint64, spec ServiceSpec) error {
	body, err := json.Marshal(spec)
	if err != nil {
		return err
	}
	path := fmt.Sprintf("/services/%s/update?version=%d", url.PathEscape(id), version)
	_, err = c.post(ctx, path, body)
	return err
}

// --- low-level helpers ---------------------------------------------------------------

func (c *Client) get(ctx context.Context, path string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+path, nil)
	if err != nil {
		return nil, err
	}
	return c.do(req)
}

func (c *Client) getJSON(ctx context.Context, path string, out any) error {
	body, err := c.get(ctx, path)
	if err != nil {
		return err
	}
	if len(body) == 0 {
		return nil
	}
	return json.Unmarshal(body, out)
}

func (c *Client) post(ctx context.Context, path string, body []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	return c.do(req)
}

func (c *Client) postJSON(ctx context.Context, path string, body []byte, out any) error {
	respBody, err := c.post(ctx, path, body)
	if err != nil {
		return err
	}
	if len(respBody) == 0 {
		return nil
	}
	return json.Unmarshal(respBody, out)
}

func (c *Client) do(req *http.Request) ([]byte, error) {
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("docker %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("docker %s %s: status %d: %s", req.Method, req.URL.Path, resp.StatusCode, string(body))
	}
	return body, nil
}

// demuxLines demultiplexes a Docker log stream into plain text lines,
// falling back to raw-text line splitting if the payload doesn't look
// like the framed multiplexed format (e.g. TTY-attached containers).
func demuxLines(raw []byte) []string {
	stdout, stderr := demuxStreams(raw)
	all := append(stdout, stderr...)
	return all
}

func demuxStreams(raw []byte) (stdout, stderr []string) {
	if looksMultiplexed(raw) {
		i := 0
		for i+8 <= len(raw) {
			streamType := raw[i]
			length := int(raw[i+4])<<24 | int(raw[i+5])<<16 | int(raw[i+6])<<8 | int(raw[i+7])
			i += 8
			if i+length > len(raw) {
				length = len(raw) - i
			}
			payload := string(raw[i : i+length])
			i += length
			lines := splitNonEmptyLines(payload)
			if streamType == 2 {
				stderr = append(stderr, lines...)
			} else {
				stdout = append(stdout, lines...)
			}
		}
		return stdout, stderr
	}
	return splitNonEmptyLines(string(raw)), nil
}

// looksMultiplexed heuristically checks whether raw begins with a
// well-formed Docker stream frame header (stream type in {0,1,2}, 3
// reserved zero bytes, and a length that doesn't overrun the buffer).
func looksMultiplexed(raw []byte) bool {
	if len(raw) < 8 {
		return false
	}
	if raw[0] > 2 || raw[1] != 0 || raw[2] != 0 || raw[3] != 0 {
		return false
	}
	length := int(raw[4])<<24 | int(raw[5])<<16 | int(raw[6])<<8 | int(raw[7])
	return length >= 0 && 8+length <= len(raw)
}

func splitNonEmptyLines(s string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			if line := s[start:i]; line != "" {
				lines = append(lines, line)
			}
			start = i + 1
		}
	}
	if start < len(s) {
		if line := s[start:]; line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

func joinLines(lines []string) string {
	out := ""
	for i, l := range lines {
		if i > 0 {
			out += "\n"
		}
		out += l
	}
	return out
}
