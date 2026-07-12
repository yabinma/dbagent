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
	"net/http"
	"net/url"
	"strconv"
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
