// Package prestoclient is the probe's "embedded lightweight Presto client,
// read-only account" (design.md Section 8.1) -- a small REST client for
// the coordinator's `/v1/*` endpoints (design.md Section 8.5 / Appendix
// B.1) plus the `/v1/statement` client protocol used to run read-only SQL
// against `system.runtime.*` and the `jmx` catalog (admission-bound engine
// tools such as `presto_session_properties` and `presto_jmx`). Deliberately returns
// loosely-typed JSON (`map[string]any` / raw bytes) for the raw
// endpoints -- Appendix B's tool-specific `data` shaping happens one
// layer up in probe/internal/adapter/presto, keeping this client generic
// and easy to point at an httptest server in unit tests (design.md
// Section 14.2: "Presto REST via httptest").
package prestoclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

type Client struct {
	BaseURL  string
	HTTP     *http.Client
	Username string // optional; PASSWORD/LDAP auth
	Password string
}

func New(baseURL string, httpClient *http.Client) *Client {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return &Client{BaseURL: baseURL, HTTP: httpClient}
}

// GetJSON issues a GET against BaseURL+path and decodes the JSON response
// body into a generic value.
func (c *Client) GetJSON(ctx context.Context, path string) (any, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+path, nil)
	if err != nil {
		return nil, err
	}
	c.applyAuth(req)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("presto GET %s: %w", path, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("presto GET %s: status %d: %s", path, resp.StatusCode, string(body))
	}
	var out any
	if len(body) > 0 {
		if err := json.Unmarshal(body, &out); err != nil {
			return nil, fmt.Errorf("presto GET %s: decode: %w", path, err)
		}
	}
	return out, nil
}

// DeletePath issues a DELETE against BaseURL+path (used by the
// presto_kill_query write-op primitive, Section 9.1; execution itself is
// M5 scope, but the low-level call is implemented now since it is
// otherwise identical to GetJSON).
func (c *Client) DeletePath(ctx context.Context, path string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.BaseURL+path, nil)
	if err != nil {
		return err
	}
	c.applyAuth(req)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("presto DELETE %s: %w", path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("presto DELETE %s: status %d: %s", path, resp.StatusCode, string(body))
	}
	return nil
}

// QueryResult accumulates the `/v1/statement` client protocol's paginated
// response into a single columns+rows result.
type QueryResult struct {
	Columns []string
	Rows    [][]any
	Error   *statementError
}

type statementError struct {
	Message string `json:"message"`
	// Presto's /v1/statement error object carries errorCode as a JSON number
	// (e.g. 8), plus symbolic errorName/errorType; decoding errorCode as a
	// string fails on every real query error ("cannot unmarshal number into
	// ... errorCode of type string").
	ErrorCode int    `json:"errorCode"`
	ErrorName string `json:"errorName"`
	ErrorType string `json:"errorType"`
}

type statementResponse struct {
	Columns []struct {
		Name string `json:"name"`
	} `json:"columns"`
	Data    [][]any         `json:"data"`
	NextURI string          `json:"nextUri"`
	Error   *statementError `json:"error"`
	Stats   statementStats  `json:"stats"`
}

type statementStats struct {
	State string `json:"state"`
}

// Query runs sql via the `/v1/statement` client protocol (POST, then
// follow `nextUri` until absent), accumulating all rows. Remaining SQL
// callers: presto_session_properties, presto_jmx, the §9.2 canary, and
// the §8.4 connectivity probe.
func (c *Client) Query(ctx context.Context, sql string) (*QueryResult, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/v1/statement", bytes.NewBufferString(sql))
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Presto-User", "dbagent-probe")
	req.Header.Set("Content-Type", "text/plain")
	c.applyAuth(req)

	result := &QueryResult{}
	nextURL := ""
	first := true

	for {
		var resp *http.Response
		if first {
			resp, err = c.HTTP.Do(req)
			first = false
		} else {
			var r *http.Request
			r, err = http.NewRequestWithContext(ctx, http.MethodGet, nextURL, nil)
			if err == nil {
				c.applyAuth(r)
				resp, err = c.HTTP.Do(r)
			}
		}
		if err != nil {
			return nil, fmt.Errorf("presto query: %w", err)
		}

		body, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		if readErr != nil {
			return nil, readErr
		}
		if resp.StatusCode >= 400 {
			return nil, fmt.Errorf("presto query: status %d: %s", resp.StatusCode, string(body))
		}

		var sr statementResponse
		if err := json.Unmarshal(body, &sr); err != nil {
			return nil, fmt.Errorf("presto query: decode: %w", err)
		}
		if sr.Error != nil {
			result.Error = sr.Error
			return result, nil
		}
		if len(sr.Columns) > 0 && result.Columns == nil {
			for _, col := range sr.Columns {
				result.Columns = append(result.Columns, col.Name)
			}
		}
		result.Rows = append(result.Rows, sr.Data...)

		if sr.NextURI == "" {
			break
		}
		nextURL = sr.NextURI
	}
	return result, nil
}

func (c *Client) applyAuth(req *http.Request) {
	if c.Username != "" {
		req.SetBasicAuth(c.Username, c.Password)
	}
}
