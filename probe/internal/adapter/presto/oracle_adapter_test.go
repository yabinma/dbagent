package presto

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/yabinma/dbagent/probe/internal/platform"
)

func TestOracleAdapter(t *testing.T) {
	for _, row := range oracleRows {
		row := row
		t.Run(row.FP+"/"+row.Case, func(t *testing.T) {
			input, ok := row.In.(SinceInput)
			if !ok {
				t.Fatalf("oracle input has type %T, want SinceInput", row.In)
			}
			want, ok := row.Want.(SinceOutcome)
			if !ok {
				t.Fatalf("oracle outcome has type %T, want SinceOutcome", row.Want)
			}

			var queryRequests atomic.Int32
			mux := http.NewServeMux()
			mux.HandleFunc("/v1/info", func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(`{"nodeVersion":{"version":"0.298"}}`))
			})
			mux.HandleFunc("/v1/query", func(w http.ResponseWriter, r *http.Request) {
				queryRequests.Add(1)
				if r.Method != http.MethodGet {
					http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode([]any{})
			})
			srv := httptest.NewServer(mux)
			t.Cleanup(srv.Close)

			adapter, _ := detectedAdapter(t, srv, platform.EnvKindK8s)
			result, err := adapter.Execute(context.Background(), platform.ToolCall{
				ToolName: "presto_list_queries",
				Args:     map[string]any{"since": input.Value},
			})
			if err != nil {
				t.Fatalf("Execute returned transport error: %v", err)
			}

			accepted := result.ExitCode == 0 && result.Error == ""
			if accepted != want.Accepted {
				t.Fatalf("Accepted=%v, want %v; result=%+v", accepted, want.Accepted, result)
			}
			if want.Accepted {
				if result.Data == nil {
					t.Fatalf("accepted input returned no data: %+v", result)
				}
				if got := queryRequests.Load(); got != 1 {
					t.Fatalf("accepted input made %d /v1/query requests, want 1", got)
				}
				return
			}

			if result.ExitCode != 1 {
				t.Fatalf("rejected input exit_code=%d, want 1: %+v", result.ExitCode, result)
			}
			if result.Data != nil {
				t.Fatalf("rejected input returned data: %+v", result.Data)
			}
			if got := queryRequests.Load(); got != 0 {
				t.Fatalf("rejected input made %d /v1/query requests, want 0", got)
			}
			lexicallyInvalid := row.FP == "FP-AD-3" || input.Value == "1x"
			if lexicallyInvalid {
				if !strings.HasPrefix(result.Error, "params validation failed:") {
					t.Fatalf("schema rejection error=%q, want params validation failed prefix", result.Error)
				}
				if strings.Contains(result.Error, "presto_list_queries: invalid since") {
					t.Fatalf("schema rejection leaked parser-layer prefix: %q", result.Error)
				}
			} else if !strings.Contains(result.Error, "presto_list_queries: invalid since") ||
				!strings.Contains(result.Error, "representable range") {
				t.Fatalf("range rejection error=%q, want parser context and range detail", result.Error)
			}
		})
	}
}
