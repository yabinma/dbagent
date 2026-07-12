package prestoclient

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGetJSON_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/info" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"nodeVersion":{"version":"0.298"},"coordinator":true}`))
	}))
	defer srv.Close()

	c := New(srv.URL, srv.Client())
	out, err := c.GetJSON(context.Background(), "/v1/info")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	m := out.(map[string]any)
	if m["coordinator"] != true {
		t.Fatalf("unexpected body: %+v", m)
	}
}

func TestGetJSON_ErrorStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("coordinator starting"))
	}))
	defer srv.Close()

	c := New(srv.URL, srv.Client())
	_, err := c.GetJSON(context.Background(), "/v1/cluster")
	if err == nil {
		t.Fatalf("expected error")
	}
}

func TestGetJSON_BasicAuthApplied(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != "svc" || pass != "secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	c := New(srv.URL, srv.Client())
	c.Username, c.Password = "svc", "secret"
	out, err := c.GetJSON(context.Background(), "/v1/info")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.(map[string]any)["ok"] != true {
		t.Fatalf("unexpected body: %+v", out)
	}
}

func TestDeletePath_Success(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		if r.Method != http.MethodDelete {
			t.Fatalf("expected DELETE, got %s", r.Method)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	c := New(srv.URL, srv.Client())
	if err := c.DeletePath(context.Background(), "/v1/query/abc"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !called {
		t.Fatalf("handler was not called")
	}
}

func TestDeletePath_ErrorStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	c := New(srv.URL, srv.Client())
	if err := c.DeletePath(context.Background(), "/v1/query/missing"); err == nil {
		t.Fatalf("expected error")
	}
}

func TestQuery_SinglePageSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/statement" {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("X-Presto-User") == "" {
			t.Fatalf("expected X-Presto-User header")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"columns": [{"name":"query_id"},{"name":"state"}],
			"data": [["q1","FAILED"],["q2","RUNNING"]],
			"stats": {"state": "FINISHED"}
		}`))
	}))
	defer srv.Close()

	c := New(srv.URL, srv.Client())
	res, err := c.Query(context.Background(), "SELECT query_id, state FROM system.runtime.queries")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res.Columns) != 2 || res.Columns[0] != "query_id" {
		t.Fatalf("unexpected columns: %+v", res.Columns)
	}
	if len(res.Rows) != 2 {
		t.Fatalf("unexpected rows: %+v", res.Rows)
	}
}

func TestQuery_FollowsNextURIPagination(t *testing.T) {
	var mux http.ServeMux
	srv := httptest.NewServer(&mux)
	defer srv.Close()

	mux.HandleFunc("/v1/statement", func(w http.ResponseWriter, r *http.Request) {
		body := map[string]any{
			"columns": []map[string]string{{"name": "x"}},
			"data":    [][]any{{1}},
			"nextUri": srv.URL + "/v1/statement/page2",
			"stats":   map[string]string{"state": "RUNNING"},
		}
		enc, _ := json.Marshal(body)
		_, _ = w.Write(enc)
	})
	mux.HandleFunc("/v1/statement/page2", func(w http.ResponseWriter, r *http.Request) {
		body := map[string]any{
			"data":  [][]any{{2}, {3}},
			"stats": map[string]string{"state": "FINISHED"},
		}
		enc, _ := json.Marshal(body)
		_, _ = w.Write(enc)
	})

	c := New(srv.URL, srv.Client())
	res, err := c.Query(context.Background(), "SELECT x FROM system.runtime.queries")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res.Rows) != 3 {
		t.Fatalf("expected 3 rows across pages, got %d: %+v", len(res.Rows), res.Rows)
	}
	if len(res.Columns) != 1 || res.Columns[0] != "x" {
		t.Fatalf("unexpected columns: %+v", res.Columns)
	}
}

func TestQuery_ReturnsStatementError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"error":{"message":"syntax error","errorCode":"SYNTAX_ERROR"}}`))
	}))
	defer srv.Close()

	c := New(srv.URL, srv.Client())
	res, err := c.Query(context.Background(), "SELECT bad syntax")
	if err != nil {
		t.Fatalf("unexpected transport error: %v", err)
	}
	if res.Error == nil || res.Error.ErrorCode != "SYNTAX_ERROR" {
		t.Fatalf("expected statement error, got %+v", res)
	}
}
