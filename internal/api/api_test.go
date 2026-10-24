package api

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"unicode/utf8"

	"github.com/HBTGmbH/easyauth-mcp/internal/auth"
	"github.com/HBTGmbH/easyauth-mcp/internal/spec"
)

func tokenFunc(tok auth.Token) func(context.Context) (auth.Token, error) {
	return func(context.Context) (auth.Token, error) { return tok, nil }
}

func schema(props ...string) map[string]any {
	properties := make(map[string]any, len(props))
	for _, p := range props {
		properties[p] = map[string]any{"type": "string"}
	}
	return map[string]any{"type": "object", "properties": properties}
}

// paramIn maps every named argument to "query" unless it is overridden.
func paramIn(where string, names ...string) map[string]string {
	m := make(map[string]string, len(names))
	for _, n := range names {
		m[n] = where
	}
	return m
}

func TestCallGetWithTokenHeaders(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			t.Errorf("Authorization = %q", r.Header.Get("Authorization"))
		}
		if r.Header.Get("x-ms-client-principal-id") != "oid-1" {
			t.Errorf("x-ms-client-principal-id = %q", r.Header.Get("x-ms-client-principal-id"))
		}
		if r.Header.Get("Accept") != "application/json" {
			t.Errorf("Accept = %q", r.Header.Get("Accept"))
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	c := NewClient(srv.URL, tokenFunc(auth.Token{AccessToken: "tok", OID: "oid-1"}))
	tool := spec.Tool{Method: http.MethodGet, Path: "/api/favorite", InputSchema: schema("opt"), ParamIn: paramIn("query", "opt")}

	res := c.Call(context.Background(), tool, nil)
	if res.IsError {
		t.Fatalf("unexpected error: %s", res.ErrorMessage)
	}
	if res.Status != http.StatusOK {
		t.Fatalf("status = %d", res.Status)
	}
	if res.Body != `{"ok":true}` {
		t.Fatalf("body = %q", res.Body)
	}
}

func TestCallPathEncoding(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.RequestURI
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	c := NewClient(srv.URL, nil)
	tool := spec.Tool{
		Method:      http.MethodGet,
		Path:        "/api/workingday/{employeeSign}",
		InputSchema: schema("employeeSign"),
		ParamIn:     map[string]string{"employeeSign": "path"},
	}

	res := c.Call(context.Background(), tool, map[string]any{"employeeSign": "a b/c"})
	if res.IsError {
		t.Fatalf("unexpected error: %s", res.ErrorMessage)
	}
	if !strings.Contains(gotPath, "%20") || !strings.Contains(gotPath, "%2F") {
		t.Fatalf("RequestURI = %q, want escaped space and slash", gotPath)
	}
}

func TestCallPathTraversalRejected(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	c := NewClient(srv.URL, nil)
	tool := spec.Tool{
		Method:      http.MethodGet,
		Path:        "/api/workingday/{employeeSign}",
		InputSchema: schema("employeeSign"),
		ParamIn:     map[string]string{"employeeSign": "path"},
	}

	for _, unsafe := range []string{"..", "../x", "", `a\b`, "a/../b"} {
		res := c.Call(context.Background(), tool, map[string]any{"employeeSign": unsafe})
		if !res.IsError {
			t.Errorf("employeeSign %q: expected error", unsafe)
			continue
		}
		if !strings.Contains(res.ErrorMessage, "invalid path parameter") {
			t.Errorf("employeeSign %q: ErrorMessage = %q", unsafe, res.ErrorMessage)
		}
	}
	if calls.Load() != 0 {
		t.Fatalf("server calls = %d, want 0", calls.Load())
	}
}

func TestCallPathLiteralDotSegment(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.EscapedPath()
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	c := NewClient(srv.URL, nil)
	tool := spec.Tool{Method: http.MethodGet, Path: "/api/workingday/.me", InputSchema: schema("opt"), ParamIn: paramIn("query", "opt")}

	res := c.Call(context.Background(), tool, nil)
	if res.IsError {
		t.Fatalf("unexpected error: %s", res.ErrorMessage)
	}
	if gotPath != "/api/workingday/.me" {
		t.Fatalf("path = %q, want /api/workingday/.me", gotPath)
	}
}

func TestCallQueryFiltersUnknownArgs(t *testing.T) {
	var query string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query = r.URL.RawQuery
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	c := NewClient(srv.URL, nil)
	tool := spec.Tool{
		Method:      http.MethodGet,
		Path:        "/api/daily-reports/list",
		InputSchema: schema("refDate", "days"),
		ParamIn:     paramIn("query", "refDate", "days"),
	}

	res := c.Call(context.Background(), tool, map[string]any{
		"refDate": "2025-09-09",
		"days":    float64(3),
		"csv":     true,
	})
	if res.IsError {
		t.Fatalf("unexpected error: %s", res.ErrorMessage)
	}
	if query != "days=3&refDate=2025-09-09" {
		t.Fatalf("query = %q", query)
	}
	if strings.Contains(query, "csv") {
		t.Fatalf("csv must not be sent: %q", query)
	}
}

func TestCallHeaderParameter(t *testing.T) {
	var gotTenant, gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotTenant = r.Header.Get("X-Tenant")
		gotAuth = r.Header.Get("Authorization")
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	c := NewClient(srv.URL, tokenFunc(auth.Token{AccessToken: "tok"}))
	tool := spec.Tool{
		Method:      http.MethodGet,
		Path:        "/api/x",
		InputSchema: schema("X-Tenant", "Authorization"),
		ParamIn:     map[string]string{"X-Tenant": "header", "Authorization": "header"},
	}

	res := c.Call(context.Background(), tool, map[string]any{
		"X-Tenant":      "tenant-1",
		"Authorization": "Bearer injected",
	})
	if res.IsError {
		t.Fatalf("unexpected error: %s", res.ErrorMessage)
	}
	if gotTenant != "tenant-1" {
		t.Fatalf("X-Tenant = %q", gotTenant)
	}
	if gotAuth != "Bearer tok" {
		t.Fatalf("Authorization = %q, want token value", gotAuth)
	}
}

func TestCallNoParamMetadataIsError(t *testing.T) {
	c := NewClient("http://127.0.0.1:1", nil)
	tool := spec.Tool{Method: http.MethodGet, Path: "/api/x", InputSchema: schema()}

	res := c.Call(context.Background(), tool, nil)
	if !res.IsError || !strings.Contains(res.ErrorMessage, "parameter metadata") {
		t.Fatalf("unexpected result: %+v", res)
	}
}

func TestCallRetryAfter401(t *testing.T) {
	var calls, refreshes atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`expired`))
			return
		}
		if r.Header.Get("Authorization") != "Bearer fresh" {
			t.Errorf("Authorization = %q after refresh", r.Header.Get("Authorization"))
		}
		w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	c := NewClient(srv.URL, tokenFunc(auth.Token{AccessToken: "old", OID: "oid"}))
	c.Refresh = func(context.Context) (auth.Token, error) {
		refreshes.Add(1)
		return auth.Token{AccessToken: "fresh", OID: "oid"}, nil
	}
	tool := spec.Tool{Method: http.MethodGet, Path: "/api/favorite", InputSchema: schema("opt"), ParamIn: paramIn("query", "opt")}

	res := c.Call(context.Background(), tool, nil)
	if res.IsError {
		t.Fatalf("unexpected error: %s", res.ErrorMessage)
	}
	if res.Status != http.StatusOK || res.Body != `{"ok":true}` {
		t.Fatalf("status=%d body=%q", res.Status, res.Body)
	}
	if calls.Load() != 2 {
		t.Fatalf("calls = %d, want 2", calls.Load())
	}
	if refreshes.Load() != 1 {
		t.Fatalf("refreshes = %d, want 1", refreshes.Load())
	}
}

func TestCallRetryAfter401StillUnauthorized(t *testing.T) {
	var calls, refreshes atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`nope`))
	}))
	defer srv.Close()

	c := NewClient(srv.URL, tokenFunc(auth.Token{AccessToken: "old"}))
	c.Refresh = func(context.Context) (auth.Token, error) {
		refreshes.Add(1)
		return auth.Token{AccessToken: "fresh"}, nil
	}
	tool := spec.Tool{Method: http.MethodGet, Path: "/api/favorite", InputSchema: schema("opt"), ParamIn: paramIn("query", "opt")}

	res := c.Call(context.Background(), tool, nil)
	if !res.IsError {
		t.Fatal("expected error")
	}
	if !strings.Contains(res.ErrorMessage, "unauthorized after token refresh") {
		t.Fatalf("ErrorMessage = %q", res.ErrorMessage)
	}
	if calls.Load() != 2 {
		t.Fatalf("calls = %d, want 2", calls.Load())
	}
	if refreshes.Load() != 1 {
		t.Fatalf("refreshes = %d, want 1", refreshes.Load())
	}
}

func TestCallUnauthorizedWithoutRefresh(t *testing.T) {
	tests := []struct {
		name  string
		token func(context.Context) (auth.Token, error)
	}{
		{name: "static mode", token: nil},
		{name: "token without refresh", token: tokenFunc(auth.Token{AccessToken: "tok"})},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte(`denied`))
			}))
			defer srv.Close()

			c := NewClient(srv.URL, tc.token)
			tool := spec.Tool{Method: http.MethodGet, Path: "/api/x", InputSchema: schema("opt"), ParamIn: paramIn("query", "opt")}

			res := c.Call(context.Background(), tool, nil)
			if !res.IsError {
				t.Fatal("401 must be an error")
			}
			if !strings.Contains(res.ErrorMessage, "unauthorized") {
				t.Fatalf("ErrorMessage = %q", res.ErrorMessage)
			}
			if calls.Load() != 1 {
				t.Fatalf("calls = %d, want 1 (no retry)", calls.Load())
			}
		})
	}
}

func TestCallForbiddenNoRefresh(t *testing.T) {
	var refreshes atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"error":"role"}`))
	}))
	defer srv.Close()

	c := NewClient(srv.URL, tokenFunc(auth.Token{AccessToken: "tok"}))
	c.Refresh = func(context.Context) (auth.Token, error) {
		refreshes.Add(1)
		return auth.Token{}, nil
	}
	tool := spec.Tool{Method: http.MethodGet, Path: "/api/x", InputSchema: schema("opt"), ParamIn: paramIn("query", "opt")}

	res := c.Call(context.Background(), tool, nil)
	if res.IsError {
		t.Fatalf("403 must not be an error: %s", res.ErrorMessage)
	}
	if res.Status != http.StatusForbidden || res.Body != `{"error":"role"}` {
		t.Fatalf("status=%d body=%q", res.Status, res.Body)
	}
	if refreshes.Load() != 0 {
		t.Fatalf("refreshes = %d, want 0", refreshes.Load())
	}
}

func TestCallNotFoundIsContent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	c := NewClient(srv.URL, nil)
	tool := spec.Tool{Method: http.MethodGet, Path: "/api/x", InputSchema: schema("opt"), ParamIn: paramIn("query", "opt")}

	res := c.Call(context.Background(), tool, nil)
	if res.IsError {
		t.Fatalf("404 must not be an error: %s", res.ErrorMessage)
	}
	if res.Status != http.StatusNotFound || res.Body != `{}` {
		t.Fatalf("status=%d body=%q", res.Status, res.Body)
	}
}

func TestCallServerErrorIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`boom`))
	}))
	defer srv.Close()

	c := NewClient(srv.URL, nil)
	tool := spec.Tool{Method: http.MethodGet, Path: "/api/x", InputSchema: schema("opt"), ParamIn: paramIn("query", "opt")}

	res := c.Call(context.Background(), tool, nil)
	if !res.IsError {
		t.Fatal("500 must be an error")
	}
	if res.Status != http.StatusInternalServerError || res.Body != "boom" {
		t.Fatalf("status=%d body=%q", res.Status, res.Body)
	}
}

func TestCallTruncatesBody(t *testing.T) {
	payload := strings.Repeat("x", 1000)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(payload))
	}))
	defer srv.Close()

	c := NewClient(srv.URL, nil)
	c.MaxBody = 100
	tool := spec.Tool{Method: http.MethodGet, Path: "/api/x", InputSchema: schema("opt"), ParamIn: paramIn("query", "opt")}

	res := c.Call(context.Background(), tool, nil)
	if res.IsError {
		t.Fatalf("unexpected error: %s", res.ErrorMessage)
	}
	if !res.Truncated {
		t.Fatal("expected Truncated")
	}
	if !strings.Contains(res.Body, "[truncated to 100 bytes]") {
		t.Fatalf("missing truncation hint: %q", res.Body)
	}
	if len(res.Body) > 100+len("\n[truncated to 100 bytes]") {
		t.Fatalf("body too long: %d", len(res.Body))
	}
}

func TestCallTruncationKeepsValidUTF8(t *testing.T) {
	// Multi-byte runes so that a byte-based cut would split one.
	payload := strings.Repeat("ä", 500)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(payload))
	}))
	defer srv.Close()

	c := NewClient(srv.URL, nil)
	c.MaxBody = 101 // odd limit inside a 2-byte rune
	tool := spec.Tool{Method: http.MethodGet, Path: "/api/x", InputSchema: schema("opt"), ParamIn: paramIn("query", "opt")}

	res := c.Call(context.Background(), tool, nil)
	if res.IsError {
		t.Fatalf("unexpected error: %s", res.ErrorMessage)
	}
	body := strings.TrimSuffix(res.Body, "\n[truncated to 101 bytes]")
	if !utf8.ValidString(body) {
		t.Fatalf("truncated body is not valid UTF-8: %q", body)
	}
	if len(body) > 101 {
		t.Fatalf("truncated body too long: %d", len(body))
	}
}

func TestCallStaticHeaders(t *testing.T) {
	var tokenCalls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer static" {
			t.Errorf("Authorization = %q", r.Header.Get("Authorization"))
		}
		if r.Header.Get("x-ms-client-principal-id") != "static-oid" {
			t.Errorf("x-ms-client-principal-id = %q", r.Header.Get("x-ms-client-principal-id"))
		}
		w.Write([]byte(`ok`))
	}))
	defer srv.Close()

	c := NewClient(srv.URL, func(context.Context) (auth.Token, error) {
		tokenCalls.Add(1)
		return auth.Token{AccessToken: "tok"}, nil
	})
	c.Token = nil
	c.Static = http.Header{
		"Authorization":            {"Bearer static"},
		"X-Ms-Client-Principal-Id": {"static-oid"},
	}
	tool := spec.Tool{Method: http.MethodGet, Path: "/api/x", InputSchema: schema("opt"), ParamIn: paramIn("query", "opt")}

	res := c.Call(context.Background(), tool, nil)
	if res.IsError {
		t.Fatalf("unexpected error: %s", res.ErrorMessage)
	}
	if tokenCalls.Load() != 0 {
		t.Fatalf("token func called %d times", tokenCalls.Load())
	}
}

func TestCallStaticHeaderNotOverwrittenByToken(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Write([]byte(`ok`))
	}))
	defer srv.Close()

	c := NewClient(srv.URL, tokenFunc(auth.Token{AccessToken: "tok"}))
	c.Static = http.Header{"Authorization": {"Bearer static"}}
	tool := spec.Tool{Method: http.MethodGet, Path: "/api/x", InputSchema: schema("opt"), ParamIn: paramIn("query", "opt")}

	res := c.Call(context.Background(), tool, nil)
	if res.IsError {
		t.Fatalf("unexpected error: %s", res.ErrorMessage)
	}
	if gotAuth != "Bearer static" {
		t.Fatalf("Authorization = %q, want static value", gotAuth)
	}
}

func TestCallTransportErrorHidesURL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srvURL := srv.URL
	srv.Close() // server is gone
	host := strings.TrimPrefix(srvURL, "http://")

	c := NewClient(srvURL, nil)
	tool := spec.Tool{Method: http.MethodGet, Path: "/api/x", InputSchema: schema("opt"), ParamIn: paramIn("query", "opt")}

	res := c.Call(context.Background(), tool, nil)
	if !res.IsError {
		t.Fatal("expected transport error")
	}
	if res.ErrorMessage == "" {
		t.Fatal("expected error message")
	}
	if strings.Contains(res.ErrorMessage, host) || strings.Contains(res.ErrorMessage, srvURL) {
		t.Fatalf("ErrorMessage leaks URL/host: %q", res.ErrorMessage)
	}
}

func TestCallTokenError(t *testing.T) {
	c := NewClient("http://127.0.0.1:1", func(context.Context) (auth.Token, error) {
		return auth.Token{}, errors.New("login failed")
	})
	tool := spec.Tool{Method: http.MethodGet, Path: "/api/x", InputSchema: schema("opt"), ParamIn: paramIn("query", "opt")}

	res := c.Call(context.Background(), tool, nil)
	if !res.IsError || !strings.Contains(res.ErrorMessage, "login failed") {
		t.Fatalf("unexpected result: %+v", res)
	}
}

func TestCallMissingPathParam(t *testing.T) {
	c := NewClient("http://127.0.0.1:1", nil)
	tool := spec.Tool{
		Method:      http.MethodGet,
		Path:        "/api/workingday/{employeeSign}",
		InputSchema: schema("employeeSign"),
		ParamIn:     map[string]string{"employeeSign": "path"},
	}

	res := c.Call(context.Background(), tool, nil)
	if !res.IsError || !strings.Contains(res.ErrorMessage, "employeeSign") {
		t.Fatalf("unexpected result: %+v", res)
	}
}

func TestCallPostSendsJSONBody(t *testing.T) {
	var gotBody string
	var gotMethod, gotQuery, gotContentType string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotQuery = r.URL.RawQuery
		gotContentType = r.Header.Get("Content-Type")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	c := NewClient(srv.URL, nil)
	tool := spec.Tool{
		Method:      http.MethodPost,
		Path:        "/api/x/{id}",
		InputSchema: schema("id", "date", "startTime", "queryFlag"),
		ParamIn: map[string]string{
			"id":        "path",
			"date":      "body",
			"startTime": "body",
			"queryFlag": "query",
		},
	}

	res := c.Call(context.Background(), tool, map[string]any{
		"id":        "1",
		"date":      "2025-09-09",
		"startTime": "08:00",
		"queryFlag": "yes",
		"unknown":   "ignored",
	})
	if res.IsError {
		t.Fatalf("unexpected error: %s", res.ErrorMessage)
	}
	if gotMethod != http.MethodPost {
		t.Fatalf("method = %q", gotMethod)
	}
	if gotQuery != "queryFlag=yes" {
		t.Fatalf("query = %q", gotQuery)
	}
	if gotContentType != "application/json" {
		t.Fatalf("Content-Type = %q", gotContentType)
	}
	if !strings.Contains(gotBody, `"date":"2025-09-09"`) || !strings.Contains(gotBody, `"startTime":"08:00"`) {
		t.Fatalf("body = %q", gotBody)
	}
	if strings.Contains(gotBody, "id") || strings.Contains(gotBody, "unknown") || strings.Contains(gotBody, "queryFlag") {
		t.Fatalf("body must only contain body args: %q", gotBody)
	}
}

func TestCallGetWithBodyPropertyIsError(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	c := NewClient(srv.URL, nil)
	tool := spec.Tool{
		Method:      http.MethodGet,
		Path:        "/api/x",
		InputSchema: schema("date"),
		ParamIn:     map[string]string{"date": "body"},
	}

	res := c.Call(context.Background(), tool, map[string]any{"date": "2025-09-09"})
	if !res.IsError {
		t.Fatal("expected error for body field on GET")
	}
	if !strings.Contains(res.ErrorMessage, "does not take a body") {
		t.Fatalf("ErrorMessage = %q", res.ErrorMessage)
	}
	if calls.Load() != 0 {
		t.Fatalf("server calls = %d, want 0", calls.Load())
	}
}

func TestCallBaseURLQueryPreserved(t *testing.T) {
	var gotLoginName, gotDays string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotLoginName = r.URL.Query().Get("login-name")
		gotDays = r.URL.Query().Get("days")
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	c := NewClient(srv.URL+"?login-name=tt", nil)
	tool := spec.Tool{
		Method:      http.MethodGet,
		Path:        "/api/favorite",
		InputSchema: schema("days"),
		ParamIn:     map[string]string{"days": "query"},
	}

	res := c.Call(context.Background(), tool, map[string]any{"days": float64(3)})
	if res.IsError {
		t.Fatalf("unexpected error: %s", res.ErrorMessage)
	}
	if gotLoginName != "tt" {
		t.Fatalf("login-name = %q, want tt", gotLoginName)
	}
	if gotDays != "3" {
		t.Fatalf("days = %q, want 3", gotDays)
	}
}

func TestCallBaseURLQueryWithoutToolArgs(t *testing.T) {
	var gotLoginName string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotLoginName = r.URL.Query().Get("login-name")
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	c := NewClient(srv.URL+"?login-name=tt", nil)
	tool := spec.Tool{Method: http.MethodGet, Path: "/api/favorite", InputSchema: schema("opt"), ParamIn: paramIn("query", "opt")}

	res := c.Call(context.Background(), tool, nil)
	if res.IsError {
		t.Fatalf("unexpected error: %s", res.ErrorMessage)
	}
	if gotLoginName != "tt" {
		t.Fatalf("login-name = %q, want tt", gotLoginName)
	}
}

func TestCallToolWithoutParameters(t *testing.T) {
	var gotPath, gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotQuery = r.URL.RawQuery
		w.Write([]byte(`[]`))
	}))
	defer srv.Close()

	c := NewClient(srv.URL, nil)
	c.Static = http.Header{"Authorization": {"Bearer static"}}
	tool := spec.Tool{
		Method:      http.MethodGet,
		Path:        "/api/favorite",
		InputSchema: map[string]any{"type": "object"},
		ParamIn:     map[string]string{},
	}

	res := c.Call(context.Background(), tool, nil)
	if res.IsError {
		t.Fatalf("unexpected error: %s", res.ErrorMessage)
	}
	if gotPath != "/api/favorite" || gotQuery != "" {
		t.Fatalf("request = %q?%q", gotPath, gotQuery)
	}
}

func TestCallRejectsMissingParameterMetadata(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`[]`))
	}))
	defer srv.Close()

	c := NewClient(srv.URL, nil)
	tool := spec.Tool{Method: http.MethodGet, Path: "/api/favorite"}
	res := c.Call(context.Background(), tool, nil)
	if !res.IsError || !strings.Contains(res.ErrorMessage, "parameter metadata") {
		t.Fatalf("unexpected result: %+v", res)
	}
}

func TestCallServerErrorKeepsBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte(`{"detail":"upstream unavailable"}`))
	}))
	defer srv.Close()

	c := NewClient(srv.URL, nil)
	c.Static = http.Header{"Authorization": {"Bearer x"}}
	tool := spec.Tool{Method: http.MethodGet, Path: "/api/x", InputSchema: schema(), ParamIn: map[string]string{}}

	res := c.Call(context.Background(), tool, nil)
	if !res.IsError {
		t.Fatal("expected a server error to be reported as error")
	}
	if !strings.Contains(res.ErrorMessage, "502") || !strings.Contains(res.ErrorMessage, "upstream unavailable") {
		t.Fatalf("error message lacks status or body: %q", res.ErrorMessage)
	}
}
