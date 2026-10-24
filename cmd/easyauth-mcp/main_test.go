package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/HBTGmbH/easyauth-mcp/internal/spec"
)

func buildBinary(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "easyauth-mcp")
	cmd := exec.CommandContext(context.Background(), "go", "build", "-o", bin, ".") //nolint:gosec // G204: fixed arguments, bin is a temp path
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, out)
	}
	return bin
}

func newSession(t *testing.T, bin string, env ...string) *mcp.ClientSession {
	t.Helper()
	cmd := exec.CommandContext(context.Background(), bin) //nolint:gosec // G204: bin is the test-built binary
	cmd.Env = append(envScrubbed(), env...)
	cmd.Stderr = os.Stderr

	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "v0"}, nil)
	session, err := client.Connect(context.Background(), &mcp.CommandTransport{Command: cmd}, nil)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	return session
}

// envScrubbed returns the process environment without any EASYAUTH_* variables so
// the tests are hermetic regardless of the developer shell.
func envScrubbed() []string {
	var env []string
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "EASYAUTH_") {
			continue
		}
		env = append(env, kv)
	}
	return env
}

func TestStdioListsAndCallsWithStaticAuth(t *testing.T) {
	var gotAuth, gotPrincipal string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotPrincipal = r.Header.Get("x-ms-client-principal-id")
		if r.URL.Path != "/api/favorite" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `[{"sign":"AB","label":"Favorite"}]`)
	}))
	defer srv.Close()

	bin := buildBinary(t)
	session := newSession(t, bin,
		"EASYAUTH_BASE_URL="+srv.URL,
		"EASYAUTH_OPENAPI="+filepath.Join("..", "..", "testdata", "openapi-fixture.json"),
		"EASYAUTH_AUTH_HEADER=Bearer test-token",
		"EASYAUTH_PRINCIPAL_HEADER=oid-1",
	)
	defer func() { _ = session.Close() }()

	ctx := context.Background()
	list, err := session.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("list tools: %v", err)
	}
	names := map[string]bool{}
	for _, tool := range list.Tools {
		names[tool.Name] = true
		if strings.Contains(tool.Name, "rest") {
			t.Errorf("unexpected /rest tool %q", tool.Name)
		}
	}
	if !names["get_api_favorite"] {
		t.Fatalf("get_api_favorite missing; got %v", names)
	}
	if names["post_api_daily_reports"] {
		t.Error("write tool post_api_daily_reports present with default GET filter")
	}

	result, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "get_api_favorite",
		Arguments: map[string]any{},
	})
	if err != nil {
		t.Fatalf("call tool: %v", err)
	}
	if result.IsError {
		t.Fatalf("tool returned error: %v", result.Content)
	}
	text := contentText(result)
	if !strings.Contains(text, `"sign":"AB"`) {
		t.Errorf("unexpected body: %q", text)
	}
	if gotAuth != "Bearer test-token" {
		t.Errorf("Authorization = %q", gotAuth)
	}
	if gotPrincipal != "oid-1" {
		t.Errorf("principal = %q", gotPrincipal)
	}
}

func TestStdioFiltersByTags(t *testing.T) {
	bin := buildBinary(t)
	session := newSession(t, bin,
		"EASYAUTH_BASE_URL=http://localhost:9",
		"EASYAUTH_OPENAPI="+filepath.Join("..", "..", "testdata", "openapi-fixture.json"),
		"EASYAUTH_AUTH_HEADER=Bearer x",
		"EASYAUTH_ALLOWED_TAGS=favorite,daily report,working days,overtime,order,report",
		"EASYAUTH_ALLOWED_METHODS=GET",
	)
	defer func() { _ = session.Close() }()

	list, err := session.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatalf("list tools: %v", err)
	}
	for _, tool := range list.Tools {
		if strings.HasPrefix(tool.Name, "get_api_etl") {
			t.Errorf("etl tool %q present despite tag filter", tool.Name)
		}
	}
	if len(list.Tools) == 0 {
		t.Fatal("no tools listed")
	}
}

func TestStdioWithoutConfigOffersSetup(t *testing.T) {
	bin := buildBinary(t)
	configPath := filepath.Join(t.TempDir(), "config.json")
	session := newSession(t, bin, "EASYAUTH_CONFIG="+configPath)
	defer func() { _ = session.Close() }()

	ctx := context.Background()
	list, err := session.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("list tools on unconfigured server: %v", err)
	}
	if !hasTool(list, helpToolName) {
		t.Fatalf("setup tool %q missing; got %v", helpToolName, toolNames(list))
	}

	result, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      helpToolName,
		Arguments: map[string]any{},
	})
	if err != nil {
		t.Fatalf("call help: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected an error result from the help tool")
	}
	text := contentText(result)
	if !strings.Contains(text, "EASYAUTH_BASE_URL") || !strings.Contains(text, "missing") {
		t.Fatalf("help does not list missing variables: %q", text)
	}
}

func TestStdioUnloadableSpecOffersSetup(t *testing.T) {
	bin := buildBinary(t)
	session := newSession(t, bin,
		"EASYAUTH_CONFIG="+filepath.Join(t.TempDir(), "missing.json"),
		"EASYAUTH_BASE_URL=http://localhost:9",
		"EASYAUTH_OPENAPI="+filepath.Join(t.TempDir(), "missing-spec.json"),
		"EASYAUTH_AUTH_HEADER=Bearer test-token",
	)
	defer func() { _ = session.Close() }()

	ctx := context.Background()
	list, err := session.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("list tools with unloadable spec: %v", err)
	}
	if !hasTool(list, helpToolName) {
		t.Fatalf("setup tool %q missing; got %v", helpToolName, toolNames(list))
	}
}

func hasTool(list *mcp.ListToolsResult, name string) bool {
	for _, tool := range list.Tools {
		if tool.Name == name {
			return true
		}
	}
	return false
}

func toolNames(list *mcp.ListToolsResult) []string {
	var names []string
	for _, tool := range list.Tools {
		names = append(names, tool.Name)
	}
	return names
}

func contentText(result *mcp.CallToolResult) string {
	var b strings.Builder
	for _, c := range result.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			b.WriteString(tc.Text)
		}
	}
	return b.String()
}

// fakeEntra serves a device code endpoint and reports one pending poll, so a
// tool call returns the code while the background login waits for confirmation.
func fakeEntra(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/tenant/oauth2/v2.0/devicecode", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"device_code":      "dev",
			"user_code":        "WXYZ-1234",
			"verification_uri": "https://example.test/device",
			"expires_in":       60,
			"interval":         5,
		})
	})
	mux.HandleFunc("/tenant/oauth2/v2.0/token", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": "authorization_pending"})
	})
	return httptest.NewServer(mux)
}

func TestStartupWithoutTokenServesAndPromptsOnCall(t *testing.T) {
	entra := fakeEntra(t)
	defer entra.Close()

	bin := buildBinary(t)
	session := newSession(t, bin,
		"EASYAUTH_BASE_URL=http://localhost:9",
		"EASYAUTH_OPENAPI="+filepath.Join("..", "..", "testdata", "openapi-fixture.json"),
		"EASYAUTH_LOGIN_URL="+entra.URL,
		"EASYAUTH_TENANT_ID=tenant",
		"EASYAUTH_CLIENT_ID=client",
		"EASYAUTH_SCOPE=api://client/user_impersonation",
		"EASYAUTH_TOKEN_STORE="+filepath.Join(t.TempDir(), "token.json"),
	)
	defer func() { _ = session.Close() }()

	ctx := context.Background()
	list, err := session.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("list tools: %v", err)
	}
	if len(list.Tools) == 0 {
		t.Fatal("server started without tools")
	}

	result, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "get_api_favorite",
		Arguments: map[string]any{},
	})
	if err != nil {
		t.Fatalf("call tool: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected a sign-in prompt as an error result")
	}
	text := contentText(result)
	if !strings.Contains(text, "WXYZ-1234") || !strings.Contains(text, "https://example.test/device") {
		t.Fatalf("sign-in prompt missing the code: %q", text)
	}
}

// TestSignInRegistersToolsWithoutRestart verifies the list_changed flow: after
// the sign-in tool completes, the real tools appear on the same connection.
func TestSignInRegistersToolsWithoutRestart(t *testing.T) {
	specData, err := os.ReadFile(filepath.Join("..", "..", "testdata", "openapi-fixture.json")) //nolint:gosec // G304: test fixture path
	if err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/tenant/oauth2/v2.0/devicecode", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"device_code": "dev", "user_code": "CODE-9",
			"verification_uri": "https://example.test/device",
			"expires_in":       60, "interval": 1,
		})
	})
	mux.HandleFunc("/tenant/oauth2/v2.0/token", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":  fakeJWT("oid-1"),
			"refresh_token": "refresh",
			"expires_in":    3600,
		})
	})
	mux.HandleFunc("/api/doc/api-docs", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write(specData)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	bin := buildBinary(t)
	session := newSession(t, bin,
		"EASYAUTH_BASE_URL="+srv.URL,
		"EASYAUTH_OPENAPI="+srv.URL+"/api/doc/api-docs",
		"EASYAUTH_LOGIN_URL="+srv.URL,
		"EASYAUTH_TENANT_ID=tenant",
		"EASYAUTH_CLIENT_ID=client",
		"EASYAUTH_SCOPE=api://client/user_impersonation",
		"EASYAUTH_TOKEN_STORE="+filepath.Join(t.TempDir(), "token.json"),
	)
	defer func() { _ = session.Close() }()

	ctx := context.Background()
	before, err := session.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("list tools: %v", err)
	}
	if !hasTool(before, signInToolName) {
		t.Fatalf("expected %s before sign-in; got %v", signInToolName, toolNames(before))
	}

	// First call starts the login (code) or completes it, depending on timing.
	first, err := session.CallTool(ctx, &mcp.CallToolParams{Name: signInToolName, Arguments: map[string]any{}})
	if err != nil {
		t.Fatalf("call sign-in: %v", err)
	}
	firstText := contentText(first)

	// A second call must complete the sign-in and install the tools.
	var lastText string
	for range 40 {
		res, callErr := session.CallTool(ctx, &mcp.CallToolParams{Name: signInToolName, Arguments: map[string]any{}})
		if callErr != nil {
			t.Fatalf("call sign-in: %v", callErr)
		}
		lastText = contentText(res)
		if strings.Contains(lastText, "now available") {
			break
		}
		if strings.Contains(lastText, "no device code") {
			t.Fatalf("unexpected prompt: %q (first was %q)", lastText, firstText)
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !strings.Contains(lastText, "now available") {
		t.Fatalf("sign-in did not complete: %q", lastText)
	}

	after, err := session.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("list tools after sign-in: %v", err)
	}
	if !hasTool(after, "get_api_favorite") {
		t.Fatalf("real tools not registered after sign-in; got %v", toolNames(after))
	}
}

func fakeJWT(oid string) string {
	enc := base64.RawURLEncoding
	payload, _ := json.Marshal(map[string]any{"oid": oid, "mailnickname": "sign", "exp": 9999999999}) //nolint:errchkjson // fixed test payload
	return enc.EncodeToString([]byte(`{"alg":"none"}`)) + "." +
		enc.EncodeToString(payload) + ".sig"
}

// TestStaticHeaderLoadsProtectedSpec covers the static auth mode when the API
// docs themselves require authentication.
func TestStaticHeaderLoadsProtectedSpec(t *testing.T) {
	specData, err := os.ReadFile(filepath.Join("..", "..", "testdata", "openapi-fixture.json")) //nolint:gosec // G304: test fixture path
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/doc/api-docs", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer static-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write(specData)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	bin := buildBinary(t)
	session := newSession(t, bin,
		"EASYAUTH_BASE_URL="+srv.URL,
		"EASYAUTH_OPENAPI="+srv.URL+"/api/doc/api-docs",
		"EASYAUTH_AUTH_HEADER=Bearer static-token",
		"EASYAUTH_ALLOWED_TAGS=favorite",
	)
	defer func() { _ = session.Close() }()

	list, err := session.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatalf("list tools: %v", err)
	}
	if !hasTool(list, "get_api_favorite") {
		t.Fatalf("real tools missing with static auth; got %v", toolNames(list))
	}
	if hasTool(list, helpToolName) {
		t.Fatal("help tool should not be exposed when the spec loads")
	}
}

func TestSignInSuccessMentionsTools(t *testing.T) {
	tools := []spec.Tool{
		{Name: "get_api_favorite"},
		{Name: "get_api_overtimes_status"},
		{Name: "aaa_first"},
	}
	got := toolNameSample(tools, 2)
	if !strings.HasPrefix(got, "aaa_first") {
		t.Fatalf("sample is not sorted: %q", got)
	}
	if !strings.Contains(got, "…") {
		t.Fatalf("sample should mark omissions: %q", got)
	}
	if all := toolNameSample(tools[:2], 5); strings.Contains(all, "…") {
		t.Fatalf("short list must not be truncated: %q", all)
	}
}
