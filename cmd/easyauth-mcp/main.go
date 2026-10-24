package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/HBTGmbH/easyauth-mcp/internal/api"
	"github.com/HBTGmbH/easyauth-mcp/internal/auth"
	"github.com/HBTGmbH/easyauth-mcp/internal/spec"
)

// version is overridable at build time via -ldflags.
var version = "dev"

func main() {
	os.Exit(run(os.Args[1:], os.Stderr))
}

func run(args []string, stderr io.Writer) int {
	s, help, err := parseSettings(args, stderr)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "error:", err)
		return 1
	}
	if help {
		return 0
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	server := mcp.NewServer(&mcp.Implementation{
		Name:    "easyauth-mcp",
		Version: version,
	}, &mcp.ServerOptions{
		Instructions: "This server exposes the operations of an OpenAPI-described API as tools. " +
			"If easyauth_sign_in is available, call it: it returns a device code, the user " +
			"confirms it in a browser, and calling it again completes the sign-in and registers " +
			"the API tools immediately. No server restart is needed at any point.",
	})

	// Never exit on configuration or spec problems: an MCP client only sees a
	// closed stdio connection ("Connection closed") and cannot tell the user
	// what is wrong. The server therefore always comes up; when it cannot build
	// the real tools it exposes a single setup-hint tool whose call returns the
	// actionable error. Only unexpected programming errors may still terminate
	// the process.
	tools, toolsErr := loadTools(s)
	var unauthorized *spec.ErrUnauthorized
	specNeedsAuth := toolsErr != nil && s.ConfigError == nil && errors.As(toolsErr, &unauthorized)
	if specNeedsAuth {
		// Some deployments protect the API docs as well. Retry with the static
		// header (if configured) or with an access token that is already
		// available. Without a token, a later sign-in tool loads the spec after
		// the user has signed in.
		if data, err := loadSpecAuthenticated(ctx, s, stderr); err == nil {
			tools, toolsErr = buildTools(data, s)
			specNeedsAuth = false
		}
	}
	// registrar installs the real tools on demand. It is shared with the
	// sign-in tool so tools become available right after a successful login,
	// without restarting the server.
	reg := &registrar{server: server, settings: s, stderr: stderr}

	switch {
	case s.ConfigError != nil:
		registerHelpTool(server, s, s.ConfigError)
		fmt.Fprintf(stderr, "easyauth-mcp: not configured: %v\n", s.ConfigError)
	case specNeedsAuth:
		registerSignInTool(server, reg)
		fmt.Fprintln(stderr, "easyauth-mcp: spec requires a sign-in; exposing easyauth_sign_in")
	case toolsErr != nil:
		registerHelpTool(server, s, toolsErr)
		fmt.Fprintf(stderr, "easyauth-mcp: spec error: %v\n", toolsErr)
	case len(tools) == 0:
		registerHelpTool(server, s, fmt.Errorf("the OpenAPI spec produced no tools with the current filter"))
		fmt.Fprintln(stderr, "easyauth-mcp: the spec produced no tools with the current filter")
	default:
		if err := reg.install(ctx, tools); err != nil {
			// Missing/invalid auth settings belong to the configuration, so
			// report them per call instead of exiting too.
			registerHelpTool(server, s, err)
			fmt.Fprintf(stderr, "easyauth-mcp: authentication not configured: %v\n", err)
			break
		}
		fmt.Fprintf(stderr, "easyauth-mcp: serving %d tool(s) from %s\n", len(tools), s.BaseURL)
	}

	// The stdio transport owns os.Stdin/os.Stdout; stdout must carry nothing
	// but JSON-RPC, which is why stdout is not written to anywhere else.
	if err := server.Run(ctx, &mcp.StdioTransport{}); err != nil && ctx.Err() == nil {
		fmt.Fprintln(stderr, "error:", err)
		return 1
	}
	return 0
}

// loadTools reads and parses the spec. A failure is returned to run, which
// turns it into a setup hint instead of terminating.
func loadTools(s settings) ([]spec.Tool, error) {
	data, err := spec.Load(s.OpenAPI)
	if err != nil {
		return nil, err
	}
	return buildTools(data, s)
}

func buildTools(data []byte, s settings) ([]spec.Tool, error) {
	spec.SetDeniedTags(s.DenyTags)
	return spec.Build(data, spec.Filter{
		PathPrefix:     s.PathPrefix,
		AllowedTags:    s.AllowedTags,
		AllowedMethods: s.AllowedMeths,
	})
}

// loadSpecAuthenticated fetches the spec with the configured credentials. Some
// deployments protect the API docs as well, in which case the anonymous fetch
// gets a 401.
//
// It must never block the server start on an interactive login: only a token
// that is already available (cached or refreshable) is used. Without one, the
// caller keeps the setup hint and the user signs in through a tool call.
func loadSpecAuthenticated(ctx context.Context, s settings, stderr io.Writer) ([]byte, error) {
	if s.AuthHeader != "" {
		return spec.LoadWithHeader(s.OpenAPI, staticHeaders(s))
	}

	session, err := buildSession(s, stderr)
	if err != nil {
		return nil, err
	}
	tok, err := session.Peek(ctx)
	if err != nil {
		return nil, err
	}
	return spec.LoadWithHeader(s.OpenAPI, tok.Header())
}

// buildClient wires either the static header mode (stage 1) or the device code
// auth (stage 3) into the generic API client.
func buildClient(_ context.Context, s settings, stderr io.Writer) (*api.Client, error) {
	client := api.NewClient(s.BaseURL, nil)
	client.Log = stderr
	client.Static = staticHeaders(s)

	if s.AuthHeader != "" {
		return client, nil
	}

	session, err := buildSession(s, stderr)
	if err != nil {
		return nil, err
	}

	// No eager login: a missing token is not an error. The first tool call that
	// needs one returns the device code as its result, so the user sees it in
	// the chat instead of a hidden stderr stream.
	client.Token = session.Token
	client.Refresh = session.Refresh
	return client, nil
}

// staticHeaders returns the headers for the static auth mode (stage 1).
func staticHeaders(s settings) http.Header {
	return headers(map[string]string{
		"Authorization":            s.AuthHeader,
		"x-ms-client-principal-id": s.PrincipalID,
	})
}

// buildSession validates the auth settings and returns a shared device-code
// session. One Session serves all tool calls and the spec fetch so refreshes
// and the login are serialized.
func buildSession(s settings, stderr io.Writer) (*auth.Session, error) {
	var missing []string
	if s.TenantID == "" {
		missing = append(missing, "--tenant-id/EASYAUTH_TENANT_ID")
	}
	if s.ClientID == "" {
		missing = append(missing, "--client-id/EASYAUTH_CLIENT_ID")
	}
	if s.Scope == "" {
		missing = append(missing, "--scope/EASYAUTH_SCOPE")
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("missing authentication settings: %s (or set EASYAUTH_AUTH_HEADER for static auth)", strings.Join(missing, ", "))
	}

	store := &auth.FileStore{Path: s.TokenStore}
	if s.Reauth {
		if err := store.Delete(); err != nil {
			return nil, fmt.Errorf("clearing token store: %w", err)
		}
	}

	return auth.NewSession(auth.NewAuth(auth.AuthConfig{
		LoginBase: s.LoginBase,
		TenantID:  s.TenantID,
		ClientID:  s.ClientID,
		Scope:     s.Scope,
		Store:     store,
		Out:       stderr,
	})), nil
}

func registerTools(server *mcp.Server, tools []spec.Tool, client *api.Client) {
	for _, tool := range tools {
		server.AddTool(&mcp.Tool{
			Name:        tool.Name,
			Description: tool.Description,
			InputSchema: tool.InputSchema,
		}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args, err := decodeArgs(req.Params.Arguments)
			if err != nil {
				return errorResult(fmt.Sprintf("invalid arguments: %v", err)), nil
			}
			res := client.Call(ctx, tool, args)
			if res.IsError {
				return errorResult(res.ErrorMessage), nil
			}
			return textResult(res.Body), nil
		})
	}
}

func decodeArgs(raw json.RawMessage) (map[string]any, error) {
	if len(raw) == 0 {
		return map[string]any{}, nil
	}
	var args map[string]any
	if err := json.Unmarshal(raw, &args); err != nil {
		return nil, err
	}
	return args, nil
}

func textResult(text string) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: text}},
	}
}

func errorResult(text string) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: text}},
		IsError: true,
	}
}

func headers(values map[string]string) map[string][]string {
	out := make(map[string][]string, len(values))
	for k, v := range values {
		if v != "" {
			out[k] = []string{v}
		}
	}
	return out
}

// registrar installs the real tools on a running server. AddTool notifies
// connected clients via tools/list_changed, so a sign-in followed by an install
// takes effect immediately; no restart is needed.
type registrar struct {
	server   *mcp.Server
	settings settings
	stderr   io.Writer

	mu        sync.Mutex
	client    *api.Client
	installed bool
}

// install builds the API client (once) and registers the tools. It returns the
// error that prevented registration, if any.
func (r *registrar) install(ctx context.Context, tools []spec.Tool) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.client == nil {
		client, err := buildClient(ctx, r.settings, r.stderr)
		if err != nil {
			return err
		}
		r.client = client
	}
	if r.installed {
		return nil
	}
	registerTools(r.server, tools, r.client)
	r.installed = true
	return nil
}
