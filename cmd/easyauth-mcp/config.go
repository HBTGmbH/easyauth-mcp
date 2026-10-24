package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/HBTGmbH/easyauth-mcp/internal/auth"
)

const defaultLoginBase = auth.DefaultLoginBase

// settings is the fully resolved configuration for one run. Configuration comes
// exclusively from flags and environment variables.
type settings struct {
	BaseURL      string
	OpenAPI      string
	LoginBase    string
	TenantID     string
	ClientID     string
	Scope        string
	TokenStore   string
	AuthHeader   string
	PrincipalID  string
	AllowedTags  []string
	AllowedMeths []string
	PathPrefix   string
	DenyTags     []string
	Reauth       bool
	// ConfigError collects every problem that makes the settings unusable
	// (missing required values, insecure URLs). The MCP server still starts and
	// reports the problem per tool call instead of exiting, so the stdio
	// connection never drops.
	ConfigError error
}

// parseSettings reads flags and environment variables (flags win) and returns
// the resolved settings. help is true when --help was requested.
//
// Only flag parsing errors are returned as err. Configuration problems are
// collected in settings.ConfigError so that the caller can keep the server
// alive and report them through the help tool.
func parseSettings(args []string, out io.Writer) (settings, bool, error) {
	fs := flag.NewFlagSet("easyauth-mcp", flag.ContinueOnError)
	fs.SetOutput(out)

	var (
		baseURL     = fs.String("base-url", "", "base URL of the API (defaults to $EASYAUTH_BASE_URL)")
		openAPI     = fs.String("openapi", "", "path or URL of the OpenAPI 3 JSON spec (defaults to $EASYAUTH_OPENAPI)")
		loginBase   = fs.String("login-url", defaultLoginBase, "Entra ID login base URL (defaults to $EASYAUTH_LOGIN_URL)")
		tenantID    = fs.String("tenant-id", "", "Entra ID tenant ID (defaults to $EASYAUTH_TENANT_ID)")
		clientID    = fs.String("client-id", "", "Entra ID client ID of the app registration (defaults to $EASYAUTH_CLIENT_ID)")
		scope       = fs.String("scope", "", "Entra ID API scope (defaults to $EASYAUTH_SCOPE)")
		tokenStore  = fs.String("token-store", "", "token store file (defaults to $EASYAUTH_TOKEN_STORE, then the state dir)")
		authHeader  = fs.String("auth-header", "", "static Authorization header value, e.g. 'Bearer ...' (defaults to $EASYAUTH_AUTH_HEADER)")
		principalID = fs.String("principal-id", "", "static x-ms-client-principal-id value (defaults to $EASYAUTH_PRINCIPAL_HEADER)")
		allowedTags = fs.String("allowed-tags", "", "comma list of allowed OpenAPI tags; empty means all tags not listed in --deny-tags (defaults to $EASYAUTH_ALLOWED_TAGS)")
		allowedMeth = fs.String("allowed-methods", "GET", "comma list of allowed HTTP methods (defaults to $EASYAUTH_ALLOWED_METHODS)")
		pathPrefix  = fs.String("path-prefix", "/api/", "only paths with this prefix become tools (defaults to $EASYAUTH_PATH_PREFIX)")
		denyTags    = fs.String("deny-tags", "", "comma list of tags that never become tools, even when allowed (defaults to $EASYAUTH_DENY_TAGS)")
		reauth      = fs.Bool("reauth", false, "ignore the cached token and sign in again")
	)

	fs.Usage = func() {
		_, _ = fmt.Fprint(out, `Usage: easyauth-mcp [flags]

Generic MCP server (stdio) that derives tools from an OpenAPI spec and calls an OpenAPI-described API protected by EasyAuth.
All logging goes to stderr; stdout carries the MCP protocol.

Configuration comes from flags and environment variables; flags win.
Environment variables: EASYAUTH_BASE_URL, EASYAUTH_OPENAPI, EASYAUTH_LOGIN_URL, EASYAUTH_TENANT_ID,
EASYAUTH_CLIENT_ID, EASYAUTH_SCOPE, EASYAUTH_TOKEN_STORE, EASYAUTH_AUTH_HEADER,
EASYAUTH_PRINCIPAL_HEADER, EASYAUTH_ALLOWED_TAGS, EASYAUTH_ALLOWED_METHODS, EASYAUTH_PATH_PREFIX,
EASYAUTH_DENY_TAGS.

Flags:
`)
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return settings{}, true, nil
		}
		return settings{}, false, err
	}

	s := settings{
		BaseURL:      resolve(fs, "base-url", *baseURL, "EASYAUTH_BASE_URL"),
		OpenAPI:      resolve(fs, "openapi", *openAPI, "EASYAUTH_OPENAPI"),
		LoginBase:    resolve(fs, "login-url", *loginBase, "EASYAUTH_LOGIN_URL"),
		TenantID:     resolve(fs, "tenant-id", *tenantID, "EASYAUTH_TENANT_ID"),
		ClientID:     resolve(fs, "client-id", *clientID, "EASYAUTH_CLIENT_ID"),
		Scope:        resolve(fs, "scope", *scope, "EASYAUTH_SCOPE"),
		TokenStore:   resolve(fs, "token-store", *tokenStore, "EASYAUTH_TOKEN_STORE"),
		AuthHeader:   resolve(fs, "auth-header", *authHeader, "EASYAUTH_AUTH_HEADER"),
		PrincipalID:  resolve(fs, "principal-id", *principalID, "EASYAUTH_PRINCIPAL_HEADER"),
		AllowedTags:  splitList(resolve(fs, "allowed-tags", *allowedTags, "EASYAUTH_ALLOWED_TAGS")),
		AllowedMeths: splitList(resolve(fs, "allowed-methods", *allowedMeth, "EASYAUTH_ALLOWED_METHODS")),
		PathPrefix:   resolve(fs, "path-prefix", *pathPrefix, "EASYAUTH_PATH_PREFIX"),
		DenyTags:     splitList(resolve(fs, "deny-tags", *denyTags, "EASYAUTH_DENY_TAGS")),
		Reauth:       *reauth,
	}

	// configErr collects all problems instead of failing early, so the message
	// given to the agent covers every missing piece at once.
	var configErr error
	addErr := func(err error) {
		if err == nil {
			return
		}
		if configErr == nil {
			configErr = err
			return
		}
		configErr = fmt.Errorf("%v; %w", configErr, err)
	}

	if s.BaseURL == "" {
		addErr(fmt.Errorf("missing --base-url or EASYAUTH_BASE_URL"))
	}
	if s.OpenAPI == "" {
		addErr(fmt.Errorf("missing --openapi or EASYAUTH_OPENAPI"))
	}
	addErr(checkHTTPS(s.BaseURL, s.LoginBase))
	if u, err := url.Parse(s.OpenAPI); err == nil && (u.Scheme == "http" || u.Scheme == "https") {
		addErr(checkHTTPS(s.OpenAPI))
	}
	if s.TokenStore == "" {
		store, err := defaultTokenStore()
		if err != nil {
			addErr(fmt.Errorf("resolving token store: %w", err))
		} else {
			s.TokenStore = store
		}
	}
	s.ConfigError = configErr
	return s, false, nil
}

// resolve applies the precedence explicit flag > env > default.
func resolve(fs *flag.FlagSet, name, current, env string) string {
	var explicit bool
	fs.Visit(func(f *flag.Flag) {
		if f.Name == name {
			explicit = true
		}
	})
	if explicit {
		return current
	}
	if v := os.Getenv(env); v != "" {
		return v
	}
	return current
}

func splitList(s string) []string {
	var items []string
	for part := range strings.SplitSeq(s, ",") {
		if part = strings.TrimSpace(part); part != "" {
			items = append(items, part)
		}
	}
	return items
}

// defaultTokenStore returns $XDG_STATE_HOME/easyauth-mcp/token.json, falling back
// to ~/.local/state/easyauth-mcp/token.json and finally the temp dir.
func defaultTokenStore() (string, error) {
	if dir := os.Getenv("XDG_STATE_HOME"); dir != "" {
		return filepath.Join(dir, "easyauth-mcp", "token.json"), nil
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		return filepath.Join(home, ".local", "state", "easyauth-mcp", "token.json"), nil
	}
	if home := os.Getenv("HOME"); home != "" {
		return filepath.Join(home, ".local", "state", "easyauth-mcp", "token.json"), nil
	}
	return filepath.Join(os.TempDir(), "easyauth-mcp", "token.json"), nil
}

func checkHTTPS(urls ...string) error {
	for _, raw := range urls {
		if raw == "" {
			continue
		}
		u, err := url.Parse(raw)
		if err != nil {
			return fmt.Errorf("invalid URL %q: %w", raw, err)
		}
		host := strings.ToLower(u.Hostname())
		if u.Scheme == "https" || host == "localhost" || host == "127.0.0.1" || host == "::1" {
			continue
		}
		return fmt.Errorf("insecure URL %q: HTTPS is required (only localhost may use HTTP)", raw)
	}
	return nil
}
