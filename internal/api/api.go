// Package api executes a generic HTTP request for an MCP tool against an
// OpenAPI-described REST API protected by EasyAuth.
//
// Where each argument goes is decided by spec.Tool.ParamIn, which maps every
// schema property to "path", "query", "header" or "body". There is no
// method-based guessing: a tool without parameter metadata is rejected.
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/HBTGmbH/easyauth-mcp/internal/auth"
	"github.com/HBTGmbH/easyauth-mcp/internal/spec"
)

// Defaults used when the Client fields are zero.
const (
	defaultTimeout = 60 * time.Second
	defaultMaxBody = 256 << 10 // 256 KiB
	errorTailLimit = 500       // max body bytes appended to an error message
)

// ignoredHeaders are never set from tool arguments; they are controlled by
// the client (auth, content negotiation, proxy identity).
var ignoredHeaders = map[string]bool{
	"authorization":            true,
	"accept":                   true,
	"content-type":             true,
	"x-ms-client-principal-id": true,
}

// Client executes tool calls against the API.
//
// The zero value is not usable; use NewClient.
type Client struct {
	BaseURL string                                        // e.g. https://<host> or http://localhost:8080
	HTTP    *http.Client                                  // default: 60s timeout
	Token   func(ctx context.Context) (auth.Token, error) // obtains/renews a token
	Refresh func(ctx context.Context) (auth.Token, error) // optional, force refresh after 401
	Static  http.Header                                   // optional static headers (stage 1)
	MaxBody int                                           // max returned body bytes; default 256 KiB
	Log     io.Writer                                     // optional, warnings only (never secrets)
}

// Result is the outcome of one tool call.
type Result struct {
	Status       int
	Body         string
	Truncated    bool
	IsError      bool // true for request/transport errors, token errors, 5xx or 401 after retry
	ErrorMessage string
}

// NewClient returns a Client for baseURL that pulls tokens from token.
func NewClient(baseURL string, token func(context.Context) (auth.Token, error)) *Client {
	return &Client{
		BaseURL: strings.TrimRight(baseURL, "/"),
		Token:   token,
	}
}

func (c *Client) httpClient() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{Timeout: defaultTimeout}
}

func (c *Client) maxBody() int {
	if c.MaxBody > 0 {
		return c.MaxBody
	}
	return defaultMaxBody
}

func (c *Client) warn(msg string) {
	if c.Log != nil {
		_, _ = fmt.Fprintln(c.Log, "easyauth: "+msg)
	}
}

// Call builds and executes the request for tool with args and returns the
// response body as text. Only arguments whose names appear in tool.ParamIn
// are sent; anything else (including a removed "csv" parameter) is dropped.
func (c *Client) Call(ctx context.Context, tool *spec.Tool, args map[string]any) Result {
	req, err := c.buildRequest(ctx, tool, args)
	if err != nil {
		if need, ok := errors.AsType[loginError](err); ok {
			return Result{IsError: true, ErrorMessage: loginMessage(need.login)}
		}
		return Result{IsError: true, ErrorMessage: err.Error()}
	}

	res := c.do(req)

	switch {
	case res.Status == http.StatusUnauthorized && c.Token != nil && c.Refresh != nil:
		c.warn("got 401, refreshing token and retrying once")
		tok, err := c.Refresh(ctx)
		if err != nil {
			res.IsError = true
			res.ErrorMessage = withBody("refreshing token after 401 failed: "+err.Error(), res.Body)
			return res
		}
		req, err = c.buildRequestWithToken(ctx, tool, args, &tok)
		if err != nil {
			return Result{IsError: true, ErrorMessage: err.Error()}
		}
		res = c.do(req)
		if res.Status == http.StatusUnauthorized {
			res.IsError = true
			res.ErrorMessage = withBody("unauthorized after token refresh", res.Body)
		}
	case res.Status == http.StatusUnauthorized && c.Token != nil:
		// Token present but no way to force a renewed token: no retry.
		res.IsError = true
		res.ErrorMessage = withBody("unauthorized", res.Body)
	case res.Status == http.StatusUnauthorized:
		// Static mode: nothing to refresh.
		res.IsError = true
		res.ErrorMessage = withBody("unauthorized", res.Body)
	}

	if res.Status >= 500 && !res.IsError {
		res.IsError = true
		res.ErrorMessage = withBody(fmt.Sprintf("server error %d", res.Status), res.Body)
	}
	return res
}

func (c *Client) buildRequest(ctx context.Context, tool *spec.Tool, args map[string]any) (*http.Request, error) {
	var tok auth.Token
	if c.Token != nil {
		t, err := c.Token(ctx)
		if err != nil {
			if required, ok := errors.AsType[*auth.ErrLoginRequired](err); ok {
				return nil, loginError{login: required.Login}
			}
			return nil, fmt.Errorf("obtaining token: %w", err)
		}
		tok = t
	}
	return c.buildRequestWithToken(ctx, tool, args, &tok)
}

// loginError carries a device code so the tool handler can show it to the user
// instead of failing with a generic authentication error.
type loginError struct {
	login auth.DeviceLogin
}

func (e loginError) Error() string {
	return "sign-in required"
}

func (c *Client) buildRequestWithToken(ctx context.Context, tool *spec.Tool, args map[string]any, tok *auth.Token) (*http.Request, error) {
	rawURL, body, headerArgs, err := c.buildTarget(tool, args)
	if err != nil {
		return nil, err
	}

	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, tool.Method, rawURL, reader)
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
	}

	// Static headers first, then token headers only if static did not set them.
	// This lets stage 1 run on static credentials while stage 3 uses tokens.
	for name, values := range c.Static {
		for _, v := range values {
			req.Header.Add(name, v)
		}
	}
	if tok.AccessToken != "" {
		for name, values := range tok.Header() {
			if req.Header.Get(name) == "" {
				for _, v := range values {
					req.Header.Set(name, v)
				}
			}
		}
	}
	// Header parameters from tool arguments must not override auth/config
	// headers, so only add them when the key is not already present.
	for name, value := range headerArgs {
		if req.Header.Get(name) == "" {
			req.Header.Set(name, value)
		}
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return req, nil
}

// buildTarget resolves path parameters, appends query parameters and, when a
// body is sent, marshals body arguments. It returns the absolute URL, an
// optional request body and the header parameters to set.
func (c *Client) buildTarget(tool *spec.Tool, args map[string]any) (string, []byte, map[string]string, error) { //nolint:gocritic // unnamedResult: the names would collide with locals
	if tool.ParamIn == nil {
		return "", nil, nil, fmt.Errorf("tool has no parameter metadata")
	}

	path, err := resolvePath(tool, args)
	if err != nil {
		return "", nil, nil, err
	}

	base, err := url.Parse(c.BaseURL)
	if err != nil {
		return "", nil, nil, fmt.Errorf("invalid base URL: %w", err)
	}
	query := base.Query()
	base.RawQuery = ""
	base.Fragment = ""
	base.RawFragment = ""

	bodyMethod := isBodyMethod(tool.Method)
	body := make(map[string]any)
	headers := make(map[string]string)
	for name, where := range tool.ParamIn {
		value, ok := args[name]
		if !ok || value == nil {
			continue
		}
		switch where {
		case "path":
			// already handled by resolvePath
		case "query":
			appendQuery(query, name, value)
		case "header":
			if ignoredHeaders[strings.ToLower(name)] {
				continue
			}
			if str, ok := stringValue(value); ok {
				headers[name] = str
			}
		case "body":
			if !bodyMethod {
				return "", nil, nil, fmt.Errorf("tool has body fields but method does not take a body")
			}
			body[name] = value
		}
	}

	target := strings.TrimRight(base.String(), "/") + path
	if encoded := query.Encode(); encoded != "" {
		target += "?" + encoded
	}

	if len(body) == 0 {
		return target, nil, headers, nil
	}
	data, err := json.Marshal(body)
	if err != nil {
		return "", nil, nil, fmt.Errorf("encoding request body: %w", err)
	}
	return target, data, headers, nil
}

// resolvePath substitutes every {name} placeholder with the matching path
// argument. Path arguments are validated against traversal before escaping.
func resolvePath(tool *spec.Tool, args map[string]any) (string, error) {
	path := tool.Path
	for _, name := range pathParamNames(tool.Path) {
		value, ok := args[name]
		if !ok || value == nil {
			return "", fmt.Errorf("missing required path parameter %q", name)
		}
		str, ok := stringValue(value)
		if !ok {
			return "", fmt.Errorf("path parameter %q cannot be converted to string", name)
		}
		if invalidPathValue(str) {
			return "", fmt.Errorf("invalid path parameter %q", name)
		}
		path = strings.ReplaceAll(path, "{"+name+"}", url.PathEscape(str))
	}
	for segment := range strings.SplitSeq(path, "/") {
		if segment == "." || segment == ".." {
			return "", fmt.Errorf("invalid path parameter: resolved path contains %q segment", segment)
		}
	}
	return path, nil
}

// invalidPathValue rejects empty values, backslashes and dot traversal
// segments. Ordinary slashes are escaped (url.PathEscape), so values like
// "a b/c" remain usable, but "." and ".." segments never reach the request.
func invalidPathValue(value string) bool {
	if value == "" || strings.ContainsRune(value, '\\') {
		return true
	}
	for segment := range strings.SplitSeq(value, "/") {
		if segment == "." || segment == ".." {
			return true
		}
	}
	return false
}

// transportErrorText returns a message without URL or host. The *url.Error
// and *net.OpError wrappers carry the address; unwrap them and keep the
// underlying cause.
func transportErrorText(err error) string {
	if urlErr, ok := errors.AsType[*url.Error](err); ok {
		err = urlErr.Err
	}
	if opErr, ok := errors.AsType[*net.OpError](err); ok {
		if opErr.Err != nil {
			err = opErr.Err
		}
	}
	return err.Error()
}

func (c *Client) do(req *http.Request) Result {
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return Result{IsError: true, ErrorMessage: "request failed: " + transportErrorText(err)}
	}
	defer func() { _ = resp.Body.Close() }()

	limit := c.maxBody()
	data, err := io.ReadAll(io.LimitReader(resp.Body, int64(limit)+1))
	if err != nil {
		return Result{Status: resp.StatusCode, IsError: true, ErrorMessage: "reading response: " + err.Error()}
	}

	res := Result{Status: resp.StatusCode}
	if len(data) > limit {
		res.Truncated = true
	}
	res.Body = truncateUTF8(string(data), limit)
	if res.Truncated {
		res.Body += fmt.Sprintf("\n[truncated to %d bytes]", limit)
	}
	return res
}

// buildTarget helpers

// pathParamNames returns the {name} placeholders of a path template in order.
func pathParamNames(path string) []string {
	var names []string
	for {
		start := strings.IndexByte(path, '{')
		if start < 0 {
			return names
		}
		rest := path[start+1:]
		before, after, ok := strings.Cut(rest, "}")
		if !ok {
			return names
		}
		names = append(names, before)
		path = after
	}
}

func isBodyMethod(method string) bool {
	switch strings.ToUpper(method) {
	case http.MethodPost, http.MethodPut, http.MethodPatch:
		return true
	default:
		return false
	}
}

func appendQuery(query url.Values, name string, value any) {
	switch v := value.(type) {
	case nil:
		return
	case []any:
		for _, item := range v {
			if str, ok := stringValue(item); ok {
				query.Add(name, str)
			}
		}
	case []string:
		for _, item := range v {
			query.Add(name, item)
		}
	case bool:
		if v {
			query.Add(name, "true")
		} else {
			query.Add(name, "false")
		}
	default:
		if str, ok := stringValue(v); ok {
			query.Add(name, str)
		}
	}
}

func stringValue(value any) (string, bool) {
	switch v := value.(type) {
	case string:
		return v, true
	case float64:
		// JSON numbers arrive as float64; format integral values without
		// exponent ("3", not "3e+00").
		if v == float64(int64(v)) {
			return fmt.Sprint(int64(v)), true
		}
		return fmt.Sprint(v), true
	case float32:
		if v == float32(int64(v)) {
			return fmt.Sprint(int64(v)), true
		}
		return fmt.Sprint(v), true
	case bool, int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		return fmt.Sprint(v), true
	case json.Number:
		return v.String(), true
	default:
		return "", false
	}
}

// truncateUTF8 cuts s to at most max bytes without splitting a UTF-8 rune.
func truncateUTF8(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	cut := limit
	for cut > 0 && s[cut]&0xC0 == 0x80 { // back off continuation bytes
		cut--
	}
	return s[:cut]
}

func withBody(message, body string) string {
	body = strings.TrimSpace(body)
	if len(body) > errorTailLimit {
		body = truncateUTF8(body, errorTailLimit) + "…"
	}
	if body == "" {
		return message
	}
	return message + ": " + body
}

// loginMessage renders the device code into a message the agent can show. It
// contains no secrets: user_code and verification_uri are meant for the user.
func loginMessage(d auth.DeviceLogin) string {
	if d.VerificationURI == "" || d.UserCode == "" {
		return "Sign-in required. Run `easyauth-mcp --init` once in a terminal to sign in, then retry."
	}
	return fmt.Sprintf(
		"Sign-in required. Open %s and enter the code %s, then run this tool again. "+
			"The sign-in happened in the background; this message appears until it is confirmed.",
		d.VerificationURI, d.UserCode)
}
