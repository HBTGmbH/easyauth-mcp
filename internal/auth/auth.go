// Package auth implements the Entra ID device code flow and keeps the access
// token fresh via refresh tokens.
//
// stdout is sacred: the MCP server speaks JSON-RPC on stdio. All output of this
// package (user code, progress, warnings) goes to Config.Out only, which the
// caller is expected to set to os.Stderr.
package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	// DefaultLoginBase is the Entra ID (formerly Azure AD) login base URL used
	// when AuthConfig.LoginBase is empty.
	DefaultLoginBase = "https://login.microsoftonline.com"
	deviceGrant      = "urn:ietf:params:oauth:grant-type:device_code"
)

// AuthConfig configures an Auth instance. LoginBase defaults to
// DefaultLoginBase; HTTP and Sleep default to sensible production values.
type AuthConfig struct {
	// LoginBase is the Entra login base URL, e.g. DefaultLoginBase.
	LoginBase string
	// TenantID is the Entra tenant (GUID or domain).
	TenantID string
	// ClientID is the public client application ID.
	ClientID string
	// Scope is the requested scope; offline_access/openid/profile are added.
	Scope string
	// HTTP is the HTTP client used for token requests.
	HTTP *http.Client
	// Store persists tokens between runs. It may be nil for in-memory only.
	Store Store
	// Out receives user-facing progress and warnings (must be stderr).
	Out io.Writer
	// Sleep is used to poll the device code endpoint; defaults to time.Sleep.
	Sleep func(time.Duration)
}

// Token is an OAuth access/refresh token pair as persisted by Store.
type Token struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	ExpiresAt    time.Time `json:"expires_at"`
	// OID is not persisted; it is decoded from AccessToken.
	OID          string `json:"-"`
	MailNickname string `json:"-"`
	// jwtExp is the access token's expiry decoded from its JWT claims. It is
	// not persisted and is the source of truth for Valid when present.
	jwtExp time.Time
}

// Valid reports whether the access token is present and not about to expire.
// When the JWT exposes an exp claim, that value is authoritative; otherwise
// ExpiresAt (from the token endpoint's expires_in) is used.
func (t *Token) Valid() bool {
	if t.AccessToken == "" {
		return false
	}
	exp := t.ExpiresAt
	if !t.jwtExp.IsZero() {
		exp = t.jwtExp
	}
	return time.Now().Before(exp.Add(-60 * time.Second))
}

// Header returns request headers for the token: Authorization Bearer and,
// when an OID is known, x-ms-client-principal-id as required by EasyAuth.
func (t *Token) Header() http.Header {
	h := make(http.Header)
	h.Set("Authorization", "Bearer "+t.AccessToken)
	if t.OID != "" {
		h.Set("x-ms-client-principal-id", t.OID)
	}
	return h
}

// Claims is the subset of JWT claims this package uses.
type Claims struct {
	OID          string
	MailNickname string
	// Exp is the token expiry from the exp claim. It is zero when the claim is
	// absent or malformed.
	Exp time.Time
}

// ParseClaims extracts oid, mailnickname and exp from a JWT payload. The
// signature is not verified; claims are only read. Any malformed input is an
// error. A missing exp claim is not an error; Exp is then zero.
func ParseClaims(accessToken string) (Claims, error) {
	parts := strings.Split(accessToken, ".")
	if len(parts) < 2 {
		return Claims{}, errors.New("access token is not a JWT")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		// Some issuers pad the segment; tolerate that.
		payload, err = base64.URLEncoding.DecodeString(parts[1])
		if err != nil {
			return Claims{}, fmt.Errorf("decoding JWT payload: %w", err)
		}
	}
	var raw struct {
		OID          string          `json:"oid"`
		MailNickname string          `json:"mailnickname"`
		Exp          json.RawMessage `json:"exp"`
	}
	if err := json.Unmarshal(payload, &raw); err != nil {
		return Claims{}, fmt.Errorf("decoding JWT claims: %w", err)
	}
	c := Claims{OID: raw.OID, MailNickname: raw.MailNickname}
	if len(raw.Exp) > 0 {
		var secs float64
		if err := json.Unmarshal(raw.Exp, &secs); err == nil && secs > 0 {
			c.Exp = time.Unix(int64(secs), 0)
		}
	}
	return c, nil
}

// Auth obtains and refreshes access tokens via the Entra device code flow.
type Auth struct {
	cfg AuthConfig

	mu    sync.Mutex
	token Token
	// deviceHook, when non-nil, receives the device code before polling starts.
	// It is used by Session to hand the code out without blocking.
	deviceHook func(DeviceLogin)
}

// NewAuth returns an Auth with defaults applied. It does not contact the
// network; tokens are loaded lazily on first use.
func NewAuth(base *AuthConfig) *Auth {
	cfg := *base
	if cfg.LoginBase == "" {
		cfg.LoginBase = DefaultLoginBase
	}
	if cfg.HTTP == nil {
		cfg.HTTP = &http.Client{Timeout: 30 * time.Second}
	}
	if cfg.Sleep == nil {
		cfg.Sleep = time.Sleep
	}
	return &Auth{cfg: cfg}
}

func (a *Auth) scope() string {
	if strings.Contains(a.cfg.Scope, "offline_access") {
		return a.cfg.Scope
	}
	return a.cfg.Scope + " offline_access openid profile"
}

func (a *Auth) tokenEndpoint() string {
	return fmt.Sprintf("%s/%s/oauth2/v2.0/token", strings.TrimRight(a.cfg.LoginBase, "/"), a.cfg.TenantID)
}

func (a *Auth) deviceEndpoint() string {
	return fmt.Sprintf("%s/%s/oauth2/v2.0/devicecode", strings.TrimRight(a.cfg.LoginBase, "/"), a.cfg.TenantID)
}

// tokenMode selects how AccessToken/Refresh resolve a token.
type tokenMode int

const (
	// modeNormal reuses a valid cached token and only refreshes when needed.
	modeNormal tokenMode = iota
	// modeRefresh ignores a valid cached token and forces a refresh.
	modeRefresh
)

// AccessToken returns a usable token: it reuses a valid cached token, refreshes
// with the stored refresh token, or falls back to an interactive device code
// login. A refresh that fails with invalid_grant clears the store and starts a
// device login.
//
// The whole operation runs under one mutex, so concurrent callers trigger at
// most one refresh or login. A device login can block other callers for a long
// time; for a sequential stdio server that is acceptable.
func (a *Auth) AccessToken(ctx context.Context) (Token, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.resolve(ctx, modeNormal)
}

// Refresh forces a token refresh using the stored refresh token, ignoring any
// cached but still-valid access token. If no refresh token is available, or the
// refresh is rejected with invalid_grant, it falls back to a device code login.
//
// Use this after a 401: the server has rejected the current access token even
// though it may not have expired yet.
func (a *Auth) Refresh(ctx context.Context) (Token, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.resolve(ctx, modeRefresh)
}

// Login discards any cached or stored token and starts a fresh device code
// login. Use it for an explicit re-authentication (e.g. --reauth).
func (a *Auth) Login(ctx context.Context) (Token, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.clear()
	tok, err := a.deviceLogin(ctx)
	if err != nil {
		return Token{}, err
	}
	return a.persist(&tok), nil
}

// resolve implements the shared AccessToken/Refresh logic. The caller must hold
// a.mu.
func (a *Auth) resolve(ctx context.Context, mode tokenMode) (Token, error) {
	a.load()
	if mode == modeNormal && a.token.Valid() {
		return a.token, nil
	}
	if a.token.RefreshToken != "" {
		tok, err := a.refresh(ctx)
		if err == nil {
			return a.persist(&tok), nil
		}
		if !errors.Is(err, errReauth) {
			return Token{}, fmt.Errorf("refreshing access token: %w", err)
		}
		// invalid_grant: drop the token and fall through to a new login.
		a.announce("Access token expired, starting a new device code login")
		a.clear()
	}
	tok, err := a.deviceLogin(ctx)
	if err != nil {
		return Token{}, err
	}
	return a.persist(&tok), nil
}

// load fills the in-memory token from the store. A broken store is reported as
// a warning (without token material) and treated as empty so that a first start
// goes straight to the device login.
func (a *Auth) load() {
	if a.cfg.Store == nil {
		return
	}
	cached, err := a.cfg.Store.Load()
	if err != nil {
		a.announce("warning: could not load token store: " + err.Error())
		return
	}
	a.token = cached
}

func (a *Auth) persist(tok *Token) Token {
	a.setClaims(tok)
	a.token = *tok
	if a.cfg.Store == nil {
		return *tok
	}
	if err := a.cfg.Store.Save(tok); err != nil {
		a.announce("warning: could not save the access token: " + err.Error())
	}
	return *tok
}

func (a *Auth) clear() {
	a.token = Token{}
	if a.cfg.Store == nil {
		return
	}
	if err := a.cfg.Store.Delete(); err != nil {
		a.announce("warning: could not delete the access token: " + err.Error())
	}
}

// setClaims decodes OID, mailnickname and the JWT exp from the access token. A
// broken token is not fatal; the token is returned without an OID (the
// principal header is omitted) and Valid falls back to ExpiresAt.
func (a *Auth) setClaims(tok *Token) {
	tok.OID, tok.MailNickname, tok.jwtExp = "", "", time.Time{}
	if tok.AccessToken == "" {
		return
	}
	c, err := ParseClaims(tok.AccessToken)
	if err != nil {
		return
	}
	tok.OID, tok.MailNickname, tok.jwtExp = c.OID, c.MailNickname, c.Exp
}

func (a *Auth) announce(msg string) {
	if a.cfg.Out != nil {
		_, _ = fmt.Fprintln(a.cfg.Out, msg)
	}
}

var errReauth = errors.New("re-authentication required")

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	Error        string `json:"error"`
	ErrorDesc    string `json:"error_description"`
}

func (a *Auth) tokenFrom(t tokenResponse) Token {
	tok := Token{AccessToken: t.AccessToken, RefreshToken: t.RefreshToken}
	if t.ExpiresIn > 0 {
		tok.ExpiresAt = time.Now().Add(time.Duration(t.ExpiresIn) * time.Second)
	}
	return tok
}

func (a *Auth) refresh(ctx context.Context) (Token, error) {
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {a.cfg.ClientID},
		"refresh_token": {a.token.RefreshToken},
		"scope":         {a.scope()},
	}
	var tr tokenResponse
	status, err := a.postForm(ctx, a.tokenEndpoint(), form, &tr)
	if err != nil {
		// Network errors never trigger a re-login.
		return Token{}, err
	}
	if status == http.StatusBadRequest && tr.Error == "invalid_grant" {
		return Token{}, errReauth
	}
	if status < 200 || status >= 300 || tr.AccessToken == "" {
		a.announce("warning: Access token refresh failed: " + describe(tr))
		return Token{}, fmt.Errorf("token endpoint returned %d: %s", status, errorCode(tr.Error))
	}
	if tr.RefreshToken == "" {
		tr.RefreshToken = a.token.RefreshToken
	}
	return a.tokenFrom(tr), nil
}

type deviceCode struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURI string `json:"verification_uri"`
	Message         string `json:"message"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
	Error           string `json:"error"`
	ErrorDesc       string `json:"error_description"`
}

func (a *Auth) deviceLogin(ctx context.Context) (Token, error) {
	dc, err := a.requestDeviceCode(ctx)
	if err != nil {
		return Token{}, err
	}
	a.announce(deviceMessage(dc))
	a.report(dc)
	return a.waitForToken(ctx, dc)
}

// DeviceLogin describes a sign-in the user has to complete in a browser. The
// code and URI are safe to show to the user (and to the MCP client); DeviceCode
// is an internal handle that must never be exposed.
type DeviceLogin struct {
	UserCode        string
	VerificationURI string
	// ExpiresIn is the lifetime of the code in seconds.
	ExpiresIn int
	// DeviceCode is the internal polling handle; never expose it.
	DeviceCode string
	// Interval is the polling interval requested by the server.
	Interval int
}

// ErrLoginRequired reports that no usable token is available and the user has
// to complete a device code sign-in first. Callers can retrieve the code and
// URI from LoginRequired via errors.As.
type ErrLoginRequired struct {
	Login DeviceLogin
}

func (e *ErrLoginRequired) Error() string {
	return "Sign-in required"
}

// requestDeviceCode asks Entra for a device code. It performs no polling.
func (a *Auth) requestDeviceCode(ctx context.Context) (DeviceLogin, error) {
	form := url.Values{
		"client_id": {a.cfg.ClientID},
		"scope":     {a.scope()},
	}
	var dc deviceCode
	status, err := a.postForm(ctx, a.deviceEndpoint(), form, &dc)
	if err != nil {
		return DeviceLogin{}, err
	}
	if status < 200 || status >= 300 || dc.DeviceCode == "" {
		a.announce("warning: device code request failed: " + describeDevice(&dc))
		return DeviceLogin{}, fmt.Errorf("device code endpoint returned %d: %s", status, errorCode(dc.Error))
	}
	return DeviceLogin{
		UserCode:        dc.UserCode,
		VerificationURI: dc.VerificationURI,
		ExpiresIn:       dc.ExpiresIn,
		DeviceCode:      dc.DeviceCode,
		Interval:        dc.Interval,
	}, nil
}

// deviceMessage renders the Entra "message" or a fallback instruction.
func deviceMessage(dc DeviceLogin) string {
	if dc.VerificationURI == "" {
		return "sign-in required"
	}
	return fmt.Sprintf("open %s and enter code %s", dc.VerificationURI, dc.UserCode)
}

// waitForToken polls the token endpoint until the user completes the sign-in,
// the code expires, or the context is canceled.
func (a *Auth) waitForToken(ctx context.Context, dc DeviceLogin) (Token, error) {
	interval := time.Duration(dc.Interval) * time.Second
	if interval <= 0 {
		interval = 5 * time.Second
	}
	deadline := time.Now().Add(time.Duration(dc.ExpiresIn) * time.Second)
	if dc.ExpiresIn <= 0 {
		deadline = time.Now().Add(15 * time.Minute)
	}

	for {
		if time.Now().After(deadline) {
			return Token{}, errors.New("device code expired before sign-in completed")
		}
		a.cfg.Sleep(interval)

		form := url.Values{
			"grant_type":  {deviceGrant},
			"client_id":   {a.cfg.ClientID},
			"device_code": {dc.DeviceCode},
		}
		var tr tokenResponse
		status, err := a.postForm(ctx, a.tokenEndpoint(), form, &tr)
		if err != nil {
			if ctx.Err() != nil {
				return Token{}, ctx.Err()
			}
			return Token{}, err
		}
		switch tr.Error {
		case "":
			if status >= 200 && status < 300 && tr.AccessToken != "" {
				return a.tokenFrom(tr), nil
			}
			a.announce("warning: sign-in token request failed: " + describe(tr))
			return Token{}, fmt.Errorf("token endpoint returned %d: %s", status, errorCode(tr.Error))
		case "authorization_pending":
			continue
		case "slow_down":
			interval += 5 * time.Second
			continue
		case "authorization_declined":
			return Token{}, errors.New("sign-in failed: authorization_declined")
		case "expired_token":
			return Token{}, errors.New("sign-in failed: expired_token")
		default:
			a.announce("warning: sign-in failed: " + describe(tr))
			return Token{}, fmt.Errorf("sign-in failed: %s", errorCode(tr.Error))
		}
	}
}

func (a *Auth) postForm(ctx context.Context, endpoint string, form url.Values, out any) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := a.cfg.HTTP.Do(req)
	if err != nil {
		return 0, fmt.Errorf("token request failed: %w", cause(err))
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if len(body) == 0 {
		return resp.StatusCode, nil
	}
	if err := json.Unmarshal(body, out); err != nil {
		return resp.StatusCode, fmt.Errorf("decoding token response: %w", err)
	}
	return resp.StatusCode, nil
}

// describe returns a detailed, human-readable description for stderr. It may
// include the Entra error_description and must never be returned to callers.
func describe(tr tokenResponse) string {
	if tr.Error == "" {
		return "no token in response"
	}
	if tr.ErrorDesc != "" {
		return tr.Error + ": " + tr.ErrorDesc
	}
	return tr.Error
}

// describeDevice is the deviceCode counterpart of describe (stderr only).
func describeDevice(dc *deviceCode) string {
	if dc.Error == "" {
		return "no device code in response"
	}
	if dc.ErrorDesc != "" {
		return dc.Error + ": " + dc.ErrorDesc
	}
	return dc.Error
}

// errorCode returns only the OAuth error code for inclusion in returned errors.
// The description is deliberately omitted as it may contain tenant/trace data.
func errorCode(code string) string {
	if code == "" {
		return "no error code in response"
	}
	return code
}

// cause strips transport wrappers that embed the request URL or the resolved
// address (url.Error, net.OpError) so error messages never leak operational
// details such as the tenant host or an IP:port.
func cause(err error) error {
	var urlErr *url.Error
	if errors.As(err, &urlErr) && urlErr.Err != nil {
		err = urlErr.Err
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) && opErr.Err != nil {
		err = opErr.Err
	}
	if dnsErr, ok := errors.AsType[*net.DNSError](err); ok {
		return fmt.Errorf("network error: %s", dnsErr.Err)
	}
	return err
}

// report hands the device code to the optional hook.
func (a *Auth) report(dc DeviceLogin) {
	if a.deviceHook != nil {
		a.deviceHook(dc)
	}
}

// TryToken returns a token only if one can be obtained without user
// interaction: a valid cached token, or one produced by refreshing the stored
// refresh token. It never starts a device login. ok is false when a login would
// be required.
func (a *Auth) TryToken(ctx context.Context) (Token, bool, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.load()
	if a.token.Valid() {
		return a.token, true, nil
	}
	if a.token.RefreshToken == "" {
		return Token{}, false, nil
	}
	tok, err := a.refresh(ctx)
	if err == nil {
		return a.persist(&tok), true, nil
	}
	if errors.Is(err, errReauth) {
		a.clear()
		return Token{}, false, nil
	}
	return Token{}, false, fmt.Errorf("refreshing access token: %w", err)
}
