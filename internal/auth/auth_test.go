package auth

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeJWT builds an unsigned JWT with the given claims payload.
func fakeJWT(t *testing.T, claims map[string]any) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	enc := base64.RawURLEncoding
	return enc.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`)) + "." +
		enc.EncodeToString(payload) + ".sig"
}

func testServer(t *testing.T, tokenHandler func(call int) (int, map[string]any)) (*httptest.Server, *int32) {
	t.Helper()
	var calls int32
	mux := http.NewServeMux()
	mux.HandleFunc("/tenant/oauth2/v2.0/devicecode", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"device_code":      "dev-code",
			"user_code":        "ABCD",
			"verification_uri": "https://example.test/device",
			"expires_in":       60,
			"interval":         1,
			"message":          "open https://example.test/device and enter ABCD",
		})
	})
	mux.HandleFunc("/tenant/oauth2/v2.0/token", func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&calls, 1)
		status, body := tokenHandler(int(n))
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(body)
	})
	return httptest.NewServer(mux), &calls
}

func newTestAuth(srv *httptest.Server, store Store, out *bytes.Buffer) *Auth {
	var w interface{ Write([]byte) (int, error) }
	if out != nil {
		w = out
	}
	cfg := AuthConfig{
		LoginBase: srv.URL,
		TenantID:  "tenant",
		ClientID:  "client",
		Scope:     "api://client/user_impersonation",
		Store:     store,
		Sleep:     func(time.Duration) {},
	}
	if w != nil {
		cfg.Out = w
	}
	return NewAuth(cfg)
}

func newFileStore(t *testing.T) *FileStore {
	t.Helper()
	return &FileStore{Path: filepath.Join(t.TempDir(), "token.json")}
}

func TestDeviceLoginPendingThenSuccess(t *testing.T) {
	srv, calls := testServer(t, func(call int) (int, map[string]any) {
		if call == 1 {
			return 400, map[string]any{"error": "authorization_pending"}
		}
		return 200, map[string]any{"access_token": "token-1", "refresh_token": "refresh-1", "expires_in": 3600}
	})
	defer srv.Close()

	store := newFileStore(t)
	out := &bytes.Buffer{}
	tok, err := newTestAuth(srv, store, out).AccessToken(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if tok.AccessToken != "token-1" {
		t.Errorf("token = %q", tok.AccessToken)
	}
	if got := atomic.LoadInt32(calls); got != 2 {
		t.Errorf("token calls = %d, want 2", got)
	}
	if !strings.Contains(out.String(), "ABCD") {
		t.Errorf("out does not mention user code: %q", out.String())
	}
	saved, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if saved.RefreshToken != "refresh-1" || saved.AccessToken != "token-1" {
		t.Errorf("stored token = %+v", saved)
	}
}

func TestCachedTokenIsReused(t *testing.T) {
	srv, calls := testServer(t, func(int) (int, map[string]any) {
		return 200, map[string]any{"access_token": "unexpected"}
	})
	defer srv.Close()

	store := newFileStore(t)
	if err := store.Save(Token{AccessToken: "cached", RefreshToken: "r", ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}

	tok, err := newTestAuth(srv, store, nil).AccessToken(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if tok.AccessToken != "cached" {
		t.Errorf("token = %q, want cached", tok.AccessToken)
	}
	if got := atomic.LoadInt32(calls); got != 0 {
		t.Errorf("token endpoint called %d times, want 0", got)
	}
}

func TestExpiredTokenIsRefreshed(t *testing.T) {
	srv, calls := testServer(t, func(int) (int, map[string]any) {
		return 200, map[string]any{"access_token": "fresh", "refresh_token": "refresh-2", "expires_in": 3600}
	})
	defer srv.Close()

	store := newFileStore(t)
	if err := store.Save(Token{AccessToken: "old", RefreshToken: "refresh-1", ExpiresAt: time.Now().Add(-time.Minute)}); err != nil {
		t.Fatal(err)
	}

	tok, err := newTestAuth(srv, store, nil).AccessToken(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if tok.AccessToken != "fresh" {
		t.Errorf("token = %q", tok.AccessToken)
	}
	if got := atomic.LoadInt32(calls); got != 1 {
		t.Errorf("token calls = %d, want 1", got)
	}
	saved, _ := store.Load()
	if saved.RefreshToken != "refresh-2" {
		t.Errorf("refresh token not rotated: %+v", saved)
	}
}

func TestInvalidGrantTriggersDeviceLogin(t *testing.T) {
	srv, calls := testServer(t, func(call int) (int, map[string]any) {
		if call == 1 {
			return 400, map[string]any{"error": "invalid_grant"}
		}
		return 200, map[string]any{"access_token": "new", "refresh_token": "r3", "expires_in": 3600}
	})
	defer srv.Close()

	store := newFileStore(t)
	if err := store.Save(Token{AccessToken: "old", RefreshToken: "stale", ExpiresAt: time.Now().Add(-time.Minute)}); err != nil {
		t.Fatal(err)
	}

	out := &bytes.Buffer{}
	tok, err := newTestAuth(srv, store, out).AccessToken(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if tok.AccessToken != "new" {
		t.Errorf("token = %q", tok.AccessToken)
	}
	if got := atomic.LoadInt32(calls); got != 2 {
		t.Errorf("token calls = %d, want 2", got)
	}
	if !strings.Contains(out.String(), "new device code login") {
		t.Errorf("out does not announce re-login: %q", out.String())
	}
	if !strings.Contains(out.String(), "ABCD") {
		t.Errorf("out does not mention user code: %q", out.String())
	}
	saved, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if saved.RefreshToken != "r3" || saved.AccessToken != "new" {
		t.Errorf("store not refreshed: %+v", saved)
	}
}

func TestRefreshForcedWithValidAccessToken(t *testing.T) {
	srv, calls := testServer(t, func(int) (int, map[string]any) {
		return 200, map[string]any{"access_token": "fresh", "refresh_token": "r2", "expires_in": 3600}
	})
	defer srv.Close()

	store := newFileStore(t)
	if err := store.Save(Token{AccessToken: "cached", RefreshToken: "r1", ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}

	tok, err := newTestAuth(srv, store, nil).Refresh(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if tok.AccessToken != "fresh" {
		t.Errorf("token = %q, want fresh", tok.AccessToken)
	}
	if got := atomic.LoadInt32(calls); got != 1 {
		t.Errorf("token calls = %d, want 1 forced refresh", got)
	}
	saved, _ := store.Load()
	if saved.AccessToken != "fresh" || saved.RefreshToken != "r2" {
		t.Errorf("refreshed token not stored: %+v", saved)
	}
}

func TestRefreshInvalidGrantClearsStoreAndLogsIn(t *testing.T) {
	srv, calls := testServer(t, func(call int) (int, map[string]any) {
		if call == 1 {
			return 400, map[string]any{"error": "invalid_grant", "error_description": "secret tenant trace"}
		}
		return 200, map[string]any{"access_token": "new", "refresh_token": "r3", "expires_in": 3600}
	})
	defer srv.Close()

	store := newFileStore(t)
	if err := store.Save(Token{AccessToken: "cached", RefreshToken: "stale", ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}

	out := &bytes.Buffer{}
	tok, err := newTestAuth(srv, store, out).Refresh(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if tok.AccessToken != "new" {
		t.Errorf("token = %q", tok.AccessToken)
	}
	if got := atomic.LoadInt32(calls); got != 2 {
		t.Errorf("token calls = %d, want refresh + device login", got)
	}
	if !strings.Contains(out.String(), "new device code login") {
		t.Errorf("missing re-login announcement: %q", out.String())
	}
	if strings.Contains(out.String(), "stale") {
		t.Errorf("out leaks refresh token: %q", out.String())
	}
	saved, _ := store.Load()
	if saved.RefreshToken != "r3" {
		t.Errorf("store not replaced after device login: %+v", saved)
	}
}

func TestRefreshWithoutRefreshTokenStartsDeviceLogin(t *testing.T) {
	srv, calls := testServer(t, func(int) (int, map[string]any) {
		return 200, map[string]any{"access_token": "new", "refresh_token": "r", "expires_in": 3600}
	})
	defer srv.Close()

	store := newFileStore(t)
	if err := store.Save(Token{AccessToken: "cached", ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}

	tok, err := newTestAuth(srv, store, nil).Refresh(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if tok.AccessToken != "new" {
		t.Errorf("token = %q", tok.AccessToken)
	}
	if got := atomic.LoadInt32(calls); got != 1 {
		t.Errorf("token calls = %d, want device login only", got)
	}
}

func TestLoginClearsAndStartsDeviceFlow(t *testing.T) {
	srv, _ := testServer(t, func(int) (int, map[string]any) {
		return 200, map[string]any{"access_token": "forced", "refresh_token": "r", "expires_in": 3600}
	})
	defer srv.Close()

	store := newFileStore(t)
	if err := store.Save(Token{AccessToken: "cached", RefreshToken: "r", ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	tok, err := newTestAuth(srv, store, nil).Login(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if tok.AccessToken != "forced" {
		t.Errorf("token = %q", tok.AccessToken)
	}
}

func TestRefreshNetworkErrorDoesNotRelogin(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if strings.HasSuffix(r.URL.Path, "/devicecode") {
			t.Error("device login must not start on network error")
		}
		// Abort the connection to simulate a transport failure.
		hj, _ := w.(http.Hijacker)
		conn, _, _ := hj.Hijack()
		conn.Close()
	}))
	defer srv.Close()

	store := newFileStore(t)
	if err := store.Save(Token{AccessToken: "old", RefreshToken: "r", ExpiresAt: time.Now().Add(-time.Minute)}); err != nil {
		t.Fatal(err)
	}

	_, err := newTestAuth(srv, store, nil).AccessToken(context.Background())
	if err == nil {
		t.Fatal("expected network error")
	}
	if !strings.Contains(err.Error(), "refreshing access token") {
		t.Errorf("unexpected error: %v", err)
	}
	if strings.Contains(err.Error(), "old") || strings.Contains(err.Error(), "Bearer") {
		t.Errorf("error leaks token material: %v", err)
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("token endpoint calls = %d, want 1", got)
	}
}

func TestNetworkErrorLeaksNoURLOrTenant(t *testing.T) {
	// A closed listener gives a connection-refused error while the request URL
	// still carries the tenant GUID.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()

	const tenantID = "tenant-guid-1234"
	cfg := AuthConfig{
		LoginBase: "http://" + addr,
		TenantID:  tenantID,
		ClientID:  "client",
		Scope:     "scope",
		Store:     &FileStore{Path: filepath.Join(t.TempDir(), "t.json")},
		Sleep:     func(time.Duration) {},
	}
	a := NewAuth(cfg)
	if err := a.cfg.Store.Save(Token{RefreshToken: "r", ExpiresAt: time.Now().Add(-time.Minute)}); err != nil {
		t.Fatal(err)
	}

	_, err = a.AccessToken(context.Background())
	if err == nil {
		t.Fatal("expected network error")
	}
	msg := err.Error()
	if strings.Contains(msg, tenantID) {
		t.Errorf("error leaks tenant id: %v", err)
	}
	if strings.Contains(msg, "http") {
		t.Errorf("error leaks URL: %v", err)
	}
}

func TestErrorDescriptionNotInReturnedError(t *testing.T) {
	const desc = "AADSTS70000: trace-id=secret-trace tenant-guid-secret"
	srv, _ := testServer(t, func(int) (int, map[string]any) {
		return 400, map[string]any{"error": "invalid_request", "error_description": desc}
	})
	defer srv.Close()

	store := newFileStore(t)
	if err := store.Save(Token{RefreshToken: "r", ExpiresAt: time.Now().Add(-time.Minute)}); err != nil {
		t.Fatal(err)
	}

	out := &bytes.Buffer{}
	_, err := newTestAuth(srv, store, out).AccessToken(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(err.Error(), desc) {
		t.Errorf("returned error contains error_description: %v", err)
	}
	if strings.Contains(err.Error(), "secret-trace") {
		t.Errorf("returned error leaks trace: %v", err)
	}
	if !strings.Contains(err.Error(), "invalid_request") {
		t.Errorf("returned error should keep error code: %v", err)
	}
}

func TestTokenValid(t *testing.T) {
	if (Token{AccessToken: "x", ExpiresAt: time.Now().Add(30 * time.Second)}).Valid() {
		t.Error("token expiring in 30s must not be valid")
	}
	if !(Token{AccessToken: "x", ExpiresAt: time.Now().Add(5 * time.Minute)}).Valid() {
		t.Error("token expiring in 5m must be valid")
	}
	if (Token{ExpiresAt: time.Now().Add(time.Hour)}).Valid() {
		t.Error("empty access token must not be valid")
	}
}

func TestTokenValidUsesJWTExp(t *testing.T) {
	exp5m := time.Now().Add(5 * time.Minute).Unix()
	tok5m := Token{AccessToken: fakeJWT(t, map[string]any{"exp": exp5m}), jwtExp: time.Unix(exp5m, 0)}
	if !tok5m.Valid() {
		t.Error("JWT exp in 5m must be valid")
	}

	exp30s := time.Now().Add(30 * time.Second).Unix()
	tok30s := Token{
		AccessToken: fakeJWT(t, map[string]any{"exp": exp30s}),
		ExpiresAt:   time.Now().Add(time.Hour), // expires_in must not override exp
		jwtExp:      time.Unix(exp30s, 0),
	}
	if tok30s.Valid() {
		t.Error("JWT exp in 30s must not be valid even if ExpiresAt is far away")
	}

	// Missing exp falls back to ExpiresAt.
	noExp := Token{AccessToken: fakeJWT(t, map[string]any{"oid": "x"}), ExpiresAt: time.Now().Add(time.Hour)}
	if !noExp.Valid() {
		t.Error("missing exp should fall back to ExpiresAt")
	}
}

func TestJWTExpWiredThroughLogin(t *testing.T) {
	// The endpoint advertises a long expires_in, but the JWT exp is authoritative.
	shortExp := time.Now().Add(30 * time.Second).Unix()
	srv, _ := testServer(t, func(int) (int, map[string]any) {
		return 200, map[string]any{
			"access_token":  fakeJWT(t, map[string]any{"oid": "abc", "exp": shortExp}),
			"refresh_token": "r",
			"expires_in":    3600,
		}
	})
	defer srv.Close()

	tok, err := newTestAuth(srv, newFileStore(t), nil).AccessToken(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if tok.ExpiresAt.Sub(time.Now()) < 30*time.Minute {
		t.Errorf("ExpiresAt should come from expires_in: %v", tok.ExpiresAt)
	}
	if tok.Valid() {
		t.Error("token with JWT exp in 30s must not be valid")
	}
}

func TestParseClaims(t *testing.T) {
	jwt := fakeJWT(t, map[string]any{"oid": "oid-123", "mailnickname": "tt", "exp": 1234})
	c, err := ParseClaims(jwt)
	if err != nil {
		t.Fatal(err)
	}
	if c.OID != "oid-123" || c.MailNickname != "tt" {
		t.Errorf("claims = %+v", c)
	}
	if !c.Exp.Equal(time.Unix(1234, 0)) {
		t.Errorf("exp = %v, want %v", c.Exp, time.Unix(1234, 0))
	}

	for _, bad := range []string{"", "not-a-jwt", "a.b.c", "a.!!!.c"} {
		if _, err := ParseClaims(bad); err == nil {
			t.Errorf("ParseClaims(%q) should fail", bad)
		}
	}
}

func TestCloudTokenWithoutOIDOmitsHeader(t *testing.T) {
	tok := Token{AccessToken: "opaque"}
	if _, ok := tok.Header()["X-Ms-Client-Principal-Id"]; ok {
		t.Error("principal header must be omitted without OID")
	}
	if got := tok.Header().Get("Authorization"); got != "Bearer opaque" {
		t.Errorf("Authorization = %q", got)
	}
}

func TestOIDDecodedAndHeaderSet(t *testing.T) {
	srv, _ := testServer(t, func(int) (int, map[string]any) {
		return 200, map[string]any{
			"access_token":  fakeJWT(t, map[string]any{"oid": "abc", "mailnickname": "tt"}),
			"refresh_token": "r",
			"expires_in":    3600,
		}
	})
	defer srv.Close()

	store := newFileStore(t)
	tok, err := newTestAuth(srv, store, nil).AccessToken(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if tok.OID != "abc" {
		t.Errorf("OID = %q", tok.OID)
	}
	if got := tok.Header().Get("x-ms-client-principal-id"); got != "abc" {
		t.Errorf("principal header = %q", got)
	}

	// OID is not persisted but re-decoded on load.
	raw := readJSON(t, store)
	if _, ok := raw["oid"]; ok {
		t.Error("OID must not be persisted")
	}
	loaded, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if loaded.OID != "abc" {
		t.Errorf("re-loaded OID = %q", loaded.OID)
	}
}

func TestConcurrentAccessTokenSingleRefresh(t *testing.T) {
	srv, calls := testServer(t, func(int) (int, map[string]any) {
		time.Sleep(10 * time.Millisecond)
		return 200, map[string]any{"access_token": "fresh", "refresh_token": "r2", "expires_in": 3600}
	})
	defer srv.Close()

	store := newFileStore(t)
	if err := store.Save(Token{AccessToken: "old", RefreshToken: "r1", ExpiresAt: time.Now().Add(-time.Minute)}); err != nil {
		t.Fatal(err)
	}
	a := newTestAuth(srv, store, nil)

	var wg sync.WaitGroup
	for range 10 {
		wg.Go(func() {
			if _, err := a.AccessToken(context.Background()); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if got := atomic.LoadInt32(calls); got != 1 {
		t.Errorf("token calls = %d, want exactly 1 refresh", got)
	}
}

func TestDeviceDeclined(t *testing.T) {
	srv, _ := testServer(t, func(int) (int, map[string]any) {
		return 400, map[string]any{"error": "authorization_declined"}
	})
	defer srv.Close()

	_, err := newTestAuth(srv, nil, nil).AccessToken(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
	if errors.Is(err, errReauth) {
		t.Fatal("decline must not be reported as reauth")
	}
	if !strings.Contains(err.Error(), "authorization_declined") {
		t.Errorf("error should carry error code: %v", err)
	}
}
