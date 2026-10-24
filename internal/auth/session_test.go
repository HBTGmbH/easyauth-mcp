package auth

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestSessionReturnsLoginRequiredWithCode(t *testing.T) {
	srv, _ := testServer(t, func(int) (int, map[string]any) {
		return 400, map[string]any{"error": "authorization_pending"}
	})
	defer srv.Close()

	authn := newTestAuth(srv, newFileStore(t), nil)
	session := NewSession(authn)

	_, err := session.Token(context.Background())
	var required *ErrLoginRequired
	if !errors.As(err, &required) {
		t.Fatalf("expected ErrLoginRequired, got %v", err)
	}
	if required.Login.UserCode != "ABCD" || required.Login.VerificationURI != "https://example.test/device" {
		t.Fatalf("unexpected device login: %+v", required.Login)
	}
}

func TestSessionPicksUpTokenAfterConfirmation(t *testing.T) {
	srv, _ := testServer(t, func(call int) (int, map[string]any) {
		if call == 1 {
			return 400, map[string]any{"error": "authorization_pending"}
		}
		return 200, map[string]any{"access_token": fakeJWT(t, map[string]any{"oid": "oid-1", "mailnickname": "sign"}), "refresh_token": "r", "expires_in": 3600}
	})
	defer srv.Close()

	authn := newTestAuth(srv, newFileStore(t), nil)
	session := NewSession(authn)

	// The first call starts the login; depending on timing it either returns
	// ErrLoginRequired or the already resolved token.
	if _, err := session.Token(context.Background()); err != nil {
		if _, ok := errors.AsType[*ErrLoginRequired](err); !ok {
			t.Fatalf("unexpected error: %v", err)
		}
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		tok, err := session.Token(context.Background())
		if err == nil && tok.AccessToken != "" {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("token was not picked up after the login completed")
}

func TestSessionReusesCachedToken(t *testing.T) {
	srv, calls := testServer(t, func(int) (int, map[string]any) {
		return 200, map[string]any{"access_token": fakeJWT(t, map[string]any{"oid": "oid", "mailnickname": "sign"}), "expires_in": 3600}
	})
	defer srv.Close()

	store := newFileStore(t)
	session := NewSession(newTestAuth(srv, store, nil))

	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, err := session.Token(context.Background()); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("login did not complete")
		}
		time.Sleep(20 * time.Millisecond)
	}
	before := atomic.LoadInt32(calls)
	second := NewSession(newTestAuth(srv, store, nil))
	if _, err := second.Token(context.Background()); err != nil {
		t.Fatalf("cached token not reused: %v", err)
	}
	if atomic.LoadInt32(calls) != before {
		t.Fatal("cached token should not trigger a network call")
	}
}

func TestSessionStartsNewLoginAfterFailure(t *testing.T) {
	var deviceCalls int32
	mux := http.NewServeMux()
	mux.HandleFunc("/tenant/oauth2/v2.0/devicecode", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&deviceCalls, 1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"device_code":"d","user_code":"U","verification_uri":"https://example.test/device","expires_in":1,"interval":1}`))
	})
	mux.HandleFunc("/tenant/oauth2/v2.0/token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"error":"expired_token"}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	authn := NewAuth(&AuthConfig{
		LoginBase: srv.URL, TenantID: "tenant", ClientID: "client", Scope: "s",
		Store: newFileStore(t), Sleep: func(time.Duration) {}, Out: io.Discard,
	})
	session := NewSession(authn)

	if _, err := session.Token(context.Background()); err == nil {
		t.Fatal("expected the first login to fail")
	}
	waitForCalls(t, &deviceCalls, 1)

	// A failed login must not poison the session: the next call starts a new one.
	_, _ = session.Token(context.Background())
	waitForCalls(t, &deviceCalls, 2)
	if got := atomic.LoadInt32(&deviceCalls); got < 2 {
		t.Fatalf("device code requests = %d, want a second attempt", got)
	}
}

func waitForCalls(t *testing.T, calls *int32, want int32) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for atomic.LoadInt32(calls) < want && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
}
