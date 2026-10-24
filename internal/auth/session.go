package auth

import (
	"context"
	"errors"
	"sync"
	"time"
)

// Session makes the device login usable from an MCP server: the first tool call
// that needs a token starts the login and returns the code immediately (via
// *ErrLoginRequired), while polling continues in the background. A later tool
// call picks up the token once the user has confirmed.
type Session struct {
	auth *Auth

	mu      sync.Mutex
	pending *pendingLogin
}

type pendingLogin struct {
	login DeviceLogin
	done  chan struct{}
	token Token
	err   error
}

// waitHint is how long Token waits for an already running login before it
// reports ErrLoginRequired again. It keeps a retried call responsive.
const waitHint = 2 * time.Second

// NewSession returns a Session backed by auth.
func NewSession(a *Auth) *Session {
	return &Session{auth: a}
}

// Token returns a usable token, refreshing it if possible. If no token can be
// produced without user interaction it starts a device login (once) and returns
// *ErrLoginRequired carrying the user code. Calling Token again after the user
// confirmed returns the stored token.
func (s *Session) Token(ctx context.Context) (Token, error) {
	if tok, ok := s.cached(ctx); ok {
		return tok, nil
	}

	s.mu.Lock()
	p := s.pending
	if p == nil {
		p = s.startLocked(ctx)
	}
	s.mu.Unlock()

	select {
	case <-p.done:
		if p.err != nil {
			// Forget the failed attempt so the next call starts a new login
			// instead of replaying the same error forever.
			s.forgetPending(p)
			return Token{}, p.err
		}
		return p.token, nil
	case <-time.After(waitHint):
		return Token{}, &ErrLoginRequired{Login: p.login}
	case <-ctx.Done():
		return Token{}, ctx.Err()
	}
}

// Login forces a fresh device login and blocks until it completes. The MCP server
// never calls it; sign-in runs non-blocking through Token, which polls in the
// background and returns ErrLoginRequired with the device code until confirmed.
func (s *Session) Login(ctx context.Context) (Token, error) {
	tok, err := s.auth.Login(ctx)
	if err != nil {
		return Token{}, err
	}
	s.forget()
	return tok, nil
}

// Refresh forces a refresh with the stored refresh token.
func (s *Session) Refresh(ctx context.Context) (Token, error) {
	tok, err := s.auth.Refresh(ctx)
	if err != nil {
		return Token{}, err
	}
	s.forget()
	return tok, nil
}

// cached returns a valid or refreshable token without user interaction.
func (s *Session) cached(ctx context.Context) (Token, bool) {
	tok, ok, err := s.auth.TryToken(ctx)
	if err != nil || !ok {
		return Token{}, false
	}
	return tok, true
}

func (s *Session) forget() {
	s.mu.Lock()
	s.pending = nil
	s.mu.Unlock()
}

// forgetPending drops p, but only if it is still the pending login, so a newer
// attempt is not discarded by a slow failure of an older one.
func (s *Session) forgetPending(p *pendingLogin) {
	s.mu.Lock()
	if s.pending == p {
		s.pending = nil
	}
	s.mu.Unlock()
}

// startLocked begins a background login and waits briefly for the device code.
// The caller must hold s.mu.
func (s *Session) startLocked(ctx context.Context) *pendingLogin {
	p := &pendingLogin{done: make(chan struct{})}
	ready := make(chan DeviceLogin, 1)

	s.auth.mu.Lock()
	s.auth.deviceHook = func(dc DeviceLogin) {
		select {
		case ready <- dc:
		default:
		}
	}
	s.auth.mu.Unlock()
	s.pending = p

	loginCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	go func() {
		defer cancel()
		tok, err := s.auth.deviceLogin(loginCtx)
		s.auth.mu.Lock()
		s.auth.deviceHook = nil
		s.auth.mu.Unlock()
		if err == nil {
			tok = s.auth.persist(&tok)
		}
		p.token, p.err = tok, err
		close(p.done)
	}()

	select {
	case p.login = <-ready:
	case <-time.After(waitHint):
	}
	return p
}

// Peek returns a token only if one is available without user interaction:
// cached, stored, or obtainable via the refresh token. It never starts a device
// login and never blocks on interaction. Use it where a login would be
// surprising, e.g. while loading the OpenAPI spec at startup.
func (s *Session) Peek(ctx context.Context) (Token, error) {
	tok, ok := s.cached(ctx)
	if !ok {
		return Token{}, errors.New("no token available without sign-in")
	}
	return tok, nil
}
