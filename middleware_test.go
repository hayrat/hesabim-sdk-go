package hesabim

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// echoPrincipal is the protected handler: it records what the middleware handed
// it, so "the request reached the handler" and "with the right principal" are
// separate assertions.
type echoPrincipal struct {
	called    bool
	principal *Principal
	found     bool
}

func (h *echoPrincipal) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.called = true
	h.principal, h.found = FromContext(r.Context())
	w.WriteHeader(http.StatusOK)
}

func TestMiddleware_RejectsRequestsWithoutBearerCredentials(t *testing.T) {
	t.Parallel()

	clock := newTestClock()
	idp := newFakeIdP(t, newSigningKey(t, testKeyID))
	v := newTestVerifier(t, idp, clock, nil)

	// RFC 6750 §3: a request that presented nothing gets the bare challenge.
	// Adding error="invalid_token" would claim something was invalid when
	// nothing was sent.
	cases := []struct {
		name   string
		header string
		set    bool
	}{
		{name: "no Authorization header"},
		{name: "empty Authorization header", header: "", set: true},
		{name: "another scheme", header: "Basic dXNlcjpwYXNz", set: true},
		{name: "scheme with no credential", header: "Bearer", set: true},
		{name: "scheme with only spaces", header: "Bearer   ", set: true},
		{name: "scheme without a separator", header: "Bearerabc", set: true},
		{name: "two space-separated values", header: "Bearer a b", set: true},
		{name: "token before the scheme", header: "abc Bearer", set: true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			handler := &echoPrincipal{}
			req := httptest.NewRequest(http.MethodGet, "/things", nil)
			if c.set {
				req.Header.Set("Authorization", c.header)
			}
			rec := httptest.NewRecorder()

			v.Middleware(handler).ServeHTTP(rec, req)

			if handler.called {
				t.Error("the protected handler must not run")
			}
			if rec.Code != http.StatusUnauthorized {
				t.Errorf("status = %d, want 401", rec.Code)
			}
			// The literal, not challengeBearer: comparing against the
			// production constant would move both sides of the assertion
			// together, and the exact RFC 6750 §3 distinction (no `error`
			// parameter when no credentials were presented) is the guard
			// under test.
			if got := rec.Header().Get("WWW-Authenticate"); got != "Bearer" {
				t.Errorf(`WWW-Authenticate = %q, want "Bearer"`, got)
			}
			assertEnvelope(t, rec)
		})
	}
}

func TestMiddleware_RejectsAnInvalidToken(t *testing.T) {
	t.Parallel()

	clock := newTestClock()
	key := newSigningKey(t, testKeyID)
	idp := newFakeIdP(t, key)
	v := newTestVerifier(t, idp, clock, nil)

	expired := validClaims(idp.issuer(), clock.Now())
	expired[claimExpiry] = clock.Now().Add(-time.Hour).Unix()

	cases := []struct {
		name  string
		token string
	}{
		{"garbage", "not-a-token"},
		{"expired", key.sign(t, expired)},
		{"signed by a stranger", signingKey{kid: testKeyID, key: newSigningKey(t, "x").key}.sign(t, validClaims(idp.issuer(), clock.Now()))},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			handler := &echoPrincipal{}
			req := httptest.NewRequest(http.MethodGet, "/things", nil)
			req.Header.Set("Authorization", "Bearer "+c.token)
			rec := httptest.NewRecorder()

			v.Middleware(handler).ServeHTTP(rec, req)

			if handler.called {
				t.Error("the protected handler must not run")
			}
			if rec.Code != http.StatusUnauthorized {
				t.Errorf("status = %d, want 401", rec.Code)
			}

			// The literal, not challengeInvalidToken — same reasoning as the
			// missing-credentials test: the constant would mutate in lockstep.
			challenge := rec.Header().Get("WWW-Authenticate")
			if challenge != `Bearer error="invalid_token"` {
				t.Errorf(`WWW-Authenticate = %q, want Bearer error="invalid_token"`, challenge)
			}
			// error_description is a verification oracle; it must never appear.
			if strings.Contains(challenge, "error_description") {
				t.Errorf("WWW-Authenticate carries error_description: %q", challenge)
			}
			assertEnvelope(t, rec)

			// Neither the challenge nor the body may echo the credential.
			body := rec.Body.String()
			for _, segment := range strings.Split(c.token, ".") {
				if segment == "" {
					continue
				}
				if strings.Contains(body, segment) || strings.Contains(challenge, segment) {
					t.Error("the response echoed part of the token")
				}
			}
		})
	}
}

func TestMiddleware_AcceptsAValidTokenAndPublishesThePrincipal(t *testing.T) {
	t.Parallel()

	clock := newTestClock()
	key := newSigningKey(t, testKeyID)
	idp := newFakeIdP(t, key)
	v := newTestVerifier(t, idp, clock, nil)

	claims := validClaims(idp.issuer(), clock.Now())
	claims[claimGrants] = []any{grantClaim("moderator", scopeClaim(ScopeTypeProvince, 6))}

	handler := &echoPrincipal{}
	req := httptest.NewRequest(http.MethodGet, "/things", nil)
	req.Header.Set("Authorization", "Bearer "+key.sign(t, claims))
	rec := httptest.NewRecorder()

	v.Middleware(handler).ServeHTTP(rec, req)

	if !handler.called {
		t.Fatal("the protected handler was not reached")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if rec.Header().Get("WWW-Authenticate") != "" {
		t.Error("a successful request must carry no challenge")
	}
	if !handler.found {
		t.Fatal("FromContext found no principal inside the handler")
	}
	if handler.principal.Subject != claims[claimSubject] {
		t.Errorf("handler saw Subject %q, want %q", handler.principal.Subject, claims[claimSubject])
	}
	// The authorization decision is the handler's, and it works on the principal
	// the middleware published.
	if !handler.principal.Can("moderator", Scope{Type: ScopeTypeProvince, ID: 6}) {
		t.Error("the published principal lost its grants")
	}
}

func TestMiddleware_LowercaseSchemeIsAccepted(t *testing.T) {
	t.Parallel()

	clock := newTestClock()
	key := newSigningKey(t, testKeyID)
	idp := newFakeIdP(t, key)
	v := newTestVerifier(t, idp, clock, nil)

	// RFC 7235: auth-scheme is case-insensitive. Some clients send "bearer".
	handler := &echoPrincipal{}
	req := httptest.NewRequest(http.MethodGet, "/things", nil)
	req.Header.Set("Authorization", "bearer "+key.sign(t, validClaims(idp.issuer(), clock.Now())))
	rec := httptest.NewRecorder()

	v.Middleware(handler).ServeHTTP(rec, req)

	if !handler.called {
		t.Fatalf("a lowercase scheme must be accepted; got status %d", rec.Code)
	}
}

func TestMiddleware_ErrorHandlerTakesOverTheWholeResponse(t *testing.T) {
	t.Parallel()

	clock := newTestClock()
	key := newSigningKey(t, testKeyID)
	idp := newFakeIdP(t, key)

	var seen []error
	v := newTestVerifier(t, idp, clock, func(cfg *Config) {
		cfg.ErrorHandler = func(w http.ResponseWriter, _ *http.Request, err error) {
			seen = append(seen, err)
			w.Header().Set("X-Custom", "1")
			w.WriteHeader(http.StatusTeapot)
			_, _ = io.WriteString(w, "handled by the application")
		}
	})

	t.Run("no credentials", func(t *testing.T) {
		rec := httptest.NewRecorder()
		handler := &echoPrincipal{}
		v.Middleware(handler).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/things", nil))

		if handler.called {
			t.Error("the protected handler must not run")
		}
		if rec.Code != http.StatusTeapot {
			t.Errorf("status = %d, want the application's 418", rec.Code)
		}
		// The SDK must not have written anything of its own: a half-written
		// response would take the status away from the application.
		if got := rec.Header().Get("WWW-Authenticate"); got != "" {
			t.Errorf("the SDK set WWW-Authenticate = %q despite an ErrorHandler", got)
		}
		if body := rec.Body.String(); body != "handled by the application" {
			t.Errorf("body = %q, want only what the application wrote", body)
		}
	})

	t.Run("invalid token", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/things", nil)
		req.Header.Set("Authorization", "Bearer not-a-token")
		v.Middleware(&echoPrincipal{}).ServeHTTP(rec, req)

		if rec.Code != http.StatusTeapot {
			t.Errorf("status = %d, want the application's 418", rec.Code)
		}
	})

	t.Run("valid token does not reach the handler", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/things", nil)
		req.Header.Set("Authorization", "Bearer "+key.sign(t, validClaims(idp.issuer(), clock.Now())))
		handler := &echoPrincipal{}
		v.Middleware(handler).ServeHTTP(rec, req)

		if !handler.called {
			t.Error("a valid token must still reach the protected handler")
		}
	})

	if len(seen) != 2 {
		t.Fatalf("the ErrorHandler was called %d times, want 2", len(seen))
	}
	if !errors.Is(seen[0], errNoCredentials) {
		t.Errorf("first error = %v, want errNoCredentials", seen[0])
	}
	if !errors.Is(seen[1], errUnauthenticated) {
		t.Errorf("second error = %v, want a token rejection", seen[1])
	}
	for _, err := range seen {
		if err == nil {
			t.Error("the ErrorHandler must never be called with a nil error")
		}
	}
}

func TestBearerToken(t *testing.T) {
	t.Parallel()

	cases := []struct {
		header string
		want   string
		ok     bool
	}{
		{"Bearer abc", "abc", true},
		{"bearer abc", "abc", true},
		{"BEARER abc", "abc", true},
		{"Bearer   abc", "abc", true},
		{"Bearer abc ", "", false},
		{"Bearer a b", "", false},
		{"Bearer\tabc", "", false},
		{"Bearer", "", false},
		{"Bearer ", "", false},
		{"Bearerabc", "", false},
		{"Basic abc", "", false},
		{"", "", false},
		{" Bearer abc", "", false},
	}

	for _, c := range cases {
		got, ok := bearerToken(c.header)
		if ok != c.ok || got != c.want {
			t.Errorf("bearerToken(%q) = (%q, %v), want (%q, %v)", c.header, got, ok, c.want, c.ok)
		}
	}
}

func assertEnvelope(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()

	const want = `{"error":{"code":"UNAUTHORIZED","message":"authentication required"}}`
	if got := rec.Body.String(); got != want {
		t.Errorf("body = %s, want %s", got, want)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
}

func TestMiddleware_RejectsAnOversizedBearerToken(t *testing.T) {
	t.Parallel()

	clock := newTestClock()
	key := newSigningKey(t, testKeyID)
	idp := newFakeIdP(t, key)
	v := newTestVerifier(t, idp, clock, nil)

	// A well-formed, correctly signed token that the issuer's own budget says
	// it cannot have minted. The middleware treats it as an invalid token, not
	// as missing credentials: something WAS presented.
	claims := validClaims(idp.issuer(), clock.Now())
	claims["padding"] = strings.Repeat("x", maxTokenBytes)
	token := key.sign(t, claims)
	if len(token) <= maxTokenBytes {
		t.Fatalf("fixture is %d bytes; the test needs one over %d", len(token), maxTokenBytes)
	}

	handler := &echoPrincipal{}
	req := httptest.NewRequest(http.MethodGet, "/things", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	v.Middleware(handler).ServeHTTP(rec, req)

	if handler.called {
		t.Error("the protected handler must not run")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
	if got := rec.Header().Get("WWW-Authenticate"); got != challengeInvalidToken {
		t.Errorf("WWW-Authenticate = %q, want %q", got, challengeInvalidToken)
	}
	assertEnvelope(t, rec)
}
