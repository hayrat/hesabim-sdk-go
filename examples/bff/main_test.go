package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hayrat/hesabim-sdk-go/examples/internal/fakeidp"
	"github.com/hayrat/hesabim-sdk-go/examples/users"
)

const (
	testClientID = "ornek-proje-bff"
	testSecret   = "test-secret"
)

type harness struct {
	idp      *fakeidp.IdP
	a        *app
	app      *httptest.Server
	client   *http.Client
	sessions *memoryStore
	users    *users.MemoryStore
}

// newHarness runs the BFF over TLS (so the Secure cookie behaves as in
// production) against a fake issuer, with a browser-like client: cookie jar,
// follows redirects.
func newHarness(t *testing.T) *harness {
	t.Helper()
	return newHarnessWithStore(t, nil)
}

// newHarnessWithStore lets a test put a wrapper (e.g. a failing store) in
// front of the in-memory sessions; wrap may be nil.
func newHarnessWithStore(t *testing.T, wrap func(*memoryStore) Store) *harness {
	t.Helper()
	h := &harness{idp: fakeidp.New(t), sessions: newMemoryStore(), users: users.NewMemoryStore()}
	var sessions Store = h.sessions
	if wrap != nil {
		sessions = wrap(h.sessions)
	}

	var handler http.Handler
	h.app = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handler.ServeHTTP(w, r) }))
	t.Cleanup(h.app.Close)

	h.idp.RegisterClient(fakeidp.Client{
		ID:          testClientID,
		Secret:      testSecret,
		RedirectURI: h.app.URL + "/auth/callback",
		PostLogout:  h.app.URL + "/",
		Audience:    fakeidp.Audience,
	})
	h.idp.SetUser(fakeidp.User{
		Sub: "01920000-0000-7000-8000-000000000001", Name: "Ayşe Yılmaz", Gender: "female", ProfileVersion: 3,
		Grants: []fakeidp.Grant{{Role: "moderator", Scopes: []fakeidp.Scope{{Type: "district", ID: 601}}}},
	})

	a, err := newApp(context.Background(), Config{
		IssuerURL:             h.idp.Issuer(),
		ClientID:              testClientID,
		ClientSecret:          testSecret,
		RedirectURI:           h.app.URL + "/auth/callback",
		PostLogoutRedirectURI: h.app.URL + "/",
		Audience:              fakeidp.Audience,
	}, sessions, h.users)
	if err != nil {
		t.Fatalf("newApp: %v", err)
	}
	h.a = a
	handler = a.routes()

	jar, _ := cookiejar.New(nil)
	h.client = h.app.Client()
	h.client.Jar = jar
	return h
}

func (h *harness) get(t *testing.T, path string) (int, string) {
	t.Helper()
	resp, err := h.client.Get(h.app.URL + path)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func (h *harness) login(t *testing.T) {
	t.Helper()
	resp, err := h.client.Get(h.app.URL + "/auth/login?returnTo=/healthz")
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.Request.URL.Path != "/healthz" {
		t.Fatalf("login ended at %s with %d, want /healthz 200", resp.Request.URL, resp.StatusCode)
	}
}

func (h *harness) sessionID(t *testing.T) string {
	t.Helper()
	u, _ := url.Parse(h.app.URL)
	for _, c := range h.client.Jar.Cookies(u) {
		if c.Name == cookieName {
			return c.Value
		}
	}
	t.Fatal("no session cookie")
	return ""
}

// expireAccessToken makes the next API call refresh.
func (h *harness) expireAccessToken(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	s, err := h.sessions.Get(ctx, h.sessionID(t))
	if err != nil {
		t.Fatal(err)
	}
	s.AccessExpiry = time.Now().Add(-time.Minute)
	if err := h.sessions.Save(ctx, s, sessionTTL, s.Version); err != nil {
		t.Fatal(err)
	}
}

func TestLogin_EstablishesSessionAndProjection(t *testing.T) {
	h := newHarness(t)

	if got, body := h.get(t, "/api/me"); got != http.StatusUnauthorized || !strings.Contains(body, "login_required") {
		t.Fatalf("API before login = %d %s, want 401 login_required", got, body)
	}
	h.login(t)

	if got, body := h.get(t, "/api/me"); got != http.StatusOK || !strings.Contains(body, "01920000-0000-7000-8000-000000000001") {
		t.Fatalf("API after login = %d %s", got, body)
	}
	if got, _ := h.get(t, "/api/districts/601/reports"); got != http.StatusOK {
		t.Fatalf("granted district = %d, want 200", got)
	}
	if got, _ := h.get(t, "/api/districts/602/reports"); got != http.StatusForbidden {
		t.Fatalf("other district = %d, want 403", got)
	}

	_, body := h.get(t, "/auth/me")
	var me struct {
		Authenticated bool
		Name, Gender  string
	}
	_ = json.Unmarshal([]byte(body), &me)
	if !me.Authenticated || me.Name != "Ayşe Yılmaz" || me.Gender != "female" {
		t.Fatalf("/auth/me = %s", body)
	}

	if u, ok, _ := h.users.Get(context.Background(), "01920000-0000-7000-8000-000000000001"); !ok || u.ProfileVer != 3 {
		t.Fatalf("projection = %+v, want profile_ver 3 from the access token", u)
	}

	// The session holds tokens server-side; the cookie is opaque and HttpOnly.
	s, err := h.sessions.Get(context.Background(), h.sessionID(t))
	if err != nil || s.AccessToken == "" || s.RefreshToken == "" || s.IDToken == "" {
		t.Fatalf("session = %+v, %v", s, err)
	}
}

func TestCallback_RejectsForeignState(t *testing.T) {
	h := newHarness(t)
	// Start a login but stop before the issuer answers.
	h.client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := h.client.Get(h.app.URL + "/auth/login")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	h.client.CheckRedirect = nil

	if got, _ := h.get(t, "/auth/callback?code=x&state=forged"); got != http.StatusBadRequest {
		t.Fatalf("forged state = %d, want 400", got)
	}
	if got, _ := h.get(t, "/api/me"); got != http.StatusUnauthorized {
		t.Fatalf("API after failed callback = %d, want 401", got)
	}
}

func TestCallback_RejectsWrongNonce(t *testing.T) {
	h := newHarness(t)
	h.idp.ForceNonce("not-the-nonce-we-sent")

	if got, _ := h.get(t, "/auth/login"); got != http.StatusBadGateway {
		t.Fatalf("login with a foreign nonce = %d, want 502", got)
	}
	if got, _ := h.get(t, "/api/me"); got != http.StatusUnauthorized {
		t.Fatalf("API after rejected login = %d, want 401", got)
	}
}

func TestRefresh_RotatesOnceUnderConcurrency(t *testing.T) {
	h := newHarness(t)
	h.login(t)
	before, _ := h.sessions.Get(context.Background(), h.sessionID(t))
	h.expireAccessToken(t)
	h.idp.SetRefreshDelay(200 * time.Millisecond)

	var wg sync.WaitGroup
	codes := make([]int, 10)
	for i := range codes {
		wg.Add(1)
		go func() {
			defer wg.Done()
			codes[i], _ = h.get(t, "/api/me")
		}()
	}
	wg.Wait()

	for i, c := range codes {
		if c != http.StatusOK {
			t.Fatalf("request %d = %d, want 200", i, c)
		}
	}
	if n := h.idp.RefreshCalls(); n != 1 {
		t.Fatalf("refresh calls = %d, want exactly 1 (a second one would trip reuse detection)", n)
	}
	after, _ := h.sessions.Get(context.Background(), h.sessionID(t))
	if after.RefreshToken == before.RefreshToken {
		t.Fatal("rotated refresh token was not stored")
	}
}

func TestRefresh_InvalidGrantEndsTheSession(t *testing.T) {
	h := newHarness(t)
	h.login(t)
	id := h.sessionID(t)
	h.idp.RevokeAllSessions()
	h.expireAccessToken(t)

	if got, body := h.get(t, "/api/me"); got != http.StatusUnauthorized || !strings.Contains(body, "login_required") {
		t.Fatalf("after revocation = %d %s, want 401 login_required", got, body)
	}
	if _, err := h.sessions.Get(context.Background(), id); err == nil {
		t.Fatal("session survived invalid_grant")
	}
}

func TestLogout_RedirectsToEndSessionWithHint(t *testing.T) {
	h := newHarness(t)
	h.login(t)
	id := h.sessionID(t)
	s, _ := h.sessions.Get(context.Background(), id)

	req, _ := http.NewRequest(http.MethodPost, h.app.URL+"/auth/logout", nil)
	req.Header.Set("Origin", h.app.URL)
	resp, err := h.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	got := resp.Request.URL // the fake issuer's /oauth/logout, after the 303
	if got.Path != "/oauth/logout" || got.Query().Get("id_token_hint") != s.IDToken ||
		got.Query().Get("post_logout_redirect_uri") != h.app.URL+"/" {
		t.Fatalf("logout landed on %s", got)
	}
	if _, err := h.sessions.Get(context.Background(), id); err == nil {
		t.Fatal("local session survived logout")
	}
}

func TestLogout_CrossOriginIsRefused(t *testing.T) {
	h := newHarness(t)
	h.login(t)

	req, _ := http.NewRequest(http.MethodPost, h.app.URL+"/auth/logout", nil)
	req.Header.Set("Origin", "https://evil.example")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	resp, err := h.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-origin logout = %d, want 403", resp.StatusCode)
	}
	if got, _ := h.get(t, "/api/me"); got != http.StatusOK {
		t.Fatalf("session should survive a refused logout, API = %d", got)
	}
}

func TestSafeReturnTo(t *testing.T) {
	for in, want := range map[string]string{
		"/raporlar?sayfa=2":     "/raporlar?sayfa=2",
		"":                      "/",
		"https://evil.example/": "/",
		"//evil.example/":       "/",
		`/\evil.example`:        "/",
		"javascript:alert(1)":   "/",
	} {
		if got := safeReturnTo(in); got != want {
			t.Errorf("safeReturnTo(%q) = %q, want %q", in, got, want)
		}
	}
}
