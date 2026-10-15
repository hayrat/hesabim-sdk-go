package main

import (
	"context"
	"errors"
	"math"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// flakyStore fails on demand in front of the in-memory store, the way a Redis
// outage would.
type flakyStore struct {
	*memoryStore
	mu        sync.Mutex
	getPlan   []bool // consumed per Get call: true = fail; empty = succeed
	skipSaves int    // let the next N Save calls through first…
	failSaves int    // …then fail the next N

	skipDeletes int // let the next N Delete calls through first…
	failDeletes int // …then fail the next N
}

func (f *flakyStore) Delete(ctx context.Context, id string) error {
	f.mu.Lock()
	fail := false
	switch {
	case f.skipDeletes > 0:
		f.skipDeletes--
	case f.failDeletes > 0:
		f.failDeletes--
		fail = true
	}
	f.mu.Unlock()
	if fail {
		return errStoreDown
	}
	return f.memoryStore.Delete(ctx, id)
}

var errStoreDown = errors.New("store unavailable")

func (f *flakyStore) Get(ctx context.Context, id string) (*Session, error) {
	f.mu.Lock()
	fail := false
	if len(f.getPlan) > 0 {
		fail, f.getPlan = f.getPlan[0], f.getPlan[1:]
	}
	f.mu.Unlock()
	if fail {
		return nil, errStoreDown
	}
	return f.memoryStore.Get(ctx, id)
}

func (f *flakyStore) Save(ctx context.Context, s *Session, ttl time.Duration, expectedVersion int64) error {
	f.mu.Lock()
	fail := false
	switch {
	case f.skipSaves > 0:
		f.skipSaves--
	case f.failSaves > 0:
		f.failSaves--
		fail = true
	}
	f.mu.Unlock()
	if fail {
		return errStoreDown
	}
	return f.memoryStore.Save(ctx, s, ttl, expectedVersion)
}

func newFlakyHarness(t *testing.T) (*harness, *flakyStore) {
	t.Helper()
	var flaky *flakyStore
	h := newHarnessWithStore(t, func(m *memoryStore) Store {
		flaky = &flakyStore{memoryStore: m}
		return flaky
	})
	return h, flaky
}

// closedURL is a token endpoint nobody listens on: the request is refused at
// dial time and never reaches an issuer.
func closedURL(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	return "http://" + addr + "/oauth/token"
}

// A refresh that never left this machine did not spend the refresh token, so
// the session is kept and the same token works once the issuer is back.
//
// MUTATION: treat a dial error as an ambiguous outcome and the session ends.
func TestRefresh_UnsentRequestKeepsTheSession(t *testing.T) {
	h := newHarness(t)
	h.login(t)
	h.expireAccessToken(t)

	tokenURL := h.a.oauth.Endpoint.TokenURL
	h.a.oauth.Endpoint.TokenURL = closedURL(t)
	if got, body := h.get(t, "/api/me"); got != http.StatusServiceUnavailable || !strings.Contains(body, "auth_unavailable") {
		t.Fatalf("issuer unreachable = %d %s, want 503 auth_unavailable", got, body)
	}
	if n := h.idp.RefreshCalls(); n != 0 {
		t.Fatalf("refresh calls = %d, want 0", n)
	}

	h.a.oauth.Endpoint.TokenURL = tokenURL
	if got, body := h.get(t, "/api/me"); got != http.StatusOK {
		t.Fatalf("after the issuer came back = %d %s, want 200", got, body)
	}
}

// The issuer accepted the request — and so spent the refresh token — but the
// answer was a 5xx. Sending the same token again would trip reuse detection,
// so the session ends here and the token is never replayed.
//
// MUTATION: return the error as a transient 503 (the old behaviour) and the
// first assertion fails; keep the session and the replay assertion fails.
func TestRefresh_AmbiguousFailureEndsTheSessionWithoutReplay(t *testing.T) {
	h := newHarness(t)
	h.login(t)
	id := h.sessionID(t)
	h.expireAccessToken(t)
	h.idp.FailNextRefresh(http.StatusBadGateway)

	if got, body := h.get(t, "/api/me"); got != http.StatusUnauthorized || !strings.Contains(body, "login_required") {
		t.Fatalf("after an ambiguous refresh = %d %s, want 401 login_required", got, body)
	}
	if _, err := h.sessions.Get(context.Background(), id); err == nil {
		t.Fatal("session survived an ambiguous refresh")
	}
	_, _ = h.get(t, "/api/me")
	if n := h.idp.RefreshCalls(); n != 1 {
		t.Fatalf("refresh calls = %d, want 1 (the spent token was replayed)", n)
	}
}

// A refresh that times out after it was sent is just as ambiguous.
func TestRefresh_TimeoutAfterSendEndsTheSession(t *testing.T) {
	h := newHarness(t)
	h.login(t)
	h.expireAccessToken(t)
	h.idp.SetRefreshDelay(300 * time.Millisecond)
	h.a.tokenClient.Timeout = 50 * time.Millisecond

	if got, body := h.get(t, "/api/me"); got != http.StatusUnauthorized {
		t.Fatalf("timed-out refresh = %d %s, want 401", got, body)
	}
	time.Sleep(400 * time.Millisecond) // let the issuer finish spending the token
	_, _ = h.get(t, "/api/me")
	if n := h.idp.RefreshCalls(); n != 1 {
		t.Fatalf("refresh calls = %d, want 1", n)
	}
}

// The browser going away mid-refresh must not abandon a rotation the issuer
// has already performed: the new refresh token is still stored.
//
// MUTATION: run the refresh on the request context and the next request
// replays the spent token (reuse detection → 401).
func TestRefresh_CompletesWhenTheClientDisconnects(t *testing.T) {
	h := newHarness(t)
	h.login(t)
	h.expireAccessToken(t)
	s, err := h.sessions.Get(context.Background(), h.sessionID(t))
	if err != nil {
		t.Fatal(err)
	}
	h.idp.SetRefreshDelay(200 * time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(50*time.Millisecond, cancel)
	_, _ = h.a.freshAccessToken(ctx, s) // the caller is gone; the result does not matter
	time.Sleep(300 * time.Millisecond)  // the issuer has spent the token by now
	h.idp.SetRefreshDelay(0)

	if got, body := h.get(t, "/api/me"); got != http.StatusOK {
		t.Fatalf("after a disconnected refresh = %d %s, want 200", got, body)
	}
	if n := h.idp.RefreshCalls(); n != 1 {
		t.Fatalf("refresh calls = %d, want 1", n)
	}
}

// A rotation that succeeded at the issuer but could not be stored is retried
// once; if that fails too, the session ends (its stored refresh token is dead).
//
// MUTATION: drop the retry and the first case fails; return a 503 instead of
// ending the session and the second case fails.
func TestRefresh_SaveFailureRetriesOnceThenEndsTheSession(t *testing.T) {
	t.Run("one failure is retried", func(t *testing.T) {
		h, flaky := newFlakyHarness(t)
		h.login(t)
		h.expireAccessToken(t)
		flaky.skipSaves, flaky.failSaves = 1, 1 // the marker write passes, the outcome write fails once
		if got, body := h.get(t, "/api/me"); got != http.StatusOK {
			t.Fatalf("= %d %s, want 200", got, body)
		}
		s, err := h.sessions.Get(context.Background(), h.sessionID(t))
		if err != nil || time.Until(s.AccessExpiry) < time.Minute {
			t.Fatalf("rotated tokens were not stored: %+v %v", s, err)
		}
	})
	t.Run("marker write fails: nothing is sent", func(t *testing.T) {
		h, flaky := newFlakyHarness(t)
		h.login(t)
		h.expireAccessToken(t)
		flaky.failSaves = 1
		if got, body := h.get(t, "/api/me"); got != http.StatusServiceUnavailable {
			t.Fatalf("= %d %s, want 503", got, body)
		}
		if n := h.idp.RefreshCalls(); n != 0 {
			t.Fatalf("refresh calls = %d, want 0", n)
		}
		if got, _ := h.get(t, "/api/me"); got != http.StatusOK {
			t.Fatalf("after the store recovered = %d, want 200", got)
		}
	})
	t.Run("two failures end the session", func(t *testing.T) {
		h, flaky := newFlakyHarness(t)
		h.login(t)
		h.expireAccessToken(t)
		flaky.skipSaves, flaky.failSaves = 1, 2
		if got, body := h.get(t, "/api/me"); got != http.StatusUnauthorized {
			t.Fatalf("= %d %s, want 401", got, body)
		}
		if n := h.idp.RefreshCalls(); n != 1 {
			t.Fatalf("refresh calls = %d, want 1", n)
		}
	})
}

// A session store outage is not a logout: 503, and the cookie is kept.
//
// MUTATION: map every Get error to "no session" (either read) and the
// request becomes a 401 that clears the cookie.
func TestStoreOutage_Is503AndKeepsTheCookie(t *testing.T) {
	cases := map[string]struct {
		plan   []bool
		expire bool
	}{
		"cookie lookup":       {plan: []bool{true}},
		"re-read under lock":  {plan: []bool{false, true}, expire: true},
		"cookie lookup on me": {plan: []bool{true}},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			h, flaky := newFlakyHarness(t)
			h.login(t)
			if c.expire {
				h.expireAccessToken(t)
			}
			path := "/api/me"
			if name == "cookie lookup on me" {
				path = "/auth/me"
			}
			flaky.mu.Lock()
			flaky.getPlan = c.plan
			flaky.mu.Unlock()

			resp, err := h.client.Get(h.app.URL + path)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusServiceUnavailable {
				t.Fatalf("store outage = %d, want 503", resp.StatusCode)
			}
			if sc := resp.Header.Get("Set-Cookie"); sc != "" {
				t.Fatalf("cookie was touched during an outage: %s", sc)
			}
			if got, _ := h.get(t, "/api/me"); got != http.StatusOK {
				t.Fatalf("after the outage = %d, want 200", got)
			}
		})
	}
}

// Starting a login — which any site can trigger with a top-level link — must
// not end the session the browser already has.
//
// MUTATION: delete the existing session (or overwrite its cookie) in login.
func TestLogin_DoesNotEndAnExistingSession(t *testing.T) {
	h := newHarness(t)
	h.login(t)

	h.client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := h.client.Get(h.app.URL + "/auth/login")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	h.client.CheckRedirect = nil

	if got, body := h.get(t, "/api/me"); got != http.StatusOK {
		t.Fatalf("after an unfinished second login = %d %s, want 200", got, body)
	}
}

// A completed login replaces the previous session: new id (fixation), and the
// old one is gone from the store.
func TestLogin_ReplacesThePreviousSession(t *testing.T) {
	h := newHarness(t)
	h.login(t)
	first := h.sessionID(t)
	h.login(t)
	second := h.sessionID(t)

	if first == second {
		t.Fatal("session id was not rotated on login")
	}
	if _, err := h.sessions.Get(context.Background(), first); err == nil {
		t.Fatal("the previous session survived a new login")
	}
	u, _ := url.Parse(h.app.URL)
	for _, c := range h.client.Jar.Cookies(u) {
		if c.Name == pendingCookieName {
			t.Fatalf("pending-login cookie left behind: %v", c)
		}
	}
}

// A process that died mid-refresh (or lost its lease, or could not delete the
// session) leaves RefreshPending behind. The next request must NOT send the
// possibly spent refresh token: the session ends instead.
//
// MUTATION: ignore RefreshPending and the stored token is sent again.
func TestRefresh_PendingMarkerIsNeverReplayed(t *testing.T) {
	h := newHarness(t)
	h.login(t)
	ctx := context.Background()
	s, err := h.sessions.Get(ctx, h.sessionID(t))
	if err != nil {
		t.Fatal(err)
	}
	s.AccessExpiry = time.Now().Add(-time.Minute)
	s.RefreshPending = true
	s.RefreshStartedAt = time.Now().Add(-time.Second)
	if err := h.sessions.Save(ctx, s, sessionTTL, s.Version); err != nil {
		t.Fatal(err)
	}

	if got, body := h.get(t, "/api/me"); got != http.StatusUnauthorized {
		t.Fatalf("pending refresh left behind = %d %s, want 401", got, body)
	}
	if n := h.idp.RefreshCalls(); n != 0 {
		t.Fatalf("refresh calls = %d, want 0 (a possibly spent token was replayed)", n)
	}
}

// The marker is written before the request leaves, so it is in the store
// while the issuer is still answering.
//
// MUTATION: write the marker after the POST (or not at all).
func TestRefresh_MarkerIsStoredBeforeTheRequest(t *testing.T) {
	h := newHarness(t)
	h.login(t)
	id := h.sessionID(t)
	h.expireAccessToken(t)
	h.idp.SetRefreshDelay(300 * time.Millisecond)

	done := make(chan struct{})
	go func() { defer close(done); _, _ = h.get(t, "/api/me") }()
	time.Sleep(100 * time.Millisecond)
	s, err := h.sessions.Get(context.Background(), id)
	if err != nil || !s.RefreshPending {
		t.Fatalf("while the refresh is in flight: err=%v, want RefreshPending set", err)
	}
	<-done
	if s, err := h.sessions.Get(context.Background(), id); err != nil || s.RefreshPending {
		t.Fatalf("after a successful refresh: err=%v, want RefreshPending cleared", err)
	}
}

// Logging out while a refresh is in flight: the refresh's result must not
// bring the deleted session back.
//
// MUTATION: make Save unconditional and the session id is valid again.
func TestRefresh_DoesNotResurrectALoggedOutSession(t *testing.T) {
	h := newHarness(t)
	h.login(t)
	id := h.sessionID(t)
	h.expireAccessToken(t)
	h.idp.SetRefreshDelay(300 * time.Millisecond)

	codes := make(chan int, 1)
	go func() { c, _ := h.get(t, "/api/me"); codes <- c }()
	time.Sleep(100 * time.Millisecond)

	req, _ := http.NewRequest(http.MethodPost, h.app.URL+"/auth/logout", nil)
	req.Header.Set("Origin", h.app.URL)
	// A second client sharing the browser's cookie jar: the first is busy in
	// the goroutine above.
	logoutClient := &http.Client{
		Transport:     h.client.Transport,
		Jar:           h.client.Jar,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := logoutClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if c := <-codes; c != http.StatusUnauthorized {
		t.Fatalf("in-flight request after logout = %d, want 401", c)
	}
	if _, err := h.sessions.Get(context.Background(), id); err == nil {
		t.Fatal("logged-out session was resurrected")
	}
}

// After the refresh request was sent, ANY non-success answer ends the session:
// an unknown 4xx (here a 400 server_error, after the issuer spent the token)
// and a configuration error (invalid_client) alike. Only "never sent" keeps it.
//
// MUTATION: treat 4xx other than invalid_grant as "not spent" (clear the
// marker, keep the session) and the token is replayed.
func TestRefresh_AnyAnswerOtherThanSuccessEndsTheSession(t *testing.T) {
	t.Run("400 server_error after the token was spent", func(t *testing.T) {
		h := newHarness(t)
		h.login(t)
		h.expireAccessToken(t)
		h.idp.FailNextRefresh(http.StatusBadRequest)

		if got, body := h.get(t, "/api/me"); got != http.StatusUnauthorized {
			t.Fatalf("= %d %s, want 401", got, body)
		}
		_, _ = h.get(t, "/api/me")
		if n := h.idp.RefreshCalls(); n != 1 {
			t.Fatalf("refresh calls = %d, want 1 (the spent token was replayed)", n)
		}
	})
	t.Run("invalid_client", func(t *testing.T) {
		h := newHarness(t)
		h.login(t)
		id := h.sessionID(t)
		h.expireAccessToken(t)
		h.a.oauth.ClientSecret = "wrong"

		if got, body := h.get(t, "/api/me"); got != http.StatusUnauthorized {
			t.Fatalf("= %d %s, want 401", got, body)
		}
		if _, err := h.sessions.Get(context.Background(), id); err == nil {
			t.Fatal("session survived a refused refresh")
		}
	})
}

// A logout whose delete failed must not look successful: 503, the cookie is
// kept, and the user can try again.
//
// MUTATION: ignore the Delete error and the logout answers 303.
func TestLogout_FailedDeleteIs503(t *testing.T) {
	h, flaky := newFlakyHarness(t)
	h.login(t)
	flaky.failDeletes = 1

	req, _ := http.NewRequest(http.MethodPost, h.app.URL+"/auth/logout", nil)
	req.Header.Set("Origin", h.app.URL)
	h.client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := h.client.Do(req)
	h.client.CheckRedirect = nil
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable || resp.Header.Get("Set-Cookie") != "" {
		t.Fatalf("logout with a failed delete = %d, Set-Cookie %q; want 503 and no cookie change",
			resp.StatusCode, resp.Header.Get("Set-Cookie"))
	}
	if got, _ := h.get(t, "/api/me"); got != http.StatusOK {
		t.Fatalf("session after the failed logout = %d, want 200 (still logged in, can retry)", got)
	}
}

// A new login whose old session cannot be deleted is not established.
//
// MUTATION: ignore the Delete error in callback and the login completes.
func TestCallback_FailedDeleteOfTheOldSessionIs503(t *testing.T) {
	h, flaky := newFlakyHarness(t)
	h.login(t)
	first := h.sessionID(t)
	flaky.skipDeletes, flaky.failDeletes = 1, 1 // the pending record goes, the old session does not

	resp, err := h.client.Get(h.app.URL + "/auth/login")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("callback with a failed delete = %d, want 503", resp.StatusCode)
	}
	if got := h.sessionID(t); got != first {
		t.Fatal("a new session was established although the old one could not be deleted")
	}
}

// A refresh that lost to a NEW login (its session was deleted and replaced
// meanwhile) answers 401 WITHOUT clearing the cookie: that cookie now belongs
// to the new session, and a late response must not log the user out of it.
//
// MUTATION: clear the cookie on errConflict and the new session is lost.
func TestRefresh_ConflictDoesNotClearTheNewSessionsCookie(t *testing.T) {
	h := newHarness(t)
	h.login(t)
	h.expireAccessToken(t)
	h.idp.SetRefreshDelay(300 * time.Millisecond)

	type result struct {
		code      int
		setCookie string
	}
	done := make(chan result, 1)
	go func() {
		resp, err := h.client.Get(h.app.URL + "/api/me")
		if err != nil {
			done <- result{}
			return
		}
		resp.Body.Close()
		done <- result{resp.StatusCode, resp.Header.Get("Set-Cookie")}
	}()
	time.Sleep(100 * time.Millisecond)
	h.idp.SetRefreshDelay(0)
	h.login(t) // completes while the old refresh is still waiting

	r := <-done
	if r.code != http.StatusUnauthorized {
		t.Fatalf("stale refresh = %d, want 401", r.code)
	}
	if strings.Contains(r.setCookie, cookieName) {
		t.Fatalf("stale refresh touched the session cookie: %s", r.setCookie)
	}
	if got, body := h.get(t, "/api/me"); got != http.StatusOK {
		t.Fatalf("new session after the stale refresh = %d %s, want 200", got, body)
	}
}

// The version never wraps around: a row at math.MaxInt64 cannot be written
// again (a wrapped version could match a stale reader's).
//
// MUTATION: drop the MaxInt64 guard and the write succeeds with a negative
// version.
func TestMemoryStore_VersionDoesNotOverflow(t *testing.T) {
	m := newMemoryStore()
	ctx := context.Background()
	s := &Session{ID: "x"}
	if err := m.Save(ctx, s, time.Minute, 0); err != nil {
		t.Fatal(err)
	}
	m.mu.Lock()
	row := m.rows["x"]
	row.s.Version = math.MaxInt64
	m.rows["x"] = row
	m.mu.Unlock()

	s.Version = math.MaxInt64
	if err := m.Save(ctx, s, time.Minute, math.MaxInt64); !errors.Is(err, errConflict) {
		t.Fatalf("save at MaxInt64 = %v, want errConflict", err)
	}
	if err := m.Save(ctx, &Session{ID: "x"}, time.Minute, 0); !errors.Is(err, errConflict) {
		t.Fatalf("create over an existing row = %v, want errConflict", err)
	}
}
