package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	hesabim "github.com/hayrat/hesabim-sdk-go"
	"github.com/hayrat/hesabim-sdk-go/examples/users"
	"golang.org/x/oauth2"
)

const (
	cookieName = "hesabim_session"

	// pendingCookieName carries an unfinished login. It is a separate cookie
	// so that starting a login — which any site can trigger with a link —
	// never touches the session the browser already has.
	pendingCookieName = "hesabim_login"

	// pendingTTL bounds a login that was started and never finished. The
	// issuer's own authorize request lives 10 minutes.
	pendingTTL = 10 * time.Minute

	// sessionTTL is how long an idle local session is kept. The issuer's SSO
	// session is 90 days, sliding; every refresh slides it, and every Save
	// here slides ours. Whether the session is REALLY alive is the issuer's
	// call: an invalid_grant on refresh ends it regardless of this value.
	sessionTTL = 90 * 24 * time.Hour

	// refreshLeeway refreshes the access token this long before it expires,
	// so a token never dies between this server and the API that reads it.
	refreshLeeway = 30 * time.Second

	// tokenRequestTimeout bounds one round trip to the token endpoint.
	tokenRequestTimeout = 5 * time.Second

	// refreshBudget bounds a whole refresh (lock wait aside): the token
	// request, the Save and its one retry. With a distributed lock, the lease
	// must be clearly longer than this (IMPLEMENTATION.md §6.3).
	refreshBudget = 10 * time.Second
)

// Config is the BFF's configuration. ClientSecret is the only secret: it comes
// from the environment, is never logged, and is never sent to the browser.
type Config struct {
	IssuerURL             string
	ClientID              string
	ClientSecret          string
	RedirectURI           string // e.g. https://app.example/auth/callback — registered at the issuer, byte for byte
	PostLogoutRedirectURI string // registered at the issuer, byte for byte
	Audience              string // api:<project-key>
}

// app wires the OIDC client (login, callback, refresh, logout) to the SDK
// verifier that protects the API.
type app struct {
	cfg          Config
	oauth        *oauth2.Config
	idTokens     *oidc.IDTokenVerifier
	api          *hesabim.Verifier
	endSession   string
	secureCookie bool
	callbackPath string

	// tokenClient talks to the token endpoint (code exchange, refresh).
	tokenClient *http.Client

	sessions Store
	locks    sessionLocks
	users    users.Store
}

func newApp(ctx context.Context, cfg Config, sessions Store, userStore users.Store) (*app, error) {
	issuer := strings.TrimSuffix(cfg.IssuerURL, "/")
	// Discovery: every endpoint is read from the issuer, none is hard-coded.
	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, fmt.Errorf("discovery: %w", err)
	}
	var extra struct {
		EndSession string `json:"end_session_endpoint"`
	}
	if err := provider.Claims(&extra); err != nil || extra.EndSession == "" {
		return nil, errors.New("discovery: no end_session_endpoint")
	}

	api, err := hesabim.New(ctx, hesabim.Config{IssuerURL: issuer, Audience: cfg.Audience})
	if err != nil {
		return nil, fmt.Errorf("hesabim verifier: %w", err)
	}

	redirect, err := url.Parse(cfg.RedirectURI)
	if err != nil || redirect.Path == "" {
		return nil, errors.New("HESABIM_REDIRECT_URI must be an absolute URL with a path")
	}

	endpoint := provider.Endpoint()
	// client_secret_basic is what the issuer's token endpoint expects.
	endpoint.AuthStyle = oauth2.AuthStyleInHeader

	return &app{
		cfg: cfg,
		oauth: &oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			Endpoint:     endpoint,
			RedirectURL:  cfg.RedirectURI,
			Scopes:       []string{oidc.ScopeOpenID, "profile", oidc.ScopeOfflineAccess},
		},
		// ID token: ES256 signature against the issuer's JWKS, iss, exp, and
		// aud == our client_id. The nonce is checked in callback.
		idTokens:     provider.Verifier(&oidc.Config{ClientID: cfg.ClientID, SupportedSigningAlgs: []string{oidc.ES256}}),
		api:          api,
		endSession:   extra.EndSession,
		secureCookie: redirect.Scheme == "https",
		callbackPath: redirect.Path,
		sessions:     sessions,
		tokenClient:  &http.Client{Timeout: tokenRequestTimeout},
		users:        userStore,
	}, nil
}

// --- /auth/login -----------------------------------------------------------

// login leaves any existing session alone: a top-level link from another site
// reaches this handler, and it must not be a way to log people out. The
// session is replaced only when the login completes (callback).
func (a *app) login(w http.ResponseWriter, r *http.Request) {
	s := &Session{
		ID:           randomToken(),
		State:        randomToken(),
		Nonce:        randomToken(),
		CodeVerifier: oauth2.GenerateVerifier(), // PKCE is mandatory for confidential clients too
		ReturnTo:     safeReturnTo(r.URL.Query().Get("returnTo")),
	}
	if err := a.sessions.Save(r.Context(), s, pendingTTL, 0); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	a.setCookie(w, pendingCookieName, s.ID, pendingTTL)

	// response_mode is deliberately absent: the issuer supports only query.
	authURL := a.oauth.AuthCodeURL(s.State, oauth2.S256ChallengeOption(s.CodeVerifier), oidc.Nonce(s.Nonce))
	http.Redirect(w, r, authURL, http.StatusFound)
}

// --- /auth/callback --------------------------------------------------------

func (a *app) callback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	pending, err := a.sessionFromCookieNamed(r, pendingCookieName)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "auth_unavailable"})
		return
	}
	if pending == nil || pending.State == "" {
		http.Error(w, "login expired — start again at /auth/login", http.StatusBadRequest)
		return
	}
	// Single use: whatever happens next, this pending login is spent.
	_ = a.sessions.Delete(ctx, pending.ID)
	a.clearCookie(w, pendingCookieName)

	q := r.URL.Query()
	if q.Get("error") != "" {
		http.Error(w, "login was not completed", http.StatusBadRequest)
		return
	}
	if subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(pending.State)) != 1 {
		http.Error(w, "invalid state", http.StatusBadRequest)
		return
	}

	// The session this browser had before (if any) ends here: a new login
	// replaces it. If it cannot be deleted, no new session is established —
	// the old id must not stay valid next to the new one.
	if old, err := r.Cookie(cookieName); err == nil && old.Value != "" {
		if err := a.sessions.Delete(ctx, old.Value); err != nil {
			log.Printf("bff: login: deleting the previous session: %v", err)
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "auth_unavailable"})
			return
		}
		a.locks.forget(old.Value)
	}

	// The code lives 2 minutes and works once. redirect_uri is sent again and
	// must equal the one used at /authorize (oauth2 does that from RedirectURL).
	tok, err := a.oauth.Exchange(a.tokenContext(ctx), q.Get("code"), oauth2.VerifierOption(pending.CodeVerifier))
	if err != nil {
		log.Printf("bff: code exchange failed: %v", err)
		http.Error(w, "login failed", http.StatusBadGateway)
		return
	}
	rawID, _ := tok.Extra("id_token").(string)
	idt, err := a.idTokens.Verify(ctx, rawID)
	if err != nil || subtle.ConstantTimeCompare([]byte(idt.Nonce), []byte(pending.Nonce)) != 1 {
		http.Error(w, "invalid id_token", http.StatusBadGateway)
		return
	}
	var profile struct {
		Name   string `json:"name"`
		Gender string `json:"gender"`
	}
	if err := idt.Claims(&profile); err != nil {
		http.Error(w, "invalid id_token", http.StatusBadGateway)
		return
	}
	// Verifying the access token here, with the same SDK the API uses, turns a
	// wrong HESABIM_AUDIENCE into a failed login instead of a mysterious 401
	// on every API call later.
	p, err := a.api.Verify(ctx, tok.AccessToken)
	if err != nil || p.Subject != idt.Subject {
		log.Printf("bff: access token rejected after login: %v", err)
		http.Error(w, "login failed", http.StatusBadGateway)
		return
	}

	// The users projection is refreshed on EVERY login: name and gender come
	// from the ID token, the key is `sub`.
	if !users.ValidGender(profile.Gender) {
		profile.Gender = ""
	}
	u := users.User{Sub: idt.Subject, Name: profile.Name, Gender: profile.Gender, ProfileVer: p.ProfileVersion, LastSeenAt: time.Now().UTC()}
	if err := a.users.Upsert(ctx, u); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// A NEW session id after login: the pre-login id was handed out to an
	// anonymous browser and must not become an authenticated one (fixation).
	s := &Session{
		ID:           randomToken(),
		Subject:      idt.Subject,
		AccessToken:  tok.AccessToken,
		RefreshToken: tok.RefreshToken,
		IDToken:      rawID,
		AccessExpiry: tok.Expiry,
	}
	if err := a.sessions.Save(ctx, s, sessionTTL, 0); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	a.setCookie(w, cookieName, s.ID, sessionTTL)
	http.Redirect(w, r, pending.ReturnTo, http.StatusSeeOther)
}

// --- /auth/logout ----------------------------------------------------------

// logout ends the local session, then sends the BROWSER to the issuer's
// end-session endpoint. Redirecting the browser (not calling the endpoint
// from here) is what lets the issuer delete its own session cookie.
func (a *app) logout(w http.ResponseWriter, r *http.Request) {
	s, err := a.sessionFromCookie(r)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "auth_unavailable"})
		return
	}
	if s == nil {
		a.clearCookie(w, cookieName)
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	// A logout is only reported once the session is really gone; otherwise
	// the old id would stay valid behind a cookie the browser just dropped.
	if err := a.sessions.Delete(r.Context(), s.ID); err != nil {
		log.Printf("bff: logout: deleting session: %v", err)
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "auth_unavailable"})
		return
	}
	a.locks.forget(s.ID)
	a.clearCookie(w, cookieName)
	if s.IDToken == "" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	u, _ := url.Parse(a.endSession)
	q := u.Query()
	q.Set("id_token_hint", s.IDToken) // mandatory: the endpoint's CSRF defence
	q.Set("post_logout_redirect_uri", a.cfg.PostLogoutRedirectURI)
	q.Set("state", randomToken())
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusSeeOther)
}

// --- /auth/me --------------------------------------------------------------

// me tells the front end whether there is a session and who it belongs to.
// It never answers 401, so the front end can call it on every page load.
func (a *app) me(w http.ResponseWriter, r *http.Request) {
	s, err := a.sessionFromCookie(r)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "auth_unavailable"})
		return
	}
	if s == nil || !s.authenticated() {
		writeJSON(w, http.StatusOK, map[string]any{"authenticated": false})
		return
	}
	u, _, err := a.users.Get(r.Context(), s.Subject)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"authenticated": true, "sub": s.Subject, "name": u.Name, "gender": u.Gender,
	})
}

// --- session → bearer token for the API --------------------------------------

// requireSession turns the cookie into a fresh access token and hands the
// request to next with `Authorization: Bearer …` set — so the API behind it is
// protected by the SDK's own middleware, exactly as in the SPA topology, and
// handlers read the caller with hesabim.FromContext.
func (a *app) requireSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s, err := a.sessionFromCookie(r)
		if err != nil {
			// The session store is down. That is NOT a logout: keep the
			// cookie, let the user retry.
			log.Printf("bff: session store: %v", err)
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "auth_unavailable"})
			return
		}
		if s == nil || !s.authenticated() {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "login_required"})
			return
		}
		token, err := a.freshAccessToken(r.Context(), s)
		switch {
		case errors.Is(err, errSessionEnded):
			a.clearCookie(w, cookieName)
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "login_required"})
			return
		case errors.Is(err, errSessionReplaced):
			// The session was logged out or replaced by a new login while
			// this request waited. The cookie may already name the NEW
			// session, so it is left alone.
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "login_required"})
			return
		case err != nil:
			// The issuer could not be reached (the refresh token was NOT
			// spent) or the session store is down. That is NOT a logout: keep
			// the session, let the user retry.
			log.Printf("bff: refresh failed: %v", err)
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "auth_unavailable"})
			return
		}
		r2 := r.Clone(r.Context())
		r2.Header.Set("Authorization", "Bearer "+token)
		next.ServeHTTP(w, r2)
	})
}

var (
	// errSessionEnded: THIS request's session was ended; clear its cookie.
	errSessionEnded = errors.New("session ended")
	// errSessionReplaced: the session was deleted or changed by someone else
	// (logout, new login) meanwhile; the cookie is not ours to clear.
	errSessionReplaced = errors.New("session replaced concurrently")
)

// freshAccessToken returns a usable access token, refreshing it if needed.
//
// The refresh token is spent the moment the issuer ACCEPTS the request, and
// presenting a spent token again revokes the whole session (reuse detection).
// Two rules make a replay impossible, even across crashes and replicas:
//
//  1. Before the request leaves, RefreshPending is stored with a conditional
//     (versioned) write. Any later attempt that finds it set — a crash, a lost
//     lease, a failed delete — ends the session instead of sending the token.
//  2. The outcome is stored with a conditional write too: if the session was
//     deleted (logout) or replaced meanwhile, the result is discarded and the
//     session is NOT brought back.
//
// Outcomes:
//
//   - never sent (dial/DNS failure): marker cleared, session kept (503)
//   - sent, and ANY answer other than success — invalid_grant, any other
//     4xx (invalid_client included), 5xx, timeout, dropped connection: the
//     token may be spent → the session ends (401), the token is never resent
//   - success but the rotated tokens cannot be stored: one retry, then the
//     session ends (its stored refresh token is already dead; the marker
//     stays and guards it)
func (a *app) freshAccessToken(ctx context.Context, s *Session) (string, error) {
	if time.Until(s.AccessExpiry) > refreshLeeway && !s.RefreshPending {
		return s.AccessToken, nil
	}

	// Detached from the request: once the refresh is on the wire, the issuer
	// rotates whether or not the browser is still waiting, and walking away
	// from the answer would lose the only live refresh token.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), refreshBudget)
	defer cancel()

	unlock := a.locks.lock(s.ID)
	defer unlock()

	// Re-read under the lock: a concurrent request may have refreshed already,
	// in which case our copy holds a refresh token that is now dead.
	cur, err := a.sessions.Get(ctx, s.ID)
	switch {
	case errors.Is(err, errNoSession):
		return "", errSessionEnded
	case err != nil:
		return "", fmt.Errorf("session store: %w", err)
	}
	if cur.RefreshPending {
		log.Printf("bff: an earlier refresh never recorded its outcome (started %s), ending the session", cur.RefreshStartedAt.Format(time.RFC3339))
		a.dropSession(ctx, cur.ID)
		return "", errSessionEnded
	}
	if time.Until(cur.AccessExpiry) > refreshLeeway {
		return cur.AccessToken, nil
	}

	cur.RefreshPending = true
	cur.RefreshStartedAt = time.Now().UTC()
	switch err := a.sessions.Save(ctx, cur, sessionTTL, cur.Version); {
	case errors.Is(err, errConflict):
		// Changed since we read it: logged out, replaced, or refreshed by
		// another replica. Nothing was sent. Use a fresh token if there is
		// one; otherwise this session is not ours any more.
		again, err := a.sessions.Get(ctx, s.ID)
		switch {
		case errors.Is(err, errNoSession):
			return "", errSessionReplaced
		case err != nil:
			return "", fmt.Errorf("session store: %w", err)
		case !again.RefreshPending && time.Until(again.AccessExpiry) > refreshLeeway:
			return again.AccessToken, nil
		}
		return "", errSessionReplaced
	case err != nil:
		return "", fmt.Errorf("session store: %w", err)
	}

	tok, err := a.oauth.TokenSource(a.tokenContext(ctx), &oauth2.Token{RefreshToken: cur.RefreshToken}).Token()
	if err != nil {
		if notSent(err) {
			// Never reached the issuer: nothing was spent.
			cur.RefreshPending = false
			cur.RefreshStartedAt = time.Time{}
			if err := a.sessions.Save(ctx, cur, sessionTTL, cur.Version); err != nil {
				// The marker stays; the next attempt ends the session. Safe.
				log.Printf("bff: could not clear the refresh marker: %v", err)
			}
			return "", err
		}
		// Sent: whatever the answer, the token may be spent. Never resend it.
		var re *oauth2.RetrieveError
		switch {
		case errors.As(err, &re) && re.ErrorCode == "invalid_grant":
			// The session is over at the issuer (logout, revocation, expiry,
			// reuse detection). Send the user to /auth/login.
		case errors.As(err, &re) && (re.ErrorCode == "invalid_client" || re.ErrorCode == "unauthorized_client"):
			log.Printf("bff: the issuer refused this client (%s) — check HESABIM_CLIENT_ID / HESABIM_CLIENT_SECRET; ending the session", re.ErrorCode)
		default:
			log.Printf("bff: refresh did not succeed, ending the session: %v", err)
		}
		a.dropSession(ctx, cur.ID)
		return "", errSessionEnded
	}

	// Rotation: the response carries a NEW refresh token and the old one is
	// already dead. Persist before anything else can fail.
	cur.AccessToken = tok.AccessToken
	cur.RefreshToken = tok.RefreshToken
	cur.AccessExpiry = tok.Expiry
	cur.RefreshPending = false
	cur.RefreshStartedAt = time.Time{}
	if raw, ok := tok.Extra("id_token").(string); ok {
		if _, err := a.idTokens.Verify(ctx, raw); err == nil {
			cur.IDToken = raw
		}
	}
	expected := cur.Version
	err = a.sessions.Save(ctx, cur, sessionTTL, expected)
	if err != nil && !errors.Is(err, errConflict) {
		err = a.sessions.Save(ctx, cur, sessionTTL, expected)
	}
	switch {
	case errors.Is(err, errConflict):
		// Logged out or replaced while we waited: discard the result, do not
		// resurrect the session, and do not touch the cookie.
		return "", errSessionReplaced
	case err != nil:
		log.Printf("bff: rotated tokens could not be stored, ending the session: %v", err)
		a.dropSession(ctx, cur.ID)
		return "", errSessionEnded
	}
	return cur.AccessToken, nil
}

// notSent reports whether a token request failed before reaching the issuer.
// Only failures that provably happen before the request is written count;
// anything else is treated as "sent, outcome unknown".
func notSent(err error) bool {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return true
	}
	var opErr *net.OpError
	return errors.As(err, &opErr) && opErr.Op == "dial"
}

// dropSession ends a session locally. A failed delete is logged, not fatal:
// a session that could still hold a spent token also still holds
// RefreshPending, so it can never send that token again.
func (a *app) dropSession(ctx context.Context, id string) {
	if err := a.sessions.Delete(ctx, id); err != nil {
		log.Printf("bff: deleting session: %v", err)
	}
	a.locks.forget(id)
}

// tokenContext makes oauth2 use tokenClient (and its timeout) for ctx.
func (a *app) tokenContext(ctx context.Context) context.Context {
	return context.WithValue(ctx, oauth2.HTTPClient, a.tokenClient)
}

// --- helpers -----------------------------------------------------------------

// sessionFromCookie returns (nil, nil) when the browser has no session and a
// non-nil error only when the store itself failed — which callers must answer
// with 503 and an untouched cookie, never with a logout.
func (a *app) sessionFromCookie(r *http.Request) (*Session, error) {
	return a.sessionFromCookieNamed(r, cookieName)
}

func (a *app) sessionFromCookieNamed(r *http.Request, name string) (*Session, error) {
	c, err := r.Cookie(name)
	if err != nil || c.Value == "" {
		return nil, nil
	}
	s, err := a.sessions.Get(r.Context(), c.Value)
	switch {
	case errors.Is(err, errNoSession):
		return nil, nil
	case err != nil:
		return nil, err
	}
	return s, nil
}

func (a *app) setCookie(w http.ResponseWriter, name, id string, ttl time.Duration) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    id,
		Path:     "/",
		MaxAge:   int(ttl.Seconds()),
		HttpOnly: true,
		Secure:   a.secureCookie, // true whenever the app is served over https
		SameSite: http.SameSiteLaxMode,
	})
}

func (a *app) clearCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{
		Name: name, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: a.secureCookie, SameSite: http.SameSiteLaxMode,
	})
}

// safeReturnTo accepts only a same-site path. Anything else — an absolute URL,
// a scheme-relative "//evil.example", a backslash trick — becomes "/", which is
// what keeps /auth/login from being an open redirect.
func safeReturnTo(v string) string {
	if !strings.HasPrefix(v, "/") || strings.HasPrefix(v, "//") || strings.Contains(v, `\`) {
		return "/"
	}
	u, err := url.Parse(v)
	if err != nil || u.IsAbs() || u.Host != "" {
		return "/"
	}
	return v
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
