// Package fakeidp is an in-process stand-in for Hayrat Hesabım, used by the
// example tests. It is NOT a reference implementation of the issuer; it serves
// exactly the surface the examples talk to, with the behaviour that matters to
// them: discovery, an ES256 JWKS, the authorization code flow with mandatory
// PKCE S256, client_secret_basic, refresh token rotation with reuse detection,
// and the end-session endpoint.
//
// Everything is real HTTP and every token is really signed, so an example that
// passes against this server is exercising the same code paths it uses in
// production.
package fakeidp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const keyID = "fake-key-1"

// Scope is one hayrat_grants scope entry.
type Scope struct {
	Type string `json:"type"`
	ID   int64  `json:"id"`
}

// Grant is one hayrat_grants entry.
type Grant struct {
	Role   string  `json:"role"`
	Scopes []Scope `json:"scopes"`
}

// User is what the fake issuer knows about the person who "logs in".
type User struct {
	Sub            string
	Name           string
	Gender         string
	ProfileVersion int64 // hayrat_profile_ver; omitted from tokens when 0
	Grants         []Grant
}

// Client is a registered OIDC client.
type Client struct {
	ID           string
	Secret       string // empty for a public client
	RedirectURI  string
	Audience     string // api:<project-key>
	PostLogout   string
	AccessTTL    time.Duration
	RefreshToken bool
}

type authCode struct {
	clientID, redirectURI, challenge, nonce string
	used                                    bool
}

type refreshToken struct {
	clientID, family string
	used             bool
}

// IdP is the fake issuer.
type IdP struct {
	Server *httptest.Server
	key    *ecdsa.PrivateKey

	mu            sync.Mutex
	user          User
	clients       map[string]Client
	codes         map[string]*authCode
	refresh       map[string]*refreshToken
	revoked       map[string]bool // refresh families
	refreshCalls  int
	refreshDelay  time.Duration
	failRefresh   int // status for the next refresh, answered AFTER the token is spent
	forcedNonce   string
	LastLogoutURL *url.URL
}

// New starts a fake issuer on loopback http (the SDK accepts http only for
// loopback issuers).
func New(t testing.TB) *IdP {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("fakeidp: generate key: %v", err)
	}
	idp := &IdP{
		key:     key,
		clients: map[string]Client{},
		codes:   map[string]*authCode{},
		refresh: map[string]*refreshToken{},
		revoked: map[string]bool{},
		user: User{
			Sub:    "01920000-0000-7000-8000-000000000001",
			Name:   "Ayşe Yılmaz",
			Gender: "female",
		},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", idp.discovery)
	mux.HandleFunc("GET /oauth/jwks", idp.jwks)
	mux.HandleFunc("GET /oauth/authorize", idp.authorize)
	mux.HandleFunc("POST /oauth/token", idp.token)
	mux.HandleFunc("/oauth/logout", idp.logout)
	idp.Server = httptest.NewServer(mux)
	t.Cleanup(idp.Server.Close)
	return idp
}

// Issuer is the issuer URL to configure.
func (f *IdP) Issuer() string { return f.Server.URL }

// SetUser replaces the person the next login authenticates as.
func (f *IdP) SetUser(u User) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.user = u
}

// RegisterClient adds a client.
func (f *IdP) RegisterClient(c Client) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if c.AccessTTL == 0 {
		c.AccessTTL = 10 * time.Minute
	}
	f.clients[c.ID] = c
}

// SetRefreshDelay slows every refresh_token grant down, so concurrent
// refreshes overlap the way they do over a real network.
func (f *IdP) SetRefreshDelay(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.refreshDelay = d
}

// FailNextRefresh makes the next refresh_token grant SPEND the presented
// token (as the real issuer does when it accepts the request) and then answer
// with status — the shape of a 5xx or a lost response whose outcome the client
// cannot know.
func (f *IdP) FailNextRefresh(status int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failRefresh = status
}

// ForceNonce makes the next ID tokens carry this nonce instead of the one the
// client sent — the shape of a replayed or injected ID token.
func (f *IdP) ForceNonce(n string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.forcedNonce = n
}

// RefreshCalls reports how many refresh_token grants reached the token
// endpoint, successful or not.
func (f *IdP) RefreshCalls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.refreshCalls
}

// RevokeAllSessions kills every refresh family, the way a logout or an admin
// revocation at the issuer does.
func (f *IdP) RevokeAllSessions() {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, rt := range f.refresh {
		f.revoked[rt.family] = true
	}
}

// AccessToken mints an access token for the current user, for resource-server
// tests that do not need a login flow.
func (f *IdP) AccessToken(t testing.TB, audience string, grants []Grant) string {
	t.Helper()
	f.mu.Lock()
	u := f.user
	f.mu.Unlock()
	if grants != nil {
		u.Grants = grants
	}
	tok, err := f.mintAccess(u, "test-client", audience, 10*time.Minute)
	if err != nil {
		t.Fatalf("fakeidp: mint access token: %v", err)
	}
	return tok
}

// IDToken mints an ID token for the current user, audience = clientID.
func (f *IdP) IDToken(t testing.TB, clientID, nonce string) string {
	t.Helper()
	f.mu.Lock()
	u := f.user
	f.mu.Unlock()
	tok, err := f.mintID(u, clientID, nonce)
	if err != nil {
		t.Fatalf("fakeidp: mint id token: %v", err)
	}
	return tok
}

func (f *IdP) discovery(w http.ResponseWriter, _ *http.Request) {
	iss := f.Issuer()
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                iss,
		"authorization_endpoint":                iss + "/oauth/authorize",
		"token_endpoint":                        iss + "/oauth/token",
		"end_session_endpoint":                  iss + "/oauth/logout",
		"jwks_uri":                              iss + "/oauth/jwks",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"ES256"},
		"scopes_supported":                      []string{"openid", "profile", "offline_access"},
		"code_challenge_methods_supported":      []string{"S256"},
		"token_endpoint_auth_methods_supported": []string{"none", "client_secret_basic"},
	})
}

func (f *IdP) jwks(w http.ResponseWriter, _ *http.Request) {
	b := func(n []byte) string { return base64.RawURLEncoding.EncodeToString(n) }
	writeJSON(w, http.StatusOK, map[string]any{"keys": []any{map[string]any{
		"kty": "EC", "crv": "P-256", "kid": keyID, "use": "sig", "alg": "ES256",
		"x": b(f.key.X.FillBytes(make([]byte, 32))),
		"y": b(f.key.Y.FillBytes(make([]byte, 32))),
	}}})
}

// authorize skips the login screen: the user is already "authenticated", so a
// valid request is answered with a code straight away.
func (f *IdP) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f.mu.Lock()
	c, ok := f.clients[q.Get("client_id")]
	f.mu.Unlock()
	switch {
	case !ok:
		http.Error(w, "unknown client", http.StatusBadRequest)
		return
	case q.Get("redirect_uri") != c.RedirectURI:
		http.Error(w, "invalid redirect_uri", http.StatusBadRequest)
		return
	case q.Get("response_type") != "code":
		http.Error(w, "unsupported response_type", http.StatusBadRequest)
		return
	case q.Get("code_challenge") == "" || q.Get("code_challenge_method") != "S256":
		http.Error(w, "code_challenge is required (PKCE is mandatory)", http.StatusBadRequest)
		return
	}
	code := randomString()
	f.mu.Lock()
	f.codes[code] = &authCode{
		clientID:    c.ID,
		redirectURI: c.RedirectURI,
		challenge:   q.Get("code_challenge"),
		nonce:       q.Get("nonce"),
	}
	f.mu.Unlock()

	back, _ := url.Parse(c.RedirectURI)
	bq := back.Query()
	bq.Set("code", code)
	bq.Set("state", q.Get("state"))
	back.RawQuery = bq.Encode()
	http.Redirect(w, r, back.String(), http.StatusFound)
}

func (f *IdP) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		oauthError(w, "invalid_request")
		return
	}
	c, ok := f.authenticateClient(r)
	if !ok {
		w.Header().Set("WWW-Authenticate", `Basic realm="token"`)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_client"})
		return
	}
	switch r.PostForm.Get("grant_type") {
	case "authorization_code":
		f.exchangeCode(w, r, c)
	case "refresh_token":
		f.rotateRefresh(w, r, c)
	default:
		oauthError(w, "unsupported_grant_type")
	}
}

func (f *IdP) authenticateClient(r *http.Request) (Client, bool) {
	id, secret, basic := r.BasicAuth()
	if basic {
		id, _ = url.QueryUnescape(id)
		secret, _ = url.QueryUnescape(secret)
	} else {
		id = r.PostForm.Get("client_id")
	}
	f.mu.Lock()
	c, ok := f.clients[id]
	f.mu.Unlock()
	if !ok {
		return Client{}, false
	}
	if c.Secret == "" {
		return c, !basic
	}
	return c, basic && subtle.ConstantTimeCompare([]byte(secret), []byte(c.Secret)) == 1
}

func (f *IdP) exchangeCode(w http.ResponseWriter, r *http.Request, c Client) {
	f.mu.Lock()
	ac, ok := f.codes[r.PostForm.Get("code")]
	if ok {
		if ac.used {
			ok = false
		}
		ac.used = true
	}
	u := f.user
	nonce := ac.nonce
	if f.forcedNonce != "" {
		nonce = f.forcedNonce
	}
	f.mu.Unlock()

	sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
	switch {
	case !ok, ac.clientID != c.ID, ac.redirectURI != r.PostForm.Get("redirect_uri"),
		base64.RawURLEncoding.EncodeToString(sum[:]) != ac.challenge:
		oauthError(w, "invalid_grant")
		return
	}
	f.issue(w, u, c, nonce, randomString())
}

func (f *IdP) rotateRefresh(w http.ResponseWriter, r *http.Request, c Client) {
	f.mu.Lock()
	f.refreshCalls++
	delay := f.refreshDelay
	f.mu.Unlock()
	time.Sleep(delay)
	f.mu.Lock()
	rt, ok := f.refresh[r.PostForm.Get("refresh_token")]
	if ok && rt.used {
		// Reuse detection: the whole family dies.
		f.revoked[rt.family] = true
	}
	valid := ok && !rt.used && !f.revoked[rt.family] && rt.clientID == c.ID
	if valid {
		rt.used = true
	}
	u := f.user
	fail := f.failRefresh
	f.failRefresh = 0
	f.mu.Unlock()
	if valid && fail != 0 {
		writeJSON(w, fail, map[string]string{"error": "server_error"})
		return
	}
	if !valid {
		oauthError(w, "invalid_grant")
		return
	}
	f.issue(w, u, c, "", rt.family)
}

func (f *IdP) issue(w http.ResponseWriter, u User, c Client, nonce, family string) {
	access, err := f.mintAccess(u, c.ID, c.Audience, c.AccessTTL)
	if err != nil {
		oauthError(w, "server_error")
		return
	}
	id, err := f.mintID(u, c.ID, nonce)
	if err != nil {
		oauthError(w, "server_error")
		return
	}
	rt := randomString()
	f.mu.Lock()
	f.refresh[rt] = &refreshToken{clientID: c.ID, family: family}
	f.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token":  access,
		"token_type":    "Bearer",
		"expires_in":    int(c.AccessTTL.Seconds()),
		"id_token":      id,
		"refresh_token": rt,
		"scope":         "openid profile offline_access",
	})
}

func (f *IdP) logout(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.LastLogoutURL = r.URL
	f.mu.Unlock()
	w.WriteHeader(http.StatusOK)
}

func (f *IdP) mintAccess(u User, clientID, audience string, ttl time.Duration) (string, error) {
	now := time.Now()
	grants := u.Grants
	if grants == nil {
		grants = []Grant{}
	}
	for i := range grants {
		if grants[i].Scopes == nil {
			grants[i].Scopes = []Scope{}
		}
	}
	claims := jwt.MapClaims{
		"iss":           f.Issuer(),
		"aud":           audience,
		"sub":           u.Sub,
		"sid":           "01920000-0000-7000-8000-0000000000aa",
		"jti":           randomString(),
		"client_id":     clientID,
		"amr":           []string{"otp"},
		"iat":           now.Unix(),
		"nbf":           now.Unix(),
		"exp":           now.Add(ttl).Unix(),
		"hayrat_ver":    1,
		"hayrat_grants": grants,
	}
	if u.ProfileVersion > 0 {
		claims["hayrat_profile_ver"] = u.ProfileVersion
	}
	return f.sign(claims)
}

func (f *IdP) mintID(u User, clientID, nonce string) (string, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		"iss":       f.Issuer(),
		"aud":       []string{clientID},
		"azp":       clientID,
		"sub":       u.Sub,
		"sid":       "01920000-0000-7000-8000-0000000000aa",
		"amr":       []string{"otp"},
		"iat":       now.Unix(),
		"auth_time": now.Unix(),
		"exp":       now.Add(time.Hour).Unix(),
		"name":      u.Name,
		"gender":    u.Gender,
	}
	if nonce != "" {
		claims["nonce"] = nonce
	}
	if u.ProfileVersion > 0 {
		claims["hayrat_profile_ver"] = u.ProfileVersion
	}
	return f.sign(claims)
}

func (f *IdP) sign(claims jwt.MapClaims) (string, error) {
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	tok.Header["kid"] = keyID
	return tok.SignedString(f.key)
}

func oauthError(w http.ResponseWriter, code string) {
	writeJSON(w, http.StatusBadRequest, map[string]string{"error": code})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func randomString() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
