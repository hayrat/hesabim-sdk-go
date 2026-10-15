package hesabim

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Shared fixtures for every test in this package.
//
// The rule they exist to serve: NOTHING here fakes the thing under test. The
// issuer is a real HTTP server, the keys are real P-256 keys, the tokens are
// really signed, and the only injected seam is the clock — which is injected so
// that a boundary can be tested AT the boundary instead of with a sleep.

const (
	testAudience = "api:test-project"
	testKeyID    = "key-1"
)

// --- keys and tokens ---

type signingKey struct {
	kid string
	key *ecdsa.PrivateKey
}

func newSigningKey(t testing.TB, kid string) signingKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate P-256 key: %v", err)
	}
	return signingKey{kid: kid, key: key}
}

// jwk renders the key the way the issuer publishes it.
func (s signingKey) jwk() map[string]any {
	return map[string]any{
		"kty": "EC",
		"crv": "P-256",
		"kid": s.kid,
		"use": "sig",
		"alg": "ES256",
		"x":   b64(s.key.X.FillBytes(make([]byte, coordinateBytes))),
		"y":   b64(s.key.Y.FillBytes(make([]byte, coordinateBytes))),
	}
}

// sign produces a real ES256 compact JWS over the claims, with the kid in the
// header exactly where the issuer puts it.
func (s signingKey) sign(t *testing.T, claims map[string]any) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims(claims))
	token.Header["kid"] = s.kid
	signed, err := token.SignedString(s.key)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return signed
}

// signHS256 forges the classic algorithm-confusion token: same kid, same
// claims, symmetric algorithm. Tests hand it the verification key's own bytes
// as the HMAC secret, which is the attack in its strongest form.
func signHS256(t *testing.T, kid string, secret []byte, claims map[string]any) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims(claims))
	token.Header["kid"] = kid
	signed, err := token.SignedString(secret)
	if err != nil {
		t.Fatalf("sign HS256: %v", err)
	}
	return signed
}

// signNone produces an unsigned token, the other half of the algorithm matrix.
func signNone(t *testing.T, kid string, claims map[string]any) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims(claims))
	token.Header["kid"] = kid
	signed, err := token.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("sign none: %v", err)
	}
	return signed
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func b64decode(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }

// jwksDocument renders a JWKS containing the given keys.
func jwksDocument(t testing.TB, keys ...signingKey) []byte {
	t.Helper()
	entries := make([]map[string]any, 0, len(keys))
	for _, k := range keys {
		entries = append(entries, k.jwk())
	}
	raw, err := json.Marshal(map[string]any{"keys": entries})
	if err != nil {
		t.Fatalf("marshal jwks: %v", err)
	}
	return raw
}

// --- clock ---

type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func newTestClock() *testClock {
	// A fixed instant, not time.Now: every expectation below is arithmetic on
	// this value and none of them should depend on when the suite runs.
	return &testClock{now: time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)}
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// --- the fake issuer ---

// fakeIdP is an httptest server that serves a discovery document and a JWKS,
// counts what was fetched, and can be made to misbehave in the specific ways
// the contract cares about.
type fakeIdP struct {
	server *httptest.Server

	mu              sync.Mutex
	jwks            []byte
	jwksStatus      int
	discovery       []byte
	discoveryStatus int
	redirectFirst   bool

	jwksHits      int
	discoveryHits int
	jwksFetched   chan struct{}
}

func newFakeIdP(t *testing.T, keys ...signingKey) *fakeIdP {
	t.Helper()

	idp := &fakeIdP{
		jwksStatus:      http.StatusOK,
		discoveryStatus: http.StatusOK,
		// Buffered generously: a test that does not care about the signal must
		// never be able to block the server on it.
		jwksFetched: make(chan struct{}, 64),
	}

	mux := http.NewServeMux()
	mux.HandleFunc(discoveryPath, func(w http.ResponseWriter, r *http.Request) {
		idp.mu.Lock()
		idp.discoveryHits++
		status, body, redirect := idp.discoveryStatus, idp.discovery, idp.redirectFirst
		idp.mu.Unlock()

		if redirect {
			http.Redirect(w, r, idp.server.URL+"/elsewhere", http.StatusFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write(body)
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		idp.mu.Lock()
		idp.jwksHits++
		status, body := idp.jwksStatus, idp.jwks
		idp.mu.Unlock()

		select {
		case idp.jwksFetched <- struct{}{}:
		default:
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write(body)
	})
	// The target of the redirect case: a perfectly good discovery document at
	// the wrong URL, so that a test proving redirects are not followed fails if
	// the client ever starts following them.
	mux.HandleFunc("/elsewhere", func(w http.ResponseWriter, _ *http.Request) {
		idp.mu.Lock()
		body := idp.discovery
		idp.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	})

	idp.server = httptest.NewServer(mux)
	t.Cleanup(idp.server.Close)

	idp.setDiscovery(t, map[string]any{
		"issuer":                 idp.server.URL,
		"authorization_endpoint": idp.server.URL + "/oauth/authorize",
		"token_endpoint":         idp.server.URL + "/oauth/token",
		"end_session_endpoint":   idp.server.URL + "/oauth/logout",
		"jwks_uri":               idp.server.URL + "/jwks",
	})
	idp.setKeys(t, keys...)

	return idp
}

func (f *fakeIdP) issuer() string { return f.server.URL }

func (f *fakeIdP) setKeys(t *testing.T, keys ...signingKey) {
	t.Helper()
	f.setJWKSBody(jwksDocument(t, keys...))
}

func (f *fakeIdP) setJWKSBody(body []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.jwks = body
}

func (f *fakeIdP) setJWKSStatus(status int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.jwksStatus = status
}

func (f *fakeIdP) setDiscovery(t *testing.T, doc map[string]any) {
	t.Helper()
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal discovery: %v", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.discovery = raw
}

func (f *fakeIdP) setDiscoveryBody(body []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.discovery = body
}

func (f *fakeIdP) setDiscoveryStatus(status int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.discoveryStatus = status
}

func (f *fakeIdP) setRedirectDiscovery(on bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.redirectFirst = on
}

func (f *fakeIdP) jwksFetchCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.jwksHits
}

func (f *fakeIdP) discoveryFetchCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.discoveryHits
}

// drainJWKSSignals empties the fetch-notification channel so a later
// waitForJWKSFetch observes only fetches that happen after this point.
func (f *fakeIdP) drainJWKSSignals() {
	for {
		select {
		case <-f.jwksFetched:
		default:
			return
		}
	}
}

// waitForJWKSFetch blocks until the JWKS endpoint is hit, or fails the test.
// Used only for the BACKGROUND refresh, which by definition no request waits
// on; every other path is synchronous and needs no waiting.
func (f *fakeIdP) waitForJWKSFetch(t *testing.T) {
	t.Helper()
	select {
	case <-f.jwksFetched:
	case <-time.After(2 * time.Second):
		t.Fatal("expected a JWKS fetch; none happened within 2s")
	}
}

// --- verifier construction ---

// newTestVerifier builds a Verifier against the fake issuer on the test clock.
// mutate may adjust the Config before New runs.
func newTestVerifier(t *testing.T, idp *fakeIdP, clock *testClock, mutate func(*Config)) *Verifier {
	t.Helper()
	cfg := Config{
		IssuerURL: idp.issuer(),
		Audience:  testAudience,
	}
	if mutate != nil {
		mutate(&cfg)
	}
	v, err := newVerifier(context.Background(), cfg, clock.Now)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return v
}

// --- claims ---

// validClaims is a claim set this issuer would really mint: every mandatory
// claim present, nothing extra.
func validClaims(issuer string, now time.Time) map[string]any {
	return map[string]any{
		claimIssuer:    issuer,
		claimAudience:  testAudience,
		claimSubject:   "01920000-0000-7000-8000-000000000001",
		claimSessionID: "01920000-0000-7000-8000-000000000002",
		claimTokenID:   "01920000-0000-7000-8000-000000000003",
		claimClientID:  "test-client",
		claimAMR:       []any{"otp"},
		claimExpiry:    now.Add(10 * time.Minute).Unix(),
		claimIssuedAt:  now.Unix(),
		claimNotBefore: now.Unix(),
		claimVersion:   1,
		claimGrants:    []any{},
	}
}

// grantClaim builds one hayrat_grants entry. ids are passed through as given so
// a test can hand in a json.Number with an exotic literal.
func grantClaim(role string, scopes ...map[string]any) map[string]any {
	entries := make([]any, 0, len(scopes))
	for _, s := range scopes {
		entries = append(entries, s)
	}
	return map[string]any{grantClaimRole: role, grantClaimScopes: entries}
}

func scopeClaim(scopeType string, id any) map[string]any {
	return map[string]any{scopeClaimType: scopeType, scopeClaimID: id}
}

// --- misc helpers ---

// onCurveP256 re-derives whether a parsed key is a valid P-256 point, without
// reusing the production code path that produced it.
func onCurveP256(k *ecdsa.PublicKey) bool {
	if k == nil || k.Curve != elliptic.P256() || k.X == nil || k.Y == nil {
		return false
	}
	if k.X.Sign() < 0 || k.Y.Sign() < 0 || k.X.BitLen() > 256 || k.Y.BitLen() > 256 {
		return false
	}
	point := make([]byte, 1+2*coordinateBytes)
	point[0] = 4
	k.X.FillBytes(point[1 : 1+coordinateBytes])
	k.Y.FillBytes(point[1+coordinateBytes:])
	_, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), point)
	return err == nil
}
