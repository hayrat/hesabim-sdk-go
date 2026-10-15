package hesabim

import (
	"bytes"
	"context"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestNew_RejectsIncompleteConfig(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		cfg  Config
	}{
		{"no issuer", Config{Audience: testAudience}},
		{"no audience", Config{IssuerURL: "https://issuer.example"}},
		{"negative skew", Config{IssuerURL: "https://issuer.example", Audience: testAudience, ClockSkew: -time.Second}},
		{"issuer is not https", Config{IssuerURL: "http://issuer.example", Audience: testAudience}},
		{"issuer is not absolute", Config{IssuerURL: "/issuer", Audience: testAudience}},
		{"issuer uses another scheme", Config{IssuerURL: "ftp://issuer.example", Audience: testAudience}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			// No server involved: every one of these must fail before a single
			// byte leaves the process.
			if _, err := New(context.Background(), c.cfg); err == nil {
				t.Fatal("want an error, got nil")
			}
		})
	}
}

func TestNew_LoopbackIssuerMayUseHTTP(t *testing.T) {
	t.Parallel()

	// httptest serves plain http on 127.0.0.1; if the loopback exemption were
	// missing, no test in this package could construct a Verifier at all.
	idp := newFakeIdP(t, newSigningKey(t, testKeyID))
	if !strings.HasPrefix(idp.issuer(), "http://127.0.0.1:") {
		t.Fatalf("test assumes a loopback http issuer, got %q", idp.issuer())
	}
	newTestVerifier(t, idp, newTestClock(), nil)
}

func TestNew_DiscoveryIssuerMustMatchConfiguredIssuer(t *testing.T) {
	t.Parallel()

	idp := newFakeIdP(t, newSigningKey(t, testKeyID))
	idp.setDiscovery(t, map[string]any{
		"issuer":   "https://someone-else.example",
		"jwks_uri": idp.issuer() + "/jwks",
	})

	_, err := New(context.Background(), Config{IssuerURL: idp.issuer(), Audience: testAudience})
	if err == nil {
		t.Fatal("want an error when the document claims a different issuer")
	}
	if idp.jwksFetchCount() != 0 {
		t.Errorf("the JWKS must not be fetched from an issuer that failed the binding check; %d fetches", idp.jwksFetchCount())
	}
}

func TestNew_IssuerTrailingSlashIsNormalisedOnBothSides(t *testing.T) {
	t.Parallel()

	idp := newFakeIdP(t, newSigningKey(t, testKeyID))
	idp.setDiscovery(t, map[string]any{
		// Document says "…/", config says "…" — the one difference that is not
		// a difference.
		"issuer":   idp.issuer() + "/",
		"jwks_uri": idp.issuer() + "/jwks",
	})

	if _, err := New(context.Background(), Config{IssuerURL: idp.issuer() + "/", Audience: testAudience}); err != nil {
		t.Fatalf("trailing slashes must normalise away: %v", err)
	}
}

func TestNew_DiscoveryTransportRules(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		setup func(t *testing.T, idp *fakeIdP)
	}{
		{
			name: "non-2xx status",
			setup: func(_ *testing.T, idp *fakeIdP) {
				idp.setDiscoveryStatus(http.StatusInternalServerError)
			},
		},
		{
			name: "redirect is not followed",
			setup: func(_ *testing.T, idp *fakeIdP) {
				// /elsewhere serves a VALID document, so this test fails if the
				// client ever starts following the redirect.
				idp.setRedirectDiscovery(true)
			},
		},
		{
			name: "body is not JSON",
			setup: func(_ *testing.T, idp *fakeIdP) {
				idp.setDiscoveryBody([]byte("not json at all"))
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			idp := newFakeIdP(t, newSigningKey(t, testKeyID))
			c.setup(t, idp)

			if _, err := New(context.Background(), Config{IssuerURL: idp.issuer(), Audience: testAudience}); err == nil {
				t.Fatal("want an error, got nil")
			}
		})
	}
}

// TestFetchDiscovery_DocumentRules exercises the rules about the document's
// CONTENT directly, rather than through New.
//
// Through New every one of these would also fail for an uninteresting second
// reason — a jwks_uri that is empty, relative or on a host that does not exist
// cannot be fetched either — and a test that cannot tell "refused by the rule"
// from "the fetch failed anyway" is not testing the rule.
func TestFetchDiscovery_DocumentRules(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		doc     func(issuer string) map[string]any
		wantErr bool
	}{
		{
			name: "the minimum a resource server needs",
			doc: func(issuer string) map[string]any {
				return map[string]any{"issuer": issuer, "jwks_uri": issuer + "/jwks"}
			},
		},
		{
			name: "every endpoint present",
			doc: func(issuer string) map[string]any {
				return map[string]any{
					"issuer":                 issuer,
					"jwks_uri":               issuer + "/jwks",
					"authorization_endpoint": issuer + "/authorize",
					"token_endpoint":         issuer + "/token",
					"end_session_endpoint":   issuer + "/logout",
				}
			},
		},
		{
			name:    "no jwks_uri",
			doc:     func(issuer string) map[string]any { return map[string]any{"issuer": issuer} },
			wantErr: true,
		},
		{
			name: "jwks_uri is relative",
			doc: func(issuer string) map[string]any {
				return map[string]any{"issuer": issuer, "jwks_uri": "/jwks"}
			},
			wantErr: true,
		},
		{
			name: "jwks_uri is plaintext on a remote host",
			doc: func(issuer string) map[string]any {
				// The loopback exemption is for a LOCAL issuer serving LOCAL
				// endpoints. Pointing key material at a remote plaintext host is
				// a key-substitution channel, not a development convenience.
				return map[string]any{"issuer": issuer, "jwks_uri": "http://keys.example/jwks"}
			},
			wantErr: true,
		},
		{
			name: "an advertised endpoint is plaintext on a remote host",
			doc: func(issuer string) map[string]any {
				return map[string]any{
					"issuer":         issuer,
					"jwks_uri":       issuer + "/jwks",
					"token_endpoint": "http://tokens.example/token",
				}
			},
			wantErr: true,
		},
		{
			name: "the document belongs to another issuer",
			doc: func(issuer string) map[string]any {
				return map[string]any{"issuer": "https://elsewhere.example", "jwks_uri": issuer + "/jwks"}
			},
			wantErr: true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			idp := newFakeIdP(t, newSigningKey(t, testKeyID))
			idp.setDiscovery(t, c.doc(idp.issuer()))

			doc, err := fetchDiscovery(context.Background(), Config{}.httpClient(), idp.issuer())
			if c.wantErr {
				if err == nil {
					t.Fatalf("want an error, got document %+v", doc)
				}
				return
			}
			if err != nil {
				t.Fatalf("want acceptance, got %v", err)
			}
			if doc.JWKSURI != idp.issuer()+"/jwks" {
				t.Errorf("jwks_uri = %q, want %q", doc.JWKSURI, idp.issuer()+"/jwks")
			}
		})
	}
}

// TestFetchBody_SizeCap pins BOTH halves of the 1 MiB rule: the reader stops at
// the cap, and a body that reaches past it is an error rather than a silently
// truncated document.
func TestFetchBody_SizeCap(t *testing.T) {
	t.Parallel()

	idp := newFakeIdP(t, newSigningKey(t, testKeyID))
	client := Config{}.httpClient()

	t.Run("exactly at the cap", func(t *testing.T) {
		idp.setJWKSBody(bytes.Repeat([]byte("x"), maxBodyBytes))
		body, err := fetchBody(context.Background(), client, idp.issuer()+"/jwks")
		if err != nil {
			t.Fatalf("a body exactly at the cap must be read: %v", err)
		}
		if len(body) != maxBodyBytes {
			t.Errorf("read %d bytes, want %d", len(body), maxBodyBytes)
		}
	})

	t.Run("one byte over the cap", func(t *testing.T) {
		idp.setJWKSBody(bytes.Repeat([]byte("x"), maxBodyBytes+1))
		if _, err := fetchBody(context.Background(), client, idp.issuer()+"/jwks"); err == nil {
			t.Fatal("a body over the cap must be an error, never a truncated read")
		}
	})
}

func TestNew_OptionalEndpointsMayBeAbsent(t *testing.T) {
	t.Parallel()

	// A resource server calls none of them. Refusing to boot over a field it
	// will never read would turn an issuer configuration change into an outage.
	idp := newFakeIdP(t, newSigningKey(t, testKeyID))
	idp.setDiscovery(t, map[string]any{
		"issuer":   idp.issuer(),
		"jwks_uri": idp.issuer() + "/jwks",
	})

	if _, err := New(context.Background(), Config{IssuerURL: idp.issuer(), Audience: testAudience}); err != nil {
		t.Fatalf("jwks_uri alone must be enough for a resource server: %v", err)
	}
}

func TestNew_FailsFastWhenTheJWKSCannotBeLoaded(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		setup func(idp *fakeIdP)
	}{
		{"jwks endpoint errors", func(idp *fakeIdP) { idp.setJWKSStatus(http.StatusBadGateway) }},
		{"jwks is not JSON", func(idp *fakeIdP) { idp.setJWKSBody([]byte("<html>")) }},
		{"jwks has no usable key", func(idp *fakeIdP) { idp.setJWKSBody([]byte(`{"keys":[]}`)) }},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			idp := newFakeIdP(t, newSigningKey(t, testKeyID))
			c.setup(idp)

			// The whole point of the eager fetch: a resource server that cannot
			// verify anything must not start and look healthy.
			if _, err := New(context.Background(), Config{IssuerURL: idp.issuer(), Audience: testAudience}); err == nil {
				t.Fatal("New must fail when the signing keys cannot be loaded")
			}
		})
	}
}

func TestNew_ReadsDiscoveryExactlyOnce(t *testing.T) {
	t.Parallel()

	clock := newTestClock()
	idp := newFakeIdP(t, newSigningKey(t, testKeyID))
	v := newTestVerifier(t, idp, clock, nil)

	if got := idp.discoveryFetchCount(); got != 1 {
		t.Fatalf("discovery fetched %d times during New, want 1", got)
	}

	// Force a JWKS refresh and check discovery is not re-read: the endpoints are
	// fixed for the life of the process.
	clock.advance(jwksMinRefreshInterval + time.Second)
	if err := v.keys.refreshNow(context.Background()); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if got := idp.discoveryFetchCount(); got != 1 {
		t.Errorf("discovery fetched %d times, want 1 — it must not be re-read on refresh", got)
	}
	if got := idp.jwksFetchCount(); got != 2 {
		t.Errorf("jwks fetched %d times, want 2 (boot + refresh)", got)
	}
}

func TestCheckAbsoluteURL(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name       string
		raw        string
		insecureOK bool
		wantOK     bool
	}{
		{"https anywhere", "https://issuer.example/jwks", false, true},
		{"http remote is refused even in local mode", "http://issuer.example/jwks", true, false},
		{"http localhost in local mode", "http://localhost:8080/jwks", true, true},
		{"http 127.0.0.1 in local mode", "http://127.0.0.1:8080/jwks", true, true},
		{"http localhost outside local mode", "http://localhost:8080/jwks", false, false},
		{"ipv6 loopback is not exempted", "http://[::1]:8080/jwks", true, false},
		{"relative", "/jwks", true, false},
		{"scheme without host", "https:///jwks", true, false},
		{"other scheme", "file:///etc/passwd", true, false},
		{"empty", "", true, false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			err := checkAbsoluteURL(c.raw, c.insecureOK)
			if (err == nil) != c.wantOK {
				t.Errorf("checkAbsoluteURL(%q, %v) error = %v, want ok=%v", c.raw, c.insecureOK, err, c.wantOK)
			}
		})
	}
}

func TestFetchBody_RespectsContextCancellation(t *testing.T) {
	t.Parallel()

	idp := newFakeIdP(t, newSigningKey(t, testKeyID))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := fetchBody(ctx, Config{}.httpClient(), idp.issuer()+"/jwks"); err == nil {
		t.Fatal("want an error for a cancelled context")
	}
}
