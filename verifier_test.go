package hesabim

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestVerify_HappyPath(t *testing.T) {
	t.Parallel()

	clock := newTestClock()
	key := newSigningKey(t, testKeyID)
	idp := newFakeIdP(t, key)
	v := newTestVerifier(t, idp, clock, nil)

	claims := validClaims(idp.issuer(), clock.Now())
	claims[claimAMR] = []any{"otp", "pwd"}
	claims[claimGrants] = []any{
		grantClaim("moderator", scopeClaim(ScopeTypeProvince, 6)),
		grantClaim("viewer"),
	}

	principal, err := v.Verify(context.Background(), key.sign(t, claims))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}

	// Each assertion pins a DIFFERENT claim to a different field: a mapping that
	// crossed sub with sid, or dropped amr, fails here.
	if principal.Subject != claims[claimSubject] {
		t.Errorf("Subject = %q, want the sub claim %q", principal.Subject, claims[claimSubject])
	}
	if principal.SessionID != claims[claimSessionID] {
		t.Errorf("SessionID = %q, want the sid claim %q", principal.SessionID, claims[claimSessionID])
	}
	if principal.ClientID != claims[claimClientID] {
		t.Errorf("ClientID = %q, want the client_id claim %q", principal.ClientID, claims[claimClientID])
	}
	if len(principal.AMR) != 2 || principal.AMR[0] != "otp" || principal.AMR[1] != "pwd" {
		t.Errorf("AMR = %v, want [otp pwd] in order", principal.AMR)
	}
	if len(principal.Grants) != 2 {
		t.Fatalf("Grants = %v, want two entries", principal.Grants)
	}
	if principal.Grants[0].Role != "moderator" ||
		len(principal.Grants[0].Scopes) != 1 ||
		principal.Grants[0].Scopes[0] != (Scope{Type: ScopeTypeProvince, ID: 6}) {
		t.Errorf("first grant = %+v, want moderator over province 6", principal.Grants[0])
	}
	if principal.Grants[1].Role != "viewer" || len(principal.Grants[1].Scopes) != 0 {
		t.Errorf("second grant = %+v, want a project-wide viewer", principal.Grants[1])
	}
}

func TestVerify_AlgorithmMatrix(t *testing.T) {
	t.Parallel()

	clock := newTestClock()
	key := newSigningKey(t, testKeyID)
	idp := newFakeIdP(t, key)
	v := newTestVerifier(t, idp, clock, nil)
	claims := validClaims(idp.issuer(), clock.Now())

	// The strongest form of the confusion attack: the public key's own bytes as
	// the HMAC secret, under the kid the issuer really published.
	publicBytes, err := key.key.PublicKey.Bytes()
	if err != nil {
		t.Fatalf("encode public key: %v", err)
	}

	cases := []struct {
		name  string
		token string
	}{
		{"HS256 with the public key as secret", signHS256(t, testKeyID, publicBytes, claims)},
		{"HS256 with an arbitrary secret", signHS256(t, testKeyID, []byte("secret"), claims)},
		{"alg none", signNone(t, testKeyID, claims)},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			if _, err := v.Verify(context.Background(), c.token); !errors.Is(err, errBadSignature) {
				t.Fatalf("want errBadSignature, got %v", err)
			}
		})
	}
}

func TestVerify_AlgorithmIsCheckedBeforeAnyKeyLookup(t *testing.T) {
	t.Parallel()

	clock := newTestClock()
	key := newSigningKey(t, testKeyID)
	idp := newFakeIdP(t, key)
	v := newTestVerifier(t, idp, clock, nil)

	// Past the refresh floor, so an unknown kid WOULD normally cost a JWKS
	// fetch. If the algorithm check ran after key resolution, an attacker could
	// drive JWKS traffic with unsigned tokens.
	clock.advance(jwksMinRefreshInterval + time.Second)
	before := idp.jwksFetchCount()

	token := signNone(t, "kid-nobody-published", validClaims(idp.issuer(), clock.Now()))
	if _, err := v.Verify(context.Background(), token); err == nil {
		t.Fatal("want a rejection")
	}
	if got := idp.jwksFetchCount(); got != before {
		t.Errorf("JWKS fetched %d times, want %d — the alg check must precede key resolution", got, before)
	}
}

func TestVerify_MalformedTokens(t *testing.T) {
	t.Parallel()

	clock := newTestClock()
	idp := newFakeIdP(t, newSigningKey(t, testKeyID))
	v := newTestVerifier(t, idp, clock, nil)

	for _, raw := range []string{"", "not-a-token", "a.b", "a.b.c.d", "!!!.###.$$$"} {
		if _, err := v.Verify(context.Background(), raw); !errors.Is(err, errUnauthenticated) {
			t.Errorf("Verify(%q) = %v, want a rejection", raw, err)
		}
	}
}

func TestVerify_KeySelection(t *testing.T) {
	t.Parallel()

	clock := newTestClock()
	key := newSigningKey(t, testKeyID)
	idp := newFakeIdP(t, key)
	v := newTestVerifier(t, idp, clock, nil)
	claims := validClaims(idp.issuer(), clock.Now())

	t.Run("no kid in the header", func(t *testing.T) {
		token := signingKey{kid: "", key: key.key}.sign(t, claims)
		if _, err := v.Verify(context.Background(), token); !errors.Is(err, errMissingKeyID) {
			t.Fatalf("want errMissingKeyID, got %v", err)
		}
	})

	t.Run("signed by another key under a published kid", func(t *testing.T) {
		impostor := signingKey{kid: testKeyID, key: newSigningKey(t, "other").key}
		if _, err := v.Verify(context.Background(), impostor.sign(t, claims)); !errors.Is(err, errBadSignature) {
			t.Fatalf("want errBadSignature, got %v", err)
		}
	})
}

func TestVerify_UnknownKidRefreshesAndThenSucceeds(t *testing.T) {
	t.Parallel()

	clock := newTestClock()
	first := newSigningKey(t, "key-1")
	idp := newFakeIdP(t, first)
	v := newTestVerifier(t, idp, clock, nil)

	// The issuer rotates. The new key is published, the old one stays for the
	// overlap window.
	second := newSigningKey(t, "key-2")
	idp.setKeys(t, first, second)
	clock.advance(jwksMinRefreshInterval)

	token := second.sign(t, validClaims(idp.issuer(), clock.Now()))
	if _, err := v.Verify(context.Background(), token); err != nil {
		t.Fatalf("a token signed with a newly published key must verify: %v", err)
	}
	if got := idp.jwksFetchCount(); got != 2 {
		t.Errorf("JWKS fetched %d times, want 2 (boot + unknown-kid refresh)", got)
	}

	// The retired key still verifies while it is published.
	if _, err := v.Verify(context.Background(), first.sign(t, validClaims(idp.issuer(), clock.Now()))); err != nil {
		t.Errorf("the overlapping key must still verify: %v", err)
	}
}

func TestVerify_UnknownKidInsideTheRefreshFloorIsRejectedWithoutAFetch(t *testing.T) {
	t.Parallel()

	clock := newTestClock()
	first := newSigningKey(t, "key-1")
	idp := newFakeIdP(t, first)
	v := newTestVerifier(t, idp, clock, nil)

	second := newSigningKey(t, "key-2")
	idp.setKeys(t, first, second)

	token := second.sign(t, validClaims(idp.issuer(), clock.Now()))
	if _, err := v.Verify(context.Background(), token); !errors.Is(err, errKeysThrottled) {
		t.Fatalf("want errKeysThrottled inside the floor, got %v", err)
	}
	if got := idp.jwksFetchCount(); got != 1 {
		t.Errorf("JWKS fetched %d times, want 1 — the floor must suppress the refresh", got)
	}
}

func TestVerify_IssuerAndAudience(t *testing.T) {
	t.Parallel()

	clock := newTestClock()
	key := newSigningKey(t, testKeyID)
	idp := newFakeIdP(t, key)
	v := newTestVerifier(t, idp, clock, nil)

	cases := []struct {
		name  string
		claim string
		value any
		want  error
	}{
		{"another issuer", claimIssuer, "https://elsewhere.example", errIssuer},
		{"issuer with a path suffix", claimIssuer, idp.issuer() + "/extra", errIssuer},
		{"issuer missing", claimIssuer, nil, errIssuer},
		{"issuer is not a string", claimIssuer, 1, errIssuer},

		{"another audience", claimAudience, "api:other-project", errAudience},
		{"audience missing", claimAudience, nil, errAudience},
		{"audience as a single-element array", claimAudience, []any{testAudience}, nil},
		{"audience as a two-element array containing ours", claimAudience, []any{testAudience, "api:other"}, errAudience},
		{"audience as a two-element array without ours", claimAudience, []any{"api:a", "api:b"}, errAudience},
		{"audience as an empty array", claimAudience, []any{}, errAudience},
		{"audience as an array of non-strings", claimAudience, []any{1}, errAudience},
		{"audience is a number", claimAudience, 1, errAudience},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			claims := validClaims(idp.issuer(), clock.Now())
			if c.value == nil {
				delete(claims, c.claim)
			} else {
				claims[c.claim] = c.value
			}

			_, err := v.Verify(context.Background(), key.sign(t, claims))
			if c.want == nil {
				if err != nil {
					t.Fatalf("want acceptance, got %v", err)
				}
				return
			}
			if !errors.Is(err, c.want) {
				t.Fatalf("want %v, got %v", c.want, err)
			}
		})
	}
}

func TestVerify_IssuerIsComparedToTheDiscoveryDocumentByteForByte(t *testing.T) {
	t.Parallel()

	// The reference value is the DOCUMENT's issuer, not the configured one.
	// Config.IssuerURL is normalised (one trailing slash) purely to bind the
	// configuration to a document; after that the issuer's own string is what a
	// token must carry.
	t.Run("document without a trailing slash", func(t *testing.T) {
		t.Parallel()
		clock := newTestClock()
		key := newSigningKey(t, testKeyID)
		idp := newFakeIdP(t, key)
		v := newTestVerifier(t, idp, clock, nil)

		if _, err := v.Verify(context.Background(), key.sign(t, validClaims(idp.issuer(), clock.Now()))); err != nil {
			t.Fatalf("the document's exact issuer must verify: %v", err)
		}
		// No normalisation: a trailing slash the issuer never emitted is a
		// different issuer.
		if _, err := v.Verify(context.Background(), key.sign(t, validClaims(idp.issuer()+"/", clock.Now()))); !errors.Is(err, errIssuer) {
			t.Fatalf("want errIssuer for a trailing slash the document does not have, got %v", err)
		}
	})

	t.Run("document WITH a trailing slash", func(t *testing.T) {
		t.Parallel()
		clock := newTestClock()
		key := newSigningKey(t, testKeyID)
		idp := newFakeIdP(t, key)
		// The document names itself with a trailing slash while the config does
		// not — a binding the normalisation still allows. The token must then
		// carry the DOCUMENT's form.
		idp.setDiscovery(t, map[string]any{
			"issuer":   idp.issuer() + "/",
			"jwks_uri": idp.issuer() + "/jwks",
		})
		v := newTestVerifier(t, idp, clock, nil)

		if _, err := v.Verify(context.Background(), key.sign(t, validClaims(idp.issuer()+"/", clock.Now()))); err != nil {
			t.Fatalf("the document's exact issuer must verify: %v", err)
		}
		if _, err := v.Verify(context.Background(), key.sign(t, validClaims(idp.issuer(), clock.Now()))); !errors.Is(err, errIssuer) {
			t.Fatalf("want errIssuer: the document says the issuer ends in a slash, got %v", err)
		}
	})
}

func TestVerify_MandatoryClaimMatrix(t *testing.T) {
	t.Parallel()

	clock := newTestClock()
	key := newSigningKey(t, testKeyID)
	idp := newFakeIdP(t, key)
	v := newTestVerifier(t, idp, clock, nil)

	// This issuer stamps every one of these on every access token, so a missing
	// one is not an older token — it is not a token from this issuer.
	missing := map[string]error{
		claimExpiry:    errExpired,
		claimIssuedAt:  errIssuedInFuture,
		claimNotBefore: errNotYetValid,
		claimTokenID:   errTokenID,
		claimClientID:  errClientID,
		claimSubject:   errSubject,
		claimSessionID: errSessionID,
		claimAMR:       errAMR,
		claimVersion:   errClaimVersion,
		claimGrants:    errGrants,
	}

	for claim, want := range missing {
		t.Run("missing "+claim, func(t *testing.T) {
			t.Parallel()
			claims := validClaims(idp.issuer(), clock.Now())
			delete(claims, claim)
			if _, err := v.Verify(context.Background(), key.sign(t, claims)); !errors.Is(err, want) {
				t.Fatalf("dropping %q gave %v, want %v", claim, err, want)
			}
		})
	}

	wrongType := []struct {
		name  string
		claim string
		value any
		want  error
	}{
		{"exp as a string", claimExpiry, "9999999999", errExpired},
		{"iat as a string", claimIssuedAt, "1", errIssuedInFuture},
		{"nbf as a bool", claimNotBefore, true, errNotYetValid},
		{"jti empty", claimTokenID, "", errTokenID},
		{"jti as a number", claimTokenID, 1, errTokenID},
		{"client_id empty", claimClientID, "", errClientID},
		{"sub empty", claimSubject, "", errSubject},
		{"sub as a number", claimSubject, 42, errSubject},
		{"sid empty", claimSessionID, "", errSessionID},
		{"amr as a string", claimAMR, "otp", errAMR},
		{"amr empty", claimAMR, []any{}, errAMR},
		{"amr with a non-string element", claimAMR, []any{"otp", 1}, errAMR},
		{"amr with an empty element", claimAMR, []any{""}, errAMR},
		{"amr null", claimAMR, nil, errAMR},
	}

	for _, c := range wrongType {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			claims := validClaims(idp.issuer(), clock.Now())
			claims[c.claim] = c.value
			if _, err := v.Verify(context.Background(), key.sign(t, claims)); !errors.Is(err, c.want) {
				t.Fatalf("want %v, got %v", c.want, err)
			}
		})
	}
}

// A service (client_credentials) token is never addressed to a project API, and
// this verifier refuses the principal marker positively even when every other
// claim is in order — here a token addressed to the project's own audience that
// carries the marker and, pessimistically, a session as well.
//
// MUTATION: delete the claimPrincipal check in verifyClaims and the marked rows
// are accepted as people.
func TestVerify_RefusesAServiceTokenOnAProjectAudience(t *testing.T) {
	t.Parallel()

	clock := newTestClock()
	key := newSigningKey(t, testKeyID)
	idp := newFakeIdP(t, key)
	v := newTestVerifier(t, idp, clock, nil)

	// The control: the same claims without the marker verify, so the refusals
	// below are the marker's doing.
	if _, err := v.Verify(context.Background(), key.sign(t, validClaims(idp.issuer(), clock.Now()))); err != nil {
		t.Fatalf("control: an ordinary user token was refused: %v", err)
	}

	cases := map[string]func(map[string]any){
		"service shape (no sid, no amr)": func(c map[string]any) {
			c[claimPrincipal] = "client"
			delete(c, claimSessionID)
			delete(c, claimAMR)
		},
		"marker on an otherwise complete user token": func(c map[string]any) { c[claimPrincipal] = "client" },
		"marker with another value":                  func(c map[string]any) { c[claimPrincipal] = "user" },
		"marker null":                                func(c map[string]any) { c[claimPrincipal] = nil },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			claims := validClaims(idp.issuer(), clock.Now())
			mutate(claims)
			if _, err := v.Verify(context.Background(), key.sign(t, claims)); !errors.Is(err, errServicePrincipal) {
				t.Fatalf("want errServicePrincipal, got %v", err)
			}
		})
	}
}

func TestVerify_ClockSkewBoundaries(t *testing.T) {
	t.Parallel()

	clock := newTestClock()
	key := newSigningKey(t, testKeyID)
	idp := newFakeIdP(t, key)
	v := newTestVerifier(t, idp, clock, nil)
	now := clock.Now()

	cases := []struct {
		name    string
		claim   string
		offset  time.Duration
		want    error
		wantErr bool
	}{
		{name: "exp one second inside the leeway", claim: claimExpiry, offset: -(defaultClockSkew - time.Second)},
		{name: "exp exactly at the leeway", claim: claimExpiry, offset: -defaultClockSkew, want: errExpired, wantErr: true},
		{name: "exp one second past the leeway", claim: claimExpiry, offset: -(defaultClockSkew + time.Second), want: errExpired, wantErr: true},

		{name: "iat one second inside the leeway", claim: claimIssuedAt, offset: defaultClockSkew - time.Second},
		{name: "iat one second past the leeway", claim: claimIssuedAt, offset: defaultClockSkew + time.Second, want: errIssuedInFuture, wantErr: true},

		{name: "nbf one second inside the leeway", claim: claimNotBefore, offset: defaultClockSkew - time.Second},
		{name: "nbf one second past the leeway", claim: claimNotBefore, offset: defaultClockSkew + time.Second, want: errNotYetValid, wantErr: true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			claims := validClaims(idp.issuer(), now)
			claims[c.claim] = now.Add(c.offset).Unix()

			_, err := v.Verify(context.Background(), key.sign(t, claims))
			if c.wantErr {
				if !errors.Is(err, c.want) {
					t.Fatalf("want %v, got %v", c.want, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("want acceptance inside the leeway, got %v", err)
			}
		})
	}
}

func TestVerify_ConfiguredClockSkewIsHonoured(t *testing.T) {
	t.Parallel()

	clock := newTestClock()
	key := newSigningKey(t, testKeyID)
	idp := newFakeIdP(t, key)
	v := newTestVerifier(t, idp, clock, func(cfg *Config) { cfg.ClockSkew = 5 * time.Minute })

	now := clock.Now()
	claims := validClaims(idp.issuer(), now)
	claims[claimExpiry] = now.Add(-4 * time.Minute).Unix()

	if _, err := v.Verify(context.Background(), key.sign(t, claims)); err != nil {
		t.Fatalf("a 5 minute leeway must accept a token that expired 4 minutes ago: %v", err)
	}
}

func TestVerify_ClaimContractVersion(t *testing.T) {
	t.Parallel()

	clock := newTestClock()
	key := newSigningKey(t, testKeyID)
	idp := newFakeIdP(t, key)
	v := newTestVerifier(t, idp, clock, nil)

	cases := []struct {
		name  string
		value any
		ok    bool
	}{
		{"version 1", 1, true},
		{"version 2", 2, false},
		{"version 0", 0, false},
		{"version as a string", "1", false},
		{"version as a float", json.Number("1.0"), false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			claims := validClaims(idp.issuer(), clock.Now())
			claims[claimVersion] = c.value

			_, err := v.Verify(context.Background(), key.sign(t, claims))
			if c.ok && err != nil {
				t.Fatalf("want acceptance, got %v", err)
			}
			if !c.ok && !errors.Is(err, errClaimVersion) {
				t.Fatalf("want errClaimVersion, got %v", err)
			}
		})
	}
}

func TestVerify_GrantShapeMatrix(t *testing.T) {
	t.Parallel()

	clock := newTestClock()
	key := newSigningKey(t, testKeyID)
	idp := newFakeIdP(t, key)
	v := newTestVerifier(t, idp, clock, nil)

	cases := []struct {
		name   string
		grants any
		want   error
	}{
		{"empty list", []any{}, nil},
		{"project-wide grant", []any{grantClaim("viewer")}, nil},
		{"scoped grant", []any{grantClaim("moderator", scopeClaim(ScopeTypeProvince, 6))}, nil},
		{"unknown scope type is carried through", []any{grantClaim("moderator", scopeClaim("planet", 6))}, nil},

		{"null", nil, errGrants},
		{"not a list", "moderator", errGrants},
		{"entry is not an object", []any{"moderator"}, errGrants},
		{"entry without a role", []any{map[string]any{grantClaimScopes: []any{}}}, errGrants},
		{"entry with an empty role", []any{grantClaim("")}, errGrants},
		{"entry with a non-string role", []any{map[string]any{grantClaimRole: 1, grantClaimScopes: []any{}}}, errGrants},
		{"entry without scopes", []any{map[string]any{grantClaimRole: "viewer"}}, errGrants},
		{"entry with null scopes", []any{map[string]any{grantClaimRole: "viewer", grantClaimScopes: nil}}, errGrants},
		{"entry with non-list scopes", []any{map[string]any{grantClaimRole: "viewer", grantClaimScopes: "all"}}, errGrants},
		{"scope is not an object", []any{map[string]any{grantClaimRole: "v", grantClaimScopes: []any{"province:6"}}}, errGrants},
		{"scope without a type", []any{grantClaim("v", map[string]any{scopeClaimID: 6})}, errGrants},
		{"scope with an empty type", []any{grantClaim("v", scopeClaim("", 6))}, errGrants},
		{"scope without an id", []any{grantClaim("v", map[string]any{scopeClaimType: ScopeTypeProvince})}, errGrants},
		{"scope with a string id", []any{grantClaim("v", scopeClaim(ScopeTypeProvince, "6"))}, errGrants},
		{"scope with a null id", []any{grantClaim("v", scopeClaim(ScopeTypeProvince, nil))}, errGrants},

		{"the same role twice", []any{grantClaim("viewer"), grantClaim("viewer", scopeClaim(ScopeTypeProvince, 6))}, errDuplicateRole},
		{"the same role twice, identically", []any{grantClaim("viewer"), grantClaim("viewer")}, errDuplicateRole},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			claims := validClaims(idp.issuer(), clock.Now())
			claims[claimGrants] = c.grants

			_, err := v.Verify(context.Background(), key.sign(t, claims))
			if c.want == nil {
				if err != nil {
					t.Fatalf("want acceptance, got %v", err)
				}
				return
			}
			if !errors.Is(err, c.want) {
				t.Fatalf("want %v, got %v", c.want, err)
			}
		})
	}
}

func TestVerify_ScopeIDBoundaries(t *testing.T) {
	t.Parallel()

	clock := newTestClock()
	key := newSigningKey(t, testKeyID)
	idp := newFakeIdP(t, key)
	v := newTestVerifier(t, idp, clock, nil)

	// The fractional and exponent literals are the discriminating cases: a
	// float64 decoder would truncate "1.0" to 1 and "3.5" to 3 and accept both.
	// Only a decoder that keeps the literal text can refuse them.
	cases := []struct {
		name   string
		id     any
		wantID int64
		ok     bool
	}{
		{name: "one", id: json.Number("1"), wantID: 1, ok: true},
		{name: "a typical refdata id", id: json.Number("34"), wantID: 34, ok: true},
		{name: "2^53-1", id: json.Number("9007199254740991"), wantID: maxSafeScopeID, ok: true},

		{name: "zero", id: json.Number("0")},
		{name: "minus one", id: json.Number("-1")},
		{name: "fractional", id: json.Number("3.5")},
		{name: "integral but written as a float", id: json.Number("1.0")},
		{name: "exponent notation", id: json.Number("1e2")},
		{name: "2^53", id: json.Number("9007199254740992")},
		{name: "2^53+1", id: json.Number("9007199254740993")},
		{name: "far beyond int64", id: json.Number("99999999999999999999999")},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			claims := validClaims(idp.issuer(), clock.Now())
			claims[claimGrants] = []any{grantClaim("moderator", scopeClaim(ScopeTypeDistrict, c.id))}

			principal, err := v.Verify(context.Background(), key.sign(t, claims))
			if !c.ok {
				if !errors.Is(err, errGrants) {
					t.Fatalf("scope id %v: want errGrants, got %v", c.id, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("scope id %v: want acceptance, got %v", c.id, err)
			}
			got := principal.Grants[0].Scopes[0].ID
			if got != c.wantID {
				t.Errorf("scope id parsed as %d, want %d — the value must survive the round trip exactly", got, c.wantID)
			}
		})
	}
}

func TestVerify_UnknownScopeTypePassesButNeverMatchesAKnownOne(t *testing.T) {
	t.Parallel()

	clock := newTestClock()
	key := newSigningKey(t, testKeyID)
	idp := newFakeIdP(t, key)
	v := newTestVerifier(t, idp, clock, nil)

	claims := validClaims(idp.issuer(), clock.Now())
	claims[claimGrants] = []any{grantClaim("moderator", scopeClaim("galaxy", 6))}

	// The token is NOT dropped: the issuer does not validate the type either, so
	// a resource server that refused unfamiliar types would lock out every user
	// granted a newly added one until it is redeployed.
	principal, err := v.Verify(context.Background(), key.sign(t, claims))
	if err != nil {
		t.Fatalf("an unfamiliar scope type must not drop the token: %v", err)
	}

	// It degrades to a check that never matches a target of a known type, which
	// denies rather than grants.
	if principal.Can("moderator", Scope{Type: ScopeTypeProvince, ID: 6}) {
		t.Error("an unfamiliar granted type must not satisfy a province target with the same id")
	}
	if principal.Can("moderator", Scope{Type: ScopeTypeDistrict, ID: 6}) {
		t.Error("an unfamiliar granted type must not satisfy a district target with the same id")
	}
	// Exact match stays type-agnostic on purpose: a caller that has been taught
	// the new type gets the right answer without an SDK release.
	if !principal.Can("moderator", Scope{Type: "galaxy", ID: 6}) {
		t.Error("exact match on the same unfamiliar type must still hold")
	}
}

func TestVerify_ErrorsCarryNoTokenOrClaimBytes(t *testing.T) {
	t.Parallel()

	clock := newTestClock()
	key := newSigningKey(t, testKeyID)
	idp := newFakeIdP(t, key)
	v := newTestVerifier(t, idp, clock, nil)

	const secretSubject = "sub-that-must-not-appear-in-a-log"
	const secretAudience = "api:audience-that-must-not-appear"

	build := func(mutateClaims func(map[string]any)) (string, map[string]any) {
		claims := validClaims(idp.issuer(), clock.Now())
		claims[claimSubject] = secretSubject
		mutateClaims(claims)
		return key.sign(t, claims), claims
	}

	cases := []struct {
		name    string
		mutate  func(map[string]any)
		needles []string
	}{
		{
			name:    "wrong audience",
			mutate:  func(c map[string]any) { c[claimAudience] = secretAudience },
			needles: []string{secretSubject, secretAudience},
		},
		{
			name:    "expired",
			mutate:  func(c map[string]any) { c[claimExpiry] = clock.Now().Add(-time.Hour).Unix() },
			needles: []string{secretSubject},
		},
		{
			name: "malformed grants",
			mutate: func(c map[string]any) {
				c[claimGrants] = []any{grantClaim("role-name-that-must-not-leak", scopeClaim("t", 0))}
			},
			needles: []string{secretSubject, "role-name-that-must-not-leak"},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			token, _ := build(c.mutate)

			_, err := v.Verify(context.Background(), token)
			if err == nil {
				t.Fatal("want a rejection")
			}
			message := err.Error()
			for _, needle := range c.needles {
				if strings.Contains(message, needle) {
					t.Errorf("error message leaked %q: %s", needle, message)
				}
			}
			// The token itself is a credential until it expires; not one segment
			// of it may appear.
			for _, segment := range strings.Split(token, ".") {
				if segment != "" && strings.Contains(message, segment) {
					t.Errorf("error message leaked a token segment: %s", message)
				}
			}
		})
	}
}

func TestVerify_HardTTLFailsClosed(t *testing.T) {
	t.Parallel()

	clock := newTestClock()
	key := newSigningKey(t, testKeyID)
	idp := newFakeIdP(t, key)
	v := newTestVerifier(t, idp, clock, nil)

	// The issuer becomes unreachable, and a day passes.
	idp.setJWKSStatus(503)
	clock.advance(jwksHardTTL)

	claims := validClaims(idp.issuer(), clock.Now())
	if _, err := v.Verify(context.Background(), key.sign(t, claims)); err == nil {
		t.Fatal("want a rejection once the cached keys are past the hard TTL")
	}

	// It recovers as soon as the issuer answers again.
	idp.setJWKSStatus(200)
	clock.advance(jwksMinRefreshInterval)
	if _, err := v.Verify(context.Background(), key.sign(t, validClaims(idp.issuer(), clock.Now()))); err != nil {
		t.Fatalf("verification must resume after a successful refresh: %v", err)
	}
}

func TestVerify_StaleWhileErrorKeepsVerifying(t *testing.T) {
	t.Parallel()

	clock := newTestClock()
	key := newSigningKey(t, testKeyID)
	idp := newFakeIdP(t, key)
	v := newTestVerifier(t, idp, clock, nil)

	idp.drainJWKSSignals()
	idp.setJWKSStatus(503)
	clock.advance(jwksSoftTTL + time.Minute)

	claims := validClaims(idp.issuer(), clock.Now())
	if _, err := v.Verify(context.Background(), key.sign(t, claims)); err != nil {
		t.Fatalf("an unreachable issuer must not invalidate tokens it already signed: %v", err)
	}

	// Prove the soft-TTL refresh really was attempted (and failed) rather than
	// the branch never being taken.
	idp.waitForJWKSFetch(t)
	if _, err := v.Verify(context.Background(), key.sign(t, claims)); err != nil {
		t.Fatalf("a failed background refresh must not drop the cached keys: %v", err)
	}
}

func TestVerify_IsSafeForConcurrentUse(t *testing.T) {
	t.Parallel()

	clock := newTestClock()
	key := newSigningKey(t, testKeyID)
	idp := newFakeIdP(t, key)
	v := newTestVerifier(t, idp, clock, nil)

	claims := validClaims(idp.issuer(), clock.Now())
	claims[claimGrants] = []any{grantClaim("moderator", scopeClaim(ScopeTypeProvince, 6))}
	token := key.sign(t, claims)

	// One verifier, many goroutines: this is the shape every resource server
	// runs in, and `go test -race` is the assertion.
	const callers = 32
	done := make(chan error, callers)
	for range callers {
		go func() {
			p, err := v.Verify(context.Background(), token)
			if err == nil && !p.Can("moderator", Scope{Type: ScopeTypeProvince, ID: 6}) {
				err = errors.New("Can returned false for a granted scope")
			}
			done <- err
		}()
	}
	for range callers {
		if err := <-done; err != nil {
			t.Errorf("concurrent Verify: %v", err)
		}
	}
}

// validClaimsAreReallyValid guards the fixture itself: every negative test above
// mutates one field of validClaims, so a fixture that was already broken would
// make all of them pass for the wrong reason.
func TestValidClaimsFixtureIsAccepted(t *testing.T) {
	t.Parallel()

	clock := newTestClock()
	key := newSigningKey(t, testKeyID)
	idp := newFakeIdP(t, key)
	v := newTestVerifier(t, idp, clock, nil)

	claims := maps.Clone(validClaims(idp.issuer(), clock.Now()))
	if _, err := v.Verify(context.Background(), key.sign(t, claims)); err != nil {
		t.Fatalf("the shared fixture must verify: %v", err)
	}
}

func TestVerify_NumericDateRange(t *testing.T) {
	t.Parallel()

	clock := newTestClock()
	key := newSigningKey(t, testKeyID)
	idp := newFakeIdP(t, key)
	v := newTestVerifier(t, idp, clock, nil)

	// A float64 that will not fit an int64 converts to an IMPLEMENTATION-DEFINED
	// value — the maximum on arm64, the minimum on amd64 — so a token carrying
	// one is read as a different date on different machines. The two that
	// matter: `"exp": 1e100` saturating upward is a token that never expires,
	// and a huge negative iat/nbf saturating downward sails through the checks
	// that exist to catch a date in the future.
	cases := []struct {
		name  string
		claim string
		value any
		want  error
	}{
		{"exp beyond the representable range", claimExpiry, json.Number("1e100"), errExpired},
		{"exp at the top of int64", claimExpiry, json.Number("9223372036854775807"), errExpired},
		{"exp one past int64", claimExpiry, json.Number("9223372036854775808"), errExpired},
		{"exp below the representable range", claimExpiry, json.Number("-1e100"), errExpired},

		{"iat beyond the representable range", claimIssuedAt, json.Number("1e100"), errIssuedInFuture},
		{"iat below the representable range", claimIssuedAt, json.Number("-1e100"), errIssuedInFuture},
		{"iat at the bottom of int64", claimIssuedAt, json.Number("-9223372036854775808"), errIssuedInFuture},
		{"iat one below int64", claimIssuedAt, json.Number("-9223372036854775809"), errIssuedInFuture},

		{"nbf beyond the representable range", claimNotBefore, json.Number("1e100"), errNotYetValid},
		{"nbf below the representable range", claimNotBefore, json.Number("-1e100"), errNotYetValid},
		{"nbf at the bottom of int64", claimNotBefore, json.Number("-9223372036854775808"), errNotYetValid},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			claims := validClaims(idp.issuer(), clock.Now())
			claims[c.claim] = c.value
			if _, err := v.Verify(context.Background(), key.sign(t, claims)); !errors.Is(err, c.want) {
				t.Fatalf("%s = %v: want %v, got %v", c.claim, c.value, c.want, err)
			}
		})
	}
}

func TestVerify_NumericDateRangeIsNotTooTight(t *testing.T) {
	t.Parallel()

	clock := newTestClock()
	key := newSigningKey(t, testKeyID)
	idp := newFakeIdP(t, key)
	v := newTestVerifier(t, idp, clock, nil)

	// The bound must exclude only what cannot be represented. A token whose
	// dates sit exactly on the edges of that range is still a token.
	claims := validClaims(idp.issuer(), clock.Now())
	claims[claimExpiry] = json.Number("253402300799") // 9999-12-31T23:59:59Z
	claims[claimIssuedAt] = json.Number("-62135596800")
	claims[claimNotBefore] = json.Number("-62135596800") // 0001-01-01T00:00:00Z

	if _, err := v.Verify(context.Background(), key.sign(t, claims)); err != nil {
		t.Fatalf("dates at the edge of the representable range must verify: %v", err)
	}

	// RFC 7519 permits a fractional NumericDate, and the float path must keep
	// working for it.
	fractional := validClaims(idp.issuer(), clock.Now())
	fractional[claimIssuedAt] = json.Number(strconv.FormatInt(clock.Now().Unix(), 10) + ".5")
	if _, err := v.Verify(context.Background(), key.sign(t, fractional)); err != nil {
		t.Fatalf("a fractional NumericDate must verify: %v", err)
	}
}

func TestVerify_TokenSizeCap(t *testing.T) {
	t.Parallel()

	clock := newTestClock()
	key := newSigningKey(t, testKeyID)
	idp := newFakeIdP(t, key)
	v := newTestVerifier(t, idp, clock, nil)

	t.Run("empty", func(t *testing.T) {
		t.Parallel()
		if _, err := v.Verify(context.Background(), ""); !errors.Is(err, errMalformedToken) {
			t.Fatalf("want errMalformedToken for an empty token, got %v", err)
		}
	})

	t.Run("exactly at the cap is not refused for size", func(t *testing.T) {
		t.Parallel()
		// The boundary is INCLUSIVE: 4096 bytes is the largest token the issuer
		// will mint, so it must reach the parser and be rejected on its merits.
		atCap := strings.Repeat("a", maxTokenBytes)
		if _, err := v.Verify(context.Background(), atCap); !errors.Is(err, errMalformedToken) {
			t.Fatalf("want errMalformedToken at exactly %d bytes, got %v", maxTokenBytes, err)
		}
	})

	t.Run("one byte over the cap", func(t *testing.T) {
		t.Parallel()
		overCap := strings.Repeat("a", maxTokenBytes+1)
		if _, err := v.Verify(context.Background(), overCap); !errors.Is(err, errTokenTooLarge) {
			t.Fatalf("want errTokenTooLarge at %d bytes, got %v", maxTokenBytes+1, err)
		}
	})

	t.Run("a genuinely signed token over the cap", func(t *testing.T) {
		t.Parallel()
		claims := validClaims(idp.issuer(), clock.Now())
		claims["padding"] = strings.Repeat("x", maxTokenBytes)
		token := key.sign(t, claims)
		if len(token) <= maxTokenBytes {
			t.Fatalf("fixture is %d bytes; the test needs one over %d", len(token), maxTokenBytes)
		}
		// Signature and claims are both perfect. Only the length refuses it,
		// because the issuer's own budget says it cannot have minted this.
		if _, err := v.Verify(context.Background(), token); !errors.Is(err, errTokenTooLarge) {
			t.Fatalf("want errTokenTooLarge, got %v", err)
		}
	})

	t.Run("a signed token just under the cap still verifies", func(t *testing.T) {
		t.Parallel()
		token, size := largestTokenUnderCap(t, key, validClaims(idp.issuer(), clock.Now()))
		if size > maxTokenBytes || size < maxTokenBytes-4 {
			t.Fatalf("fixture is %d bytes; wanted one within four bytes of the %d cap", size, maxTokenBytes)
		}
		if _, err := v.Verify(context.Background(), token); err != nil {
			t.Fatalf("a %d-byte token is inside the issuer's budget and must verify: %v", size, err)
		}
	})
}

func TestVerify_SizeIsCheckedBeforeAnyKeyLookup(t *testing.T) {
	t.Parallel()

	clock := newTestClock()
	key := newSigningKey(t, testKeyID)
	idp := newFakeIdP(t, key)
	v := newTestVerifier(t, idp, clock, nil)

	// Past the refresh floor, so an unknown kid WOULD normally cost a JWKS
	// fetch. An oversized token must not be able to buy one.
	clock.advance(jwksMinRefreshInterval + time.Second)
	before := idp.jwksFetchCount()

	claims := validClaims(idp.issuer(), clock.Now())
	claims["padding"] = strings.Repeat("x", maxTokenBytes)
	oversized := signingKey{kid: "kid-nobody-published", key: key.key}.sign(t, claims)

	if _, err := v.Verify(context.Background(), oversized); !errors.Is(err, errTokenTooLarge) {
		t.Fatalf("want errTokenTooLarge, got %v", err)
	}
	if got := idp.jwksFetchCount(); got != before {
		t.Errorf("JWKS fetched %d times, want %d — the size gate must precede key resolution", got, before)
	}
}

// largestTokenUnderCap signs the claim set with as much padding as the budget
// allows, so the boundary is exercised from below by a REAL token.
func largestTokenUnderCap(t *testing.T, key signingKey, claims map[string]any) (string, int) {
	t.Helper()

	sign := func(padding int) string {
		c := make(map[string]any, len(claims)+1)
		maps.Copy(c, claims)
		if padding > 0 {
			c["padding"] = strings.Repeat("x", padding)
		}
		return key.sign(t, c)
	}

	// One measurement, then arithmetic: base64 costs four characters per three
	// payload bytes, so the distance to the cap converts directly into padding.
	base := len(sign(0))
	padding := max((maxTokenBytes-base)*3/4, 0)

	for len(sign(padding+1)) <= maxTokenBytes {
		padding++
	}
	for padding > 0 && len(sign(padding)) > maxTokenBytes {
		padding--
	}
	token := sign(padding)
	return token, len(token)
}

func TestVerify_ValidationOrder(t *testing.T) {
	t.Parallel()

	clock := newTestClock()
	key := newSigningKey(t, testKeyID)
	idp := newFakeIdP(t, key)
	v := newTestVerifier(t, idp, clock, nil)
	now := clock.Now()

	// # Why single-corruption tests are not enough
	//
	// Every case elsewhere in this file breaks ONE rule, so they all stay green
	// under any permutation of the checks. The contract fixes an ORDER, and the
	// only way to pin an order is to break several rules at once and assert
	// which rejection comes back. Each case below breaks its own rule plus
	// every rule that is supposed to be checked AFTER it.
	corrupt := map[string]func(map[string]any){
		"iss":       func(c map[string]any) { c[claimIssuer] = "https://elsewhere.example" },
		"aud":       func(c map[string]any) { c[claimAudience] = "api:other" },
		"exp":       func(c map[string]any) { c[claimExpiry] = now.Add(-time.Hour).Unix() },
		"iat":       func(c map[string]any) { c[claimIssuedAt] = now.Add(time.Hour).Unix() },
		"nbf":       func(c map[string]any) { c[claimNotBefore] = now.Add(time.Hour).Unix() },
		"jti":       func(c map[string]any) { delete(c, claimTokenID) },
		"client_id": func(c map[string]any) { delete(c, claimClientID) },
		"sub":       func(c map[string]any) { delete(c, claimSubject) },
		"sid":       func(c map[string]any) { delete(c, claimSessionID) },
		"amr":       func(c map[string]any) { delete(c, claimAMR) },
		"ver":       func(c map[string]any) { c[claimVersion] = 2 },
		"grants":    func(c map[string]any) { delete(c, claimGrants) },
	}

	// The binding order of the contract, first check first.
	order := []struct {
		rule string
		want error
	}{
		{"iss", errIssuer},
		{"aud", errAudience},
		{"exp", errExpired},
		{"iat", errIssuedInFuture},
		{"nbf", errNotYetValid},
		{"jti", errTokenID},
		{"client_id", errClientID},
		{"sub", errSubject},
		{"sid", errSessionID},
		{"amr", errAMR},
		{"ver", errClaimVersion},
		{"grants", errGrants},
	}

	for i, step := range order {
		t.Run(step.rule+" wins over everything after it", func(t *testing.T) {
			t.Parallel()

			claims := validClaims(idp.issuer(), now)
			for _, later := range order[i:] {
				corrupt[later.rule](claims)
			}

			_, err := v.Verify(context.Background(), key.sign(t, claims))
			if !errors.Is(err, step.want) {
				t.Fatalf("with %s and every later rule broken, want %v, got %v", step.rule, step.want, err)
			}
		})
	}

	t.Run("the signature wins over every claim", func(t *testing.T) {
		t.Parallel()

		// Until the signature verifies, every claim is attacker-controlled text.
		// Reading one before that is reading a document nobody signed.
		claims := validClaims(idp.issuer(), now)
		for _, step := range order {
			corrupt[step.rule](claims)
		}
		impostor := signingKey{kid: testKeyID, key: newSigningKey(t, "impostor").key}

		if _, err := v.Verify(context.Background(), impostor.sign(t, claims)); !errors.Is(err, errBadSignature) {
			t.Fatalf("want errBadSignature ahead of any claim check, got %v", err)
		}
	})

	t.Run("the size gate wins over the signature", func(t *testing.T) {
		t.Parallel()

		claims := validClaims(idp.issuer(), now)
		claims["padding"] = strings.Repeat("x", maxTokenBytes)
		impostor := signingKey{kid: testKeyID, key: newSigningKey(t, "impostor").key}

		if _, err := v.Verify(context.Background(), impostor.sign(t, claims)); !errors.Is(err, errTokenTooLarge) {
			t.Fatalf("want errTokenTooLarge ahead of the signature check, got %v", err)
		}
	})
}

func TestVerify_SkewBoundariesAreInclusiveForIatAndNbf(t *testing.T) {
	t.Parallel()

	clock := newTestClock()
	key := newSigningKey(t, testKeyID)
	idp := newFakeIdP(t, key)
	v := newTestVerifier(t, idp, clock, nil)
	now := clock.Now()

	// exp is EXCLUSIVE at the boundary (a token that expired exactly one leeway
	// ago is gone) and that case lives in TestVerify_ClockSkewBoundaries. iat
	// and nbf are the other direction: a date exactly one leeway in the future
	// is still inside the tolerance, and only an exact-boundary test can tell a
	// correct comparison from an off-by-one.
	cases := []struct {
		name   string
		claim  string
		offset time.Duration
		want   error
	}{
		{name: "iat exactly one leeway in the future", claim: claimIssuedAt, offset: defaultClockSkew},
		{name: "iat one nanosecond past the leeway", claim: claimIssuedAt, offset: defaultClockSkew + time.Second, want: errIssuedInFuture},
		{name: "nbf exactly one leeway in the future", claim: claimNotBefore, offset: defaultClockSkew},
		{name: "nbf one second past the leeway", claim: claimNotBefore, offset: defaultClockSkew + time.Second, want: errNotYetValid},
		{name: "exp exactly one leeway in the past", claim: claimExpiry, offset: -defaultClockSkew, want: errExpired},
		{name: "exp one second inside the leeway", claim: claimExpiry, offset: -(defaultClockSkew - time.Second)},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			claims := validClaims(idp.issuer(), now)
			claims[c.claim] = now.Add(c.offset).Unix()

			_, err := v.Verify(context.Background(), key.sign(t, claims))
			if c.want == nil {
				if err != nil {
					t.Fatalf("want acceptance at the boundary, got %v", err)
				}
				return
			}
			if !errors.Is(err, c.want) {
				t.Fatalf("want %v, got %v", c.want, err)
			}
		})
	}
}

// hayrat_profile_ver is a cache marker, not authorization: absent or malformed
// reads as 0 and never rejects the token.
//
// MUTATION: drop the ProfileVersion assignment in Verify and the "present" row
// fails; make profileVersion return an error path for garbage and the rows that
// expect acceptance fail.
func TestVerify_ProfileVersionClaim(t *testing.T) {
	t.Parallel()

	clock := newTestClock()
	key := newSigningKey(t, testKeyID)
	idp := newFakeIdP(t, key)
	v := newTestVerifier(t, idp, clock, nil)

	cases := []struct {
		name  string
		claim any // nil means: leave the claim out
		want  int64
	}{
		{"absent (an issuer that predates the claim)", nil, 0},
		{"present", 7, 7},
		{"large but exact", int64(1) << 40, 1 << 40},
		{"zero", 0, 0},
		{"a string", "7", 0},
		{"a float", json.Number("7.5"), 0},
		{"negative", -3, 0},
		{"null", json.RawMessage("null"), 0},
		{"beyond int64", json.Number("99999999999999999999"), 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			claims := validClaims(idp.issuer(), clock.Now())
			if c.claim != nil {
				claims[claimProfileVersion] = c.claim
			}
			principal, err := v.Verify(context.Background(), key.sign(t, claims))
			if err != nil {
				t.Fatalf("the claim must never reject a token: %v", err)
			}
			if principal.ProfileVersion != c.want {
				t.Errorf("ProfileVersion = %d, want %d", principal.ProfileVersion, c.want)
			}
		})
	}
}
