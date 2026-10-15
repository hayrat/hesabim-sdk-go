package hesabim

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// The claim names of the contract, as constants.
//
// COPIED from the issuer rather than imported — this module shares no code with
// the issuer — and constants rather than literals for the reason the issuer
// gives: a typo in a claim name is a silent authorization failure, in somebody
// else's service, months later.
const (
	claimIssuer    = "iss"
	claimSubject   = "sub"
	claimAudience  = "aud"
	claimExpiry    = "exp"
	claimIssuedAt  = "iat"
	claimNotBefore = "nbf"
	claimTokenID   = "jti"
	claimClientID  = "client_id"
	claimSessionID = "sid"
	claimAMR       = "amr"

	// claimPrincipal marks a SERVICE (client_credentials) token.
	// A project API serves people: this verifier establishes a user Principal and
	// has no machine one, so a token bearing the marker — whatever its value — is
	// refused, positively, instead of relying on the claims a service token
	// happens to lack.
	claimPrincipal = "hayrat_principal"

	claimVersion = "hayrat_ver"
	claimGrants  = "hayrat_grants"

	claimProfileVersion = "hayrat_profile_ver"

	grantClaimRole   = "role"
	grantClaimScopes = "scopes"
	scopeClaimType   = "type"
	scopeClaimID     = "id"
)

// claimVersionV1 is the only claim-contract version this build understands. A
// token announcing another one is REFUSED rather than read on a best-effort
// basis: the version exists so that a future contract can change the meaning of
// a claim, and a reader that guesses at meanings it was not taught is a reader
// that will eventually guess "authorized".
const claimVersionV1 = 1

// maxTokenBytes is the longest compact JWT this package will look at.
//
// The number is the MINT-SIDE budget, not one invented here: the issuer refuses
// to create an access token larger than 4096 bytes, because the
// token rides in an Authorization header through proxies whose per-header
// ceilings start at 4 KB. A longer token therefore cannot have come from this
// issuer, and discovering that by base64-decoding and JSON-parsing it first is
// work an unauthenticated caller should not be able to ask for.
//
// COPIED rather than derived, like every other constant in this package that
// mirrors the issuer. If the mint-side budget ever changes, this is the line
// that changes with it.
const maxTokenBytes = 4096

// Verifier turns bearer tokens from one issuer into principals.
//
// Safe for concurrent use and intended to be built once per process: it owns
// the JWKS cache, and a second Verifier means a second cache, a second refresh
// schedule and twice the load on the issuer.
type Verifier struct {
	// issuer is the DISCOVERY DOCUMENT's `issuer`, verbatim — not the
	// configured one. Config.IssuerURL is normalised (one trailing slash) only
	// to bind the configuration to the document; from that point on the
	// document's own string is the reference a token's `iss` is measured
	// against, byte for byte.
	issuer   string
	audience string
	skew     time.Duration
	resolver ScopeResolver
	onError  func(w http.ResponseWriter, r *http.Request, err error)

	parser *jwt.Parser
	keys   *keyCache

	// now is the clock. A field rather than a call to time.Now so the skew and
	// TTL behaviour can be tested at the boundaries instead of near them.
	now func() time.Time
}

// New builds a Verifier: it reads the issuer's discovery document, checks that
// the document belongs to the configured issuer, and fetches the JWKS.
//
// # Fail fast, at boot
//
// All of that happens HERE, and an unreachable issuer is an error rather than a
// deferred one. A resource server that starts without being able to verify
// anything is a resource server that returns 401 to every request while looking
// healthy — the failure belongs at startup, where a deployment notices it,
// rather than in production traffic.
//
// Discovery is read exactly once. The endpoints are fixed for the life of the
// process; only the JWKS is refreshed.
func New(ctx context.Context, cfg Config) (*Verifier, error) {
	return newVerifier(ctx, cfg, time.Now)
}

// newVerifier is New with the clock as a parameter, so that the skew and TTL
// boundaries can be tested AT the boundary rather than near it. Unexported: a
// caller's clock is not something an authorization decision should depend on.
func newVerifier(ctx context.Context, cfg Config, now func() time.Time) (*Verifier, error) {
	if cfg.IssuerURL == "" {
		return nil, errors.New("hesabim: Config.IssuerURL is required")
	}
	if cfg.Audience == "" {
		return nil, errors.New("hesabim: Config.Audience is required")
	}
	if cfg.ClockSkew < 0 {
		return nil, errors.New("hesabim: Config.ClockSkew must not be negative")
	}

	issuer := normalizeIssuer(cfg.IssuerURL)
	if err := checkAbsoluteURL(issuer, isLoopbackIssuer(issuer)); err != nil {
		return nil, errors.New("hesabim: Config.IssuerURL " + err.Error())
	}

	skew := cfg.ClockSkew
	if skew == 0 {
		skew = defaultClockSkew
	}

	client := cfg.httpClient()
	doc, err := fetchDiscovery(ctx, client, issuer)
	if err != nil {
		return nil, err
	}

	v := &Verifier{
		issuer:   doc.Issuer,
		audience: cfg.Audience,
		skew:     skew,
		resolver: cfg.Resolver,
		onError:  cfg.ErrorHandler,
		parser: jwt.NewParser(
			// ES256 and nothing else, checked by the parser BEFORE the key is
			// looked up and long before a signature is verified. This is the
			// algorithm-confusion defence: `alg: none` and `alg: HS256` (with
			// the public key as the HMAC secret) both die here, and neither
			// costs a JWKS lookup.
			jwt.WithValidMethods([]string{jwt.SigningMethodES256.Alg()}),

			// Numbers stay json.Number. A scope id is a BIGINT and float64
			// silently rounds above 2^53 — the difference between "district
			// 9007199254740993" and "district 9007199254740992" is two
			// different places, and a verifier that cannot tell them apart is
			// making authorization decisions about the wrong one. Keeping the
			// literal text also makes a fractional id (`1.0`, `3.5`) refusable
			// rather than truncatable.
			jwt.WithJSONNumber(),

			// Claim validation is this package's job, not the library's: the
			// contract requires exp, iat AND nbf to be present, which the
			// library's defaults do not, and requires the skew and the ordering
			// spelled out in verifyClaims.
			jwt.WithoutClaimsValidation(),
		),
		now: now,
	}

	v.keys = &keyCache{
		fetch: func(ctx context.Context) (map[string]*ecdsa.PublicKey, error) {
			body, err := fetchBody(ctx, client, doc.JWKSURI)
			if err != nil {
				return nil, err
			}
			return parseJWKS(body)
		},
		now: func() time.Time { return v.now() },
	}

	// seed, not refreshNow: boot keeps the underlying cause (the operator has
	// to fix the deployment it names) and respects ctx (fail-fast is New's
	// contract). The runtime path keeps flattening to its sentinels.
	if err := v.keys.seed(ctx); err != nil {
		return nil, fmt.Errorf("hesabim: could not load the issuer's signing keys at startup: %w", err)
	}

	return v, nil
}

// Verify checks a raw compact JWT and returns the principal behind it.
//
// Public because [Verifier.Middleware] cannot be the only entry point: an Echo,
// Gin or gRPC integration needs the decision without net/http's handler shape.
// Middleware is a thin wrapper over this.
//
// # The order of the checks is part of the contract
//
// Signature first, everything else after. Until the signature verifies, every
// claim in the token is attacker-controlled text; checking `aud` or reading
// `hayrat_grants` before that would be reading a document nobody signed. After
// it, the claims are checked in the order the contract lists — cheapest
// identity bindings (iss, aud) before time, time before presence, presence
// before the authorization payload — so that the most likely rejection happens
// first and the most expensive parse happens last.
//
// Any error means the token is not usable. The error names the rule and never
// the value; see errors.go.
func (v *Verifier) Verify(ctx context.Context, rawToken string) (*Principal, error) {
	// The length gate runs FIRST, before a single base64 or JSON byte is
	// touched. Everything after this point allocates in proportion to what the
	// caller sent, and the caller is unauthenticated.
	if rawToken == "" {
		return nil, errMalformedToken
	}
	if len(rawToken) > maxTokenBytes {
		return nil, errTokenTooLarge
	}

	claims := jwt.MapClaims{}
	if _, err := v.parser.ParseWithClaims(rawToken, claims, v.keyfunc(ctx)); err != nil {
		return nil, parseFailure(err)
	}
	return v.verifyClaims(claims)
}

// keyfunc resolves the token header's kid against the JWKS cache.
//
// A missing kid is a rejection rather than a "try every key". The issuer stamps
// one on every token, and trying every key is how a key that was withdrawn from
// service keeps verifying tokens: with no kid to pin the choice, retirement
// stops meaning anything.
func (v *Verifier) keyfunc(ctx context.Context) jwt.Keyfunc {
	return func(token *jwt.Token) (any, error) {
		kid, _ := token.Header["kid"].(string)
		if kid == "" {
			return nil, errMissingKeyID
		}
		return v.keys.key(ctx, kid)
	}
}

// parseFailure maps the library's outcome onto this package's vocabulary.
//
// The library's own error text is DISCARDED, not wrapped: it renders parts of
// the token (the `alg` it found, the JSON it could not decode) and those are
// attacker-controlled bytes that must not reach a log line through this path.
// Errors this package raised inside the keyfunc are recovered by identity and
// passed through, because they were written under the same rule.
func parseFailure(err error) error {
	for _, known := range []error{
		errMissingKeyID,
		errUnknownKeyID,
		errKeysUnavailable,
		errKeysStale,
		errKeysThrottled,
	} {
		if errors.Is(err, known) {
			return known
		}
	}
	switch {
	case errors.Is(err, jwt.ErrTokenSignatureInvalid):
		return errBadSignature
	case errors.Is(err, jwt.ErrTokenMalformed):
		return errMalformedToken
	default:
		// ErrTokenUnverifiable for an absent or unregistered `alg`, plus
		// anything a future version of the library adds. Refusing an
		// outcome this build does not recognise is the only safe default.
		return errBadSignature
	}
}

// verifyClaims applies the mandatory claim matrix.
//
// Every claim below is stamped by this issuer on every access token. That is
// what makes "missing" and "wrongly typed" the same verdict as "wrong": a token
// without `sid` is not an older token from this issuer, it is a token from
// somewhere else, and there is no version of this contract under which reading
// it partially is better than refusing it.
func (v *Verifier) verifyClaims(claims jwt.MapClaims) (*Principal, error) {
	// EXACT, with no normalisation. The issuer publishes its own name in the
	// discovery document and stamps that same string into every token, so the
	// two are byte-identical by construction; a reader that trims a trailing
	// slash here is accepting an `iss` this issuer does not produce, and `iss`
	// is the claim that decides WHOSE keys and WHOSE authorization semantics
	// the rest of this function is about.
	if iss, ok := claims[claimIssuer].(string); !ok || iss != v.issuer {
		return nil, errIssuer
	}
	if !v.audienceMatches(claims[claimAudience]) {
		return nil, errAudience
	}

	now := v.now()

	// exp: present, and not yet passed. The skew is added to the deadline, so a
	// resource server whose clock runs fast still accepts a token the issuer
	// considers live.
	exp, ok := numericDate(claims[claimExpiry])
	if !ok || !now.Before(exp.Add(v.skew)) {
		return nil, errExpired
	}
	// iat: present, and not in the future. A token issued after now is a token
	// from a clock nobody shares.
	iat, ok := numericDate(claims[claimIssuedAt])
	if !ok || iat.After(now.Add(v.skew)) {
		return nil, errIssuedInFuture
	}
	// nbf: present, and reached. RFC 9068 makes it mandatory in an access
	// token, and this issuer emits it.
	nbf, ok := numericDate(claims[claimNotBefore])
	if !ok || nbf.After(now.Add(v.skew)) {
		return nil, errNotYetValid
	}

	if _, ok := nonEmptyString(claims[claimTokenID]); !ok {
		return nil, errTokenID
	}
	clientID, ok := nonEmptyString(claims[claimClientID])
	if !ok {
		return nil, errClientID
	}
	subject, ok := nonEmptyString(claims[claimSubject])
	if !ok {
		return nil, errSubject
	}
	if _, marked := claims[claimPrincipal]; marked {
		return nil, errServicePrincipal
	}
	sessionID, ok := nonEmptyString(claims[claimSessionID])
	if !ok {
		return nil, errSessionID
	}
	amr, ok := stringList(claims[claimAMR])
	if !ok {
		return nil, errAMR
	}

	if !isClaimVersion(claims[claimVersion], claimVersionV1) {
		return nil, errClaimVersion
	}

	grants, err := parseGrants(claims[claimGrants])
	if err != nil {
		return nil, err
	}

	return &Principal{
		Subject:   subject,
		SessionID: sessionID,
		ClientID:  clientID,
		AMR:       amr,
		Grants:    grants,
		// Not required: a token from an issuer that predates the claim simply
		// has none, and the application's refresh logic then sees 0.
		ProfileVersion: profileVersion(claims[claimProfileVersion]),
		resolver:       v.resolver,
	}, nil
}

// profileVersion reads `hayrat_profile_ver`: a non-negative integer, or 0.
//
// Absent, null, a string, a fraction, a negative or an out-of-range number all
// read as 0 rather than rejecting the token. The claim is a staleness marker
// for an application's cache, not part of authorization: 0 is below every
// version a real user can hold (rows start at 1), so a malformed
// value can at worst fail to trigger a refresh, never widen anything. Rejecting
// would let a cosmetic claim lock users out of every deployed resource server.
func profileVersion(raw any) int64 {
	number, ok := raw.(json.Number)
	if !ok {
		return 0
	}
	v, err := number.Int64()
	if err != nil || v < 0 {
		return 0
	}
	return v
}

// audienceMatches accepts the two shapes RFC 7519 allows for `aud` and no
// others.
//
// A MULTI-element array is refused even when the configured audience is one of
// the elements. This issuer mints one audience per token — audience isolation
// is the reason a project's access token is useless at another project's API —
// so a token addressed to several audiences did not come from it, and the
// question of which of those audiences this server is has no safe answer.
func (v *Verifier) audienceMatches(raw any) bool {
	switch aud := raw.(type) {
	case string:
		return aud == v.audience
	case []any:
		if len(aud) != 1 {
			return false
		}
		single, ok := aud[0].(string)
		return ok && single == v.audience
	default:
		return false
	}
}

// The range of Unix seconds this package will interpret as a date: year 1 to
// the end of year 9999.
//
// The bound is not cosmetic. Converting a float64 outside int64's range is
// UNDEFINED in Go — on arm64 it saturates to the maximum, on amd64 it produces
// the minimum — so `"exp": 1e100` becomes either a date in the year
// 292277026596 or one in the deep past depending on the machine the resource
// server happens to run on. The first of those is a token that never expires.
// A value that cannot be represented is not a late date, it is not a date, and
// the only reading that is the same on every platform is refusal.
const (
	minNumericDate = -62135596800 // 0001-01-01T00:00:00Z
	maxNumericDate = 253402300799 // 9999-12-31T23:59:59Z
)

// numericDate reads a JSON NumericDate.
//
// The INTEGER path is exact and is the only one this issuer uses: json.Number
// keeps the literal text, so the seconds are parsed straight out of it with no
// float in the way. RFC 7519 also permits a fractional NumericDate, which is
// handled by the second path — and bounded BEFORE the conversion, because
// bounding afterwards would be bounding a value the conversion already
// corrupted.
//
// A non-numeric, absent or unrepresentable value is reported as absent, which
// every caller turns into a rejection.
func numericDate(raw any) (time.Time, bool) {
	number, ok := raw.(json.Number)
	if !ok {
		return time.Time{}, false
	}

	if seconds, err := number.Int64(); err == nil {
		if seconds < minNumericDate || seconds > maxNumericDate {
			return time.Time{}, false
		}
		return time.Unix(seconds, 0), true
	}

	seconds, err := number.Float64()
	if err != nil || math.IsNaN(seconds) || math.IsInf(seconds, 0) {
		return time.Time{}, false
	}
	if seconds < minNumericDate || seconds > maxNumericDate {
		return time.Time{}, false
	}
	whole, frac := math.Modf(seconds)
	return time.Unix(int64(whole), int64(frac*float64(time.Second))), true
}

// nonEmptyString is the shape of every mandatory identifier claim. Empty and
// absent are one verdict: an empty `sub` identifies nobody.
func nonEmptyString(raw any) (string, bool) {
	s, ok := raw.(string)
	return s, ok && s != ""
}

// stringList reads `amr`: a non-empty array whose every element is a non-empty
// string. An empty array would say "authenticated by no method", which is not a
// statement this issuer makes.
func stringList(raw any) ([]string, bool) {
	items, ok := raw.([]any)
	if !ok || len(items) == 0 {
		return nil, false
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		s, ok := nonEmptyString(item)
		if !ok {
			return nil, false
		}
		out = append(out, s)
	}
	return out, true
}

// isClaimVersion compares the contract version exactly.
//
// The value must be the NUMBER 1. The string "1" is refused: a claim whose type
// changed is a claim from a contract this build was not written against, and
// coercing it is exactly the guess the version field exists to prevent.
func isClaimVersion(raw any, want int64) bool {
	number, ok := raw.(json.Number)
	if !ok {
		return false
	}
	got, err := number.Int64()
	return err == nil && got == want
}

// parseGrants validates and reads `hayrat_grants`.
//
// # Everything here is fail-closed, and the shape is checked before it is used
//
// The claim is the authorization payload. A reader that is lenient about its
// shape is lenient about what a user may do, so every deviation — a null where
// an array belongs, a missing role, a scope id that is not an integer — rejects
// the whole token rather than skipping the entry. Skipping would silently
// narrow or widen a permission set, and neither direction is something the
// caller can detect.
//
// # Two things this function deliberately does NOT do
//
// It does not validate the scope TYPE against the known vocabulary. The issuer
// does not either: the type list lives in reference data, and a resource server
// that rejects tokens carrying a type it has not been taught would lock out
// every user granted a newly added type until it is redeployed. An unfamiliar
// type simply never matches a target of a familiar one, which denies.
//
// It does not tolerate a duplicated ROLE. The mint side merges a role's grants
// into a single entry, so two entries for one role cannot come from this
// issuer; and if the reader had to pick one, "whichever came first" would be a
// coin flip over somebody's permissions.
func parseGrants(raw any) ([]Grant, error) {
	// A missing claim and an explicit null both land here as a failed type
	// assertion, which is the intended verdict for both: absent means "this
	// issuer does not speak authorization", and every access token from this
	// issuer speaks it, if only to say `[]`.
	items, ok := raw.([]any)
	if !ok {
		return nil, errGrants
	}

	grants := make([]Grant, 0, len(items))
	seen := make(map[string]struct{}, len(items))

	for _, item := range items {
		entry, ok := item.(map[string]any)
		if !ok {
			return nil, errGrants
		}
		role, ok := nonEmptyString(entry[grantClaimRole])
		if !ok {
			return nil, errGrants
		}
		if _, duplicate := seen[role]; duplicate {
			return nil, errDuplicateRole
		}
		seen[role] = struct{}{}

		rawScopes, ok := entry[grantClaimScopes].([]any)
		if !ok {
			// Including null. An absent scope list is not the same as an empty
			// one — empty means PROJECT-WIDE — so a claim that leaves it out is
			// a claim whose most permissive reading is also its most dangerous.
			return nil, errGrants
		}

		scopes := make([]Scope, 0, len(rawScopes))
		for _, rawScope := range rawScopes {
			scope, err := parseScope(rawScope)
			if err != nil {
				return nil, err
			}
			scopes = append(scopes, scope)
		}

		grants = append(grants, Grant{Role: role, Scopes: scopes})
	}

	return grants, nil
}

// parseScope reads one {"type": …, "id": …} entry.
//
// The id must be an INTEGER in 1..2^53-1, read losslessly. json.Number.Int64
// parses the literal text, so "1.0" and "1e2" fail — they are not the shape the
// issuer emits, and accepting them would mean accepting a value that a float64
// round trip could have altered. The upper bound is the mint side's own, and
// the lower bound is 1 because reference-data ids are BIGSERIALs: 0 and
// negatives are not places.
func parseScope(raw any) (Scope, error) {
	entry, ok := raw.(map[string]any)
	if !ok {
		return Scope{}, errGrants
	}
	scopeType, ok := nonEmptyString(entry[scopeClaimType])
	if !ok {
		return Scope{}, errGrants
	}
	number, ok := entry[scopeClaimID].(json.Number)
	if !ok {
		return Scope{}, errGrants
	}
	id, err := number.Int64()
	if err != nil || id < 1 || id > maxSafeScopeID {
		return Scope{}, errGrants
	}
	return Scope{Type: scopeType, ID: id}, nil
}
