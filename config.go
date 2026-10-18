package hesabim

import (
	"net/http"
	"time"
)

// Config is everything a resource server has to know to accept this issuer's
// access tokens.
//
// Only IssuerURL and Audience are required. Every optional field has a default
// that is safe to ship with; none of them is a secret, so a Config may be built
// from plain configuration.
type Config struct {
	// IssuerURL is the issuer to trust, e.g. "https://hesabim.hayrat.com".
	//
	// It binds this configuration to a discovery document: the document's
	// `issuer` field must equal this value, with a trailing slash normalised
	// away on both sides — that is the ONLY place normalisation happens, and it
	// exists so an operator's trailing slash is not a boot failure.
	//
	// A token's `iss` is then compared byte-for-byte against the DOCUMENT's
	// issuer, not against this field. The document is the issuer's own
	// statement of its name and is the same string it stamps into every token,
	// so any tolerance applied at that comparison would be tolerance the issuer
	// never asked for.
	//
	// https is required. http is accepted only for the hosts "localhost" and
	// "127.0.0.1", which exist so a developer can run the issuer locally — no
	// deployment reachable by anyone else can satisfy that exemption.
	IssuerURL string

	// Audience is this resource server's API identifier, e.g. "api:my-project".
	// The issuer mints one audience per token, so `aud` must be exactly this
	// value: a token addressed to another API is not a token for this one.
	Audience string

	// HTTPClient fetches the discovery document and the JWKS. Optional; the
	// default is a client with a 10s timeout.
	//
	// The client is COPIED and its CheckRedirect is replaced — a redirect on the
	// discovery or JWKS path would let whoever controls it move key material to
	// another origin, so redirects are never followed. Nothing else about the
	// supplied client is altered, which is what makes a custom transport (proxy,
	// pinned roots, instrumentation) usable here.
	HTTPClient *http.Client

	// ClockSkew is the leeway applied to exp, iat and nbf. Optional; default
	// 30s. Negative values are rejected by New — a negative leeway would make
	// verification stricter than the issuer's own clock in a way no caller
	// intends, and silently clamping it would hide the typo.
	ClockSkew time.Duration

	// Resolver optionally teaches Can about scope containment (a province
	// covering its districts). Nil means exact match only.
	//
	// The SDK does not know Turkish administrative geography and will not learn
	// it: the hierarchy is refdata, it changes, and a stale copy compiled into
	// every resource server is a wrong authorization answer that nobody can
	// deploy their way out of. The application owns the lookup.
	Resolver ScopeResolver

	// ErrorHandler optionally takes over the 401 response. When set it writes
	// the ENTIRE response — the SDK sets no header, no status and no body, it
	// only decides that the request is unauthenticated.
	//
	// err carries the rule that was violated and never a token byte or a claim
	// value, so it is safe to log; it is not safe to echo to the client, which
	// would turn the response into an oracle.
	ErrorHandler func(w http.ResponseWriter, r *http.Request, err error)
}

// The scope-type vocabulary, mirrored from the issuer's claim contract.
//
// COPIED rather than imported, and deliberately so: this package is published
// separately from the issuer and shares no code with it. The wire format is
// the single source of truth; these constants are a convenience that keeps a
// typo from becoming a silent authorization failure.
//
// The list is not a whitelist. A token may carry a scope type this build has
// never heard of — the issuer adds types without waiting for every resource
// server to redeploy — and such a scope simply fails to match any target of a
// known type, which denies rather than grants.
const (
	ScopeTypeRegion   = "region"
	ScopeTypeProvince = "province"
	ScopeTypeDistrict = "district"
	ScopeTypeSchool   = "school"
	// ScopeTypeLanguage is flat — a language, not a place. No place contains
	// a language and a language contains no place; a Resolver has nothing to
	// add for it.
	ScopeTypeLanguage = "language"
)

// ScopeResolver decides containment questions this package cannot answer on its
// own.
type ScopeResolver interface {
	// Covers reports whether a granted scope covers the target (e.g. a province
	// covering a district inside it).
	//
	// Called ONLY when exact match has already failed, and never with a
	// malformed target — a target with an empty type or an out-of-range id is
	// rejected before any resolver runs, so an implementation may assume both
	// arguments are well formed.
	//
	// Must be safe for concurrent use: one verifier serves every request.
	//
	// A panic here propagates to the verifying request; this package does not
	// recover. (The JS SDK, whose exceptions are ordinary control flow, catches
	// a throwing resolver and denies instead — a deliberate asymmetry.)
	Covers(granted, target Scope) bool
}

// defaultHTTPTimeout bounds the two calls this package makes to the issuer.
// Both are on the boot path or on a background refresh, never in the critical
// path of a request that already has a usable key, so the number only has to be
// generous enough for a cold TLS handshake.
const defaultHTTPTimeout = 10 * time.Second

// defaultClockSkew is the leeway that makes an unsynchronised resource server
// clock a non-event. Access tokens live ~10 minutes, so 30s of leeway costs a
// twentieth of the lifetime at each end and buys tolerance for the drift a host
// without NTP accumulates in a day.
const defaultClockSkew = 30 * time.Second

// httpClient returns the client this verifier will use: a copy of the
// configured one (or a default) with redirects disabled.
func (cfg Config) httpClient() *http.Client {
	base := cfg.HTTPClient
	if base == nil {
		base = &http.Client{Timeout: defaultHTTPTimeout}
	}
	clone := *base
	clone.CheckRedirect = func(*http.Request, []*http.Request) error {
		// Returning ErrUseLastResponse hands the 3xx back instead of following
		// it; the 2xx-only rule in fetchBody then rejects it.
		return http.ErrUseLastResponse
	}
	return &clone
}
