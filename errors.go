package hesabim

import (
	"errors"
	"fmt"
)

// Every rejection this package produces is built here, from a FIXED string.
//
// # Why the reasons are constants and never carry a value
//
// The error reaches two places a token must not: an application log, and — if
// the integrator is careless — an HTTP response. So a rejection names the RULE
// that failed ("aud is not exactly the configured audience") and never the
// value that failed it. That rules out the two leaks that matter: token bytes,
// which are a credential until they expire, and claim values, which are the
// subject's identity and authorization.
//
// It also rules out an oracle. An attacker probing a resource server learns
// only "rejected", never "rejected because your aud was api:other-project",
// which is the difference between a 401 and a discovery tool.
//
// The errors are UNEXPORTED. The SDK's public surface is deliberately
// small and does not include sentinels, so an integrator cannot branch on
// them; what an integrator can do is what the contract intends — let the SDK
// decide, and either take the default 401 or write their own from the fact of
// the call. The strings stay stable enough to grep in a log.
var errUnauthenticated = errors.New("token rejected")

// reject builds one of the sentinels below. Deliberately takes no format
// arguments: a rejection with a value in it is the bug this file exists to
// prevent, and the only way to be sure is to make it unrepresentable.
func reject(reason string) error {
	return fmt.Errorf("hesabim: %w: %s", errUnauthenticated, reason)
}

var (
	// Credential presentation.
	errNoCredentials = reject("no bearer credentials")

	// Parsing and signature. An `alg` outside ES256 — `none` included — is
	// refused by the parser before the key is ever looked up, and surfaces here
	// as errBadSignature: from the caller's side "signed with something this
	// issuer does not use" and "signed badly" are the same answer.
	errMalformedToken = reject("not a well-formed JWT")
	errTokenTooLarge  = reject("longer than the issuer's access-token budget")
	errBadSignature   = reject("not signed with ES256 by a current issuer key")
	errMissingKeyID   = reject("header carries no kid")
	errUnknownKeyID   = reject("no current signing key with that kid")

	// Key material availability. Distinct from errUnknownKeyID because the
	// token may be perfectly good and this server simply cannot prove it.
	errKeysUnavailable = reject("signing keys are unavailable")
	errKeysStale       = reject("signing keys are older than the hard TTL")
	errKeysThrottled   = reject("signing keys were refreshed too recently to try again")

	// The mandatory claim matrix. This issuer stamps every one of these on
	// every access token, so a missing or wrongly typed claim is not a token
	// from a slightly older version — it is not a token from this issuer.
	errIssuer           = reject("iss is not the configured issuer")
	errAudience         = reject("aud is not exactly the configured audience")
	errExpired          = reject("exp is missing or has passed")
	errIssuedInFuture   = reject("iat is missing or is in the future")
	errNotYetValid      = reject("nbf is missing or has not been reached")
	errTokenID          = reject("jti is missing or empty")
	errClientID         = reject("client_id is missing or empty")
	errSubject          = reject("sub is missing or empty")
	errServicePrincipal = reject("hayrat_principal marks a service token, which a project API does not accept")
	errSessionID        = reject("sid is missing or empty")
	errAMR              = reject("amr is not a non-empty list of non-empty strings")
	errClaimVersion     = reject("hayrat_ver is missing or is not 1")
	errGrants           = reject("hayrat_grants is missing or malformed")
	errDuplicateRole    = reject("hayrat_grants carries the same role twice")
)

// JWKS document errors. These are not token rejections — they describe the
// issuer's key set — but they follow the same rule: no JWKS bytes in the
// message, because a JWKS fetched from the wrong place is attacker-controlled
// content and a log is not the place to render it.
var (
	errMalformedJWKS = errors.New("hesabim: jwks is not a well-formed JSON object")
	errAmbiguousJWKS = errors.New("hesabim: jwks carries two usable keys with the same kid")
	errEmptyJWKS     = errors.New("hesabim: jwks carries no usable ES256 key")
)
