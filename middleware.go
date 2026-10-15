package hesabim

import (
	"context"
	"net/http"
	"strings"
)

// The two WWW-Authenticate challenges, and the difference between them is
// RFC 6750 §3.
//
// A request that presented NO credentials gets the bare scheme. Adding
// error="invalid_token" there would be a lie — nothing was invalid, nothing was
// sent — and RFC 6750 says not to. A request that presented a token that failed
// gets the error code, which is what tells a client library to stop retrying
// with the same token and refresh instead.
//
// Neither carries error_description. The description field is where a helpful
// implementation explains WHICH check failed, and that is a verification oracle
// handed to whoever is probing: it turns a uniform 401 into a map of the
// issuer's claim contract, and in the worst case echoes a claim value back to
// an unauthenticated caller.
const (
	challengeBearer       = "Bearer"
	challengeInvalidToken = `Bearer error="invalid_token"`
)

// unauthorizedBody is the project's error envelope. The `code` is the
// machine-readable half and the only half a client should branch on; `message`
// is a fixed English string, deliberately generic, and the user-facing text is
// the front end's business.
var unauthorizedBody = []byte(`{"error":{"code":"UNAUTHORIZED","message":"authentication required"}}`)

// Middleware authenticates a request and hands the Principal to next through
// the request context.
//
// # It decides 401 and never 403
//
// The middleware answers "who is calling", which is a question with a single
// correct enforcement point. "May they do this" is a question about a specific
// resource, and only the handler knows the resource — so authorization is a
// [Principal.Can] call inside the handler, not a rule this package can be
// configured with. A middleware that took a role or a scope as an argument
// would have to decide it before knowing what the request was about, and the
// answer would be wrong for every route with an id in it.
func (v *Verifier) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, ok := bearerToken(r.Header.Get("Authorization"))
		if !ok {
			v.unauthorized(w, r, errNoCredentials, challengeBearer)
			return
		}

		principal, err := v.Verify(r.Context(), raw)
		if err != nil {
			v.unauthorized(w, r, err, challengeInvalidToken)
			return
		}

		ctx := context.WithValue(r.Context(), principalKey{}, principal)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// unauthorized writes the refusal, or lets the application write it.
//
// When an ErrorHandler is configured this function touches NOTHING on the
// ResponseWriter — no header, no status, no body. Half-writing a response and
// then delegating would leave the application unable to set its own status,
// which is the one thing an override is for.
func (v *Verifier) unauthorized(w http.ResponseWriter, r *http.Request, err error, challenge string) {
	if v.onError != nil {
		v.onError(w, r, err)
		return
	}

	w.Header().Set("WWW-Authenticate", challenge)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusUnauthorized)
	_, _ = w.Write(unauthorizedBody)
}

// bearerToken extracts the credential from an Authorization header.
//
// The scheme comparison is case-insensitive because RFC 7235 says auth-scheme
// is; the token itself is not touched beyond trimming the separating spaces
// that RFC 6750's `1*SP` permits. A value containing whitespace is refused
// rather than split: `Bearer a b` is not a token with a space in it, it is a
// header this package does not understand, and guessing which half is the
// credential is how a proxy-mangled header becomes an authentication bypass.
func bearerToken(header string) (string, bool) {
	const scheme = "Bearer"

	if len(header) <= len(scheme) || !strings.EqualFold(header[:len(scheme)], scheme) {
		return "", false
	}
	if header[len(scheme)] != ' ' {
		return "", false
	}
	token := strings.TrimLeft(header[len(scheme)+1:], " ")
	if token == "" || strings.ContainsAny(token, " \t") {
		return "", false
	}
	return token, true
}
