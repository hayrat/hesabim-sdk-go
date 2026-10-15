// Package hesabim verifies Hayrat Hesabım access tokens in a Go resource
// server and answers one authorization question: may this principal do
// something to these targets?
//
// # What this package is, and what it is not
//
// It is a RESOURCE SERVER library. It never redirects a browser, never holds a
// client secret, never talks to the token endpoint. It reads the issuer's
// discovery document once at startup, keeps its JWKS current, and turns a
// bearer token into a [Principal].
//
// It is not an OAuth client. The login flow belongs to the front end (see the
// JavaScript SDK); by the time a request reaches this package the token
// already exists.
//
// # The authorization model, in one paragraph
//
// A token carries GRANTS: one entry per role, each with its own scopes. The
// only check this package offers is [Principal.Can], which finds the grant for
// a role and then asks whether THAT grant's scopes cover the target. There is
// deliberately no HasRole and no InScope. Two independent predicates over a
// flattened role list and a flattened scope list authorize combinations nobody
// granted — a user who is moderator in Ankara and viewer in İzmir would pass
// `hasRole("moderator") && inScope(İzmir)`. The pairing is the contract, and an
// API that lets a caller break it is the vulnerability.
//
// # Usage
//
//	v, err := hesabim.New(ctx, hesabim.Config{
//	    IssuerURL: "https://hesabim.hayrat.com",
//	    Audience:  "api:my-project",
//	})
//	if err != nil {
//	    log.Fatal(err) // fail fast: the issuer must be reachable at boot
//	}
//	mux.Handle("/things", v.Middleware(thingsHandler))
//
// and inside a handler:
//
//	p, ok := hesabim.FromContext(r.Context())
//	if !ok || !p.Can("moderator", hesabim.Scope{Type: hesabim.ScopeTypeDistrict, ID: 1234}) {
//	    http.Error(w, "forbidden", http.StatusForbidden)
//	    return
//	}
//
// The 401 is this package's decision; the 403 is the application's. The
// middleware only proves WHO is calling.
package hesabim
