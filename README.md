# hesabim-sdk-go

Go resource-server SDK for **Hayrat Hesabım** (OIDC identity provider).

It does one job: turn an incoming `Authorization: Bearer …` header into a
verified `Principal`, and answer `Can(role, targets…)` about it. It is not an
OAuth client — the login flow belongs to the front end, or to a
Backend-for-Frontend ([`examples/bff`](examples/bff) is a complete one).

> **Integrating an application?** Start with
> [`IMPLEMENTATION.md`](IMPLEMENTATION.md) (Turkish): registration request,
> environment variables, and a step-by-step guide an engineer — or an AI coding
> agent — can follow end to end. Complete, tested programs live in
> [`examples/`](examples/): resource servers on net/http and Echo, and
> a full Backend-for-Frontend (login, callback, refresh rotation, logout).

## Installation

```
go get github.com/hayrat/hesabim-sdk-go@latest
```

Requires Go 1.26. The only dependency is `github.com/golang-jwt/jwt/v5`.

## Quick start (net/http)

```go
package main

import (
	"context"
	"log"
	"net/http"

	hesabim "github.com/hayrat/hesabim-sdk-go"
)

func main() {
	verifier, err := hesabim.New(context.Background(), hesabim.Config{
		IssuerURL: "https://hesabim.hayrat.com",
		Audience:  "api:my-project", // this API's identifier in the registry
	})
	if err != nil {
		// Deliberate: New reads discovery and the JWKS. A resource server that
		// cannot verify anything must not start and look healthy.
		log.Fatalf("hesabim: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/districts/", verifier.Middleware(http.HandlerFunc(listDistricts)))
	log.Fatal(http.ListenAndServe(":8080", mux))
}

func listDistricts(w http.ResponseWriter, r *http.Request) {
	principal, ok := hesabim.FromContext(r.Context())
	if !ok {
		http.Error(w, "unauthenticated", http.StatusUnauthorized)
		return
	}

	target := hesabim.Scope{Type: hesabim.ScopeTypeDistrict, ID: districtIDFromPath(r)}
	if !principal.Can("moderator", target) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	// … the request is authorized …
}
```

The middleware decides **401** and nothing else. The **403** is yours, because
only your handler knows which resource the request is about.

## Configuration

| Field          | Required | Default              | Notes                                                     |
| -------------- | -------- | -------------------- | --------------------------------------------------------- |
| `IssuerURL`    | yes      | —                    | Must match the discovery document's `issuer` (trailing slash normalised). |
| `Audience`     | yes      | —                    | This API's identifier, e.g. `api:my-project`.              |
| `HTTPClient`   | no       | 10s timeout          | Copied; redirects are always disabled.                     |
| `ClockSkew`    | no       | 30s                  | Leeway for `exp`, `iat`, `nbf`.                            |
| `Resolver`     | no       | nil (exact match)    | Teaches `Can` about scope containment.                     |
| `ErrorHandler` | no       | project 401 envelope | Takes over the entire 401 response.                        |

## Authorization: `Can` and nothing else

An access token carries **grants**: one entry per role, each with **its own**
scopes.

```json
"hayrat_grants": [
  {"role": "moderator", "scopes": [{"type": "province", "id": 6}]},
  {"role": "viewer",    "scopes": []}
]
```

`Can(role, targets…)` finds the grant for the role and asks whether **that
grant's** scopes cover the targets:

| Situation                              | Result                                    |
| -------------------------------------- | ----------------------------------------- |
| No grant for the role                  | `false`                                   |
| Grant has empty `Scopes`               | `true` — project-wide for that role       |
| Grant is scoped, no targets given      | `false` — a scoped grant is not global    |
| Several targets                        | **all** must be covered (AND)             |
| Malformed target (empty type, id ≤ 0)  | `false`, without consulting the resolver  |

There is **no** `HasRole`, no `InScope`, no role list. That is not an oversight:
a user who is *moderator in Ankara* and *viewer in İzmir* flattens to
`roles=[moderator, viewer]`, `scopes=[Ankara, İzmir]`, and the most natural
check over those two lists — `hasRole("moderator") && inScope(İzmir)` —
authorizes something nobody granted.

`Principal.Grants` **is** exported, for enumeration only (building a
`WHERE district_id IN (…)` filter, rendering a menu). Flattening it into
independent role and scope lists reintroduces exactly the vulnerability above.

### Scope hierarchies

The SDK does not know that İzmir contains Konak — that is reference data, it
changes, and a copy compiled into every resource server would be a wrong answer
nobody can deploy their way out of. Supply a resolver:

```go
type geo struct{ districtsByProvince map[int64][]int64 }

func (g geo) Covers(granted, target hesabim.Scope) bool {
	if granted.Type != hesabim.ScopeTypeProvince || target.Type != hesabim.ScopeTypeDistrict {
		return false
	}
	return slices.Contains(g.districtsByProvince[granted.ID], target.ID)
}
```

`Covers` is called **only** when exact match has already failed, never with a
malformed target, and must be safe for concurrent use.

## Other frameworks

Runnable versions of everything below: [`examples/resource-server`](examples/resource-server).

For Echo, wrap the stock middleware — do **not** re-implement the header
handling. The stock middleware carries semantics a hand-rolled
`strings.TrimPrefix` version silently drops: the case-insensitive `Bearer`
scheme (RFC 7235), the RFC 6750 §3 distinction between "no credentials" and "a
bad token" in `WWW-Authenticate`, and a challenge header at all.

```go
e.Use(echo.WrapMiddleware(v.Middleware))

// In a handler:
principal, ok := hesabim.FromContext(c.Request().Context())
```

`Verify` stays public for frameworks where wrapping `net/http` middleware is
not an option (gRPC interceptors, custom listeners). If you must call it
directly, extract the token the way `Middleware` does — case-insensitive
scheme, single space, non-empty remainder — and answer 401 with a
`WWW-Authenticate: Bearer` challenge, without putting `err` in the response
body (see "Security notes").

## Security notes

**This SDK is the authority.** The browser SDK's `can()` exists to hide buttons
the user cannot use; it decides nothing. Every authorization decision that
matters is a `Can` call in your handler, on a token this package verified.

**Verification is fail-closed throughout.** ES256 only — `alg: none` and
`alg: HS256` are refused during parsing, before any key is looked up. `aud` must
be exactly one element equal to `Config.Audience`; a multi-audience token cannot
have come from this issuer. `iss` is compared byte-for-byte against the
discovery document's `issuer`, with no normalisation — `Config.IssuerURL`'s
trailing slash is normalised only to bind your configuration to a document, and
never at the token comparison. Every claim in the contract (`exp`, `iat`, `nbf`,
`jti`, `client_id`, `sub`, `sid`, `amr`, `hayrat_ver`, `hayrat_grants`) is
mandatory: missing or wrongly typed is the same verdict as wrong, and a date
outside the representable Unix-seconds range is not a date at all. The one
exception is `hayrat_profile_ver`, a cache marker rather than authorization: it
surfaces as `Principal.ProfileVersion` (0 when absent or malformed, never a
rejection) — compare it with the version you stored for the user and refresh
their profile when it is larger.

**Tokens over 4096 bytes are refused before parsing.** That is the issuer's own
mint-side budget, chosen because the token travels in
an `Authorization` header through proxies whose per-header ceilings start at
4 KB. A longer token cannot have come from this issuer, and the length check
runs ahead of any base64 decode, JSON parse or key lookup so an unauthenticated
caller cannot buy that work.

**Scope ids are parsed losslessly.** They are `BIGINT`s that also travel through
a JavaScript parser, so the SDK reads them from the JSON literal rather than
through a `float64`, and refuses anything outside `1 … 2^53-1`. A rounded scope
id is an authorization decision about the wrong place.

**Key freshness has three bounds.** The JWKS is fetched eagerly at `New`.
An unknown `kid` triggers a synchronous refresh, rate-limited to one attempt per
60 seconds (successful or not) so a token full of invented `kid`s cannot turn
your service into a load generator against the issuer. After 15 minutes the
cache refreshes in the background while requests continue to be served. After
**24 hours without a successful fetch the cache is no longer trusted** and
verification fails closed — that bound is what makes it safe to keep serving
from a stale cache while the issuer is briefly unreachable.

**Nothing leaks.** The 401 body is a fixed envelope
(`{"error":{"code":"UNAUTHORIZED","message":"authentication required"}}`), the
`WWW-Authenticate` header carries no `error_description`, and the errors
`Verify` returns name the rule that failed and never the value that failed it.
They are safe to log; they are **not** safe to echo to the client, which would
turn your 401 into a map of the claim contract. If you supply an `ErrorHandler`,
keep the response body generic.

**Front-end integration (JS SDK).** The browser talks to the IdP's token
endpoint directly, and that endpoint only allows origins derived from a client's
registered redirect URIs (`https` only on the live issuer). An origin that is
not registered fails as an opaque CORS error in the browser console — the token
request is a simple POST, so there may be no preflight at all, just a response
the browser hides — so check the registration before debugging the SDK. Your
own API needs CORS only if the SPA is served from another origin; see
IMPLEMENTATION.md §5.7 and `examples/resource-server/nethttp/cors.go`.

## Development

```
go build ./... && go vet ./... && go test -race ./...
(cd examples && go vet ./... && go test -race ./...)
```

`examples/` is a separate module so that the SDK itself keeps a single
dependency (`github.com/golang-jwt/jwt/v5`).

## License

MIT — see [LICENSE](LICENSE).

The test suite runs against a fake issuer (`httptest`) with real P-256 keys and
real ES256-signed tokens. `FuzzParseJWKS` fuzzes the JWKS reader; its seed
corpus runs as part of the ordinary unit tests.
