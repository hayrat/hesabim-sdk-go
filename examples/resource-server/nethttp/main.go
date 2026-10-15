// Command nethttp is a complete Hesabım resource server on net/http.
//
// Topology A: a browser SPA logs in with the JavaScript SDK and calls this API
// with `Authorization: Bearer <access token>`. This server verifies the token
// locally (JWKS, no call to the issuer per request) and authorizes with Can.
//
//	HESABIM_AUDIENCE=api:ornek-proje go run ./resource-server/nethttp
//
// CORS_ALLOWED_ORIGINS (optional) is needed only when the SPA is served from
// another origin than this API.
package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"slices"
	"strconv"
	"time"

	hesabim "github.com/hayrat/hesabim-sdk-go"
	"github.com/hayrat/hesabim-sdk-go/examples/users"
)

func main() {
	cfg, err := configFromEnv()
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	cfg.Resolver = geo{districtsByProvince: map[int64][]int64{6: {601, 602}}}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	verifier, err := hesabim.New(ctx, cfg)
	if err != nil {
		// Deliberate: New reads discovery and the JWKS. A resource server that
		// cannot verify any token must not start and look healthy.
		log.Fatalf("hesabim: %v", err)
	}

	addr := envOr("ADDR", ":8080")
	log.Printf("listening on %s", addr)
	// Optional: only when the SPA is served from another origin (see cors.go).
	handler := withCORS(newHandler(verifier, users.NewMemoryStore()), allowedOrigins(os.Getenv("CORS_ALLOWED_ORIGINS")))
	log.Fatal(http.ListenAndServe(addr, handler))
}

// configFromEnv reads the two values a resource server needs. Neither is a
// secret.
func configFromEnv() (hesabim.Config, error) {
	audience := os.Getenv("HESABIM_AUDIENCE")
	if audience == "" {
		return hesabim.Config{}, errMissing("HESABIM_AUDIENCE")
	}
	return hesabim.Config{
		IssuerURL: envOr("HESABIM_ISSUER_URL", "https://hesabim.hayrat.com"),
		Audience:  audience,
	}, nil
}

func newHandler(v *hesabim.Verifier, store users.Store) http.Handler {
	api := http.NewServeMux()
	api.HandleFunc("GET /api/me", me)
	api.Handle("POST /api/me/sync", users.SyncHandler(store))
	api.HandleFunc("GET /api/districts/{id}/reports", districtReports)

	root := http.NewServeMux()
	root.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	// Every /api/ route requires a valid token. The middleware decides 401;
	// each handler decides its own 403.
	root.Handle("/api/", v.Middleware(api))
	return root
}

// me returns who is calling and what they hold. Grants are exported for
// ENUMERATION (menus, WHERE clauses) — never flatten them into a role list
// and a scope list and check those separately.
func me(w http.ResponseWriter, r *http.Request) {
	p, ok := hesabim.FromContext(r.Context())
	if !ok {
		http.Error(w, "unauthenticated", http.StatusUnauthorized)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"sub": p.Subject, "grants": p.Grants})
}

// districtReports is the authorization pattern: the handler knows the
// resource, so the handler asks Can about it.
func districtReports(w http.ResponseWriter, r *http.Request) {
	p, ok := hesabim.FromContext(r.Context())
	if !ok {
		http.Error(w, "unauthenticated", http.StatusUnauthorized)
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if !p.Can("moderator", hesabim.Scope{Type: hesabim.ScopeTypeDistrict, ID: id}) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"district": id, "reports": []string{}})
}

// geo teaches Can that a province contains its districts. The SDK matches
// (type, id) exactly; containment is your reference data. In a real service
// this map is loaded from your own geography tables.
type geo struct{ districtsByProvince map[int64][]int64 }

func (g geo) Covers(granted, target hesabim.Scope) bool {
	if granted.Type != hesabim.ScopeTypeProvince || target.Type != hesabim.ScopeTypeDistrict {
		return false
	}
	return slices.Contains(g.districtsByProvince[granted.ID], target.ID)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

type errMissing string

func (e errMissing) Error() string { return string(e) + " is required" }
