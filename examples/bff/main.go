// Command bff is a complete Backend-for-Frontend integration with Hesabım.
//
// Topology B: the browser never sees a token. This server runs the OIDC
// Authorization Code flow (+ PKCE, + client secret) itself, keeps access and
// refresh tokens in a server-side session, and gives the browser only an
// HttpOnly session cookie. Its own /api is protected by the SDK middleware,
// fed with the session's access token.
//
//	HESABIM_CLIENT_ID=ornek-proje-bff \
//	HESABIM_CLIENT_SECRET=... \
//	HESABIM_AUDIENCE=api:ornek-proje \
//	HESABIM_REDIRECT_URI=http://localhost:8080/auth/callback \
//	HESABIM_POST_LOGOUT_REDIRECT_URI=http://localhost:8080/ \
//	go run ./bff
//
// Routes:
//
//	GET  /auth/login?returnTo=/path   start login (redirects to Hesabım)
//	GET  /auth/callback               finish login (registered redirect URI)
//	POST /auth/logout                 end the session, then Hesabım's
//	GET  /auth/me                     {"authenticated":…, "sub", "name", "gender"}
//	     /api/...                     your API; 401 {"error":"login_required"} without a session
package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
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
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Production: replace newMemoryStore with a Redis-backed Store and
	// users.NewMemoryStore with users.SQLStore.
	a, err := newApp(ctx, cfg, newMemoryStore(), users.NewMemoryStore())
	if err != nil {
		log.Fatalf("hesabim: %v", err) // never start a server that cannot log anyone in
	}
	addr := envOr("ADDR", ":8080")
	log.Printf("listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, a.routes()))
}

func configFromEnv() (Config, error) {
	cfg := Config{
		IssuerURL:             envOr("HESABIM_ISSUER_URL", "https://hesabim.hayrat.com"),
		ClientID:              os.Getenv("HESABIM_CLIENT_ID"),
		ClientSecret:          os.Getenv("HESABIM_CLIENT_SECRET"),
		RedirectURI:           os.Getenv("HESABIM_REDIRECT_URI"),
		PostLogoutRedirectURI: os.Getenv("HESABIM_POST_LOGOUT_REDIRECT_URI"),
		Audience:              os.Getenv("HESABIM_AUDIENCE"),
	}
	for name, v := range map[string]string{
		"HESABIM_CLIENT_ID":                cfg.ClientID,
		"HESABIM_CLIENT_SECRET":            cfg.ClientSecret,
		"HESABIM_REDIRECT_URI":             cfg.RedirectURI,
		"HESABIM_POST_LOGOUT_REDIRECT_URI": cfg.PostLogoutRedirectURI,
		"HESABIM_AUDIENCE":                 cfg.Audience,
	} {
		if v == "" {
			// The name only — never the value, and never the secret.
			return Config{}, errMissing(name)
		}
	}
	return cfg, nil
}

func (a *app) routes() http.Handler {
	api := http.NewServeMux()
	api.HandleFunc("GET /api/me", apiMe)
	api.HandleFunc("GET /api/districts/{id}/reports", districtReports)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("GET /auth/login", a.login)
	mux.HandleFunc("GET "+a.callbackPath, a.callback)
	mux.HandleFunc("POST /auth/logout", a.logout)
	mux.HandleFunc("GET /auth/me", a.me)
	mux.Handle("/api/", a.requireSession(a.api.Middleware(api)))

	// Cookie authentication needs CSRF protection on state-changing requests.
	// SameSite=Lax already stops most of it; CrossOriginProtection rejects any
	// cross-origin POST/PUT/PATCH/DELETE using Sec-Fetch-Site / Origin.
	return http.NewCrossOriginProtection().Handler(mux)
}

// apiMe and districtReports are ordinary resource-server handlers: they do
// not know a session exists. The principal comes from the SDK middleware.
func apiMe(w http.ResponseWriter, r *http.Request) {
	p, ok := hesabim.FromContext(r.Context())
	if !ok {
		http.Error(w, "unauthenticated", http.StatusUnauthorized)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"sub": p.Subject, "grants": p.Grants})
}

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
	writeJSON(w, http.StatusOK, map[string]any{"district": id, "reports": json.RawMessage("[]")})
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

type errMissing string

func (e errMissing) Error() string { return string(e) + " is required" }
