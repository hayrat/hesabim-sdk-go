// Command chi is a Hesabım resource server on chi. chi speaks net/http
// middleware natively, so the SDK's middleware is used as is.
//
//	HESABIM_AUDIENCE=api:ornek-proje go run ./resource-server/chi
package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	hesabim "github.com/hayrat/hesabim-sdk-go"
)

func main() {
	audience := os.Getenv("HESABIM_AUDIENCE")
	if audience == "" {
		log.Fatal("HESABIM_AUDIENCE is required")
	}
	issuer := os.Getenv("HESABIM_ISSUER_URL")
	if issuer == "" {
		issuer = "https://hesabim.hayrat.com"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	verifier, err := hesabim.New(ctx, hesabim.Config{IssuerURL: issuer, Audience: audience})
	if err != nil {
		log.Fatalf("hesabim: %v", err) // never start a server that cannot verify tokens
	}

	log.Fatal(http.ListenAndServe(":8080", newRouter(verifier)))
}

func newRouter(v *hesabim.Verifier) http.Handler {
	r := chi.NewRouter()
	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	r.Route("/api", func(r chi.Router) {
		r.Use(v.Middleware)
		r.Get("/me", me)
		r.Get("/districts/{id}/reports", districtReports)
	})
	return r
}

func me(w http.ResponseWriter, r *http.Request) {
	p, ok := hesabim.FromContext(r.Context())
	if !ok {
		http.Error(w, "unauthenticated", http.StatusUnauthorized)
		return
	}
	writeJSON(w, map[string]any{"sub": p.Subject, "grants": p.Grants})
}

func districtReports(w http.ResponseWriter, r *http.Request) {
	p, ok := hesabim.FromContext(r.Context())
	if !ok {
		http.Error(w, "unauthenticated", http.StatusUnauthorized)
		return
	}
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || id <= 0 {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if !p.Can("moderator", hesabim.Scope{Type: hesabim.ScopeTypeDistrict, ID: id}) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	writeJSON(w, map[string]any{"district": id, "reports": []string{}})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
