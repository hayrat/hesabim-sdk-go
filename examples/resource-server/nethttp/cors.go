package main

import (
	"net/http"
	"slices"
	"strings"
)

// withCORS lets a browser SPA served from ANOTHER origin call this API.
//
// Prefer not to need it: serve the SPA and the API from one origin (a reverse
// proxy routing /api to this server) and there is no CORS at all. When the
// origins must differ, this wrapper goes OUTSIDE the auth middleware: a
// preflight (OPTIONS) never carries the Authorization header, so behind the
// middleware it would be a 401 and the browser would never send the real
// request.
//
// Only exact, allow-listed origins are answered; no wildcard, no reflection of
// arbitrary origins. Credentials (cookies) are not allowed — the token travels
// in the Authorization header.
func withCORS(next http.Handler, allowed []string) http.Handler {
	if len(allowed) == 0 {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		ok := origin != "" && slices.Contains(allowed, origin)
		if ok {
			h := w.Header()
			h.Set("Access-Control-Allow-Origin", origin)
			h.Add("Vary", "Origin")
		}
		if r.Method == http.MethodOptions && r.Header.Get("Access-Control-Request-Method") != "" {
			if ok {
				h := w.Header()
				h.Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE")
				h.Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
				h.Set("Access-Control-Max-Age", "600")
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// allowedOrigins parses CORS_ALLOWED_ORIGINS: a comma-separated list of exact
// origins, e.g. "https://app.example,https://localhost:5173". Empty = CORS off.
func allowedOrigins(v string) []string {
	var out []string
	for _, o := range strings.Split(v, ",") {
		if o = strings.TrimRight(strings.TrimSpace(o), "/"); o != "" {
			out = append(out, o)
		}
	}
	return out
}
