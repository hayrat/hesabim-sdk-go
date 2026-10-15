package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hayrat/hesabim-sdk-go/examples/internal/fakeidp"
	"github.com/hayrat/hesabim-sdk-go/examples/users"
)

func TestResourceServer(t *testing.T) {
	idp := fakeidp.New(t)
	v := idp.NewVerifier(t, geo{districtsByProvince: map[int64][]int64{6: {601, 602}}})
	store := users.NewMemoryStore()
	h := newHandler(v, store)

	inAnkara := idp.AccessToken(t, fakeidp.Audience, []fakeidp.Grant{
		{Role: "moderator", Scopes: []fakeidp.Scope{{Type: "province", ID: 6}}},
	})
	viewerEverywhere := idp.AccessToken(t, fakeidp.Audience, []fakeidp.Grant{{Role: "viewer"}})
	otherProject := idp.AccessToken(t, "api:baska-proje", []fakeidp.Grant{{Role: "moderator"}})

	cases := []struct {
		name, method, path, token string
		want                      int
	}{
		{"health needs no token", "GET", "/healthz", "", http.StatusOK},
		{"no token is 401", "GET", "/api/me", "", http.StatusUnauthorized},
		{"garbage token is 401", "GET", "/api/me", "not-a-jwt", http.StatusUnauthorized},
		{"token for another API is 401", "GET", "/api/me", otherProject, http.StatusUnauthorized},
		{"valid token reaches the handler", "GET", "/api/me", viewerEverywhere, http.StatusOK},
		{"district inside the granted province, via resolver", "GET", "/api/districts/601/reports", inAnkara, http.StatusOK},
		{"district outside the granted province is 403", "GET", "/api/districts/3501/reports", inAnkara, http.StatusForbidden},
		{"project-wide viewer is not a moderator", "GET", "/api/districts/601/reports", viewerEverywhere, http.StatusForbidden},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got, body := fakeidp.Do(t, h, c.method, c.path, c.token, ""); got != c.want {
				t.Fatalf("status = %d, want %d (body %q)", got, c.want, body)
			}
		})
	}
}

func TestMeSync_WritesOnlyTheCallersRow(t *testing.T) {
	idp := fakeidp.New(t)
	store := users.NewMemoryStore()
	h := newHandler(idp.NewVerifier(t, nil), store)
	token := idp.AccessToken(t, fakeidp.Audience, nil)

	if got, _ := fakeidp.Do(t, h, "POST", "/api/me/sync", "", `{"name":"x"}`); got != http.StatusUnauthorized {
		t.Fatalf("sync without token = %d, want 401", got)
	}
	if got, _ := fakeidp.Do(t, h, "POST", "/api/me/sync", token, `{"name":"Ayşe Yılmaz","gender":"robot"}`); got != http.StatusBadRequest {
		t.Fatalf("invalid gender = %d, want 400", got)
	}
	// A "sub" in the body is ignored: the key always comes from the token.
	body := `{"sub":"someone-else","name":"  Ayşe Yılmaz ","gender":"female"}`
	if got, b := fakeidp.Do(t, h, "POST", "/api/me/sync", token, body); got != http.StatusNoContent {
		t.Fatalf("sync = %d, want 204 (%s)", got, b)
	}
	u, ok, _ := store.Get(context.Background(), "01920000-0000-7000-8000-000000000001")
	if !ok || u.Name != "Ayşe Yılmaz" || u.Gender != "female" {
		t.Fatalf("stored row = %+v (found %v)", u, ok)
	}
	if _, ok, _ := store.Get(context.Background(), "someone-else"); ok {
		t.Fatal("a row was written under a sub taken from the body")
	}
}

// The JS SDK posts {name: u.name ?? null, gender: u.gender ?? null}; null and
// missing fields are stored as "". profile_ver is NOT taken from the body: it
// comes from the verified access token's hayrat_profile_ver.
//
// MUTATION: read profile_ver from the body (or drop it) and the stored version
// is not 7.
func TestMeSync_NullsAndProfileVersionFromTheToken(t *testing.T) {
	idp := fakeidp.New(t)
	idp.SetUser(fakeidp.User{Sub: "01920000-0000-7000-8000-000000000001", ProfileVersion: 7})
	store := users.NewMemoryStore()
	h := newHandler(idp.NewVerifier(t, nil), store)
	token := idp.AccessToken(t, fakeidp.Audience, nil)

	body := `{"name":null,"gender":null,"profile_ver":99}`
	if got, b := fakeidp.Do(t, h, "POST", "/api/me/sync", token, body); got != http.StatusNoContent {
		t.Fatalf("sync = %d, want 204 (%s)", got, b)
	}
	u, ok, _ := store.Get(context.Background(), "01920000-0000-7000-8000-000000000001")
	if !ok || u.Name != "" || u.Gender != "" || u.ProfileVer != 7 {
		t.Fatalf("stored row = %+v (found %v), want empty name/gender and profile_ver 7", u, ok)
	}
}

// With CORS_ALLOWED_ORIGINS set, a cross-origin SPA's preflight is answered
// BEFORE authentication (a preflight never carries the token), and only for
// allow-listed origins.
//
// MUTATION: mount the CORS wrapper inside the auth middleware and the
// preflight is a 401; drop the allow-list check and the foreign origin gets
// Access-Control-Allow-Origin.
func TestCORS_PreflightBeforeAuth(t *testing.T) {
	idp := fakeidp.New(t)
	token := idp.AccessToken(t, fakeidp.Audience, nil)
	h := withCORS(newHandler(idp.NewVerifier(t, nil), users.NewMemoryStore()), []string{"https://app.example"})

	do := func(method, origin, bearer string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, "http://api.test/api/me", nil)
		req.Header.Set("Origin", origin)
		if method == http.MethodOptions {
			req.Header.Set("Access-Control-Request-Method", "GET")
			req.Header.Set("Access-Control-Request-Headers", "authorization")
		}
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	pre := do(http.MethodOptions, "https://app.example", "")
	if pre.Code != http.StatusNoContent || pre.Header().Get("Access-Control-Allow-Origin") != "https://app.example" ||
		!strings.Contains(strings.ToLower(pre.Header().Get("Access-Control-Allow-Headers")), "authorization") {
		t.Fatalf("allowed preflight = %d %v", pre.Code, pre.Header())
	}
	if got := do(http.MethodGet, "https://app.example", token); got.Code != http.StatusOK ||
		got.Header().Get("Access-Control-Allow-Origin") != "https://app.example" {
		t.Fatalf("allowed GET = %d %v", got.Code, got.Header())
	}
	foreign := do(http.MethodOptions, "https://evil.example", "")
	if foreign.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("foreign origin was allowed: %v", foreign.Header())
	}
	if got := do(http.MethodGet, "https://evil.example", token); got.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("foreign GET carries ACAO: %v", got.Header())
	}
}
