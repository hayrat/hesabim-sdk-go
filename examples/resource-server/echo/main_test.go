package main

import (
	"net/http"
	"testing"

	"github.com/hayrat/hesabim-sdk-go/examples/internal/fakeidp"
)

func TestResourceServer(t *testing.T) {
	idp := fakeidp.New(t)
	h := newServer(idp.NewVerifier(t, nil))

	moderatorIn601 := idp.AccessToken(t, fakeidp.Audience, []fakeidp.Grant{
		{Role: "moderator", Scopes: []fakeidp.Scope{{Type: "district", ID: 601}}},
	})
	otherProject := idp.AccessToken(t, "api:baska-proje", []fakeidp.Grant{{Role: "moderator"}})

	cases := []struct {
		name, path, token string
		want              int
	}{
		{"health needs no token", "/healthz", "", http.StatusOK},
		{"no token is 401", "/api/me", "", http.StatusUnauthorized},
		{"token for another API is 401", "/api/me", otherProject, http.StatusUnauthorized},
		{"valid token reaches the handler", "/api/me", moderatorIn601, http.StatusOK},
		{"granted district is allowed", "/api/districts/601/reports", moderatorIn601, http.StatusOK},
		{"other district is 403", "/api/districts/602/reports", moderatorIn601, http.StatusForbidden},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got, body := fakeidp.Do(t, h, "GET", c.path, c.token, ""); got != c.want {
				t.Fatalf("status = %d, want %d (body %q)", got, c.want, body)
			}
		})
	}
}
