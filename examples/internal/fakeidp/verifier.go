package fakeidp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	hesabim "github.com/hayrat/hesabim-sdk-go"
)

// Audience is the API identifier the example tests use.
const Audience = "api:ornek-proje"

// NewVerifier builds a real SDK verifier against the fake issuer.
func (f *IdP) NewVerifier(t testing.TB, resolver hesabim.ScopeResolver) *hesabim.Verifier {
	t.Helper()
	v, err := hesabim.New(context.Background(), hesabim.Config{
		IssuerURL: f.Issuer(),
		Audience:  Audience,
		Resolver:  resolver,
	})
	if err != nil {
		t.Fatalf("hesabim.New: %v", err)
	}
	return v
}

// Do sends a request to h and returns status and body.
func Do(t testing.TB, h http.Handler, method, path, bearer, body string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(method, "http://app.test"+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code, rec.Body.String()
}
