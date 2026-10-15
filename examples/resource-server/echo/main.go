// Command echo is a Hesabım resource server on Echo v4.
//
// Wrap the SDK's net/http middleware with echo.WrapMiddleware — do not
// re-implement the Authorization header parsing; the stock middleware carries
// the RFC 6750 challenge semantics a hand-rolled version silently drops.
//
//	HESABIM_AUDIENCE=api:ornek-proje go run ./resource-server/echo
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	hesabim "github.com/hayrat/hesabim-sdk-go"
	"github.com/labstack/echo/v4"
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

	log.Fatal(newServer(verifier).Start(":8080"))
}

func newServer(v *hesabim.Verifier) *echo.Echo {
	e := echo.New()
	e.HideBanner = true
	e.GET("/healthz", func(c echo.Context) error { return c.NoContent(http.StatusOK) })

	api := e.Group("/api", echo.WrapMiddleware(v.Middleware))
	api.GET("/me", me)
	api.GET("/districts/:id/reports", districtReports)
	return e
}

// principal reads what the SDK middleware put on the request context.
func principal(c echo.Context) (*hesabim.Principal, error) {
	p, ok := hesabim.FromContext(c.Request().Context())
	if !ok {
		return nil, echo.NewHTTPError(http.StatusUnauthorized)
	}
	return p, nil
}

func me(c echo.Context) error {
	p, err := principal(c)
	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, map[string]any{"sub": p.Subject, "grants": p.Grants})
}

func districtReports(c echo.Context) error {
	p, err := principal(c)
	if err != nil {
		return err
	}
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil || id <= 0 {
		return echo.NewHTTPError(http.StatusNotFound)
	}
	if !p.Can("moderator", hesabim.Scope{Type: hesabim.ScopeTypeDistrict, ID: id}) {
		return echo.NewHTTPError(http.StatusForbidden)
	}
	return c.JSON(http.StatusOK, map[string]any{"district": id, "reports": []string{}})
}
