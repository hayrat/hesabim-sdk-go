// Command gin is a Hesabım resource server on Gin.
//
// Gin has no adapter for net/http middleware, so hesabimAuth below runs the
// SDK's middleware and continues the Gin chain only when it let the request
// through. Copy that function as is.
//
//	HESABIM_AUDIENCE=api:ornek-proje go run ./resource-server/gin
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
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

	log.Fatal(newRouter(verifier).Run(":8080"))
}

// hesabimAuth adapts the SDK middleware to Gin. On success the verified
// request (carrying the Principal in its context) replaces c.Request; on
// failure the SDK has already written the 401 and the chain is aborted.
func hesabimAuth(v *hesabim.Verifier) gin.HandlerFunc {
	return func(c *gin.Context) {
		passed := false
		v.Middleware(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			passed = true
			c.Request = r
		})).ServeHTTP(c.Writer, c.Request)
		if !passed {
			c.Abort()
			return
		}
		c.Next()
	}
}

func newRouter(v *hesabim.Verifier) *gin.Engine {
	r := gin.New()
	r.GET("/healthz", func(c *gin.Context) { c.Status(http.StatusOK) })

	api := r.Group("/api", hesabimAuth(v))
	api.GET("/me", me)
	api.GET("/districts/:id/reports", districtReports)
	return r
}

func me(c *gin.Context) {
	p, ok := hesabim.FromContext(c.Request.Context())
	if !ok {
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}
	c.JSON(http.StatusOK, gin.H{"sub": p.Subject, "grants": p.Grants})
}

func districtReports(c *gin.Context) {
	p, ok := hesabim.FromContext(c.Request.Context())
	if !ok {
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil || id <= 0 {
		c.AbortWithStatus(http.StatusNotFound)
		return
	}
	if !p.Can("moderator", hesabim.Scope{Type: hesabim.ScopeTypeDistrict, ID: id}) {
		c.AbortWithStatus(http.StatusForbidden)
		return
	}
	c.JSON(http.StatusOK, gin.H{"district": id, "reports": []string{}})
}
