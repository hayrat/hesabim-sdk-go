package hesabim

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// maxBodyBytes caps every response this package reads.
//
// A discovery document is a few hundred bytes and a JWKS with a rotation
// overlap is a few thousand; 1 MiB is three orders of magnitude of headroom and
// still bounds the memory a hostile or broken origin can make a resource server
// allocate. Without a cap, an endless body is a one-request OOM.
const maxBodyBytes = 1 << 20

// discoveryPath is appended to the issuer. RFC 8414 fixes it, and the SDK
// hardcodes NO other path: everything else it talks to comes out of the
// document this one returns.
const discoveryPath = "/.well-known/openid-configuration"

// discoveryDocument is the subset of the OpenID Provider Metadata this project
// contracts on. The three endpoints a resource server never calls are parsed
// anyway so that a document pointing them somewhere insecure fails at boot
// rather than in whichever SDK does call them.
type discoveryDocument struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	EndSessionEndpoint    string `json:"end_session_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
}

// fetchDiscovery reads and validates the issuer's metadata.
//
// # The issuer binding is the whole point
//
// The document says who it belongs to, and if that does not equal the issuer
// the operator configured, this is not the issuer the operator configured. The
// check turns a misdirected discovery URL — a typo, a stale environment
// variable, a DNS answer from somewhere unexpected — into a boot failure
// instead of a resource server that happily trusts another party's signing
// keys.
//
// Normalisation is one trailing slash and nothing else. Case, port and path are
// significant, because `iss` comparison at verification time is byte equality
// and anything this function tolerates here it must tolerate there.
func fetchDiscovery(ctx context.Context, client *http.Client, issuer string) (discoveryDocument, error) {
	body, err := fetchBody(ctx, client, issuer+discoveryPath)
	if err != nil {
		return discoveryDocument{}, fmt.Errorf("hesabim: discovery: %w", err)
	}

	var doc discoveryDocument
	if err := json.Unmarshal(body, &doc); err != nil {
		// The parse error is dropped rather than wrapped: encoding/json quotes
		// the offending input, and this input came from the network.
		return discoveryDocument{}, errors.New("hesabim: discovery document is not a well-formed JSON object")
	}

	if normalizeIssuer(doc.Issuer) != issuer {
		return discoveryDocument{}, errors.New("hesabim: discovery document is issued by a different issuer than the configured one")
	}

	// http is allowed at all only for a local issuer; see checkAbsoluteURL.
	insecureOK := isLoopbackIssuer(issuer)

	if doc.JWKSURI == "" {
		return discoveryDocument{}, errors.New("hesabim: discovery document has no jwks_uri")
	}
	if err := checkAbsoluteURL(doc.JWKSURI, insecureOK); err != nil {
		return discoveryDocument{}, fmt.Errorf("hesabim: discovery jwks_uri: %w", err)
	}

	// The remaining endpoints are validated WHEN PRESENT but not required. A
	// resource server never calls them, and refusing to boot over a field it
	// will never read turns an issuer's configuration change into an outage
	// with no security benefit. A field that IS present and points at an
	// insecure or relative URL is still a hard error — that costs nothing and
	// catches a misconfigured deployment before its browser-side SDK does.
	for name, endpoint := range map[string]string{
		"authorization_endpoint": doc.AuthorizationEndpoint,
		"token_endpoint":         doc.TokenEndpoint,
		"end_session_endpoint":   doc.EndSessionEndpoint,
	} {
		if endpoint == "" {
			continue
		}
		if err := checkAbsoluteURL(endpoint, insecureOK); err != nil {
			return discoveryDocument{}, fmt.Errorf("hesabim: discovery %s: %w", name, err)
		}
	}

	return doc, nil
}

// fetchBody performs the one HTTP shape this package uses: GET, 2xx only,
// redirects already disabled by the client, body capped.
func fetchBody(ctx context.Context, client *http.Client, target string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		// A 3xx lands here too: the client hands redirects back instead of
		// following them, so "moved" and "unavailable" are one refusal.
		return nil, fmt.Errorf("%s responded %d", target, resp.StatusCode)
	}

	// One byte over the cap is read on purpose — it is how an over-long body is
	// distinguished from one that ends exactly at the limit.
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxBodyBytes {
		return nil, fmt.Errorf("%s responded with more than %d bytes", target, maxBodyBytes)
	}
	return body, nil
}

// normalizeIssuer strips the one difference that is not a difference.
func normalizeIssuer(issuer string) string {
	return strings.TrimSuffix(issuer, "/")
}

// checkAbsoluteURL enforces the transport rule shared by the issuer and every
// endpoint it advertises.
//
// # Why http survives at all
//
// A developer runs the issuer on their laptop, where there is no certificate
// and no reason for one: the traffic never leaves the machine. The exemption is
// therefore written against the two hostnames that CANNOT be reached from
// anywhere else — "localhost" and "127.0.0.1" — rather than against a flag,
// because a flag ends up set in production exactly once and that once is
// enough. Note that BOTH the issuer and the URL being checked must be local:
// a local issuer advertising a plaintext jwks_uri on a remote host is a key
// substitution channel, not a development convenience.
func checkAbsoluteURL(raw string, insecureOK bool) error {
	u, err := url.Parse(raw)
	if err != nil {
		return errors.New("is not a valid URL")
	}
	if !u.IsAbs() || u.Host == "" {
		return errors.New("is not an absolute URL")
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if insecureOK && isLoopbackHost(u.Hostname()) {
			return nil
		}
		return errors.New("must use https")
	default:
		return errors.New("must use https")
	}
}

// isLoopbackIssuer reports whether the configured issuer is one a developer is
// running locally.
func isLoopbackIssuer(issuer string) bool {
	u, err := url.Parse(issuer)
	if err != nil {
		return false
	}
	return isLoopbackHost(u.Hostname())
}

// isLoopbackHost lists the two names the contract exempts, and only those. "::1"
// is absent deliberately: widening a security exemption beyond what is written
// down is how exemptions stop being exemptions.
func isLoopbackHost(host string) bool {
	return host == "localhost" || host == "127.0.0.1"
}
