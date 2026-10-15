package hesabim

import (
	"testing"
)

// FuzzParseJWKS drives the one parser in this package that reads
// attacker-reachable bytes before any signature has been checked.
//
// # What it asserts, and why it is not "does not panic"
//
// A panic in a resource server's request path is a denial of service, so
// surviving arbitrary input is the floor. The ceiling is the invariants
// everything downstream ASSUMES about a parsed key set — that every kid is
// non-empty and unique, and every key is a genuine P-256 point — because those
// assumptions are what make the verifier's key selection unambiguous. A parser
// that returned an empty map, or two keys under one kid, or a point off the
// curve, would not crash anything; it would quietly make key selection or
// signature verification wrong, which is worse.
//
// The seeds are the corpus the unit tests already care about, so a CI run that
// never fuzzes still exercises every one of them.
func FuzzParseJWKS(f *testing.F) {
	valid := string(jwksDocument(f, newSigningKey(f, "fuzz-seed")))

	seeds := []string{
		valid,
		"",
		"{}",
		"null",
		"[]",
		`{"keys":null}`,
		`{"keys":[]}`,
		`{"keys":[{}]}`,
		`{"keys":{}}`,
		`{"keys":[{"kty":"EC","crv":"P-256","kid":"a","x":"","y":""}]}`,
		`{"keys":[{"kty":"EC","crv":"P-256","kid":"a","x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","y":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}]}`,
		`{"keys":[{"kty":"EC","crv":"P-256","kid":"a","x":"!!!","y":"!!!"}]}`,
		`{"keys":[{"kty":"EC","crv":"P-521","kid":"a","x":"AA","y":"AA"}]}`,
		`{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"a","x":"AA"}]}`,
		`{"keys":[{"kty":"EC","crv":"P-256","kid":"","x":"AA","y":"AA"}]}`,
		`{"keys":[{"kty":"EC","crv":"P-256","kid":"a","key_ops":"verify","x":"AA","y":"AA"}]}`,
		`{"keys":[{"kty":"EC","crv":"P-256","kid":"a","use":"enc","x":"AA","y":"AA"}]}`,
		// Two entries under one kid: the ambiguity case, which must be an error
		// rather than a silent choice.
		`{"keys":[{"kty":"EC","crv":"P-256","kid":"a"},{"kty":"EC","crv":"P-256","kid":"a"}]}`,
		// Deep nesting and a very long string, the two shapes that most often
		// find a parser's stack or allocation limits.
		`{"keys":[[[[[[[[[[]]]]]]]]]]}`,
		`{"keys":[{"kty":"EC","crv":"P-256","kid":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]}`,
	}
	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, raw string) {
		keys, err := parseJWKS([]byte(raw))
		if err != nil {
			if keys != nil {
				t.Errorf("parseJWKS returned %d keys alongside error %v; a failed parse must yield nothing", len(keys), err)
			}
			return
		}

		if len(keys) == 0 {
			t.Error("parseJWKS reported success with an empty key set")
		}
		for kid, key := range keys {
			if kid == "" {
				t.Error("parseJWKS accepted a key with an empty kid; it could never be selected by a token")
			}
			if !onCurveP256(key) {
				t.Errorf("parseJWKS accepted a key under kid %q that is not a valid P-256 point", kid)
			}
		}
	})
}
