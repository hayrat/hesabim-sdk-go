package hesabim

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"math/big"
	"testing"
)

// jwksFrom renders a JWKS around hand-built entries.
func jwksFrom(t *testing.T, entries ...map[string]any) []byte {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"keys": entries})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return raw
}

// omitMarker asks mutate to DELETE a member rather than set it.
//
// It exists because "the member is absent" and "the member is present and null"
// are different documents that the acceptance rules treat differently, and a
// helper in which nil meant both could not express the second one. With this
// marker, `omitted` deletes and a literal nil marshals to a JSON null.
type omitMarker struct{}

var omitted = omitMarker{}

// mutate copies a JWK and applies edits, so each case differs from a KNOWN GOOD
// key in exactly one way. A test that built its own broken key from scratch
// could pass for the wrong reason.
func mutate(base map[string]any, edits map[string]any) map[string]any {
	out := make(map[string]any, len(base)+len(edits))
	for k, v := range base {
		out[k] = v
	}
	for k, v := range edits {
		if _, drop := v.(omitMarker); drop {
			delete(out, k)
			continue
		}
		out[k] = v
	}
	return out
}

func TestParseJWKS_AcceptanceMatrix(t *testing.T) {
	t.Parallel()

	good := newSigningKey(t, testKeyID).jwk()

	// A point that decodes to 32+32 bytes but is not on P-256: x from a real
	// key, y incremented. Nothing but the on-curve check catches this.
	offCurve := newSigningKey(t, "off-curve").jwk()
	{
		y, err := decodeCoordinate(offCurve["y"].(string))
		if err != nil {
			t.Fatalf("decode y: %v", err)
		}
		y.Add(y, big.NewInt(1))
		offCurve["y"] = b64(y.FillBytes(make([]byte, coordinateBytes)))
	}

	cases := []struct {
		name     string
		entry    map[string]any
		accepted bool
	}{
		{"the reference key", good, true},
		// ABSENT is the only tolerated alternative to the required value. These
		// three use the omit marker, so the member really is missing from the
		// serialised document rather than present as a null.
		{"use omitted", mutate(good, map[string]any{"use": omitted}), true},
		{"alg omitted", mutate(good, map[string]any{"alg": omitted}), true},
		{"key_ops omitted", mutate(good, map[string]any{"key_ops": omitted}), true},
		{"all three omitted", mutate(good, map[string]any{"use": omitted, "alg": omitted, "key_ops": omitted}), true},
		{"key_ops contains verify", mutate(good, map[string]any{"key_ops": []any{"verify"}}), true},
		{"key_ops contains verify among others", mutate(good, map[string]any{"key_ops": []any{"sign", "verify"}}), true},

		{"wrong kty", mutate(good, map[string]any{"kty": "RSA"}), false},
		{"wrong crv", mutate(good, map[string]any{"crv": "P-384"}), false},
		{"kid missing", mutate(good, map[string]any{"kid": omitted}), false},
		{"kid empty", mutate(good, map[string]any{"kid": ""}), false},
		{"use is enc", mutate(good, map[string]any{"use": "enc"}), false},
		{"alg is RS256", mutate(good, map[string]any{"alg": "RS256"}), false},
		{"alg is ES384", mutate(good, map[string]any{"alg": "ES384"}), false},
		{"key_ops present without verify", mutate(good, map[string]any{"key_ops": []any{"sign"}}), false},
		{"key_ops present and empty", mutate(good, map[string]any{"key_ops": []any{}}), false},

		// PRESENT-but-not-the-value. A null or an empty string is the document
		// saying something about the key, and what it says is not "sig" /
		// "ES256" / "verify". Reading either as absence would let a key the
		// issuer did not endorse verify signatures.
		{"use is explicitly null", mutate(good, map[string]any{"use": nil}), false},
		{"use is an empty string", mutate(good, map[string]any{"use": ""}), false},
		{"use is not a string", mutate(good, map[string]any{"use": 1}), false},
		{"alg is explicitly null", mutate(good, map[string]any{"alg": nil}), false},
		{"alg is an empty string", mutate(good, map[string]any{"alg": ""}), false},
		{"alg is not a string", mutate(good, map[string]any{"alg": []any{"ES256"}}), false},
		{"key_ops is explicitly null", mutate(good, map[string]any{"key_ops": nil}), false},
		{"key_ops is an empty string", mutate(good, map[string]any{"key_ops": ""}), false},
		{"key_ops holds an empty string", mutate(good, map[string]any{"key_ops": []any{""}}), false},
		{"x is 31 bytes", mutate(good, map[string]any{"x": b64(make([]byte, coordinateBytes-1))}), false},
		{"x is 33 bytes", mutate(good, map[string]any{"x": b64(make([]byte, coordinateBytes+1))}), false},
		{"y is 31 bytes", mutate(good, map[string]any{"y": b64(make([]byte, coordinateBytes-1))}), false},
		{"x is not base64url", mutate(good, map[string]any{"x": "!!!!"}), false},
		{"x is padded base64", mutate(good, map[string]any{"x": "AAAA===="}), false},
		{"point is off the curve", offCurve, false},
		{"point is the identity", mutate(good, map[string]any{
			"x": b64(make([]byte, coordinateBytes)),
			"y": b64(make([]byte, coordinateBytes)),
		}), false},
		{"a field has the wrong JSON type", mutate(good, map[string]any{"key_ops": "verify"}), false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			// Every document also carries a known-good key under another kid, so
			// an accepted/skipped verdict is observable without the "no usable
			// key" error standing in for it.
			companion := newSigningKey(t, "companion").jwk()
			keys, err := parseJWKS(jwksFrom(t, c.entry, companion))
			if err != nil {
				t.Fatalf("parseJWKS: %v", err)
			}

			kid, _ := c.entry["kid"].(string)
			if _, present := keys[kid]; present != c.accepted {
				t.Errorf("key %q accepted=%v, want %v", kid, present, c.accepted)
			}
			// An empty kid must never reach the map under ANY case: a key that
			// cannot be selected by a token is not usable, and letting it in
			// would also collapse every anonymous key into one slot, defeating
			// the duplicate check.
			if _, present := keys[""]; present {
				t.Error("a key with no kid was accepted; nothing could ever select it")
			}
			if _, ok := keys["companion"]; !ok {
				t.Error("a non-conforming key must be skipped silently, not take the document down")
			}
		})
	}
}

func TestParseJWKS_CoordinateWidthIsCheckedIndependentlyOfTheCurve(t *testing.T) {
	t.Parallel()

	// The case the fixed 32-byte width exists for, and the only one the
	// on-curve check cannot catch on its own: x and y are split 31/33 instead of
	// 32/32, so they CONCATENATE to a point that really is on the curve. A
	// reader that only checked the joined length would accept a key under a kid
	// whose published coordinates are something else entirely.
	real := newSigningKey(t, "split").key
	joined := make([]byte, 2*coordinateBytes)
	real.X.FillBytes(joined[:coordinateBytes])
	real.Y.FillBytes(joined[coordinateBytes:])

	entry := mutate(newSigningKey(t, "split").jwk(), map[string]any{
		"x": b64(joined[:coordinateBytes-1]),
		"y": b64(joined[coordinateBytes-1:]),
	})

	companion := newSigningKey(t, "companion").jwk()
	keys, err := parseJWKS(jwksFrom(t, entry, companion))
	if err != nil {
		t.Fatalf("parseJWKS: %v", err)
	}
	if _, present := keys["split"]; present {
		t.Error("a key whose coordinates are not 32 bytes each must be skipped, even when they concatenate to a valid point")
	}
}

func TestParseJWKS_DuplicateUsableKidRejectsTheDocument(t *testing.T) {
	t.Parallel()

	first := newSigningKey(t, "same-kid").jwk()
	second := newSigningKey(t, "same-kid").jwk()

	_, err := parseJWKS(jwksFrom(t, first, second))
	if !errors.Is(err, errAmbiguousJWKS) {
		t.Fatalf("want errAmbiguousJWKS for two usable keys under one kid, got %v", err)
	}
}

func TestParseJWKS_DuplicateKidIsOnlyAmbiguousWhenBothAreUsable(t *testing.T) {
	t.Parallel()

	usable := newSigningKey(t, "same-kid").jwk()
	// Same kid, but an encryption key: it never becomes a candidate, so there is
	// nothing ambiguous to refuse.
	unusable := mutate(newSigningKey(t, "same-kid").jwk(), map[string]any{"use": "enc"})

	keys, err := parseJWKS(jwksFrom(t, usable, unusable))
	if err != nil {
		t.Fatalf("parseJWKS: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("want 1 key, got %d", len(keys))
	}
}

func TestParseJWKS_EmptyAndMalformedDocuments(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		raw  string
		want error
	}{
		{"not JSON", "definitely not json", errMalformedJWKS},
		{"JSON but not an object", `["keys"]`, errMalformedJWKS},
		{"keys is null", `{"keys":null}`, errEmptyJWKS},
		{"keys is empty", `{"keys":[]}`, errEmptyJWKS},
		{"keys holds nothing usable", `{"keys":[{"kty":"RSA","kid":"a"}]}`, errEmptyJWKS},
		{"no keys member", `{}`, errEmptyJWKS},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			keys, err := parseJWKS([]byte(c.raw))
			if !errors.Is(err, c.want) {
				t.Fatalf("parseJWKS(%q) error = %v, want %v", c.raw, err, c.want)
			}
			if keys != nil {
				t.Error("a failed parse must not return keys — the cache would replace good keys with them")
			}
		})
	}
}

func TestParseJWKS_ProducesTheKeyThatVerifies(t *testing.T) {
	t.Parallel()

	// The acceptance matrix proves what is rejected; this proves the accepted
	// key is the RIGHT one, by checking a signature the private half made.
	signer := newSigningKey(t, testKeyID)
	keys, err := parseJWKS(jwksDocument(t, signer))
	if err != nil {
		t.Fatalf("parseJWKS: %v", err)
	}
	pub, ok := keys[testKeyID]
	if !ok {
		t.Fatal("the key is missing from the parsed set")
	}

	digest := [32]byte{1, 2, 3}
	r, s, err := ecdsa.Sign(rand.Reader, signer.key, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if !ecdsa.Verify(pub, digest[:], r, s) {
		t.Error("the parsed key does not verify a signature from its own private half")
	}
	if pub.Curve != elliptic.P256() {
		t.Errorf("curve = %v, want P-256", pub.Curve)
	}
}

func decodeCoordinate(encoded string) (*big.Int, error) {
	raw, err := b64decode(encoded)
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(raw), nil
}
