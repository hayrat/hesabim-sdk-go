package hesabim

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"slices"
)

// The JWKS reader is HAND-WRITTEN, and that is a deliberate dependency choice.
//
// A general JOSE library parses key types this issuer will never mint, in
// formats this issuer will never emit, behind configuration this package would
// have to get right. The issuer signs with ES256 over P-256 and nothing else
// (its signing-key policy), so the reader below is thirty lines of
// filter and one curve. Fewer lines of somebody else's parser stand between a
// hostile JWKS document and a verification key.
//
// The filter is also the SECURITY boundary. Everything after it assumes a key
// is a P-256 point that the issuer intends to be used for verification, so
// every one of those words is checked here.

// coordinateBytes is the fixed width of a P-256 coordinate. RFC 7518 §6.2.1.2
// requires the octet string to be the full field size, left-padded — 31 bytes
// is not "the same number, shorter", it is a document that does not follow the
// spec, and accepting it means accepting a second encoding of the same key.
const coordinateBytes = 32

// jwk is one entry of a JWKS, in the only shape this package accepts.
type jwk struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	Kid string `json:"kid"`
	X   string `json:"x"`
	Y   string `json:"y"`

	// The three OPTIONAL members are held as raw JSON so that ABSENT can be
	// told apart from PRESENT-but-something-else.
	//
	// Decoding them into a string or a slice would collapse the distinction:
	// `"use": null` and `"use": ""` both unmarshal to the empty string, which
	// would then read as "the member was omitted" and let the key through. RFC
	// 7517 makes these members optional, not nullable — a document that spells
	// one out is saying something about the key, and the only value that says
	// "usable for verifying this issuer's signatures" is the specific one. A
	// null is not that value, and neither is an empty string.
	Use    json.RawMessage `json:"use"`
	Alg    json.RawMessage `json:"alg"`
	KeyOps json.RawMessage `json:"key_ops"`
}

// absentOrExactly reports whether an optional string member is either missing
// entirely or present with exactly the required value.
//
// A nil RawMessage is the absent case — encoding/json leaves the field
// untouched when the member does not appear, and writes the four bytes `null`
// when it does appear as a null, which is what makes the two distinguishable
// here and nowhere else.
func absentOrExactly(raw json.RawMessage, want string) bool {
	if len(raw) == 0 {
		return true
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		// A number, an object, an array: present and not a string.
		return false
	}
	// `null` unmarshals into a string without error and leaves it empty, so it
	// lands here alongside `""` — both are present-but-not-the-value.
	return value == want
}

// absentOrPermitsVerify reports whether key_ops is missing entirely or present
// and includes "verify".
//
// `[]` and `null` are both refusals: the first is the issuer saying this key
// may be used for nothing, the second is present-but-not-a-list. Reading either
// as "unrestricted" would invert the member's meaning.
func absentOrPermitsVerify(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return true
	}
	var ops []string
	if err := json.Unmarshal(raw, &ops); err != nil {
		return false
	}
	return slices.Contains(ops, "verify")
}

// parseJWKS turns a JWKS document into the keys this package will verify with,
// indexed by kid.
//
// # Three outcomes, and the difference between them matters
//
//   - A key that does not pass the filter is SKIPPED, silently. A JWKS is a
//     public directory that may legitimately carry keys for encryption, for
//     another algorithm, or for a future the reader has not been taught. Failing
//     the whole document because one entry is unfamiliar would mean the issuer
//     cannot add a key type without breaking every deployed resource server.
//
//   - Two USABLE keys sharing a kid rejects the whole document. A kid is the
//     token's instruction for which key to use; two answers means the reader has
//     to choose, and "try both" is how a retired key keeps verifying tokens
//     forever. Ambiguity in key selection is not a thing to resolve, it is a
//     thing to refuse.
//
//   - No usable key at all is an error, not an empty set. An empty set would
//     make every token fail with "unknown kid", which reads as a token problem
//     and is not; and an error is what lets the cache keep the keys it already
//     had (see keyCache) instead of replacing them with nothing.
func parseJWKS(raw []byte) (map[string]*ecdsa.PublicKey, error) {
	// Keys are held raw and decoded one at a time so that a single entry with a
	// wrong FIELD TYPE — key_ops as a string, x as a number — is skipped like
	// any other non-conforming key instead of failing the document. Rejecting
	// the set for a neighbour's malformed field is the same brittleness the
	// silent-skip rule exists to avoid.
	var doc struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, errMalformedJWKS
	}

	keys := make(map[string]*ecdsa.PublicKey, len(doc.Keys))
	for _, entry := range doc.Keys {
		var k jwk
		if err := json.Unmarshal(entry, &k); err != nil {
			continue
		}
		pub, ok := k.publicKey()
		if !ok {
			continue
		}
		if _, duplicate := keys[k.Kid]; duplicate {
			return nil, errAmbiguousJWKS
		}
		keys[k.Kid] = pub
	}

	if len(keys) == 0 {
		return nil, errEmptyJWKS
	}
	return keys, nil
}

// publicKey applies the acceptance rules and returns the verification key, or
// reports that this entry is not one.
//
// The `use`, `key_ops` and `alg` rules are all of the "absent or exactly this"
// shape. Absent is permitted because RFC 7517 makes all three optional and a
// conforming issuer may omit them; anything else PRESENT is the issuer telling
// the reader something other than "use this key to verify", and there is no
// reading of "this key is for encryption" — or of an explicit null — under
// which verifying a signature with it is correct.
func (k jwk) publicKey() (*ecdsa.PublicKey, bool) {
	if k.Kty != "EC" || k.Crv != "P-256" {
		return nil, false
	}
	if k.Kid == "" {
		// Without a kid the key cannot be selected by a token, so it is not
		// usable here even if the arithmetic is perfect. Accepting it would also
		// mean the duplicate check above collapses every anonymous key into one
		// slot.
		return nil, false
	}
	if !absentOrExactly(k.Use, "sig") {
		return nil, false
	}
	if !absentOrExactly(k.Alg, "ES256") {
		return nil, false
	}
	if !absentOrPermitsVerify(k.KeyOps) {
		return nil, false
	}

	x, err := base64.RawURLEncoding.DecodeString(k.X)
	if err != nil || len(x) != coordinateBytes {
		return nil, false
	}
	y, err := base64.RawURLEncoding.DecodeString(k.Y)
	if err != nil || len(y) != coordinateBytes {
		return nil, false
	}

	// ParseUncompressedPublicKey does the check that cannot be skipped: that
	// (x, y) is ON the curve and is not the identity. A point off the curve is
	// not a slow-failing key, it is the input to an invalid-curve attack, and
	// the only safe moment to refuse it is before it reaches the verifier.
	point := make([]byte, 0, 1+2*coordinateBytes)
	point = append(point, 4) // uncompressed point marker, SEC 1 §2.3.3
	point = append(point, x...)
	point = append(point, y...)

	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), point)
	if err != nil {
		return nil, false
	}
	return pub, true
}
