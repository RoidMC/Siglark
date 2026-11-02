package nxs

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"strconv"
	"strings"
)

// PublicJWK is a canonical EC/P-384 public key as sent by hosts.
type PublicJWK struct {
	Crv string `json:"crv"`
	Kty string `json:"kty"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

type publicJWKWire struct {
	Crv string  `json:"crv"`
	Kty string  `json:"kty"`
	X   string  `json:"x"`
	Y   string  `json:"y"`
	D   *string `json:"d"`
}

// Base64URL encodes bytes as unpadded base64url.
func Base64URL(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// DecodeBase64URL decodes strictly canonical unpadded base64url and enforces
// the expected byte length when want >= 0.
func DecodeBase64URL(s string, want int) ([]byte, error) {
	if s == "" || strings.ContainsAny(s, "=+/ \t\r\n") {
		return nil, fmt.Errorf("noncanonical base64url")
	}
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("noncanonical base64url")
	}
	if Base64URL(b) != s {
		return nil, fmt.Errorf("noncanonical base64url")
	}
	if want >= 0 && len(b) != want {
		return nil, fmt.Errorf("base64url length %d, want %d", len(b), want)
	}
	return b, nil
}

// ParsePublicJWK validates a host public JWK and returns the key material.
func ParsePublicJWK(raw json.RawMessage) (*PublicJWK, *ecdsa.PublicKey, error) {
	var w publicJWKWire
	if err := json.Unmarshal(raw, &w); err != nil {
		return nil, nil, fmt.Errorf("malformed publicKeyJwk: %w", err)
	}
	if w.D != nil {
		return nil, nil, fmt.Errorf("publicKeyJwk must not contain d")
	}
	if w.Crv != "P-384" || w.Kty != "EC" {
		return nil, nil, fmt.Errorf("publicKeyJwk must be EC/P-384")
	}
	xb, err := DecodeBase64URL(w.X, 48)
	if err != nil {
		return nil, nil, fmt.Errorf("publicKeyJwk.x: %w", err)
	}
	yb, err := DecodeBase64URL(w.Y, 48)
	if err != nil {
		return nil, nil, fmt.Errorf("publicKeyJwk.y: %w", err)
	}
	point := append([]byte{4}, append(xb, yb...)...)
	px, py := elliptic.Unmarshal(elliptic.P384(), point)
	if px == nil {
		return nil, nil, fmt.Errorf("publicKeyJwk is not a valid P-384 point")
	}
	key := &PublicJWK{Crv: "P-384", Kty: "EC", X: w.X, Y: w.Y}
	return key, &ecdsa.PublicKey{Curve: elliptic.P384(), X: px, Y: py}, nil
}

// Thumbprint returns the RFC 7638 thumbprint (crv,kty,x,y member order).
func (k *PublicJWK) Thumbprint() string {
	text := `{"crv":"` + k.Crv + `","kty":"` + k.Kty + `","x":"` + k.X + `","y":"` + k.Y + `"}`
	sum := sha256.Sum256([]byte(text))
	return Base64URL(sum[:])
}

// SignP384 signs payload with ES384 and returns the P1363 r||s form.
func SignP384(priv *ecdsa.PrivateKey, payload []byte) (string, error) {
	digest := sha512.Sum384(payload)
	r, s, err := ecdsa.Sign(rand.Reader, priv, digest[:])
	if err != nil {
		return "", err
	}
	out := make([]byte, 96)
	r.FillBytes(out[:48])
	s.FillBytes(out[48:])
	return Base64URL(out), nil
}

// VerifyES384 verifies a P1363 ES384 signature encoded as unpadded base64url.
func VerifyES384(pub *ecdsa.PublicKey, payload []byte, sig string) error {
	raw, err := DecodeBase64URL(sig, 96)
	if err != nil {
		return err
	}
	digest := sha512.Sum384(payload)
	r := new(big.Int).SetBytes(raw[:48])
	s := new(big.Int).SetBytes(raw[48:])
	if !ecdsa.Verify(pub, digest[:], r, s) {
		return fmt.Errorf("signature verification failed")
	}
	return nil
}

// CanonicalJSON renders a JSON array exactly like ECMA-262 JSON.stringify:
// no whitespace, UTF-8 strings unescaped beyond JSON control rules.
func CanonicalJSON(values ...any) []byte {
	var b strings.Builder
	b.WriteByte('[')
	for i, v := range values {
		if i > 0 {
			b.WriteByte(',')
		}
		switch x := v.(type) {
		case string:
			writeJSONString(&b, x)
		case int:
			b.WriteString(strconv.Itoa(x))
		case int64:
			b.WriteString(strconv.FormatInt(x, 10))
		case uint64:
			b.WriteString(strconv.FormatUint(x, 10))
		default:
			panic(fmt.Sprintf("nxs: unsupported canonical JSON type %T", v))
		}
	}
	b.WriteByte(']')
	return []byte(b.String())
}

func writeJSONString(b *strings.Builder, s string) {
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(b, `\u%04x`, r)
				continue
			}
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
}

// BodySHA256 is the base64url SHA-256 of the request body bytes.
func BodySHA256(body []byte) string {
	sum := sha256.Sum256(body)
	return Base64URL(sum[:])
}

// LeadingZeroBits counts leading zero bits in the SHA-256 of payload.
func LeadingZeroBits(payload []byte) int {
	sum := sha256.Sum256(payload)
	n := 0
	for _, v := range sum {
		if v == 0 {
			n += 8
			continue
		}
		for mask := byte(0x80); mask != 0; mask >>= 1 {
			if v&mask == 0 {
				n++
				continue
			}
			return n
		}
		return n
	}
	return n
}

// ChallengeContext is the signed registration context. Missing strings digest
// as empty strings.
type ChallengeContext struct {
	Mode            string `json:"mode"`
	Label           string `json:"label,omitempty"`
	AuthorizationID string `json:"authorizationId,omitempty"`
	ServiceID       string `json:"serviceId,omitempty"`
	RegistrationID  string `json:"registrationId,omitempty"`
}

// ContextDigest is base64url(SHA-256(canonical [mode,label,authorizationId,serviceId,registrationId])).
func ContextDigest(c ChallengeContext) string {
	sum := sha256.Sum256(CanonicalJSON(c.Mode, c.Label, c.AuthorizationID, c.ServiceID, c.RegistrationID))
	return Base64URL(sum[:])
}

// CompleteProofPayload builds the completion proof array.
func CompleteProofPayload(audience, challengeID, nonce, thumbprint, contextDigest string, expiresAt int64, proofNonce, idempotencyKey string) []byte {
	return CanonicalJSON(Protocol, "complete", audience, challengeID, nonce, thumbprint,
		contextDigest, expiresAt, proofNonce, idempotencyKey)
}

// RequestPayload builds the signed operational request array.
func RequestPayload(audience, method, path string, timestamp int64, instanceID, keyID, idempotencyKey string, generation, sequence int64, body []byte) []byte {
	return CanonicalJSON(Protocol, SignatureVersion, audience, method, path, timestamp,
		instanceID, keyID, idempotencyKey, generation, sequence, BodySHA256(body))
}

// RotateProofPayload builds the rotation proof array.
func RotateProofPayload(audience, instanceID, oldKeyID, newThumbprint string, generation int64, idempotencyKey string) []byte {
	return CanonicalJSON(Protocol, "rotate", audience, instanceID, oldKeyID, newThumbprint, generation, idempotencyKey)
}

// VerifyCompleteProof verifies the 10-tuple completion signature.
func VerifyCompleteProof(pub *ecdsa.PublicKey, audience, challengeID, nonce, thumbprint, contextDigest string, expiresAt int64, proofNonce, idempotencyKey, signature string) error {
	payload := CompleteProofPayload(audience, challengeID, nonce, thumbprint, contextDigest, expiresAt, proofNonce, idempotencyKey)
	if err := VerifyES384(pub, payload, signature); err != nil {
		return errInvalidSignature("The completion signature is invalid.")
	}
	return nil
}
