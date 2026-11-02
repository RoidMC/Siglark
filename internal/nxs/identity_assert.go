package nxs

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
	"time"
)

// HostIdentity signs the server identity assertion a Bedrock client expects in
// an answer SDP. Geyser's built-in signaling embeds one for itself; its assisted
// path never does, so the provider mints the assertion on the host's behalf
// from the same PEM the host uses (mirroring OperatorIdentity: an ES384
// self-signed token carrying the P-384 public key, plus a detached ES384 JWS
// over the answer's canonical fingerprint JSON).
type HostIdentity struct {
	key    *ecdsa.PrivateKey
	domain string
}

// LoadHostIdentity reads a PEM file holding a P-384 private key (SEC1
// "EC PRIVATE KEY" or PKCS#8) and returns an identity signer.
func LoadHostIdentity(path, domain string) (*HostIdentity, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var key *ecdsa.PrivateKey
	rest := raw
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		switch block.Type {
		case "EC PRIVATE KEY":
			parsed, err := x509.ParseECPrivateKey(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("identity pem: %w", err)
			}
			key = parsed
		case "PRIVATE KEY":
			parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("identity pem: %w", err)
			}
			ec, ok := parsed.(*ecdsa.PrivateKey)
			if !ok {
				return nil, fmt.Errorf("identity pem: key is %T, want EC", parsed)
			}
			key = ec
		}
		if key != nil {
			break
		}
	}
	if key == nil {
		return nil, fmt.Errorf("identity pem: no private key block in %s", path)
	}
	if key.Curve != elliptic.P384() {
		return nil, fmt.Errorf("identity pem: curve is %s, want P-384", key.Curve.Params().Name)
	}
	return &HostIdentity{key: key, domain: domain}, nil
}

// Assertion builds the base64 identity value for an answer SDP, matching
// Geyser's OperatorIdentity.identityValue: a detached ES384 JWS over the
// canonical fingerprint JSON of the answer, wrapped with the self-signed
// server token into {"idp":...,"assertion":{...}} and base64-encoded.
func (h *HostIdentity) Assertion(answer string) (string, error) {
	fingerprints, err := CanonicalFingerprintJSON(answer)
	if err != nil {
		return "", fmt.Errorf("identity assertion: %w", err)
	}
	compact, err := h.sign([]byte(fingerprints))
	if err != nil {
		return "", fmt.Errorf("identity assertion: %w", err)
	}
	// The fingerprints attribute keeps the empty payload segment:
	// "<header>..<signature>" (Geyser joins parts 0 and 2 with two dots).
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("identity assertion: malformed compact JWS")
	}
	detached := parts[0] + ".." + parts[2]

	spki, err := x509.MarshalPKIXPublicKey(&h.key.PublicKey)
	if err != nil {
		return "", fmt.Errorf("identity assertion: %w", err)
	}
	claims, err := json.Marshal(serverTokenClaims{
		CPK: base64.StdEncoding.EncodeToString(spki),
		IAT: time.Now().Unix(),
		ISS: h.domain,
	})
	if err != nil {
		return "", fmt.Errorf("identity assertion: %w", err)
	}
	token, err := h.sign(claims)
	if err != nil {
		return "", fmt.Errorf("identity assertion: %w", err)
	}

	// The assertion is serialized as an escaped JSON string, not a nested
	// object: {"idp":{"domain":"Siglark-SelfhostNXS","protocol":"default"},
	// "assertion":"{\"token\":\"...\",\"fingerprints\":\"..sig\"}"}. The client
	// parses the string itself, so the shape has to match exactly.
	inner := `{"token":"` + token + `","fingerprints":"` + detached + `"}`
	domain, err := json.Marshal(h.domain)
	if err != nil {
		return "", fmt.Errorf("identity assertion: %w", err)
	}
	assertion, err := json.Marshal(inner)
	if err != nil {
		return "", fmt.Errorf("identity assertion: %w", err)
	}
	value := `{"idp":{"domain":` + string(domain) + `,"protocol":"default"},"assertion":` + string(assertion) + `}`
	return base64.StdEncoding.EncodeToString([]byte(value)), nil
}

// sign produces an ES384 compact JWS: base64url parts, IEEE-P1363 signature.
func (h *HostIdentity) sign(payload []byte) (string, error) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES384"}`))
	body := base64.RawURLEncoding.EncodeToString(payload)
	digest := sha512.Sum384([]byte(header + "." + body))
	r, s, err := ecdsa.Sign(rand.Reader, h.key, digest[:])
	if err != nil {
		return "", err
	}
	sig := make([]byte, 96)
	r.FillBytes(sig[:48])
	s.FillBytes(sig[48:])
	return header + "." + body + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// serverTokenClaims is the self-signed token embedded in the assertion. Only
// presence differs from the client-side token: no xid, xname or expiry.
type serverTokenClaims struct {
	CPK string `json:"cpk"`
	IAT int64  `json:"iat"`
	ISS string `json:"iss,omitempty"`
}

// InsertIdentityAttribute places "a=identity:<value>" immediately before the
// first media line, exactly where Geyser's withAssertion puts it.
func InsertIdentityAttribute(answer, value string) string {
	line := "a=identity:" + value
	lines := strings.Split(strings.TrimRight(answer, "\r\n"), "\r\n")
	out := make([]string, 0, len(lines)+1)
	inserted := false
	for _, l := range lines {
		if !inserted && strings.HasPrefix(l, "m=") {
			out = append(out, line)
			inserted = true
		}
		out = append(out, l)
	}
	if !inserted {
		out = append(out, line)
	}
	return strings.Join(out, "\r\n") + "\r\n"
}
