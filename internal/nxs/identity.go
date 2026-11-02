package nxs

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

// IdentityTrust selects how a client's signaling token is trusted.
type IdentityTrust string

const (
	// TrustMinecraftAuth validates the token against Minecraft's authorization
	// service keys, which is what a retail client presents.
	TrustMinecraftAuth IdentityTrust = "minecraft"
	// TrustAny reads the claims without checking the signer. The cpk binding is
	// still verified, so the peer must hold the key its token names.
	TrustAny IdentityTrust = "any"
)

const (
	minecraftJWKSUrl     = "https://authorization.franchise.minecraft-services.net/.well-known/keys"
	minecraftAudience    = "api://auth-minecraft-services/multiplayer"
	minecraftIssuer      = "https://authorization.franchise.minecraft-services.net/"
	minecraftKeyCacheTTL = time.Hour
)

// ClientIdentity is the decoded a=identity attribute of an offer.
type ClientIdentity struct {
	Domain          string
	Protocol        string
	Token           string
	FingerprintsJWS string
}

// VerifiedIdentity is the result of checking a client's signaling assertion.
type VerifiedIdentity struct {
	// CPK is the canonical standard base64 SPKI DER from the token's cpk claim.
	CPK string
	// CPKDER is the decoded canonical key, used for the identity binding MAC.
	CPKDER []byte
	XUID   string
	XName  string
	// TokenAlg and TokenIssuer describe how the assertion was signed, so
	// operators can confirm which trust path a client used.
	TokenAlg    string
	TokenIssuer string
	TokenKeyID  string
}

// IdentityVerifier validates client signaling assertions. It is safe for
// concurrent use.
type IdentityVerifier struct {
	trust IdentityTrust
	http  *http.Client

	mu       sync.Mutex
	keys     map[string]signingKey
	keyOrder []string
	fetched  time.Time
}

// signingKey is one entry of the authorization key set: Minecraft publishes
// RSA keys for account tokens.
type signingKey struct {
	ec  *ecdsa.PublicKey
	rsa *rsa.PublicKey
}

// NewIdentityVerifier builds a verifier for the given trust policy.
func NewIdentityVerifier(trust IdentityTrust) *IdentityVerifier {
	if trust != TrustAny {
		trust = TrustMinecraftAuth
	}
	return &IdentityVerifier{
		trust: trust,
		http:  &http.Client{Timeout: 10 * time.Second},
	}
}

// Trust returns the policy in force.
func (v *IdentityVerifier) Trust() IdentityTrust { return v.trust }

// ParseClientIdentity decodes the offer's a=identity attribute.
func ParseClientIdentity(sdp string) (*ClientIdentity, error) {
	var raw string
	for _, line := range splitSDP(sdp) {
		if strings.HasPrefix(line, "a=identity:") {
			raw = strings.TrimSpace(strings.TrimPrefix(line, "a=identity:"))
			break
		}
	}
	if raw == "" {
		return nil, fmt.Errorf("offer carries no identity assertion")
	}
	decoded, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("identity assertion is not standard base64")
	}
	var outer struct {
		Idp struct {
			Domain   string `json:"domain"`
			Protocol string `json:"protocol"`
		} `json:"idp"`
		Assertion string `json:"assertion"`
	}
	if err := json.Unmarshal(decoded, &outer); err != nil {
		return nil, fmt.Errorf("identity assertion is not JSON")
	}
	if outer.Assertion == "" {
		return nil, fmt.Errorf("identity assertion is empty")
	}
	var inner struct {
		Token        string `json:"token"`
		Fingerprints string `json:"fingerprints"`
	}
	if err := json.Unmarshal([]byte(outer.Assertion), &inner); err != nil {
		return nil, fmt.Errorf("identity assertion is malformed")
	}
	if inner.Token == "" || inner.Fingerprints == "" {
		return nil, fmt.Errorf("identity assertion lacks a token or fingerprint proof")
	}
	return &ClientIdentity{
		Domain:          outer.Idp.Domain,
		Protocol:        outer.Idp.Protocol,
		Token:           inner.Token,
		FingerprintsJWS: inner.Fingerprints,
	}, nil
}

// Verify checks the token under the configured trust and proves the assertion
// holds the key that signed the offer's fingerprints.
func (v *IdentityVerifier) Verify(sdp string, offer *ClientOffer, now time.Time) (*VerifiedIdentity, error) {
	identity, err := ParseClientIdentity(sdp)
	if err != nil {
		return nil, err
	}
	parts, err := parseJWT(identity.Token)
	if err != nil {
		return nil, err
	}
	if err := v.trustToken(parts, now); err != nil {
		return nil, err
	}
	cpk := stringClaim(parts.claims, "cpk")
	if cpk == "" {
		return nil, fmt.Errorf("the token does not name a client public key")
	}
	der, pub, err := canonicalCPK(cpk)
	if err != nil {
		return nil, err
	}

	fingerprints, err := CanonicalFingerprintJSON(sdp)
	if err != nil {
		return nil, err
	}
	if len(offer.Fingerprints) == 0 {
		return nil, fmt.Errorf("offer has no fingerprints")
	}
	if err := verifyDetachedJWS(pub, identity.FingerprintsJWS, fingerprints); err != nil {
		return nil, err
	}
	return &VerifiedIdentity{
		CPK:         cpk,
		CPKDER:      der,
		XUID:        stringClaim(parts.claims, "xid"),
		XName:       stringClaim(parts.claims, "xname"),
		TokenAlg:    stringClaim(parts.header, "alg"),
		TokenIssuer: stringClaim(parts.claims, "iss"),
		TokenKeyID:  stringClaim(parts.header, "kid"),
	}, nil
}

type jwtParts struct {
	headerB64  string
	payloadB64 string
	sigB64     string
	header     map[string]any
	claims     map[string]any
}

func parseJWT(token string) (*jwtParts, error) {
	fields := strings.Split(token, ".")
	if len(fields) != 3 {
		return nil, fmt.Errorf("the identity token is not a JWT")
	}
	headerRaw, err := base64.RawURLEncoding.DecodeString(fields[0])
	if err != nil {
		return nil, fmt.Errorf("the identity token header is malformed")
	}
	payloadRaw, err := base64.RawURLEncoding.DecodeString(fields[1])
	if err != nil {
		return nil, fmt.Errorf("the identity token payload is malformed")
	}
	parts := &jwtParts{headerB64: fields[0], payloadB64: fields[1], sigB64: fields[2]}
	if err := json.Unmarshal(headerRaw, &parts.header); err != nil {
		return nil, fmt.Errorf("the identity token header is not JSON")
	}
	dec := json.NewDecoder(strings.NewReader(string(payloadRaw)))
	dec.UseNumber()
	if err := dec.Decode(&parts.claims); err != nil {
		return nil, fmt.Errorf("the identity token payload is not JSON")
	}
	return parts, nil
}

func (v *IdentityVerifier) trustToken(parts *jwtParts, now time.Time) error {
	exp, ok := numberClaim(parts.claims, "exp")
	if !ok || exp <= 0 {
		return fmt.Errorf("the identity token carries no expiry")
	}
	if now.Unix() >= exp {
		return fmt.Errorf("the identity token has expired")
	}
	if v.trust != TrustMinecraftAuth {
		return nil
	}
	if strings.TrimSpace(stringClaim(parts.claims, "sub")) == "" {
		return fmt.Errorf("the identity token carries no subject")
	}
	if !hasAudience(parts.claims, minecraftAudience) {
		return fmt.Errorf("the identity token audience is not accepted (aud=%v)", parts.claims["aud"])
	}
	if iss := stringClaim(parts.claims, "iss"); iss != minecraftIssuer {
		return fmt.Errorf("the identity token issuer is not accepted (iss=%q)", iss)
	}
	alg := stringClaim(parts.header, "alg")
	if !tokenAlgSupported(alg) {
		return fmt.Errorf("the identity token algorithm is not accepted (alg=%q)", alg)
	}
	return v.verifyWithKeys(parts, stringClaim(parts.header, "kid"), alg, time.Now(), false)
}

// verifyWithKeys checks the token signature, refreshing the key set once if the
// cached keys do not accept it.
func (v *IdentityVerifier) verifyWithKeys(parts *jwtParts, keyID, alg string, now time.Time, refreshed bool) error {
	keys, err := v.minecraftKeys(now, refreshed)
	if err != nil {
		return err
	}
	payload := parts.headerB64 + "." + parts.payloadB64
	if keyID != "" {
		if key, ok := keys[keyID]; ok && verifyTokenSignature(key, alg, []byte(payload), parts.sigB64) == nil {
			return nil
		}
	} else {
		for _, key := range keys {
			if verifyTokenSignature(key, alg, []byte(payload), parts.sigB64) == nil {
				return nil
			}
		}
	}
	if refreshed {
		return fmt.Errorf("the identity token was not signed by a trusted key (alg=%s kid=%s)", alg, keyID)
	}
	return v.verifyWithKeys(parts, keyID, alg, now, true)
}

// tokenAlgSupported lists the signature families an account token may use.
func tokenAlgSupported(alg string) bool {
	switch alg {
	case "ES384", "RS256", "RS384", "RS512":
		return true
	default:
		return false
	}
}

// verifyTokenSignature checks the JWS signature with the matching key family.
func verifyTokenSignature(key signingKey, alg string, payload []byte, sig string) error {
	if alg == "ES384" {
		if key.ec == nil {
			return fmt.Errorf("the key set holds no EC key")
		}
		return VerifyES384(key.ec, payload, sig)
	}
	if key.rsa == nil {
		return fmt.Errorf("the key set holds no RSA key")
	}
	raw, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil {
		return fmt.Errorf("the token signature is malformed")
	}
	var digest []byte
	var hash crypto.Hash
	switch alg {
	case "RS256":
		sum := sha256.Sum256(payload)
		digest, hash = sum[:], crypto.SHA256
	case "RS384":
		sum := sha512.Sum384(payload)
		digest, hash = sum[:], crypto.SHA384
	case "RS512":
		sum := sha512.Sum512(payload)
		digest, hash = sum[:], crypto.SHA512
	default:
		return fmt.Errorf("unsupported token algorithm %q", alg)
	}
	if err := rsa.VerifyPKCS1v15(key.rsa, hash, digest, raw); err != nil {
		return fmt.Errorf("signature verification failed")
	}
	return nil
}

func (v *IdentityVerifier) minecraftKeys(now time.Time, force bool) (map[string]signingKey, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if !force && len(v.keys) > 0 && now.Sub(v.fetched) < minecraftKeyCacheTTL {
		return v.keys, nil
	}
	resp, err := v.http.Get(minecraftJWKSUrl)
	if err != nil {
		return nil, fmt.Errorf("the Minecraft authorization keys could not be fetched")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("the Minecraft authorization keys could not be fetched")
	}
	var doc struct {
		Keys []struct {
			Kty string `json:"kty"`
			Crv string `json:"crv"`
			X   string `json:"x"`
			Y   string `json:"y"`
			N   string `json:"n"`
			E   string `json:"e"`
			Kid string `json:"kid"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, fmt.Errorf("the Minecraft authorization keys are malformed")
	}
	keys := make(map[string]signingKey, len(doc.Keys))
	order := make([]string, 0, len(doc.Keys))
	for i, key := range doc.Keys {
		var parsed signingKey
		switch {
		case key.Kty == "EC" && key.Crv == "P-384" && key.X != "" && key.Y != "":
			_, pub, err := ParsePublicJWK(mustJSON(PublicJWK{Crv: "P-384", Kty: "EC", X: key.X, Y: key.Y}))
			if err != nil {
				continue
			}
			parsed.ec = pub
		case key.Kty == "RSA" && key.N != "" && key.E != "":
			n, err := base64.RawURLEncoding.DecodeString(key.N)
			if err != nil || len(n) == 0 {
				continue
			}
			e, err := base64.RawURLEncoding.DecodeString(key.E)
			if err != nil || len(e) == 0 {
				continue
			}
			exponent := new(big.Int).SetBytes(e)
			public := &rsa.PublicKey{
				N: new(big.Int).SetBytes(n),
				E: int(exponent.Int64()),
			}
			if public.N.BitLen() < 2048 || public.E < 3 {
				continue
			}
			parsed.rsa = public
		default:
			continue
		}
		id := key.Kid
		if id == "" {
			id = fmt.Sprintf("key-%d", i)
		}
		keys[id] = parsed
		order = append(order, id)
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("the Minecraft authorization keys are unusable")
	}
	v.keys = keys
	v.keyOrder = order
	v.fetched = now
	return keys, nil
}

func mustJSON(v any) json.RawMessage {
	raw, err := json.Marshal(v)
	if err != nil {
		panic("nxs: marshal JWK: " + err.Error())
	}
	return raw
}

// canonicalCPK decodes the token's standard base64 SPKI DER and re-encodes it
// canonically, rejecting anything that is not a valid P-384 point.
func canonicalCPK(cpk string) ([]byte, *ecdsa.PublicKey, error) {
	der, err := base64.StdEncoding.DecodeString(cpk)
	if err != nil {
		return nil, nil, fmt.Errorf("the token's cpk is not standard base64")
	}
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, nil, fmt.Errorf("the token's cpk is not a public key")
	}
	key, ok := pub.(*ecdsa.PublicKey)
	if !ok || key.Curve == nil || key.Curve.Params().Name != "P-384" {
		return nil, nil, fmt.Errorf("the token's cpk is not a P-384 key")
	}
	canonical, err := CanonicalPublicKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("the token's cpk is not canonical")
	}
	if canonical != cpk {
		return nil, nil, fmt.Errorf("the token's cpk is not canonical")
	}
	return der, key, nil
}

// verifyDetachedJWS verifies header..signature over the detached payload.
func verifyDetachedJWS(pub *ecdsa.PublicKey, detached, payload string) error {
	fields := strings.Split(detached, ".")
	if len(fields) != 3 || fields[1] != "" {
		return fmt.Errorf("the fingerprint proof is not a detached JWS")
	}
	headerRaw, err := base64.RawURLEncoding.DecodeString(fields[0])
	if err != nil {
		return fmt.Errorf("the fingerprint proof header is malformed")
	}
	var header map[string]any
	if err := json.Unmarshal(headerRaw, &header); err != nil {
		return fmt.Errorf("the fingerprint proof header is not JSON")
	}
	if alg := stringClaim(header, "alg"); alg != "ES384" {
		return fmt.Errorf("the fingerprint proof is not signed with ES384")
	}
	sig, err := base64.RawURLEncoding.DecodeString(fields[2])
	if err != nil || len(sig) != 96 {
		return fmt.Errorf("the fingerprint proof signature is malformed")
	}
	// A detached JWS omits the payload segment from its serialization, but the
	// signature still covers the base64url-encoded payload, exactly as a
	// non-detached JWS would.
	encoded := base64.RawURLEncoding.EncodeToString([]byte(payload))
	if err := VerifyES384(pub, []byte(fields[0]+"."+encoded), fields[2]); err != nil {
		return fmt.Errorf("the fingerprint proof does not match the offer")
	}
	return nil
}

func stringClaim(m map[string]any, name string) string {
	if v, ok := m[name].(string); ok {
		return v
	}
	return ""
}

func numberClaim(m map[string]any, name string) (int64, bool) {
	switch v := m[name].(type) {
	case json.Number:
		n, err := v.Int64()
		return n, err == nil
	case float64:
		return int64(v), true
	}
	return 0, false
}

func hasAudience(m map[string]any, want string) bool {
	switch v := m["aud"].(type) {
	case string:
		return v == want
	case []any:
		for _, item := range v {
			if s, ok := item.(string); ok && s == want {
				return true
			}
		}
	}
	return false
}
