package nxs

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// AdmissionAudience builds the stateless admission audience for an endpoint
// incarnation.
func AdmissionAudience(incarnation string) string {
	return "nxs-stateless-host-v1/" + incarnation
}

// AdmissionClaims are the values a host needs to validate a client later.
type AdmissionClaims struct {
	// ExpiresAt is epoch milliseconds and must be exactly representable in
	// epoch seconds.
	ExpiresAt int64
	// ClientFingerprintSHA256 is the DTLS certificate fingerprint.
	ClientFingerprintSHA256 [32]byte
	ClientSCTPPort          uint16
	ClientMaxMessageSize    uint32
	NetworkID               uint64
	ClientICEPassword       string
}

// MintedAdmission is the answer-side ICE material carrying the token.
type MintedAdmission struct {
	AnswerUfrag string
	ICEPassword string
}

// MintAdmission seals a stateless admission token into the answer ufrag.
// The provider calls this when handing a client the host's connection
// details; hosts validate the result locally.
func MintAdmission(key AdmissionKey, audience, clientUfrag string, claims AdmissionClaims, binding [16]byte, now time.Time) (*MintedAdmission, error) {
	return mintAdmission(key, audience, clientUfrag, claims, binding, nil, now)
}

// mintAdmission is the deterministic entry point used by conformance tests.
func mintAdmission(key AdmissionKey, audience, clientUfrag string, claims AdmissionClaims, binding [16]byte, nonce []byte, now time.Time) (*MintedAdmission, error) {
	if err := validateAdmissionKey(key); err != nil {
		return nil, err
	}
	if err := validateAdmissionAudience(audience); err != nil {
		return nil, err
	}
	if err := validateClaims(claims, now); err != nil {
		return nil, err
	}
	plain := make([]byte, 0, 67+len(claims.ClientICEPassword))
	plain = appendUint32BE(plain, uint32(claims.ExpiresAt/1000))
	plain = append(plain, claims.ClientFingerprintSHA256[:]...)
	plain = appendUint16BE(plain, claims.ClientSCTPPort)
	plain = appendUint32BE(plain, claims.ClientMaxMessageSize)
	plain = append(plain, binding[:]...)
	plain = appendUint64BE(plain, claims.NetworkID)
	plain = append(plain, byte(len(claims.ClientICEPassword)))
	plain = append(plain, []byte(claims.ClientICEPassword)...)

	aeadKey := deriveAdmissionKey(key.Secret, audience)
	block, err := aes.NewCipher(aeadKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if nonce == nil {
		nonce = make([]byte, 12)
		if _, err := rand.Read(nonce); err != nil {
			return nil, err
		}
	}
	if len(nonce) != 12 {
		return nil, fmt.Errorf("admission nonce must be 12 bytes")
	}

	header := AdmissionPrefix + key.KeyID
	sealed := gcm.Seal(nil, nonce, plain, admissionAAD(header, audience, clientUfrag))
	ufrag := header + base64.RawStdEncoding.EncodeToString(append(append([]byte{}, nonce...), sealed...))

	pwd, err := admissionPassword(key.Secret, audience, ufrag)
	if err != nil {
		return nil, err
	}
	return &MintedAdmission{AnswerUfrag: ufrag, ICEPassword: pwd}, nil
}

func validateClaims(claims AdmissionClaims, now time.Time) error {
	nowMs := now.UnixMilli()
	if claims.ExpiresAt%1000 != 0 {
		return fmt.Errorf("admission expiry must be whole seconds")
	}
	if claims.ExpiresAt <= nowMs {
		return fmt.Errorf("admission expiry is in the past")
	}
	if claims.ExpiresAt-nowMs > int64(MaxAdmissionTTLSkewSeconds)*1000 {
		return fmt.Errorf("admission expiry is too far in the future")
	}
	if claims.ClientSCTPPort == 0 {
		return fmt.Errorf("client SCTP port must be nonzero")
	}
	if claims.ClientMaxMessageSize == 0 || claims.ClientMaxMessageSize > 262144 {
		return fmt.Errorf("client max message size is out of range")
	}
	if claims.NetworkID == 0 {
		return fmt.Errorf("network ID zero is reserved for diagnostics")
	}
	if len(claims.ClientICEPassword) < 22 || len(claims.ClientICEPassword) > 91 {
		return fmt.Errorf("client ICE password length is out of range")
	}
	for _, r := range claims.ClientICEPassword {
		ok := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '+' || r == '/' || r == '='
		if !ok {
			return fmt.Errorf("client ICE password is outside the ICE base64 alphabet")
		}
	}
	return nil
}

func deriveAdmissionKey(secret, audience string) []byte {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte("nxs-stateless-aead-v1\x00" + audience))
	return mac.Sum(nil)
}

func admissionAAD(header, audience, clientUfrag string) []byte {
	return []byte("nxs-stateless-admission-v1\x00" + header + "\x00" + audience + "\x00" + clientUfrag)
}

func admissionPassword(secret, audience, ufrag string) (string, error) {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte("nxs-stateless-ice-v1\x00" + audience + "\x00" + ufrag))
	return base64.RawStdEncoding.EncodeToString(mac.Sum(nil)[:24]), nil
}

// IdentityBinding returns the first 16 bytes of the signaling-identity HMAC.
// cpk is the canonical base64 SPKI DER of the client's P-384 key.
func IdentityBinding(secret, audience string, cpk []byte) []byte {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte("nxs-identity-binding-v1\x00" + audience + "\x00"))
	mac.Write(cpk)
	return mac.Sum(nil)[:16]
}

// CanonicalPublicKey returns standard base64 of the canonical P-384 SPKI DER.
func CanonicalPublicKey(pub *ecdsa.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(der), nil
}

func validateAdmissionKey(key AdmissionKey) error {
	if len(key.KeyID) != 4 {
		return fmt.Errorf("admission key id must be four characters")
	}
	for _, r := range key.KeyID {
		if !(r >= 'A' && r <= 'Z') && !(r >= '0' && r <= '9') {
			return fmt.Errorf("admission key id must be uppercase alphanumeric")
		}
	}
	if len(key.Secret) != 43 {
		return fmt.Errorf("admission secret must be 43 characters")
	}
	if _, err := DecodeBase64URL(key.Secret, 32); err != nil {
		return fmt.Errorf("admission secret is not canonical base64url")
	}
	return nil
}

func validateAdmissionAudience(audience string) error {
	const prefix = "nxs-stateless-host-v1/"
	if !strings.HasPrefix(audience, prefix) {
		return fmt.Errorf("admission audience has the wrong prefix")
	}
	inc := strings.TrimPrefix(audience, prefix)
	if len(inc) != 32 {
		return fmt.Errorf("admission incarnation must be 32 hex characters")
	}
	if _, err := hex.DecodeString(inc); err != nil || strings.ToLower(inc) != inc {
		return fmt.Errorf("admission incarnation must be lowercase hex")
	}
	return nil
}

func appendUint16BE(b []byte, v uint16) []byte {
	return append(b, byte(v>>8), byte(v))
}

func appendUint32BE(b []byte, v uint32) []byte {
	return append(b, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

func appendUint64BE(b []byte, v uint64) []byte {
	return append(b, byte(v>>56), byte(v>>48), byte(v>>40), byte(v>>32), byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}
