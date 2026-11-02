package nxs

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strconv"
	"testing"
	"time"
)

type admissionFixture struct {
	Context struct {
		KeyID    string `json:"keyId"`
		Secret   string `json:"secret"`
		Audience string `json:"audience"`
	} `json:"context"`
	Claims struct {
		ExpiresAt            int64  `json:"expiresAt"`
		ClientFingerprintHex string `json:"clientFingerprintHex"`
		ClientICEPwd         string `json:"clientIcePwd"`
		ClientSCTPPort       uint16 `json:"clientSctpPort"`
		ClientMaxMessageSize uint32 `json:"clientMaxMessageSize"`
		NetworkID            string `json:"networkId"`
		IdentityBindingHex   string `json:"identityBindingHex"`
	} `json:"claims"`
	ClientICEFrag string `json:"clientIceUfrag"`
	NonceHex      string `json:"nonceHex"`
	Now           int64  `json:"now"`
	MaxTTLMs      int64  `json:"maxTtlMs"`
	Expected      struct {
		LocalUfrag  string `json:"localUfrag"`
		ICEPwd      string `json:"icePwd"`
		UfragLength int    `json:"ufragLength"`
	} `json:"expected"`
	Identity struct {
		PublicKeyJWK  PublicJWK `json:"publicKeyJwk"`
		CanonicalCPK  string    `json:"canonicalCpk"`
		HMACInputHex  string    `json:"hmacInputHex"`
		HMACSHA256Hex string    `json:"hmacSha256Hex"`
	} `json:"identity"`
}

func TestStatelessAdmissionFixture(t *testing.T) {
	data, err := os.ReadFile("../../testdata/nxs/stateless-admission-v1.fixtures.json")
	if err != nil {
		t.Fatal(err)
	}
	var fx admissionFixture
	if err := json.Unmarshal(data, &fx); err != nil {
		t.Fatal(err)
	}

	fingerprint, err := hex.DecodeString(fx.Claims.ClientFingerprintHex)
	if err != nil || len(fingerprint) != 32 {
		t.Fatalf("fingerprint: %v", err)
	}
	var fp [32]byte
	copy(fp[:], fingerprint)

	networkID, err := strconv.ParseUint(fx.Claims.NetworkID, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	bindingRaw, err := hex.DecodeString(fx.Claims.IdentityBindingHex)
	if err != nil || len(bindingRaw) != 16 {
		t.Fatalf("binding: %v", err)
	}
	var binding [16]byte
	copy(binding[:], bindingRaw)

	nonce, err := hex.DecodeString(fx.NonceHex)
	if err != nil {
		t.Fatal(err)
	}

	claims := AdmissionClaims{
		ExpiresAt:               fx.Claims.ExpiresAt,
		ClientFingerprintSHA256: fp,
		ClientSCTPPort:          fx.Claims.ClientSCTPPort,
		ClientMaxMessageSize:    fx.Claims.ClientMaxMessageSize,
		NetworkID:               networkID,
		ClientICEPassword:       fx.Claims.ClientICEPwd,
	}
	key := AdmissionKey{KeyID: fx.Context.KeyID, Secret: fx.Context.Secret}
	minted, err := mintAdmission(key, fx.Context.Audience, fx.ClientICEFrag, claims, binding, nonce, time.UnixMilli(fx.Now))
	if err != nil {
		t.Fatal(err)
	}
	if minted.AnswerUfrag != fx.Expected.LocalUfrag {
		t.Fatalf("answer ufrag mismatch\n got: %s\nwant: %s", minted.AnswerUfrag, fx.Expected.LocalUfrag)
	}
	if minted.ICEPassword != fx.Expected.ICEPwd {
		t.Fatalf("ice password mismatch\n got: %s\nwant: %s", minted.ICEPassword, fx.Expected.ICEPwd)
	}
	if len(minted.AnswerUfrag) != fx.Expected.UfragLength {
		t.Fatalf("ufrag length = %d, want %d", len(minted.AnswerUfrag), fx.Expected.UfragLength)
	}
}

func TestStatelessIdentityBindingFixture(t *testing.T) {
	data, err := os.ReadFile("../../testdata/nxs/stateless-admission-v1.fixtures.json")
	if err != nil {
		t.Fatal(err)
	}
	var fx admissionFixture
	if err := json.Unmarshal(data, &fx); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(fx.Identity.PublicKeyJWK)
	if err != nil {
		t.Fatal(err)
	}
	_, pub, err := ParsePublicJWK(raw)
	if err != nil {
		t.Fatal(err)
	}
	cpk, err := CanonicalPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	if cpk != fx.Identity.CanonicalCPK {
		t.Fatalf("canonical cpk mismatch\n got: %s\nwant: %s", cpk, fx.Identity.CanonicalCPK)
	}

	got := IdentityBinding(fx.Context.Secret, fx.Context.Audience, []byte(cpk))
	if hex.EncodeToString(got) != fx.Claims.IdentityBindingHex {
		t.Fatalf("identity binding = %x, want %s", got, fx.Claims.IdentityBindingHex)
	}

	mac := hmac.New(sha256.New, []byte(fx.Context.Secret))
	mac.Write([]byte("nxs-identity-binding-v1\x00" + fx.Context.Audience + "\x00"))
	mac.Write([]byte(cpk))
	if hex.EncodeToString(mac.Sum(nil)) != fx.Identity.HMACSHA256Hex {
		t.Fatalf("full identity hmac mismatch")
	}
}

func TestAdmissionRejectsInvalidClaims(t *testing.T) {
	key := AdmissionKey{KeyID: "K001", Secret: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"}
	now := time.UnixMilli(1788484800000)
	base := AdmissionClaims{
		ExpiresAt:            1788484830000,
		ClientSCTPPort:       5000,
		ClientMaxMessageSize: 262144,
		NetworkID:            1,
		ClientICEPassword:    "clientPassword01234567890",
	}
	if _, err := MintAdmission(key, AdmissionAudience("0123456789abcdef0123456789abcdef"), "uf", base, [16]byte{}, now); err != nil {
		t.Fatal(err)
	}
	expired := base
	expired.ExpiresAt = now.UnixMilli()
	if _, err := MintAdmission(key, AdmissionAudience("0123456789abcdef0123456789abcdef"), "uf", expired, [16]byte{}, now); err == nil {
		t.Fatal("expected expired claim to be rejected")
	}
	tooLong := base
	tooLong.ExpiresAt = now.UnixMilli() + 121000
	if _, err := MintAdmission(key, AdmissionAudience("0123456789abcdef0123456789abcdef"), "uf", tooLong, [16]byte{}, now); err == nil {
		t.Fatal("expected far-future claim to be rejected")
	}
	zeroNetwork := base
	zeroNetwork.NetworkID = 0
	if _, err := MintAdmission(key, AdmissionAudience("0123456789abcdef0123456789abcdef"), "uf", zeroNetwork, [16]byte{}, now); err == nil {
		t.Fatal("expected zero network ID to be rejected")
	}
}
