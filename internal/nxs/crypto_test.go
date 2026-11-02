package nxs

import (
	"encoding/json"
	"os"
	"testing"
)

type fixtureChallenge struct {
	Protocol      string           `json:"protocol"`
	Signature     string           `json:"signature"`
	ChallengeID   string           `json:"challengeId"`
	Nonce         string           `json:"nonce"`
	Audience      string           `json:"audience"`
	Thumbprint    string           `json:"thumbprint"`
	Context       ChallengeContext `json:"context"`
	ContextDigest string           `json:"contextDigest"`
	ExpiresAt     int64            `json:"expiresAt"`
	ServerTime    int64            `json:"serverTime"`
	PoW           ProofOfWork      `json:"pow"`
}

type fixtureProof struct {
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

type fixtureRequest struct {
	Input struct {
		Audience       string `json:"audience"`
		Method         string `json:"method"`
		Path           string `json:"path"`
		Timestamp      int64  `json:"timestamp"`
		InstanceID     string `json:"instanceId"`
		KeyID          string `json:"keyId"`
		IdempotencyKey string `json:"idempotencyKey"`
		Generation     int64  `json:"generation"`
		Sequence       int64  `json:"sequence"`
		Body           string `json:"body"`
	} `json:"input"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

type fixtureRotation struct {
	ReplacementPublicKeyJWK PublicJWK `json:"replacementPublicKeyJwk"`
	Input                   struct {
		Audience       string `json:"audience"`
		InstanceID     string `json:"instanceId"`
		OldKeyID       string `json:"oldKeyId"`
		Generation     int64  `json:"generation"`
		IdempotencyKey string `json:"idempotencyKey"`
	} `json:"input"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

type nxsFixtures struct {
	PublicKeyJWK   json.RawMessage  `json:"publicKeyJwk"`
	Challenge      fixtureChallenge `json:"challenge"`
	ProofNonce     string           `json:"proofNonce"`
	IdempotencyKey string           `json:"idempotencyKey"`
	Proof          fixtureProof     `json:"proof"`
	Request        fixtureRequest   `json:"request"`
	Rotation       fixtureRotation  `json:"rotation"`
}

func loadFixtures[T any](t *testing.T, path string) T {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out T
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestFixtureThumbprintAndContext(t *testing.T) {
	fx := loadFixtures[nxsFixtures](t, "../../testdata/nxs/nxs-v1.fixtures.json")
	key, _, err := ParsePublicJWK(fx.PublicKeyJWK)
	if err != nil {
		t.Fatal(err)
	}
	if got := key.Thumbprint(); got != fx.Challenge.Thumbprint {
		t.Fatalf("thumbprint = %s, want %s", got, fx.Challenge.Thumbprint)
	}
	if got := ContextDigest(fx.Challenge.Context); got != fx.Challenge.ContextDigest {
		t.Fatalf("contextDigest = %s, want %s", got, fx.Challenge.ContextDigest)
	}
}

func TestFixtureCompletionProof(t *testing.T) {
	fx := loadFixtures[nxsFixtures](t, "../../testdata/nxs/nxs-v1.fixtures.json")
	_, pub, err := ParsePublicJWK(fx.PublicKeyJWK)
	if err != nil {
		t.Fatal(err)
	}
	payload := CompleteProofPayload(
		fx.Challenge.Audience, fx.Challenge.ChallengeID, fx.Challenge.Nonce,
		fx.Challenge.Thumbprint, fx.Challenge.ContextDigest, fx.Challenge.ExpiresAt,
		fx.ProofNonce, fx.IdempotencyKey,
	)
	if string(payload) != fx.Proof.Payload {
		t.Fatalf("proof payload mismatch\n got: %s\nwant: %s", payload, fx.Proof.Payload)
	}
	if err := VerifyES384(pub, payload, fx.Proof.Signature); err != nil {
		t.Fatal(err)
	}
}

func TestFixtureRequestSignature(t *testing.T) {
	fx := loadFixtures[nxsFixtures](t, "../../testdata/nxs/nxs-v1.fixtures.json")
	_, pub, err := ParsePublicJWK(fx.PublicKeyJWK)
	if err != nil {
		t.Fatal(err)
	}
	in := fx.Request.Input
	payload := RequestPayload(in.Audience, in.Method, in.Path, in.Timestamp, in.InstanceID,
		in.KeyID, in.IdempotencyKey, in.Generation, in.Sequence, []byte(in.Body))
	if string(payload) != fx.Request.Payload {
		t.Fatalf("request payload mismatch\n got: %s\nwant: %s", payload, fx.Request.Payload)
	}
	if err := VerifyES384(pub, payload, fx.Request.Signature); err != nil {
		t.Fatal(err)
	}
	if got := BodySHA256([]byte(in.Body)); got != "gbTKXii0H2PwM5KsmHfDXepWMxlOLqblOPv6sqGyh50" {
		t.Fatalf("body hash = %s", got)
	}
}

func TestFixtureRotationProof(t *testing.T) {
	fx := loadFixtures[nxsFixtures](t, "../../testdata/nxs/nxs-v1.fixtures.json")
	raw, err := json.Marshal(fx.Rotation.ReplacementPublicKeyJWK)
	if err != nil {
		t.Fatal(err)
	}
	key, pub, err := ParsePublicJWK(raw)
	if err != nil {
		t.Fatal(err)
	}
	in := fx.Rotation.Input
	payload := RotateProofPayload(in.Audience, in.InstanceID, in.OldKeyID, key.Thumbprint(), in.Generation, in.IdempotencyKey)
	if string(payload) != fx.Rotation.Payload {
		t.Fatalf("rotation payload mismatch\n got: %s\nwant: %s", payload, fx.Rotation.Payload)
	}
	if err := VerifyES384(pub, payload, fx.Rotation.Signature); err != nil {
		t.Fatal(err)
	}
}

func TestDecodeBase64URLStrict(t *testing.T) {
	valid := Base64URL([]byte{1, 2, 3})
	if _, err := DecodeBase64URL(valid, 3); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{valid + "=", valid + "+/", "AA==", "A"} {
		if _, err := DecodeBase64URL(bad, -1); err == nil {
			t.Fatalf("expected %q to be rejected", bad)
		}
	}
}
