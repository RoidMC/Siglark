package nxs_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/roidmc/siglark/internal/nxs"
	"github.com/roidmc/siglark/internal/storage/memory"
)

const (
	testOrigin = "https://provider.test"
	testNowMs  = int64(1788484200000)
)

type testHost struct {
	priv *ecdsa.PrivateKey
	jwk  nxs.PublicJWK
	reg  *nxs.RegistrationResponse
}

func newTestHost(t *testing.T) *testHost {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	x := make([]byte, 48)
	y := make([]byte, 48)
	priv.X.FillBytes(x)
	priv.Y.FillBytes(y)
	return &testHost{
		priv: priv,
		jwk:  nxs.PublicJWK{Crv: "P-384", Kty: "EC", X: nxs.Base64URL(x), Y: nxs.Base64URL(y)},
	}
}

func (h *testHost) jwkJSON(t *testing.T) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(h.jwk)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func newTestServer(t *testing.T) (*nxs.Service, *httptest.Server) {
	t.Helper()
	store := memory.New()
	svc, err := nxs.NewService(nxs.Options{
		Store:               store,
		Origin:              testOrigin,
		ChallengeTTL:        5 * time.Minute,
		HeartbeatIntervalMs: 10000,
		LeaseMillis:         70000,
		MinUpdateIntervalMs: 1000,
		Clock:               func() time.Time { return time.UnixMilli(testNowMs) },
	})
	if err != nil {
		t.Fatal(err)
	}
	router := chi.NewRouter()
	nxs.NewHandler(svc).Mount(router)
	ts := httptest.NewServer(router)
	t.Cleanup(ts.Close)
	return svc, ts
}

func postJSON(t *testing.T, url string, body any, headers map[string]string) (int, []byte) {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, out
}

func (h *testHost) signedPost(t *testing.T, ts *httptest.Server, op string, body any, idem string, seq int64) (int, []byte) {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	path := "/v1/nxs/" + op
	payload := nxs.RequestPayload(testOrigin, http.MethodPost, path, testNowMs, h.reg.InstanceID, h.reg.KeyID, idem, h.reg.LeaseGeneration, seq, raw)
	sig, err := nxs.SignP384(h.priv, payload)
	if err != nil {
		t.Fatal(err)
	}
	headers := map[string]string{
		"nxs-instance-id":       h.reg.InstanceID,
		"nxs-key-id":            h.reg.KeyID,
		"nxs-timestamp":         strconv.FormatInt(testNowMs, 10),
		"nxs-signature-version": nxs.SignatureVersion,
		"nxs-generation":        strconv.FormatInt(h.reg.LeaseGeneration, 10),
		"nxs-sequence":          strconv.FormatInt(seq, 10),
		"nxs-signature":         sig,
		"idempotency-key":       idem,
	}
	return postJSON(t, ts.URL+path, body, headers)
}

func decode[T any](t *testing.T, raw []byte) T {
	t.Helper()
	var out T
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode %s: %v", raw, err)
	}
	return out
}

func TestDiscovery(t *testing.T) {
	_, ts := newTestServer(t)
	resp, err := http.Get(ts.URL + nxs.DiscoveryPath)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	doc := decode[nxs.DiscoveryDocument](t, mustRead(t, resp.Body))
	if doc.Provider != testOrigin {
		t.Fatalf("provider = %q", doc.Provider)
	}
	if len(doc.Protocols) != 1 || doc.Protocols[0] != nxs.Protocol {
		t.Fatalf("protocols = %v", doc.Protocols)
	}
	if len(doc.Signatures) != 1 || doc.Signatures[0] != nxs.SignatureVersion {
		t.Fatalf("signatures = %v", doc.Signatures)
	}
}

func TestEnrollmentHeartbeatAndAdmission(t *testing.T) {
	svc, ts := newTestServer(t)
	h := newTestHost(t)

	status, raw := postJSON(t, ts.URL+"/v1/nxs/register", map[string]any{
		"protocol":     nxs.Protocol,
		"publicKeyJwk": h.jwkJSON(t),
		"label":        "MVP host",
	}, nil)
	if status != http.StatusOK {
		t.Fatalf("register status = %d: %s", status, raw)
	}
	ch := decode[*nxs.Challenge](t, raw)
	if ch.Context.Mode != "new-service" || ch.PoW.Difficulty != 0 {
		t.Fatalf("challenge mode/pow = %s/%d", ch.Context.Mode, ch.PoW.Difficulty)
	}
	if ch.Thumbprint != h.jwk.Thumbprint() {
		t.Fatalf("thumbprint mismatch")
	}

	proof := nxs.CompleteProofPayload(ch.Audience, ch.ChallengeID, ch.Nonce, ch.Thumbprint, ch.ContextDigest, ch.ExpiresAt, "0", "intent-mvp-00000001")
	sig, err := nxs.SignP384(h.priv, proof)
	if err != nil {
		t.Fatal(err)
	}
	status, raw = postJSON(t, ts.URL+"/v1/nxs/complete", map[string]any{
		"protocol":       nxs.Protocol,
		"challengeId":    ch.ChallengeID,
		"proofNonce":     "0",
		"signature":      sig,
		"idempotencyKey": "intent-mvp-00000001",
	}, nil)
	if status != http.StatusOK {
		t.Fatalf("complete status = %d: %s", status, raw)
	}
	h.reg = decode[*nxs.RegistrationResponse](t, raw)
	if h.reg.LeaseGeneration != 1 || h.reg.AdmissionKey == nil {
		t.Fatalf("registration = %+v", h.reg)
	}
	if len(h.reg.AdmissionKey.Secret) != 43 {
		t.Fatalf("admission secret length = %d", len(h.reg.AdmissionKey.Secret))
	}

	// Replaying a consumed completion is a recovery signal, never a success.
	status, raw = postJSON(t, ts.URL+"/v1/nxs/complete", map[string]any{
		"protocol":       nxs.Protocol,
		"challengeId":    ch.ChallengeID,
		"proofNonce":     "0",
		"signature":      sig,
		"idempotencyKey": "intent-mvp-00000001",
	}, nil)
	if status != http.StatusConflict || !strings.Contains(string(raw), "recovery_required") {
		t.Fatalf("replayed complete = %d: %s", status, raw)
	}

	baseHeartbeat := map[string]any{
		"acceptingPlayers": true,
		"capacity":         10,
		"connectedPlayers": map[string]any{"count": 0, "sampledAt": testNowMs},
	}
	status, raw = h.signedPost(t, ts, "heartbeat", baseHeartbeat, "intent-hb-00000001", 1)
	if status != http.StatusOK {
		t.Fatalf("heartbeat#1 status = %d: %s", status, raw)
	}
	hb1 := decode[nxs.HeartbeatResponse](t, raw)
	if hb1.Readiness.Routable || hb1.HostProfileRevision != nil {
		t.Fatalf("heartbeat#1 readiness = %+v, revision = %v", hb1.Readiness, hb1.HostProfileRevision)
	}

	incarnation := strings.Repeat("ab", 16)
	profileHeartbeat := map[string]any{
		"acceptingPlayers": true,
		"capacity":         10,
		"connectedPlayers": map[string]any{"count": 1, "sampledAt": testNowMs},
		"hostProfile": map[string]any{
			"candidates":      []any{},
			"dtlsFingerprint": "sha-256 " + strings.Repeat("AB:", 31) + "AB",
			"admissionKeyId":  h.reg.AdmissionKey.KeyID,
			"sctpPort":        19132,
			"maxMessageSize":  262144,
			"statelessAdmission": map[string]any{
				"capability":  nxs.StatelessCapability,
				"incarnation": incarnation,
			},
		},
		"installedAdmissionKeyIds": []string{h.reg.AdmissionKey.KeyID},
	}
	status, raw = h.signedPost(t, ts, "heartbeat", profileHeartbeat, "intent-hb-00000002", 2)
	if status != http.StatusOK {
		t.Fatalf("heartbeat#2 status = %d: %s", status, raw)
	}
	hb2 := decode[nxs.HeartbeatResponse](t, raw)
	if !hb2.Readiness.Routable || hb2.HostProfileRevision == nil {
		t.Fatalf("heartbeat#2 readiness = %+v revision=%v", hb2.Readiness, hb2.HostProfileRevision)
	}

	// Identical retry returns the recorded result instead of re-applying.
	status, replay := h.signedPost(t, ts, "heartbeat", profileHeartbeat, "intent-hb-00000002", 2)
	if status != http.StatusOK || !bytes.Equal(replay, raw) {
		t.Fatalf("idempotent replay = %d: %s", status, replay)
	}

	// A recovery bumps the generation, fencing the previous runtime identity.
	status, raw = postJSON(t, ts.URL+"/v1/nxs/register", map[string]any{
		"protocol":       nxs.Protocol,
		"registrationId": h.reg.RegistrationID,
	}, nil)
	if status != http.StatusOK {
		t.Fatalf("recover register status = %d: %s", status, raw)
	}
	rc := decode[*nxs.Challenge](t, raw)
	if rc.Context.Mode != "recover" {
		t.Fatalf("recover challenge mode = %q", rc.Context.Mode)
	}
	recSig, err := nxs.SignP384(h.priv, nxs.CompleteProofPayload(rc.Audience, rc.ChallengeID, rc.Nonce, rc.Thumbprint, rc.ContextDigest, rc.ExpiresAt, "0", "intent-recover-00000001"))
	if err != nil {
		t.Fatal(err)
	}
	status, raw = postJSON(t, ts.URL+"/v1/nxs/complete", map[string]any{
		"protocol":       nxs.Protocol,
		"challengeId":    rc.ChallengeID,
		"proofNonce":     "0",
		"signature":      recSig,
		"idempotencyKey": "intent-recover-00000001",
	}, nil)
	if status != http.StatusOK {
		t.Fatalf("recover complete status = %d: %s", status, raw)
	}
	recovered := decode[*nxs.RegistrationResponse](t, raw)
	if recovered.LeaseGeneration != h.reg.LeaseGeneration+1 {
		t.Fatalf("recovered generation = %d", recovered.LeaseGeneration)
	}

	oldGen := h.reg.LeaseGeneration
	payload := nxs.RequestPayload(testOrigin, http.MethodPost, "/v1/nxs/heartbeat", testNowMs, h.reg.InstanceID, h.reg.KeyID, "intent-hb-00000004", oldGen, 4, []byte(`{}`))
	sig, _ = nxs.SignP384(h.priv, payload)
	headers := map[string]string{
		"nxs-instance-id": h.reg.InstanceID, "nxs-key-id": h.reg.KeyID,
		"nxs-timestamp": strconv.FormatInt(testNowMs, 10), "nxs-signature-version": nxs.SignatureVersion,
		"nxs-generation": strconv.FormatInt(oldGen, 10), "nxs-sequence": "4",
		"nxs-signature": sig, "idempotency-key": "intent-hb-00000004",
	}
	status, raw = postJSON(t, ts.URL+"/v1/nxs/heartbeat", map[string]any{}, headers)
	if status != http.StatusConflict || !strings.Contains(string(raw), "generation_fenced") {
		t.Fatalf("fenced heartbeat = %d: %s", status, raw)
	}

	claims := nxs.AdmissionClaims{
		ExpiresAt:            testNowMs + 30000,
		ClientSCTPPort:       5000,
		ClientMaxMessageSize: 262144,
		NetworkID:            1,
		ClientICEPassword:    "clientPassword01234567890",
	}
	minted, err := svc.MintAdmissionForRegistration(t.Context(), h.reg.RegistrationID, claims, [16]byte{}, "clientUfrag")
	if err != nil {
		t.Fatal(err)
	}
	wantPrefix := nxs.AdmissionPrefix + h.reg.AdmissionKey.KeyID
	if !strings.HasPrefix(minted.AnswerUfrag, wantPrefix) {
		t.Fatalf("ufrag prefix = %q, want %q", minted.AnswerUfrag, wantPrefix)
	}
	if len(minted.ICEPassword) != 32 {
		t.Fatalf("ice password length = %d", len(minted.ICEPassword))
	}
}

func TestRotationRetireAndRecovery(t *testing.T) {
	_, ts := newTestServer(t)
	h := newTestHost(t)

	status, raw := postJSON(t, ts.URL+"/v1/nxs/register", map[string]any{
		"protocol": nxs.Protocol, "publicKeyJwk": h.jwkJSON(t),
	}, nil)
	if status != http.StatusOK {
		t.Fatalf("register: %d %s", status, raw)
	}
	ch := decode[*nxs.Challenge](t, raw)
	sig, _ := nxs.SignP384(h.priv, nxs.CompleteProofPayload(ch.Audience, ch.ChallengeID, ch.Nonce, ch.Thumbprint, ch.ContextDigest, ch.ExpiresAt, "0", "intent-rot-00000001"))
	status, raw = postJSON(t, ts.URL+"/v1/nxs/complete", map[string]any{
		"protocol": nxs.Protocol, "challengeId": ch.ChallengeID, "proofNonce": "0",
		"signature": sig, "idempotencyKey": "intent-rot-00000001",
	}, nil)
	if status != http.StatusOK {
		t.Fatalf("complete: %d %s", status, raw)
	}
	h.reg = decode[*nxs.RegistrationResponse](t, raw)

	oldKeyID := h.reg.KeyID
	replacement := newTestHost(t)
	rotProof := nxs.RotateProofPayload(testOrigin, h.reg.InstanceID, oldKeyID, replacement.jwk.Thumbprint(), h.reg.LeaseGeneration, "intent-rot-00000002")
	rotSig, _ := nxs.SignP384(replacement.priv, rotProof)
	status, raw = h.signedPost(t, ts, "rotate", map[string]any{
		"publicKeyJwk": replacement.jwkJSON(t),
		"proof":        rotSig,
	}, "intent-rot-00000002", 2)
	if status != http.StatusOK {
		t.Fatalf("rotate: %d %s", status, raw)
	}
	rot := decode[nxs.RotationResponse](t, raw)
	if rot.KeyID == oldKeyID {
		t.Fatal("rotation reused the old key id")
	}

	// The replacement key is current; the lease generation does not change.
	h.priv, h.jwk = replacement.priv, replacement.jwk
	h.reg.KeyID = rot.KeyID
	status, raw = h.signedPost(t, ts, "heartbeat", map[string]any{
		"acceptingPlayers": true, "capacity": 10,
		"connectedPlayers": map[string]any{"count": 0, "sampledAt": testNowMs},
	}, "intent-rot-00000003", 3)
	if status != http.StatusOK {
		t.Fatalf("heartbeat after rotate: %d %s", status, raw)
	}

	// Retire the previous key using the current one.
	h.reg.KeyID = rot.KeyID
	status, raw = h.signedPost(t, ts, "retire", map[string]any{"keyId": oldKeyID}, "intent-rot-00000004", 4)
	if status != http.StatusOK {
		t.Fatalf("retire: %d %s", status, raw)
	}

	// The retired key can no longer sign.
	payload := nxs.RequestPayload(testOrigin, http.MethodPost, "/v1/nxs/heartbeat", testNowMs, h.reg.InstanceID, oldKeyID, "intent-rot-00000005", h.reg.LeaseGeneration, 5, []byte(`{}`))
	oldSig, _ := nxs.SignP384(replacement.priv, payload) // wrong key material on purpose
	headers := map[string]string{
		"nxs-instance-id": h.reg.InstanceID, "nxs-key-id": oldKeyID,
		"nxs-timestamp": strconv.FormatInt(testNowMs, 10), "nxs-signature-version": nxs.SignatureVersion,
		"nxs-generation": strconv.FormatInt(h.reg.LeaseGeneration, 10), "nxs-sequence": "5",
		"nxs-signature": oldSig, "idempotency-key": "intent-rot-00000005",
	}
	status, raw = postJSON(t, ts.URL+"/v1/nxs/heartbeat", map[string]any{}, headers)
	if status != http.StatusUnauthorized {
		t.Fatalf("retired key = %d: %s", status, raw)
	}

	// Recover keeps the identity but starts a new generation.
	status, raw = postJSON(t, ts.URL+"/v1/nxs/register", map[string]any{
		"protocol": nxs.Protocol, "registrationId": h.reg.RegistrationID,
	}, nil)
	if status != http.StatusOK {
		t.Fatalf("recovery register: %d %s", status, raw)
	}
	ch = decode[*nxs.Challenge](t, raw)
	if ch.Context.Mode != "recover" || ch.Context.RegistrationID != h.reg.RegistrationID {
		t.Fatalf("recovery challenge = %+v", ch.Context)
	}
	sig, _ = nxs.SignP384(h.priv, nxs.CompleteProofPayload(ch.Audience, ch.ChallengeID, ch.Nonce, ch.Thumbprint, ch.ContextDigest, ch.ExpiresAt, "0", "intent-rot-00000006"))
	status, raw = postJSON(t, ts.URL+"/v1/nxs/complete", map[string]any{
		"protocol": nxs.Protocol, "challengeId": ch.ChallengeID, "proofNonce": "0",
		"signature": sig, "idempotencyKey": "intent-rot-00000006",
	}, nil)
	if status != http.StatusOK {
		t.Fatalf("recovery complete: %d %s", status, raw)
	}
	recovered := decode[*nxs.RegistrationResponse](t, raw)
	if recovered.LeaseGeneration != 2 || recovered.InstanceID != h.reg.InstanceID || recovered.RegistrationID != h.reg.RegistrationID {
		t.Fatalf("recovery response = %+v", recovered)
	}
}

func mustRead(t *testing.T, r io.Reader) []byte {
	t.Helper()
	b, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
