package nxs

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

// TestHostIdentityAssertionFormat pins the assertion shape to what a Bedrock
// client parses: the assertion is an escaped JSON string, the fingerprints JWS
// is detached, and the token carries cpk, iat and iss.
func TestHostIdentityAssertionFormat(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id := &HostIdentity{key: key, domain: "Siglark-SelfhostNXS"}

	const answer = "v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n" +
		"m=application 19132 UDP/DTLS/SCTP webrtc-datachannel\r\nc=IN IP4 172.30.224.1\r\n" +
		"a=fingerprint:sha-256 6C:4E:BE:D4:BE:B9:66:6A:FD:BF:EA:1E:2E:7E:20:D6:E1:82:B7:CF:28:30:0B:98:0D:53:1E:F6:EE:DE:AE:05\r\n" +
		"a=setup:active\r\n"

	value, err := id.Assertion(answer)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		t.Fatalf("identity value is not standard base64: %v", err)
	}
	var outer struct {
		Idp struct {
			Domain   string `json:"domain"`
			Protocol string `json:"protocol"`
		} `json:"idp"`
		Assertion string `json:"assertion"`
	}
	if err := json.Unmarshal(raw, &outer); err != nil {
		t.Fatalf("outer identity JSON: %v\n%s", err, raw)
	}
	if outer.Idp.Domain != "Siglark-SelfhostNXS" || outer.Idp.Protocol != "default" {
		t.Fatalf("idp mismatch: %+v", outer.Idp)
	}

	var inner struct {
		Token       string `json:"token"`
		Fingerprints string `json:"fingerprints"`
	}
	if err := json.Unmarshal([]byte(outer.Assertion), &inner); err != nil {
		t.Fatalf("assertion is not an escaped JSON string: %v", err)
	}

	parts := strings.Split(inner.Token, ".")
	if len(parts) != 3 {
		t.Fatalf("token is not a compact JWS: %d parts", len(parts))
	}
	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || string(header) != `{"alg":"ES384"}` {
		t.Fatalf("token header = %q (err %v)", header, err)
	}
	var claims map[string]any
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("token payload: %v", err)
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("token claims: %v", err)
	}
	cpk, _ := claims["cpk"].(string)
	if !strings.HasPrefix(cpk, "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE") {
		t.Fatalf("cpk is not a P-384 SPKI in standard base64: %q", cpk)
	}
	if _, ok := claims["iat"].(float64); !ok {
		t.Fatalf("iat missing: %v", claims)
	}
	if claims["iss"] != "Siglark-SelfhostNXS" {
		t.Fatalf("iss = %v", claims["iss"])
	}

	fp := strings.Split(inner.Fingerprints, ".")
	if len(fp) != 3 || fp[1] != "" {
		t.Fatalf("fingerprints is not a detached JWS: %q", inner.Fingerprints)
	}
	if fpHeader, err := base64.RawURLEncoding.DecodeString(fp[0]); err != nil || string(fpHeader) != `{"alg":"ES384"}` {
		t.Fatalf("fingerprints header = %q (err %v)", fpHeader, err)
	}

	// The detached payload must be the answer's canonical fingerprint JSON.
	want, err := CanonicalFingerprintJSON(answer)
	if err != nil {
		t.Fatal(err)
	}
	if want == "" || !strings.Contains(want, `"algorithm":"sha-256"`) {
		t.Fatalf("canonical fingerprint JSON malformed: %s", want)
	}
}

func TestInsertIdentityAttribute(t *testing.T) {
	answer := "v=0\r\nm=application 19132 UDP/DTLS/SCTP webrtc-datachannel\r\nc=IN IP4 1.2.3.4\r\n"
	got := InsertIdentityAttribute(answer, "AbC=")
	want := "v=0\r\na=identity:AbC=\r\nm=application 19132 UDP/DTLS/SCTP webrtc-datachannel\r\nc=IN IP4 1.2.3.4\r\n"
	if got != want {
		t.Fatalf("inserted identity in the wrong place:\n got %q\nwant %q", got, want)
	}
}
