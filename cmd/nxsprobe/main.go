// Command nxsprobe exercises an NXS provider end to end from the CLI and
// validates each response, so protocol behaviour can be checked without
// reading Geyser logs or proxying traffic.
package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/roidmc/siglark/internal/nxs"
)

type probe struct {
	base       string
	token      string
	client     *http.Client
	priv       *ecdsa.PrivateKey
	jwk        nxs.PublicJWK
	instance   string
	keyID      string
	generation int64
	sequence   int64
}

func main() {
	provider := flag.String("provider", "", "provider origin, for example http://localhost:8080")
	token := flag.String("token", "", "optional bearer token for enrollment")
	label := flag.String("label", "nxsprobe", "registration label")
	keep := flag.Bool("keep", false, "keep the registration instead of deregistering")
	insecure := flag.Bool("insecure", false, "skip TLS verification (development only)")
	timeout := flag.Duration("timeout", 10*time.Second, "per-request timeout")
	flag.Parse()

	if *provider == "" {
		fmt.Fprintln(os.Stderr, "-provider is required")
		os.Exit(2)
	}
	origin := strings.TrimRight(*provider, "/")
	if err := nxs.ValidateOrigin(origin); err != nil {
		fmt.Fprintf(os.Stderr, "provider origin: %v\n", err)
		os.Exit(2)
	}

	p := &probe{base: origin, token: *token, client: &http.Client{
		Timeout:   *timeout,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: *insecure}},
	}}
	if err := p.newKey(); err != nil {
		fmt.Fprintf(os.Stderr, "generate key: %v\n", err)
		os.Exit(1)
	}

	if err := p.step("discovery", func() error { return p.discovery() }); err != nil {
		os.Exit(1)
	}
	if err := p.step("register + complete", func() error { return p.register(*label) }); err != nil {
		os.Exit(1)
	}
	if err := p.step("heartbeat", func() error { return p.heartbeat() }); err != nil {
		os.Exit(1)
	}
	if !*keep {
		if err := p.step("deregister", p.deregister); err != nil {
			os.Exit(1)
		}
	}
	fmt.Println("nxsprobe: all steps passed")
}

func (p *probe) step(name string, fn func() error) error {
	fmt.Printf("\n=== %s\n", name)
	return fn()
}

func (p *probe) newKey() error {
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return err
	}
	x := make([]byte, 48)
	y := make([]byte, 48)
	priv.X.FillBytes(x)
	priv.Y.FillBytes(y)
	p.priv = priv
	p.jwk = nxs.PublicJWK{Crv: "P-384", Kty: "EC", X: nxs.Base64URL(x), Y: nxs.Base64URL(y)}
	return nil
}

func (p *probe) discovery() error {
	status, raw, err := p.do(http.MethodGet, nxs.DiscoveryPath, nil, nil)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("status %d: %s", status, raw)
	}
	var doc struct {
		Provider      string   `json:"provider"`
		Protocols     []string `json:"protocols"`
		Signatures    []string `json:"signatures"`
		Authorization struct {
			Schemes []string `json:"schemes"`
		} `json:"authorization"`
		Limits struct {
			HeartbeatIntervalMs int `json:"heartbeatIntervalMs"`
		} `json:"limits"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return fmt.Errorf("decode: %w", err)
	}
	if doc.Provider != p.base {
		return fmt.Errorf("provider mismatch: got %q want %q", doc.Provider, p.base)
	}
	if !contains(doc.Protocols, nxs.Protocol) {
		return fmt.Errorf("protocols %v do not include %q", doc.Protocols, nxs.Protocol)
	}
	if !contains(doc.Signatures, nxs.SignatureVersion) {
		return fmt.Errorf("signatures %v do not include %q", doc.Signatures, nxs.SignatureVersion)
	}
	fmt.Printf("provider=%s protocols=%v signatures=%v heartbeatIntervalMs=%d\n",
		doc.Provider, doc.Protocols, doc.Signatures, doc.Limits.HeartbeatIntervalMs)
	return nil
}

func (p *probe) register(label string) error {
	body := map[string]any{
		"protocol":     nxs.Protocol,
		"publicKeyJwk": p.jwk,
		"label":        label,
	}
	headers := map[string]string{}
	if p.token != "" {
		headers["Authorization"] = "Bearer " + p.token
	}
	status, raw, err := p.do(http.MethodPost, "/v1/nxs/register", body, headers)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("status %d: %s", status, raw)
	}
	var ch nxs.Challenge
	if err := json.Unmarshal(raw, &ch); err != nil {
		return fmt.Errorf("decode: %w", err)
	}
	if ch.Protocol != nxs.Protocol || ch.Signature != nxs.SignatureVersion {
		return fmt.Errorf("protocol/signature = %q/%q", ch.Protocol, ch.Signature)
	}
	if ch.Audience != p.base {
		return fmt.Errorf("audience mismatch: got %q want %q", ch.Audience, p.base)
	}
	if ch.Thumbprint != p.jwk.Thumbprint() {
		return fmt.Errorf("thumbprint mismatch: got %q", ch.Thumbprint)
	}
	if ch.PoW.Difficulty < 0 || ch.PoW.Difficulty > 24 {
		return fmt.Errorf("pow difficulty out of range: %d", ch.PoW.Difficulty)
	}
	if ch.ContextDigest != nxs.ContextDigest(ch.Context) {
		return fmt.Errorf("contextDigest mismatch")
	}
	if ch.ExpiresAt <= time.Now().UnixMilli() {
		return fmt.Errorf("challenge already expired")
	}
	fmt.Printf("challenge=%s mode=%s difficulty=%d expiresAt=%d\n",
		ch.ChallengeID, ch.Context.Mode, ch.PoW.Difficulty, ch.ExpiresAt)
	return p.completeChallenge(&ch)
}

func (p *probe) completeChallenge(ch *nxs.Challenge) error {
	idem := randomToken(24)
	nonce := "0"
	if ch.PoW.Difficulty > 0 {
		for i := 0; ; i++ {
			nonce = strconv.Itoa(i)
			payload := nxs.CompleteProofPayload(ch.Audience, ch.ChallengeID, ch.Nonce, ch.Thumbprint,
				ch.ContextDigest, ch.ExpiresAt, nonce, idem)
			if nxs.LeadingZeroBits(payload) >= ch.PoW.Difficulty {
				break
			}
			if i > 1<<26 {
				return fmt.Errorf("proof of work did not converge")
			}
		}
	}
	sig, err := nxs.SignP384(p.priv, nxs.CompleteProofPayload(ch.Audience, ch.ChallengeID, ch.Nonce,
		ch.Thumbprint, ch.ContextDigest, ch.ExpiresAt, nonce, idem))
	if err != nil {
		return err
	}
	status, raw, err := p.do(http.MethodPost, "/v1/nxs/complete", map[string]any{
		"protocol":       nxs.Protocol,
		"challengeId":    ch.ChallengeID,
		"proofNonce":     nonce,
		"idempotencyKey": idem,
		"signature":      sig,
	}, nil)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("status %d: %s", status, raw)
	}
	var reg nxs.RegistrationResponse
	if err := json.Unmarshal(raw, &reg); err != nil {
		return fmt.Errorf("decode: %w", err)
	}
	if reg.Protocol != nxs.Protocol || reg.Provider != p.base || reg.RegistrationID == "" ||
		reg.InstanceID == "" || reg.KeyID == "" || reg.LeaseGeneration < 1 {
		return fmt.Errorf("registration response invalid: %+v", reg)
	}
	p.instance, p.keyID, p.generation = reg.InstanceID, reg.KeyID, reg.LeaseGeneration
	fmt.Printf("registrationId=%s instanceId=%s keyId=%s generation=%d\n",
		reg.RegistrationID, reg.InstanceID, reg.KeyID, reg.LeaseGeneration)
	return nil
}

func (p *probe) heartbeat() error {
	p.sequence++
	ts := time.Now().UnixMilli()
	body := map[string]any{
		"acceptingPlayers": true,
		"capacity":         1,
		"connectedPlayers": map[string]any{"count": 0, "sampledAt": ts - 1},
	}
	status, raw, err := p.signedPost("/v1/nxs/heartbeat", body)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("status %d: %s", status, raw)
	}
	var hb nxs.HeartbeatResponse
	if err := json.Unmarshal(raw, &hb); err != nil {
		return fmt.Errorf("decode: %w", err)
	}
	if hb.CheckIn.LeaseMillis <= 0 || hb.CheckIn.AfterMillis <= 0 {
		return fmt.Errorf("check-in invalid: %+v", hb.CheckIn)
	}
	fmt.Printf("readiness=%t reasons=%v afterMillis=%d leaseMillis=%d\n",
		hb.Readiness.Routable, hb.Readiness.Reasons, hb.CheckIn.AfterMillis, hb.CheckIn.LeaseMillis)
	return nil
}

func (p *probe) deregister() error {
	p.sequence++
	status, raw, err := p.signedPost("/v1/nxs/deregister", map[string]any{})
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("status %d: %s", status, raw)
	}
	fmt.Printf("deregistered %s\n", p.instance)
	return nil
}

func (p *probe) signedPost(path string, body any) (int, []byte, error) {
	raw, err := json.Marshal(body)
	if err != nil {
		return 0, nil, err
	}
	ts := time.Now().UnixMilli()
	idem := randomToken(24)
	payload := nxs.RequestPayload(p.base, http.MethodPost, path, ts, p.instance, p.keyID,
		idem, p.generation, p.sequence, raw)
	sig, err := nxs.SignP384(p.priv, payload)
	if err != nil {
		return 0, nil, err
	}
	headers := map[string]string{
		"nxs-instance-id":       p.instance,
		"nxs-key-id":            p.keyID,
		"nxs-timestamp":         strconv.FormatInt(ts, 10),
		"nxs-signature-version": nxs.SignatureVersion,
		"nxs-generation":        strconv.FormatInt(p.generation, 10),
		"nxs-sequence":          strconv.FormatInt(p.sequence, 10),
		"nxs-signature":         sig,
		"idempotency-key":       idem,
	}
	status, out, err := p.do(http.MethodPost, path, body, headers)
	if err != nil {
		return 0, nil, err
	}
	fmt.Println(string(out))
	return status, out, nil
}

func (p *probe) do(method, path string, body any, headers map[string]string) (int, []byte, error) {
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return 0, nil, err
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, p.base+path, reader)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, out, nil
}

func randomToken(n int) string {
	const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		panic(err)
	}
	for i, b := range buf {
		buf[i] = alphabet[int(b)%len(alphabet)]
	}
	return string(buf)
}

func contains(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}
