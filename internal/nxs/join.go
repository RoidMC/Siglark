package nxs

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
)

// JoinPath is the client-facing NetherNet signaling endpoint.
const JoinPath = "/v1/join"

// JoinHandler serves the endpoints a Bedrock client uses to discover and join
// a host through the provider.
type JoinHandler struct {
	svc        *Service
	hub        *ControlHub
	identities map[string]*HostIdentity
}

// NewJoinHandler builds the join front end. Identities maps a registration ID
// to the host identity used to sign answer assertions; a registration without
// one gets answers exactly as the host issued them.
func NewJoinHandler(svc *Service, hub *ControlHub, identities map[string]*HostIdentity) *JoinHandler {
	return &JoinHandler{svc: svc, hub: hub, identities: identities}
}

// Mount registers the status and join routes.
func (h *JoinHandler) Mount(r chi.Router) {
	r.Get(JoinPath, h.status)
	r.Post(JoinPath+"/{networkID}", h.join)
}

// pongData is the status document a client reads from GET /v1/join. Field
// order is part of the wire shape.
type pongData struct {
	DataVersion    int    `json:"dataVersion"`
	Name           string `json:"name"`
	Protocol       int    `json:"protocol"`
	Version        string `json:"version"`
	Level          string `json:"level"`
	Players        int64  `json:"players"`
	MaxPlayers     int64  `json:"maxPlayers"`
	GameType       int    `json:"gameType"`
	Editor         bool   `json:"editor"`
	Hardcore       bool   `json:"hardcore"`
	OnlineAuth     bool   `json:"onlineAuth"`
	SelfSignedAuth bool   `json:"selfSignedAuth"`
	Nonce          string `json:"nonce"`
	TransportLayer int    `json:"transportLayer"`
	Connection     int    `json:"connection"`
}

func (h *JoinHandler) status(w http.ResponseWriter, r *http.Request) {
	reg, err := h.svc.ResolveHost(r.Context(), r.Host)
	if err != nil || reg.ServerStatus == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if _, expired := h.svc.leaseExpiredAt(reg); expired {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	protocol, version := listingProtocol(reg)
	doc := pongData{
		DataVersion:    7,
		Name:           reg.ServerStatus.Name,
		Protocol:       protocol,
		Version:        version,
		Level:          reg.ServerStatus.Level,
		Players:        reg.ConnectedPlayers.Count,
		MaxPlayers:     reg.ServerStatus.MaxPlayerCount,
		GameType:       reg.ServerStatus.GameType,
		TransportLayer: 2,
		Connection:     4,
		OnlineAuth:     true,
		// Geyser's assisted path signs an answer with its provider-state
		// certificate and never adds a server identity assertion (only built-in
		// signaling does). A client told "not self-signed" waits for that
		// assertion and abandons the transport, so the listing must declare the
		// self-signed certificate the host actually uses.
		SelfSignedAuth: true,
		Nonce:          listingNonce(reg.RegistrationID),
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(raw)
}

func listingProtocol(reg *Registration) (int, string) {
	protocol, version := 2187, "1.26.50"
	if len(reg.BedrockProtocols) == 0 {
		return protocol, version
	}
	var reported struct {
		Accepted []int  `json:"accepted"`
		Version  string `json:"version"`
	}
	if err := json.Unmarshal(reg.BedrockProtocols, &reported); err != nil || len(reported.Accepted) == 0 {
		return protocol, version
	}
	protocol = reported.Accepted[len(reported.Accepted)-1]
	if reported.Version != "" {
		version = reported.Version
	}
	return protocol, version
}

// listingNonce is stable per registration and looks random to a client.
func listingNonce(registrationID string) string {
	sum := sha256.Sum256([]byte("nxs-pong-nonce\x00" + registrationID))
	return hex.EncodeToString(sum[:8])
}

func (h *JoinHandler) join(w http.ResponseWriter, r *http.Request) {
	networkText := chi.URLParam(r, "networkID")
	reject := func(status int, reason string, attrs ...any) {
		attrs = append([]any{"networkId", networkText, "host", r.Host, "status", status, "reason", reason}, attrs...)
		slog.Debug("nxs: join rejected", attrs...)
		w.WriteHeader(status)
	}

	if networkText == "" || strings.Contains(networkText, "/") {
		reject(http.StatusNotFound, "invalid network id")
		return
	}
	networkID, ok := parseNetworkID(networkText)
	if !ok {
		reject(http.StatusBadRequest, "unparseable network id")
		return
	}

	sdp, status := readOffer(w, r)
	if status != 0 {
		reject(status, "unreadable offer body")
		return
	}

	reg, err := h.svc.ResolveHost(r.Context(), r.Host)
	if err != nil {
		reject(http.StatusNotFound, "unknown host", "error", err)
		return
	}
	if _, expired := h.svc.leaseExpiredAt(reg); expired {
		reject(http.StatusServiceUnavailable, "lease expired")
		return
	}
	if !reg.AcceptingPlayers {
		reject(http.StatusServiceUnavailable, "host not accepting players")
		return
	}

	offer, err := ParseClientOffer(sdp)
	if err != nil {
		reject(http.StatusBadRequest, "malformed client offer", "error", err)
		return
	}
	verified, err := h.svc.verifier.Verify(sdp, offer, h.svc.now())
	if err != nil {
		canonical, _ := CanonicalFingerprintJSON(sdp)
		reject(http.StatusUnauthorized, "client identity rejected", "error", err,
			"canonicalFingerprints", canonical, "offer", sdp)
		return
	}

	var profile HostProfile
	if len(reg.ProfileJSON) > 0 {
		if err := json.Unmarshal(reg.ProfileJSON, &profile); err != nil {
			reject(http.StatusServiceUnavailable, "unreadable host profile", "error", err)
			return
		}
	}
	if profile.StatelessAdmission == nil || profile.DTLSFingerprint == "" || reg.Incarnation == "" {
		reject(http.StatusServiceUnavailable, "host profile lacks assisted join data",
			"statelessAdmission", profile.StatelessAdmission != nil,
			"dtlsFingerprint", profile.DTLSFingerprint != "", "incarnation", reg.Incarnation != "")
		return
	}
	epoch, installed := reg.AdmissionKeys[reg.ActiveAdmissionKeyID]
	if !installed || !epoch.Acked {
		reject(http.StatusServiceUnavailable, "admission key not installed",
			"installed", installed, "acked", epoch.Acked)
		return
	}

	fingerprint, err := offer.FingerprintSHA256()
	if err != nil {
		reject(http.StatusBadRequest, "offer fingerprint unavailable", "error", err)
		return
	}

	audience := AdmissionAudience(reg.Incarnation)
	binding := IdentityBinding(epoch.Secret, audience, verified.CPKDER)
	var binding16 [16]byte
	copy(binding16[:], binding)
	expiresAt := h.svc.now().Add(h.svc.opts.AdmissionTTL).Truncate(time.Second).UnixMilli()
	claims := AdmissionClaims{
		ExpiresAt:               expiresAt,
		ClientFingerprintSHA256: fingerprint,
		ClientSCTPPort:          uint16(offer.SCTPPort),
		ClientMaxMessageSize:    uint32(offer.MaxMessageSize),
		NetworkID:               networkID,
		ClientICEPassword:       offer.Password,
	}
	minted, err := MintAdmission(
		AdmissionKey{KeyID: epoch.KeyID, Secret: epoch.Secret},
		audience, offer.Ufrag, claims, binding16, h.svc.now(),
	)
	if err != nil {
		reject(http.StatusInternalServerError, "admission minting failed", "error", err)
		return
	}

	prepared, err := PrepareClientOffer(sdp, remoteIP(r), maxOfferCandidates)
	if err != nil {
		reject(http.StatusBadRequest, "offer cannot be prepared", "error", err)
		return
	}

	answer, err := h.hub.Assist(r.Context(), AssistRequest{
		InstanceID:      reg.InstanceID,
		Generation:      reg.LeaseGeneration,
		Incarnation:     reg.Incarnation,
		KeyID:           epoch.KeyID,
		HostFingerprint: profile.DTLSFingerprint,
		NetworkID:       networkText,
		CPK:             verified.CPK,
		LocalUfrag:      minted.AnswerUfrag,
		LocalPassword:   minted.ICEPassword,
		Offer:           prepared,
	})
	if err != nil {
		proto := AsError(err)
		status := proto.Status
		if status == 0 {
			status = http.StatusInternalServerError
		}
		reject(status, "host refused assisted join", "error", err, "code", proto.Code)
		return
	}
	// A host's assisted answer carries only its public endpoint, so the
	// advertised addresses have to be substituted in. Its connection line stays
	// untouched: it names a local adapter the client really reaches.
	if len(profile.Candidates) > 0 {
		answer, err = RewriteAnswerCandidates(answer, &profile)
		if err != nil {
			reject(http.StatusServiceUnavailable, "answer cannot be rewritten", "error", err)
			return
		}
	}
	// Geyser's assisted path never adds a server identity assertion, but a
	// client expects one to bind the answer's DTLS certificate to a signer.
	// Mint it from the configured host identity.
	if identity := h.identities[reg.RegistrationID]; identity != nil {
		value, err := identity.Assertion(answer)
		if err != nil {
			reject(http.StatusServiceUnavailable, "identity assertion failed", "error", err)
			return
		}
		answer = InsertIdentityAttribute(answer, value)
	}
	slog.Debug("nxs: join accepted", "networkId", networkText, "host", r.Host,
		"xuid", verified.XUID, "xname", verified.XName,
		"tokenAlg", verified.TokenAlg, "tokenIssuer", verified.TokenIssuer,
		"tokenKeyId", verified.TokenKeyID)
	w.Header().Set("Content-Type", "application/sdp")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(answer))
}

func readOffer(w http.ResponseWriter, r *http.Request) (string, int) {
	r.Body = http.MaxBytesReader(w, r.Body, maxOfferBodyBytes)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			return "", http.StatusRequestEntityTooLarge
		}
		return "", http.StatusBadRequest
	}
	if len(body) == 0 || len(body) > maxOfferBodyBytes {
		return "", http.StatusBadRequest
	}
	return string(body), 0
}

func parseNetworkID(s string) (uint64, bool) {
	if len(s) == 0 || len(s) > 20 || s[0] == '0' {
		return 0, false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, false
		}
	}
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil || n == 0 {
		return 0, false
	}
	return n, true
}

func remoteIP(r *http.Request) net.IP {
	host := r.RemoteAddr
	if name, _, err := net.SplitHostPort(host); err == nil {
		host = name
	}
	return net.ParseIP(host)
}
