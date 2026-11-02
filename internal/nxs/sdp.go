package nxs

import (
	"encoding/hex"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
)

// Client offer limits mirror what a host enforces on an assisted join.
const (
	maxOfferLines          = 256
	maxOfferCandidates     = 32
	maxInferredCandidates  = 8
	inferredCandidateBase  = 90000000
	inferredCandidatePrio  = 1677721855
	maxOfferBodyBytes      = 65536
	maxAnswerBodyBytes     = 65536
	offerMediaLine         = "application [0-9]{1,5} UDP/DTLS/SCTP webrtc-datachannel"
	clientOfferSCTPPort    = 5000
	clientOfferMaxMsgSize  = 262144
	maxControlMessageBytes = 524288
)

var (
	offerMediaRe  = regexp.MustCompile("^" + offerMediaLine)
	fingerprintRe = regexp.MustCompile(`^sha-256 (?i:[0-9a-f]{2})(?::(?i:[0-9a-f]{2})){31}$`)
	iceValueRe    = regexp.MustCompile(`^[A-Za-z0-9+/]+$`)
)

// OfferCandidate is one a=candidate line from a client offer.
type OfferCandidate struct {
	Component int
	Protocol  string
	Priority  int64
	Address   string
	Port      int
	Type      string
	Line      string
}

// ClientOffer is the validated subset of a client SDP offer the provider needs
// before it can mint an admission and ask a host for an answer.
type ClientOffer struct {
	Ufrag          string
	Password       string
	Fingerprints   []string
	SCTPPort       int
	MaxMessageSize int
	Candidates     []OfferCandidate

	lines []string
}

// ParseClientOffer validates an offer as the protocol requires and returns the
// values needed to build an assisted join. The same rules the host applies to
// an assisted join are enforced here, so a malformed offer is refused with 400
// rather than sent on and refused later.
func ParseClientOffer(sdp string) (*ClientOffer, error) {
	if len(sdp) > maxOfferBodyBytes {
		return nil, fmt.Errorf("offer exceeds %d bytes", maxOfferBodyBytes)
	}
	lines := splitSDP(sdp)
	if len(lines) > maxOfferLines {
		return nil, fmt.Errorf("offer has more than %d lines", maxOfferLines)
	}
	for _, line := range lines {
		if strings.ContainsRune(line, 0) {
			return nil, fmt.Errorf("offer contains a NUL byte")
		}
	}

	media, err := singleLine(lines, "m=", "m=")
	if err != nil {
		return nil, err
	}
	if !offerMediaRe.MatchString(media) {
		return nil, fmt.Errorf("offer media line is unsupported")
	}
	setup, err := singleLine(lines, "a=setup:", "a=setup:")
	if err != nil {
		return nil, err
	}
	if setup != "actpass" {
		return nil, fmt.Errorf("offer must use a=setup:actpass")
	}
	portText, err := singleLine(lines, "a=sctp-port:", "a=sctp-port:")
	if err != nil {
		return nil, err
	}
	if portText != strconv.Itoa(clientOfferSCTPPort) {
		return nil, fmt.Errorf("offer SCTP port must be %d", clientOfferSCTPPort)
	}
	sizeText, err := singleLine(lines, "a=max-message-size:", "a=max-message-size:")
	if err != nil {
		return nil, err
	}
	if sizeText != strconv.Itoa(clientOfferMaxMsgSize) {
		return nil, fmt.Errorf("offer max-message-size must be %d", clientOfferMaxMsgSize)
	}
	for _, line := range lines {
		if line == "a=ice-lite" {
			return nil, fmt.Errorf("offer must not be ICE lite")
		}
	}

	ufrag, err := singleLine(lines, "a=ice-ufrag:", "a=ice-ufrag:")
	if err != nil {
		return nil, err
	}
	if len(ufrag) < 4 || len(ufrag) > 256 || !iceValueRe.MatchString(ufrag) {
		return nil, fmt.Errorf("offer ice-ufrag is malformed")
	}
	password, err := singleLine(lines, "a=ice-pwd:", "a=ice-pwd:")
	if err != nil {
		return nil, err
	}
	if len(password) < 22 || len(password) > 256 || !iceValueRe.MatchString(password) {
		return nil, fmt.Errorf("offer ice-pwd is malformed")
	}
	fingerprint, err := singleLine(lines, "a=fingerprint:", "a=fingerprint:")
	if err != nil {
		return nil, err
	}
	if !fingerprintRe.MatchString(fingerprint) {
		return nil, fmt.Errorf("offer fingerprint is malformed")
	}

	offer := &ClientOffer{
		Ufrag:          ufrag,
		Password:       password,
		Fingerprints:   []string{fingerprint},
		SCTPPort:       clientOfferSCTPPort,
		MaxMessageSize: clientOfferMaxMsgSize,
		lines:          lines,
	}
	for _, line := range lines {
		if !strings.HasPrefix(line, "a=candidate:") {
			continue
		}
		candidate, err := parseOfferCandidate(line)
		if err != nil {
			return nil, err
		}
		if len(offer.Candidates) == maxOfferCandidates {
			return nil, fmt.Errorf("offer has more than %d candidates", maxOfferCandidates)
		}
		offer.Candidates = append(offer.Candidates, candidate)
	}
	if len(offer.Candidates) == 0 {
		return nil, fmt.Errorf("offer has no numeric candidate")
	}
	return offer, nil
}

func splitSDP(sdp string) []string {
	raw := strings.Split(strings.ReplaceAll(sdp, "\r\n", "\n"), "\n")
	out := make([]string, 0, len(raw))
	for _, line := range raw {
		if line == "" {
			continue
		}
		out = append(out, line)
	}
	return out
}

func singleLine(lines []string, prefix, label string) (string, error) {
	var found []string
	for _, line := range lines {
		if strings.HasPrefix(line, prefix) {
			found = append(found, strings.TrimSpace(strings.TrimPrefix(line, prefix)))
		}
	}
	if len(found) != 1 {
		return "", fmt.Errorf("offer must carry exactly one %s line", label)
	}
	return found[0], nil
}

func parseOfferCandidate(line string) (OfferCandidate, error) {
	parts := strings.Split(strings.TrimPrefix(line, "a=candidate:"), " ")
	if len(parts) < 8 || len(parts) > 24 {
		return OfferCandidate{}, fmt.Errorf("offer candidate is malformed")
	}
	if parts[1] != "1" || !strings.EqualFold(parts[2], "UDP") {
		return OfferCandidate{}, fmt.Errorf("offer candidate must be component 1 UDP")
	}
	priority, err := strconv.ParseInt(parts[3], 10, 64)
	if err != nil || priority < 1 || priority > 2147483647 {
		return OfferCandidate{}, fmt.Errorf("offer candidate priority is malformed")
	}
	if !isNumericAddress(parts[4]) {
		return OfferCandidate{}, fmt.Errorf("offer candidate address is not an IP literal")
	}
	port, err := strconv.Atoi(parts[5])
	if err != nil || port < 1 || port > 65535 {
		return OfferCandidate{}, fmt.Errorf("offer candidate port is malformed")
	}
	if parts[6] != "typ" || !isOfferCandidateType(parts[7]) {
		return OfferCandidate{}, fmt.Errorf("offer candidate type is malformed")
	}
	return OfferCandidate{
		Component: 1,
		Protocol:  "UDP",
		Priority:  priority,
		Address:   parts[4],
		Port:      port,
		Type:      parts[7],
		Line:      line,
	}, nil
}

func isOfferCandidateType(s string) bool {
	switch s {
	case "host", "srflx", "prflx", "relay":
		return true
	default:
		return false
	}
}

func isNumericAddress(s string) bool {
	return net.ParseIP(s) != nil
}

// FingerprintSHA256 returns the first offered DTLS certificate fingerprint.
func (o *ClientOffer) FingerprintSHA256() ([32]byte, error) {
	var out [32]byte
	if len(o.Fingerprints) == 0 {
		return out, fmt.Errorf("offer has no fingerprint")
	}
	value := o.Fingerprints[0]
	if !strings.HasPrefix(strings.ToLower(value), "sha-256 ") {
		return out, fmt.Errorf("offer fingerprint is not sha-256")
	}
	digest := strings.TrimSpace(value[len("sha-256 "):])
	parts := strings.Split(digest, ":")
	if len(parts) != 32 {
		return out, fmt.Errorf("offer fingerprint digest is malformed")
	}
	for i, part := range parts {
		if len(part) != 2 {
			return out, fmt.Errorf("offer fingerprint digest is malformed")
		}
		b, err := hex.DecodeString(part)
		if err != nil {
			return out, fmt.Errorf("offer fingerprint digest is malformed")
		}
		out[i] = b[0]
	}
	return out, nil
}

// CanonicalFingerprintJSON is the detached JWS payload for the offer's
// fingerprints, built exactly as the specification prescribes.
func CanonicalFingerprintJSON(sdp string) (string, error) {
	var b strings.Builder
	b.WriteString(`{"fingerprint":[`)
	first := true
	for _, line := range splitSDP(sdp) {
		if !strings.HasPrefix(line, "a=fingerprint:") {
			continue
		}
		value := strings.TrimSpace(strings.TrimPrefix(line, "a=fingerprint:"))
		fields := strings.Split(value, " ")
		if len(fields) != 2 || fields[0] == "" || fields[1] == "" {
			return "", fmt.Errorf("offer fingerprint line is malformed")
		}
		if !first {
			b.WriteString(",")
		}
		first = false
		b.WriteString(`{"algorithm":"` + fields[0] + `","digest":"` + fields[1] + `"}`)
	}
	b.WriteString(`]}`)
	return b.String(), nil
}

// PrepareClientOffer keeps only numeric client candidates and, for clients that
// cannot learn their public address, adds predicted srflx candidates built from
// the address the signaling request came from.
func PrepareClientOffer(sdp string, from net.IP, max int) (string, error) {
	offer, err := ParseClientOffer(sdp)
	if err != nil {
		return "", err
	}
	if max <= 0 || max > maxOfferCandidates {
		max = maxOfferCandidates
	}

	var inferred []string
	if isRoutableIP(from) && !offerHasReflexive(offer) {
		ports := make([]int, 0, maxInferredCandidates)
		seen := map[int]bool{}
		for _, c := range offer.Candidates {
			if c.Type != "host" || !strings.EqualFold(c.Protocol, "UDP") {
				continue
			}
			if seen[c.Port] || len(ports) == maxInferredCandidates {
				continue
			}
			seen[c.Port] = true
			ports = append(ports, c.Port)
		}
		for i, port := range ports {
			inferred = append(inferred, fmt.Sprintf(
				"a=candidate:%d 1 UDP %d %s %d typ srflx raddr 0.0.0.0 rport 0",
				inferredCandidateBase+i, inferredCandidatePrio, from.String(), port,
			))
		}
	}
	keep := max - len(inferred)
	if keep < 1 {
		keep = 1
	}

	out := make([]string, 0, len(offer.lines)+len(inferred))
	lastCandidate := -1
	kept := 0
	for _, line := range offer.lines {
		// The assertion carries the player's game token. The provider has already
		// verified it and passes the binding key instead, so it must not reach the
		// host.
		if strings.HasPrefix(line, "a=identity:") {
			continue
		}
		if strings.HasPrefix(line, "a=candidate:") {
			if kept == keep {
				continue
			}
			kept++
			lastCandidate = len(out)
		}
		out = append(out, line)
	}
	if len(inferred) > 0 {
		if lastCandidate >= 0 {
			at := lastCandidate + 1
			out = append(out[:at], append(inferred, out[at:]...)...)
		} else {
			out = append(out, inferred...)
		}
	}

	var b strings.Builder
	for _, line := range out {
		b.WriteString(line)
		b.WriteString("\r\n")
	}
	return b.String(), nil
}

func offerHasReflexive(o *ClientOffer) bool {
	for _, c := range o.Candidates {
		if c.Type != "host" {
			return true
		}
	}
	return false
}

// isRoutableIP reports whether an address is one a peer elsewhere might reach.
func isRoutableIP(ip net.IP) bool {
	if ip == nil || ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return false
	}
	if v4 := ip.To4(); v4 != nil {
		switch {
		case v4[0] == 10:
			return false
		case v4[0] == 172 && v4[1] >= 16 && v4[1] <= 31:
			return false
		case v4[0] == 192 && v4[1] == 168:
			return false
		case v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127: // carrier-grade NAT
			return false
		case v4[0] == 169 && v4[1] == 254:
			return false
		}
		return true
	}
	// IPv6 unique local addresses
	return ip[0] != 0xfc && ip[0] != 0xfd
}
