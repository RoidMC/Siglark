package nxs

import (
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"strings"
)

var (
	profileFoundationRe = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,32}$`)
	profileAddressRe    = regexp.MustCompile(`[<>"\s]`)
)

// ProfileCandidate is one ICE candidate a host published in its host profile.
type ProfileCandidate struct {
	Foundation string `json:"foundation"`
	Priority   int64  `json:"priority"`
	Address    string `json:"address"`
	Port       int    `json:"port"`
	Type       string `json:"type"`
}

// parseProfileCandidates validates the candidates a host published. A profile
// that fails validation cannot be handed to a client as-is.
func parseProfileCandidates(profile *HostProfile) ([]ProfileCandidate, error) {
	if len(profile.Candidates) == 0 {
		return nil, fmt.Errorf("host profile has no candidate")
	}
	out := make([]ProfileCandidate, 0, len(profile.Candidates))
	for _, raw := range profile.Candidates {
		var c ProfileCandidate
		if err := json.Unmarshal(raw, &c); err != nil {
			return nil, fmt.Errorf("host profile candidate is malformed")
		}
		if !profileFoundationRe.MatchString(c.Foundation) {
			return nil, fmt.Errorf("host profile candidate foundation is malformed")
		}
		if c.Priority < 1 || c.Priority > 2147483647 {
			return nil, fmt.Errorf("host profile candidate priority is out of range")
		}
		if c.Port < 1 || c.Port > 65535 {
			return nil, fmt.Errorf("host profile candidate port is out of range")
		}
		if ip := net.ParseIP(c.Address); ip == nil || profileAddressRe.MatchString(c.Address) {
			return nil, fmt.Errorf("host profile candidate address is not an IP literal")
		}
		switch c.Type {
		case "host", "srflx", "relay":
		default:
			return nil, fmt.Errorf("host profile candidate type is unsupported")
		}
		out = append(out, c)
	}
	return out, nil
}

// RewriteAnswerCandidates replaces the candidates of a host-issued answer with
// the ones the host published in its profile. A host's assisted answer carries
// only its public endpoint, which a client on the same network can never reach;
// the profile lists every endpoint the host advertises.
//
// Only the candidate lines are replaced. The connection line is left exactly as
// the host wrote it: Geyser names its local virtual adapter there, and that is
// the path a client on this machine actually reaches. Pointing it at the WLAN
// address instead sends the DTLS handshake through a client tunnel that drops
// it.
func RewriteAnswerCandidates(answer string, profile *HostProfile) (string, error) {
	candidates, err := parseProfileCandidates(profile)
	if err != nil {
		return "", err
	}
	lines := strings.Split(strings.TrimRight(answer, "\r\n"), "\r\n")
	kept := make([]string, 0, len(lines)+len(candidates)+1)
	for _, line := range lines {
		if strings.HasPrefix(line, "a=candidate:") ||
			strings.HasPrefix(line, "a=remote-candidates:") ||
			line == "a=end-of-candidates" {
			continue
		}
		kept = append(kept, line)
	}
	for _, c := range candidates {
		line := fmt.Sprintf("a=candidate:%s 1 UDP %d %s %d typ %s", c.Foundation, c.Priority, c.Address, c.Port, c.Type)
		if c.Type == "srflx" {
			line += " raddr 0.0.0.0 rport 0"
		}
		kept = append(kept, line)
	}
	kept = append(kept, "a=end-of-candidates")
	return strings.Join(kept, "\r\n") + "\r\n", nil
}

