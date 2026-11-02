package nxs

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// ValidateOrigin enforces the canonical origin profile shared by signed
// contexts: lowercase ASCII DNS, canonical IPv4/IPv6 literals, no path,
// query, fragment, userinfo, escapes or default port.
func ValidateOrigin(s string) error {
	if s == "" {
		return fmt.Errorf("origin is empty")
	}
	if len(s) > 267 {
		return fmt.Errorf("origin exceeds 267 characters")
	}
	for _, r := range s {
		if r <= 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) {
			return fmt.Errorf("origin contains whitespace or control characters")
		}
	}
	if strings.ContainsAny(s, "\\%@?#") {
		return fmt.Errorf("origin contains a prohibited character")
	}

	var scheme, rest string
	switch {
	case strings.HasPrefix(s, "https://"):
		scheme, rest = "https", strings.TrimPrefix(s, "https://")
	case strings.HasPrefix(s, "http://"):
		scheme, rest = "http", strings.TrimPrefix(s, "http://")
	default:
		return fmt.Errorf("origin must start with https:// or http://")
	}
	if rest == "" {
		return fmt.Errorf("origin has no host")
	}

	var host, port string
	if rest[0] == '[' {
		end := strings.IndexByte(rest, ']')
		if end < 0 {
			return fmt.Errorf("origin has an unterminated IPv6 literal")
		}
		host = rest[:end+1]
		tail := rest[end+1:]
		if tail != "" {
			if !strings.HasPrefix(tail, ":") || len(tail) == 1 {
				return fmt.Errorf("origin has an invalid authority")
			}
			port = tail[1:]
		}
	} else {
		idx := strings.IndexByte(rest, ':')
		if idx >= 0 {
			if idx == len(rest)-1 {
				return fmt.Errorf("origin has an empty port")
			}
			host, port = rest[:idx], rest[idx+1:]
		} else {
			host = rest
		}
	}
	if host == "" {
		return fmt.Errorf("origin has no host")
	}

	hostKind := "dns"
	switch {
	case strings.HasPrefix(host, "["):
		if err := validateIPv6(host[1 : len(host)-1]); err != nil {
			return err
		}
		hostKind = "ipv6"
	case looksNumericHost(host):
		if err := validateIPv4(host); err != nil {
			return err
		}
		hostKind = "ipv4"
	default:
		if err := validateDNSName(host); err != nil {
			return err
		}
	}

	if port != "" {
		if len(port) > 5 {
			return fmt.Errorf("origin port has too many digits")
		}
		if len(port) > 1 && port[0] == '0' {
			return fmt.Errorf("origin port has a leading zero")
		}
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return fmt.Errorf("origin port is out of range")
		}
		if scheme == "https" && n == 443 {
			return fmt.Errorf("origin must omit the default https port")
		}
		if scheme == "http" && n == 80 {
			return fmt.Errorf("origin must omit the default http port")
		}
	}

	if scheme == "http" {
		switch hostKind {
		case "ipv4":
			if host != "127.0.0.1" {
				return fmt.Errorf("http origins only allow localhost, 127.0.0.1 or [::1]")
			}
		case "ipv6":
			if host != "[::1]" {
				return fmt.Errorf("http origins only allow localhost, 127.0.0.1 or [::1]")
			}
		default:
			if host != "localhost" {
				return fmt.Errorf("http origins only allow localhost, 127.0.0.1 or [::1]")
			}
		}
	}
	return nil
}

func looksNumericHost(host string) bool {
	for _, r := range host {
		if (r < '0' || r > '9') && r != '.' {
			return false
		}
	}
	return host != ""
}

func validateIPv4(host string) error {
	parts := strings.Split(host, ".")
	if len(parts) != 4 {
		return fmt.Errorf("IPv4 origin must have four octets")
	}
	for _, p := range parts {
		if p == "" || len(p) > 3 {
			return fmt.Errorf("IPv4 origin has an invalid octet")
		}
		if len(p) > 1 && p[0] == '0' {
			return fmt.Errorf("IPv4 origin has a leading zero")
		}
		n, err := strconv.Atoi(p)
		if err != nil || n > 255 {
			return fmt.Errorf("IPv4 origin octet is out of range")
		}
	}
	return nil
}

func validateDNSName(host string) error {
	if len(host) > 253 {
		return fmt.Errorf("DNS origin exceeds 253 characters")
	}
	labels := strings.Split(host, ".")
	for i, label := range labels {
		if label == "" || len(label) > 63 {
			return fmt.Errorf("DNS origin has an invalid label length")
		}
		if strings.HasPrefix(label, "xn--") {
			return fmt.Errorf("DNS origin may not contain an xn-- label")
		}
		for j := 0; j < len(label); j++ {
			c := label[j]
			if c >= 'A' && c <= 'Z' {
				return fmt.Errorf("DNS origin must be lowercase")
			}
			if !(c >= 'a' && c <= 'z') && !(c >= '0' && c <= '9') && c != '-' {
				return fmt.Errorf("DNS origin has an invalid character")
			}
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return fmt.Errorf("DNS origin label may not start or end with a hyphen")
		}
		if i == len(labels)-1 {
			if label[0] < 'a' || label[0] > 'z' {
				return fmt.Errorf("DNS origin final label must start with a letter")
			}
		}
	}
	return nil
}

func validateIPv6(host string) error {
	if host == "" || strings.Contains(host, "%") {
		return fmt.Errorf("IPv6 origin is invalid")
	}
	addr, err := netip.ParseAddr(host)
	if err != nil || !addr.Is6() || addr.Is4() {
		return fmt.Errorf("IPv6 origin is invalid")
	}
	if canonicalIPv6(addr) != host {
		return fmt.Errorf("IPv6 origin is not canonical")
	}
	return nil
}

func canonicalIPv6(addr netip.Addr) string {
	b := addr.As16()
	var groups [8]uint16
	for i := range groups {
		groups[i] = uint16(b[2*i])<<8 | uint16(b[2*i+1])
	}
	bestStart, bestLen := -1, 0
	for i := 0; i < 8; {
		if groups[i] != 0 {
			i++
			continue
		}
		j := i
		for j < 8 && groups[j] == 0 {
			j++
		}
		if j-i > bestLen {
			bestStart, bestLen = i, j-i
		}
		i = j
	}
	if bestLen >= 2 {
		left := renderIPv6Groups(groups[:bestStart])
		right := renderIPv6Groups(groups[bestStart+bestLen:])
		return left + "::" + right
	}
	return renderIPv6Groups(groups[:])
}

func renderIPv6Groups(groups []uint16) string {
	parts := make([]string, len(groups))
	for i, g := range groups {
		parts[i] = fmt.Sprintf("%x", g)
	}
	return strings.Join(parts, ":")
}
