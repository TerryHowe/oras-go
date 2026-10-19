/*
Copyright The ORAS Authors.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package auth

import (
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

// realmTrustLevel is the trust a realmTrust grants to a realm host.
type realmTrustLevel int

const (
	// realmUntrusted applies the full internal-address check.
	realmUntrusted realmTrustLevel = iota
	// realmTrustedBroadly allows internal addresses other than link-local and
	// cloud metadata addresses. It is granted by a `*.domain` pattern or by
	// Client.AllowInternalRealms.
	realmTrustedBroadly
	// realmTrustedExplicitly skips the address check altogether. It is
	// granted only to a host named exactly in Client.TrustedRealmHosts.
	realmTrustedExplicitly
)

// metadataAddrs are cloud instance metadata service addresses outside the
// link-local ranges. They stay blocked under broad trust.
var metadataAddrs = []netip.Addr{
	netip.MustParseAddr("100.100.100.200"), // Alibaba Cloud
	netip.MustParseAddr("fd00:ec2::254"),   // AWS (IPv6)
	netip.MustParseAddr("fd20:ce::254"),    // Google Cloud (IPv6)
}

// isMetadataAddr reports whether addr is a link-local address, which covers
// the 169.254.169.254 metadata service of most clouds, or one of
// metadataAddrs.
func isMetadataAddr(addr netip.Addr) bool {
	addr = addr.Unmap()
	if addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() {
		return true
	}
	for _, m := range metadataAddrs {
		if addr == m {
			return true
		}
	}
	return false
}

// trustedHost is a normalized entry of Client.TrustedRealmHosts.
type trustedHost struct {
	// name is the lower-cased host name or canonical IP address. For a
	// suffix pattern it is the suffix with its leading dot, e.g.
	// ".corp.example".
	name string
	// suffix reports whether the entry is a `*.domain` pattern.
	suffix bool
	// port is the port the entry is restricted to, or empty for any port.
	port string
}

// realmTrust is the normalized form of the realm trust configured on a
// Client. A nil *realmTrust trusts nothing.
type realmTrust struct {
	hosts         []trustedHost
	allowInternal bool
}

// newRealmTrust normalizes hosts and allowInternal into a realmTrust, or
// returns nil when nothing is trusted. Entries that cannot be parsed are
// dropped, so a malformed entry never widens trust.
func newRealmTrust(hosts []string, allowInternal bool) *realmTrust {
	trust := &realmTrust{allowInternal: allowInternal}
	for _, h := range hosts {
		if th, ok := parseTrustedHost(h); ok {
			trust.hosts = append(trust.hosts, th)
		}
	}
	if len(trust.hosts) == 0 && !trust.allowInternal {
		return nil
	}
	return trust
}

// parseTrustedHost parses an entry of Client.TrustedRealmHosts. An entry is a
// host name, an IP address, or a `*.domain` pattern, optionally followed by a
// port. IPv6 addresses take a port only in brackets, e.g. "[fd00::1]:8443".
func parseTrustedHost(s string) (trustedHost, bool) {
	s = strings.TrimSpace(s)
	if s == "" || strings.ContainsAny(s, "/?#@ \t") {
		return trustedHost{}, false
	}
	host, port := s, ""
	if h, p, err := net.SplitHostPort(s); err == nil {
		n, err := strconv.ParseUint(p, 10, 16)
		if err != nil || n == 0 {
			return trustedHost{}, false
		}
		host, port = h, strconv.FormatUint(n, 10)
	} else if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") {
		host = s[1 : len(s)-1]
	}
	if rest, ok := strings.CutPrefix(host, "*."); ok {
		name := normalizeHostName(rest)
		if name == "" || strings.Contains(name, "*") || strings.Contains(name, "..") || strings.HasPrefix(name, ".") {
			return trustedHost{}, false
		}
		return trustedHost{name: "." + name, suffix: true, port: port}, true
	}
	name := normalizeHostName(host)
	if name == "" || strings.Contains(name, "*") {
		return trustedHost{}, false
	}
	return trustedHost{name: name, port: port}, true
}

// normalizeHostName lower-cases host and strips a trailing dot. An IP address
// is rewritten in its canonical form, so that equivalent spellings compare
// equal.
func normalizeHostName(host string) string {
	if addr, err := netip.ParseAddr(host); err == nil {
		return addr.Unmap().String()
	}
	return strings.TrimSuffix(strings.ToLower(host), ".")
}

// level returns the trust t grants to the host of u. A host named exactly
// wins over a matching suffix pattern. A suffix pattern does not match the
// domain itself, so "*.corp.example" matches "gitlab.corp.example" but not
// "corp.example", nor IP addresses.
func (t *realmTrust) level(u *url.URL) realmTrustLevel {
	if t == nil {
		return realmUntrusted
	}
	hostname := u.Hostname()
	host := normalizeHostName(hostname)
	_, err := netip.ParseAddr(hostname)
	isIP := err == nil
	port := u.Port()
	if port == "" {
		switch strings.ToLower(u.Scheme) {
		case "https":
			port = "443"
		case "http":
			port = "80"
		}
	}
	level := realmUntrusted
	if t.allowInternal {
		level = realmTrustedBroadly
	}
	for _, th := range t.hosts {
		if th.port != "" && th.port != port {
			continue
		}
		if !th.suffix {
			if host == th.name {
				return realmTrustedExplicitly
			}
			continue
		}
		if isIP {
			continue
		}
		if len(host) > len(th.name) && strings.HasSuffix(host, th.name) {
			level = realmTrustedBroadly
		}
	}
	return level
}
