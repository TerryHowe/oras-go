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
	"net/netip"
)

// DefaultBlockedRealmPrefixes returns a fresh copy of the address prefixes that
// are blocked as bearer realm destinations when Client.BlockedRealmPrefixes is
// nil:
//
//   - loopback: 127.0.0.0/8, ::1/128
//   - link-local: 169.254.0.0/16, fe80::/10, which covers the instance metadata
//     service of most cloud providers (169.254.169.254)
//   - link-local multicast: 224.0.0.0/24, ff02::/16
//   - unspecified: 0.0.0.0/8, ::/128
//   - metadata services outside link-local: 100.100.100.200/32 (Alibaba Cloud),
//     fd00:ec2::254/128 (AWS IPv6), fd20:ce::254/128 (Google Cloud IPv6) and
//     168.63.129.16/32 (Azure WireServer)
//
// Private (RFC 1918), unique local (fc00::/7) and carrier-grade NAT
// (100.64.0.0/10) addresses are not blocked by default; see
// PrivateRealmPrefixes.
func DefaultBlockedRealmPrefixes() []netip.Prefix {
	return []netip.Prefix{
		netip.MustParsePrefix("127.0.0.0/8"),
		netip.MustParsePrefix("::1/128"),
		netip.MustParsePrefix("169.254.0.0/16"),
		netip.MustParsePrefix("fe80::/10"),
		netip.MustParsePrefix("224.0.0.0/24"),
		netip.MustParsePrefix("ff02::/16"),
		netip.MustParsePrefix("0.0.0.0/8"),
		netip.MustParsePrefix("::/128"),
		netip.MustParsePrefix("100.100.100.200/32"),
		netip.MustParsePrefix("fd00:ec2::254/128"),
		netip.MustParsePrefix("fd20:ce::254/128"),
		netip.MustParsePrefix("168.63.129.16/32"),
	}
}

// PrivateRealmPrefixes returns a fresh copy of the private address prefixes:
// RFC 1918 (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16), unique local
// (fc00::/7) and carrier-grade NAT (100.64.0.0/10).
//
// Append them to DefaultBlockedRealmPrefixes for a strict mode that also
// rejects realms on internal networks:
//
//	client.BlockedRealmPrefixes = append(
//		auth.DefaultBlockedRealmPrefixes(), auth.PrivateRealmPrefixes()...)
func PrivateRealmPrefixes() []netip.Prefix {
	return []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("172.16.0.0/12"),
		netip.MustParsePrefix("192.168.0.0/16"),
		netip.MustParsePrefix("fc00::/7"),
		netip.MustParsePrefix("100.64.0.0/10"),
	}
}

// effectiveBlockedRealmPrefixes resolves the configured list: nil selects the
// defaults, any non-nil list (even an empty one) is used as is.
func effectiveBlockedRealmPrefixes(configured []netip.Prefix) []netip.Prefix {
	if configured == nil {
		return DefaultBlockedRealmPrefixes()
	}
	return configured
}

// blockedRealmPrefix returns the first prefix in prefixes that contains addr.
// Besides addr itself, the IPv4 address embedded in an IPv4-mapped
// (::ffff:0:0/96), NAT64 (64:ff9b::/96) or 6to4 (2002::/16) address is
// matched, so that these forms cannot be used to reach a blocked IPv4 prefix.
func blockedRealmPrefix(addr netip.Addr, prefixes []netip.Prefix) (netip.Prefix, bool) {
	// A zone makes Prefix.Contains report false, which would let fe80::1%eth0
	// slip past the link-local prefix.
	addr = addr.WithZone("")
	candidates := []netip.Addr{addr, addr.Unmap()}
	if embedded, ok := embeddedIPv4(addr); ok {
		candidates = append(candidates, embedded)
	}
	for _, p := range prefixes {
		for _, c := range candidates {
			if p.Contains(c) {
				return p, true
			}
		}
	}
	return netip.Prefix{}, false
}

var (
	nat64Prefix = netip.MustParsePrefix("64:ff9b::/96")
	sixToFour   = netip.MustParsePrefix("2002::/16")
)

// embeddedIPv4 extracts the IPv4 address carried by a NAT64 or 6to4 address.
func embeddedIPv4(addr netip.Addr) (netip.Addr, bool) {
	if !addr.Is6() || addr.Is4In6() {
		return netip.Addr{}, false
	}
	b := addr.As16()
	switch {
	case nat64Prefix.Contains(addr):
		return netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]}), true
	case sixToFour.Contains(addr):
		return netip.AddrFrom4([4]byte{b[2], b[3], b[4], b[5]}), true
	}
	return netip.Addr{}, false
}
