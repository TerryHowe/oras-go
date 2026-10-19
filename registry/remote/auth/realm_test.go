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
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
)

func Test_parseTrustedHost(t *testing.T) {
	tests := []struct {
		in     string
		want   trustedHost
		wantOK bool
	}{
		{"gitlab.corp.example", trustedHost{name: "gitlab.corp.example"}, true},
		{"  GitLab.Corp.Example.  ", trustedHost{name: "gitlab.corp.example"}, true},
		{"gitlab.corp.example:8443", trustedHost{name: "gitlab.corp.example", port: "8443"}, true},
		{"gitlab.corp.example:08443", trustedHost{name: "gitlab.corp.example", port: "8443"}, true},
		{"*.corp.example", trustedHost{name: ".corp.example", suffix: true}, true},
		{"*.Corp.Example:443", trustedHost{name: ".corp.example", suffix: true, port: "443"}, true},
		{"10.0.0.5", trustedHost{name: "10.0.0.5"}, true},
		{"10.0.0.5:5000", trustedHost{name: "10.0.0.5", port: "5000"}, true},
		{"fd00::1", trustedHost{name: "fd00::1"}, true},
		{"FD00:0:0::1", trustedHost{name: "fd00::1"}, true},
		{"[fd00::1]", trustedHost{name: "fd00::1"}, true},
		{"[fd00::1]:8443", trustedHost{name: "fd00::1", port: "8443"}, true},
		{"", trustedHost{}, false},
		{"*", trustedHost{}, false},
		{"*.", trustedHost{}, false},
		{"**.corp.example", trustedHost{}, false},
		{"*.*.corp.example", trustedHost{}, false},
		{"*..corp.example", trustedHost{}, false},
		{"gitlab.*.example", trustedHost{}, false},
		{"corp*.example", trustedHost{}, false},
		{"https://gitlab.corp.example", trustedHost{}, false},
		{"gitlab.corp.example/jwt/auth", trustedHost{}, false},
		{"user@gitlab.corp.example", trustedHost{}, false},
		{"gitlab corp.example", trustedHost{}, false},
		{"gitlab.corp.example:0", trustedHost{}, false},
		{"gitlab.corp.example:65536", trustedHost{}, false},
		{"gitlab.corp.example:https", trustedHost{}, false},
		{"gitlab.corp.example:", trustedHost{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, ok := parseTrustedHost(tt.in)
			if ok != tt.wantOK || got != tt.want {
				t.Errorf("parseTrustedHost(%q) = %+v, %v, want %+v, %v", tt.in, got, ok, tt.want, tt.wantOK)
			}
		})
	}
}

func Test_newRealmTrust(t *testing.T) {
	if got := newRealmTrust(nil, false); got != nil {
		t.Errorf("newRealmTrust(nil, false) = %+v, want nil", got)
	}
	if got := newRealmTrust([]string{"*", "https://x"}, false); got != nil {
		t.Errorf("newRealmTrust() with only malformed entries = %+v, want nil", got)
	}
	got := newRealmTrust([]string{"*", "A.example"}, true)
	want := &realmTrust{hosts: []trustedHost{{name: "a.example"}}, allowInternal: true}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("newRealmTrust() = %+v, want %+v", got, want)
	}
}

func Test_realmTrust_level(t *testing.T) {
	trust := newRealmTrust([]string{
		"gitlab.corp.example",
		"*.corp.example",
		"pinned.example:8443",
		"*.pinned.example:443",
		"10.0.0.5",
		"[fd00::1]",
		"*.0.0.6",
	}, false)
	allowAll := newRealmTrust(nil, true)
	allowAllAndHost := newRealmTrust([]string{"gitlab.corp.example"}, true)

	tests := []struct {
		name  string
		trust *realmTrust
		realm string
		want  realmTrustLevel
	}{
		{"nil trust", nil, "https://gitlab.corp.example/jwt/auth", realmUntrusted},
		{"exact host", trust, "https://gitlab.corp.example/jwt/auth", realmTrustedExplicitly},
		{"exact host is case-insensitive", trust, "https://GITLAB.corp.Example/jwt/auth", realmTrustedExplicitly},
		{"exact host with trailing dot", trust, "https://gitlab.corp.example./jwt/auth", realmTrustedExplicitly},
		{"exact host without port matches any port", trust, "https://gitlab.corp.example:8443/jwt/auth", realmTrustedExplicitly},
		{"suffix pattern matches subdomain", trust, "https://auth.corp.example/token", realmTrustedBroadly},
		{"suffix pattern matches nested subdomain", trust, "https://a.b.corp.example/token", realmTrustedBroadly},
		{"suffix pattern does not match the domain itself", trust, "https://corp.example/token", realmUntrusted},
		{"suffix pattern does not match a sibling domain", trust, "https://evilcorp.example/token", realmUntrusted},
		{"suffix pattern does not match a lookalike suffix", trust, "https://auth.corp.example.evil.test/token", realmUntrusted},
		{"port-pinned host on its port", trust, "https://pinned.example:8443/token", realmTrustedExplicitly},
		{"port-pinned host on another port", trust, "https://pinned.example/token", realmUntrusted},
		{"port-pinned pattern on the default port", trust, "https://auth.pinned.example/token", realmTrustedBroadly},
		{"port-pinned pattern on another port", trust, "http://auth.pinned.example/token", realmUntrusted},
		{"IPv4 literal", trust, "http://10.0.0.5:5001/token", realmTrustedExplicitly},
		{"IPv6 literal", trust, "http://[fd00:0::1]:5001/token", realmTrustedExplicitly},
		{"suffix pattern never matches an IP literal", trust, "http://10.0.0.6/token", realmUntrusted},
		{"unrelated host", trust, "https://auth.example.com/token", realmUntrusted},
		{"allow-all", allowAll, "https://anything.example/token", realmTrustedBroadly},
		{"allow-all with exact host", allowAllAndHost, "https://gitlab.corp.example/token", realmTrustedExplicitly},
		{"allow-all with other host", allowAllAndHost, "https://other.example/token", realmTrustedBroadly},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, err := url.Parse(tt.realm)
			if err != nil {
				t.Fatalf("failed to parse %q: %v", tt.realm, err)
			}
			if got := tt.trust.level(u); got != tt.want {
				t.Errorf("level(%q) = %v, want %v", tt.realm, got, tt.want)
			}
		})
	}
}

func Test_isMetadataAddr(t *testing.T) {
	tests := []struct {
		addr string
		want bool
	}{
		{"169.254.169.254", true},
		{"169.254.0.1", true},
		{"::ffff:169.254.169.254", true},
		{"fe80::1", true},
		{"ff02::1", true},
		{"100.100.100.200", true},
		{"fd00:ec2::254", true},
		{"fd20:ce::254", true},
		{"10.0.0.1", false},
		{"127.0.0.1", false},
		{"100.64.0.1", false},
		{"fd00::1", false},
		{"93.184.215.14", false},
	}
	for _, tt := range tests {
		if got := isMetadataAddr(netip.MustParseAddr(tt.addr)); got != tt.want {
			t.Errorf("isMetadataAddr(%s) = %v, want %v", tt.addr, got, tt.want)
		}
	}
}

func Test_validateRealm_Trust(t *testing.T) {
	setLookupIPAddr(t, fakeLookupIPAddr(map[string][]string{
		"gitlab.corp.example":       {"192.168.110.193"},
		"auth.corp.example":         {"10.1.2.3"},
		"corp.example":              {"10.1.2.4"},
		"evilcorp.example":          {"10.1.2.5"},
		"imds.corp.example":         {"169.254.169.254"},
		"alibaba.corp.example":      {"100.100.100.200"},
		"aws6.corp.example":         {"fd00:ec2::254"},
		"loopback.corp.example":     {"127.0.0.1"},
		"cgnat.corp.example":        {"100.64.0.1"},
		"metadata.trusted.example":  {"169.254.169.254"},
		"untrusted.internal.test":   {"10.9.9.9"},
		"mixed.corp.example":        {"10.1.2.6", "169.254.169.254"},
		"public.corp.example":       {"93.184.215.14"},
		"private.anywhere.example":  {"172.16.0.1"},
		"linklocal.anywhere.test":   {"169.254.1.1"},
		"linklocal6.anywhere.test":  {"fe80::1"},
		"alibaba.anywhere.test":     {"100.100.100.200"},
		"loopback.anywhere.example": {"::1"},
	}))
	registryHTTPS, _ := url.Parse("https://registry.corp.example/v2/")
	registryHTTP, _ := url.Parse("http://registry.corp.example/v2/")

	hosts := newRealmTrust([]string{"gitlab.corp.example", "*.corp.example", "metadata.trusted.example", "100.100.100.200"}, false)
	allowAll := newRealmTrust(nil, true)
	allowAllAndHost := newRealmTrust([]string{"metadata.trusted.example"}, true)

	tests := []struct {
		name     string
		realm    string
		registry *url.URL
		trust    *realmTrust
		wantErr  string
	}{
		// Default behavior is unchanged.
		{"untrusted RFC 1918 host is rejected", "https://gitlab.corp.example/jwt/auth", registryHTTPS, nil, "resolves to 192.168.110.193"},
		{"untrusted error suggests trusting the host", "https://gitlab.corp.example/jwt/auth", registryHTTPS, nil, "trusted realm host"},

		// Explicit hosts.
		{"trusted host resolving to RFC 1918 is allowed", "https://gitlab.corp.example/jwt/auth", registryHTTPS, hosts, ""},
		{"trusted host matches case-insensitively", "https://GitLab.Corp.Example/jwt/auth", registryHTTPS, hosts, ""},
		{"explicitly trusted host resolving to link-local is allowed", "https://metadata.trusted.example/token", registryHTTPS, hosts, ""},
		{"explicitly trusted metadata IP literal is allowed", "http://100.100.100.200/token", registryHTTP, hosts, ""},
		{"untrusted host is rejected despite other trusted hosts", "https://untrusted.internal.test/token", registryHTTPS, hosts, "resolves to 10.9.9.9"},

		// Suffix patterns.
		{"pattern match resolving to RFC 1918 is allowed", "https://auth.corp.example/token", registryHTTPS, hosts, ""},
		{"pattern match resolving to loopback is allowed", "https://loopback.corp.example/token", registryHTTPS, hosts, ""},
		{"pattern match resolving to CGNAT is allowed", "https://cgnat.corp.example/token", registryHTTPS, hosts, ""},
		{"pattern match resolving to a public address is allowed", "https://public.corp.example/token", registryHTTPS, hosts, ""},
		{"pattern does not cover the domain itself", "https://corp.example/token", registryHTTPS, hosts, "resolves to 10.1.2.4"},
		{"pattern does not cover a sibling domain", "https://evilcorp.example/token", registryHTTPS, hosts, "resolves to 10.1.2.5"},
		{"pattern match resolving to IMDS is rejected", "https://imds.corp.example/token", registryHTTPS, hosts, "link-local or cloud metadata"},
		{"pattern match resolving to Alibaba metadata is rejected", "https://alibaba.corp.example/token", registryHTTPS, hosts, "link-local or cloud metadata"},
		{"pattern match resolving to AWS IPv6 metadata is rejected", "https://aws6.corp.example/token", registryHTTPS, hosts, "link-local or cloud metadata"},
		{"pattern match with any metadata address is rejected", "https://mixed.corp.example/token", registryHTTPS, hosts, "resolves to 169.254.169.254"},

		// Allow-all.
		{"allow-all permits RFC 1918", "https://private.anywhere.example/token", registryHTTPS, allowAll, ""},
		{"allow-all permits loopback", "https://loopback.anywhere.example/token", registryHTTPS, allowAll, ""},
		{"allow-all permits an RFC 1918 literal", "http://10.0.0.5/token", registryHTTP, allowAll, ""},
		{"allow-all rejects link-local", "https://linklocal.anywhere.test/token", registryHTTPS, allowAll, "link-local or cloud metadata"},
		{"allow-all rejects IPv6 link-local", "https://linklocal6.anywhere.test/token", registryHTTPS, allowAll, "link-local or cloud metadata"},
		{"allow-all rejects Alibaba metadata", "https://alibaba.anywhere.test/token", registryHTTPS, allowAll, "link-local or cloud metadata"},
		{"allow-all rejects an IMDS literal", "http://169.254.169.254/latest/meta-data/", registryHTTP, allowAll, "link-local or cloud metadata"},
		{"allow-all rejects an Alibaba metadata literal", "http://100.100.100.200/latest/meta-data/", registryHTTP, allowAll, "link-local or cloud metadata"},
		{"allow-all rejects an IPv6 link-local literal", "http://[fe80::1]/token", registryHTTP, allowAll, "link-local or cloud metadata"},
		{"allow-all with an explicit host allows its metadata address", "https://metadata.trusted.example/token", registryHTTPS, allowAllAndHost, ""},

		// Scheme and downgrade checks apply regardless of trust.
		{"downgrade is rejected for a trusted host", "http://gitlab.corp.example/jwt/auth", registryHTTPS, hosts, "uses http but registry was contacted over https"},
		{"downgrade is rejected for a pattern match", "http://auth.corp.example/token", registryHTTPS, hosts, "uses http but registry was contacted over https"},
		{"downgrade is rejected under allow-all", "http://private.anywhere.example/token", registryHTTPS, allowAll, "uses http but registry was contacted over https"},
		{"unsupported scheme is rejected for a trusted host", "ftp://gitlab.corp.example/token", registryHTTPS, hosts, "unsupported scheme"},
		{"unsupported scheme is rejected under allow-all", "file:///etc/passwd", registryHTTPS, allowAll, "unsupported scheme"},
		{"http realm for a plain-http registry is allowed when trusted", "http://gitlab.corp.example/jwt/auth", registryHTTP, hosts, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateRealm(context.Background(), tt.realm, tt.registry, tt.trust)
			if tt.wantErr == "" {
				if err != nil {
					t.Errorf("validateRealm(%q) error = %v, want nil", tt.realm, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("validateRealm(%q) error = %v, want error containing %q", tt.realm, err, tt.wantErr)
			}
		})
	}
}

// TestClient_Do_Bearer_TrustedRealmHosts verifies the realm trust of a Client
// end to end: a trusted realm on an internal address is used, an untrusted one
// is refused before any request reaches it, and every redirect hop of the token
// request is judged on its own host.
func TestClient_Do_Bearer_TrustedRealmHosts(t *testing.T) {
	const wantToken = "test/access/token"

	tests := []struct {
		name          string
		trustedHosts  []string
		allowInternal bool
		// realmRedirect, if set, is where the realm redirects the token
		// request.
		realmRedirect string
		wantErr       string
		// wantRealmHits and wantInternalHits are the expected number of
		// requests to the realm and to the untrusted internal server.
		wantRealmHits    int64
		wantInternalHits int64
	}{
		{
			name:    "untrusted internal realm is rejected",
			wantErr: "resolves to 192.168.110.193",
		},
		{
			name:          "trusted internal realm is used",
			trustedHosts:  []string{"gitlab.corp.example"},
			wantRealmHits: 1,
		},
		{
			name:          "realm matching a trusted pattern is used",
			trustedHosts:  []string{"*.corp.example"},
			wantRealmHits: 1,
		},
		{
			name:          "realm is used under allow-all",
			allowInternal: true,
			wantRealmHits: 1,
		},
		{
			name:         "trust for another host does not apply",
			trustedHosts: []string{"gitlab.other.example", "*.other.example"},
			wantErr:      "resolves to 192.168.110.193",
		},
		{
			name:          "redirect from a trusted realm to an untrusted internal host is rejected",
			trustedHosts:  []string{"gitlab.corp.example"},
			realmRedirect: "http://internal.test/token",
			wantErr:       "redirect of token request rejected",
			wantRealmHits: 1,
		},
		{
			name:          "redirect from a pattern-trusted realm to a metadata host is rejected",
			trustedHosts:  []string{"*.corp.example"},
			realmRedirect: "http://imds.corp.example/latest/meta-data/",
			wantErr:       "redirect of token request rejected",
			wantRealmHits: 1,
		},
		{
			name:          "redirect under allow-all to a metadata host is rejected",
			allowInternal: true,
			realmRedirect: "http://imds.corp.example/latest/meta-data/",
			wantErr:       "redirect of token request rejected",
			wantRealmHits: 1,
		},
		{
			name:             "redirect from a trusted realm to another trusted internal host is allowed",
			trustedHosts:     []string{"gitlab.corp.example", "internal.test"},
			realmRedirect:    "http://internal.test/token",
			wantRealmHits:    1,
			wantInternalHits: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			writeToken := func(w http.ResponseWriter) {
				if _, err := fmt.Fprintf(w, `{"token":%q}`, wantToken); err != nil {
					t.Errorf("failed to write token response: %v", err)
				}
			}
			var internalHits atomic.Int64
			internal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				internalHits.Add(1)
				writeToken(w)
			}))
			defer internal.Close()

			var realmHits atomic.Int64
			realm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				realmHits.Add(1)
				if tt.realmRedirect != "" {
					http.Redirect(w, r, tt.realmRedirect, http.StatusFound)
					return
				}
				writeToken(w)
			}))
			defer realm.Close()

			registry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") == "Bearer "+wantToken {
					return
				}
				challenge := fmt.Sprintf("Bearer realm=%q,service=%q,scope=%q", "http://gitlab.corp.example/jwt/auth", "container_registry", "repository:test:pull")
				w.Header().Set("Www-Authenticate", challenge)
				w.WriteHeader(http.StatusUnauthorized)
			}))
			defer registry.Close()

			setLookupIPAddr(t, fakeLookupIPAddr(map[string][]string{
				"registry.corp.example": {"192.168.110.10"},
				"gitlab.corp.example":   {"192.168.110.193"},
				"internal.test":         {"10.9.9.9"},
				"imds.corp.example":     {"169.254.169.254"},
			}))
			client := &Client{
				Client: &http.Client{
					Transport: &http.Transport{DialContext: hostDialer(t, map[string]string{
						"registry.corp.example": registry.Listener.Addr().String(),
						"gitlab.corp.example":   realm.Listener.Addr().String(),
						"internal.test":         internal.Listener.Addr().String(),
						"imds.corp.example":     internal.Listener.Addr().String(),
					})},
				},
				TrustedRealmHosts:   tt.trustedHosts,
				AllowInternalRealms: tt.allowInternal,
			}

			req, err := http.NewRequest(http.MethodGet, "http://registry.corp.example/v2/test/manifests/latest", nil)
			if err != nil {
				t.Fatalf("failed to create test request: %v", err)
			}
			resp, err := client.Do(req)
			if tt.wantErr != "" {
				if err == nil {
					resp.Body.Close()
					t.Fatal("Client.Do() error = nil, want error")
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("Client.Do() error = %v, want error containing %q", err, tt.wantErr)
				}
			} else {
				if err != nil {
					t.Fatalf("Client.Do() error = %v", err)
				}
				resp.Body.Close()
				if resp.StatusCode != http.StatusOK {
					t.Errorf("Client.Do() = %v, want %v", resp.StatusCode, http.StatusOK)
				}
			}
			if got := realmHits.Load(); got != tt.wantRealmHits {
				t.Errorf("realm received %d requests, want %d", got, tt.wantRealmHits)
			}
			if got := internalHits.Load(); got != tt.wantInternalHits {
				t.Errorf("internal server received %d requests, want %d", got, tt.wantInternalHits)
			}
		})
	}
}

func TestClient_Clone_RealmTrust(t *testing.T) {
	c := &Client{
		TrustedRealmHosts:   []string{"gitlab.corp.example"},
		AllowInternalRealms: true,
	}
	clone := c.Clone()
	if !reflect.DeepEqual(clone.TrustedRealmHosts, c.TrustedRealmHosts) {
		t.Errorf("Clone().TrustedRealmHosts = %v, want %v", clone.TrustedRealmHosts, c.TrustedRealmHosts)
	}
	if !clone.AllowInternalRealms {
		t.Error("Clone().AllowInternalRealms = false, want true")
	}
	clone.TrustedRealmHosts[0] = "changed.example"
	if c.TrustedRealmHosts[0] != "gitlab.corp.example" {
		t.Error("mutating the clone's TrustedRealmHosts changed the original")
	}
}
