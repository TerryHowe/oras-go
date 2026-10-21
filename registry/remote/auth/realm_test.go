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
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/oras-project/oras-go/v3/registry/remote/credentials"
	"github.com/oras-project/oras-go/v3/registry/remote/properties"
)

func TestDefaultBlockedRealmPrefixes_returnsFreshCopy(t *testing.T) {
	a := DefaultBlockedRealmPrefixes()
	a[0] = netip.MustParsePrefix("203.0.113.0/24")
	if b := DefaultBlockedRealmPrefixes(); b[0] == a[0] {
		t.Error("mutating the returned slice changed the defaults")
	}
	p := PrivateRealmPrefixes()
	p[0] = netip.MustParsePrefix("203.0.113.0/24")
	if q := PrivateRealmPrefixes(); q[0] == p[0] {
		t.Error("mutating the returned slice changed the private prefixes")
	}
}

func Test_validateRealm_blockedPrefixes(t *testing.T) {
	setLookupIPAddr(t, fakeLookupIPAddr(map[string][]string{
		"gitlab.corp.example": {"192.168.110.193"},
		"ula.example":         {"fd12:3456:789a::1"},
		"cgnat.example":       {"100.64.0.1"},
		"metadata.example":    {"169.254.169.254"},
		"zero.example":        {"0.0.0.0"},
		"nat64.example":       {"64:ff9b::a9fe:a9fe"},
		"loopback.example":    {"127.0.0.1"},
	}))
	registryHTTPS, _ := url.Parse("https://registry.corp.example/v2/")
	registryLocal, _ := url.Parse("http://localhost:5000/v2/")

	strict := append(DefaultBlockedRealmPrefixes(), PrivateRealmPrefixes()...)
	onlyLinkLocal := []netip.Prefix{netip.MustParsePrefix("169.254.0.0/16")}
	noLoopback := slices.DeleteFunc(DefaultBlockedRealmPrefixes(), func(p netip.Prefix) bool {
		return p.Addr().IsLoopback()
	})

	tests := []struct {
		name     string
		realm    string
		registry *url.URL
		blocked  []netip.Prefix
		wantErr  string // substring; empty means allowed
	}{
		// Default list.
		{"default: RFC 1918 literal allowed", "https://192.168.110.193/token", registryHTTPS, DefaultBlockedRealmPrefixes(), ""},
		{"default: RFC 1918 hostname allowed (#1631)", "https://gitlab.corp.example/jwt/auth", registryHTTPS, DefaultBlockedRealmPrefixes(), ""},
		{"default: ULA literal allowed", "https://[fd12:3456:789a::1]/token", registryHTTPS, DefaultBlockedRealmPrefixes(), ""},
		{"default: ULA hostname allowed", "https://ula.example/token", registryHTTPS, DefaultBlockedRealmPrefixes(), ""},
		{"default: CGNAT hostname allowed", "https://cgnat.example/token", registryHTTPS, DefaultBlockedRealmPrefixes(), ""},
		{"default: loopback hostname rejected", "https://loopback.example/token", registryHTTPS, DefaultBlockedRealmPrefixes(), "127.0.0.0/8"},
		{"default: link-local hostname rejected", "https://metadata.example/token", registryHTTPS, DefaultBlockedRealmPrefixes(), "169.254.0.0/16"},
		{"default: 0.0.0.0 hostname rejected", "https://zero.example/token", registryHTTPS, DefaultBlockedRealmPrefixes(), "0.0.0.0/8"},
		{"default: IPv6 link-local rejected", "https://[fe80::1]/token", registryHTTPS, DefaultBlockedRealmPrefixes(), "fe80::/10"},
		{"default: IPv6 link-local with zone rejected", "https://[fe80::1%25eth0]/token", registryHTTPS, DefaultBlockedRealmPrefixes(), "fe80::/10"},
		{"default: IPv6 link-local multicast rejected", "https://[ff02::1]/token", registryHTTPS, DefaultBlockedRealmPrefixes(), "ff02::/16"},
		{"default: Alibaba metadata rejected", "https://100.100.100.200/token", registryHTTPS, DefaultBlockedRealmPrefixes(), "100.100.100.200/32"},
		{"default: AWS IPv6 metadata rejected", "https://[fd00:ec2::254]/token", registryHTTPS, DefaultBlockedRealmPrefixes(), "fd00:ec2::254/128"},
		{"default: GCP IPv6 metadata rejected", "https://[fd20:ce::254]/token", registryHTTPS, DefaultBlockedRealmPrefixes(), "fd20:ce::254/128"},
		{"default: Azure WireServer rejected", "https://168.63.129.16/token", registryHTTPS, DefaultBlockedRealmPrefixes(), "168.63.129.16/32"},
		{"default: neighbour of Azure WireServer allowed", "https://168.63.129.17/token", registryHTTPS, DefaultBlockedRealmPrefixes(), ""},

		// Embedded IPv4.
		{"NAT64 literal of IMDS rejected", "https://[64:ff9b::a9fe:a9fe]/token", registryHTTPS, DefaultBlockedRealmPrefixes(), "169.254.0.0/16"},
		{"NAT64 hostname of IMDS rejected", "https://nat64.example/token", registryHTTPS, DefaultBlockedRealmPrefixes(), "169.254.0.0/16"},
		{"NAT64 of IMDS rejected with a custom list", "https://[64:ff9b::a9fe:a9fe]/token", registryHTTPS, onlyLinkLocal, "169.254.0.0/16"},
		{"6to4 of IMDS rejected", "https://[2002:a9fe:a9fe::1]/token", registryHTTPS, DefaultBlockedRealmPrefixes(), "169.254.0.0/16"},
		{"IPv4-mapped IMDS rejected with a custom list", "https://[::ffff:169.254.169.254]/token", registryHTTPS, onlyLinkLocal, "169.254.0.0/16"},
		{"NAT64 of a public address allowed", "https://[64:ff9b::5db8:d70e]/token", registryHTTPS, DefaultBlockedRealmPrefixes(), ""},
		{"NAT64 of RFC 1918 allowed by default", "https://[64:ff9b::c0a8:6ec1]/token", registryHTTPS, DefaultBlockedRealmPrefixes(), ""},
		{"NAT64 of RFC 1918 rejected in strict mode", "https://[64:ff9b::c0a8:6ec1]/token", registryHTTPS, strict, "192.168.0.0/16"},

		// Strict mode.
		{"strict: RFC 1918 literal rejected", "https://192.168.110.193/token", registryHTTPS, strict, "192.168.0.0/16"},
		{"strict: RFC 1918 hostname rejected", "https://gitlab.corp.example/jwt/auth", registryHTTPS, strict, "192.168.0.0/16"},
		{"strict: ULA hostname rejected", "https://ula.example/token", registryHTTPS, strict, "fc00::/7"},
		{"strict: CGNAT hostname rejected", "https://cgnat.example/token", registryHTTPS, strict, "100.64.0.0/10"},
		{"strict: loopback still rejected", "https://127.0.0.1/token", registryHTTPS, strict, "127.0.0.0/8"},

		// Empty and custom lists.
		{"empty list: loopback allowed", "https://127.0.0.1/token", registryHTTPS, []netip.Prefix{}, ""},
		{"empty list: metadata allowed", "https://metadata.example/token", registryHTTPS, []netip.Prefix{}, ""},
		{"empty list: scheme still rejected", "ftp://example.com/token", registryHTTPS, []netip.Prefix{}, "unsupported scheme"},
		{"empty list: downgrade still rejected", "http://auth.example/token", registryHTTPS, []netip.Prefix{}, "uses http"},
		{"custom list is exact: unlisted metadata allowed", "https://100.100.100.200/token", registryHTTPS, onlyLinkLocal, ""},
		{"custom list without loopback: dev realm allowed", "http://127.0.0.1:5001/token", registryLocal, noLoopback, ""},
		{"downgrade still rejected with custom list", "http://auth.example/token", registryHTTPS, noLoopback, "uses http"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateRealm(context.Background(), tt.realm, tt.registry, tt.blocked)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("validateRealm() error = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("validateRealm() error = %v, want error containing %q", err, tt.wantErr)
			}
		})
	}
}

func Test_effectiveBlockedRealmPrefixes(t *testing.T) {
	if got := effectiveBlockedRealmPrefixes(nil); !slices.Equal(got, DefaultBlockedRealmPrefixes()) {
		t.Errorf("nil list resolved to %v, want the defaults", got)
	}
	if got := effectiveBlockedRealmPrefixes([]netip.Prefix{}); got == nil || len(got) != 0 {
		t.Errorf("empty list resolved to %v, want it kept empty and non-nil", got)
	}
	custom := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	if got := effectiveBlockedRealmPrefixes(custom); !slices.Equal(got, custom) {
		t.Errorf("custom list resolved to %v, want %v", got, custom)
	}
}

func TestClient_Clone_BlockedRealmPrefixes(t *testing.T) {
	t.Run("copy does not share the slice", func(t *testing.T) {
		original := &Client{BlockedRealmPrefixes: PrivateRealmPrefixes()}
		want := PrivateRealmPrefixes()
		clone := original.Clone()
		clone.BlockedRealmPrefixes[0] = netip.MustParsePrefix("203.0.113.0/24")
		if !slices.Equal(original.BlockedRealmPrefixes, want) {
			t.Errorf("mutating the clone changed the original: %v", original.BlockedRealmPrefixes)
		}
	})
	t.Run("nil stays nil", func(t *testing.T) {
		if got := (&Client{}).Clone().BlockedRealmPrefixes; got != nil {
			t.Errorf("Clone() = %v, want nil so the defaults still apply", got)
		}
	})
	t.Run("empty stays non-nil", func(t *testing.T) {
		got := (&Client{BlockedRealmPrefixes: []netip.Prefix{}}).Clone().BlockedRealmPrefixes
		if got == nil {
			t.Error("Clone() = nil, want an empty non-nil list so nothing is blocked")
		}
	})
}

// TestClient_Do_Bearer_RealmBlockedPrefixes verifies that the configured list
// applies both to the realm in the challenge and to every redirect hop of the
// token request.
func TestClient_Do_Bearer_RealmBlockedPrefixes(t *testing.T) {
	const wantToken = "test/access/token"
	strict := append(DefaultBlockedRealmPrefixes(), PrivateRealmPrefixes()...)

	tests := []struct {
		name string
		// redirect makes the realm redirect to the private target instead of
		// answering itself.
		redirect bool
		blocked  []netip.Prefix
		wantErr  string
	}{
		{name: "private realm allowed by default"},
		{name: "private realm rejected in strict mode", blocked: strict, wantErr: "blocked prefix 192.168.0.0/16"},
		{name: "redirect to private target allowed by default", redirect: true},
		{name: "redirect to private target rejected in strict mode", redirect: true, blocked: strict, wantErr: "redirect of token request rejected"},
		{name: "empty list allows the realm", blocked: []netip.Prefix{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var privateHits atomic.Int64
			private := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				privateHits.Add(1)
				fmt.Fprintf(w, `{"access_token":%q}`, wantToken)
			}))
			defer private.Close()
			realm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, "http://private.test/token", http.StatusFound)
			}))
			defer realm.Close()
			registry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") == "Bearer "+wantToken {
					return
				}
				realmHost := "private.test"
				if tt.redirect {
					realmHost = "auth.test"
				}
				w.Header().Set("Www-Authenticate", fmt.Sprintf("Bearer realm=%q,service=%q,scope=%q",
					"http://"+realmHost+"/token", "registry.test", "repository:test:pull"))
				w.WriteHeader(http.StatusUnauthorized)
			}))
			defer registry.Close()

			setLookupIPAddr(t, fakeLookupIPAddr(map[string][]string{
				"auth.test":    {"93.184.215.14"},
				"private.test": {"192.168.110.193"},
			}))
			hosts := map[string]string{
				"registry.test": registry.Listener.Addr().String(),
				"auth.test":     realm.Listener.Addr().String(),
				"private.test":  private.Listener.Addr().String(),
			}
			client := &Client{
				Client: &http.Client{Transport: &http.Transport{DialContext: hostDialer(t, hosts)}},
				CredentialFunc: func(context.Context, properties.Resource) (credentials.Credential, error) {
					return credentials.Credential{Username: "test_user", Password: "test_password"}, nil
				},
				BlockedRealmPrefixes: tt.blocked,
			}
			client.TokenFetcher = NewCompositeTokenFetcher(client.Client, client.Header, client.ClientID, true)

			req, err := http.NewRequest(http.MethodGet, "http://registry.test/v2/test/manifests/latest", nil)
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
				if got := privateHits.Load(); got != 0 {
					t.Errorf("private server received %d requests, want 0", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("Client.Do() error = %v", err)
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Errorf("Client.Do() = %v, want %v", resp.StatusCode, http.StatusOK)
			}
		})
	}
}
