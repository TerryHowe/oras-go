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

package remote

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/oras-project/oras-go/v3/registry/remote/auth"
	"github.com/oras-project/oras-go/v3/registry/remote/properties"
)

func TestClientBuilder_Build_RealmTrust(t *testing.T) {
	hosts := []string{"gitlab.corp.example", "*.corp.example"}
	props := &properties.Registry{
		Reference: properties.Reference{Registry: "registry.corp.example"},
		Attributes: properties.Attributes{
			TrustedRealmHosts:   hosts,
			AllowInternalRealms: true,
		},
	}
	client, err := NewClientBuilder().Build(props)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if !reflect.DeepEqual(client.TrustedRealmHosts, hosts) {
		t.Errorf("Build().TrustedRealmHosts = %v, want %v", client.TrustedRealmHosts, hosts)
	}
	if !client.AllowInternalRealms {
		t.Error("Build().AllowInternalRealms = false, want true")
	}
	// The client holds its own copy, so later edits to the properties do not
	// change the trust of a client already built.
	hosts[0] = "changed.example"
	if client.TrustedRealmHosts[0] != "gitlab.corp.example" {
		t.Error("mutating the properties changed the built client's TrustedRealmHosts")
	}

	plain, err := NewClientBuilder().Build(&properties.Registry{
		Reference: properties.Reference{Registry: "registry.corp.example"},
	})
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if plain.TrustedRealmHosts != nil || plain.AllowInternalRealms {
		t.Errorf("Build() without realm trust = %v, %v, want nil, false", plain.TrustedRealmHosts, plain.AllowInternalRealms)
	}
}

func TestClientBuilder_NewRepository_MirrorsDoNotInheritRealmTrust(t *testing.T) {
	props := &properties.Registry{
		Reference: properties.Reference{
			Registry:   "registry.corp.example",
			Repository: "test/repo",
		},
		Attributes: properties.Attributes{
			TokenFlow:           properties.TokenFlowDistribution,
			TrustedRealmHosts:   []string{"gitlab.corp.example"},
			AllowInternalRealms: true,
		},
		Mirrors: []properties.Mirror{{Location: "mirror.example.com"}},
	}
	repo, err := NewClientBuilder().NewRepository(props)
	if err != nil {
		t.Fatalf("NewRepository() error = %v", err)
	}
	primary, ok := repo.Registry.Client.(*auth.Client)
	if !ok {
		t.Fatalf("primary client is %T, want *auth.Client", repo.Registry.Client)
	}
	if len(primary.TrustedRealmHosts) != 1 || !primary.AllowInternalRealms {
		t.Errorf("primary realm trust = %v, %v, want the configured trust", primary.TrustedRealmHosts, primary.AllowInternalRealms)
	}
	if len(repo.mirrors) != 1 {
		t.Fatalf("got %d mirrors, want 1", len(repo.mirrors))
	}
	mirror, ok := repo.mirrors[0].Repository.Registry.Client.(*auth.Client)
	if !ok {
		t.Fatalf("mirror client is %T, want *auth.Client", repo.mirrors[0].Repository.Registry.Client)
	}
	if mirror.TrustedRealmHosts != nil || mirror.AllowInternalRealms {
		t.Errorf("mirror realm trust = %v, %v, want nil, false", mirror.TrustedRealmHosts, mirror.AllowInternalRealms)
	}
	// Other attributes are still shared with mirrors.
	if mirror.TokenFetcher == nil {
		t.Error("mirror did not inherit the token flow")
	}
	if props.Attributes.TrustedRealmHosts == nil || !props.Attributes.AllowInternalRealms {
		t.Error("building mirrors cleared the realm trust of the caller's properties")
	}
}

// TestClientBuilder_RealmTrust_ScopedPerRegistry verifies that realm trust
// configured for one registry does not apply to challenges from another
// registry built by the same ClientBuilder.
func TestClientBuilder_RealmTrust_ScopedPerRegistry(t *testing.T) {
	const (
		wantToken = "test/access/token"
		// realmHost is an RFC 1918 literal, so the test needs no resolver.
		realmHost = "10.0.0.5"
	)
	var realmHits atomic.Int64
	realm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		realmHits.Add(1)
		if _, err := fmt.Fprintf(w, `{"token":%q}`, wantToken); err != nil {
			t.Errorf("failed to write token response: %v", err)
		}
	}))
	defer realm.Close()

	registry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "Bearer "+wantToken {
			return
		}
		challenge := fmt.Sprintf("Bearer realm=%q,service=%q", "http://"+realmHost+"/token", r.Host)
		w.Header().Set("Www-Authenticate", challenge)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer registry.Close()

	dialTargets := map[string]string{
		"registry-a.test": registry.Listener.Addr().String(),
		"registry-b.test": registry.Listener.Addr().String(),
		realmHost:         realm.Listener.Addr().String(),
	}
	builder := NewClientBuilder()
	builder.BaseTransport = &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			target, ok := dialTargets[host]
			if !ok {
				return nil, fmt.Errorf("unexpected dial to %q", addr)
			}
			var d net.Dialer
			return d.DialContext(ctx, network, target)
		},
	}

	clientA, err := builder.Build(&properties.Registry{
		Reference:  properties.Reference{Registry: "registry-a.test"},
		Attributes: properties.Attributes{TrustedRealmHosts: []string{realmHost}},
	})
	if err != nil {
		t.Fatalf("Build(A) error = %v", err)
	}
	clientB, err := builder.Build(&properties.Registry{
		Reference: properties.Reference{Registry: "registry-b.test"},
	})
	if err != nil {
		t.Fatalf("Build(B) error = %v", err)
	}

	do := func(client *auth.Client, registry string) (*http.Response, error) {
		req, err := http.NewRequest(http.MethodGet, "http://"+registry+"/v2/test/manifests/latest", nil)
		if err != nil {
			t.Fatalf("failed to create test request: %v", err)
		}
		return client.Do(req)
	}

	resp, err := do(clientA, "registry-a.test")
	if err != nil {
		t.Fatalf("registry A: Client.Do() error = %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("registry A: Client.Do() = %v, want %v", resp.StatusCode, http.StatusOK)
	}
	if got := realmHits.Load(); got != 1 {
		t.Fatalf("realm received %d requests for registry A, want 1", got)
	}

	resp, err = do(clientB, "registry-b.test")
	if err == nil {
		resp.Body.Close()
		t.Fatal("registry B: Client.Do() error = nil, want the realm to be rejected")
	}
	if !strings.Contains(err.Error(), "private") {
		t.Errorf("registry B: Client.Do() error = %v, want an internal address rejection", err)
	}
	if got := realmHits.Load(); got != 1 {
		t.Errorf("realm received %d requests in total, want 1 (none for registry B)", got)
	}
}
