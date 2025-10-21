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

package configuration

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestNewAuthJson(t *testing.T) {
	tempDir := t.TempDir()
	path := filepath.Join(tempDir, "auth.json")

	aj, err := NewAuthJson(path)
	if err != nil {
		t.Fatalf("NewAuthJson() error = %v", err)
	}

	if aj.Path() != path {
		t.Errorf("Path() = %v, want %v", aj.Path(), path)
	}

	if aj.IsAuthConfigured() {
		t.Error("IsAuthConfigured() should be false for new auth.json")
	}
}

func TestAuthJson_EncodeDecodeAuth(t *testing.T) {
	tests := []struct {
		name     string
		username string
		password string
	}{
		{
			name:     "basic credentials",
			username: "testuser",
			password: "testpass",
		},
		{
			name:     "username with special chars",
			username: "user@example.com",
			password: "p@ssw0rd!",
		},
		{
			name:     "empty password",
			username: "testuser",
			password: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded := encodeAuth(tt.username, tt.password)
			if encoded == "" && (tt.username != "" || tt.password != "") {
				t.Error("encodeAuth() returned empty string for non-empty credentials")
			}

			username, password, err := decodeAuth(encoded)
			if err != nil {
				t.Errorf("decodeAuth() error = %v", err)
			}

			if username != tt.username {
				t.Errorf("decodeAuth() username = %v, want %v", username, tt.username)
			}

			if password != tt.password {
				t.Errorf("decodeAuth() password = %v, want %v", password, tt.password)
			}
		})
	}
}

func TestAuthJson_PutGetDeleteCredential(t *testing.T) {
	tempDir := t.TempDir()
	path := filepath.Join(tempDir, "auth.json")

	aj, err := NewAuthJson(path)
	if err != nil {
		t.Fatalf("NewAuthJson() error = %v", err)
	}

	serverAddress := "registry.example.com"
	cred := Credential{
		Username: "testuser",
		Password: "testpass",
	}

	// Test initial state - no credentials
	gotCred, err := aj.GetCredential(serverAddress)
	if err != nil {
		t.Errorf("GetCredential() error = %v", err)
	}
	if gotCred != EmptyCredential {
		t.Errorf("GetCredential() = %v, want %v", gotCred, EmptyCredential)
	}

	// Test putting credential
	if err := aj.PutCredential(serverAddress, cred); err != nil {
		t.Errorf("PutCredential() error = %v", err)
	}

	// Test getting credential
	gotCred, err = aj.GetCredential(serverAddress)
	if err != nil {
		t.Errorf("GetCredential() error = %v", err)
	}
	if gotCred != cred {
		t.Errorf("GetCredential() = %v, want %v", gotCred, cred)
	}

	// Verify file was written
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Error("auth.json file was not created")
	}

	// Test deleting credential
	if err := aj.DeleteCredential(serverAddress); err != nil {
		t.Errorf("DeleteCredential() error = %v", err)
	}

	// Test getting credential after deletion
	gotCred, err = aj.GetCredential(serverAddress)
	if err != nil {
		t.Errorf("GetCredential() error = %v", err)
	}
	if gotCred != EmptyCredential {
		t.Errorf("GetCredential() after delete = %v, want %v", gotCred, EmptyCredential)
	}
}

func TestAuthJson_LoadFromFile(t *testing.T) {
	tempDir := t.TempDir()
	path := filepath.Join(tempDir, "auth.json")

	// Create a test auth.json file with base64-encoded auth
	testAuth := base64.StdEncoding.EncodeToString([]byte("testuser:testpass"))
	authData := authFile{
		Auths: map[string]authEntry{
			"registry.example.com": {
				Auth: testAuth,
			},
		},
	}

	data, err := json.MarshalIndent(authData, "", "\t")
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	// Load the auth.json file
	aj, err := NewAuthJson(path)
	if err != nil {
		t.Fatalf("NewAuthJson() error = %v", err)
	}

	// Test getting credential from loaded file
	cred, err := aj.GetCredential("registry.example.com")
	if err != nil {
		t.Errorf("GetCredential() error = %v", err)
	}

	expectedCred := Credential{
		Username: "testuser",
		Password: "testpass",
	}

	if cred != expectedCred {
		t.Errorf("GetCredential() = %v, want %v", cred, expectedCred)
	}
}

func TestAuthJson_HierarchicalNamespaceMatching(t *testing.T) {
	tempDir := t.TempDir()
	path := filepath.Join(tempDir, "auth.json")

	aj, err := NewAuthJson(path)
	if err != nil {
		t.Fatalf("NewAuthJson() error = %v", err)
	}

	// Set up hierarchical credentials
	dockerDefault := Credential{
		Username: "default_user",
		Password: "default_pass",
	}
	orgNs := Credential{
		Username: "org_user",
		Password: "org_pass",
	}
	teamNs := Credential{
		Username: "team_user",
		Password: "team_pass",
	}

	// Store credentials at different namespace levels
	if err := aj.PutCredential("docker.io", dockerDefault); err != nil {
		t.Fatalf("PutCredential() error = %v", err)
	}
	if err := aj.PutCredential("docker.io/myorg", orgNs); err != nil {
		t.Fatalf("PutCredential() error = %v", err)
	}
	if err := aj.PutCredential("docker.io/myorg/team", teamNs); err != nil {
		t.Fatalf("PutCredential() error = %v", err)
	}

	tests := []struct {
		name          string
		serverAddress string
		want          Credential
		wantErr       bool
	}{
		{
			name:          "Exact match at registry level",
			serverAddress: "docker.io",
			want:          dockerDefault,
		},
		{
			name:          "Exact match at org level",
			serverAddress: "docker.io/myorg",
			want:          orgNs,
		},
		{
			name:          "Exact match at team level",
			serverAddress: "docker.io/myorg/team",
			want:          teamNs,
		},
		{
			name:          "Fall back from repo to team",
			serverAddress: "docker.io/myorg/team/repo",
			want:          teamNs,
		},
		{
			name:          "Fall back from repo to org",
			serverAddress: "docker.io/myorg/other/repo",
			want:          orgNs,
		},
		{
			name:          "Fall back to registry default",
			serverAddress: "docker.io/other/repo",
			want:          dockerDefault,
		},
		{
			name:          "No match returns empty credential",
			serverAddress: "unknown.registry.com/foo/bar",
			want:          EmptyCredential,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := aj.GetCredential(tt.serverAddress)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetCredential() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("GetCredential() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAuthJson_StripServerAddress(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"registry.example.com", "registry.example.com"},
		{"https://registry.example.com", "registry.example.com"},
		{"http://registry.example.com", "registry.example.com"},
		{"registry.example.com/", "registry.example.com"},
		{"https://registry.example.com/", "registry.example.com"},
		{"registry.example.com:5000", "registry.example.com:5000"},
		{"https://registry.example.com:5000/", "registry.example.com:5000"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := stripServerAddress(tt.input)
			if got != tt.want {
				t.Errorf("stripServerAddress() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAuthJson_BothAuthFormats(t *testing.T) {
	tempDir := t.TempDir()
	path := filepath.Join(tempDir, "auth.json")

	// Create auth.json with both formats
	testAuth := base64.StdEncoding.EncodeToString([]byte("encoded_user:encoded_pass"))
	authData := authFile{
		Auths: map[string]authEntry{
			"registry1.example.com": {
				Auth: testAuth,
			},
			"registry2.example.com": {
				Username: "plain_user",
				Password: "plain_pass",
			},
			"registry3.example.com": {
				Auth:     testAuth,
				Username: "plain_user",
				Password: "plain_pass",
			},
		},
	}

	data, err := json.MarshalIndent(authData, "", "\t")
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	aj, err := NewAuthJson(path)
	if err != nil {
		t.Fatalf("NewAuthJson() error = %v", err)
	}

	// Test auth field only
	cred1, err := aj.GetCredential("registry1.example.com")
	if err != nil {
		t.Errorf("GetCredential(registry1) error = %v", err)
	}
	if cred1.Username != "encoded_user" || cred1.Password != "encoded_pass" {
		t.Errorf("GetCredential(registry1) = %v, want encoded_user:encoded_pass", cred1)
	}

	// Test username/password fields only
	cred2, err := aj.GetCredential("registry2.example.com")
	if err != nil {
		t.Errorf("GetCredential(registry2) error = %v", err)
	}
	if cred2.Username != "plain_user" || cred2.Password != "plain_pass" {
		t.Errorf("GetCredential(registry2) = %v, want plain_user:plain_pass", cred2)
	}

	// Test both fields (username/password takes precedence)
	cred3, err := aj.GetCredential("registry3.example.com")
	if err != nil {
		t.Errorf("GetCredential(registry3) error = %v", err)
	}
	if cred3.Username != "plain_user" || cred3.Password != "plain_pass" {
		t.Errorf("GetCredential(registry3) = %v, want plain_user:plain_pass (username/password should take precedence)", cred3)
	}
}

func TestAuthJson_ConfigInterface(t *testing.T) {
	tempDir := t.TempDir()
	path := filepath.Join(tempDir, "auth.json")

	aj, err := NewAuthJson(path)
	if err != nil {
		t.Fatalf("NewAuthJson() error = %v", err)
	}

	// Test GetCredentialHelper (not supported)
	helper := aj.GetCredentialHelper("registry.example.com")
	if helper != "" {
		t.Errorf("GetCredentialHelper() = %v, want empty string", helper)
	}

	// Test CredentialsStore (not supported)
	store := aj.CredentialsStore()
	if store != "" {
		t.Errorf("CredentialsStore() = %v, want empty string", store)
	}

	// Test SetCredentialsStore (should be no-op)
	if err := aj.SetCredentialsStore("test"); err != nil {
		t.Errorf("SetCredentialsStore() error = %v", err)
	}

	// Verify it's still empty
	store = aj.CredentialsStore()
	if store != "" {
		t.Errorf("CredentialsStore() after Set = %v, want empty string", store)
	}
}

func TestGetAuthPaths(t *testing.T) {
	tests := []struct {
		name          string
		serverAddress string
		want          []string
	}{
		{
			name:          "registry only",
			serverAddress: "docker.io",
			want:          []string{"docker.io"},
		},
		{
			name:          "registry with org",
			serverAddress: "docker.io/library",
			want:          []string{"docker.io/library", "docker.io"},
		},
		{
			name:          "full image path",
			serverAddress: "docker.io/library/nginx",
			want:          []string{"docker.io/library/nginx", "docker.io/library", "docker.io"},
		},
		{
			name:          "deep namespace",
			serverAddress: "registry.example.com/org/team/repo/image",
			want: []string{
				"registry.example.com/org/team/repo/image",
				"registry.example.com/org/team/repo",
				"registry.example.com/org/team",
				"registry.example.com/org",
				"registry.example.com",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getAuthPaths(tt.serverAddress)
			if len(got) != len(tt.want) {
				t.Errorf("getAuthPaths() length = %v, want %v", len(got), len(tt.want))
				return
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("getAuthPaths()[%d] = %v, want %v", i, got[i], tt.want[i])
				}
			}
		})
	}
}
