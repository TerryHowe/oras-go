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
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Credential represents a username and password pair for authentication.
// This is defined here to avoid circular dependencies with the credentials package.
//
// Reference: https://github.com/containers/image/blob/main/docs/containers-auth.json.5.md
type Credential struct {
	Username string
	Password string
}

// EmptyCredential is an empty credential.
var EmptyCredential = Credential{}

// authEntry represents a single authentication entry in the containers-auth.json file.
// Reference: https://github.com/containers/image/blob/main/docs/containers-auth.json.5.md
type authEntry struct {
	Auth     string `json:"auth,omitempty"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
}

// authFile represents the structure of a containers-auth.json file.
// Reference: https://github.com/containers/image/blob/main/docs/containers-auth.json.5.md
type authFile struct {
	Auths map[string]authEntry `json:"auths"`
}

// AuthJson represents authentication configuration using the containers-auth.json format.
// It implements credential storage compatible with Podman, Buildah, and Skopeo.
//
// Reference: https://github.com/containers/image/blob/main/docs/containers-auth.json.5.md
type AuthJson struct {
	// path is the file path to the auth.json file.
	path string
	// rwLock is a read-write lock for thread-safe access.
	rwLock sync.RWMutex
	// auths holds the authentication entries.
	auths map[string]authEntry
}

const (
	authJsonUserDir    = ".config/containers"
	authJsonFileName   = "auth.json"
	authJsonSystemPath = "/etc/containers/auth.json"
)

// stripServerAddress returns a serverAddress without scheme or trailing /
// This normalizes server addresses for consistent credential lookups.
//
// Reference: https://github.com/containers/image/blob/main/docs/containers-auth.json.5.md
func stripServerAddress(serverAddress string) string {
	serverAddress = strings.TrimPrefix(serverAddress, "http://")
	serverAddress = strings.TrimPrefix(serverAddress, "https://")
	serverAddress = strings.TrimRight(serverAddress, "/")
	return serverAddress
}

// getAuthPaths returns a list of paths to check for credentials in hierarchical order.
// For example, for "docker.io/terrylhowe/helm", it returns:
//   - "docker.io/terrylhowe/helm"
//   - "docker.io/terrylhowe"
//   - "docker.io"
//
// This supports namespace-specific credentials as documented in containers-auth.json.
//
// Reference: https://github.com/containers/image/blob/main/docs/containers-auth.json.5.md
func getAuthPaths(serverAddress string) []string {
	addr := stripServerAddress(serverAddress)

	// Split by '/' to get all path components
	parts := strings.Split(addr, "/")
	if len(parts) == 0 {
		return []string{addr}
	}

	// Build paths from most specific to least specific
	paths := make([]string, 0, len(parts))
	for i := len(parts); i > 0; i-- {
		paths = append(paths, strings.Join(parts[:i], "/"))
	}
	return paths
}

// GetDefaultAuthJsonPath returns the path to the default auth.json file.
// It checks $HOME/.config/containers/auth.json first, then falls back to
// /etc/containers/auth.json.
//
// Reference: https://github.com/containers/image/blob/main/docs/containers-auth.json.5.md
func GetDefaultAuthJsonPath() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to get user home directory: %w", err)
	}

	// Try user-specific path first
	userPath := filepath.Join(homeDir, authJsonUserDir, authJsonFileName)
	if _, err := os.Stat(userPath); err == nil {
		return userPath, nil
	}

	// Fall back to system-wide path
	return authJsonSystemPath, nil
}

// NewAuthJson creates a new AuthJson with the given path.
// It loads the existing auth.json file if it exists.
//
// Reference: https://github.com/containers/image/blob/main/docs/containers-auth.json.5.md
func NewAuthJson(path string) (*AuthJson, error) {
	aj := &AuthJson{
		path:  path,
		auths: make(map[string]authEntry),
	}

	// Try to load existing file
	if err := aj.loadFile(); err != nil {
		return nil, fmt.Errorf("failed to load auth.json from %s: %w", path, err)
	}

	return aj, nil
}

// loadFile loads the JSON configuration from the file.
func (aj *AuthJson) loadFile() error {
	data, err := os.ReadFile(aj.path)
	if err != nil {
		if os.IsNotExist(err) {
			// File doesn't exist, start with empty auths
			return nil
		}
		return err
	}

	var file authFile
	if err := json.Unmarshal(data, &file); err != nil {
		return fmt.Errorf("failed to parse JSON: %w", err)
	}

	if file.Auths != nil {
		aj.auths = file.Auths
	}

	return nil
}

// saveFile saves the current configuration to the JSON file.
func (aj *AuthJson) saveFile() error {
	file := authFile{
		Auths: aj.auths,
	}

	data, err := json.MarshalIndent(file, "", "\t")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	// Ensure the directory exists
	dir := filepath.Dir(aj.path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", dir, err)
	}

	return os.WriteFile(aj.path, data, 0600)
}

// encodeAuth encodes a username and password into base64 format (username:password).
// Reference: https://github.com/containers/image/blob/main/docs/containers-auth.json.5.md
func encodeAuth(username, password string) string {
	if username == "" && password == "" {
		return ""
	}
	return base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
}

// decodeAuth decodes a base64-encoded auth string into username and password.
// Reference: https://github.com/containers/image/blob/main/docs/containers-auth.json.5.md
func decodeAuth(auth string) (string, string, error) {
	if auth == "" {
		return "", "", nil
	}

	decoded, err := base64.StdEncoding.DecodeString(auth)
	if err != nil {
		return "", "", fmt.Errorf("failed to decode auth: %w", err)
	}

	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid auth format")
	}

	return parts[0], parts[1], nil
}

// GetCredential returns a Credential for the given server address.
// It supports hierarchical namespace matching as per containers-auth.json specification.
// For example, for "docker.io/terrylhowe/helm", it will try to match:
//  1. "docker.io/terrylhowe/helm" (exact match)
//  2. "docker.io/terrylhowe" (namespace match)
//  3. "docker.io" (registry match)
//
// Reference: https://github.com/containers/image/blob/main/docs/containers-auth.json.5.md
func (aj *AuthJson) GetCredential(serverAddress string) (Credential, error) {
	aj.rwLock.RLock()
	defer aj.rwLock.RUnlock()

	// Try hierarchical namespace matching
	for _, path := range getAuthPaths(serverAddress) {
		if entry, exists := aj.auths[path]; exists {
			// Try to get credentials from username/password fields first
			if entry.Username != "" || entry.Password != "" {
				return Credential{
					Username: entry.Username,
					Password: entry.Password,
				}, nil
			}

			// Fall back to decoding the auth field
			if entry.Auth != "" {
				username, password, err := decodeAuth(entry.Auth)
				if err != nil {
					return EmptyCredential, fmt.Errorf("failed to decode auth for %s: %w", path, err)
				}
				return Credential{
					Username: username,
					Password: password,
				}, nil
			}
		}
	}

	// No credentials found
	return EmptyCredential, nil
}

// PutCredential stores a credential for the given server address.
// It stores both the base64-encoded auth field and plain username/password fields.
//
// Reference: https://github.com/containers/image/blob/main/docs/containers-auth.json.5.md
func (aj *AuthJson) PutCredential(serverAddress string, cred Credential) error {
	aj.rwLock.Lock()
	defer aj.rwLock.Unlock()

	serverAddress = stripServerAddress(serverAddress)

	// Store both encoded auth and plain fields for compatibility
	aj.auths[serverAddress] = authEntry{
		Auth:     encodeAuth(cred.Username, cred.Password),
		Username: cred.Username,
		Password: cred.Password,
	}

	return aj.saveFile()
}

// DeleteCredential removes the credential for the given server address.
//
// Reference: https://github.com/containers/image/blob/main/docs/containers-auth.json.5.md
func (aj *AuthJson) DeleteCredential(serverAddress string) error {
	aj.rwLock.Lock()
	defer aj.rwLock.Unlock()

	serverAddress = stripServerAddress(serverAddress)
	delete(aj.auths, serverAddress)

	return aj.saveFile()
}

// GetCredentialHelper returns the credential helper for the given server address.
// The containers-auth.json format does not support per-server credential helpers.
//
// Reference: https://github.com/containers/image/blob/main/docs/containers-auth.json.5.md
func (aj *AuthJson) GetCredentialHelper(serverAddress string) string {
	// containers-auth.json doesn't support credential helpers
	return ""
}

// CredentialsStore returns the configured credentials store.
// The containers-auth.json format does not support a credentials store field.
//
// Reference: https://github.com/containers/image/blob/main/docs/containers-auth.json.5.md
func (aj *AuthJson) CredentialsStore() string {
	// containers-auth.json doesn't have a credsStore field
	return ""
}

// SetCredentialsStore sets the credentials store.
// The containers-auth.json format does not support a credentials store field.
//
// Reference: https://github.com/containers/image/blob/main/docs/containers-auth.json.5.md
func (aj *AuthJson) SetCredentialsStore(credsStore string) error {
	// containers-auth.json doesn't support setting a credsStore
	// This is a no-op for compatibility with the Config interface
	return nil
}

// IsAuthConfigured returns whether authentication is configured.
//
// Reference: https://github.com/containers/image/blob/main/docs/containers-auth.json.5.md
func (aj *AuthJson) IsAuthConfigured() bool {
	aj.rwLock.RLock()
	defer aj.rwLock.RUnlock()

	return len(aj.auths) > 0
}

// Path returns the path to the configuration file.
//
// Reference: https://github.com/containers/image/blob/main/docs/containers-auth.json.5.md
func (aj *AuthJson) Path() string {
	return aj.path
}
