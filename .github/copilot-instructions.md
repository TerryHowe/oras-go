# GitHub Copilot Instructions for oras-go

## Project Overview

`oras-go` is a Go library for managing OCI (Open Container Initiative) artifacts, compliant with the OCI Image Format Specification and OCI Distribution Specification. It provides unified APIs for pushing, pulling, and managing artifacts across OCI-compliant registries, local file systems, and in-memory stores.

**Current version:** v2 (main branch)  
**Go versions:** Supports the two latest versions of Go (currently 1.24 and 1.25)  
**License:** Apache License 2.0

## Key Concepts

Before making changes, understand these core concepts:

1. **Targets and Content Stores** (see `docs/Targets.md`):
   - Memory Store: Stores everything in memory
   - OCI Store: Stores content in OCI-Image layout on the file system
   - File Store: Stores location-addressable content on the file system
   - Repository Store: Communicates with remote artifact repositories

2. **Modeling Artifacts** (see `docs/Modeling-Artifacts.md`):
   - Understanding OCI artifact structure and descriptors

## Coding Standards

### File Headers

All Go source files must include the Apache 2.0 license header:

```go
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
```

### Go Conventions

- Follow standard Go formatting and conventions (use `gofmt`)
- Use meaningful variable and function names
- Add package documentation comments for public packages
- Include examples in `*_test.go` files using `Example*` functions
- Avoid CRLF line endings (enforced by `make check-encoding`)
- Keep code race-condition free (tested with `-race` flag)

### Testing

- Write tests in `*_test.go` files alongside source code
- Use table-driven tests where appropriate (see existing `*_test.go` files for patterns)
- Examples should be in `example_*_test.go` files and include `// Output:` comments
- Achieve good test coverage (tracked via codecov)
- Run tests with race detector: `go test -race`

### Code Organization

- Internal packages are in `internal/` directory and are not part of public API
- Public API is in root and sub-packages like `content/`, `registry/`
- Example files are named `example_*_test.go` or `*_example_test.go`
- Keep backward compatibility for public APIs (semantic versioning)

## Development Workflow

### Building and Testing

Use the Makefile targets:

```bash
# Vendor dependencies (required before testing)
make vendor

# Run tests with coverage
make test

# Check encoding (no CRLF line endings)
make check-encoding

# Fix encoding issues
make fix-encoding

# Clean build artifacts
make clean
```

### Running Tests

```bash
# Run all tests with race detection and coverage
make test

# Run tests for a specific package
go test -race -v ./content/file/...

# Run a specific test
go test -race -v -run TestName ./package/path
```

## Important Files and Directories

- `README.md` - Main project documentation
- `MIGRATION_GUIDE.md` - Migration guide from v1 to v2
- `docs/` - Detailed documentation
  - `Modeling-Artifacts.md` - Artifact modeling concepts
  - `Targets.md` - Content stores and targets
  - `tutorial/` - Step-by-step tutorials
- `Makefile` - Build and test targets
- `go.mod` - Go module dependencies
- `.github/workflows/` - CI/CD workflows

## Common Patterns

### Descriptor Creation

Use `content.NewDescriptorFromBytes()` to create descriptors from byte content:

```go
descriptor := content.NewDescriptorFromBytes(mediaType, content)
```

### Error Handling

- Return errors with context using `fmt.Errorf("...: %w", err)`
- Use package `errdef` for standard error definitions
- Check for specific error types when needed

### Content Store Operations

Content stores implement the `Target` or `GraphTarget` interface:
- `Fetch(ctx, desc)` - Retrieve content
- `Push(ctx, desc, reader)` - Store content
- `Resolve(ctx, reference)` - Resolve reference to descriptor
- `Exists(ctx, desc)` - Check if content exists

### Testing with Temp Directories

Use `t.TempDir()` in tests for temporary directories (automatically cleaned up):

```go
func TestExample(t *testing.T) {
    tempDir := t.TempDir()
    // use tempDir
}
```

## Package Structure

- `oras.land/oras-go/v2` - Root package (copy operations, pack operations)
- `oras.land/oras-go/v2/content` - Content store implementations
  - `content/file` - File store
  - `content/oci` - OCI store
  - `content/memory` - Memory store
- `oras.land/oras-go/v2/registry` - Registry abstractions
  - `registry/remote` - Remote repository operations
  - `registry/remote/auth` - Authentication
  - `registry/remote/credentials` - Credentials management

## Resources

- [OCI Image Specification](https://github.com/opencontainers/image-spec)
- [OCI Distribution Specification](https://github.com/opencontainers/distribution-spec)
- [pkg.go.dev documentation](https://pkg.go.dev/oras.land/oras-go/v2)
- [ORAS Project](https://oras.land/)

## Code Review Guidelines

When reviewing code or making changes:

1. Ensure Apache 2.0 license headers are present
2. Verify tests are included and pass
3. Check for race conditions
4. Maintain backward compatibility
5. Update documentation if APIs change
6. Follow semantic versioning principles
7. Keep examples up to date
