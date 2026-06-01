# Contributing to PureLink

Thank you for your interest in contributing! This guide will help you get started.

## Getting Started

1. Fork the repository
2. Clone your fork:
   ```bash
   git clone https://github.com/YOUR_USERNAME/PureLink.git
   cd PureLink
   ```
3. Create a feature branch:
   ```bash
   git checkout -b feat/your-feature
   ```

## Prerequisites

- [Go 1.24.2+](https://go.dev/dl/)
- [golangci-lint](https://golangci-lint.run/welcome/install/) (for linting)

## Development Workflow

```bash
# Build the binary
make build

# Run all tests with race detector and coverage
make test

# Run linter
make lint

# Format all Go files
make fmt

# View coverage summary
make coverage

# Run benchmarks
make bench

# Run fuzz smoke tests
make fuzz

# Run security scans (gosec + govulncheck)
make sec

# Download and tidy dependencies
make deps

# Remove build artifacts
make clean
```

## Code Style

- Follow standard Go conventions (`gofmt`, `go vet`)
- Keep exported APIs minimal; prefer `internal/` for application code
- Add tests for all new packages and critical paths
- Use meaningful commit messages following [Conventional Commits](https://www.conventionalcommits.org/):
  - `feat:` for new features
  - `fix:` for bug fixes
  - `docs:` for documentation changes
  - `test:` for test additions/changes
  - `chore:` for maintenance tasks
  - `refactor:` for code restructuring
  - `ci:` for CI/CD changes

## Project Layout

Follow the standard Go project layout:

| Directory | Purpose |
|---|---|
| `cmd/purelink/` | Main entry point and CLI command definitions |
| `internal/` | Application code (not importable externally) |
| `pkg/` | Reusable domain libraries (importable externally) |

### Adding a New Provider

1. Create a new file in `pkg/abuse/providers/` implementing the `abuse.Provider` interface:

   ```go
   type Provider interface {
       Name() string
       Check(ctx context.Context, ip string) (*ProviderResult, error)
       RateLimit() RateLimit
   }
   ```

2. Register the provider constructor in `pkg/abuse/providers/providers.go`:
   - Add to the `Default()` slice
   - Add to the `ByName()` map

3. Add the provider name to `KnownProviderNames` in `pkg/abuse/provider.go`

4. Add tests and update the default config in `internal/config/config.go` if appropriate

### Adding a New Output Format

1. Implement a `render<Type><Format>()` function in `internal/output/output.go`
2. Add the format string to the `formats` map in `internal/config/config.go`
3. Wire it into the relevant `Render*` method's switch statement
4. Add golden test files in `internal/output/testdata/`

## Testing

### Unit Tests

Run the full test suite:

```bash
make test
```

Tests are located alongside the source files (e.g., `endpoint.go` → `endpoint_test.go`).

### Golden File Tests

Output renderers use golden file snapshot tests. To update golden files after intentional output changes:

```bash
go test ./internal/output/ -update
```

### Fuzz Tests

Run fuzz smoke tests:

```bash
make fuzz
```

Fuzz targets:
- `FuzzEndpointParse` in `pkg/endpoint/`
- `FuzzVMessURI` in `pkg/v2rayn/`

## Pull Request Process

1. Ensure all tests pass (`make test`)
2. Ensure the linter passes (`make lint`)
3. Update documentation if you change user-facing behavior
4. Reference any related issues in the PR description
5. Keep the `purelink` binary/command name unchanged unless explicitly required
6. Avoid committing secrets, API keys, or private endpoint data

## Reporting Issues

Please include:

- PureLink version (`purelink version`)
- Operating system and architecture
- Steps to reproduce
- Expected vs actual behavior
- Logs or output (use the `--verbose` flag for additional detail)

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).
