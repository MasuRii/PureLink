# Contributing to PureLink

Thank you for your interest in contributing!

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/MasuRii/PureLink.git`
3. Create a feature branch: `git checkout -b feat/your-feature`

## Development Workflow

```bash
make deps      # Download and tidy dependencies
make build     # Build the binary
make test      # Run all tests with coverage
make lint      # Run golangci-lint
```

## Code Style

- Follow standard Go conventions (`gofmt`, `go vet`)
- Keep exported APIs minimal; prefer `internal/` for application code
- Add tests for all new packages and critical paths
- Use meaningful commit messages following [Conventional Commits](https://www.conventionalcommits.org/)

## Pull Request Process

1. Ensure all tests pass (`make test`)
2. Update documentation if needed
3. Reference any related issues
4. Request review from maintainers

## Reporting Issues

Please include:
- PureLink version (`purelink version`)
- Operating system and architecture
- Steps to reproduce
- Expected vs actual behavior
