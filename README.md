<div align="center">

# 🔗 PureLink

**CLI toolkit for vetting endpoints, IPs, and domains — ensuring your connections are clean, unique, and abuse-free.**

[![Go Version](https://img.shields.io/badge/go-1.24.2-00ADD8?logo=go&logoColor=white)](https://go.dev/) [![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE) [![CI](https://github.com/MasuRii/PureLink/actions/workflows/ci.yml/badge.svg)](https://github.com/MasuRii/PureLink/actions/workflows/ci.yml) [![Go Report Card](https://goreportcard.com/badge/github.com/MasuRii/PureLink)](https://goreportcard.com/report/github.com/MasuRii/PureLink) [![Release](https://img.shields.io/github/v/release/MasuRii/PureLink?include_prereleases)](https://github.com/MasuRii/PureLink/releases) [![GitHub Downloads](https://img.shields.io/github/downloads/MasuRii/PureLink/total)](https://github.com/MasuRii/PureLink/releases)

<br />

[Features](#features) · [Installation](#installation) · [Quick Start](#quick-start) · [Commands](#commands) · [Configuration](#configuration) · [Contributing](CONTRIBUTING.md)

</div>

---

## Overview

PureLink is a fast, opinionated command-line tool for security engineers, network admins, and developers who need to validate remote endpoints before routing traffic through them. It answers one question: **"Can I trust this endpoint?"**

Built in Go with zero CGO dependencies, PureLink ships as a single static binary for Linux, macOS, and Windows.

## Features

| Category | Description |
|---|---|
| **Abuse Reputation** | Query multi-source threat intelligence for IP/domain abuse history |
| **Purity Check** | Verify whether an address is a residential IP, datacenter, VPN exit, or proxy |
| **Uniqueness Audit** | Detect duplicates and collisions across subscription lists |
| **Latency & Health** | Quick TCP/HTTP probes with region-aware diagnostics |
| **Batch Processing** | Validate entire host lists with concurrent workers and progress tracking |
| **Interactive TUI** | Bubble Tea-powered terminal UI for navigating, filtering, and sorting batch results |
| **v2rayN Import** | Extract and validate endpoints directly from v2rayN databases and share links |
| **Link Parsing** | Parse vmess, vless, trojan, ss, hysteria2, tuic, wireguard, and other share link formats |
| **Multiple Formats** | Output as Table, JSON, CSV, or Markdown |
| **Log Redaction** | Automatic redaction of tokens, passwords, UUIDs, and sensitive URLs in log output |

## Installation

### Go Install

```bash
go install github.com/MasuRii/PureLink/cmd/purelink@latest
```

### From Source

```bash
git clone https://github.com/MasuRii/PureLink.git
cd PureLink
make build
```

The binary is written to `bin/purelink`.

### Prebuilt Binaries

Download from the [releases page](https://github.com/MasuRii/PureLink/releases). Builds are available for:

| OS | Architectures |
|---|---|
| Linux | amd64, arm64 |
| macOS | amd64, arm64 |
| Windows | amd64, arm64 |

## Quick Start

```bash
# Check a single IP
purelink check 159.89.194.243

# Check with abuse intelligence
purelink check 159.89.194.243 --abuse

# Check with purity signals and DNS info
purelink check 159.89.194.243 --purity --dns

# Fail CI when abuse risk is detected
purelink check 159.89.194.243 --fail-on-abuse

# Batch check from a file
purelink batch ./endpoints.txt

# Batch from stdin with JSON output and 16 workers
cat endpoints.txt | purelink batch - --stdin --format json --workers 16

# Verify endpoint uniqueness across lists
purelink dedupe ./list-a.txt ./list-b.txt

# Full diagnostic report with TLS and HTTP probes
purelink report example.com:443 --verbose

# Import endpoints from a v2rayN installation
purelink import v2rayn ~/v2rayN/

# Import from share link files
purelink import link ./subscription.txt

# Launch the interactive TUI after a batch run
purelink batch ./endpoints.txt --abuse --interactive
```

## Commands

| Command | Purpose |
|---|---|
| `check <endpoint>` | Validate a single endpoint (reachability, TLS, abuse, purity) |
| `batch <file\|->` | Process endpoint lists with concurrency, sorting, and filtering |
| `dedupe <file...>` | Detect duplicates across one or more endpoint list files |
| `report <endpoint>` | Generate a full diagnostic report (DNS, TLS, HTTP, abuse, purity) |
| `import v2rayn <dir>` | Extract endpoints from a v2rayN installation directory |
| `import link <file>` | Parse share links from a file |
| `configure` | Show configuration guidance |
| `version` | Print version information |

### Global Flags

| Flag | Short | Default | Description |
|---|---|---|---|
| `--config` | `-c` | — | Config file path (default: `~/.purelink.yaml`) |
| `--format` | `-o` | `table` | Output format: `table`, `json`, `csv`, `md` |
| `--verbose` | `-v` | `false` | Enable verbose output |
| `--timeout` | `-t` | `10` | Timeout per check in seconds (1s–5m) |
| `--no-color` | — | `false` | Disable colored terminal output |

### Batch Flags

| Flag | Default | Description |
|---|---|---|
| `--workers` | `8` | Concurrent worker count (1–256) |
| `--abuse` | `false` | Include abuse intelligence in results |
| `--sort` | `abuse` | Sort by: `abuse`, `latency`, `host`, `port` |
| `--filter` | `all` | Filter by: `all`, `reachable`, `unreachable`, `abusive`, `suspicious`, `clean`, `errors` |
| `--dedupe` | `false` | Deduplicate endpoints before processing |
| `--stdin` | `false` | Read from stdin instead of file |
| `--interactive` | `false` | Launch interactive TUI after batch completes |
| `--no-progress` | `false` | Suppress progress display |
| `--fail-on-abuse` | `false` | Exit with code 4 when abuse risk is detected |

### Check Flags

| Flag | Description |
|---|---|
| `--abuse` | Include abuse intelligence |
| `--purity` | Include purity signals |
| `--dns` | Include DNS resolution info |
| `--http` | Include HTTP probe |
| `--fail-on-abuse` | Exit with code 4 when abuse or purity risk is detected |

## Configuration

PureLink reads configuration from a YAML file or environment variables.

### Config File

By default, PureLink looks for `~/.purelink.yaml` in your home directory, then `./.purelink.yaml` in the current directory. Override with `--config`.

```yaml
# ~/.purelink.yaml
format: table
verbose: false
timeout: 10
workers: 8
no_color: false

providers:
  abuse:
    - blackbox
    - ipapi.is
    - iplogs
  purity:
    - ipapi.is
    - iplogs
```

### Environment Variables

All config keys can be set via `PURELINK_` prefixed environment variables:

| Variable | Example |
|---|---|
| `PURELINK_FORMAT` | `json` |
| `PURELINK_WORKERS` | `16` |
| `PURELINK_TIMEOUT` | `30` |
| `PURELINK_NO_COLOR` | `true` |
| `PURELINK_PROVIDERS_ABUSE` | `blackbox,ipapi.is` |

### Available Providers

| Provider | Purpose |
|---|---|
| `blackbox` | Fast boolean proxy/hosting/Tor pre-filter |
| `ipapi.is` | Combined abuse/purity signal |
| `iplogs` | VPN/proxy/Tor verdict scoring |
| `ip-api.com` | Geo/ISP/ASN/hosting enrichment |
| `rustyip` | Modular per-signal lightweight checks |
| `ippriv` | Security-only enrichment (VPN/proxy/Tor/hosting) |
| `iplookup.it` | Batch-friendly geo/ASN/VPN/proxy flags |
| `google-dns` | DNS resolution via Google Public DNS (DoH) |
| `cloudflare-dns` | DNS resolution via Cloudflare (DoH) |

## Interactive TUI

When running `batch` with the `--interactive` flag, PureLink launches a terminal UI built with [Bubble Tea](https://github.com/charmbracelet/bubbletea):

| Key | Action |
|---|---|
| `↑` / `k` | Move cursor up |
| `↓` / `j` | Move cursor down |
| `PgUp` / `PgDn` | Jump 10 items |
| `Home` / `g` | Go to first item |
| `End` / `G` | Go to last item |
| `Enter` | View detail for selected item |
| `/` | Open filter/search prompt |
| `s` | Cycle sort mode (abuse → latency → host → port → purity) |
| `f` | Cycle filter mode (all → reachable → unreachable → abusive → suspicious → clean → errors) |
| `q` | Quit |

## Project Structure

```
PureLink/
├── cmd/purelink/              # Application entry point (Cobra commands)
├── internal/
│   ├── app/                   # Structured logging with sensitive data redaction
│   ├── checker/               # TCP/TLS/HTTP/DNS connectivity probes
│   ├── config/                # Viper-based configuration loading and validation
│   ├── engine/                # Batch worker pool, deduplication, aggregation, parsers
│   ├── importer/              # v2rayN and share link file import orchestration
│   ├── output/                # Table/JSON/CSV/Markdown renderers + golden test data
│   └── tui/                   # Bubble Tea interactive terminal UI
├── pkg/
│   ├── abuse/                 # Provider interface, result merging, purity classification
│   │   └── providers/         # 9 provider implementations (blackbox, ipapi, iplogs, etc.)
│   ├── endpoint/              # Host:port parsing and normalization
│   ├── errors/                # Sentinel errors and validation types
│   ├── ip/                    # IP address classification utilities
│   └── v2rayn/                # Scanner, URI parser, SQLite reader, credential redactor
└── .github/
    ├── workflows/             # CI, release, and dependency review workflows
    └── ISSUE_TEMPLATE/        # Bug report and feature request templates
```

## Development

### Prerequisites

- [Go 1.24.2+](https://go.dev/dl/)
- [golangci-lint](https://golangci-lint.run/welcome/install/) (for linting)
- [goreleaser](https://goreleaser.com/install/) (for releases)

### Common Commands

```bash
make build               # Build the binary to bin/
make test                # Run all tests with race detector and coverage
make lint                # Run golangci-lint
make fmt                 # Format all Go files
make coverage            # Generate coverage summary
make bench               # Run benchmarks
make fuzz                # Run fuzz smoke tests
make sec                 # Run gosec and govulncheck
make clean               # Remove build artifacts
make install             # Install to $GOPATH/bin
make deps                # Download and tidy dependencies
```

### CI Pipeline

Every push and pull request runs:

1. **Format check** — `gofmt` verification
2. **Lint** — `golangci-lint` with 11 enabled linters
3. **Vulnerability scan** — `govulncheck`
4. **Security scan** — `gosec`
5. **Unit tests** — Race-enabled across Linux, macOS, and Windows
6. **Coverage gate** — Minimum 35% total coverage enforced
7. **Static build** — CGO-disabled binary verification
8. **Dependency review** — On all pull requests

### Releases

Releases are automated via [GoReleaser](https://goreleaser.com/) on every `v*` tag:

```bash
git tag v1.0.0
git push origin v1.0.0
```

This triggers a GitHub Actions workflow that builds cross-platform binaries, generates checksums and SBOMs, and creates a draft GitHub release.

## License

MIT © [MasuRii](https://github.com/MasuRii)
