<div align="center">

# 🔗 PureLink

**CLI toolkit for vetting endpoints, IPs, and domains — ensuring your connections are clean, unique, and abuse-free.**

[![Go Version](https://img.shields.io/badge/go-1.25.11-00ADD8?logo=go&logoColor=white)](https://go.dev/) [![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE) [![CI](https://github.com/MasuRii/PureLink/actions/workflows/ci.yml/badge.svg)](https://github.com/MasuRii/PureLink/actions/workflows/ci.yml) [![Go Report Card](https://goreportcard.com/badge/github.com/MasuRii/PureLink)](https://goreportcard.com/report/github.com/MasuRii/PureLink) [![Release](https://img.shields.io/github/v/release/MasuRii/PureLink?include_prereleases)](https://github.com/MasuRii/PureLink/releases) [![GitHub Downloads](https://img.shields.io/github/downloads/MasuRii/PureLink/total)](https://github.com/MasuRii/PureLink/releases)

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
| **Purity Check** | Verify whether an address is residential, datacenter, VPN, proxy, Tor, or hosting infrastructure |
| **Uniqueness Audit** | Detect duplicates and collisions across endpoint and subscription lists |
| **Latency & Health** | Quick TCP/HTTP/DNS/TLS probes with region-aware diagnostics |
| **Batch Processing** | Validate entire host lists with concurrent workers, retries, filtering, sorting, and live progress |
| **Interactive TUI** | First-run onboarding plus action shortcuts for import, batch, check, report, dedupe, speedtest, and export |
| **Live Streaming TUI** | Long-running TUI actions stream each result as it arrives with smart tail auto-follow and cancellation on quit |
| **Subscription URL Import** | Fetch HTTP(S) subscription URLs and parse base64/plain v2rayN-style share-link content |
| **v2rayN Import** | Extract and validate endpoints directly from v2rayN databases, folders, pasted content, and share links |
| **Link Parsing** | Parse vmess, vless, trojan, ss, hysteria2, tuic, wireguard, socks, http, anytls, naive, SIP008, and WireGuard INI formats |
| **Live Speedtest** | Run optional Cloudflare download speed checks from the CLI or TUI and include Mbps in summaries |
| **Export Engine** | Export clean or visible endpoints as plain endpoints, CSV, JSON, share links, or base64 subscription payloads; split visible exports by region or protocol in the TUI |
| **Secret-Safe Output** | Raw share links are omitted from JSON/default output and only used for explicit share-link/subscription exports |
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

### Homebrew (macOS & Linux)

```bash
brew install --cask MasuRii/tap/purelink
```

### Scoop (Windows)

```powershell
scoop bucket add MasuRii https://github.com/MasuRii/scoop-bucket.git
scoop install purelink
```

### WinGet (Windows)

```powershell
winget install MasuRii.PureLink
```

### Docker

```bash
docker run --rm ghcr.io/masurii/purelink:latest --version
docker run --rm ghcr.io/masurii/purelink:latest check 1.2.3.4
```

### npm

```bash
npm install -g purelink
# Or run without installing:
npx purelink --version
```

## Quick Start

```bash
# Launch the interactive TUI
purelink

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

# Import from HTTP(S) subscription URLs
purelink import url "https://provider.example/subscription"

# Measure live download speed
purelink speedtest

# Export clean reachable endpoints after checks
purelink batch ./endpoints.txt --abuse --purity --export-clean clean.csv --export-format csv

# Export clean imported share links as a base64 subscription when raw links are preserved
purelink import link ./subscription.txt --abuse --export-clean clean.sub --export-format subscription

# Launch the interactive TUI after a batch run
purelink batch ./endpoints.txt --abuse --interactive
```

## Commands

| Command | Purpose |
|---|---|
| `purelink` | Launch the interactive TUI |
| `check <endpoint>` | Validate a single endpoint (reachability, TLS, abuse, purity) |
| `batch <file\|->` | Process endpoint lists with concurrency, sorting, and filtering |
| `dedupe <file...>` | Detect duplicates across one or more endpoint list files |
| `report <endpoint>` | Generate a full diagnostic report (DNS, TLS, HTTP, abuse, purity) |
| `import v2rayn <dir>` | Extract endpoints from a v2rayN installation directory |
| `import link <file>` | Parse share links or subscription content from a file |
| `import url <url...>` / `import sub <url...>` | Fetch and parse HTTP(S) subscription URLs |
| `speedtest` | Run an optional live download speed test |
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
| `--purity` | `false` | Include purity/VPN/proxy signals in results |
| `--region` | `false` | Include endpoint country/region lookup |
| `--speed-test` | `false` | Run an optional live download speed test and show Mbps in output/TUI summaries |
| `--sort` | `abuse` | Sort by: `abuse`, `latency`, `host`, `port` |
| `--filter` | `all` | Filter by: `all`, `reachable`, `unreachable`, `abusive`, `suspicious`, `clean`, `errors` |
| `--dedupe` | `false` | Deduplicate endpoints before processing |
| `--stdin` | `false` | Read from stdin instead of file |
| `--interactive` | `false` | Launch interactive TUI after batch completes |
| `--no-progress` | `false` | Suppress progress display |
| `--fail-on-abuse` | `false` | Exit with code 4 when abuse or purity risk is detected |
| `--export-clean` | — | Write clean reachable endpoints to a file after checks |
| `--export-format` | `endpoints` | Export format: `endpoints`, `txt`, `links`, `share-links`, `subscription`, `v2rayn`, `csv`, or `json` |

### Check Flags

| Flag | Description |
|---|---|
| `--abuse` | Include abuse intelligence |
| `--purity` | Include purity signals |
| `--region` | Include endpoint country/region lookup |
| `--dns` | Include DNS resolution info |
| `--http` | Include HTTP probe |
| `--fail-on-abuse` | Exit with code 4 when abuse or purity risk is detected |

### Import Flags

The `import v2rayn`, `import link`, and `import url` commands share these flags:

| Flag | Default | Description |
|---|---|---|
| `--output` | `-` | Write extracted endpoints to a file or stdout for non-interactive imports |
| `--skip-secrets` | `true` | Redact credentials and raw share links from non-interactive output |
| `--interactive`, `-i` | `false` | Check imported endpoints and open the TUI |
| `--abuse` | `false` | Enable abuse checks after import |
| `--purity` | `false` | Enable purity checks after import |
| `--region` | `false` | Include endpoint country/region lookup after import |
| `--speed-test` | `false` | Run an optional live download speed test and show Mbps in the TUI/header |
| `--workers` | `8` | Concurrent worker count for post-import checks |
| `--sort` | `abuse` | Sort checked results by `abuse`, `latency`, `host`, or `port` |
| `--filter` | `all` | Filter checked results: `all`, `reachable`, `unreachable`, `abusive`, `suspicious`, `clean`, `errors` |
| `--export-clean` | — | Write clean reachable checked endpoints to this file |
| `--export-format` | `endpoints` | Export format: `endpoints`, `txt`, `links`, `share-links`, `subscription`, `v2rayn`, `csv`, or `json` |
| `--fail-on-abuse` | `false` | Exit with code 4 when imported results exceed abuse or purity thresholds |

### Speedtest Flags

| Flag | Default | Description |
|---|---|---|
| `--url` | Cloudflare speed endpoint | Download URL used for speed testing |
| `--bytes` | `10000000` | Maximum bytes to download |

### Export Formats

`--export-clean` writes only clean, reachable endpoints. The TUI can also export the currently visible list (`e`), split visible endpoints by region (`r`), split by protocol (`p`), or export clean endpoints (`E`).

| Format | Output | Notes |
|---|---|---|
| `endpoints`, `txt`, `proxy-pool` | Plain `host:port` lines | Default for CLI and TUI endpoint exports |
| `csv` | `protocol,host,port,country,country_code,abuse_score,purity` | Does not include raw share links |
| `json` | Pretty JSON batch items | Raw share links are excluded with `json:"-"` |
| `links`, `share-links` | Original imported share links, one per line | Requires preserved raw links |
| `subscription`, `v2rayn` | Base64-encoded newline-separated share links | Requires preserved raw links |

Share-link and subscription exports only work when the import source preserved raw share links, such as `import link`, `import url`, pasted TUI subscriptions, and share-link backed v2rayN data. DB-only imports, WireGuard INI, SIP008 JSON, or any path using redacted non-interactive output may not have raw links; in that case PureLink returns `no preserved share links available for export` instead of emitting secrets accidentally.

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

Running `purelink` without a subcommand launches the interactive terminal UI by default. First-time users see an onboarding screen with import/check/report shortcuts, and `batch --interactive` opens the same [Bubble Tea](https://github.com/charmbracelet/bubbletea)-powered UI after processing results.

TUI actions stream results progressively: batch checks emit each checked endpoint as it completes, imports emit one parsed endpoint at a time, check/report emit a single live result, and the cursor auto-follows the tail only while you are already near the bottom. Pressing `q` or `ctrl+c` cancels any active action before quitting.

| Key | Action |
|---|---|
| `↑` / `k` | Move cursor up |
| `↓` / `j` | Move cursor down |
| `PgUp` / `PgDn` | Jump 10 items |
| `Home` / `g` | Go to first item |
| `End` / `G` | Go to last item |
| `Enter` | View detail for selected item |
| `/` | Open filter/search prompt |
| `?` | Open action menu / onboarding shortcuts |
| `i` | Import HTTP(S) subscription URLs, pasted raw links, or pasted subscription content |
| `b` | Run a batch endpoint file |
| `l` | Import a share-link file |
| `v` | Import a v2rayN folder |
| `c` | Check one endpoint |
| `R` | Run a DNS/TLS/HTTP report for one endpoint |
| `d` | Dedupe endpoint files |
| `D` | Dedupe the current loaded list |
| `T` | Run a live download speed test |
| `s` | Cycle sort mode (abuse → latency → host → port → purity) |
| `f` | Cycle filter mode (all → reachable → unreachable → abusive → suspicious → clean → errors) |
| `e` | Export the currently visible list as plain endpoints |
| `r` | Export visible endpoints split by region |
| `p` | Export visible endpoints split by protocol |
| `E` | Export clean reachable endpoints as plain endpoints |
| `q` / `ctrl+c` | Cancel active action and quit |

## Project Structure

```
PureLink/
├── cmd/purelink/              # Application entry point (Cobra commands)
├── internal/
│   ├── app/                   # Structured logging with sensitive data redaction
│   ├── checker/               # TCP/TLS/HTTP/DNS connectivity probes
│   ├── config/                # Viper-based configuration loading and validation
│   ├── engine/                # Batch worker pool, deduplication, aggregation, parsers, exports
│   ├── importer/              # v2rayN, share link file, and HTTP(S) subscription import orchestration
│   ├── output/                # Table/JSON/CSV/Markdown renderers + golden test data
│   ├── speedtest/             # Bounded live download speed measurements
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

- [Go 1.25.11+](https://go.dev/dl/)
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
git tag v1.1.0
git push origin v1.1.0
```

This triggers a GitHub Actions workflow that verifies the build and tests, runs GoReleaser for cross-platform binaries/checksums/SBOMs, creates a draft GitHub release, and publishes the npm wrapper with the configured `NPM_TOKEN` secret.

## License

MIT © [MasuRii](https://github.com/MasuRii)
