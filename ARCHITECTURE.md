# Architecture

PureLink is a modular Go CLI application for vetting endpoints, IPs, and domains against abuse intelligence and purity signals. It follows Go's standard project layout with clear separation between the CLI layer, internal application code, and reusable domain libraries.

## Layers

```
┌───────────────────────────────────────────────────────┐
│                  cmd/purelink                          │  Entry point & CLI wiring
│  8 commands: check, batch, dedupe, report,             │
│  import v2rayn, import link, version, configure        │
├───────────────────────────────────────────────────────┤
│  internal/                                             │
│    ├── app/          Structured logging & redaction     │
│    ├── checker/      TCP/TLS/HTTP/DNS probes            │
│    ├── config/       Viper config & validation          │
│    ├── engine/       Batch worker pool, dedupe,         │
│    │                aggregator, input parsers           │
│    ├── importer/     v2rayN & link file orchestration   │
│    ├── output/       Table/JSON/CSV/MD renderers        │
│    └── tui/          Bubble Tea interactive UI           │
├───────────────────────────────────────────────────────┤
│  pkg/                                                  │
│    ├── abuse/        Provider interface & merge          │
│    │   └── providers/  9 provider implementations        │
│    ├── endpoint/     Host:port parsing & normalization   │
│    ├── errors/       Sentinel errors & validation        │
│    ├── ip/           IP address classification           │
│    └── v2rayn/       Scanner, URI parser, redactor       │
└───────────────────────────────────────────────────────┘
```

## Principles

- **cmd/**: Only main packages live here. Minimal logic; wires subcommands to internal packages via Cobra.
- **internal/**: Application-specific code that cannot be imported by external projects.
- **pkg/**: Reusable domain libraries that may be imported downstream.
- All network calls are context-aware with configurable timeouts.
- No CGO dependencies — `modernc.org/sqlite` provides a pure-Go SQLite implementation.
- Sensitive data (tokens, passwords, UUIDs, subscribe URLs) is automatically redacted in all log and output paths.

## Data Flow

### Single Endpoint Check

```
User input (host:port)
  → endpoint.Parse()
  → checker.CheckEndpoint() — TCP dial, TLS handshake, HTTP probe
  → abuse.Provider.Check() — parallel provider queries (if --abuse/--purity)
  → abuse.Merge() — aggregate scores and purity verdicts
  → output.Renderer — render in chosen format
```

### Batch Processing

```
File/Stdin
  → engine.ParseReader() — auto-detect plain text, JSON, CSV, v2rayN share links
  → engine.Dedupe() (optional — if --dedupe flag)
  → engine.BatchEngine.Run()
      → N worker goroutines with per-provider rate limiting
      → checker.CheckEndpoint() + abuse providers per endpoint
  → engine.Summarize() — aggregate stats
  → output.Renderer.RenderBatch() or tui.Run() (if --interactive)
```

### v2rayN Import

```
Directory path
  → v2rayn.Discover() — locate guiNDB.db, guiNConfig.json, or config.json
  → v2rayn.ReadProfiles() — query SQLite (modernc.org/sqlite)
  → importer.DeduplicateImported()
  → output.Renderer.RenderImport()
```

## CLI Commands

| Command | Purpose |
|---------|---------|
| `check` | Validate a single endpoint (reachability, TLS, abuse, purity) |
| `batch` | Process endpoint lists from files or stdin with concurrency |
| `dedupe` | Detect duplicates across subscription lists |
| `report` | Generate a full diagnostic report (DNS, TLS, HTTP, abuse, purity) |
| `import v2rayn` | Extract endpoints from a v2rayN SQLite database |
| `import link` | Parse share links from a file |
| `version` | Print version |
| `configure` | Show configuration guidance |

## External Integrations

PureLink queries 9 no-key or free-tier providers for abuse and purity signals:

| Provider | Purpose |
|----------|---------|
| Blackbox / ipinfo.app | Fast boolean proxy/hosting/Tor pre-filter |
| ipapi.is | Primary combined abuse/purity signal |
| IPLogs | High-fidelity VPN/proxy/Tor verdict scoring |
| ip-api.com | Secondary geo/ISP/ASN/hosting enrichment |
| RustyIP / ip.nc.gy | Modular per-signal lightweight checks |
| IPPriv | Security-only enrichment (VPN/proxy/Tor/hosting) |
| iplookup.it | Batch-friendly geo/ASN/VPN/proxy flags |
| Google Public DNS | DNS resolution (DoH) |
| Cloudflare DNS | DNS resolution cross-check (DoH) |

All providers implement the `abuse.Provider` interface with `Name()`, `Check()`, and `RateLimit()` methods. Rate limiting is enforced per-provider via `golang.org/x/time/rate`.

## Purity Classification

The purity system classifies endpoints into categories based on provider signals:

| Verdict | Criteria |
|---------|----------|
| `clean` | No VPN/proxy/Tor signals, score < 50, not a datacenter |
| `suspicious` | Datacenter detected or score ≥ 50 |
| `vpn_likely` | VPN, proxy, or Tor signal with score < 70 |
| `vpn_detected` | VPN, proxy, or Tor signal with score ≥ 70 |
| `unknown` | Insufficient data from providers |

## Error Handling

PureLink uses sentinel errors defined in `pkg/errors` for programmatic error classification:

| Error | Usage |
|-------|-------|
| `ErrInvalidEndpoint` | Malformed host:port input |
| `ErrInvalidConfig` | Invalid CLI flags or config file values |
| `ErrFileNotFound` | Input file does not exist |
| `ErrBatchEmpty` | No valid endpoints parsed from input |
| `ErrProviderTimeout` | Provider HTTP request timed out |
| `ErrProviderRateLimited` | Provider returned HTTP 429 |
| `ErrV2rayNNotDetected` | Directory is not a valid v2rayN installation |
| `ErrV2rayNDBNotFound` | SQLite database not found in v2rayN directory |

Exit codes follow a convention: 0 for success, 1 for general errors, 4 for abuse threshold exceeded (when `--fail-on-abuse` is used).

## Testing Strategy

| Layer | Approach |
|-------|----------|
| Unit tests | Standard `go test` with `testify` assertions |
| Golden files | Snapshot-based output verification in `internal/output/testdata/` |
| Fuzz tests | `go test -fuzz` for endpoint parsing and v2rayN URI parsing |
| Benchmarks | `go test -bench` for hot paths (endpoint parsing, deduplication) |
| Race detector | All tests run with `-race` in CI |
| Coverage gate | Minimum 35% total coverage enforced by CI |

## Technology Stack

| Component | Library |
|-----------|---------|
| CLI framework | [Cobra](https://github.com/spf13/cobra) + [Viper](https://github.com/spf13/viper) |
| TUI framework | [Bubble Tea](https://github.com/charmbracelet/bubbletea) + [Lip Gloss](https://github.com/charmbracelet/lipgloss) |
| SQLite | [modernc.org/sqlite](https://pkg.go.dev/modernc.org/sqlite) (pure Go, no CGO) |
| Rate limiting | [golang.org/x/time](https://pkg.go.dev/golang.org/x/time/rate) |
| Testing | [testify](https://github.com/stretchr/testify) |
| Release automation | [GoReleaser](https://goreleaser.com/) |
