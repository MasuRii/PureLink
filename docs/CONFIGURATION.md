# Configuration Reference

PureLink supports three configuration methods, evaluated in the following order of precedence (highest first):

1. **CLI flags** — override everything
2. **Environment variables** — override config file values
3. **Config file** — baseline defaults

## Config File

### Location

PureLink searches for the config file in this order:

1. Path specified by `--config` / `-c`
2. `~/.purelink.yaml` (home directory)
3. `.purelink.yaml` (current working directory)

The file uses YAML format.

### Example

```yaml
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

### Fields

| Field | Type | Default | Constraints | Description |
|---|---|---|---|---|
| `format` | string | `table` | `table`, `json`, `csv`, `md` | Output format |
| `verbose` | bool | `false` | — | Enable debug-level logging |
| `timeout` | int | `10` | 1–300 (seconds) | Per-check timeout |
| `workers` | int | `8` | 1–256 | Concurrent worker count for batch |
| `no_color` | bool | `false` | — | Disable colored output |
| `providers.abuse` | list | `[blackbox, ipapi.is, iplogs]` | Valid provider names | Providers used for abuse scoring |
| `providers.purity` | list | `[ipapi.is, iplogs]` | Valid provider names | Providers used for purity classification |

## Environment Variables

All config keys can be set via environment variables with the `PURELINK_` prefix. Nested keys use underscores as separators.

| Environment Variable | Config Equivalent | Example |
|---|---|---|
| `PURELINK_FORMAT` | `format` | `json` |
| `PURELINK_VERBOSE` | `verbose` | `true` |
| `PURELINK_TIMEOUT` | `timeout` | `30` |
| `PURELINK_WORKERS` | `workers` | `16` |
| `PURELINK_NO_COLOR` | `no_color` | `true` |
| `PURELINK_PROVIDERS_ABUSE` | `providers.abuse` | `blackbox,ipapi.is` |
| `PURELINK_PROVIDERS_PURITY` | `providers.purity` | `ipapi.is,iplogs` |

Environment variable names are case-insensitive and dashes in flag names are converted to underscores (e.g., `--no-color` → `PURELINK_NO_COLOR`).

## CLI Flags

### Global Flags

| Flag | Short | Default | Description |
|---|---|---|---|
| `--config` | `-c` | — | Config file path |
| `--format` | `-o` | `table` | Output format |
| `--verbose` | `-v` | `false` | Verbose output |
| `--timeout` | `-t` | `10` | Timeout per check in seconds |
| `--no-color` | — | `false` | Disable colored output |

### `check` Flags

| Flag | Default | Description |
|---|---|---|
| `--abuse` | `false` | Include abuse intelligence |
| `--purity` | `false` | Include purity signals |
| `--dns` | `false` | Include DNS resolution info |
| `--http` | `false` | Include HTTP probe |
| `--fail-on-abuse` | `false` | Exit with code 4 when abuse/purity risk detected |

### `batch` Flags

| Flag | Default | Description |
|---|---|---|
| `--workers` | `8` | Concurrent workers (1–256) |
| `--abuse` | `false` | Include abuse intelligence |
| `--sort` | `abuse` | Sort mode: `abuse`, `latency`, `host`, `port` |
| `--filter` | `all` | Filter: `all`, `reachable`, `unreachable`, `abusive`, `suspicious`, `clean`, `errors` |
| `--dedupe` | `false` | Deduplicate before processing |
| `--stdin` | `false` | Read from stdin |
| `--interactive` | `false` | Launch TUI after batch completes |
| `--no-progress` | `false` | Suppress progress display |
| `--fail-on-abuse` | `false` | Exit with code 4 when abuse risk detected |

## Providers

### Available Providers

| Name | Key | Purpose | Default (abuse) | Default (purity) |
|---|---|---|---|---|
| Blackbox | `blackbox` | Proxy/hosting/Tor pre-filter | ✅ | — |
| ipapi.is | `ipapi.is` | Combined abuse/purity signal | ✅ | ✅ |
| IPLogs | `iplogs` | VPN/proxy/Tor verdict scoring | ✅ | ✅ |
| ip-api.com | `ip-api.com` | Geo/ISP/ASN/hosting enrichment | — | — |
| RustyIP | `rustyip` | Modular per-signal checks | — | — |
| IPPriv | `ippriv` | Security-only enrichment | — | — |
| iplookup.it | `iplookup.it` | Batch-friendly geo/ASN flags | — | — |
| Google DNS | `google-dns` | DNS resolution via DoH | — | — |
| Cloudflare DNS | `cloudflare-dns` | DNS resolution cross-check via DoH | — | — |

### Provider Rate Limits

Each provider defines its own rate limit. PureLink enforces per-provider rate limiting via a token bucket algorithm (`golang.org/x/time/rate`) to avoid hitting API limits. No API keys are required for any built-in provider.

## Exit Codes

| Code | Meaning |
|---|---|
| `0` | Success |
| `1` | General error (invalid input, config error, network failure) |
| `4` | Abuse threshold exceeded (only when `--fail-on-abuse` is used) |
