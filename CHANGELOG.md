# Changelog

All notable changes to PureLink will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project uses version tags compatible with Go modules.

## [Unreleased]

### Added

- **CLI Commands**: `check`, `batch`, `dedupe`, `report`, `import v2rayn`, `import link`, `version`, `configure`.
- **Batch Engine**: Concurrent worker pool with per-provider rate limiting, sorting (abuse/latency/host/port), and filtering (reachable/unreachable/abusive/suspicious/clean/errors).
- **Interactive TUI**: Bubble Tea-powered terminal UI with keyboard navigation, live filtering, sort cycling, and detail view.
- **v2rayN Integration**: Import endpoints from v2rayN SQLite databases (`guiNDB.db`) and share link files.
- **Share Link Parsing**: Support for vmess, vless, trojan, shadowsocks, hysteria2, tuic, wireguard, socks, http, anytls, naive, SIP008 JSON, and WireGuard INI formats.
- **9 Abuse Providers**: blackbox, ipapi.is, iplogs, ip-api.com, rustyip, ippriv, iplookup.it, google-dns, cloudflare-dns.
- **Purity Classification**: Endpoint classification into clean/suspicious/vpn_likely/vpn_detected based on aggregated provider signals.
- **Output Formats**: Table, JSON, CSV, and Markdown renderers with golden file snapshot tests.
- **Log Redaction**: Automatic redaction of tokens, passwords, UUIDs, and sensitive URLs in structured logging.
- **Configuration**: YAML config file support (`~/.purelink.yaml`), environment variable overrides (`PURELINK_*`), and CLI flags.
- **Exit Codes**: Semantic exit codes — 0 (success), 1 (general error), 4 (abuse threshold exceeded via `--fail-on-abuse`).
- **Testing**: Unit tests with race detector, golden file snapshot tests, fuzz tests (endpoint parsing, v2rayN URI parsing), benchmarks, and a 35% coverage gate.
- **CI Pipeline**: Format check, lint (11 linters), vulnerability scan (govulncheck), security scan (gosec), cross-platform tests (Linux/macOS/Windows), CGO-disabled verification, and dependency review.
- **Release Automation**: GoReleaser v2 with cross-platform builds (linux/darwin/windows × amd64/arm64), checksums, SBOMs, and draft GitHub releases.
- **Repository Governance**: CODEOWNERS, issue templates (bug report, feature request), pull request template, security policy, and contributing guide.
- Initial repository metadata for `github.com/MasuRii/PureLink`.
