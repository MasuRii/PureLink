# Changelog

All notable changes to PureLink will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project uses version tags compatible with Go modules.

## [Unreleased]

## [1.1.1] - 2026-06-03

### Restored

- **Homebrew**: Restored `homebrew_casks` publisher targeting `MasuRii/homebrew-tap` using `TAP_GITHUB_TOKEN`.
- **Scoop**: Restored `scoops` publisher targeting `MasuRii/scoop-bucket` using `SCOOP_BUCKET_GITHUB_TOKEN`.
- **Docker / OCI Images**: Restored `dockers_v2` multi-platform image builds (linux/amd64 + linux/arm64) pushed to `ghcr.io/masurii/purelink`, with Buildx/QEMU setup in CI.
- **WinGet**: Changed `skip_upload` from `true` to `auto` to enable draft-PR automation when `WINGET_GITHUB_TOKEN` is present.

### Changed

- **npm package**: Bumped npm wrapper metadata to `1.1.1`.
- **Release CI**: Added `docker/setup-qemu-action@v3` and `docker/setup-buildx-action@v3` steps for reliable multi-platform Docker builds.
- **SBOMs**: Kept archive and source SBOMs disabled pending syft compatibility verification with GoReleaser v2.

## [1.1.0] - 2026-06-03

### Added

- **TUI first-run onboarding**: Added branded onboarding and an action menu for importing subscriptions, running batch files, importing link files/v2rayN folders, checking/reporting endpoints, deduping files, deduping the current list, and running speed tests without leaving the TUI.
- **Live TUI streaming**: TUI actions now stream results progressively as `CheckResultMsg` updates arrive, with smart tail auto-follow and cancellation on quit/error.
- **Subscription URL import**: Added `import url <url...>` with `sub` alias for HTTP(S) subscription URLs, plus TUI support for pasted URLs, raw share links, and base64/plain subscription content.
- **Live speedtest**: Added `speedtest` CLI command and optional `--speed-test` integration for batch/import/TUI summaries using a bounded Cloudflare download by default.
- **Export engine**: Added clean endpoint exports via `--export-clean` and `--export-format` with `endpoints`/`txt`, `csv`, `json`, `links`/`share-links`, and `subscription`/`v2rayn` formats.
- **Grouped TUI exports**: Added TUI export shortcuts for visible endpoints, clean endpoints, and visible endpoints split by region or protocol with summary files.
- **Share-link and subscription exports**: Preserved raw imported share links for explicit share-link/subscription exports while keeping raw links out of JSON/default output.
- **Region metadata**: Added `--region` lookup support in check, batch, and import flows for country/region-aware summaries and exports.

### Changed

- **Documentation**: Updated README for Go 1.25.10, new commands/flags, TUI action keys, live streaming behavior, speedtest, subscription imports, export formats, and raw share-link limitations.
- **npm package**: Bumped npm wrapper metadata to `1.1.0`; release workflow still derives publish version from the pushed `v*` tag and uses the `NPM_TOKEN` secret as `NODE_AUTH_TOKEN`.
- **Batch/import output**: Clean exports now reject share-link/subscription formats with a clear `no preserved share links available for export` error when raw links were not available.

### Fixed

- **Secret safety**: Ensured raw share links are excluded from JSON serialization and redacted non-interactive import output while remaining available in memory only for explicit export workflows.
- **Provider merging**: Allowed clean exports when at least one provider succeeded and remaining provider errors are warnings, while rejecting items with no successful provider data.
- **Provider scoring**: Expanded provider edge-case coverage for score normalization and partial-warning behavior.

### Tests

- Added deterministic coverage for TUI streaming, smart auto-follow, cancellation-safe actions, onboarding/action views, export formats, share-link preservation, subscription URL imports, speedtest behavior, v2rayN parsing, CLI help snapshots, output goldens, fuzz cases, and e2e-style CLI flows.
- Verified the offline suite passes with gofmt, go vet, go build, all tests, golden snapshots, and total coverage above 80% in the release-readiness verification context.

### Release Notes

- Recommended release tag: `v1.1.0`.
- This is a backward-compatible minor release; no breaking CLI changes are expected.
- Share-link/subscription export requires preserved raw imported links. v2rayN DB-only imports, WireGuard INI, SIP008 JSON, or redacted non-interactive output may not contain raw links and will return a clear error instead of leaking secrets.
- Before publishing, ensure release secrets exist in GitHub settings: `TAP_GITHUB_TOKEN`, `SCOOP_BUCKET_GITHUB_TOKEN`, `WINGET_GITHUB_TOKEN`, and `NPM_TOKEN`.

## [1.0.0] - 2026-06-02

### Distribution

- **Homebrew**: Added GoReleaser `homebrew_casks:` automation targeting `MasuRii/homebrew-tap`. Install: `brew install --cask MasuRii/tap/purelink`.
- **Scoop**: Added GoReleaser `scoops:` automation targeting `MasuRii/scoop-bucket`. Install: `scoop bucket add MasuRii ... && scoop install purelink`.
- **Docker / OCI Images**: Added `dockers_v2:` multi-arch image builds (linux/amd64 + linux/arm64) pushed to `ghcr.io/masurii/purelink`.
- **WinGet**: Added GoReleaser `winget:` manifest generation with draft-PR automation to `microsoft/winget-pkgs`. Install: `winget install MasuRii.PureLink`. **Note:** `skip_upload: true` is set initially; change to `auto` when ready to publish.
- **npm**: Added npm wrapper package under `npm/` with platform-aware `postinstall` binary download. Published via GitHub Actions with `NPM_TOKEN`. Install: `npm install -g purelink`.
- **Maintainer Documentation**: Narrowed `docs/DISTRIBUTION.md` to the five implemented channels with required repository secrets and setup checklist.

### Documentation

- **Distribution Guide**: Added `docs/DISTRIBUTION.md` with package-manager and distribution channel recommendations across Windows, macOS, Linux, and cross-platform ecosystems (Homebrew, WinGet, Scoop, Chocolatey, npm, AUR, Docker, deb/rpm, Snap) with a prioritized rollout order.

### Fixed

- **Release CI**: Corrected Go version mismatch in release workflow (`1.24.2` → `1.25.10`) and added a pre-release verification gate (build + test) before GoReleaser execution.

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
