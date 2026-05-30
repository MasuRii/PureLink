# PureLink

> CLI toolkit for vetting endpoints, IPs, and domains — ensuring your connections are clean, unique, and abuse-free.

## Overview

PureLink is a fast, opinionated command-line tool for security engineers, network admins, and developers who need to validate remote endpoints before routing traffic through them. It answers one question: **"Can I trust this endpoint?"**

## Features

- **Abuse Reputation** — Query multi-source threat intelligence for IP/domain abuse history
- **Purity Check** — Verify whether an address is a residential IP, datacenter, VPN exit, or proxy
- **Uniqueness Audit** — Detect duplicates and collisions across subscription lists
- **Latency & Health** — Quick TCP/HTTP probes with region-aware diagnostics
- **Batch Mode** — Validate entire host lists from files or stdin
- **Multiple Output Formats** — Table, JSON, CSV, and Markdown reports

## Installation

### From Source

```bash
git clone https://github.com/MasuRii/PureLink.git
cd purelink
make build
```

### Prebuilt Binaries

Download from the [releases page](https://github.com/MasuRii/PureLink/releases).

### Go Install

```bash
go install github.com/MasuRii/PureLink/cmd/purelink@latest
```

## Quick Start

```bash
# Check a single IP
purelink check 159.89.194.243

# Check with abuse intelligence
purelink check 159.89.194.243 --abuse

# Batch check from a file
purelink batch ./endpoints.txt --format json

# Verify endpoint uniqueness across lists
purelink dedupe ./list-a.txt ./list-b.txt

# Full report with latency and purity score
purelink report 159.89.194.243:22539 --verbose
```

## Usage

```
PureLink — Endpoint purity and abuse scanner

Usage:
  purelink [command]

Available Commands:
  check       Validate a single endpoint
  batch       Validate endpoints from a file or stdin
  dedupe      Find duplicates across endpoint lists
  report      Generate a full diagnostic report
  version     Print version information

Flags:
  -h, --help      help for purelink
  -v, --verbose   enable verbose output
  -o, --output    output format (table|json|csv|md)
```

## Project Structure

```
PureLink/
├── cmd/purelink/         # Application entry point
├── internal/
│   ├── checker/          # Core validation logic
│   ├── config/           # Configuration and CLI flags
│   └── output/           # Formatters (table, json, csv)
├── pkg/
│   ├── ip/               # IP analysis utilities
│   ├── endpoint/         # Endpoint parsing and probing
│   └── abuse/            # Threat intelligence integrations
├── docs/                 # Documentation
├── scripts/              # Build and release scripts
└── test/                 # Integration and fixture data
```

## Development

```bash
# Run tests
make test

# Run linter
make lint

# Build for all platforms
make release
```

## License

MIT © MasuRii
