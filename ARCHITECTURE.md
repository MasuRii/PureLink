# Architecture

PureLink is structured as a modular Go CLI application.

## Layers

```
┌─────────────────────────────────────┐
│           cmd/purelink              │  Entry point & CLI wiring
├─────────────────────────────────────┤
│  internal/                          │
│    ├── checker/    Validation logic │
│    ├── config/     App configuration│
│    └── output/     Report formatters│
├─────────────────────────────────────┤
│  pkg/                               │
│    ├── ip/         IP utilities     │
│    ├── endpoint/   Host:port parsing│
│    └── abuse/      Threat intel     │
└─────────────────────────────────────┘
```

## Principles

- **cmd/**: Only main packages live here. Minimal logic.
- **internal/**: Application-specific code that cannot be imported by external projects.
- **pkg/**: Reusable domain libraries that may be imported downstream.
- **docs/**: Markdown documentation and design decisions.
- **scripts/**: Build, release, and utility automation.

## External Integrations

Planned integrations for abuse reputation and purity checks:
- AbuseIPDB API
- VirusTotal API
- IPinfo / IPGeolocation
- Shodan (optional)
- Custom allow/block lists
