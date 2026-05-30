# Go CLI/TUI Repository Research

This document records actively maintained Go CLI/TUI projects and libraries that can inform PureLink's command structure, output rendering, configuration, and future interactive batch mode.

## Recommended References

| # | Repository | License | Maintenance / Credibility | PureLink adaptation |
|---|------------|---------|---------------------------|--------------------|
| 1 | [spf13/cobra](https://github.com/spf13/cobra) | Apache-2.0 | De-facto Go CLI framework used by Kubernetes, Docker, Hugo, and GitHub CLI; active 2026 development noted in research. | Model `check`, `batch`, `dedupe`, `report`, `version`, and shell-completion command structure. |
| 2 | [urfave/cli](https://github.com/urfave/cli) | MIT | Mature CLI framework with active v3 development and a smaller dependency footprint than Cobra. | Alternative if PureLink needs a simpler declarative command tree. |
| 3 | [charmbracelet/bubbletea](https://github.com/charmbracelet/bubbletea) | MIT | Widely adopted Elm-style TUI framework in the Charm ecosystem. | Future interactive `batch` TUI with async endpoint checks and result navigation. |
| 4 | [charmbracelet/lipgloss](https://github.com/charmbracelet/lipgloss) | MIT | Active terminal styling/layout library; integrates across Charm tools. | Styled terminal tables, status messages, and consistent color handling. |
| 5 | [charmbracelet/bubbles](https://github.com/charmbracelet/bubbles) | MIT | Production TUI components including tables, spinners, progress bars, lists, and viewports. | Batch progress indicators, result tables, and detailed report panes. |
| 6 | [charmbracelet/huh](https://github.com/charmbracelet/huh) | MIT | High-level forms/prompts built on Bubble Tea, including accessible-mode support. | Future `purelink configure` wizard for defaults and optional API keys. |
| 7 | [jedib0t/go-pretty](https://github.com/jedib0t/go-pretty) | MIT | Mature table/list/progress rendering library with table, CSV, TSV, HTML, and Markdown output. | Backend candidate for `--format table`, `--format csv`, and `--format md`. |
| 8 | [olekukonko/tablewriter](https://github.com/olekukonko/tablewriter) | MIT | Revived v1.x line with generics, streaming support, and modern renderers noted in research. | Lightweight table dependency, especially for streaming batch results. |
| 9 | [charmbracelet/glamour](https://github.com/charmbracelet/glamour) | MIT | Markdown renderer used by developer CLIs such as GitHub CLI and Gitea. | Render Markdown reports with terminal-friendly styling. |
| 10 | [spf13/viper](https://github.com/spf13/viper) | MIT | Standard Go configuration library with env vars, config files, defaults, and flag binding. | Manage defaults for output format, timeout, provider selection, and API keys. |
| 11 | [jesseduffield/lazygit](https://github.com/jesseduffield/lazygit) | MIT | Large, mature Go TUI application with async operations, panels, keybindings, and configuration. | Reference patterns for long-running scans, status bars, keybinding maps, and modal details. |
| 12 | [yorukot/superfile](https://github.com/yorukot/superfile) | MIT | Modern Bubble Tea/Lip Gloss multi-panel file manager with active maintenance. | Reference for multi-pane endpoint/result layouts and themeable TUI design. |

## Highest-ROI Path for PureLink

1. Use Cobra plus Viper for command structure, configuration, shell completions, and environment overrides.
2. Use Lip Gloss/Bubbles for spinners, progress, and terminal-native table presentation.
3. Use go-pretty or tablewriter if PureLink needs a focused output-formatting dependency without a full TUI stack.
4. Defer Bubble Tea until an interactive `batch` mode is needed.

## Caveats

- The Charm ecosystem has been moving quickly; integration should follow current module paths and APIs at implementation time.
- GoReleaser and GitHub Actions should pin versions before public release if reproducibility becomes critical.
- PureLink should keep the product/binary command name `purelink` even if package/module ownership remains `github.com/MasuRii/PureLink`.
