package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

const pureLinkASCII = ` ███████████                                █████        ███             █████     
▒▒███▒▒▒▒▒███                              ▒▒███        ▒▒▒             ▒▒███      
 ▒███    ▒███ █████ ████ ████████   ██████  ▒███        ████  ████████   ▒███ █████
 ▒██████████ ▒▒███ ▒███ ▒▒███▒▒███ ███▒▒███ ▒███       ▒▒███ ▒▒███▒▒███  ▒███▒▒███ 
 ▒███▒▒▒▒▒▒   ▒███ ▒███  ▒███ ▒▒▒ ▒███████  ▒███        ▒███  ▒███ ▒███  ▒██████▒  
 ▒███         ▒███ ▒███  ▒███     ▒███▒▒▒   ▒███      █ ▒███  ▒███ ▒███  ▒███▒▒███ 
 █████        ▒▒████████ █████    ▒▒██████  ███████████ █████ ████ █████ ████ █████
▒▒▒▒▒          ▒▒▒▒▒▒▒▒ ▒▒▒▒▒      ▒▒▒▒▒▒  ▒▒▒▒▒▒▒▒▒▒▒ ▒▒▒▒▒ ▒▒▒▒ ▒▒▒▒▒ ▒▒▒▒ ▒▒▒▒▒ `

func (m BatchModel) renderBrandASCII() string {
	lines := strings.Split(pureLinkASCII, "\n")
	out := make([]string, 0, len(lines))
	for i, line := range lines {
		style := m.theme.BrandA
		switch i % 3 {
		case 1:
			style = m.theme.BrandB
		case 2:
			style = m.theme.BrandC
		}
		out = append(out, style.Render(line))
	}
	return lipgloss.JoinVertical(lipgloss.Left, out...)
}

func (m BatchModel) renderOnboarding() string {
	var b strings.Builder
	b.WriteString(m.renderBrandASCII())
	b.WriteString("\n\n")
	b.WriteString(m.theme.Title.Render("First run: no endpoints loaded yet — import, check, and inspect without leaving the TUI"))
	b.WriteString("\n")
	b.WriteString(m.theme.Subtitle.Render("Paste HTTP(S) subscription URLs, raw vmess/vless/trojan/ss links, or base64/plain v2rayN-style subscriptions."))
	b.WriteString("\n\n")
	b.WriteString("  i  import subscription/raw URLs (multiple accepted)\n")
	b.WriteString("  b  run a batch endpoint file\n")
	b.WriteString("  l  import share-link file\n")
	b.WriteString("  v  import v2rayN folder\n")
	b.WriteString("  c  check one endpoint\n")
	b.WriteString("  R  report DNS/TLS/HTTP for one endpoint\n")
	b.WriteString("  d  dedupe files    D  dedupe current list\n")
	b.WriteString("  T  run speed test  ?  show this menu\n\n")
	b.WriteString(m.theme.Help.Render("After results load: ↑↓ navigate, enter detail, / search, s sort, f filter, e/r/p/E export."))
	return m.theme.Border.Width(maxInt(m.viewportWidth(), lipgloss.Width(pureLinkASCII)+2)).Render(b.String())
}

func (m BatchModel) renderActionMenu() string {
	var b strings.Builder
	b.WriteString(m.renderBrandASCII())
	b.WriteString("\n\n")
	b.WriteString(m.theme.Title.Render("PureLink actions"))
	b.WriteString("\n\n")
	b.WriteString("  i  import HTTP(S) subscription URLs / pasted raw links\n")
	b.WriteString("  b  run batch file\n")
	b.WriteString("  l  import link file\n")
	b.WriteString("  v  import v2rayN folder\n")
	b.WriteString("  c  check endpoint\n")
	b.WriteString("  R  report endpoint\n")
	b.WriteString("  d  dedupe files\n")
	b.WriteString("  D  dedupe current loaded list\n")
	b.WriteString("  T  speed test\n")
	b.WriteString("  esc close\n")
	return m.theme.FocusedBorder.Width(m.viewportWidth()).Render(b.String())
}

func (m BatchModel) renderActionInput() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n\n", m.theme.Title.Render(actionTitle(m.currentAction)))
	b.WriteString(m.theme.Subtitle.Render(actionPlaceholder(m.currentAction)))
	b.WriteString("\n\n")
	b.WriteString(m.actionInput.View())
	b.WriteString("\n\n")
	b.WriteString(m.theme.Help.Render("enter run  esc cancel"))
	return m.theme.FocusedBorder.Width(m.viewportWidth()).Render(b.String())
}
