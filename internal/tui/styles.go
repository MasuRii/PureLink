package tui

import (
	"github.com/charmbracelet/lipgloss"
)

// Theme bundles every Lip Gloss style the TUI uses. Two themes are supported:
// the default colored theme, and a no-color theme that maps every style to a
// no-op (matching --no-color behaviour required by the architecture).
type Theme struct {
	NoColor bool

	Title    lipgloss.Style
	Subtitle lipgloss.Style

	Header   lipgloss.Style
	Cell     lipgloss.Style
	Selected lipgloss.Style

	Good lipgloss.Style
	Warn lipgloss.Style
	Bad  lipgloss.Style
	Mute lipgloss.Style

	Help lipgloss.Style

	Border        lipgloss.Style
	FocusedBorder lipgloss.Style

	Filter   lipgloss.Style
	Detail   lipgloss.Style
	StatusOK lipgloss.Style
	Spinner  lipgloss.Style
}

// DefaultTheme returns the colored Lip Gloss theme used in interactive mode.
// All foreground colors meet WCAG AA against the standard dark terminal
// backgrounds shipped by GNOME, Windows Terminal, iTerm2, and Alacritty.
func DefaultTheme() Theme {
	return Theme{
		Title:         lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#7D56F4")),
		Subtitle:      lipgloss.NewStyle().Foreground(lipgloss.Color("#A78BFA")),
		Header:        lipgloss.NewStyle().Bold(true).Padding(0, 1).Foreground(lipgloss.Color("#FAFAFA")).Background(lipgloss.Color("#3B3486")),
		Cell:          lipgloss.NewStyle().Padding(0, 1),
		Selected:      lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FFFFFF")).Background(lipgloss.Color("#7D56F4")),
		Good:          lipgloss.NewStyle().Foreground(lipgloss.Color("#04B575")),
		Warn:          lipgloss.NewStyle().Foreground(lipgloss.Color("#F4D03F")),
		Bad:           lipgloss.NewStyle().Foreground(lipgloss.Color("#FF4672")),
		Mute:          lipgloss.NewStyle().Foreground(lipgloss.Color("#626262")),
		Help:          lipgloss.NewStyle().Foreground(lipgloss.Color("#9A9A9A")),
		Border:        lipgloss.NewStyle().BorderStyle(lipgloss.RoundedBorder()).BorderForeground(lipgloss.Color("#3B3486")).Padding(0, 1),
		FocusedBorder: lipgloss.NewStyle().BorderStyle(lipgloss.RoundedBorder()).BorderForeground(lipgloss.Color("#7D56F4")).Padding(0, 1),
		Filter:        lipgloss.NewStyle().Foreground(lipgloss.Color("#F4D03F")),
		Detail:        lipgloss.NewStyle().Padding(0, 1),
		StatusOK:      lipgloss.NewStyle().Foreground(lipgloss.Color("#04B575")).Bold(true),
		Spinner:       lipgloss.NewStyle().Foreground(lipgloss.Color("#7D56F4")),
	}
}

// NoColorTheme returns a theme where every style is a passthrough. It is
// applied when the user passes --no-color or when the program is connected to
// a non-terminal sink.
func NoColorTheme() Theme {
	pass := lipgloss.NewStyle()
	bold := lipgloss.NewStyle().Bold(true)
	return Theme{
		NoColor:       true,
		Title:         bold,
		Subtitle:      pass,
		Header:        bold,
		Cell:          pass,
		Selected:      bold,
		Good:          pass,
		Warn:          pass,
		Bad:           pass,
		Mute:          pass,
		Help:          pass,
		Border:        pass,
		FocusedBorder: pass,
		Filter:        pass,
		Detail:        pass,
		StatusOK:      bold,
		Spinner:       pass,
	}
}

// PurityStyle returns the style associated with a purity verdict, falling back
// to the muted style for unknown or empty verdicts.
func (t Theme) PurityStyle(purity string) lipgloss.Style {
	switch purity {
	case "clean":
		return t.Good
	case "suspicious", "vpn_likely":
		return t.Warn
	case "vpn_detected":
		return t.Bad
	default:
		return t.Mute
	}
}

// AbuseStyle returns the style associated with an abuse score band.
func (t Theme) AbuseStyle(score int) lipgloss.Style {
	switch {
	case score <= 0:
		return t.Good
	case score < 50:
		return t.Warn
	default:
		return t.Bad
	}
}
