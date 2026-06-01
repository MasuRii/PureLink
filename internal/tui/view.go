package tui

import (
	"fmt"
	"strconv"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// Init satisfies tea.Model. The TUI starts the spinner so streaming callers
// see motion while results stream in. Static callers see the spinner stop on
// the first BatchCompleteMsg.
func (m BatchModel) Init() tea.Cmd {
	return m.spin.Tick
}

// Update implements the Bubble Tea reducer.
func (m BatchModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.SetSize(msg.Width, msg.Height)
		return m, nil

	case tea.KeyMsg:
		return m.handleKey(msg)

	case CheckResultMsg:
		// Streaming integration path: append/replace by host:port key.
		key := msg.Endpoint.Normalize()
		replaced := false
		for i, existing := range m.snapshot.Items {
			if existing.Endpoint.Normalize() == key {
				m.snapshot.Items[i] = msg.Item
				replaced = true
				break
			}
		}
		if !replaced {
			m.snapshot.Items = append(m.snapshot.Items, msg.Item)
		}
		m.recompute()
		return m, nil

	case BatchCompleteMsg:
		m.snapshot.Summary = msg.Summary
		return m, nil

	case ErrorMsg:
		m.lastErr = msg.Err
		return m, nil
	}

	// Forward to spinner so it keeps animating until quit.
	var cmd tea.Cmd
	m.spin, cmd = m.spin.Update(msg)
	return m, cmd
}

func (m BatchModel) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if m.mode == ModeFilter {
		switch msg.String() {
		case "esc":
			m.mode = ModeList
			m.filterInput.SetValue("")
			m.filterInput.Blur()
			m.SetSearch("")
			return m, nil
		case "enter":
			m.SetSearch(m.filterInput.Value())
			m.mode = ModeList
			m.filterInput.Blur()
			return m, nil
		default:
			var cmd tea.Cmd
			m.filterInput, cmd = m.filterInput.Update(msg)
			m.SetSearch(m.filterInput.Value())
			return m, cmd
		}
	}

	if m.mode == ModeDetail {
		switch msg.String() {
		case "esc", "enter", "q":
			m.mode = ModeList
			return m, nil
		}
		var cmd tea.Cmd
		m.detail, cmd = m.detail.Update(msg)
		return m, cmd
	}

	switch msg.String() {
	case "q", "ctrl+c":
		m.quitting = true
		return m, tea.Quit
	case "up", "k":
		m.MoveCursor(-1)
	case "down", "j":
		m.MoveCursor(1)
	case "pgup":
		m.MoveCursor(-10)
	case "pgdown", " ":
		m.MoveCursor(10)
	case "home", "g":
		m.cursor = 0
	case "end", "G":
		if len(m.visible) > 0 {
			m.cursor = len(m.visible) - 1
		}
	case "/":
		m.mode = ModeFilter
		m.filterInput.Focus()
	case "s":
		m.CycleSort()
	case "f":
		m.CycleFilter()
	case "enter":
		if _, ok := m.Selected(); ok {
			m.mode = ModeDetail
			m.detail.SetContent(m.renderDetail())
		}
	}
	return m, nil
}

// View renders the multi-panel layout described in 07-wireframes.md §9.
func (m BatchModel) View() string {
	if m.quitting {
		return ""
	}

	header := m.renderHeader()
	body := m.renderTable()
	help := m.renderHelp()

	if m.mode == ModeDetail {
		body = m.theme.FocusedBorder.Width(m.viewportWidth()).Render(m.renderDetail())
	}

	filterRow := ""
	if m.mode == ModeFilter || m.search != "" {
		prompt := m.filterInput.View()
		if m.mode != ModeFilter {
			prompt = "/ " + m.search
		}
		filterRow = m.theme.Filter.Render(prompt)
	}

	parts := []string{header}
	if filterRow != "" {
		parts = append(parts, filterRow)
	}
	parts = append(parts, body, help)
	return lipgloss.JoinVertical(lipgloss.Left, parts...)
}

func (m BatchModel) viewportWidth() int {
	if m.width > 4 {
		return m.width - 4
	}
	return 80
}

func (m BatchModel) renderHeader() string {
	source := m.snapshot.Source
	if source == "" {
		source = "endpoints"
	}
	total := m.snapshot.Summary.Total
	if total == 0 {
		total = len(m.snapshot.Items)
	}
	processed := m.snapshot.Summary.Processed
	if processed == 0 {
		processed = total
	}
	pct := 0
	if total > 0 {
		pct = processed * 100 / total
	}

	left := m.theme.Title.Render(fmt.Sprintf("PureLink Batch — %d/%d (%d%%)", processed, total, pct))
	right := m.theme.Subtitle.Render(fmt.Sprintf("source: %s  sort: %s  filter: %s",
		source, m.sortKey, m.filterKey))
	gap := strings.Repeat(" ", maxInt(1, m.width-lipgloss.Width(left)-lipgloss.Width(right)))
	return left + gap + right
}

func (m BatchModel) renderTable() string {
	cols := []struct {
		title string
		width int
	}{
		{"Host", 26},
		{"Port", 6},
		{"Reach", 6},
		{"Lat", 7},
		{"Abuse", 6},
		{"Purity", 14},
	}

	var b strings.Builder
	// header row
	for i, c := range cols {
		cell := padRight(c.title, c.width)
		b.WriteString(m.theme.Header.Render(cell))
		if i < len(cols)-1 {
			b.WriteString(" ")
		}
	}
	b.WriteString("\n")

	if len(m.visible) == 0 {
		b.WriteString(m.theme.Mute.Render("(no results match the current filter)"))
		return m.theme.Border.Width(m.viewportWidth()).Render(b.String())
	}

	height := maxInt(5, m.height-10)
	start := 0
	if m.cursor >= height {
		start = m.cursor - height + 1
	}
	end := start + height
	if end > len(m.visible) {
		end = len(m.visible)
	}

	for i := start; i < end; i++ {
		item := m.visible[i]
		host := padRight(item.Endpoint.Host, cols[0].width)
		port := padRight(strconv.Itoa(item.Endpoint.Port), cols[1].width)
		reach := padRight(boolShort(item.Reachable), cols[2].width)
		lat := padRight(formatLatency(item.LatencyMs, item.Reachable), cols[3].width)
		abuse := padRight(strconv.Itoa(item.AbuseScore), cols[4].width)
		purity := padRight(item.Purity, cols[5].width)

		if i == m.cursor {
			row := host + " " + port + " " + reach + " " + lat + " " + abuse + " " + purity
			b.WriteString(m.theme.Selected.Render(row))
		} else {
			b.WriteString(host)
			b.WriteString(" ")
			b.WriteString(port)
			b.WriteString(" ")
			if item.Reachable {
				b.WriteString(m.theme.Good.Render(reach))
			} else {
				b.WriteString(m.theme.Bad.Render(reach))
			}
			b.WriteString(" ")
			b.WriteString(lat)
			b.WriteString(" ")
			b.WriteString(m.theme.AbuseStyle(item.AbuseScore).Render(abuse))
			b.WriteString(" ")
			b.WriteString(m.theme.PurityStyle(item.Purity).Render(purity))
		}
		b.WriteString("\n")
	}
	return m.theme.Border.Width(m.viewportWidth()).Render(b.String())
}

func boolShort(v bool) string {
	if v {
		return "yes"
	}
	return "no"
}

func formatLatency(ms int64, reachable bool) string {
	if !reachable {
		return "—"
	}
	return strconv.FormatInt(ms, 10) + "ms"
}

// padRight pads s with spaces on the right up to width, truncating with an
// ellipsis if longer.
func padRight(s string, width int) string {
	if len(s) > width {
		if width <= 1 {
			return s[:width]
		}
		return s[:width-1] + "…"
	}
	return s + strings.Repeat(" ", width-len(s))
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func (m BatchModel) renderHelp() string {
	hints := []string{
		"q quit",
		"↑↓ nav",
		"enter detail",
		"/ search",
		"s sort",
		"f filter",
	}
	if m.mode == ModeFilter {
		hints = []string{"esc cancel", "enter apply"}
	}
	if m.mode == ModeDetail {
		hints = []string{"esc/enter close", "↑↓ scroll"}
	}
	help := strings.Join(hints, "  ")
	if m.lastErr != nil {
		help = m.theme.Bad.Render("error: "+m.lastErr.Error()) + "  " + help
	}
	return m.theme.Help.Render(help)
}

func (m BatchModel) renderDetail() string {
	item, ok := m.Selected()
	if !ok {
		return m.theme.Mute.Render("no selection")
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n", m.theme.Title.Render(fmt.Sprintf("Detail: %s", item.Endpoint.String())))
	fmt.Fprintf(&b, "  Host:       %s\n", item.Endpoint.Host)
	fmt.Fprintf(&b, "  Port:       %d\n", item.Endpoint.Port)
	fmt.Fprintf(&b, "  Reachable:  %s\n", boolLabel(item.Reachable, m.theme))
	fmt.Fprintf(&b, "  Latency:    %dms\n", item.LatencyMs)
	fmt.Fprintf(&b, "  Abuse:      %s\n", m.theme.AbuseStyle(item.AbuseScore).Render(strconv.Itoa(item.AbuseScore)))
	fmt.Fprintf(&b, "  Purity:     %s\n", m.theme.PurityStyle(item.Purity).Render(item.Purity))
	if len(item.ProviderErrs) > 0 {
		b.WriteString("\n")
		b.WriteString(m.theme.Subtitle.Render("Provider Errors\n"))
		for _, msg := range item.ProviderErrs {
			fmt.Fprintf(&b, "  - %s\n", msg)
		}
	}
	return b.String()
}

func boolLabel(v bool, t Theme) string {
	if v {
		return t.Good.Render("true")
	}
	return t.Bad.Render("false")
}
