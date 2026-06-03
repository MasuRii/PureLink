package tui

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/MasuRii/PureLink/internal/engine"
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

	case ActionStartedMsg:
		if m.activeActionCancel != nil {
			m.activeActionCancel()
		}
		m.activeActionStream = msg.Stream
		m.activeActionCancel = msg.Cancel
		m.snapshot = Snapshot{Source: msg.Source}
		m.cursor = 0
		m.mode = ModeList
		m.currentAction = ActionNone
		m.lastErr = nil
		m.lastNotice = msg.Notice
		m.recompute()
		return m, waitForActionStream(msg.Stream)

	case CheckResultMsg:
		// Streaming integration path: append/replace by host:port key.
		follow := m.shouldAutoFollowTail()
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
		m.snapshot.Summary = engine.Summarize(m.snapshot.Items)
		if msg.Total > 0 {
			m.snapshot.Summary.Total = msg.Total
		}
		if msg.Processed > 0 {
			m.snapshot.Summary.Processed = msg.Processed
		}
		m.recompute()
		if follow && len(m.visible) > 0 {
			m.cursor = len(m.visible) - 1
		}
		return m, m.nextActionStreamCmd()

	case BatchCompleteMsg:
		m.snapshot.Summary = msg.Summary
		if msg.Source != "" {
			m.snapshot.Source = msg.Source
		}
		m.lastErr = nil
		m.lastNotice = msg.Notice
		m.activeActionStream = nil
		m.activeActionCancel = nil
		return m, nil

	case actionStreamClosedMsg:
		m.activeActionStream = nil
		m.activeActionCancel = nil
		return m, nil

	case ErrorMsg:
		if m.activeActionCancel != nil {
			m.activeActionCancel()
		}
		m.activeActionStream = nil
		m.activeActionCancel = nil
		m.lastNotice = ""
		m.lastErr = msg.Err
		return m, nil

	case ActionCompleteMsg:
		m.activeActionStream = nil
		m.activeActionCancel = nil
		if len(msg.Snapshot.Items) == 0 && msg.Snapshot.Summary.SpeedMbps > 0 {
			m.snapshot.Summary.SpeedMbps = msg.Snapshot.Summary.SpeedMbps
			m.snapshot.Source = msg.Snapshot.Source
		} else {
			m.snapshot = msg.Snapshot
		}
		m.mode = ModeList
		m.currentAction = ActionNone
		m.lastErr = nil
		m.lastNotice = msg.Notice
		m.recompute()
		return m, nil
	}

	// Forward to spinner so it keeps animating until quit.
	var cmd tea.Cmd
	m.spin, cmd = m.spin.Update(msg)
	return m, cmd
}

func (m BatchModel) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if m.mode == ModeInput {
		switch msg.String() {
		case "esc":
			m.mode = ModeList
			m.currentAction = ActionNone
			m.actionInput.Blur()
			return m, nil
		case "enter":
			value := m.actionInput.Value()
			m.actionInput.Blur()
			m.mode = ModeList
			m.lastErr = nil
			m.lastNotice = "running " + strings.ToLower(actionTitle(m.currentAction)) + "..."
			return m, m.runActionCmd(value)
		default:
			var cmd tea.Cmd
			m.actionInput, cmd = m.actionInput.Update(msg)
			return m, cmd
		}
	}

	if m.mode == ModeActionMenu {
		switch msg.String() {
		case "esc", "q", "?":
			m.mode = ModeList
			return m, nil
		case "i":
			m.OpenAction(ActionImportURL)
		case "b":
			m.OpenAction(ActionBatchFile)
		case "l":
			m.OpenAction(ActionLinkFile)
		case "v":
			m.OpenAction(ActionV2RayN)
		case "c":
			m.OpenAction(ActionCheck)
		case "R":
			m.OpenAction(ActionReport)
		case "d":
			m.OpenAction(ActionDedupeFiles)
		case "D":
			m.DeduplicateCurrent()
		case "T":
			m.lastNotice = "running speed test..."
			return m, speedtestCmd()
		}
		return m, nil
	}

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
		if m.activeActionCancel != nil {
			m.activeActionCancel()
		}
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
	case "?":
		m.OpenActionMenu()
	case "i":
		m.OpenAction(ActionImportURL)
	case "b":
		m.OpenAction(ActionBatchFile)
	case "l":
		m.OpenAction(ActionLinkFile)
	case "v":
		m.OpenAction(ActionV2RayN)
	case "c":
		m.OpenAction(ActionCheck)
	case "R":
		m.OpenAction(ActionReport)
	case "d":
		m.OpenAction(ActionDedupeFiles)
	case "D":
		m.DeduplicateCurrent()
	case "T":
		m.lastNotice = "running speed test..."
		return m, speedtestCmd()
	case "s":
		m.CycleSort()
	case "f":
		m.CycleFilter()
	case "e":
		if err := m.ExportVisible(); err != nil {
			m.lastNotice = ""
			m.lastErr = err
		}
	case "r":
		if err := m.ExportVisibleByRegion(); err != nil {
			m.lastNotice = ""
			m.lastErr = err
		}
	case "p":
		if err := m.ExportVisibleByProtocol(); err != nil {
			m.lastNotice = ""
			m.lastErr = err
		}
	case "E":
		if err := m.ExportClean(); err != nil {
			m.lastNotice = ""
			m.lastErr = err
		}
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

	if m.mode == ModeActionMenu {
		body = m.renderActionMenu()
	} else if m.mode == ModeInput {
		body = m.renderActionInput()
	} else if m.mode == ModeDetail {
		body = m.theme.FocusedBorder.Width(m.viewportWidth()).Render(m.renderDetail())
	} else if len(m.snapshot.Items) == 0 && m.snapshot.Summary.Total == 0 {
		body = m.renderOnboarding()
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
	speed := ""
	if m.snapshot.Summary.SpeedMbps > 0 {
		speed = fmt.Sprintf("  speed: %.2f Mbps", m.snapshot.Summary.SpeedMbps)
	}
	right := m.theme.Subtitle.Render(fmt.Sprintf("source: %s  sort: %s  filter: %s%s",
		source, m.sortKey, m.filterKey, speed))
	gap := strings.Repeat(" ", maxInt(1, m.width-lipgloss.Width(left)-lipgloss.Width(right)))
	return left + gap + right
}

func (m BatchModel) renderTable() string {
	cols := tableColumns(m.visible)

	var b strings.Builder
	for i, c := range cols {
		cell := padRight(c.title, c.width)
		b.WriteString(m.theme.Header.Render(cell))
		if i < len(cols)-1 {
			b.WriteString(" ")
		}
	}
	b.WriteString("\n")

	if len(m.visible) == 0 {
		message := "(no results match the current filter)"
		if len(m.snapshot.Items) == 0 && m.snapshot.Summary.Total == 0 {
			message = "(no endpoints loaded) Press i to import subscription/raw URLs, b to batch-check a file, c to check an endpoint, or ? for all actions."
		}
		b.WriteString(m.theme.Mute.Render(message))
		return m.theme.Border.Width(maxInt(m.viewportWidth(), lipgloss.Width(b.String())+2)).Render(b.String())
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
		cells := tableRowCells(item)
		padded := make([]string, len(cells))
		for idx, cell := range cells {
			padded[idx] = padRight(cell, cols[idx].width)
		}

		if i == m.cursor {
			b.WriteString(m.theme.Selected.Render(strings.Join(padded, " ")))
		} else {
			b.WriteString(padded[0])
			b.WriteString(" ")
			b.WriteString(padded[1])
			b.WriteString(" ")
			b.WriteString(padded[2])
			b.WriteString(" ")
			b.WriteString(padded[3])
			b.WriteString(" ")
			if item.Reachable {
				b.WriteString(m.theme.Good.Render(padded[4]))
			} else {
				b.WriteString(m.theme.Bad.Render(padded[4]))
			}
			b.WriteString(" ")
			b.WriteString(padded[5])
			b.WriteString(" ")
			abuseStyle := m.theme.AbuseStyle(item.AbuseScore)
			if abuseScoreUnknown(item.AbuseScore, item.Purity) {
				abuseStyle = m.theme.Mute
			}
			b.WriteString(abuseStyle.Render(padded[6]))
			b.WriteString(" ")
			b.WriteString(m.theme.PurityStyle(item.Purity).Render(padded[7]))
		}
		b.WriteString("\n")
	}
	return m.theme.Border.Width(maxInt(m.viewportWidth(), lipgloss.Width(b.String())+2)).Render(b.String())
}

type tableColumn struct {
	title string
	width int
}

func tableColumns(items []engine.BatchItem) []tableColumn {
	cols := []tableColumn{
		{title: "Host"},
		{title: "Port"},
		{title: "Protocol"},
		{title: "Region"},
		{title: "Reachable"},
		{title: "Latency"},
		{title: "Abuse Score"},
		{title: "Purity"},
	}
	for i := range cols {
		cols[i].width = lipgloss.Width(cols[i].title)
	}
	for _, item := range items {
		cells := tableRowCells(item)
		for i, cell := range cells {
			cols[i].width = maxInt(cols[i].width, lipgloss.Width(cell))
		}
	}
	return cols
}

func tableRowCells(item engine.BatchItem) []string {
	return []string{
		item.Endpoint.Host,
		strconv.Itoa(item.Endpoint.Port),
		displayValue(item.Protocol),
		displayRegion(item),
		boolShort(item.Reachable),
		formatLatency(item.LatencyMs, item.Reachable),
		formatAbuseScore(item.AbuseScore, item.Purity),
		item.Purity,
	}
}

func displayRegion(item engine.BatchItem) string {
	if item.Country != "" {
		return item.Country
	}
	if item.CountryCode != "" {
		return item.CountryCode
	}
	return "—"
}

func displayValue(value string) string {
	if value == "" {
		return "—"
	}
	return value
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

func formatAbuseScore(score int, purity string) string {
	if abuseScoreUnknown(score, purity) {
		return "—"
	}
	return strconv.Itoa(score)
}

func abuseScoreUnknown(score int, purity string) bool {
	return score == 0 && purity == "unknown"
}

// padRight pads s with spaces on the right up to width. It never truncates;
// callers compute dynamic column widths from the full visible values.
func padRight(s string, width int) string {
	pad := width - lipgloss.Width(s)
	if pad <= 0 {
		return s
	}
	return s + strings.Repeat(" ", pad)
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func (m BatchModel) shouldAutoFollowTail() bool {
	if len(m.visible) == 0 {
		return true
	}
	return m.cursor >= len(m.visible)-2
}

func (m BatchModel) nextActionStreamCmd() tea.Cmd {
	if m.activeActionStream == nil {
		return nil
	}
	return waitForActionStream(m.activeActionStream)
}

func waitForActionStream(ch <-chan tea.Msg) tea.Cmd {
	if ch == nil {
		return nil
	}
	return func() tea.Msg {
		msg, ok := <-ch
		if !ok {
			return actionStreamClosedMsg{}
		}
		return msg
	}
}

func (m BatchModel) renderHelp() string {
	hints := []string{
		"q quit",
		"↑↓ nav",
		"enter detail",
		"/ search",
		"? actions",
		"i import",
		"c check",
		"s sort",
		"f filter",
		"e export listed",
		"r by region",
		"p by protocol",
		"E export clean",
	}
	if m.mode == ModeFilter {
		hints = []string{"esc cancel", "enter apply"}
	}
	if m.mode == ModeInput {
		hints = []string{"enter run", "esc cancel"}
	}
	if m.mode == ModeActionMenu {
		hints = []string{"i import", "b batch", "c check", "R report", "d dedupe", "T speed", "esc close"}
	}
	if m.mode == ModeDetail {
		hints = []string{"esc/enter close", "↑↓ scroll"}
	}
	help := strings.Join(hints, "  ")
	if m.lastErr != nil {
		help = m.theme.Bad.Render("error: "+m.lastErr.Error()) + "  " + help
	} else if m.lastNotice != "" {
		help = m.theme.Good.Render(m.lastNotice) + "  " + help
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
	fmt.Fprintf(&b, "  Protocol:   %s\n", displayValue(item.Protocol))
	fmt.Fprintf(&b, "  Region:     %s\n", displayRegion(item))
	fmt.Fprintf(&b, "  Reachable:  %s\n", boolLabel(item.Reachable, m.theme))
	fmt.Fprintf(&b, "  Latency:    %dms\n", item.LatencyMs)
	abuseStyle := m.theme.AbuseStyle(item.AbuseScore)
	if abuseScoreUnknown(item.AbuseScore, item.Purity) {
		abuseStyle = m.theme.Mute
	}
	fmt.Fprintf(&b, "  Abuse:      %s\n", abuseStyle.Render(formatAbuseScore(item.AbuseScore, item.Purity)))
	fmt.Fprintf(&b, "  Purity:     %s\n", m.theme.PurityStyle(item.Purity).Render(item.Purity))
	if item.ProviderTotal > 0 {
		fmt.Fprintf(&b, "  Providers:  %d/%d successful\n", item.ProviderSuccesses, item.ProviderTotal)
	}
	if item.SpeedMbps > 0 {
		fmt.Fprintf(&b, "  Speed:      %.2f Mbps\n", item.SpeedMbps)
	}
	if len(item.ProviderErrs) > 0 {
		b.WriteString("\n")
		if item.ProviderSuccesses > 0 {
			b.WriteString(m.theme.Subtitle.Render("Provider Warnings\n"))
			b.WriteString("  Verdict used the successful provider responses below; unavailable providers were not averaged in.\n")
		} else {
			b.WriteString(m.theme.Subtitle.Render("Provider Errors\n"))
			b.WriteString("  No provider returned usable data, so abuse/purity should be treated as unknown.\n")
		}
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
