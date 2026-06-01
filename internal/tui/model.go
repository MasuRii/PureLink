package tui

import (
	"fmt"
	"sort"
	"strings"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"

	"github.com/MasuRii/PureLink/internal/engine"
)

// Mode represents the current focus of the BatchModel.
type Mode int

const (
	// ModeList is the default mode: navigate the result table.
	ModeList Mode = iota
	// ModeFilter is active while the user types into the filter box.
	ModeFilter
	// ModeDetail shows the full provider/diagnostic detail for the cursor.
	ModeDetail
)

// SortKey identifies a column to sort by. The cycle order matches the help
// bar shown to the user.
type SortKey int

const (
	SortAbuse SortKey = iota
	SortLatency
	SortHost
	SortPort
	SortPurity
)

// String returns the lower-case label used in headers and key hints.
func (k SortKey) String() string {
	switch k {
	case SortAbuse:
		return "abuse"
	case SortLatency:
		return "latency"
	case SortHost:
		return "host"
	case SortPort:
		return "port"
	case SortPurity:
		return "purity"
	default:
		return "abuse"
	}
}

// FilterKey identifies the active filter band shown above the table.
type FilterKey int

const (
	FilterAll FilterKey = iota
	FilterReachable
	FilterUnreachable
	FilterAbusive
	FilterSuspicious
	FilterClean
	FilterErrors
)

// String returns the lower-case label that matches engine.FilterItems.
func (f FilterKey) String() string {
	switch f {
	case FilterReachable:
		return "reachable"
	case FilterUnreachable:
		return "unreachable"
	case FilterAbusive:
		return "abusive"
	case FilterSuspicious:
		return "suspicious"
	case FilterClean:
		return "clean"
	case FilterErrors:
		return "errors"
	default:
		return "all"
	}
}

// Snapshot captures the data the TUI needs from a completed (or partial)
// batch run. It is designed to be assembled by the caller from the existing
// engine.BatchResult so cmd/purelink does not need to know any TUI internals.
type Snapshot struct {
	Items   []engine.BatchItem
	Summary engine.BatchSummary
	Source  string // optional batch source label, e.g. "endpoints.txt"
}

// Options configures BatchModel rendering. NoColor and Width default to safe
// values when unset.
type Options struct {
	NoColor bool
	// Width is the initial render width; if 0 the model adapts on the first
	// tea.WindowSizeMsg. A reasonable terminal default is used for tests.
	Width int
	// Height is the initial render height with the same semantics as Width.
	Height int
}

// BatchModel is the top-level Bubble Tea model for `purelink batch -i`.
// It is intentionally driven by a snapshot rather than a live engine to keep
// the package self-contained and testable without spawning real workers.
type BatchModel struct {
	theme    Theme
	snapshot Snapshot

	// view state
	mode      Mode
	cursor    int
	sortKey   SortKey
	filterKey FilterKey
	search    string

	// derived
	visible []engine.BatchItem

	// components
	filterInput textinput.Model
	detail      viewport.Model
	spin        spinner.Model

	width  int
	height int

	// quitting flips after the user requests a clean exit.
	quitting bool

	// lastErr is rendered in the help bar when present.
	lastErr error
}

// NewBatchModel constructs a model from a snapshot. The model is fully
// usable in tests without ever rendering to a terminal.
func NewBatchModel(snap Snapshot, opts Options) BatchModel {
	theme := DefaultTheme()
	if opts.NoColor {
		theme = NoColorTheme()
	}
	width := opts.Width
	if width <= 0 {
		width = 100
	}
	height := opts.Height
	if height <= 0 {
		height = 24
	}
	ti := textinput.New()
	ti.Placeholder = "type to filter host/purity, esc to clear"
	ti.CharLimit = 128
	ti.Prompt = "/ "
	vp := viewport.New(width, max(height-8, 8))
	sp := spinner.New(spinner.WithSpinner(spinner.Dot))
	sp.Style = theme.Spinner
	m := BatchModel{
		theme:       theme,
		snapshot:    snap,
		mode:        ModeList,
		filterInput: ti,
		detail:      vp,
		spin:        sp,
		width:       width,
		height:      height,
	}
	m.recompute()
	return m
}

// Snapshot returns the immutable snapshot the model was constructed with.
func (m BatchModel) SnapshotData() Snapshot { return m.snapshot }

// Visible returns the currently filtered+sorted slice. It is exported for
// tests so they can assert the result of filter/sort operations without
// rendering.
func (m BatchModel) Visible() []engine.BatchItem {
	out := make([]engine.BatchItem, len(m.visible))
	copy(out, m.visible)
	return out
}

// Cursor returns the current cursor index into the visible slice.
func (m BatchModel) Cursor() int { return m.cursor }

// Mode returns the current input mode.
func (m BatchModel) Mode() Mode { return m.mode }

// SortKey returns the active sort column.
func (m BatchModel) SortKey() SortKey { return m.sortKey }

// FilterKey returns the active filter band.
func (m BatchModel) FilterKey() FilterKey { return m.filterKey }

// Search returns the current free-text search string applied on top of the
// filter band.
func (m BatchModel) Search() string { return m.search }

// Quitting reports whether the model has signalled exit.
func (m BatchModel) Quitting() bool { return m.quitting }

// Selected returns the currently highlighted item, if any.
func (m BatchModel) Selected() (engine.BatchItem, bool) {
	if m.cursor < 0 || m.cursor >= len(m.visible) {
		return engine.BatchItem{}, false
	}
	return m.visible[m.cursor], true
}

// CycleSort advances the sort column to the next key in the cycle.
func (m *BatchModel) CycleSort() {
	m.sortKey = (m.sortKey + 1) % 5
	m.recompute()
}

// CycleFilter advances the filter band to the next key in the cycle.
func (m *BatchModel) CycleFilter() {
	m.filterKey = (m.filterKey + 1) % 7
	m.recompute()
}

// SetSearch sets the free-text search string and recomputes the visible set.
func (m *BatchModel) SetSearch(s string) {
	m.search = strings.TrimSpace(s)
	m.recompute()
}

// MoveCursor adjusts the cursor by delta, clamped to [0, len(visible)-1].
func (m *BatchModel) MoveCursor(delta int) {
	if len(m.visible) == 0 {
		m.cursor = 0
		return
	}
	target := m.cursor + delta
	if target < 0 {
		target = 0
	}
	if target >= len(m.visible) {
		target = len(m.visible) - 1
	}
	m.cursor = target
}

// SetSize updates the render dimensions and propagates to sub-components.
// Negative values are treated as zero. The caller is expected to invoke this
// from a tea.WindowSizeMsg.
func (m *BatchModel) SetSize(w, h int) {
	if w < 0 {
		w = 0
	}
	if h < 0 {
		h = 0
	}
	m.width = w
	m.height = h
	m.detail.Width = w
	if h > 8 {
		m.detail.Height = h - 8
	}
}

// recompute filters and sorts the snapshot into the visible slice. It is
// safe to call repeatedly; the snapshot itself is never mutated.
func (m *BatchModel) recompute() {
	items := make([]engine.BatchItem, len(m.snapshot.Items))
	copy(items, m.snapshot.Items)

	// Filter band first, then text search. Both honour engine semantics
	// where possible (so users see consistent behaviour with --filter).
	if filtered, err := engine.FilterItems(items, m.filterKey.String()); err == nil {
		items = filtered
	}
	if m.search != "" {
		needle := strings.ToLower(m.search)
		out := make([]engine.BatchItem, 0, len(items))
		for _, it := range items {
			if matchesSearch(it, needle) {
				out = append(out, it)
			}
		}
		items = out
	}

	// Sorting reuses engine semantics for built-in keys; purity is TUI-only.
	switch m.sortKey {
	case SortPurity:
		sort.SliceStable(items, func(i, j int) bool {
			if items[i].Purity == items[j].Purity {
				return items[i].AbuseScore > items[j].AbuseScore
			}
			return purityRank(items[i].Purity) > purityRank(items[j].Purity)
		})
	default:
		_ = engine.SortItems(items, m.sortKey.String())
	}

	m.visible = items
	if m.cursor >= len(items) {
		m.cursor = len(items) - 1
	}
	if m.cursor < 0 {
		m.cursor = 0
	}
}

func matchesSearch(it engine.BatchItem, needle string) bool {
	if needle == "" {
		return true
	}
	if strings.Contains(strings.ToLower(it.Endpoint.Host), needle) {
		return true
	}
	if strings.Contains(strings.ToLower(it.Purity), needle) {
		return true
	}
	if strings.Contains(fmt.Sprintf("%d", it.Endpoint.Port), needle) {
		return true
	}
	return false
}

// purityRank weights purity verdicts for descending "risk" sort.
func purityRank(p string) int {
	switch p {
	case "vpn_detected":
		return 5
	case "vpn_likely":
		return 4
	case "suspicious":
		return 3
	case "unknown":
		return 2
	case "clean":
		return 1
	default:
		return 0
	}
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
