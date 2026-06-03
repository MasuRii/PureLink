// Package tui implements PureLink's interactive Bubble Tea UI for batch
// results. It is intentionally a self-contained component: callers feed it a
// snapshot of engine results and the TUI handles navigation, filtering,
// sorting, detail rendering, first-run imports/checks, and graceful quit.
// User-pasted subscription/link input is parsed into public BatchItem fields;
// credentials are never rendered in table output.
package tui

import (
	"context"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/MasuRii/PureLink/internal/engine"
	"github.com/MasuRii/PureLink/pkg/endpoint"
)

// CheckResultMsg is dispatched when a single batch item finishes.
// Streaming callers (future Phase 4 wiring) can deliver these as the engine
// produces them; the static integration path simply seeds the model with a
// fully populated BatchResult and never sends this message.
type CheckResultMsg struct {
	Endpoint  endpoint.Endpoint
	Item      engine.BatchItem
	Processed int
	Total     int
}

// BatchCompleteMsg signals that the streaming batch finished and a final
// summary is available. Static callers can ignore this type.
type BatchCompleteMsg struct {
	Summary engine.BatchSummary
	Source  string
	Notice  string
}

type ActionStartedMsg struct {
	Stream <-chan tea.Msg
	Cancel context.CancelFunc
	Source string
	Notice string
}

type actionStreamClosedMsg struct{}

// ErrorMsg surfaces a non-fatal error to the TUI for display.
type ErrorMsg struct {
	Err error
}

// ActionCompleteMsg replaces the current snapshot after an interactive TUI
// workflow such as URL import, check, report, or batch file parsing finishes.
type ActionCompleteMsg struct {
	Snapshot Snapshot
	Notice   string
}
