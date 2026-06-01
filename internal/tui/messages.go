// Package tui implements PureLink's interactive Bubble Tea UI for batch
// results. It is intentionally a self-contained component: callers feed it a
// snapshot of engine results and the TUI handles navigation, filtering,
// sorting, detail rendering, and graceful quit. No raw v2rayN secrets, share
// links, or credentials are accepted by this package; only the public
// engine.BatchItem fields are displayed.
package tui

import (
	"github.com/MasuRii/PureLink/internal/engine"
	"github.com/MasuRii/PureLink/pkg/endpoint"
)

// CheckResultMsg is dispatched when a single batch item finishes.
// Streaming callers (future Phase 4 wiring) can deliver these as the engine
// produces them; the static integration path simply seeds the model with a
// fully populated BatchResult and never sends this message.
type CheckResultMsg struct {
	Endpoint endpoint.Endpoint
	Item     engine.BatchItem
}

// BatchCompleteMsg signals that the streaming batch finished and a final
// summary is available. Static callers can ignore this type.
type BatchCompleteMsg struct {
	Summary engine.BatchSummary
}

// ErrorMsg surfaces a non-fatal error to the TUI for display.
type ErrorMsg struct {
	Err error
}


