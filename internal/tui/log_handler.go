package tui

import (
	"context"
	"log/slog"
	"sync"
)

// LogHandler is a slog.Handler that buffers records in memory while the TUI
// owns the terminal. Direct stderr writes corrupt the Bubble Tea frame; the
// CLI wires this handler in interactive mode and optionally flushes the
// buffered records to a log file on exit (see 15-logging-observability.md).
type LogHandler struct {
	mu      sync.Mutex
	level   slog.Level
	records []slog.Record
}

// NewLogHandler returns a buffering handler that emits records at level or
// higher.
func NewLogHandler(level slog.Level) *LogHandler {
	return &LogHandler{level: level}
}

// Enabled reports whether the handler accepts records at the given level.
func (h *LogHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.level
}

// Handle stores the record. The slog.Record is intentionally a value copy:
// Clone is used to prevent aliasing back to the caller's attribute pointers.
func (h *LogHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.records = append(h.records, r.Clone())
	return nil
}

// WithAttrs returns the same handler. Per slog spec we should return a new
// handler bound to the supplied attrs; in this MVP the buffer is shared
// because UI consumers do not chain attrs.
func (h *LogHandler) WithAttrs(_ []slog.Attr) slog.Handler { return h }

// WithGroup returns the same handler for the same reason as WithAttrs.
func (h *LogHandler) WithGroup(_ string) slog.Handler { return h }

// Records returns a snapshot of the buffered records. The slice is safe to
// iterate without holding the handler lock.
func (h *LogHandler) Records() []slog.Record {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]slog.Record, len(h.records))
	copy(out, h.records)
	return out
}

// Reset clears the buffer. Useful for tests and for flushing after the
// records are written to a log file sink.
func (h *LogHandler) Reset() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.records = h.records[:0]
}
