package tui

import (
	"context"
	"errors"
	"io"
	"os"

	tea "github.com/charmbracelet/bubbletea"

	plerrors "github.com/MasuRii/PureLink/pkg/errors"
)

// RunOptions configures Run. It is intentionally minimal so cmd/purelink can
// adopt the TUI with a one-line call once integration is wired.
type RunOptions struct {
	// Snapshot is the data the model renders. Required.
	Snapshot Snapshot
	// NoColor disables coloured output (matches the global --no-color flag).
	NoColor bool
	// Output overrides the destination Bubble Tea writes to. Defaults to
	// os.Stdout when nil. Tests pass io.Discard for non-terminal verification.
	Output io.Writer
	// Input overrides the input source. Defaults to os.Stdin.
	Input *os.File
	// Headless skips opening the alt screen and starting the program loop.
	// Used by tests to verify model construction without a TTY.
	Headless bool
}

// ErrNoTTY is returned by Run when the program detects it is not connected to
// a terminal capable of supporting the TUI. Callers should fall back to
// static output.
var ErrNoTTY = errors.New("tui: no terminal attached; falling back to static output")

// Run launches the interactive TUI for a completed batch run. The function
// blocks until the user quits or an error is returned. The returned model is
// the final BatchModel state, which callers can inspect for selections or
// metrics.
func Run(ctx context.Context, opts RunOptions) (BatchModel, error) {
	if len(opts.Snapshot.Items) == 0 && opts.Snapshot.Summary.Total == 0 {
		return BatchModel{}, plerrors.ErrBatchEmpty
	}

	if !opts.Headless && !hasTerminalInput(opts.Input) {
		return BatchModel{}, ErrNoTTY
	}

	model := NewBatchModel(opts.Snapshot, Options{NoColor: opts.NoColor})
	if opts.Headless {
		// In headless mode we just return the constructed model so callers
		// (and tests) can drive Update() manually. The contract is that no
		// terminal I/O occurs.
		return model, nil
	}

	progOpts := []tea.ProgramOption{tea.WithAltScreen()}
	if opts.Output != nil {
		progOpts = append(progOpts, tea.WithOutput(opts.Output))
	}
	if opts.Input != nil {
		progOpts = append(progOpts, tea.WithInput(opts.Input))
	}
	if ctx != nil {
		progOpts = append(progOpts, tea.WithContext(ctx))
	}

	prog := tea.NewProgram(model, progOpts...)
	finalModel, err := prog.Run()
	if err != nil {
		return BatchModel{}, err
	}
	if bm, ok := finalModel.(BatchModel); ok {
		return bm, nil
	}
	return model, nil
}

// IsEmptySnapshot reports whether the supplied error matches the package's
// empty-snapshot sentinel. Callers can use this to fall back to static
// rendering instead of failing hard.
func IsEmptySnapshot(err error) bool {
	return errors.Is(err, plerrors.ErrBatchEmpty)
}

func hasTerminalInput(input *os.File) bool {
	if input == nil {
		input = os.Stdin
	}
	info, err := input.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}
