package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MasuRii/PureLink/internal/tui"
)

func execute(args ...string) (string, string, error) {
	var out, errOut bytes.Buffer
	cmd := newRootCommand(&out, &errOut)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return out.String(), errOut.String(), err
}

func TestVersionCommand(t *testing.T) {
	out, _, err := execute("version")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "PureLink") {
		t.Fatalf("out=%q", out)
	}
}
func TestHelpCommand(t *testing.T) {
	out, _, err := execute("--help")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "check") || !strings.Contains(out, "batch") {
		t.Fatalf("out=%q", out)
	}
}
func TestImportLinkJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "links.txt")
	if err := os.WriteFile(path, []byte("trojan://credential@192.0.2.1:443#123e4567-e89b-12d3-a456-426614174000\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, _, err := execute("--format", "json", "import", "link", path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "credential") || strings.Contains(out, "123e4567-e89b-12d3-a456-426614174000") || !strings.Contains(out, "192.0.2.1") {
		t.Fatalf("out=%q", out)
	}
}

func TestBatchHelpIncludesUXFlags(t *testing.T) {
	out, _, err := execute("batch", "--help")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"--sort", "--filter", "--fail-on-abuse", "--no-progress"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %s in help:\n%s", want, out)
		}
	}
}

func TestExitCodeAbuseThreshold(t *testing.T) {
	if got := exitCode(errAbuseThresholdExceeded); got != 4 {
		t.Fatalf("exitCode=%d", got)
	}
	if got := userError(errAbuseThresholdExceeded); !strings.Contains(got, "abuse or purity threshold exceeded") {
		t.Fatalf("userError=%q", got)
	}
}

func TestBatchInteractiveUsesTUI(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "endpoints.txt")
	if err := os.WriteFile(path, []byte("127.0.0.1:1\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	oldRunTUI := runTUI
	called := false
	runTUI = func(ctx context.Context, opts tui.RunOptions) (tui.BatchModel, error) {
		called = true
		if opts.Snapshot.Source != path {
			t.Fatalf("snapshot source=%q, want %q", opts.Snapshot.Source, path)
		}
		if opts.Snapshot.Summary.Total != 1 || len(opts.Snapshot.Items) != 1 {
			t.Fatalf("unexpected snapshot: %+v", opts.Snapshot)
		}
		return tui.BatchModel{}, nil
	}
	defer func() { runTUI = oldRunTUI }()

	out, errOut, err := execute("--timeout", "1", "--no-color", "batch", path, "--interactive", "--no-progress")
	if err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("interactive batch did not call TUI runner")
	}
	if strings.Contains(errOut, "not implemented") {
		t.Fatalf("unexpected warning: %q", errOut)
	}
	if out != "" {
		t.Fatalf("interactive success should not render static output, got %q", out)
	}
}

func TestBatchProgressAndNoColor(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "endpoints.txt")
	if err := os.WriteFile(path, []byte("127.0.0.1:1\n127.0.0.1:2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, errOut, err := execute("--timeout", "1", "--no-color", "batch", path, "--sort", "host", "--filter", "errors")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(errOut, "Checking 2 endpoints") {
		t.Fatalf("progress stderr=%q", errOut)
	}
	if strings.Contains(out, "─") || !strings.Contains(out, "Summary") {
		t.Fatalf("unexpected output=%q", out)
	}
}
