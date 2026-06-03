package tui

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/MasuRii/PureLink/internal/checker"
	"github.com/MasuRii/PureLink/internal/engine"
	"github.com/MasuRii/PureLink/internal/speedtest"
	"github.com/MasuRii/PureLink/pkg/endpoint"
)

func assertTUIGolden(t *testing.T, name, got string) {
	t.Helper()
	want, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read golden %s: %v", name, err)
	}
	nGot := strings.ReplaceAll(got, "\r\n", "\n")
	nWant := strings.ReplaceAll(string(want), "\r\n", "\n")
	if !bytes.Equal([]byte(nGot), []byte(nWant)) {
		t.Fatalf("golden mismatch %s\n--- got ---\n%s\n--- want ---\n%s", name, nGot, nWant)
	}
}

func TestGoldenNoColorViews(t *testing.T) {
	tests := []struct {
		name   string
		golden string
		model  BatchModel
	}{
		{"onboarding", "view.onboarding.golden", NewBatchModel(Snapshot{Source: "interactive"}, Options{NoColor: true, Width: 120, Height: 30})},
		{"action-menu", "view.action-menu.golden", func() BatchModel {
			m := NewBatchModel(Snapshot{Source: "interactive"}, Options{NoColor: true, Width: 120, Height: 30})
			m.OpenActionMenu()
			return m
		}()},
		{"list", "view.list.golden", NewBatchModel(sampleSnapshot(), Options{NoColor: true, Width: 120, Height: 30})},
		{"detail", "view.detail.golden", func() BatchModel {
			m := NewBatchModel(sampleSnapshot(), Options{NoColor: true, Width: 120, Height: 30})
			updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
			return updated.(BatchModel)
		}()},
		{"help", "view.help.golden", func() BatchModel {
			m := NewBatchModel(sampleSnapshot(), Options{NoColor: true, Width: 120, Height: 30})
			m.OpenActionMenu()
			return m
		}()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertTUIGolden(t, tt.golden, tt.model.View())
		})
	}
}

func TestGoldenRiskyProviderWarningDetail(t *testing.T) {
	snap := Snapshot{
		Items: []engine.BatchItem{{
			Endpoint:          endpoint.Endpoint{Host: "vpn.example", Port: 8443},
			Protocol:          "vless",
			Country:           "Germany",
			CountryCode:       "DE",
			Reachable:         true,
			LatencyMs:         20,
			AbuseScore:        80,
			Purity:            "vpn_detected",
			SpeedMbps:         12.34,
			ProviderSuccesses: 1,
			ProviderTotal:     2,
			ProviderErrs:      []string{"ipapi.is: timeout after retry"},
		}},
		Summary: engine.BatchSummary{Total: 1, Processed: 1, Reachable: 1, Abusive: 1},
		Source:  "risky.txt",
	}
	m := NewBatchModel(snap, Options{NoColor: true, Width: 100, Height: 24})
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	assertTUIGolden(t, "view.detail.risky-provider-warning.golden", updated.(BatchModel).renderDetail())
}

func TestBatchModelActionCheckAndSpeedtestUseInjectedRunners(t *testing.T) {
	oldCheck := actionCheckEndpoint
	oldSpeed := actionSpeedtestRun
	actionCheckEndpoint = func(ctx context.Context, ep endpoint.Endpoint, opts checker.Options) checker.CheckResult {
		return checker.CheckResult{Endpoint: ep, Reachable: true, LatencyMs: 9, DNSAddrs: []string{"127.0.0.1"}, TLSVersion: "TLS1.3", HTTPStatus: 200}
	}
	actionSpeedtestRun = func(ctx context.Context, opts speedtest.Options) (speedtest.Result, error) {
		return speedtest.Result{URL: "local", Bytes: 1_000, Duration: time.Second, Mbps: 0.01}, nil
	}
	t.Cleanup(func() { actionCheckEndpoint = oldCheck; actionSpeedtestRun = oldSpeed })

	m := NewBatchModel(Snapshot{Source: "interactive"}, Options{NoColor: true})
	m.OpenAction(ActionReport)
	bm := runActionForTest(t, m, "example.com:443")
	if len(bm.Visible()) != 1 || !bm.Visible()[0].Reachable || !strings.Contains(strings.Join(bm.Visible()[0].ProviderErrs, "\n"), "tls") {
		t.Fatalf("unexpected report action state: %+v", bm.Visible())
	}

	msg := speedtestCmd()()
	updated, _ := bm.Update(msg)
	bm = updated.(BatchModel)
	if bm.snapshot.Summary.SpeedMbps != 0.01 || !strings.Contains(bm.lastNotice, "speed:") {
		t.Fatalf("unexpected speedtest action state: summary=%+v notice=%q", bm.snapshot.Summary, bm.lastNotice)
	}
}

func TestBatchModelInputModeEnterEscAndErrorMessage(t *testing.T) {
	m := NewBatchModel(Snapshot{Source: "interactive"}, Options{NoColor: true})
	m.OpenAction(ActionDedupeFiles)
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	bm := updated.(BatchModel)
	if bm.Mode() != ModeList || bm.lastNotice == "" {
		t.Fatalf("enter should leave input mode with running notice: mode=%v notice=%q", bm.Mode(), bm.lastNotice)
	}
	bm = runActionForTest(t, bm, "")
	if bm.lastErr == nil || !strings.Contains(bm.View(), "enter one or more files") {
		t.Fatalf("expected dedupe error in view, err=%v view=%s", bm.lastErr, bm.View())
	}

	bm.OpenAction(ActionImportURL)
	updated, _ = bm.Update(tea.KeyMsg{Type: tea.KeyEsc})
	bm = updated.(BatchModel)
	if bm.Mode() != ModeList || bm.currentAction != ActionNone {
		t.Fatalf("esc should cancel input, mode=%v action=%v", bm.Mode(), bm.currentAction)
	}
}

func TestBatchModelGroupedExports(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "listed.txt")
	m := NewBatchModel(sampleSnapshot(), Options{NoColor: true, ExportListedPath: path})
	if err := m.ExportVisibleByRegion(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(m.lastNotice, "region") {
		t.Fatalf("unexpected region notice: %q", m.lastNotice)
	}
	if _, err := os.Stat(filepath.Join(dir, "listed-by-region", "PureLink-export-summary.txt")); err != nil {
		t.Fatalf("missing region summary: %v", err)
	}
	if err := m.ExportVisibleByProtocol(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(m.lastNotice, "protocol") {
		t.Fatalf("unexpected protocol notice: %q", m.lastNotice)
	}
}

func TestBatchCompleteUpdatesSummary(t *testing.T) {
	m := NewBatchModel(Snapshot{Items: []engine.BatchItem{{Endpoint: endpoint.Endpoint{Host: "x", Port: 1}, Purity: "unknown"}}}, Options{NoColor: true})
	updated, _ := m.Update(BatchCompleteMsg{Summary: engine.BatchSummary{Total: 10, Processed: 10}})
	bm := updated.(BatchModel)
	if bm.snapshot.Summary.Total != 10 || !strings.Contains(bm.renderHeader(), "10/10") {
		t.Fatalf("summary not updated: %+v header=%s", bm.snapshot.Summary, bm.renderHeader())
	}
}
