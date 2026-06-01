package tui

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/MasuRii/PureLink/internal/engine"
	"github.com/MasuRii/PureLink/pkg/endpoint"
	plerrors "github.com/MasuRii/PureLink/pkg/errors"
)

func sampleSnapshot() Snapshot {
	items := []engine.BatchItem{
		{Endpoint: endpoint.Endpoint{Host: "ex1.purelink.dev", Port: 443}, Reachable: true, LatencyMs: 12, AbuseScore: 0, Purity: "clean"},
		{Endpoint: endpoint.Endpoint{Host: "198.51.100.10", Port: 8080}, Reachable: false, LatencyMs: 0, Purity: "unknown"},
		{Endpoint: endpoint.Endpoint{Host: "ex2.example.com", Port: 443}, Reachable: true, LatencyMs: 45, AbuseScore: 67, Purity: "vpn_detected"},
		{Endpoint: endpoint.Endpoint{Host: "203.0.113.5", Port: 443}, Reachable: true, LatencyMs: 89, AbuseScore: 12, Purity: "clean"},
		{Endpoint: endpoint.Endpoint{Host: "suspicious.example", Port: 443}, Reachable: true, LatencyMs: 33, AbuseScore: 55, Purity: "suspicious"},
	}
	return Snapshot{
		Items:   items,
		Summary: engine.Summarize(items),
		Source:  "endpoints.txt",
	}
}

func TestNewBatchModelInitialState(t *testing.T) {
	m := NewBatchModel(sampleSnapshot(), Options{})
	if m.Cursor() != 0 {
		t.Fatalf("cursor: want 0, got %d", m.Cursor())
	}
	if m.Mode() != ModeList {
		t.Fatalf("mode: want ModeList, got %d", m.Mode())
	}
	if got := len(m.Visible()); got != 5 {
		t.Fatalf("visible: want 5, got %d", got)
	}
	if m.SortKey() != SortAbuse {
		t.Fatalf("sort: want SortAbuse, got %v", m.SortKey())
	}
}

func TestBatchModelSortByAbuseDescending(t *testing.T) {
	m := NewBatchModel(sampleSnapshot(), Options{})
	visible := m.Visible()
	if visible[0].AbuseScore < visible[len(visible)-1].AbuseScore {
		t.Fatalf("default sort is not descending by abuse: first=%d last=%d",
			visible[0].AbuseScore, visible[len(visible)-1].AbuseScore)
	}
	if visible[0].Endpoint.Host != "ex2.example.com" {
		t.Fatalf("highest abuse should be ex2.example.com, got %s", visible[0].Endpoint.Host)
	}
}

func TestBatchModelCycleSortHost(t *testing.T) {
	m := NewBatchModel(sampleSnapshot(), Options{})
	// abuse -> latency -> host
	m.CycleSort()
	m.CycleSort()
	if m.SortKey() != SortHost {
		t.Fatalf("expected SortHost, got %v", m.SortKey())
	}
	visible := m.Visible()
	for i := 1; i < len(visible); i++ {
		if visible[i-1].Endpoint.Normalize() > visible[i].Endpoint.Normalize() {
			t.Fatalf("hosts not sorted ascending at %d (%q > %q)",
				i, visible[i-1].Endpoint.Normalize(), visible[i].Endpoint.Normalize())
		}
	}
}

func TestBatchModelCycleFilterReachable(t *testing.T) {
	m := NewBatchModel(sampleSnapshot(), Options{})
	m.CycleFilter() // -> reachable
	if m.FilterKey() != FilterReachable {
		t.Fatalf("expected FilterReachable, got %v", m.FilterKey())
	}
	for _, it := range m.Visible() {
		if !it.Reachable {
			t.Fatalf("filter did not exclude unreachable host %s", it.Endpoint.Host)
		}
	}
	if got := len(m.Visible()); got != 4 {
		t.Fatalf("reachable filter: want 4, got %d", got)
	}
}

func TestBatchModelSearchHostSubstring(t *testing.T) {
	m := NewBatchModel(sampleSnapshot(), Options{})
	m.SetSearch("ex2")
	if got := len(m.Visible()); got != 1 {
		t.Fatalf("search ex2: want 1, got %d", got)
	}
	if m.Visible()[0].Endpoint.Host != "ex2.example.com" {
		t.Fatalf("search returned wrong host: %s", m.Visible()[0].Endpoint.Host)
	}
	m.SetSearch("")
	if got := len(m.Visible()); got != 5 {
		t.Fatalf("search reset: want 5, got %d", got)
	}
}

func TestBatchModelMoveCursorClamped(t *testing.T) {
	m := NewBatchModel(sampleSnapshot(), Options{})
	m.MoveCursor(-10)
	if m.Cursor() != 0 {
		t.Fatalf("cursor floor: want 0, got %d", m.Cursor())
	}
	m.MoveCursor(99)
	if m.Cursor() != len(m.Visible())-1 {
		t.Fatalf("cursor ceiling: want %d, got %d", len(m.Visible())-1, m.Cursor())
	}
}

func TestBatchModelHandlesQuitKey(t *testing.T) {
	m := NewBatchModel(sampleSnapshot(), Options{})
	updated, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'q'}})
	bm, ok := updated.(BatchModel)
	if !ok {
		t.Fatalf("Update did not return BatchModel: %T", updated)
	}
	if !bm.Quitting() {
		t.Fatalf("expected Quitting() to be true after q")
	}
	if cmd == nil {
		t.Fatalf("expected tea.Quit command")
	}
}

func TestBatchModelEnterOpensDetail(t *testing.T) {
	m := NewBatchModel(sampleSnapshot(), Options{})
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	bm := updated.(BatchModel)
	if bm.Mode() != ModeDetail {
		t.Fatalf("expected ModeDetail, got %v", bm.Mode())
	}
	updated2, _ := bm.Update(tea.KeyMsg{Type: tea.KeyEsc})
	bm2 := updated2.(BatchModel)
	if bm2.Mode() != ModeList {
		t.Fatalf("expected ModeList after esc, got %v", bm2.Mode())
	}
}

func TestBatchModelFilterModeKeystrokes(t *testing.T) {
	m := NewBatchModel(sampleSnapshot(), Options{})
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'/'}})
	bm := updated.(BatchModel)
	if bm.Mode() != ModeFilter {
		t.Fatalf("expected ModeFilter after /, got %v", bm.Mode())
	}
	updated2, _ := bm.Update(tea.KeyMsg{Type: tea.KeyEsc})
	bm2 := updated2.(BatchModel)
	if bm2.Mode() != ModeList {
		t.Fatalf("expected ModeList after esc, got %v", bm2.Mode())
	}
	if bm2.Search() != "" {
		t.Fatalf("expected search cleared, got %q", bm2.Search())
	}
}

func TestBatchModelStreamingResultMsg(t *testing.T) {
	snap := Snapshot{Summary: engine.BatchSummary{Total: 1}}
	m := NewBatchModel(snap, Options{})
	if got := len(m.Visible()); got != 0 {
		t.Fatalf("initial visible: want 0, got %d", got)
	}
	msg := CheckResultMsg{
		Endpoint: endpoint.Endpoint{Host: "x", Port: 1},
		Item: engine.BatchItem{
			Endpoint:  endpoint.Endpoint{Host: "x", Port: 1},
			Reachable: true,
			LatencyMs: 5,
			Purity:    "clean",
		},
	}
	updated, _ := m.Update(msg)
	bm := updated.(BatchModel)
	if got := len(bm.Visible()); got != 1 {
		t.Fatalf("after stream msg: want 1, got %d", got)
	}
}

func TestBatchModelViewRendersHeaderAndHelp(t *testing.T) {
	m := NewBatchModel(sampleSnapshot(), Options{NoColor: true, Width: 120, Height: 30})
	view := m.View()
	if !strings.Contains(view, "PureLink Batch") {
		t.Fatalf("view missing title: %s", view)
	}
	if !strings.Contains(view, "endpoints.txt") {
		t.Fatalf("view missing source label")
	}
	if !strings.Contains(view, "q quit") {
		t.Fatalf("view missing help bar: %s", view)
	}
	if !strings.Contains(view, "ex2.example.com") {
		t.Fatalf("view missing top row")
	}
}

func TestBatchModelViewQuittingIsEmpty(t *testing.T) {
	m := NewBatchModel(sampleSnapshot(), Options{NoColor: true})
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'q'}})
	if v := updated.(BatchModel).View(); v != "" {
		t.Fatalf("expected empty view while quitting, got %q", v)
	}
}

func TestNoColorThemePassthrough(t *testing.T) {
	plain := NoColorTheme()
	if !plain.NoColor {
		t.Fatal("NoColorTheme().NoColor should be true")
	}
	if plain.PurityStyle("clean").Render("ok") != "ok" {
		t.Fatalf("no-color theme rendered ANSI for purity")
	}
	if plain.AbuseStyle(99).Render("99") != "99" {
		t.Fatalf("no-color theme rendered ANSI for abuse")
	}
}

func TestRunHeadlessReturnsModel(t *testing.T) {
	bm, err := Run(context.Background(), RunOptions{Snapshot: sampleSnapshot(), Headless: true, NoColor: true})
	if err != nil {
		t.Fatalf("Run headless returned error: %v", err)
	}
	if got := len(bm.Visible()); got != 5 {
		t.Fatalf("headless model visible: want 5, got %d", got)
	}
}

func TestRunReturnsErrNoTTYForFileInput(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "input")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	_, err = Run(context.Background(), RunOptions{Snapshot: sampleSnapshot(), Input: f})
	if err == nil {
		t.Fatal("expected ErrNoTTY")
	}
	if !errors.Is(err, ErrNoTTY) {
		t.Fatalf("expected ErrNoTTY, got %v", err)
	}
}

func TestRunRejectsEmptySnapshot(t *testing.T) {
	_, err := Run(context.Background(), RunOptions{Snapshot: Snapshot{}, Headless: true})
	if err == nil {
		t.Fatal("expected error for empty snapshot")
	}
	if !IsEmptySnapshot(err) {
		t.Fatalf("expected IsEmptySnapshot to match, got %v", err)
	}
	if !errors.Is(err, plerrors.ErrBatchEmpty) {
		t.Fatalf("expected plerrors.ErrBatchEmpty, got %v", err)
	}
}

func TestLogHandlerBuffersAndRespectsLevel(t *testing.T) {
	h := NewLogHandler(slog.LevelInfo)
	logger := slog.New(h)
	logger.Debug("debug message")
	logger.Info("info message")
	logger.Warn("warn message")
	if got := len(h.Records()); got != 2 {
		t.Fatalf("LogHandler: want 2 records (info+warn), got %d", got)
	}
	h.Reset()
	if got := len(h.Records()); got != 0 {
		t.Fatalf("LogHandler reset failed: %d records remain", got)
	}
}

func TestLogHandlerHandlesConcurrentWrites(t *testing.T) {
	h := NewLogHandler(slog.LevelDebug)
	logger := slog.New(h)
	const n = 50
	done := make(chan struct{})
	for i := 0; i < n; i++ {
		go func(i int) {
			logger.Info("concurrent", "i", i)
			done <- struct{}{}
		}(i)
	}
	for i := 0; i < n; i++ {
		<-done
	}
	if got := len(h.Records()); got != n {
		t.Fatalf("LogHandler concurrent: want %d records, got %d", n, got)
	}
}

func TestBatchModelSetSizePropagates(t *testing.T) {
	m := NewBatchModel(sampleSnapshot(), Options{NoColor: true, Width: 80, Height: 24})
	m.SetSize(140, 40)
	if m.detail.Width != 140 {
		t.Fatalf("detail width: want 140, got %d", m.detail.Width)
	}
	if m.detail.Height != 32 {
		t.Fatalf("detail height: want 32 (h-8), got %d", m.detail.Height)
	}
	m.SetSize(-5, -5)
	if m.width != 0 || m.height != 0 {
		t.Fatalf("negative dims should clamp to zero, got w=%d h=%d", m.width, m.height)
	}
}

func TestBatchModelSnapshotDataExposed(t *testing.T) {
	snap := sampleSnapshot()
	m := NewBatchModel(snap, Options{NoColor: true})
	got := m.SnapshotData()
	if got.Source != "endpoints.txt" {
		t.Fatalf("source: want endpoints.txt, got %q", got.Source)
	}
	if len(got.Items) != len(snap.Items) {
		t.Fatalf("items copied: want %d, got %d", len(snap.Items), len(got.Items))
	}
}

func TestBatchModelSortByPurityDescendingRisk(t *testing.T) {
	m := NewBatchModel(sampleSnapshot(), Options{NoColor: true})
	// abuse -> latency -> host -> port -> purity
	for i := 0; i < 4; i++ {
		m.CycleSort()
	}
	if m.SortKey() != SortPurity {
		t.Fatalf("expected SortPurity, got %v", m.SortKey())
	}
	vis := m.Visible()
	if len(vis) == 0 {
		t.Fatal("expected visible items")
	}
	if vis[0].Purity != "vpn_detected" {
		t.Fatalf("highest purity risk should be vpn_detected, got %q", vis[0].Purity)
	}
	if vis[len(vis)-1].Purity == "vpn_detected" {
		t.Fatalf("lowest entry should not be vpn_detected")
	}
	// Cycling once more must wrap back to SortAbuse.
	m.CycleSort()
	if m.SortKey() != SortAbuse {
		t.Fatalf("sort cycle did not wrap to SortAbuse, got %v", m.SortKey())
	}
}

func TestBatchModelFilterCycleWrapsToAll(t *testing.T) {
	m := NewBatchModel(sampleSnapshot(), Options{NoColor: true})
	for i := 0; i < 7; i++ {
		m.CycleFilter()
	}
	if m.FilterKey() != FilterAll {
		t.Fatalf("filter cycle did not wrap to FilterAll after 7 cycles, got %v", m.FilterKey())
	}
}

func TestBatchModelInitReturnsSpinnerCmd(t *testing.T) {
	m := NewBatchModel(sampleSnapshot(), Options{NoColor: true})
	if cmd := m.Init(); cmd == nil {
		t.Fatal("Init() must return a non-nil tea.Cmd to start the spinner")
	}
}

func TestBatchModelDetailBodyIncludesProviderErrors(t *testing.T) {
	snap := Snapshot{
		Items: []engine.BatchItem{{
			Endpoint:     endpoint.Endpoint{Host: "err.example", Port: 443},
			Reachable:    true,
			LatencyMs:    20,
			AbuseScore:   80,
			Purity:       "vpn_detected",
			ProviderErrs: []string{"ipapi.is: rate limited"},
		}},
		Summary: engine.BatchSummary{Total: 1, Processed: 1, Reachable: 1},
		Source:  "errs.txt",
	}
	m := NewBatchModel(snap, Options{NoColor: true, Width: 100, Height: 24})
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	bm := updated.(BatchModel)
	detail := bm.renderDetail()
	if !strings.Contains(detail, "err.example") || !strings.Contains(detail, "rate limited") {
		t.Fatalf("detail missing expected fields: %s", detail)
	}
}

func TestBatchModelEmptyVisibleRendersHint(t *testing.T) {
	snap := Snapshot{
		Items: []engine.BatchItem{{
			Endpoint:  endpoint.Endpoint{Host: "only.example", Port: 80},
			Reachable: true,
			Purity:    "clean",
		}},
		Summary: engine.BatchSummary{Total: 1, Processed: 1, Reachable: 1},
	}
	m := NewBatchModel(snap, Options{NoColor: true, Width: 100, Height: 24})
	m.SetSearch("definitely-not-a-real-host-string")
	view := m.View()
	if !strings.Contains(view, "no results match") {
		t.Fatalf("empty visible should show hint, view=%s", view)
	}
}

func TestBatchModelPadRightTruncatesLongHosts(t *testing.T) {
	long := strings.Repeat("a", 60)
	snap := Snapshot{
		Items: []engine.BatchItem{{
			Endpoint:  endpoint.Endpoint{Host: long, Port: 443},
			Reachable: true,
			Purity:    "clean",
		}},
		Summary: engine.BatchSummary{Total: 1, Processed: 1, Reachable: 1},
	}
	m := NewBatchModel(snap, Options{NoColor: true, Width: 120, Height: 24})
	view := m.View()
	if !strings.Contains(view, "…") {
		t.Fatalf("long host should be truncated with ellipsis, view=%s", view)
	}
}

func TestSortKeyAndFilterKeyStrings(t *testing.T) {
	cases := []struct {
		k    SortKey
		want string
	}{
		{SortAbuse, "abuse"},
		{SortLatency, "latency"},
		{SortHost, "host"},
		{SortPort, "port"},
		{SortPurity, "purity"},
	}
	for _, c := range cases {
		if got := c.k.String(); got != c.want {
			t.Errorf("SortKey(%d).String() = %q, want %q", c.k, got, c.want)
		}
	}

	fcases := []struct {
		k    FilterKey
		want string
	}{
		{FilterAll, "all"},
		{FilterReachable, "reachable"},
		{FilterUnreachable, "unreachable"},
		{FilterAbusive, "abusive"},
		{FilterSuspicious, "suspicious"},
		{FilterClean, "clean"},
		{FilterErrors, "errors"},
	}
	for _, c := range fcases {
		if got := c.k.String(); got != c.want {
			t.Errorf("FilterKey(%d).String() = %q, want %q", c.k, got, c.want)
		}
	}
}
