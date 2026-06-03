package tui

import (
	"context"
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/MasuRii/PureLink/internal/checker"
	"github.com/MasuRii/PureLink/internal/engine"
	"github.com/MasuRii/PureLink/internal/importer"
	"github.com/MasuRii/PureLink/internal/speedtest"
	"github.com/MasuRii/PureLink/pkg/endpoint"
	"github.com/MasuRii/PureLink/pkg/v2rayn"
)

const defaultActionTimeout = 10 * time.Second

var (
	actionCheckEndpoint = checker.CheckEndpoint
	actionSpeedtestRun  = speedtest.Run
)

func (m *BatchModel) OpenAction(kind ActionKind) {
	m.currentAction = kind
	m.mode = ModeInput
	m.actionInput.SetValue("")
	m.actionInput.Prompt = "> "
	m.actionInput.Placeholder = actionPlaceholder(kind)
	m.actionInput.Focus()
	m.lastErr = nil
	m.lastNotice = ""
}

func (m *BatchModel) OpenActionMenu() {
	m.mode = ModeActionMenu
	m.lastErr = nil
}

func (m *BatchModel) DeduplicateCurrent() {
	seen := map[string]struct{}{}
	items := make([]engine.BatchItem, 0, len(m.snapshot.Items))
	for _, item := range m.snapshot.Items {
		key := item.Endpoint.Normalize()
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		items = append(items, item)
	}
	removed := len(m.snapshot.Items) - len(items)
	m.snapshot.Items = items
	m.snapshot.Summary = engine.Summarize(items)
	m.lastErr = nil
	m.lastNotice = fmt.Sprintf("deduped current list: removed %d duplicate endpoints", removed)
	m.recompute()
}

func (m BatchModel) runActionCmd(value string) tea.Cmd {
	kind := m.currentAction
	value = strings.TrimSpace(value)
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), actionTimeout(kind))
		stream := make(chan tea.Msg, 64)
		go streamAction(ctx, cancel, stream, kind, value)
		return ActionStartedMsg{Stream: stream, Cancel: cancel, Source: actionSource(kind, value), Notice: "running " + strings.ToLower(actionTitle(kind)) + "..."}
	}
}

func streamAction(ctx context.Context, cancel context.CancelFunc, stream chan<- tea.Msg, kind ActionKind, value string) {
	defer close(stream)
	defer cancel()
	send := func(msg tea.Msg) bool { return sendActionMsg(ctx, stream, msg) }
	switch kind {
	case ActionImportURL:
		eps, err := importer.ImportPastedSubscriptions(ctx, value, importer.SubscriptionOptions{Timeout: importer.DefaultSubscriptionTimeout})
		if err != nil {
			send(ErrorMsg{Err: err})
			return
		}
		streamImported(ctx, stream, eps)
		send(BatchCompleteMsg{Summary: engine.BatchSummary{Total: len(eps), Processed: len(eps)}, Source: "tui import", Notice: fmt.Sprintf("imported %d endpoints from pasted URLs/content", len(eps))})
	case ActionBatchFile:
		parsed, err := engine.ParseFile(value)
		if err != nil {
			send(ErrorMsg{Err: err})
			return
		}
		endpoints := make([]endpoint.Endpoint, 0, len(parsed))
		for _, p := range parsed {
			endpoints = append(endpoints, p.Endpoint)
		}
		be := engine.BatchEngine{Workers: 8, Timeout: defaultActionTimeout, ResultProgress: func(item engine.BatchItem, processed, total int) {
			send(CheckResultMsg{Endpoint: item.Endpoint, Item: item, Processed: processed, Total: total})
		}}
		result, err := be.Run(ctx, endpoints)
		if err != nil {
			send(ErrorMsg{Err: err})
			return
		}
		send(BatchCompleteMsg{Summary: result.Summary, Source: value, Notice: fmt.Sprintf("checked %d endpoints from %s", len(result.Items), value)})
	case ActionLinkFile:
		eps, err := importer.ImportLinkFile(value)
		if err != nil {
			send(ErrorMsg{Err: err})
			return
		}
		streamImported(ctx, stream, eps)
		send(BatchCompleteMsg{Summary: engine.BatchSummary{Total: len(eps), Processed: len(eps)}, Source: value, Notice: fmt.Sprintf("imported %d endpoints from link file", len(eps))})
	case ActionV2RayN:
		eps, err := importer.ImportV2rayN(value)
		if err != nil {
			send(ErrorMsg{Err: err})
			return
		}
		streamImported(ctx, stream, eps)
		send(BatchCompleteMsg{Summary: engine.BatchSummary{Total: len(eps), Processed: len(eps)}, Source: value, Notice: fmt.Sprintf("imported %d endpoints from v2rayN", len(eps))})
	case ActionCheck, ActionReport:
		ep, err := endpoint.Parse(value)
		if err != nil {
			send(ErrorMsg{Err: err})
			return
		}
		opts := checker.Options{Timeout: defaultActionTimeout}
		label := "checked"
		if kind == ActionReport {
			opts = checker.Options{DNS: true, HTTP: true, TLS: true, Timeout: defaultActionTimeout}
			label = "reported"
		}
		res := actionCheckEndpoint(ctx, *ep, opts)
		item := batchItemFromCheck(res)
		if !send(CheckResultMsg{Endpoint: item.Endpoint, Item: item, Processed: 1, Total: 1}) {
			return
		}
		send(BatchCompleteMsg{Summary: engine.Summarize([]engine.BatchItem{item}), Source: value, Notice: fmt.Sprintf("%s %s", label, ep.String())})
	case ActionDedupeFiles:
		files := strings.Fields(value)
		if len(files) == 0 {
			send(ErrorMsg{Err: fmt.Errorf("enter one or more files")})
			return
		}
		result, err := engine.DedupeFiles(files)
		if err != nil {
			send(ErrorMsg{Err: err})
			return
		}
		items := make([]engine.BatchItem, 0, len(result.Unique))
		for _, ep := range result.Unique {
			items = append(items, engine.BatchItem{Endpoint: ep, Purity: "unknown"})
		}
		send(ActionCompleteMsg{Snapshot: Snapshot{Items: items, Summary: engine.Summarize(items), Source: strings.Join(files, ",")}, Notice: fmt.Sprintf("deduped %d inputs to %d unique endpoints", result.TotalCount, result.UniqueCount)})
	default:
		send(ErrorMsg{Err: fmt.Errorf("unknown action")})
	}
}

func streamImported(ctx context.Context, stream chan<- tea.Msg, eps []v2rayn.ImportedEndpoint) {
	items := batchItemsFromImported(eps)
	for i, item := range items {
		if !sendActionMsg(ctx, stream, CheckResultMsg{Endpoint: item.Endpoint, Item: item, Processed: i + 1, Total: len(items)}) {
			return
		}
	}
}

func sendActionMsg(ctx context.Context, stream chan<- tea.Msg, msg tea.Msg) bool {
	select {
	case <-ctx.Done():
		return false
	case stream <- msg:
		return true
	}
}

func actionSource(kind ActionKind, value string) string {
	switch kind {
	case ActionImportURL:
		return "tui import"
	default:
		if strings.TrimSpace(value) == "" {
			return strings.ToLower(actionTitle(kind))
		}
		return value
	}
}

func speedtestCmd() tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), defaultActionTimeout)
		defer cancel()
		result, err := actionSpeedtestRun(ctx, speedtest.Options{Timeout: defaultActionTimeout})
		if err != nil {
			return ErrorMsg{Err: err}
		}
		return ActionCompleteMsg{Snapshot: Snapshot{Summary: engine.BatchSummary{SpeedMbps: result.Mbps}, Source: result.URL}, Notice: "speed: " + speedtest.Format(result)}
	}
}

func batchItemsFromImported(eps []v2rayn.ImportedEndpoint) []engine.BatchItem {
	items := make([]engine.BatchItem, 0, len(eps))
	for _, ep := range eps {
		items = append(items, engine.BatchItem{Endpoint: ep.ToEndpoint(), Protocol: ep.Protocol, RawURI: ep.RawURI, Purity: "unknown"})
	}
	return items
}

func batchItemFromCheck(res checker.CheckResult) engine.BatchItem {
	item := engine.BatchItem{Endpoint: res.Endpoint, Reachable: res.Reachable, LatencyMs: res.LatencyMs, Purity: "unknown"}
	if res.Error != "" {
		item.ProviderErrs = append(item.ProviderErrs, "check: "+res.Error)
	}
	if len(res.DNSAddrs) > 0 {
		item.ProviderErrs = append(item.ProviderErrs, "dns: "+strings.Join(res.DNSAddrs, ", "))
	}
	if res.TLSVersion != "" {
		item.ProviderErrs = append(item.ProviderErrs, "tls: "+res.TLSVersion+" "+res.TLSCipher)
	}
	if res.HTTPStatus > 0 {
		item.ProviderErrs = append(item.ProviderErrs, fmt.Sprintf("http: %d", res.HTTPStatus))
	}
	return item
}

func actionPlaceholder(kind ActionKind) string {
	switch kind {
	case ActionImportURL:
		return "paste HTTP(S) subscription URLs, raw share links, or base64/plain subscription content"
	case ActionBatchFile:
		return "path to endpoint file to batch-check"
	case ActionLinkFile:
		return "path to share-link file"
	case ActionV2RayN:
		return "path to v2rayN folder"
	case ActionCheck:
		return "endpoint to check, e.g. example.com:443"
	case ActionReport:
		return "endpoint for DNS/TLS/HTTP report"
	case ActionDedupeFiles:
		return "space-separated endpoint files to dedupe"
	default:
		return "input"
	}
}

func actionTitle(kind ActionKind) string {
	switch kind {
	case ActionImportURL:
		return "Import subscription/raw URLs"
	case ActionBatchFile:
		return "Run batch file"
	case ActionLinkFile:
		return "Import link file"
	case ActionV2RayN:
		return "Import v2rayN folder"
	case ActionCheck:
		return "Check endpoint"
	case ActionReport:
		return "Report endpoint"
	case ActionDedupeFiles:
		return "Dedupe files"
	default:
		return "Action"
	}
}

func actionTimeout(kind ActionKind) time.Duration {
	if kind == ActionImportURL {
		return importer.DefaultSubscriptionTimeout
	}
	return defaultActionTimeout
}
