package output

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/MasuRii/PureLink/internal/checker"
	"github.com/MasuRii/PureLink/internal/engine"
	"github.com/MasuRii/PureLink/pkg/abuse"
	"github.com/MasuRii/PureLink/pkg/v2rayn"
)

type Renderer struct {
	Format  string
	Writer  io.Writer
	NoColor bool
}

func New(format string, w io.Writer) *Renderer {
	if w == nil {
		w = io.Discard
	}
	return &Renderer{Format: format, Writer: w}
}

func (r *Renderer) RenderCheck(check checker.CheckResult, providers []abuse.ProviderResult) error {
	purity := "unknown"
	if check.Reachable {
		purity = "clean"
	}
	item := engine.BatchItem{Endpoint: check.Endpoint, Reachable: check.Reachable, LatencyMs: check.LatencyMs, Purity: purity}
	if len(providers) > 0 {
		merged := abuse.Merge(providers)
		item.AbuseScore = merged.Score
		item.Purity = merged.Purity
		item.Country = merged.Country
		item.CountryCode = merged.CountryCode
	}
	switch r.Format {
	case "json":
		return writeJSON(r.Writer, map[string]interface{}{"endpoint": check.Endpoint.String(), "reachable": check.Reachable, "latency_ms": check.LatencyMs, "check": check, "providers": providers, "abuse": item.AbuseScore, "purity": item.Purity, "country": item.Country, "country_code": item.CountryCode})
	case "csv":
		return renderBatchCSV(r.Writer, []engine.BatchItem{item})
	case "md":
		return renderBatchMD(r.Writer, []engine.BatchItem{item}, engine.Summarize([]engine.BatchItem{item}), "PureLink Check Report")
	default:
		return renderBatchTable(r.Writer, []engine.BatchItem{item}, engine.Summarize([]engine.BatchItem{item}), r.NoColor)
	}
}

func (r *Renderer) RenderBatch(result engine.BatchResult) error {
	switch r.Format {
	case "json":
		return writeJSON(r.Writer, result)
	case "csv":
		return renderBatchCSV(r.Writer, result.Items)
	case "md":
		return renderBatchMD(r.Writer, result.Items, result.Summary, "PureLink Batch Report")
	default:
		return renderBatchTable(r.Writer, result.Items, result.Summary, r.NoColor)
	}
}
func (r *Renderer) RenderDedupe(result engine.DedupeResult) error {
	switch r.Format {
	case "json":
		return writeJSON(r.Writer, result)
	case "csv":
		return renderDedupeCSV(r.Writer, result)
	case "md":
		return renderDedupeMD(r.Writer, result)
	default:
		return renderDedupeTable(r.Writer, result)
	}
}
func (r *Renderer) RenderImport(eps []v2rayn.ImportedEndpoint) error {
	switch r.Format {
	case "json":
		return writeJSON(r.Writer, eps)
	case "csv":
		return renderImportCSV(r.Writer, eps)
	case "md":
		return renderImportMD(r.Writer, eps)
	default:
		return renderImportTable(r.Writer, eps)
	}
}
func (r *Renderer) RenderReport(check checker.CheckResult, providers []abuse.ProviderResult, verbose bool) error {
	switch r.Format {
	case "json":
		return writeJSON(r.Writer, reportPayload(check, providers, verbose))
	case "csv":
		return renderReportCSV(r.Writer, check, providers)
	case "md":
		return renderReportMD(r.Writer, check, providers, verbose)
	default:
		return renderReportTable(r.Writer, check, providers, verbose, r.NoColor)
	}
}

func reportPayload(check checker.CheckResult, providers []abuse.ProviderResult, verbose bool) map[string]interface{} {
	merged := abuse.Merge(providers)
	payload := map[string]interface{}{
		"generated":    time.Now().UTC(),
		"endpoint":     check.Endpoint.String(),
		"host":         check.Endpoint.Host,
		"port":         check.Endpoint.Port,
		"reachable":    check.Reachable,
		"latency_ms":   check.LatencyMs,
		"abuse_score":  merged.Score,
		"purity":       merged.Purity,
		"country":      merged.Country,
		"country_code": merged.CountryCode,
	}
	if len(check.DNSAddrs) > 0 {
		payload["dns_addrs"] = check.DNSAddrs
	}
	if check.TLSVersion != "" || check.TLSCipher != "" {
		payload["tls"] = map[string]string{"version": check.TLSVersion, "cipher": check.TLSCipher}
	}
	if check.HTTPStatus != 0 {
		payload["http_status"] = check.HTTPStatus
	}
	if verbose {
		payload["check"] = check
		payload["providers"] = providers
	} else if len(providers) > 0 {
		payload["providers"] = providerNames(providers)
	}
	return payload
}

func renderReportCSV(w io.Writer, check checker.CheckResult, providers []abuse.ProviderResult) error {
	merged := abuse.Merge(providers)
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"host", "port", "country", "country_code", "reachable", "latency_ms", "dns_addrs", "tls_version", "http_status", "abuse_score", "purity", "providers"})
	_ = cw.Write([]string{check.Endpoint.Host, strconv.Itoa(check.Endpoint.Port), merged.Country, merged.CountryCode, strconv.FormatBool(check.Reachable), strconv.FormatInt(check.LatencyMs, 10), strings.Join(check.DNSAddrs, ";"), check.TLSVersion, strconv.Itoa(check.HTTPStatus), strconv.Itoa(merged.Score), merged.Purity, strings.Join(providerNames(providers), ";")})
	cw.Flush()
	return cw.Error()
}

func renderReportTable(w io.Writer, check checker.CheckResult, providers []abuse.ProviderResult, verbose, noColor bool) error {
	merged := abuse.Merge(providers)
	line := "────────────────────────────────────────────────────────────"
	if noColor {
		line = "------------------------------------------------------------"
	}
	fmt.Fprintf(w, "Endpoint\n%s\n", line)
	fmt.Fprintf(w, "Host:    %s\nPort:    %d\n", check.Endpoint.Host, check.Endpoint.Port)
	if len(check.DNSAddrs) > 0 {
		fmt.Fprintf(w, "IP:      %s\n", check.DNSAddrs[0])
	}

	fmt.Fprintf(w, "\nDNS\n%s\n", line)
	if len(check.DNSAddrs) == 0 {
		fmt.Fprintln(w, "A/AAAA:  —")
	} else if verbose {
		fmt.Fprintf(w, "A/AAAA:  %s\n", strings.Join(check.DNSAddrs, ", "))
	} else {
		fmt.Fprintf(w, "A/AAAA:  %s\n", check.DNSAddrs[0])
	}
	fmt.Fprintln(w, "CNAME:   —")

	fmt.Fprintf(w, "\nReachability\n%s\n", line)
	fmt.Fprintf(w, "TCP:     %t (%dms)\n", check.Reachable, check.LatencyMs)
	if check.TLSVersion == "" {
		fmt.Fprintln(w, "TLS:     —")
	} else if verbose && check.TLSCipher != "" {
		fmt.Fprintf(w, "TLS:     %s (%s)\n", check.TLSVersion, check.TLSCipher)
	} else {
		fmt.Fprintf(w, "TLS:     %s\n", check.TLSVersion)
	}
	if check.HTTPStatus == 0 {
		fmt.Fprintln(w, "HTTP:    —")
	} else {
		fmt.Fprintf(w, "HTTP:    %d\n", check.HTTPStatus)
	}
	if verbose && check.Error != "" {
		fmt.Fprintf(w, "Error:   %s\n", check.Error)
	}

	fmt.Fprintf(w, "\nAbuse / Purity\n%s\n", line)
	fmt.Fprintf(w, "Score:     %d / 100\n", merged.Score)
	fmt.Fprintf(w, "Verdict:   %s\n", displayValue(merged.Purity))
	fmt.Fprintf(w, "Region:    %s\n", displayCountry(merged.Country, merged.CountryCode))
	fmt.Fprintf(w, "Providers: %s\n", displayList(providerNames(providers)))
	if verbose {
		for _, p := range providers {
			fmt.Fprintf(w, "  %s: %s\n", displayValue(p.Provider), formatProviderSignals(p))
		}
	}
	return nil
}

func renderReportMD(w io.Writer, check checker.CheckResult, providers []abuse.ProviderResult, verbose bool) error {
	merged := abuse.Merge(providers)
	fmt.Fprintf(w, "# PureLink Diagnostic Report\n\nGenerated: %s\n\n", time.Now().UTC().Format(time.RFC3339))
	fmt.Fprintf(w, "## Endpoint\n\n- **Host**: %s\n- **Port**: %d\n", check.Endpoint.Host, check.Endpoint.Port)
	if len(check.DNSAddrs) > 0 {
		fmt.Fprintf(w, "- **IP**: %s\n", check.DNSAddrs[0])
	}
	fmt.Fprintf(w, "\n## DNS\n\n- **A/AAAA**: %s\n- **CNAME**: —\n", displayList(check.DNSAddrs))
	fmt.Fprintf(w, "\n## Reachability\n\n- **TCP**: %t (%dms)\n- **TLS**: %s\n- **HTTP**: %s\n", check.Reachable, check.LatencyMs, displayValue(check.TLSVersion), displayHTTPStatus(check.HTTPStatus))
	fmt.Fprintf(w, "\n## Abuse / Purity\n\n- **Score**: %d / 100\n- **Verdict**: %s\n- **Region**: %s\n- **Providers**: %s\n", merged.Score, displayValue(merged.Purity), displayCountry(merged.Country, merged.CountryCode), displayList(providerNames(providers)))
	if verbose && len(providers) > 0 {
		fmt.Fprint(w, "\n### Provider Signals\n\n")
		for _, p := range providers {
			fmt.Fprintf(w, "- **%s**: %s\n", displayValue(p.Provider), formatProviderSignals(p))
		}
	}
	return nil
}

func providerNames(providers []abuse.ProviderResult) []string {
	names := make([]string, 0, len(providers))
	seen := map[string]struct{}{}
	for _, p := range providers {
		name := p.Provider
		if name == "" {
			name = "unknown"
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func formatProviderSignals(p abuse.ProviderResult) string {
	parts := []string{fmt.Sprintf("score=%d", p.Score)}
	if p.Confidence > 0 {
		parts = append(parts, fmt.Sprintf("confidence=%.2f", p.Confidence))
	}
	parts = append(parts, fmt.Sprintf("datacenter=%t", p.IsDatacenter), fmt.Sprintf("vpn=%t", p.IsVPN), fmt.Sprintf("proxy=%t", p.IsProxy), fmt.Sprintf("tor=%t", p.IsTor))
	if p.Purity != "" {
		parts = append(parts, "purity="+p.Purity)
	}
	if region := displayCountry(p.Country, p.CountryCode); region != "—" {
		parts = append(parts, "region="+region)
	}
	if len(p.Categories) > 0 {
		parts = append(parts, "categories="+strings.Join(p.Categories, ","))
	}
	return strings.Join(parts, "  ")
}

func displayList(values []string) string {
	if len(values) == 0 {
		return "—"
	}
	return strings.Join(values, ", ")
}

func displayValue(value string) string {
	if value == "" {
		return "—"
	}
	return value
}

func displayText(value string) string {
	return displayValue(value)
}

func displayCountry(country, countryCode string) string {
	if country != "" {
		return country
	}
	if countryCode != "" {
		return countryCode
	}
	return "—"
}

func displayRegion(item engine.BatchItem) string {
	return displayCountry(item.Country, item.CountryCode)
}

func displayHTTPStatus(status int) string {
	if status == 0 {
		return "—"
	}
	return strconv.Itoa(status)
}

func displayAbuseScore(item engine.BatchItem) string {
	if item.AbuseScore == 0 && item.Purity == "unknown" {
		return "—"
	}
	return strconv.Itoa(item.AbuseScore)
}

func writeJSON(w io.Writer, v interface{}) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func renderBatchCSV(w io.Writer, items []engine.BatchItem) error {
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"host", "port", "protocol", "country", "country_code", "reachable", "latency_ms", "abuse_score", "purity"})
	for _, item := range items {
		_ = cw.Write([]string{item.Endpoint.Host, strconv.Itoa(item.Endpoint.Port), item.Protocol, item.Country, item.CountryCode, strconv.FormatBool(item.Reachable), strconv.FormatInt(item.LatencyMs, 10), displayAbuseScore(item), item.Purity})
	}
	cw.Flush()
	return cw.Error()
}
func renderBatchTable(w io.Writer, items []engine.BatchItem, s engine.BatchSummary, noColor bool) error {
	headers := []string{"Host", "Port", "Protocol", "Region", "Reachable", "Latency", "Abuse Score", "Purity"}
	widths := make([]int, len(headers))
	for i, header := range headers {
		widths[i] = len(header)
	}
	rows := make([][]string, 0, len(items))
	for _, item := range items {
		row := []string{item.Endpoint.Host, strconv.Itoa(item.Endpoint.Port), displayText(item.Protocol), displayRegion(item), strconv.FormatBool(item.Reachable), fmt.Sprintf("%dms", item.LatencyMs), displayAbuseScore(item), item.Purity}
		rows = append(rows, row)
		for i, cell := range row {
			if len(cell) > widths[i] {
				widths[i] = len(cell)
			}
		}
	}
	writeAlignedRow(w, headers, widths)
	lineWidth := 0
	for _, width := range widths {
		lineWidth += width
	}
	lineWidth += len(widths) - 1
	if noColor {
		fmt.Fprintln(w, strings.Repeat("-", lineWidth))
	} else {
		fmt.Fprintln(w, strings.Repeat("─", lineWidth))
	}
	for _, row := range rows {
		writeAlignedRow(w, row, widths)
	}
	fmt.Fprintf(w, "\nSummary\n  Total:       %d\n  Reachable:   %d\n  Unreachable: %d\n  Clean:       %d\n  Suspicious:  %d\n  Avg Latency: %dms\n", s.Total, s.Reachable, s.Unreachable, s.Clean, s.Suspicious, s.AvgLatency)
	if s.SpeedMbps > 0 {
		fmt.Fprintf(w, "  Speed:       %.2f Mbps\n", s.SpeedMbps)
	}
	fmt.Fprintf(w, "  Errors:      %d\n", s.Errors)
	return nil
}
func writeAlignedRow(w io.Writer, cells []string, widths []int) {
	for i, cell := range cells {
		if i > 0 {
			fmt.Fprint(w, " ")
		}
		fmt.Fprintf(w, "%-*s", widths[i], cell)
	}
	fmt.Fprintln(w)
}

func renderBatchMD(w io.Writer, items []engine.BatchItem, s engine.BatchSummary, title string) error {
	fmt.Fprintf(w, "# %s\n\nGenerated: %s\n\n| Host | Port | Protocol | Region | Reachable | Latency | Abuse Score | Purity |\n|---|---:|---|---|---|---:|---:|---|\n", title, time.Now().UTC().Format(time.RFC3339))
	for _, item := range items {
		fmt.Fprintf(w, "| %s | %d | %s | %s | %t | %dms | %s | %s |\n", item.Endpoint.Host, item.Endpoint.Port, displayText(item.Protocol), displayRegion(item), item.Reachable, item.LatencyMs, displayAbuseScore(item), item.Purity)
	}
	fmt.Fprintf(w, "\n## Summary\n\n- **Total**: %d\n- **Reachable**: %d\n- **Clean**: %d\n- **Suspicious**: %d\n", s.Total, s.Reachable, s.Clean, s.Suspicious)
	if s.SpeedMbps > 0 {
		fmt.Fprintf(w, "- **Speed**: %.2f Mbps\n", s.SpeedMbps)
	}
	return nil
}

func renderDedupeCSV(w io.Writer, r engine.DedupeResult) error {
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"endpoint", "count", "sources"})
	keys := collisionKeys(r.Collisions)
	for _, key := range keys {
		_ = cw.Write([]string{key, strconv.Itoa(len(r.Collisions[key])), formatSources(r.Collisions[key])})
	}
	cw.Flush()
	return cw.Error()
}
func renderDedupeTable(w io.Writer, r engine.DedupeResult) error {
	fmt.Fprintf(w, "Unique Endpoints: %d\nDuplicates Found: %d\n\nEndpoint            Count  Sources\n", r.UniqueCount, r.TotalCount-r.UniqueCount)
	for _, key := range collisionKeys(r.Collisions) {
		fmt.Fprintf(w, "%-19s %-6d %s\n", key, len(r.Collisions[key]), formatSources(r.Collisions[key]))
	}
	return nil
}
func renderDedupeMD(w io.Writer, r engine.DedupeResult) error {
	fmt.Fprintf(w, "# PureLink Dedupe Report\n\nUnique Count: %d\nTotal Count: %d\n\n| Endpoint | Count | Sources |\n|---|---:|---|\n", r.UniqueCount, r.TotalCount)
	for _, key := range collisionKeys(r.Collisions) {
		fmt.Fprintf(w, "| %s | %d | %s |\n", key, len(r.Collisions[key]), formatSources(r.Collisions[key]))
	}
	return nil
}

func renderImportCSV(w io.Writer, eps []v2rayn.ImportedEndpoint) error {
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"protocol", "host", "port", "label", "sub_group", "source"})
	for _, ep := range eps {
		_ = cw.Write([]string{ep.Protocol, ep.Host, strconv.Itoa(ep.Port), ep.Label, ep.SubGroup, ep.Source})
	}
	cw.Flush()
	return cw.Error()
}
func renderImportTable(w io.Writer, eps []v2rayn.ImportedEndpoint) error {
	fmt.Fprintln(w, "Protocol      Host                Port   Label")
	for _, ep := range eps {
		fmt.Fprintf(w, "%-13s %-19s %-6d %s\n", ep.Protocol, truncate(ep.Host, 19), ep.Port, ep.Label)
	}
	return nil
}
func renderImportMD(w io.Writer, eps []v2rayn.ImportedEndpoint) error {
	fmt.Fprintln(w, "# PureLink Import\n\n| Protocol | Host | Port | Label | SubGroup | Source |\n|---|---|---:|---|---|---|")
	for _, ep := range eps {
		fmt.Fprintf(w, "| %s | %s | %d | %s | %s | %s |\n", ep.Protocol, ep.Host, ep.Port, ep.Label, ep.SubGroup, ep.Source)
	}
	return nil
}

func collisionKeys(m map[string][]engine.CollisionSource) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
func formatSources(src []engine.CollisionSource) string {
	parts := make([]string, 0, len(src))
	for _, s := range src {
		parts = append(parts, fmt.Sprintf("%s#%d", s.File, s.Line))
	}
	return strings.Join(parts, ", ")
}
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 3 {
		return s[:n]
	}
	return s[:n-3] + "..."
}

// Printer keeps backward compatibility with older callers.
type Printer struct{ Format string }

func (p *Printer) PrintJSON(v interface{}) error { return writeJSON(io.Discard, v) }
func (p *Printer) PrintTable(headers []string)   {}
