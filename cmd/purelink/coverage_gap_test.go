package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/MasuRii/PureLink/internal/config"
	"github.com/MasuRii/PureLink/internal/engine"
	"github.com/MasuRii/PureLink/pkg/abuse"
	"github.com/MasuRii/PureLink/pkg/endpoint"
	"github.com/MasuRii/PureLink/pkg/v2rayn"
)

func TestBatchCommandFailOnAbuseUsesFakeProvider(t *testing.T) {
	withCLIFakes(t)
	providersByName = func(names []string) []abuse.Provider {
		return []abuse.Provider{cliFakeProvider{result: abuse.ProviderResult{Score: 80, Confidence: 1, Purity: "vpn_detected"}}}
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "endpoints.txt")
	if err := os.WriteFile(path, []byte("127.0.0.1:1\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	out, _, err := execute("--format", "json", "--timeout", "1", "batch", path, "--fail-on-abuse", "--no-progress")
	if err == nil || exitCode(err) != 4 {
		t.Fatalf("expected abuse threshold exit, got err=%v code=%d output=%s", err, exitCode(err), out)
	}
	if !strings.Contains(out, "vpn_detected") || !strings.Contains(out, "\"abusive\": 1") {
		t.Fatalf("batch output did not include risky provider result: %s", out)
	}
}

func TestCheckCommandPurityRegionFailOnAbuseFlags(t *testing.T) {
	withCLIFakes(t)
	var gotNames []string
	providersByName = func(names []string) []abuse.Provider {
		gotNames = append([]string(nil), names...)
		return []abuse.Provider{cliFakeProvider{result: abuse.ProviderResult{Score: 10, Confidence: 1, Purity: "vpn_likely", Country: "Germany", CountryCode: "de"}}}
	}

	out, _, err := execute("--format", "json", "check", "192.0.2.123:443", "--purity", "--region", "--fail-on-abuse")
	if err == nil || exitCode(err) != 4 {
		t.Fatalf("expected purity risk exit, got err=%v code=%d output=%s", err, exitCode(err), out)
	}
	for _, want := range []string{"ipapi.is", "iplogs", "ip-api.com"} {
		if !containsString(gotNames, want) {
			t.Fatalf("provider names %v missing %q", gotNames, want)
		}
	}
	if !strings.Contains(out, "vpn_likely") || !strings.Contains(out, "Germany") {
		t.Fatalf("check output missing purity/region data: %s", out)
	}
}

func TestReportCommandVerboseJSONIncludesDiagnostics(t *testing.T) {
	withCLIFakes(t)
	out, _, err := execute("--format", "json", "report", "192.0.2.44:443", "--verbose")
	if err != nil {
		t.Fatal(err)
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(out), &payload); err != nil {
		t.Fatalf("invalid report json %q: %v", out, err)
	}
	if _, ok := payload["check"].(map[string]any); !ok {
		t.Fatalf("verbose report missing check object: %#v", payload)
	}
	providers, ok := payload["providers"].([]any)
	if !ok || len(providers) != 1 {
		t.Fatalf("verbose report missing provider objects: %#v", payload["providers"])
	}
	if payload["http_status"] != float64(204) {
		t.Fatalf("report did not include injected HTTP status: %#v", payload)
	}
}

func TestDedupeCommandJSON(t *testing.T) {
	dir := t.TempDir()
	first := filepath.Join(dir, "first.txt")
	second := filepath.Join(dir, "second.txt")
	if err := os.WriteFile(first, []byte("192.0.2.1:443\n198.51.100.2:80\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(second, []byte("192.0.2.1:443\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	out, _, err := execute("--format", "json", "dedupe", first, second)
	if err != nil {
		t.Fatal(err)
	}
	var result engine.DedupeResult
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("invalid dedupe json %q: %v", out, err)
	}
	if result.TotalCount != 3 || result.UniqueCount != 2 || len(result.Collisions) != 1 {
		t.Fatalf("unexpected dedupe result: %+v", result)
	}
}

func TestSpeedtestCommandTextRewritesDefaultURLForBytes(t *testing.T) {
	withCLIFakes(t)
	out, _, err := execute("speedtest", "--bytes", "42")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "Speed:") || !strings.Contains(out, "https://speed.cloudflare.com/__down?bytes=42") {
		t.Fatalf("speedtest text output missing rewritten URL: %s", out)
	}
}

func TestPureCLIHelpers(t *testing.T) {
	cfg := config.Default()
	if got, want := providerNames(true, true, true, cfg), []string{"blackbox", "ipapi.is", "iplogs", "ip-api.com"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("providerNames=%v, want %v", got, want)
	}
	if got, want := mergeProviderNames([]string{"a", "b"}, []string{"b", "c"}), []string{"a", "b", "c"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("mergeProviderNames=%v, want %v", got, want)
	}
	if providerResultsRisky(nil) {
		t.Fatal("nil provider results should not be risky")
	}
	if providerResultsRisky([]abuse.ProviderResult{{Score: 49, Purity: "clean"}}) {
		t.Fatal("clean low-score provider result should not be risky")
	}
	if !providerResultsRisky([]abuse.ProviderResult{{Score: 50, Purity: "clean"}}) || !providerResultsRisky([]abuse.ProviderResult{{Score: 1, Purity: "vpn_detected"}}) {
		t.Fatal("score or purity risk was not detected")
	}
	if batchResultRisky(engine.BatchResult{Summary: engine.BatchSummary{Abusive: 0, Suspicious: 0}}) {
		t.Fatal("clean batch summary should not be risky")
	}
	if !batchResultRisky(engine.BatchResult{Summary: engine.BatchSummary{Suspicious: 1}}) || !riskExceeded(10, "vpn_likely") || riskExceeded(10, "clean") {
		t.Fatal("batch/purity helper risk decisions are wrong")
	}

	eps := []v2rayn.ImportedEndpoint{{
		Protocol: "vless",
		Host:     "192.0.2.10",
		Port:     443,
		Label:    "id=123e4567-e89b-12d3-a456-426614174000",
		SubGroup: "token=secret-value",
		Source:   "https://example.test/subscribe?token=secret-value",
	}}
	redacted := redactImportedEndpoints(eps)
	joined := redacted[0].Label + redacted[0].SubGroup + redacted[0].Source
	if strings.Contains(joined, "secret-value") || strings.Contains(joined, "123e4567") {
		t.Fatalf("imported endpoint was not redacted: %+v", redacted[0])
	}
	if !strings.Contains(eps[0].SubGroup, "secret-value") {
		t.Fatal("redactImportedEndpoints mutated input slice")
	}
	if got := dedupeEndpointList([]endpoint.Endpoint{{Host: "b", Port: 2}, {Host: "b", Port: 2}, {Host: "a", Port: 1}}); len(got) != 2 || got[0].Host != "b" || got[1].Host != "a" {
		t.Fatalf("dedupeEndpointList kept wrong endpoints/order: %+v", got)
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
