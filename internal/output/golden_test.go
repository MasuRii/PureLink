package output

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/MasuRii/PureLink/internal/checker"
	"github.com/MasuRii/PureLink/internal/engine"
	"github.com/MasuRii/PureLink/pkg/abuse"
	"github.com/MasuRii/PureLink/pkg/endpoint"
	"github.com/MasuRii/PureLink/pkg/v2rayn"
)

var (
	// Matches RFC3339 timestamps in Markdown lines like "Generated: 2026-06-02T12:34:56Z"
	timestampRegexMD = regexp.MustCompile(`Generated:\s*\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z`)
	// Matches JSON timestamp values like "generated": "2026-06-02T12:34:56.789012345Z"
	timestampRegexJSON = regexp.MustCompile(`"generated":\s*"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z"`)
)

func normalizeOutput(data []byte) []byte {
	s := string(data)
	s = timestampRegexMD.ReplaceAllString(s, "Generated: __TIMESTAMP__")
	s = timestampRegexJSON.ReplaceAllString(s, `"generated": "__TIMESTAMP__"`)
	return []byte(s)
}

func goldenPath(t *testing.T, name string) string {
	t.Helper()
	return filepath.Join("testdata", name)
}

func readGolden(t *testing.T, name string) []byte {
	t.Helper()
	path := goldenPath(t, name)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading golden file %s: %v", path, err)
	}
	return data
}

func assertGolden(t *testing.T, name string, got []byte) {
	t.Helper()
	want := readGolden(t, name)
	nGot := normalizeOutput(got)
	nWant := normalizeOutput(want)
	if !bytes.Equal(nGot, nWant) {
		t.Fatalf("golden mismatch for %s\n--- got ---\n%s\n--- want ---\n%s", name, nGot, nWant)
	}
}

// ------------------------------------------------------------------
// Shared fixtures
// ------------------------------------------------------------------

func goldenCheck() checker.CheckResult {
	return checker.CheckResult{
		Endpoint:   endpoint.Endpoint{Host: "example.com", Port: 443, Raw: "example.com:443"},
		Reachable:  true,
		LatencyMs:  42,
		DNSAddrs:   []string{"93.184.216.34"},
		TLSVersion: "TLS1.3",
		TLSCipher:  "TLS_AES_128_GCM_SHA256",
		HTTPStatus: 200,
	}
}

func goldenProviders() []abuse.ProviderResult {
	return []abuse.ProviderResult{
		{Provider: "ipapi.is", Score: 10, Confidence: 0.95, IsDatacenter: false, IsVPN: false, IsProxy: false, IsTor: false, Purity: "clean", Categories: []string{"residential"}},
	}
}

func goldenBatch() engine.BatchResult {
	return engine.BatchResult{
		Items: []engine.BatchItem{
			{Endpoint: endpoint.Endpoint{Host: "192.0.2.1", Port: 443}, Reachable: true, LatencyMs: 12, AbuseScore: 0, Purity: "clean"},
			{Endpoint: endpoint.Endpoint{Host: "192.0.2.2", Port: 80}, Reachable: false, LatencyMs: 0, AbuseScore: 75, Purity: "suspicious"},
		},
		Summary: engine.BatchSummary{Total: 2, Processed: 2, Reachable: 1, Unreachable: 1, Abusive: 0, Suspicious: 1, Clean: 1, AvgLatency: 6, Errors: 0},
	}
}

func goldenDedupe() engine.DedupeResult {
	return engine.DedupeResult{
		Unique:      []endpoint.Endpoint{{Host: "192.0.2.1", Port: 443}},
		Collisions:  map[string][]engine.CollisionSource{"example.com:443": {{File: "list1.txt", Line: 3}, {File: "list2.txt", Line: 7}}},
		UniqueCount: 1,
		TotalCount:  3,
	}
}

func goldenImport() []v2rayn.ImportedEndpoint {
	return []v2rayn.ImportedEndpoint{
		{Protocol: "vmess", Host: "192.0.2.10", Port: 443, Label: "US-East", SubGroup: "Premium", Source: "subs.json"},
		{Protocol: "vless", Host: "192.0.2.11", Port: 8443, Label: "EU-West", SubGroup: "Basic", Source: "subs.json"},
	}
}

// ------------------------------------------------------------------
// Golden tests
// ------------------------------------------------------------------

func TestGoldenRenderCheck(t *testing.T) {
	check := goldenCheck()
	providers := goldenProviders()

	tests := []struct {
		format string
		golden string
	}{
		{"json", "check.json.golden"},
		{"csv", "check.csv.golden"},
		{"table", "check.table.golden"},
		{"md", "check.md.golden"},
	}

	for _, tt := range tests {
		t.Run(tt.format, func(t *testing.T) {
			var buf bytes.Buffer
			if err := New(tt.format, &buf).RenderCheck(check, providers); err != nil {
				t.Fatal(err)
			}
			assertGolden(t, tt.golden, buf.Bytes())
		})
	}
}

func TestGoldenRenderBatch(t *testing.T) {
	batch := goldenBatch()

	tests := []struct {
		format string
		golden string
	}{
		{"json", "batch.json.golden"},
		{"csv", "batch.csv.golden"},
		{"table", "batch.table.golden"},
		{"md", "batch.md.golden"},
	}

	for _, tt := range tests {
		t.Run(tt.format, func(t *testing.T) {
			var buf bytes.Buffer
			if err := New(tt.format, &buf).RenderBatch(batch); err != nil {
				t.Fatal(err)
			}
			assertGolden(t, tt.golden, buf.Bytes())
		})
	}
}

func TestGoldenRenderDedupe(t *testing.T) {
	dedupe := goldenDedupe()

	tests := []struct {
		format string
		golden string
	}{
		{"json", "dedupe.json.golden"},
		{"csv", "dedupe.csv.golden"},
		{"table", "dedupe.table.golden"},
		{"md", "dedupe.md.golden"},
	}

	for _, tt := range tests {
		t.Run(tt.format, func(t *testing.T) {
			var buf bytes.Buffer
			if err := New(tt.format, &buf).RenderDedupe(dedupe); err != nil {
				t.Fatal(err)
			}
			assertGolden(t, tt.golden, buf.Bytes())
		})
	}
}

func TestGoldenRenderImport(t *testing.T) {
	eps := goldenImport()

	tests := []struct {
		format string
		golden string
	}{
		{"json", "import.json.golden"},
		{"csv", "import.csv.golden"},
		{"table", "import.table.golden"},
		{"md", "import.md.golden"},
	}

	for _, tt := range tests {
		t.Run(tt.format, func(t *testing.T) {
			var buf bytes.Buffer
			if err := New(tt.format, &buf).RenderImport(eps); err != nil {
				t.Fatal(err)
			}
			assertGolden(t, tt.golden, buf.Bytes())
		})
	}
}

func TestGoldenRenderReport(t *testing.T) {
	check := goldenCheck()
	providers := goldenProviders()

	tests := []struct {
		format  string
		golden  string
		verbose bool
	}{
		{"json", "report.json.golden", false},
		{"csv", "report.csv.golden", false},
		{"table", "report.table.golden", false},
		{"md", "report.md.golden", false},
	}

	for _, tt := range tests {
		t.Run(tt.format, func(t *testing.T) {
			var buf bytes.Buffer
			if err := New(tt.format, &buf).RenderReport(check, providers, tt.verbose); err != nil {
				t.Fatal(err)
			}
			assertGolden(t, tt.golden, buf.Bytes())
		})
	}
}

// ------------------------------------------------------------------
// Report verbose mode uses the same table helpers but with extra
// sections. Verify it still renders without panic; a full golden is
// omitted because the output is a superset of the non-verbose path.
// ------------------------------------------------------------------

func TestGoldenRenderReportVerboseDoesNotPanic(t *testing.T) {
	check := goldenCheck()
	providers := goldenProviders()

	for _, format := range []string{"json", "csv", "table", "md"} {
		var buf bytes.Buffer
		if err := New(format, &buf).RenderReport(check, providers, true); err != nil {
			t.Fatalf("format=%s: %v", format, err)
		}
		// Sanity assertions rather than golden files for verbose mode.
		out := buf.String()
		if out == "" {
			t.Fatalf("format=%s produced empty output", format)
		}
		if format == "json" && !strings.Contains(out, "providers") {
			t.Fatalf("format=%s verbose json should contain full providers", format)
		}
	}
}
