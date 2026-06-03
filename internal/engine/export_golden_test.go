package engine

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MasuRii/PureLink/pkg/endpoint"
)

func exportGoldenItems() []BatchItem {
	return []BatchItem{
		{Endpoint: endpoint.Endpoint{Host: "192.0.2.10", Port: 443}, Protocol: "vless", Country: "United States", CountryCode: "US", Reachable: true, LatencyMs: 12, AbuseScore: 0, Purity: "clean", ProviderTotal: 2, ProviderSuccesses: 1},
		{Endpoint: endpoint.Endpoint{Host: "198.51.100.20", Port: 8080}, Protocol: "trojan", Country: "Germany", CountryCode: "DE", Reachable: false, LatencyMs: 0, AbuseScore: 65, Purity: "suspicious"},
		{Endpoint: endpoint.Endpoint{Host: "vpn.example", Port: 8443}, Protocol: "vmess", CountryCode: "SG", Reachable: true, LatencyMs: 33, AbuseScore: 72, Purity: "vpn_detected"},
	}
}

func assertEngineGolden(t *testing.T, name string, got []byte) {
	t.Helper()
	want, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read golden %s: %v", name, err)
	}
	got = []byte(strings.ReplaceAll(string(got), "\r\n", "\n"))
	want = []byte(strings.ReplaceAll(string(want), "\r\n", "\n"))
	if !bytes.Equal(got, want) {
		t.Fatalf("golden mismatch %s\n--- got ---\n%s\n--- want ---\n%s", name, got, want)
	}
}

func TestGoldenWriteExport(t *testing.T) {
	tests := []struct {
		format string
		golden string
	}{
		{"endpoints", "export.endpoints.golden"},
		{"csv", "export.csv.golden"},
		{"json", "export.json.golden"},
	}
	for _, tt := range tests {
		t.Run(tt.format, func(t *testing.T) {
			var buf bytes.Buffer
			if err := WriteExport(&buf, exportGoldenItems(), tt.format); err != nil {
				t.Fatal(err)
			}
			assertEngineGolden(t, tt.golden, buf.Bytes())
		})
	}
}

func TestGoldenWriteSplitExportSummary(t *testing.T) {
	tests := []struct {
		groupBy string
		golden  string
	}{
		{"region", "export-summary-region.golden"},
		{"protocol", "export-summary-protocol.golden"},
	}
	for _, tt := range tests {
		t.Run(tt.groupBy, func(t *testing.T) {
			dir := t.TempDir()
			result, err := WriteSplitExport(dir, exportGoldenItems(), tt.groupBy, "endpoints")
			if err != nil {
				t.Fatal(err)
			}
			if result.Count != len(exportGoldenItems()) || len(result.Files) != 3 {
				t.Fatalf("unexpected split result: %+v", result)
			}
			data, err := os.ReadFile(filepath.Join(dir, "PureLink-export-summary.txt"))
			if err != nil {
				t.Fatal(err)
			}
			assertEngineGolden(t, tt.golden, data)
		})
	}
}

func TestExportNameHelpers(t *testing.T) {
	cases := []struct {
		name string
		got  string
		want string
	}{
		{"slug spaces", slugifyExportLabel("United States"), "united-states"},
		{"slug empty", slugifyExportLabel("  "), "unknown"},
		{"slug punctuation", slugifyExportLabel("SG / Singapore!"), "sg-singapore"},
		{"slug unicode", slugifyExportLabel("日本語"), "unknown"},
		{"slug repeated separators", slugifyExportLabel("US---West___1"), "us-west-1"},
		{"slug long label", slugifyExportLabel(strings.Repeat("a", 40)), strings.Repeat("a", 40)},
		{"region csv", splitExportFileName("region", "United States", "csv"), "PureLink-region-united-states.csv"},
		{"protocol json", splitExportFileName("protocol", "vmess", "json"), "PureLink-protocol-vmess.json"},
		{"all default", splitExportFileName("", "All", "endpoints"), "PureLink-export-all.txt"},
		{"display proto", displayGroupBy("proto"), "protocol"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Fatalf("got %q, want %q", tt.got, tt.want)
			}
		})
	}
}

func TestCleanItemsFiltersOnlyExportableItems(t *testing.T) {
	items := exportGoldenItems()
	items = append(items,
		BatchItem{Endpoint: endpoint.Endpoint{Host: "no-provider", Port: 443}, Reachable: true, AbuseScore: 0, Purity: "clean", ProviderTotal: 1},
		BatchItem{Endpoint: endpoint.Endpoint{Host: "partial-warning", Port: 443}, Reachable: true, AbuseScore: 0, Purity: "clean", ProviderTotal: 2, ProviderSuccesses: 1, ProviderErrs: []string{"one timeout"}},
	)
	clean := CleanItems(items)
	if len(clean) != 2 {
		t.Fatalf("expected exactly 2 clean exportable items, got %+v", clean)
	}
	if clean[0].Endpoint.Host != "192.0.2.10" || clean[1].Endpoint.Host != "partial-warning" {
		t.Fatalf("unexpected clean items: %+v", clean)
	}
}
