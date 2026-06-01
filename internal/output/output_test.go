package output

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"strings"
	"testing"

	"github.com/MasuRii/PureLink/internal/checker"
	"github.com/MasuRii/PureLink/internal/engine"
	"github.com/MasuRii/PureLink/pkg/abuse"
	"github.com/MasuRii/PureLink/pkg/endpoint"
)

func testBatch() engine.BatchResult {
	item := engine.BatchItem{Endpoint: endpoint.Endpoint{Host: "192.0.2.1", Port: 443}, Reachable: true, LatencyMs: 12, AbuseScore: 0, Purity: "clean"}
	return engine.BatchResult{Items: []engine.BatchItem{item}, Summary: engine.Summarize([]engine.BatchItem{item})}
}

func TestRenderBatchJSON(t *testing.T) {
	var buf bytes.Buffer
	if err := New("json", &buf).RenderBatch(testBatch()); err != nil {
		t.Fatal(err)
	}
	var got map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
}
func TestRenderBatchCSV(t *testing.T) {
	var buf bytes.Buffer
	if err := New("csv", &buf).RenderBatch(testBatch()); err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(strings.NewReader(buf.String())).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if rows[0][0] != "host" || rows[1][0] != "192.0.2.1" {
		t.Fatalf("rows=%v", rows)
	}
}
func TestRenderBatchMarkdown(t *testing.T) {
	var buf bytes.Buffer
	if err := New("md", &buf).RenderBatch(testBatch()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "| 192.0.2.1 | 443 |") {
		t.Fatalf("unexpected markdown: %s", buf.String())
	}
}
func TestRenderBatchTable(t *testing.T) {
	var buf bytes.Buffer
	if err := New("table", &buf).RenderBatch(testBatch()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "Summary") {
		t.Fatalf("unexpected table: %s", buf.String())
	}
}

func TestRenderBatchTableNoColorUsesASCIISeparator(t *testing.T) {
	var buf bytes.Buffer
	r := New("table", &buf)
	r.NoColor = true
	if err := r.RenderBatch(testBatch()); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "─") || !strings.Contains(buf.String(), "---") {
		t.Fatalf("unexpected no-color table: %s", buf.String())
	}
}

func TestRenderReportTableVerboseSections(t *testing.T) {
	var buf bytes.Buffer
	check := checker.CheckResult{Endpoint: endpoint.Endpoint{Host: "example.test", Port: 443}, Reachable: true, LatencyMs: 12, DNSAddrs: []string{"192.0.2.10"}, TLSVersion: "TLS1.3", TLSCipher: "TLS_AES_128_GCM_SHA256", HTTPStatus: 200}
	providers := []abuse.ProviderResult{{Provider: "ipapi.is", Score: 65, Confidence: 0.9, IsDatacenter: true, Purity: "suspicious"}}
	if err := New("table", &buf).RenderReport(check, providers, true); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"Endpoint", "DNS", "Reachability", "Abuse / Purity", "HTTP:    200", "TLS1.3", "ipapi.is", "datacenter=true"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in report:\n%s", want, out)
		}
	}
}

func TestRenderReportJSONNonVerboseOmitsProviderDetails(t *testing.T) {
	var buf bytes.Buffer
	check := checker.CheckResult{Endpoint: endpoint.Endpoint{Host: "example.test", Port: 443}, Reachable: true, LatencyMs: 12}
	providers := []abuse.ProviderResult{{Provider: "ipapi.is", Score: 0, Purity: "clean"}}
	if err := New("json", &buf).RenderReport(check, providers, false); err != nil {
		t.Fatal(err)
	}
	var got map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if _, ok := got["check"]; ok {
		t.Fatalf("non-verbose report included full check: %s", buf.String())
	}
	if !strings.Contains(buf.String(), "ipapi.is") {
		t.Fatalf("expected provider name summary: %s", buf.String())
	}
}
