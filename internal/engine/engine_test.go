package engine

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/MasuRii/PureLink/internal/checker"
	"github.com/MasuRii/PureLink/pkg/endpoint"
)

func TestParseReaderAndDedupe(t *testing.T) {
	input := "Example.COM:443\nexample.com:443\n{\"host\":\"192.0.2.1\",\"port\":8080}\n192.0.2.2,8443,label\n"
	items, err := ParseReader(strings.NewReader(input), "test")
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 4 {
		t.Fatalf("expected 4 items, got %d", len(items))
	}
	res := Dedupe(items)
	if res.UniqueCount != 3 || len(res.Collisions) != 1 {
		t.Fatalf("got %+v", res)
	}
}

func TestBatchEngineRun(t *testing.T) {
	eps := []endpoint.Endpoint{{Host: "192.0.2.1", Port: 443}, {Host: "192.0.2.2", Port: 443}}
	progressCalls := 0
	be := BatchEngine{Workers: 1, Timeout: time.Second, Filter: "reachable", Progress: func(processed, total int) {
		progressCalls++
		if total != 2 || processed < 1 || processed > 2 {
			t.Fatalf("unexpected progress %d/%d", processed, total)
		}
	}, Checker: func(ctx context.Context, ep endpoint.Endpoint, opts checker.Options) checker.CheckResult {
		return checker.CheckResult{Endpoint: ep, Reachable: true, LatencyMs: 5}
	}}
	res, err := be.Run(context.Background(), eps)
	if err != nil {
		t.Fatal(err)
	}
	if res.Summary.Total != 2 || res.Summary.Reachable != 2 || res.Summary.Clean != 2 {
		t.Fatalf("got %+v", res.Summary)
	}
	if len(res.Items) != 2 || progressCalls != 2 {
		t.Fatalf("items=%d progressCalls=%d", len(res.Items), progressCalls)
	}
}

func TestSortAndFilterBatchItems(t *testing.T) {
	items := []BatchItem{
		{Endpoint: endpoint.Endpoint{Host: "b.example", Port: 443}, Reachable: true, LatencyMs: 30, AbuseScore: 10, Purity: "clean"},
		{Endpoint: endpoint.Endpoint{Host: "a.example", Port: 8443}, Reachable: true, LatencyMs: 10, AbuseScore: 80, Purity: "vpn_detected"},
		{Endpoint: endpoint.Endpoint{Host: "c.example", Port: 80}, Reachable: false, LatencyMs: 0, AbuseScore: 0, Purity: "unknown", ProviderErrs: []string{"provider failed"}},
	}
	filtered, err := FilterItems(items, "abusive")
	if err != nil {
		t.Fatal(err)
	}
	if len(filtered) != 1 || filtered[0].Endpoint.Host != "a.example" {
		t.Fatalf("filtered=%+v", filtered)
	}
	if err := SortItems(items, "latency"); err != nil {
		t.Fatal(err)
	}
	if items[0].Endpoint.Host != "c.example" || items[1].Endpoint.Host != "a.example" {
		t.Fatalf("items sorted by latency=%+v", items)
	}
	if err := ValidateSortMode("unknown"); err == nil {
		t.Fatal("expected invalid sort error")
	}
}
