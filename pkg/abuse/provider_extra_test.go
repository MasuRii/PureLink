package abuse

import (
	"context"
	"errors"
	"testing"
)

func TestNormalizeResultClampsAndInfersPurity(t *testing.T) {
	res := NormalizeResult("provider-x", &ProviderResult{Score: 150, Confidence: -2, IsVPN: true, Country: " US ", CountryCode: " us "})
	if res.Provider != "provider-x" || res.Score != 100 || res.Confidence != 0 || res.Country != "US" || res.CountryCode != "US" || res.Purity != "vpn_detected" {
		t.Fatalf("unexpected normalized result: %+v", res)
	}

	res = NormalizeResult("provider-y", &ProviderResult{Score: -10, Confidence: 2})
	if res.Score != 0 || res.Confidence != 1 || res.Purity != "clean" {
		t.Fatalf("unexpected clamped clean result: %+v", res)
	}

	res = NormalizeResult("nil-provider", nil)
	if res.Provider != "nil-provider" || res.Purity != "unknown" {
		t.Fatalf("unexpected nil normalization: %+v", res)
	}
}

func TestMergeDeduplicatesCategoriesAndKeepsRiskiestPurity(t *testing.T) {
	merged := Merge([]ProviderResult{
		{Provider: "a", Score: 10, Confidence: 0.3, Categories: []string{"residential", "vpn"}, Purity: "clean", CountryCode: "us"},
		{Provider: "b", Score: 65, Confidence: 0.9, Categories: []string{"vpn", "proxy"}, IsProxy: true, Purity: "vpn_likely", Country: "Germany"},
	})
	if merged.Score != 65 || merged.Confidence != 0.9 || !merged.IsProxy || merged.Purity != "vpn_likely" || merged.Country != "Germany" || merged.CountryCode != "US" {
		t.Fatalf("unexpected merged result: %+v", merged)
	}
	if len(merged.Categories) != 3 {
		t.Fatalf("expected deduped categories, got %v", merged.Categories)
	}
}

func TestReporterCheckContextRespectsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := NewReporter().CheckContext(ctx, "192.0.2.1")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

func FuzzNormalizeResult(f *testing.F) {
	f.Add(0, 0.0, false, false, false, false)
	f.Add(101, 2.0, true, false, false, false)
	f.Add(-1, -1.0, false, true, false, true)
	f.Fuzz(func(t *testing.T, score int, confidence float64, dc, vpn, proxy, tor bool) {
		res := NormalizeResult("fuzz", &ProviderResult{Score: score, Confidence: confidence, IsDatacenter: dc, IsVPN: vpn, IsProxy: proxy, IsTor: tor})
		if res.Score < 0 || res.Score > 100 {
			t.Fatalf("score outside clamp: %+v", res)
		}
		if res.Confidence < 0 || res.Confidence > 1 {
			t.Fatalf("confidence outside clamp: %+v", res)
		}
		if res.Purity == "" {
			t.Fatalf("purity should be populated: %+v", res)
		}
	})
}
