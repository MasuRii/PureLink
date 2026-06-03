package providers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/MasuRii/PureLink/pkg/abuse"
	plerrors "github.com/MasuRii/PureLink/pkg/errors"
)

func TestProviderUtilityExtractionHelpers(t *testing.T) {
	data := map[string]interface{}{
		"boolString": "yes",
		"boolFloat":  1.0,
		"number":     42.0,
		"nested":     map[string]interface{}{"value": "ok"},
		"empty":      "",
		"country":    "  Germany  ",
	}
	if !boolFromKeys(data, "boolString") || !boolFromKeys(data, "boolFloat") || boolFromKeys(data, "missing") {
		t.Fatalf("boolFromKeys returned unexpected values")
	}
	if got := intFromKeys(data, "number"); got != 42 {
		t.Fatalf("intFromKeys=%d, want 42", got)
	}
	if got := firstNonEmpty("", "  US  "); got != "US" {
		t.Fatalf("firstNonEmpty=%q", got)
	}
	if got := nestedMap(data, "nested")["value"]; got != "ok" {
		t.Fatalf("nestedMap returned %v", got)
	}
	if got := stringFromKeys(data, "country"); got != "  Germany  " {
		t.Fatalf("stringFromKeys=%q", got)
	}
}

func TestIPLogsNormalizationHelpers(t *testing.T) {
	verdicts := map[string]string{
		"VPN Detected": "vpn_detected",
		"proxy":        "vpn_likely",
		"data-center":  "suspicious",
		"residential":  "clean",
	}
	for in, want := range verdicts {
		if got := normalizeIPLogsVerdict(in); got != want {
			t.Fatalf("normalizeIPLogsVerdict(%q)=%q, want %q", in, got, want)
		}
	}
	if got := normalizedIPLogsScore("0.42"); got != 42 {
		t.Fatalf("normalizedIPLogsScore string fraction=%d, want 42", got)
	}
	vpn, proxy, tor, dc, cats := parseIPLogsSignals([]interface{}{
		map[string]interface{}{"type": "vpn-exit", "matched_lists": []interface{}{"list-a"}},
		"tor node",
		"hosting",
		map[string]interface{}{"proxy": "true"},
	})
	if !vpn || !proxy || !tor || !dc || len(cats) < 4 {
		t.Fatalf("unexpected parsed signals vpn=%v proxy=%v tor=%v dc=%v cats=%v", vpn, proxy, tor, dc, cats)
	}
}

func TestIPAPIComAndRustyIPLocalServers(t *testing.T) {
	ipapi := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/192.0.2.55" {
			t.Fatalf("unexpected ip-api path %s", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"proxy":true,"hosting":false,"country":"United States","countryCode":"us","isp":"Example","as":"AS64500"}`))
	}))
	defer ipapi.Close()
	res, err := NewIPAPICom(WithBaseURL(ipapi.URL)).Check(context.Background(), "192.0.2.55")
	if err != nil {
		t.Fatal(err)
	}
	if res.Score != 70 || !res.IsProxy || res.CountryCode != "US" || res.Purity != "vpn_detected" {
		t.Fatalf("unexpected ip-api.com result: %+v", res)
	}

	rusty := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("ip") != "192.0.2.56" {
			t.Fatalf("unexpected rusty query %s", r.URL.RawQuery)
		}
		_, _ = w.Write([]byte(`{"hosting":true}`))
	}))
	defer rusty.Close()
	res, err = NewRustyIP(WithBaseURL(rusty.URL)).Check(context.Background(), "192.0.2.56")
	if err != nil {
		t.Fatal(err)
	}
	if res.Score != 40 || !res.IsDatacenter || res.Purity != "suspicious" {
		t.Fatalf("unexpected rustyip result: %+v", res)
	}
}

func TestProviderContextCancellationDuringRetry(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "retry", http.StatusInternalServerError)
	}))
	defer srv.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := NewBlackbox(WithBaseURL(srv.URL)).Check(ctx, "192.0.2.1")
	if !errors.Is(err, plerrors.ErrProviderTimeout) {
		t.Fatalf("expected normalized timeout, got %v", err)
	}
}

func TestProviderRequestBodyLimitKeepsDecoderBounded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"is_vpn":`))
		_, _ = w.Write(make([]byte, maxProviderBodyBytes+10))
	}))
	defer srv.Close()
	_, err := NewIPAPI(WithBaseURL(srv.URL), WithHTTPClient(&http.Client{Timeout: time.Second})).Check(context.Background(), "192.0.2.1")
	var providerErr *abuse.ProviderError
	if err == nil || !errors.As(err, &providerErr) {
		t.Fatalf("expected provider decode error, got %v", err)
	}
}
