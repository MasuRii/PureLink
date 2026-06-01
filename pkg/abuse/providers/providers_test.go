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

func TestIPAPIProviderCheck(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("q") != "192.0.2.1" {
			t.Fatalf("unexpected query %s", r.URL.RawQuery)
		}
		_, _ = w.Write([]byte(`{"is_vpn":true,"is_proxy":false,"is_tor":false,"is_datacenter":true,"abuse":{"score":72}}`))
	}))
	defer srv.Close()
	res, err := NewIPAPI(WithBaseURL(srv.URL)).Check(context.Background(), "192.0.2.1")
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsVPN || !res.IsDatacenter || res.Score != 72 {
		t.Fatalf("got %+v", res)
	}
}

func TestIPLogsProviderCheck(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("unexpected method %s", r.Method)
		}
		_, _ = w.Write([]byte(`{"verdict":"vpn_likely","score":61,"confidence":0.9,"signals":{"is_vpn":true,"matched_lists":["test"]}}`))
	}))
	defer srv.Close()
	res, err := NewIPLogs(WithBaseURL(srv.URL)).Check(context.Background(), "192.0.2.1")
	if err != nil {
		t.Fatal(err)
	}
	if res.Purity != "vpn_likely" || res.Score != 61 || !res.IsVPN {
		t.Fatalf("got %+v", res)
	}
}

func TestBlackboxProviderCheck(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("Y")) }))
	defer srv.Close()
	res, err := NewBlackbox(WithBaseURL(srv.URL)).Check(context.Background(), "192.0.2.1")
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsProxy || res.Score == 0 {
		t.Fatalf("got %+v", res)
	}
}

func TestIPPrivProviderCheck(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/192.0.2.1" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"security":{"vpn":true,"proxy":false,"tor":false,"hosting":true},"score":83,"asn":"AS64500","organization":"Example ISP"}`))
	}))
	defer srv.Close()

	res, err := NewIPPriv(WithBaseURL(srv.URL)).Check(context.Background(), "192.0.2.1")
	if err != nil {
		t.Fatal(err)
	}
	if res.Provider != "ippriv" || !res.IsVPN || !res.IsDatacenter || res.Score != 83 {
		t.Fatalf("got %+v", res)
	}
}

func TestIPLookupProviderCheck(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"security":{"is_proxy":true,"is_tor":true},"risk_score":65,"country":"ZZ","asn":"AS64501","reverse_dns":"example.test"}`))
	}))
	defer srv.Close()

	res, err := NewIPLookup(WithBaseURL(srv.URL)).Check(context.Background(), "192.0.2.2")
	if err != nil {
		t.Fatal(err)
	}
	if res.Provider != "iplookup.it" || !res.IsProxy || !res.IsTor || res.Score != 65 {
		t.Fatalf("got %+v", res)
	}
}

func TestDNSProvidersCheck(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("name") != "example.com" || r.URL.Query().Get("type") != "A" {
			t.Fatalf("unexpected query %s", r.URL.RawQuery)
		}
		_, _ = w.Write([]byte(`{"Status":0,"AD":true,"Answer":[{"name":"example.com.","type":1,"TTL":300,"data":"93.184.216.34"}]}`))
	}))
	defer srv.Close()

	for _, provider := range []abuse.Provider{
		NewGoogleDNS(WithBaseURL(srv.URL)),
		NewCloudflareDNS(WithBaseURL(srv.URL)),
	} {
		res, err := provider.Check(context.Background(), "example.com")
		if err != nil {
			t.Fatal(err)
		}
		if res.Score != 0 || len(res.Categories) != 1 || res.Categories[0] != "dns" {
			t.Fatalf("got %+v", res)
		}
	}
}

func TestProviderMalformedJSONReturnsProviderError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`{"is_vpn":`)) }))
	defer srv.Close()

	_, err := NewIPAPI(WithBaseURL(srv.URL)).Check(context.Background(), "192.0.2.1")
	if err == nil {
		t.Fatal("expected error")
	}
	var providerErr *abuse.ProviderError
	if !errors.As(err, &providerErr) {
		t.Fatalf("expected provider error, got %T", err)
	}
}

func TestProviderRetriesRateLimit(t *testing.T) {
	attempts := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts == 1 {
			http.Error(w, "rate limited", http.StatusTooManyRequests)
			return
		}
		_, _ = w.Write([]byte(`{"is_vpn":false,"abuse":{"score":0}}`))
	}))
	defer srv.Close()

	res, err := NewIPAPI(WithBaseURL(srv.URL)).Check(context.Background(), "192.0.2.1")
	if err != nil {
		t.Fatal(err)
	}
	if attempts != 2 || res.Score != 0 {
		t.Fatalf("attempts=%d result=%+v", attempts, res)
	}
}

func TestProviderRetriesServerError(t *testing.T) {
	attempts := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts == 1 {
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte("Y"))
	}))
	defer srv.Close()

	res, err := NewBlackbox(WithBaseURL(srv.URL)).Check(context.Background(), "192.0.2.1")
	if err != nil {
		t.Fatal(err)
	}
	if attempts != 2 || !res.IsProxy {
		t.Fatalf("attempts=%d result=%+v", attempts, res)
	}
}

func TestProviderExhaustsRateLimitRetries(t *testing.T) {
	attempts := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		http.Error(w, "rate limited", http.StatusTooManyRequests)
	}))
	defer srv.Close()

	_, err := NewIPAPI(WithBaseURL(srv.URL)).Check(context.Background(), "192.0.2.1")
	if !errors.Is(err, plerrors.ErrProviderRateLimited) {
		t.Fatalf("expected rate limited error, got %v", err)
	}
	if attempts != 4 {
		t.Fatalf("expected 4 attempts, got %d", attempts)
	}
}

func TestProviderTimeoutNormalization(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		_, _ = w.Write([]byte(`{"is_vpn":false}`))
	}))
	defer srv.Close()

	client := &http.Client{Timeout: 5 * time.Millisecond}
	_, err := NewIPAPI(WithBaseURL(srv.URL), WithHTTPClient(client)).Check(context.Background(), "192.0.2.1")
	if !errors.Is(err, plerrors.ErrProviderTimeout) {
		t.Fatalf("expected timeout error, got %v", err)
	}
}

func TestByNameIncludesPlannedProviders(t *testing.T) {
	providers := ByName([]string{"ippriv", "iplookup.it", "google-dns", "dns.google", "cloudflare-dns"})
	if len(providers) != 5 {
		t.Fatalf("expected 5 providers, got %d", len(providers))
	}
}
