package speedtest

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestFormatDeterministicByteTiers(t *testing.T) {
	tests := []struct {
		name string
		in   Result
		want string
	}{
		{"bytes", Result{Bytes: 999, Duration: 500 * time.Millisecond, Mbps: 1.25}, "1.25 Mbps (999 B in 0.50s)"},
		{"kilobytes", Result{Bytes: 1_500, Duration: 2 * time.Second, Mbps: 0.01}, "0.01 Mbps (1.50 KB in 2.00s)"},
		{"megabytes", Result{Bytes: 2_500_000, Duration: 1250 * time.Millisecond, Mbps: 16}, "16.00 Mbps (2.50 MB in 1.25s)"},
		{"gigabytes", Result{Bytes: 3_000_000_000, Duration: 3 * time.Second, Mbps: 8000}, "8000.00 Mbps (3.00 GB in 3.00s)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Format(tt.in); got != tt.want {
				t.Fatalf("Format() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRunDownloadsFromLocalServerAndHonorsMaxBytes(t *testing.T) {
	var sawUserAgent bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawUserAgent = strings.Contains(r.Header.Get("User-Agent"), "PureLink speedtest")
		_, _ = w.Write([]byte(strings.Repeat("x", 64)))
	}))
	defer srv.Close()

	res, err := Run(context.Background(), Options{URL: srv.URL, MaxBytes: 7, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if res.URL != srv.URL || res.Bytes != 7 || res.Duration <= 0 || res.Mbps <= 0 {
		t.Fatalf("unexpected result: %+v", res)
	}
	if !sawUserAgent {
		t.Fatal("speedtest request did not send PureLink user agent")
	}
}

func TestRunReturnsHTTPStatusError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusTeapot)
	}))
	defer srv.Close()

	_, err := Run(context.Background(), Options{URL: srv.URL, Timeout: time.Second})
	if err == nil || !strings.Contains(err.Error(), "HTTP 418") {
		t.Fatalf("expected HTTP 418 error, got %v", err)
	}
}

func TestRunRespectsCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := Run(ctx, Options{URL: "http://127.0.0.1:1", Timeout: time.Second})
	if err == nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}
