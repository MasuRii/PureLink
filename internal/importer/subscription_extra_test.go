package importer

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestFetchSubscriptionHTTPStatusSanitizesURL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
	defer srv.Close()

	_, _, err := FetchSubscription(context.Background(), srv.URL+"/sub?token=secret#frag", SubscriptionOptions{Timeout: time.Second})
	if err == nil || !strings.Contains(err.Error(), "HTTP 403") {
		t.Fatalf("expected HTTP 403, got %v", err)
	}
	if strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "frag") {
		t.Fatalf("subscription error leaked secret URL parts: %v", err)
	}
}

func TestFetchSubscriptionRejectsInvalidURLForms(t *testing.T) {
	for _, raw := range []string{"http://", "::::", "ftp://example.com/sub"} {
		t.Run(raw, func(t *testing.T) {
			_, _, err := FetchSubscription(context.Background(), raw, SubscriptionOptions{})
			if err == nil {
				t.Fatal("expected error")
			}
			if strings.HasPrefix(raw, "ftp") && !errors.Is(err, errUnsupportedSubscriptionScheme) {
				t.Fatalf("expected unsupported scheme, got %v", err)
			}
		})
	}
}

func TestImportSubscriptionURLsSkipsBlankTokensAndDeduplicates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("vless://u@192.0.2.101:443#a\nvless://u@192.0.2.101:443#b\n"))
	}))
	defer srv.Close()

	eps, err := ImportSubscriptionURLs(context.Background(), []string{" ", srv.URL}, SubscriptionOptions{Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if len(eps) != 1 || eps[0].Source != srv.URL {
		t.Fatalf("unexpected imported endpoints: %+v", eps)
	}
}

func TestSplitSubscriptionTokensSeparatesCommonDelimiters(t *testing.T) {
	got := splitSubscriptionTokens("a,b c\td\r\ne")
	want := []string{"a", "b", "c", "d", "e"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}
