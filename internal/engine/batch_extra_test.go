package engine

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/MasuRii/PureLink/internal/checker"
	"github.com/MasuRii/PureLink/pkg/abuse"
	"github.com/MasuRii/PureLink/pkg/endpoint"
	plerrors "github.com/MasuRii/PureLink/pkg/errors"
)

type staticProvider struct {
	name string
	res  *abuse.ProviderResult
	err  error
	rl   abuse.RateLimit
}

func (p staticProvider) Name() string               { return p.name }
func (p staticProvider) RateLimit() abuse.RateLimit { return p.rl }
func (p staticProvider) Check(ctx context.Context, ip string) (*abuse.ProviderResult, error) {
	return p.res, p.err
}

func TestBatchEngineProviderErrorsAndFilters(t *testing.T) {
	be := BatchEngine{
		Workers: 1,
		Timeout: time.Second,
		Abuse:   true,
		Providers: []abuse.Provider{
			staticProvider{name: "bad-json", err: &abuse.ProviderError{Name: "bad-json", Err: errors.New("decode json: bad"), Status: 200}},
			staticProvider{name: "ok", res: &abuse.ProviderResult{Score: 20, Confidence: 1, Purity: "clean"}},
		},
		Filter: "errors",
		Checker: func(ctx context.Context, ep endpoint.Endpoint, opts checker.Options) checker.CheckResult {
			return checker.CheckResult{Endpoint: ep, Reachable: true, LatencyMs: 1}
		},
	}
	res, err := be.Run(context.Background(), []endpoint.Endpoint{{Host: "192.0.2.1", Port: 443}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Items) != 1 || res.Items[0].ProviderSuccesses != 1 || !strings.Contains(strings.Join(res.Items[0].ProviderErrs, "\n"), "unsupported response format") {
		t.Fatalf("unexpected provider error item: %+v", res.Items)
	}
}

func TestBatchEngineValidationAndEmptyInputs(t *testing.T) {
	if _, err := (&BatchEngine{}).Run(context.Background(), nil); !errors.Is(err, plerrors.ErrBatchEmpty) {
		t.Fatalf("expected ErrBatchEmpty, got %v", err)
	}
	if _, err := (&BatchEngine{SortBy: "bad"}).Run(context.Background(), []endpoint.Endpoint{{Host: "x", Port: 1}}); !errors.Is(err, plerrors.ErrInvalidConfig) {
		t.Fatalf("expected invalid sort config, got %v", err)
	}
	if _, err := (&BatchEngine{Filter: "bad"}).Run(context.Background(), []endpoint.Endpoint{{Host: "x", Port: 1}}); !errors.Is(err, plerrors.ErrInvalidConfig) {
		t.Fatalf("expected invalid filter config, got %v", err)
	}
}

func TestProviderErrorMessageVariants(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want string
	}{
		{"timeout", plerrors.ErrProviderTimeout, "provider: timeout"},
		{"rate", &abuse.ProviderError{Name: "p", Err: plerrors.ErrProviderRateLimited, Status: 429}, "p: rate limited"},
		{"http", &abuse.ProviderError{Name: "p", Err: errors.New("http error"), Status: 500}, "p: HTTP 500 (unexpected provider response)"},
		{"decode", &abuse.ProviderError{Name: "p", Err: errors.New("decode json: bad"), Status: 200}, "p: unsupported response format"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := providerErrorMessage("", tc.err); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
	if got := providerRetryErrorMessage("p", plerrors.ErrProviderRateLimited); got != "p: rate limited after retry" {
		t.Fatalf("retry rate message=%q", got)
	}
}

func TestParseReaderInvalidAndEmptyInputs(t *testing.T) {
	if _, err := ParseReader(strings.NewReader("# comments only\n\n"), "empty.txt"); !errors.Is(err, plerrors.ErrBatchEmpty) {
		t.Fatalf("expected empty error, got %v", err)
	}
	_, err := ParseReader(strings.NewReader("example.com:bad\n"), "bad.txt")
	if err == nil || !strings.Contains(err.Error(), "bad.txt:1") {
		t.Fatalf("expected source line in parse error, got %v", err)
	}
}
