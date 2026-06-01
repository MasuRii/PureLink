package providers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/MasuRii/PureLink/pkg/abuse"
	plerrors "github.com/MasuRii/PureLink/pkg/errors"
)

const maxProviderBodyBytes int64 = 1 << 20

var (
	rateLimitRetryDelays = []time.Duration{50 * time.Millisecond, 100 * time.Millisecond, 200 * time.Millisecond}
	serverRetryDelays    = []time.Duration{50 * time.Millisecond}
	timeoutRetryDelays   = []time.Duration{50 * time.Millisecond}
)

type Option func(*clientConfig)

type clientConfig struct {
	baseURL string
	client  *http.Client
}

func WithBaseURL(baseURL string) Option {
	return func(c *clientConfig) { c.baseURL = strings.TrimRight(baseURL, "/") }
}
func WithHTTPClient(client *http.Client) Option { return func(c *clientConfig) { c.client = client } }

func apply(defaultBaseURL string, opts []Option) clientConfig {
	cfg := clientConfig{baseURL: defaultBaseURL, client: &http.Client{Timeout: 10 * time.Second}}
	for _, opt := range opts {
		opt(&cfg)
	}
	if cfg.client == nil {
		cfg.client = &http.Client{Timeout: 10 * time.Second}
	}
	return cfg
}

func requestJSON(ctx context.Context, client *http.Client, method, endpoint string, body any, out any, provider string) error {
	resp, err := doRequest(ctx, client, method, endpoint, body, provider)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	dec := json.NewDecoder(io.LimitReader(resp.Body, maxProviderBodyBytes))
	if err := dec.Decode(out); err != nil {
		return &abuse.ProviderError{Name: provider, Err: fmt.Errorf("decode json: %w", err), Status: resp.StatusCode}
	}
	return nil
}

func requestText(ctx context.Context, client *http.Client, endpoint string, provider string) (string, error) {
	resp, err := doRequest(ctx, client, http.MethodGet, endpoint, nil, provider)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	b, err := io.ReadAll(io.LimitReader(resp.Body, maxProviderBodyBytes))
	if err != nil {
		return "", &abuse.ProviderError{Name: provider, Err: fmt.Errorf("read body: %w", err), Status: resp.StatusCode}
	}
	return string(b), nil
}

func doRequest(ctx context.Context, client *http.Client, method, endpoint string, body any, provider string) (*http.Response, error) {
	var lastErr error
	attempt := 0
	for {
		resp, err := doSingleRequest(ctx, client, method, endpoint, body)
		if err == nil && resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return resp, nil
		}

		if err != nil {
			lastErr = normalizeRequestError(provider, err)
		} else {
			lastErr = normalizeStatusError(provider, resp.StatusCode)
			_ = resp.Body.Close()
		}

		delay, ok := retryDelay(lastErr, resp, attempt)
		if !ok {
			return nil, lastErr
		}
		attempt++
		if err := sleepContext(ctx, delay); err != nil {
			return nil, &abuse.ProviderError{Name: provider, Err: plerrors.ErrProviderTimeout}
		}
	}
}

func doSingleRequest(ctx context.Context, client *http.Client, method, endpoint string, body any) (*http.Response, error) {
	var reader io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reader = bytes.NewReader(buf)
	}

	req, err := http.NewRequestWithContext(ctx, method, endpoint, reader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/dns-json, application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return client.Do(req)
}

func retryDelay(err error, resp *http.Response, attempt int) (time.Duration, bool) {
	if resp != nil {
		switch {
		case resp.StatusCode == http.StatusTooManyRequests:
			if attempt < len(rateLimitRetryDelays) {
				return rateLimitRetryDelays[attempt], true
			}
		case resp.StatusCode >= 500:
			if attempt < len(serverRetryDelays) {
				return serverRetryDelays[attempt], true
			}
		}
	}
	if errors.Is(err, plerrors.ErrProviderTimeout) && attempt < len(timeoutRetryDelays) {
		return timeoutRetryDelays[attempt], true
	}
	return 0, false
}

func normalizeRequestError(provider string, err error) error {
	if isTimeout(err) {
		return &abuse.ProviderError{Name: provider, Err: plerrors.ErrProviderTimeout}
	}
	return &abuse.ProviderError{Name: provider, Err: err}
}

func normalizeStatusError(provider string, status int) error {
	if status == http.StatusTooManyRequests {
		return &abuse.ProviderError{Name: provider, Err: plerrors.ErrProviderRateLimited, Status: status}
	}
	return &abuse.ProviderError{Name: provider, Err: fmt.Errorf("http error"), Status: status}
}

func isTimeout(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func sleepContext(ctx context.Context, delay time.Duration) error {
	if delay <= 0 {
		return ctx.Err()
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func categories(isVPN, isProxy, isTor, isHosting bool) []string {
	cats := []string{}
	if isVPN {
		cats = append(cats, "vpn")
	}
	if isProxy {
		cats = append(cats, "proxy")
	}
	if isTor {
		cats = append(cats, "tor")
	}
	if isHosting {
		cats = append(cats, "hosting")
	}
	return cats
}

func Default() []abuse.Provider {
	return []abuse.Provider{
		NewBlackbox(),
		NewIPAPI(),
		NewIPLogs(),
		NewIPAPICom(),
		NewRustyIP(),
		NewIPPriv(),
		NewIPLookup(),
		NewGoogleDNS(),
		NewCloudflareDNS(),
	}
}

func ByName(names []string) []abuse.Provider {
	ctors := map[string]func() abuse.Provider{
		"blackbox":       func() abuse.Provider { return NewBlackbox() },
		"ipapi.is":       func() abuse.Provider { return NewIPAPI() },
		"iplogs":         func() abuse.Provider { return NewIPLogs() },
		"ip-api.com":     func() abuse.Provider { return NewIPAPICom() },
		"rustyip":        func() abuse.Provider { return NewRustyIP() },
		"ippriv":         func() abuse.Provider { return NewIPPriv() },
		"iplookup.it":    func() abuse.Provider { return NewIPLookup() },
		"google-dns":     func() abuse.Provider { return NewGoogleDNS() },
		"dns.google":     func() abuse.Provider { return NewGoogleDNS() },
		"cloudflare-dns": func() abuse.Provider { return NewCloudflareDNS() },
	}
	out := make([]abuse.Provider, 0, len(names))
	for _, name := range names {
		if ctor, ok := ctors[name]; ok {
			out = append(out, ctor())
		}
	}
	return out
}

func boolFromKeys(data map[string]interface{}, keys ...string) bool {
	for _, key := range keys {
		if v, ok := data[key]; ok {
			switch typed := v.(type) {
			case bool:
				if typed {
					return true
				}
			case string:
				if strings.EqualFold(typed, "true") || strings.EqualFold(typed, "yes") || typed == "1" || strings.EqualFold(typed, "y") {
					return true
				}
			case float64:
				if typed > 0 {
					return true
				}
			}
		}
	}
	return false
}

func intFromKeys(data map[string]interface{}, keys ...string) int {
	for _, key := range keys {
		if v, ok := data[key]; ok {
			switch typed := v.(type) {
			case float64:
				return int(typed)
			case int:
				return typed
			case json.Number:
				n, _ := typed.Int64()
				return int(n)
			}
		}
	}
	return 0
}

func stringFromKeys(data map[string]interface{}, keys ...string) string {
	for _, key := range keys {
		if v, ok := data[key]; ok {
			if s, ok := v.(string); ok {
				return s
			}
		}
	}
	return ""
}

func nestedMap(data map[string]interface{}, keys ...string) map[string]interface{} {
	for _, key := range keys {
		if raw, ok := data[key]; ok {
			if m, ok := raw.(map[string]interface{}); ok {
				return m
			}
		}
	}
	return nil
}
