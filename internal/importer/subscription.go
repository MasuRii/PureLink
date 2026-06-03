package importer

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/MasuRii/PureLink/pkg/v2rayn"
)

const (
	DefaultSubscriptionTimeout  = 15 * time.Second
	DefaultSubscriptionMaxBytes = 5 * 1024 * 1024
)

var errUnsupportedSubscriptionScheme = errors.New("subscription import supports only http(s) URLs")

// SubscriptionOptions controls remote subscription fetching. The defaults are
// intentionally conservative because subscription URLs can contain secrets.
type SubscriptionOptions struct {
	Timeout  time.Duration
	MaxBytes int64
	Client   *http.Client
}

// ImportSubscriptionURLs fetches one or more HTTP(S) subscription URLs and
// parses v2rayN/base64/plain share-link content from the response bodies.
func ImportSubscriptionURLs(ctx context.Context, urls []string, opts SubscriptionOptions) ([]v2rayn.ImportedEndpoint, error) {
	var out []v2rayn.ImportedEndpoint
	for _, raw := range urls {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		content, source, err := FetchSubscription(ctx, raw, opts)
		if err != nil {
			return nil, err
		}
		for _, ep := range v2rayn.ParseContent(content) {
			ep.Source = source
			out = append(out, ep)
		}
	}
	return DeduplicateImported(out), nil
}

// ImportPastedSubscriptions accepts text pasted into the TUI. HTTP(S) tokens
// are fetched; non-HTTP content is parsed locally as raw share links or a
// pasted base64/plain subscription body.
func ImportPastedSubscriptions(ctx context.Context, text string, opts SubscriptionOptions) ([]v2rayn.ImportedEndpoint, error) {
	var fetched []v2rayn.ImportedEndpoint
	var rawParts []string
	for _, token := range splitSubscriptionTokens(text) {
		u, err := url.Parse(token)
		if err == nil && (strings.EqualFold(u.Scheme, "http") || strings.EqualFold(u.Scheme, "https")) && u.Host != "" {
			eps, err := ImportSubscriptionURLs(ctx, []string{token}, opts)
			if err != nil {
				return nil, err
			}
			fetched = append(fetched, eps...)
			continue
		}
		rawParts = append(rawParts, token)
	}
	if len(rawParts) > 0 {
		for _, ep := range v2rayn.ParseContent(strings.Join(rawParts, "\n")) {
			ep.Source = "pasted"
			fetched = append(fetched, ep)
		}
	}
	return DeduplicateImported(fetched), nil
}

// FetchSubscription downloads a single HTTP(S) URL with timeout and response
// body limits. Returned errors use a sanitized URL without query/fragment data.
func FetchSubscription(ctx context.Context, rawURL string, opts SubscriptionOptions) (string, string, error) {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return "", "", fmt.Errorf("invalid subscription URL")
	}
	if !strings.EqualFold(u.Scheme, "http") && !strings.EqualFold(u.Scheme, "https") {
		return "", "", errUnsupportedSubscriptionScheme
	}
	if u.Host == "" {
		return "", "", fmt.Errorf("invalid subscription URL")
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DefaultSubscriptionTimeout
	}
	maxBytes := opts.MaxBytes
	if maxBytes <= 0 {
		maxBytes = DefaultSubscriptionMaxBytes
	}
	source := sanitizeURL(u)
	client := opts.Client
	if client == nil {
		client = &http.Client{Timeout: timeout}
	}
	if ctx == nil {
		ctx = context.Background()
	}
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, u.String(), nil)
	if err != nil {
		return "", "", fmt.Errorf("invalid subscription URL")
	}
	req.Header.Set("User-Agent", "PureLink/1 subscription-import")
	resp, err := client.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("fetch subscription %s: %w", source, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", "", fmt.Errorf("fetch subscription %s: HTTP %d", source, resp.StatusCode)
	}
	limited := io.LimitReader(resp.Body, maxBytes+1)
	b, err := io.ReadAll(limited)
	if err != nil {
		return "", "", fmt.Errorf("read subscription %s: %w", source, err)
	}
	if int64(len(b)) > maxBytes {
		return "", "", fmt.Errorf("subscription %s exceeds %d byte limit", source, maxBytes)
	}
	return string(b), source, nil
}

func splitSubscriptionTokens(text string) []string {
	return strings.FieldsFunc(text, func(r rune) bool {
		return r == '\n' || r == '\r' || r == '\t' || r == ' ' || r == ','
	})
}

func sanitizeURL(u *url.URL) string {
	safe := *u
	safe.User = nil
	safe.RawQuery = ""
	safe.Fragment = ""
	return safe.String()
}
