package speedtest

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"
)

const (
	DefaultURL     = "https://speed.cloudflare.com/__down?bytes=10000000"
	DefaultMaxByte = 10_000_000
)

type Options struct {
	URL      string
	MaxBytes int64
	Timeout  time.Duration
}

type Result struct {
	URL      string        `json:"url"`
	Bytes    int64         `json:"bytes"`
	Duration time.Duration `json:"duration"`
	Mbps     float64       `json:"mbps"`
}

func Run(ctx context.Context, opts Options) (Result, error) {
	if opts.URL == "" {
		opts.URL = DefaultURL
	}
	if opts.MaxBytes <= 0 {
		opts.MaxBytes = DefaultMaxByte
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 15 * time.Second
	}

	ctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, opts.URL, nil)
	if err != nil {
		return Result{}, err
	}
	req.Header.Set("User-Agent", "PureLink speedtest")

	start := time.Now()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return Result{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return Result{}, fmt.Errorf("speed test HTTP %d", resp.StatusCode)
	}

	bytesRead, err := io.Copy(io.Discard, io.LimitReader(resp.Body, opts.MaxBytes))
	if err != nil {
		return Result{}, err
	}
	duration := time.Since(start)
	if duration <= 0 {
		duration = time.Nanosecond
	}
	mbps := float64(bytesRead*8) / duration.Seconds() / 1_000_000
	return Result{URL: opts.URL, Bytes: bytesRead, Duration: duration, Mbps: mbps}, nil
}

func Format(result Result) string {
	return fmt.Sprintf("%.2f Mbps (%s in %.2fs)", result.Mbps, formatBytes(result.Bytes), result.Duration.Seconds())
}

func formatBytes(bytes int64) string {
	switch {
	case bytes >= 1_000_000_000:
		return fmt.Sprintf("%.2f GB", float64(bytes)/1_000_000_000)
	case bytes >= 1_000_000:
		return fmt.Sprintf("%.2f MB", float64(bytes)/1_000_000)
	case bytes >= 1_000:
		return fmt.Sprintf("%.2f KB", float64(bytes)/1_000)
	default:
		return fmt.Sprintf("%d B", bytes)
	}
}
