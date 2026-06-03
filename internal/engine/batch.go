package engine

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/MasuRii/PureLink/internal/checker"
	"github.com/MasuRii/PureLink/pkg/abuse"
	"github.com/MasuRii/PureLink/pkg/endpoint"
	plerrors "github.com/MasuRii/PureLink/pkg/errors"
	"golang.org/x/time/rate"
)

type CheckFunc func(context.Context, endpoint.Endpoint, checker.Options) checker.CheckResult

type ProgressFunc func(processed, total int)
type ResultProgressFunc func(item BatchItem, processed, total int)

type BatchEngine struct {
	Workers        int
	Timeout        time.Duration
	Providers      []abuse.Provider
	Abuse          bool
	Checker        CheckFunc
	SortBy         string
	Filter         string
	Progress       ProgressFunc
	ResultProgress ResultProgressFunc
	RetryProgress  ProgressFunc
}

func (e *BatchEngine) Run(ctx context.Context, endpoints []endpoint.Endpoint) (*BatchResult, error) {
	if len(endpoints) == 0 {
		return nil, plerrors.ErrBatchEmpty
	}
	if err := ValidateSortMode(e.SortBy); err != nil {
		return nil, err
	}
	if err := ValidateFilterMode(e.Filter); err != nil {
		return nil, err
	}
	workers := e.Workers
	if workers <= 0 {
		workers = 8
	}
	if e.Timeout <= 0 {
		e.Timeout = 10 * time.Second
	}
	check := e.Checker
	if check == nil {
		check = checker.CheckEndpoint
	}
	limiters := map[string]*rate.Limiter{}
	for _, p := range e.Providers {
		rl := p.RateLimit()
		if rl.RequestsPerMinute <= 0 {
			rl.RequestsPerMinute = 60
		}
		if rl.Burst <= 0 {
			rl.Burst = 1
		}
		limiters[p.Name()] = rate.NewLimiter(rate.Every(time.Minute/time.Duration(rl.RequestsPerMinute)), rl.Burst)
	}

	jobs := make(chan endpoint.Endpoint)
	results := make(chan BatchItem, len(endpoints))
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ep := range jobs {
				results <- e.runOne(ctx, ep, check, limiters)
			}
		}()
	}
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect results while jobs are still being queued so progress updates
	// reflect completed checks immediately instead of after the queue fills.
	total := len(endpoints)
	items := make([]BatchItem, 0, total)
	done := make(chan struct{})
	go func() {
		processed := 0
		for item := range results {
			items = append(items, item)
			processed++
			if e.Progress != nil {
				e.Progress(processed, total)
			}
			if e.ResultProgress != nil {
				e.ResultProgress(item, processed, total)
			}
		}
		close(done)
	}()

sendLoop:
	for _, ep := range endpoints {
		select {
		case <-ctx.Done():
			break sendLoop
		case jobs <- ep:
		}
	}
	close(jobs)
	<-done
	if e.Abuse {
		e.retryProviderTimeouts(ctx, items, limiters, workers)
	}
	visible, err := FilterItems(items, e.Filter)
	if err != nil {
		return nil, err
	}
	if err := SortItems(visible, e.SortBy); err != nil {
		return nil, err
	}
	return &BatchResult{Items: visible, Summary: Summarize(items)}, nil
}

func ValidateSortMode(sortBy string) error {
	switch strings.ToLower(sortBy) {
	case "", "abuse", "latency", "host", "port":
		return nil
	default:
		return fmt.Errorf("%w: invalid sort %q", plerrors.ErrInvalidConfig, sortBy)
	}
}

func ValidateFilterMode(filter string) error {
	switch strings.ToLower(filter) {
	case "", "all", "reachable", "unreachable", "abusive", "suspicious", "clean", "errors":
		return nil
	default:
		return fmt.Errorf("%w: invalid filter %q", plerrors.ErrInvalidConfig, filter)
	}
}

func FilterItems(items []BatchItem, filter string) ([]BatchItem, error) {
	if err := ValidateFilterMode(filter); err != nil {
		return nil, err
	}
	switch strings.ToLower(filter) {
	case "", "all":
		return items, nil
	}
	out := make([]BatchItem, 0, len(items))
	for _, item := range items {
		if matchesFilter(item, filter) {
			out = append(out, item)
		}
	}
	return out, nil
}

func SortItems(items []BatchItem, sortBy string) error {
	if err := ValidateSortMode(sortBy); err != nil {
		return err
	}
	switch strings.ToLower(sortBy) {
	case "", "abuse":
		sort.SliceStable(items, func(i, j int) bool {
			if items[i].AbuseScore == items[j].AbuseScore {
				return items[i].LatencyMs < items[j].LatencyMs
			}
			return items[i].AbuseScore > items[j].AbuseScore
		})
	case "latency":
		sort.SliceStable(items, func(i, j int) bool {
			if items[i].LatencyMs == items[j].LatencyMs {
				return items[i].Endpoint.Normalize() < items[j].Endpoint.Normalize()
			}
			return items[i].LatencyMs < items[j].LatencyMs
		})
	case "host":
		sort.SliceStable(items, func(i, j int) bool { return items[i].Endpoint.Normalize() < items[j].Endpoint.Normalize() })
	case "port":
		sort.SliceStable(items, func(i, j int) bool {
			if items[i].Endpoint.Port == items[j].Endpoint.Port {
				return items[i].Endpoint.Normalize() < items[j].Endpoint.Normalize()
			}
			return items[i].Endpoint.Port < items[j].Endpoint.Port
		})
	}
	return nil
}

func matchesFilter(item BatchItem, filter string) bool {
	switch strings.ToLower(filter) {
	case "reachable":
		return item.Reachable
	case "unreachable":
		return !item.Reachable
	case "abusive":
		return item.AbuseScore >= 50
	case "suspicious":
		return item.Purity == "suspicious" || item.Purity == "vpn_likely" || item.Purity == "vpn_detected"
	case "clean":
		return item.Purity == "clean" && item.AbuseScore < 50
	case "errors":
		return len(item.ProviderErrs) > 0 || !item.Reachable
	default:
		return true
	}
}

func (e *BatchEngine) runOne(ctx context.Context, ep endpoint.Endpoint, check CheckFunc, limiters map[string]*rate.Limiter) BatchItem {
	itemCtx, cancel := context.WithTimeout(ctx, e.Timeout)
	defer cancel()
	cr := check(itemCtx, ep, checker.Options{Timeout: e.Timeout})
	item := BatchItem{Endpoint: ep, Reachable: cr.Reachable, LatencyMs: cr.LatencyMs, Purity: "unknown"}
	if !e.Abuse {
		if item.Reachable {
			item.Purity = "clean"
		}
		return item
	}
	ip := ep.Host
	if net.ParseIP(ip) == nil {
		if addrs, err := net.DefaultResolver.LookupHost(itemCtx, ep.Host); err == nil && len(addrs) > 0 {
			ip = addrs[0]
		} else {
			item.ProviderErrs = append(item.ProviderErrs, "dns resolution failed")
			return item
		}
	}
	item.ProviderResolvedAddress = ip
	providerResults := []abuse.ProviderResult{}
	item.ProviderTotal = len(e.Providers)
	for _, p := range e.Providers {
		if lim := limiters[p.Name()]; lim != nil {
			if err := lim.Wait(itemCtx); err != nil {
				item.PendingProviderRetries = append(item.PendingProviderRetries, p.Name())
				continue
			}
		}
		res, err := p.Check(itemCtx, ip)
		if err != nil {
			if isRetryableProviderError(err) {
				item.PendingProviderRetries = append(item.PendingProviderRetries, p.Name())
			} else {
				item.ProviderErrs = append(item.ProviderErrs, providerErrorMessage(p.Name(), err))
			}
			continue
		}
		providerResults = append(providerResults, *abuse.NormalizeResult(p.Name(), res))
	}
	item.ProviderResults = providerResults
	item.ProviderSuccesses = len(providerResults)
	applyMergedProviderResults(&item)
	return item
}

const (
	providerRetryAttempts = 1
	providerRetryBackoff  = 750 * time.Millisecond
)

type providerRetryJob struct {
	ItemIndex int
	Provider  abuse.Provider
	IP        string
}

type providerRetryResult struct {
	ItemIndex int
	Provider  string
	Result    abuse.ProviderResult
	Err       error
}

func (e *BatchEngine) retryProviderTimeouts(ctx context.Context, items []BatchItem, limiters map[string]*rate.Limiter, workers int) {
	providerByName := map[string]abuse.Provider{}
	for _, provider := range e.Providers {
		providerByName[provider.Name()] = provider
	}

	jobs := make([]providerRetryJob, 0)
	for i := range items {
		if len(items[i].PendingProviderRetries) == 0 {
			continue
		}
		ip := items[i].ProviderResolvedAddress
		if ip == "" {
			ip = items[i].Endpoint.Host
		}
		for _, name := range uniqueProviderNames(items[i].PendingProviderRetries) {
			provider, ok := providerByName[name]
			if !ok {
				items[i].ProviderErrs = append(items[i].ProviderErrs, name+": retry skipped (provider unavailable)")
				continue
			}
			jobs = append(jobs, providerRetryJob{ItemIndex: i, Provider: provider, IP: ip})
		}
		items[i].PendingProviderRetries = nil
	}
	if len(jobs) == 0 {
		return
	}
	if e.RetryProgress != nil {
		e.RetryProgress(0, len(jobs))
	}

	retryWorkers := workers / 4
	if retryWorkers < 1 {
		retryWorkers = 1
	}
	if retryWorkers > 4 {
		retryWorkers = 4
	}

	jobCh := make(chan providerRetryJob)
	resultCh := make(chan providerRetryResult, len(jobs))
	var wg sync.WaitGroup
	for i := 0; i < retryWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobCh {
				resultCh <- e.runProviderRetry(ctx, job, limiters[job.Provider.Name()])
			}
		}()
	}
	go func() {
	sendRetries:
		for _, job := range jobs {
			select {
			case <-ctx.Done():
				break sendRetries
			case jobCh <- job:
			}
		}
		close(jobCh)
		wg.Wait()
		close(resultCh)
	}()

	processed := 0
	for result := range resultCh {
		processed++
		item := &items[result.ItemIndex]
		if result.Err != nil {
			item.ProviderErrs = append(item.ProviderErrs, providerRetryErrorMessage(result.Provider, result.Err))
		} else {
			item.ProviderResults = append(item.ProviderResults, result.Result)
		}
		item.ProviderSuccesses = len(item.ProviderResults)
		applyMergedProviderResults(item)
		if e.RetryProgress != nil {
			e.RetryProgress(processed, len(jobs))
		}
	}
}

func (e *BatchEngine) runProviderRetry(ctx context.Context, job providerRetryJob, limiter *rate.Limiter) providerRetryResult {
	var lastErr error
	for attempt := 0; attempt < providerRetryAttempts; attempt++ {
		if err := sleepContext(ctx, providerRetryBackoff*time.Duration(attempt+1)); err != nil {
			return providerRetryResult{ItemIndex: job.ItemIndex, Provider: job.Provider.Name(), Err: err}
		}
		if limiter != nil {
			if err := limiter.Wait(ctx); err != nil {
				return providerRetryResult{ItemIndex: job.ItemIndex, Provider: job.Provider.Name(), Err: err}
			}
		}
		retryCtx, cancel := context.WithTimeout(ctx, e.Timeout)
		res, err := job.Provider.Check(retryCtx, job.IP)
		cancel()
		if err == nil {
			return providerRetryResult{ItemIndex: job.ItemIndex, Provider: job.Provider.Name(), Result: *abuse.NormalizeResult(job.Provider.Name(), res)}
		}
		lastErr = err
		if !isRetryableProviderError(err) {
			break
		}
	}
	return providerRetryResult{ItemIndex: job.ItemIndex, Provider: job.Provider.Name(), Err: lastErr}
}

func sleepContext(ctx context.Context, delay time.Duration) error {
	if delay <= 0 {
		return nil
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

func applyMergedProviderResults(item *BatchItem) {
	merged := abuse.Merge(item.ProviderResults)
	item.AbuseScore = merged.Score
	item.Purity = merged.Purity
	item.Country = merged.Country
	item.CountryCode = merged.CountryCode
}

func uniqueProviderNames(names []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(names))
	for _, name := range names {
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		out = append(out, name)
	}
	return out
}

func isRetryableProviderError(err error) bool {
	if err == nil {
		return false
	}
	var providerErr *abuse.ProviderError
	if errors.As(err, &providerErr) {
		return errors.Is(providerErr.Err, plerrors.ErrProviderTimeout) || errors.Is(providerErr.Err, plerrors.ErrProviderRateLimited) || errors.Is(providerErr.Err, context.DeadlineExceeded) || errors.Is(providerErr.Err, context.Canceled)
	}
	return errors.Is(err, plerrors.ErrProviderTimeout) || errors.Is(err, plerrors.ErrProviderRateLimited) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled)
}

func providerRetryErrorMessage(provider string, err error) string {
	if isRetryableProviderError(err) {
		if errors.Is(err, plerrors.ErrProviderRateLimited) {
			return provider + ": rate limited after retry"
		}
		return provider + ": timeout after retry"
	}
	return providerErrorMessage(provider, err)
}

func providerErrorMessage(provider string, err error) string {
	if provider == "" {
		provider = "provider"
	}

	var providerErr *abuse.ProviderError
	if errors.As(err, &providerErr) {
		if providerErr.Name != "" {
			provider = providerErr.Name
		}
		if errors.Is(providerErr.Err, plerrors.ErrProviderTimeout) || errors.Is(providerErr.Err, context.DeadlineExceeded) || errors.Is(providerErr.Err, context.Canceled) {
			return provider + ": timeout"
		}
		if errors.Is(providerErr.Err, plerrors.ErrProviderRateLimited) {
			return provider + ": rate limited"
		}
		reason := friendlyProviderReason(providerErr.Err.Error())
		if providerErr.Status > 0 && reason != "unsupported response format" {
			return fmt.Sprintf("%s: HTTP %d (%s)", provider, providerErr.Status, reason)
		}
		return provider + ": " + reason
	}

	if errors.Is(err, plerrors.ErrProviderTimeout) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return provider + ": timeout"
	}
	if errors.Is(err, plerrors.ErrProviderRateLimited) {
		return provider + ": rate limited"
	}
	return provider + ": " + friendlyProviderReason(err.Error())
}

func friendlyProviderReason(msg string) string {
	switch {
	case msg == "", msg == "http error":
		return "unexpected provider response"
	case msg == plerrors.ErrProviderTimeout.Error():
		return "timeout"
	case msg == plerrors.ErrProviderRateLimited.Error():
		return "rate limited"
	case strings.Contains(msg, "decode json"), strings.Contains(msg, "cannot unmarshal"):
		return "unsupported response format"
	default:
		return msg
	}
}
