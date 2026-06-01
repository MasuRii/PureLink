package engine

import (
	"context"
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

type BatchEngine struct {
	Workers   int
	Timeout   time.Duration
	Providers []abuse.Provider
	Abuse     bool
	Checker   CheckFunc
	SortBy    string
	Filter    string
	Progress  ProgressFunc
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

	sent := 0
sendLoop:
	for _, ep := range endpoints {
		select {
		case <-ctx.Done():
			break sendLoop
		case jobs <- ep:
			sent++
		}
	}
	close(jobs)

	items := make([]BatchItem, 0, sent)
	processed := 0
	for item := range results {
		items = append(items, item)
		processed++
		if e.Progress != nil {
			e.Progress(processed, sent)
		}
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
	providerResults := []abuse.ProviderResult{}
	for _, p := range e.Providers {
		if lim := limiters[p.Name()]; lim != nil {
			if err := lim.Wait(itemCtx); err != nil {
				item.ProviderErrs = append(item.ProviderErrs, p.Name()+": timeout")
				continue
			}
		}
		res, err := p.Check(itemCtx, ip)
		if err != nil {
			item.ProviderErrs = append(item.ProviderErrs, err.Error())
			continue
		}
		providerResults = append(providerResults, *abuse.NormalizeResult(p.Name(), res))
	}
	merged := abuse.Merge(providerResults)
	item.AbuseScore = merged.Score
	item.Purity = merged.Purity
	return item
}
