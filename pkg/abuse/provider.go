package abuse

import (
	"context"
	"fmt"
	"strings"
)

type Provider interface {
	Name() string
	Check(ctx context.Context, ip string) (*ProviderResult, error)
	RateLimit() RateLimit
}

type ProviderResult struct {
	Provider     string                 `json:"provider,omitempty"`
	Score        int                    `json:"score"`
	Confidence   float64                `json:"confidence"`
	Categories   []string               `json:"categories,omitempty"`
	IsDatacenter bool                   `json:"is_datacenter"`
	IsVPN        bool                   `json:"is_vpn"`
	IsProxy      bool                   `json:"is_proxy"`
	IsTor        bool                   `json:"is_tor"`
	Purity       string                 `json:"purity,omitempty"`
	Country      string                 `json:"country,omitempty"`
	CountryCode  string                 `json:"country_code,omitempty"`
	Raw          map[string]interface{} `json:"raw,omitempty"`
}

type RateLimit struct {
	RequestsPerMinute int
	Burst             int
}

type ProviderError struct {
	Name   string
	Err    error
	Status int
}

func (e *ProviderError) Error() string {
	if e.Status > 0 {
		return fmt.Sprintf("provider %s: status %d: %v", e.Name, e.Status, e.Err)
	}
	return fmt.Sprintf("provider %s: %v", e.Name, e.Err)
}

func (e *ProviderError) Unwrap() error { return e.Err }

var KnownProviderNames = map[string]struct{}{
	"ipapi.is":       {},
	"iplogs":         {},
	"blackbox":       {},
	"ip-api.com":     {},
	"rustyip":        {},
	"ippriv":         {},
	"iplookup.it":    {},
	"google-dns":     {},
	"cloudflare-dns": {},
}

func NormalizeResult(provider string, r *ProviderResult) *ProviderResult {
	if r == nil {
		return &ProviderResult{Provider: provider, Purity: "unknown"}
	}
	r.Provider = provider
	if r.Score < 0 {
		r.Score = 0
	}
	if r.Score > 100 {
		r.Score = 100
	}
	if r.Confidence < 0 {
		r.Confidence = 0
	}
	if r.Confidence > 1 {
		r.Confidence = 1
	}
	r.Country = strings.TrimSpace(r.Country)
	r.CountryCode = strings.ToUpper(strings.TrimSpace(r.CountryCode))
	if r.Purity == "" {
		r.Purity = PurityFromSignals(r)
	}
	return r
}

func PurityFromSignals(r *ProviderResult) string {
	switch {
	case r.IsVPN || r.IsProxy || r.IsTor:
		if r.Score >= 70 {
			return "vpn_detected"
		}
		return "vpn_likely"
	case r.IsDatacenter || r.Score >= 50:
		return "suspicious"
	case r.Score == 0 && !r.IsDatacenter:
		return "clean"
	default:
		return "unknown"
	}
}

func Merge(results []ProviderResult) ProviderResult {
	merged := ProviderResult{Confidence: 0, Purity: "unknown", Raw: map[string]interface{}{}}
	if len(results) == 0 {
		return merged
	}

	seen := map[string]struct{}{}
	bestPurityRank := purityRiskRank(merged.Purity)
	for i := range results {
		r := NormalizeResult(results[i].Provider, &results[i])
		if r.Score > merged.Score {
			merged.Score = r.Score
		}
		if r.Confidence > merged.Confidence {
			merged.Confidence = r.Confidence
		}
		merged.IsDatacenter = merged.IsDatacenter || r.IsDatacenter
		merged.IsVPN = merged.IsVPN || r.IsVPN
		merged.IsProxy = merged.IsProxy || r.IsProxy
		merged.IsTor = merged.IsTor || r.IsTor
		if merged.Country == "" && r.Country != "" {
			merged.Country = r.Country
		}
		if merged.CountryCode == "" && r.CountryCode != "" {
			merged.CountryCode = r.CountryCode
		}
		for _, c := range r.Categories {
			if _, ok := seen[c]; !ok {
				merged.Categories = append(merged.Categories, c)
				seen[c] = struct{}{}
			}
		}
		if r.Purity != "" {
			if rank := purityRiskRank(r.Purity); rank > bestPurityRank {
				merged.Purity = r.Purity
				bestPurityRank = rank
			}
		}
	}
	if merged.Purity == "unknown" {
		merged.Purity = PurityFromSignals(&merged)
	}
	return merged
}

func purityRiskRank(purity string) int {
	switch purity {
	case "vpn_detected":
		return 5
	case "vpn_likely":
		return 4
	case "suspicious":
		return 3
	case "clean":
		return 1
	default:
		return 0
	}
}
