package providers

import (
	"context"
	"strconv"
	"strings"

	"github.com/MasuRii/PureLink/pkg/abuse"
)

type IPLogs struct{ cfg clientConfig }

func NewIPLogs(opts ...Option) *IPLogs {
	return &IPLogs{cfg: apply("https://iplogs.com/v1/check", opts)}
}
func (p *IPLogs) Name() string               { return "iplogs" }
func (p *IPLogs) RateLimit() abuse.RateLimit { return abuse.RateLimit{RequestsPerMinute: 60, Burst: 3} }

func (p *IPLogs) Check(ctx context.Context, ip string) (*abuse.ProviderResult, error) {
	var resp map[string]interface{}
	if err := requestJSON(ctx, p.cfg.client, "POST", p.cfg.baseURL, map[string]string{"ip": ip}, &resp, p.Name()); err != nil {
		return nil, err
	}

	verdict := normalizeIPLogsVerdict(stringFromKeys(resp, "verdict", "purity", "risk_level"))
	score := normalizedIPLogsScore(resp["score"])
	confidence := floatFromKeys(resp, "confidence")
	country := stringFromKeys(resp, "country", "country_name")
	countryCode := stringFromKeys(resp, "country_code", "countryCode")

	isVPN := boolFromKeys(resp, "is_vpn", "vpn")
	isProxy := boolFromKeys(resp, "is_proxy", "proxy")
	isTor := boolFromKeys(resp, "is_tor", "tor")
	isDatacenter := boolFromKeys(resp, "is_datacenter", "datacenter", "is_hosting", "hosting")

	sigVPN, sigProxy, sigTor, sigDatacenter, sigCats := parseIPLogsSignals(resp["signals"])
	isVPN = isVPN || sigVPN
	isProxy = isProxy || sigProxy
	isTor = isTor || sigTor
	isDatacenter = isDatacenter || sigDatacenter

	cats := append([]string{}, sigCats...)
	cats = append(cats, stringListFromKeys(resp, "matched_lists", "matchedLists", "lists", "categories")...)
	cats = append(cats, categories(isVPN, isProxy, isTor, isDatacenter)...)
	cats = uniqueStrings(cats)

	if score == 0 {
		score = scoreFromIPLogsVerdict(verdict, isVPN, isProxy, isTor, isDatacenter)
	}

	return abuse.NormalizeResult(p.Name(), &abuse.ProviderResult{Score: score, Confidence: confidence, Categories: cats, IsDatacenter: isDatacenter, IsVPN: isVPN, IsProxy: isProxy, IsTor: isTor, Purity: verdict, Country: country, CountryCode: countryCode}), nil
}

func normalizeIPLogsVerdict(raw string) string {
	verdict := strings.ToLower(strings.TrimSpace(raw))
	verdict = strings.ReplaceAll(verdict, "-", "_")
	verdict = strings.ReplaceAll(verdict, " ", "_")
	switch {
	case verdict == "vpn_detected", verdict == "detected":
		return "vpn_detected"
	case verdict == "vpn_likely", verdict == "vpn", verdict == "proxy", verdict == "proxy_detected":
		return "vpn_likely"
	case verdict == "suspicious", verdict == "datacenter", verdict == "hosting", verdict == "data_center":
		return "suspicious"
	case verdict == "clean", verdict == "residential", verdict == "ok", verdict == "safe":
		return "clean"
	default:
		return verdict
	}
}

func parseIPLogsSignals(raw interface{}) (isVPN, isProxy, isTor, isDatacenter bool, categories []string) {
	applyName := func(name string) {
		cleaned := strings.ToLower(strings.TrimSpace(name))
		cleaned = strings.ReplaceAll(cleaned, "-", "_")
		cleaned = strings.ReplaceAll(cleaned, " ", "_")
		if cleaned == "" {
			return
		}
		categories = append(categories, cleaned)
		switch {
		case strings.Contains(cleaned, "vpn"):
			isVPN = true
		case strings.Contains(cleaned, "proxy"):
			isProxy = true
		case strings.Contains(cleaned, "tor"):
			isTor = true
		case strings.Contains(cleaned, "datacenter"), strings.Contains(cleaned, "hosting"), strings.Contains(cleaned, "data_center"):
			isDatacenter = true
		}
	}

	var walk func(interface{})
	walk = func(value interface{}) {
		switch typed := value.(type) {
		case map[string]interface{}:
			isVPN = isVPN || boolFromKeys(typed, "is_vpn", "vpn")
			isProxy = isProxy || boolFromKeys(typed, "is_proxy", "proxy")
			isTor = isTor || boolFromKeys(typed, "is_tor", "tor")
			isDatacenter = isDatacenter || boolFromKeys(typed, "is_datacenter", "datacenter", "is_hosting", "hosting")
			categories = append(categories, stringListFromKeys(typed, "matched_lists", "matchedLists", "lists", "categories")...)
			for _, key := range []string{"name", "type", "signal", "category", "id"} {
				if name := stringFromKeys(typed, key); name != "" {
					applyName(name)
				}
			}
		case []interface{}:
			for _, item := range typed {
				walk(item)
			}
		case []string:
			for _, item := range typed {
				applyName(item)
			}
		case string:
			applyName(typed)
		}
	}
	walk(raw)

	return isVPN, isProxy, isTor, isDatacenter, uniqueStrings(categories)
}

func normalizedIPLogsScore(raw interface{}) int {
	value, ok := numberAsFloat(raw)
	if !ok {
		return 0
	}
	if value >= 0 && value <= 1 {
		value *= 100
	}
	return int(value)
}

func scoreFromIPLogsVerdict(verdict string, isVPN, isProxy, isTor, isDatacenter bool) int {
	switch {
	case verdict == "vpn_detected", strings.Contains(verdict, "detected"), isVPN || isProxy || isTor:
		return 70
	case verdict == "vpn_likely", strings.Contains(verdict, "vpn"), strings.Contains(verdict, "proxy"):
		return 60
	case verdict == "suspicious", strings.Contains(verdict, "suspicious"), isDatacenter:
		return 50
	default:
		return 0
	}
}

func floatFromKeys(data map[string]interface{}, keys ...string) float64 {
	for _, key := range keys {
		if value, ok := numberAsFloat(data[key]); ok {
			return value
		}
	}
	return 0
}

func numberAsFloat(raw interface{}) (float64, bool) {
	switch typed := raw.(type) {
	case float64:
		return typed, true
	case float32:
		return float64(typed), true
	case int:
		return float64(typed), true
	case int64:
		return float64(typed), true
	case string:
		value, err := strconv.ParseFloat(strings.TrimSpace(typed), 64)
		return value, err == nil
	default:
		return 0, false
	}
}

func stringListFromKeys(data map[string]interface{}, keys ...string) []string {
	for _, key := range keys {
		if values := stringListFromValue(data[key]); len(values) > 0 {
			return values
		}
	}
	return nil
}

func stringListFromValue(raw interface{}) []string {
	switch typed := raw.(type) {
	case []interface{}:
		values := make([]string, 0, len(typed))
		for _, item := range typed {
			if value, ok := item.(string); ok && strings.TrimSpace(value) != "" {
				values = append(values, strings.TrimSpace(value))
			}
		}
		return values
	case []string:
		values := make([]string, 0, len(typed))
		for _, value := range typed {
			if strings.TrimSpace(value) != "" {
				values = append(values, strings.TrimSpace(value))
			}
		}
		return values
	case string:
		if strings.TrimSpace(typed) == "" {
			return nil
		}
		return []string{strings.TrimSpace(typed)}
	default:
		return nil
	}
}

func uniqueStrings(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		cleaned := strings.TrimSpace(value)
		if cleaned == "" {
			continue
		}
		if _, ok := seen[cleaned]; ok {
			continue
		}
		seen[cleaned] = struct{}{}
		out = append(out, cleaned)
	}
	return out
}
