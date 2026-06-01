package providers

import (
	"context"
	"fmt"
	"net/url"

	"github.com/MasuRii/PureLink/pkg/abuse"
)

type IPLookup struct{ cfg clientConfig }

func NewIPLookup(opts ...Option) *IPLookup {
	return &IPLookup{cfg: apply("https://www.iplookup.it/ip", opts)}
}
func (p *IPLookup) Name() string { return "iplookup.it" }
func (p *IPLookup) RateLimit() abuse.RateLimit {
	return abuse.RateLimit{RequestsPerMinute: 60, Burst: 3}
}

func (p *IPLookup) Check(ctx context.Context, ip string) (*abuse.ProviderResult, error) {
	var resp map[string]interface{}
	endpoint := fmt.Sprintf("%s/%s", p.cfg.baseURL, url.PathEscape(ip))
	if err := requestJSON(ctx, p.cfg.client, "GET", endpoint, nil, &resp, p.Name()); err != nil {
		return nil, err
	}

	security := nestedMap(resp, "security", "privacy", "threat")
	if security == nil {
		security = resp
	}
	isVPN := boolFromKeys(security, "vpn", "is_vpn") || boolFromKeys(resp, "vpn", "is_vpn")
	isProxy := boolFromKeys(security, "proxy", "is_proxy") || boolFromKeys(resp, "proxy", "is_proxy")
	isTor := boolFromKeys(security, "tor", "is_tor") || boolFromKeys(resp, "tor", "is_tor")
	isHosting := boolFromKeys(security, "hosting", "is_hosting", "datacenter", "is_datacenter") || boolFromKeys(resp, "hosting", "is_hosting", "datacenter", "is_datacenter")

	score := intFromKeys(resp, "score", "risk_score", "risk")
	if score == 0 {
		switch {
		case isVPN || isProxy || isTor:
			score = 70
		case isHosting:
			score = 40
		}
	}

	raw := map[string]interface{}{}
	for _, key := range []string{"country", "asn", "as", "isp", "reverse_dns"} {
		if value := stringFromKeys(resp, key); value != "" {
			raw[key] = value
		}
	}

	return abuse.NormalizeResult(p.Name(), &abuse.ProviderResult{Score: score, Confidence: 0.55, Categories: categories(isVPN, isProxy, isTor, isHosting), IsDatacenter: isHosting, IsVPN: isVPN, IsProxy: isProxy, IsTor: isTor, Raw: raw}), nil
}
