package providers

import (
	"context"
	"fmt"
	"net/url"

	"github.com/MasuRii/PureLink/pkg/abuse"
)

type IPPriv struct{ cfg clientConfig }

func NewIPPriv(opts ...Option) *IPPriv {
	return &IPPriv{cfg: apply("https://api.ippriv.com/api/security", opts)}
}
func (p *IPPriv) Name() string { return "ippriv" }
func (p *IPPriv) RateLimit() abuse.RateLimit {
	return abuse.RateLimit{RequestsPerMinute: 60, Burst: 3}
}

func (p *IPPriv) Check(ctx context.Context, ip string) (*abuse.ProviderResult, error) {
	var resp map[string]interface{}
	endpoint := fmt.Sprintf("%s/%s", p.cfg.baseURL, url.PathEscape(ip))
	if err := requestJSON(ctx, p.cfg.client, "GET", endpoint, nil, &resp, p.Name()); err != nil {
		return nil, err
	}

	security := nestedMap(resp, "security", "privacy")
	if security == nil {
		security = resp
	}
	isVPN := boolFromKeys(security, "vpn", "is_vpn", "isVPN") || boolFromKeys(resp, "vpn", "is_vpn", "isVPN")
	isProxy := boolFromKeys(security, "proxy", "is_proxy", "isProxy") || boolFromKeys(resp, "proxy", "is_proxy", "isProxy")
	isTor := boolFromKeys(security, "tor", "is_tor", "isTor") || boolFromKeys(resp, "tor", "is_tor", "isTor")
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

	cats := categories(isVPN, isProxy, isTor, isHosting)
	raw := map[string]interface{}{}
	if asn := stringFromKeys(resp, "asn", "as"); asn != "" {
		raw["asn"] = asn
	}
	if org := stringFromKeys(resp, "organization", "org", "isp"); org != "" {
		raw["organization"] = org
	}

	return abuse.NormalizeResult(p.Name(), &abuse.ProviderResult{Score: score, Confidence: 0.6, Categories: cats, IsDatacenter: isHosting, IsVPN: isVPN, IsProxy: isProxy, IsTor: isTor, Raw: raw}), nil
}
