package providers

import (
	"context"
	"fmt"
	"net/url"

	"github.com/MasuRii/PureLink/pkg/abuse"
)

type RustyIP struct{ cfg clientConfig }

func NewRustyIP(opts ...Option) *RustyIP { return &RustyIP{cfg: apply("https://ip.nc.gy/json", opts)} }
func (p *RustyIP) Name() string          { return "rustyip" }
func (p *RustyIP) RateLimit() abuse.RateLimit {
	return abuse.RateLimit{RequestsPerMinute: 120, Burst: 10}
}

func (p *RustyIP) Check(ctx context.Context, ip string) (*abuse.ProviderResult, error) {
	var resp map[string]interface{}
	endpoint := fmt.Sprintf("%s?ip=%s", p.cfg.baseURL, url.QueryEscape(ip))
	if err := requestJSON(ctx, p.cfg.client, "GET", endpoint, nil, &resp, p.Name()); err != nil {
		return nil, err
	}
	boolVal := func(keys ...string) bool {
		for _, k := range keys {
			if v, ok := resp[k].(bool); ok && v {
				return true
			}
		}
		return false
	}
	isProxy := boolVal("proxy", "is_proxy")
	isVPN := boolVal("vpn", "is_vpn")
	isTor := boolVal("tor", "is_tor")
	isHosting := boolVal("hosting", "is_hosting", "datacenter", "is_datacenter")
	score := 0
	if isProxy || isVPN || isTor {
		score = 70
	} else if isHosting {
		score = 40
	}
	return abuse.NormalizeResult(p.Name(), &abuse.ProviderResult{Score: score, Confidence: 0.5, IsProxy: isProxy, IsVPN: isVPN, IsTor: isTor, IsDatacenter: isHosting}), nil
}
