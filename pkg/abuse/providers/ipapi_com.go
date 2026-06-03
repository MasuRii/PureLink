package providers

import (
	"context"
	"fmt"
	"net/url"

	"github.com/MasuRii/PureLink/pkg/abuse"
)

type IPAPICom struct{ cfg clientConfig }

func NewIPAPICom(opts ...Option) *IPAPICom {
	return &IPAPICom{cfg: apply("http://ip-api.com/json", opts)}
}
func (p *IPAPICom) Name() string { return "ip-api.com" }
func (p *IPAPICom) RateLimit() abuse.RateLimit {
	return abuse.RateLimit{RequestsPerMinute: 45, Burst: 3}
}

func (p *IPAPICom) Check(ctx context.Context, ip string) (*abuse.ProviderResult, error) {
	var resp struct {
		Proxy       bool   `json:"proxy"`
		Hosting     bool   `json:"hosting"`
		Mobile      bool   `json:"mobile"`
		Country     string `json:"country"`
		CountryCode string `json:"countryCode"`
		ISP         string `json:"isp"`
		AS          string `json:"as"`
	}
	endpoint := fmt.Sprintf("%s/%s?fields=proxy,hosting,mobile,country,countryCode,isp,as,query", p.cfg.baseURL, url.PathEscape(ip))
	if err := requestJSON(ctx, p.cfg.client, "GET", endpoint, nil, &resp, p.Name()); err != nil {
		return nil, err
	}
	score := 0
	if resp.Proxy {
		score = 70
	} else if resp.Hosting {
		score = 40
	}
	cats := []string{}
	if resp.Proxy {
		cats = append(cats, "proxy")
	}
	if resp.Hosting {
		cats = append(cats, "hosting")
	}
	return abuse.NormalizeResult(p.Name(), &abuse.ProviderResult{Score: score, Confidence: 0.6, Categories: cats, IsProxy: resp.Proxy, IsDatacenter: resp.Hosting, Country: resp.Country, CountryCode: resp.CountryCode, Raw: map[string]interface{}{"country": resp.Country, "country_code": resp.CountryCode, "isp": resp.ISP, "as": resp.AS}}), nil
}
