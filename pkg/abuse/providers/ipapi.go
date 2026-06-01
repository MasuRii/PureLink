package providers

import (
	"context"
	"fmt"
	"net/url"

	"github.com/MasuRii/PureLink/pkg/abuse"
)

type IPAPI struct{ cfg clientConfig }

func NewIPAPI(opts ...Option) *IPAPI        { return &IPAPI{cfg: apply("https://api.ipapi.is", opts)} }
func (p *IPAPI) Name() string               { return "ipapi.is" }
func (p *IPAPI) RateLimit() abuse.RateLimit { return abuse.RateLimit{RequestsPerMinute: 60, Burst: 5} }

func (p *IPAPI) Check(ctx context.Context, ip string) (*abuse.ProviderResult, error) {
	var resp struct {
		IsVPN        bool `json:"is_vpn"`
		IsProxy      bool `json:"is_proxy"`
		IsTor        bool `json:"is_tor"`
		IsDatacenter bool `json:"is_datacenter"`
		Company      struct {
			Type string `json:"type"`
		} `json:"company"`
		Abuse struct {
			Score   int `json:"score"`
			Reports int `json:"reports"`
		} `json:"abuse"`
	}
	endpoint := fmt.Sprintf("%s?q=%s", p.cfg.baseURL, url.QueryEscape(ip))
	if err := requestJSON(ctx, p.cfg.client, "GET", endpoint, nil, &resp, p.Name()); err != nil {
		return nil, err
	}
	cats := []string{}
	if resp.IsDatacenter || resp.Company.Type == "hosting" {
		cats = append(cats, "datacenter")
	}
	if resp.IsVPN {
		cats = append(cats, "vpn")
	}
	if resp.IsProxy {
		cats = append(cats, "proxy")
	}
	if resp.IsTor {
		cats = append(cats, "tor")
	}
	return abuse.NormalizeResult(p.Name(), &abuse.ProviderResult{Score: resp.Abuse.Score, Confidence: 0.8, Categories: cats, IsDatacenter: resp.IsDatacenter || resp.Company.Type == "hosting", IsVPN: resp.IsVPN, IsProxy: resp.IsProxy, IsTor: resp.IsTor}), nil
}
