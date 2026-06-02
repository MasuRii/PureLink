package providers

import (
	"context"

	"github.com/MasuRii/PureLink/pkg/abuse"
)

type IPLogs struct{ cfg clientConfig }

func NewIPLogs(opts ...Option) *IPLogs {
	return &IPLogs{cfg: apply("https://iplogs.com/v1/check", opts)}
}
func (p *IPLogs) Name() string               { return "iplogs" }
func (p *IPLogs) RateLimit() abuse.RateLimit { return abuse.RateLimit{RequestsPerMinute: 60, Burst: 3} }

func (p *IPLogs) Check(ctx context.Context, ip string) (*abuse.ProviderResult, error) {
	var resp struct {
		Verdict    string  `json:"verdict"`
		Score      float64 `json:"score"`
		Confidence float64 `json:"confidence"`
		Signals    struct {
			IsVPN        bool     `json:"is_vpn"`
			IsProxy      bool     `json:"is_proxy"`
			IsTor        bool     `json:"is_tor"`
			IsDatacenter bool     `json:"is_datacenter"`
			MatchedLists []string `json:"matched_lists"`
		} `json:"signals"`
	}
	if err := requestJSON(ctx, p.cfg.client, "POST", p.cfg.baseURL, map[string]string{"ip": ip}, &resp, p.Name()); err != nil {
		return nil, err
	}
	score := int(resp.Score)
	if resp.Score >= 0 && resp.Score <= 1 {
		score = int(resp.Score * 100)
	}
	cats := append([]string{}, resp.Signals.MatchedLists...)
	return abuse.NormalizeResult(p.Name(), &abuse.ProviderResult{Score: score, Confidence: resp.Confidence, Categories: cats, IsDatacenter: resp.Signals.IsDatacenter, IsVPN: resp.Signals.IsVPN, IsProxy: resp.Signals.IsProxy, IsTor: resp.Signals.IsTor, Purity: resp.Verdict}), nil
}
