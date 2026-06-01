package providers

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/MasuRii/PureLink/pkg/abuse"
)

type Blackbox struct{ cfg clientConfig }

func NewBlackbox(opts ...Option) *Blackbox {
	return &Blackbox{cfg: apply("https://blackbox.ipinfo.app/api/v1", opts)}
}
func (p *Blackbox) Name() string { return "blackbox" }
func (p *Blackbox) RateLimit() abuse.RateLimit {
	return abuse.RateLimit{RequestsPerMinute: 120, Burst: 10}
}

func (p *Blackbox) Check(ctx context.Context, ip string) (*abuse.ProviderResult, error) {
	text, err := requestText(ctx, p.cfg.client, fmt.Sprintf("%s/%s", p.cfg.baseURL, url.PathEscape(ip)), p.Name())
	if err != nil {
		return nil, err
	}
	flagged := strings.EqualFold(strings.TrimSpace(text), "Y") || strings.Contains(strings.ToLower(text), "true")
	score := 0
	if flagged {
		score = 60
	}
	return abuse.NormalizeResult(p.Name(), &abuse.ProviderResult{Score: score, Confidence: 0.6, IsProxy: flagged, IsDatacenter: flagged}), nil
}
