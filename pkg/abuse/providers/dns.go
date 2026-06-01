package providers

import (
	"context"
	"fmt"
	"net/url"

	"github.com/MasuRii/PureLink/pkg/abuse"
)

type DNSProvider struct {
	cfg  clientConfig
	name string
}

func NewGoogleDNS(opts ...Option) *DNSProvider {
	return &DNSProvider{cfg: apply("https://dns.google/resolve", opts), name: "google-dns"}
}

func NewCloudflareDNS(opts ...Option) *DNSProvider {
	return &DNSProvider{cfg: apply("https://cloudflare-dns.com/dns-query", opts), name: "cloudflare-dns"}
}

func (p *DNSProvider) Name() string { return p.name }
func (p *DNSProvider) RateLimit() abuse.RateLimit {
	return abuse.RateLimit{RequestsPerMinute: 120, Burst: 10}
}

func (p *DNSProvider) Check(ctx context.Context, name string) (*abuse.ProviderResult, error) {
	var resp struct {
		Status int  `json:"Status"`
		TC     bool `json:"TC"`
		RD     bool `json:"RD"`
		RA     bool `json:"RA"`
		AD     bool `json:"AD"`
		CD     bool `json:"CD"`
		Answer []struct {
			Name string `json:"name"`
			Type int    `json:"type"`
			TTL  int    `json:"TTL"`
			Data string `json:"data"`
		} `json:"Answer"`
	}
	endpoint := fmt.Sprintf("%s?name=%s&type=A", p.cfg.baseURL, url.QueryEscape(name))
	if err := requestJSON(ctx, p.cfg.client, "GET", endpoint, nil, &resp, p.Name()); err != nil {
		return nil, err
	}

	answers := make([]interface{}, 0, len(resp.Answer))
	addresses := make([]interface{}, 0, len(resp.Answer))
	for _, answer := range resp.Answer {
		answers = append(answers, map[string]interface{}{"name": answer.Name, "type": answer.Type, "ttl": answer.TTL, "data": answer.Data})
		if answer.Type == 1 && answer.Data != "" {
			addresses = append(addresses, answer.Data)
		}
	}

	return abuse.NormalizeResult(p.Name(), &abuse.ProviderResult{Score: 0, Confidence: 0.2, Categories: []string{"dns"}, Raw: map[string]interface{}{"status": resp.Status, "answers": answers, "addresses": addresses, "ad": resp.AD, "cd": resp.CD}}), nil
}
