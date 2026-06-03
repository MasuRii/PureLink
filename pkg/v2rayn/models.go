package v2rayn

import (
	"fmt"
	"net"
	"strings"

	"github.com/MasuRii/PureLink/pkg/endpoint"
)

type ImportedEndpoint struct {
	Protocol string `json:"protocol"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Label    string `json:"label,omitempty"`
	SubGroup string `json:"sub_group,omitempty"`
	Source   string `json:"source"`
	// RawURI preserves the original share link in memory for explicit share-link
	// exports. It is intentionally omitted from normal JSON/import output because
	// share links can contain credentials.
	RawURI string `json:"-"`
}

var configTypeProtocol = map[int]string{1: "vmess", 3: "shadowsocks", 4: "socks", 5: "vless", 6: "trojan", 7: "hysteria2", 8: "tuic", 9: "wireguard", 10: "http", 11: "anytls", 12: "naive"}

func ProtocolForConfigType(t int) (string, bool) { v, ok := configTypeProtocol[t]; return v, ok }

func (e ImportedEndpoint) Validate() error {
	if e.Protocol == "" || e.Host == "" || e.Port < 1 || e.Port > 65535 || e.Source == "" {
		return fmt.Errorf("invalid imported endpoint")
	}
	return nil
}

func (e ImportedEndpoint) ToEndpoint() endpoint.Endpoint {
	return endpoint.Endpoint{Host: normalizeHost(e.Host), Port: e.Port, Raw: net.JoinHostPort(normalizeHost(e.Host), fmt.Sprintf("%d", e.Port))}
}

func normalizeHost(h string) string {
	h = strings.Trim(strings.TrimSpace(h), "[]")
	if ip := net.ParseIP(h); ip != nil {
		return strings.ToLower(ip.String())
	}
	return strings.ToLower(h)
}

func NewImported(protocol, host string, port int, label, subgroup, source string) (ImportedEndpoint, bool) {
	ep := ImportedEndpoint{Protocol: strings.ToLower(strings.TrimSpace(protocol)), Host: normalizeHost(host), Port: port, Label: strings.TrimSpace(label), SubGroup: strings.TrimSpace(subgroup), Source: source}
	return ep, ep.Validate() == nil
}

func (e ImportedEndpoint) WithRawURI(raw string) ImportedEndpoint {
	e.RawURI = strings.TrimSpace(raw)
	return e
}
