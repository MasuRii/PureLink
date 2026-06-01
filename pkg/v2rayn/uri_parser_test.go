package v2rayn

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestParseShareLinks(t *testing.T) {
	vmessPayload := base64.StdEncoding.EncodeToString([]byte(`{"add":"192.0.2.1","port":"443","ps":"test-vmess","id":"PLACEHOLDER_ID"}`))
	links := []struct {
		name, line, protocol, host, label string
		port                              int
	}{
		{"vmess", "vmess://" + strings.TrimRight(vmessPayload, "="), "vmess", "192.0.2.1", "test-vmess", 443},
		{"vless", "vless://placeholder-id@192.0.2.2:8443?security=tls#test-vless", "vless", "192.0.2.2", "test-vless", 8443},
		{"trojan", "trojan://credential@192.0.2.3:443#test-trojan", "trojan", "192.0.2.3", "test-trojan", 443},
		{"ss", "ss://" + base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm:credential")) + "@192.0.2.4:8388#test-ss", "shadowsocks", "192.0.2.4", "test-ss", 8388},
	}
	for _, tt := range links {
		t.Run(tt.name, func(t *testing.T) {
			ep, ok := ParseLine(tt.line)
			if !ok {
				t.Fatalf("ParseLine returned false")
			}
			if ep.Protocol != tt.protocol || ep.Host != tt.host || ep.Port != tt.port || ep.Label != tt.label {
				t.Fatalf("got %+v", ep)
			}
			if strings.Contains(ep.Label, "credential") || strings.Contains(ep.Host, "placeholder-id") {
				t.Fatalf("credential leaked: %+v", ep)
			}
		})
	}
}

func TestParseWireGuardINI(t *testing.T) {
	content := `[Interface]
PrivateKey = PLACEHOLDER
[Peer]
PublicKey = PLACEHOLDER
PresharedKey = PLACEHOLDER
Endpoint = 192.0.2.10:51820`
	eps := ParseWireGuardINI(content)
	if len(eps) != 1 {
		t.Fatalf("expected 1 endpoint, got %d", len(eps))
	}
	if eps[0].Protocol != "wireguard" || eps[0].Host != "192.0.2.10" || eps[0].Port != 51820 {
		t.Fatalf("got %+v", eps[0])
	}
}

func TestRedact(t *testing.T) {
	uuid := "12345678" + "-1234" + "-1234" + "-1234" + "-123456789abc"
	in := "password=PLACEHOLDER token=ABC " + uuid
	out := Redact(in)
	for _, forbidden := range []string{"PLACEHOLDER", "ABC", uuid} {
		if strings.Contains(out, forbidden) {
			t.Fatalf("redaction leaked %q in %q", forbidden, out)
		}
	}
}
