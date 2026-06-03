package v2rayn

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestParseLine_Protocols(t *testing.T) {
	vmessPayload := base64.StdEncoding.EncodeToString([]byte(`{"add":"192.0.2.1","port":"443","ps":"vmess-label"}`))
	v2raynPayload := base64.StdEncoding.EncodeToString([]byte(`{"Address":"192.0.2.20","Port":"9443","Remarks":"inner","ConfigType":5}`))

	tests := []struct {
		name     string
		line     string
		protocol string
		host     string
		port     int
		label    string
		ok       bool
	}{
		{"hysteria2", "hysteria2://user@192.0.2.5:443#hy2-label", "hysteria2", "192.0.2.5", 443, "hy2-label", true},
		{"hy2 alias", "hy2://user@192.0.2.5:8443#hy2-label", "hysteria2", "192.0.2.5", 8443, "hy2-label", true},
		{"tuic", "tuic://user@192.0.2.6:443#tuic-label", "tuic", "192.0.2.6", 443, "tuic-label", true},
		{"anytls", "anytls://user@192.0.2.7:443#anytls-label", "anytls", "192.0.2.7", 443, "anytls-label", true},
		{"naive", "naive://user@192.0.2.8:443#naive-label", "naive", "192.0.2.8", 443, "naive-label", true},
		{"naive+https", "naive+https://user@192.0.2.8:443#naive-label", "naive", "192.0.2.8", 443, "naive-label", true},
		{"naive+quic", "naive+quic://user@192.0.2.8:443#naive-label", "naive", "192.0.2.8", 443, "naive-label", true},
		{"socks4", "socks4://192.0.2.9:1080#socks-label", "socks", "192.0.2.9", 1080, "socks-label", true},
		{"socks5", "socks5://192.0.2.9:1080#socks-label", "socks", "192.0.2.9", 1080, "socks-label", true},
		{"http", "http://192.0.2.11:8080#http-label", "http", "192.0.2.11", 8080, "http-label", true},
		{"wireguard uri", "wireguard://192.0.2.10:51820#wg-label", "wireguard", "192.0.2.10", 51820, "wg-label", true},
		{"vmess", "vmess://" + strings.TrimRight(vmessPayload, "="), "vmess", "192.0.2.1", 443, "vmess-label", true},
		{"v2rayn inner", "v2rayn://" + strings.TrimRight(v2raynPayload, "="), "vless", "192.0.2.20", 9443, "inner", true},
		{"empty", "", "", "", 0, "", false},
		{"comment", "# this is a comment", "", "", 0, "", false},
		{"unknown", "unknown://192.0.2.1:443", "", "", 0, "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ep, ok := ParseLine(tt.line)
			if ok != tt.ok {
				t.Fatalf("ParseLine(%q) ok=%v, want %v", tt.line, ok, tt.ok)
			}
			if !ok {
				return
			}
			if ep.Protocol != tt.protocol || ep.Host != tt.host || ep.Port != tt.port || ep.Label != tt.label {
				t.Fatalf("ParseLine(%q) = %+v, want protocol=%s host=%s port=%d label=%s", tt.line, ep, tt.protocol, tt.host, tt.port, tt.label)
			}
		})
	}
}

func TestParseContent_Base64Subscription(t *testing.T) {
	plain := "vless://placeholder@192.0.2.30:443#sub-one\n trojan://secret@192.0.2.31:8443#sub-two\n"
	encoded := base64.StdEncoding.EncodeToString([]byte(plain))
	eps := ParseContent(encoded)
	if len(eps) != 2 {
		t.Fatalf("expected 2 endpoints, got %d", len(eps))
	}
	if eps[0].Protocol != "vless" || eps[0].Host != "192.0.2.30" || eps[1].Protocol != "trojan" || eps[1].Port != 8443 {
		t.Fatalf("unexpected endpoints: %+v", eps)
	}
}

func TestParseContent_WireGuardINIMultiline(t *testing.T) {
	content := `[Interface]
PrivateKey = PLACEHOLDER
Address = 10.0.0.2/32

[Peer]
PublicKey = PLACEHOLDER
AllowedIPs = 0.0.0.0/0
Endpoint = 192.0.2.70:51820
`
	eps := ParseContent(content)
	if len(eps) != 1 {
		t.Fatalf("expected 1 endpoint, got %d", len(eps))
	}
	if eps[0].Protocol != "wireguard" || eps[0].Host != "192.0.2.70" || eps[0].Port != 51820 {
		t.Fatalf("got %+v", eps[0])
	}
}

func TestParseLine_SIP008(t *testing.T) {
	arr := `[{"server":"192.0.2.50","server_port":8080,"remarks":"sip-arr"}]`
	obj := `{"servers":[{"server":"192.0.2.51","server_port":8081,"remarks":"sip-obj"}]}`

	tests := []struct {
		name  string
		input string
		host  string
		port  int
		label string
	}{
		{"array", arr, "192.0.2.50", 8080, "sip-arr"},
		{"object", obj, "192.0.2.51", 8081, "sip-obj"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			eps := ParseContent(tt.input)
			if len(eps) != 1 {
				t.Fatalf("expected 1 endpoint, got %d", len(eps))
			}
			if eps[0].Host != tt.host || eps[0].Port != tt.port || eps[0].Label != tt.label {
				t.Fatalf("got %+v", eps[0])
			}
		})
	}
}

func TestParseWireGuardINI_MultiplePeers(t *testing.T) {
	content := `[Interface]
PrivateKey = PLACEHOLDER
[Peer]
PublicKey = PLACEHOLDER
Endpoint = 192.0.2.60:51820
[Peer]
PublicKey = PLACEHOLDER2
Endpoint = [2001:db8::1]:51821
`
	eps := ParseWireGuardINI(content)
	if len(eps) != 2 {
		t.Fatalf("expected 2 endpoints, got %d", len(eps))
	}
	if eps[0].Host != "192.0.2.60" || eps[0].Port != 51820 {
		t.Fatalf("got %+v", eps[0])
	}
	if eps[1].Host != "2001:db8::1" || eps[1].Port != 51821 {
		t.Fatalf("got %+v", eps[1])
	}
}

func TestParseLine_MalformedBase64(t *testing.T) {
	_, ok := ParseLine("vmess://!!!not-base64!!!")
	if ok {
		t.Fatal("expected false for malformed base64")
	}
}

func TestParseLine_MissingHost(t *testing.T) {
	_, ok := ParseLine("vless://user@:443#label")
	if ok {
		t.Fatal("expected false for missing host")
	}
}
