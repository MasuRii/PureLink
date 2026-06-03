package v2rayn

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestParseContentBase64SubscriptionWithWhitespace(t *testing.T) {
	plain := "vless://placeholder@192.0.2.100:443#nested\n"
	encoded := base64.StdEncoding.EncodeToString([]byte(plain))
	wrapped := encoded[:8] + "\n\t" + encoded[8:]
	eps := ParseContent(wrapped)
	if len(eps) != 1 || eps[0].Host != "192.0.2.100" || eps[0].Label != "nested" {
		t.Fatalf("unexpected base64 subscription parse: %+v", eps)
	}
}

func TestParseLineRejectsInvalidPortsAndMissingHosts(t *testing.T) {
	bad := []string{
		"vless://user@example.com:bad#x",
		"trojan://user@example.com:70000#x",
		"ss://@",
		"vmess://" + base64.StdEncoding.EncodeToString([]byte(`{"add":"192.0.2.1","port":"0"}`)),
		"v2rayn://" + base64.StdEncoding.EncodeToString([]byte(`{"Address":"192.0.2.1","Port":"bad","ConfigType":5}`)),
	}
	for _, line := range bad {
		t.Run(line, func(t *testing.T) {
			if ep, ok := ParseLine(line); ok {
				t.Fatalf("expected parse failure, got %+v", ep)
			}
		})
	}
}

func TestParseStandardDecodesFragmentAndDefaultPorts(t *testing.T) {
	cases := []struct {
		line     string
		protocol string
		port     int
		label    string
	}{
		{"vless://user@example.com#hello%20world", "vless", 443, "hello world"},
		{"socks5://example.com#sock", "socks", 1080, "sock"},
		{"http://example.com#web", "http", 80, "web"},
	}
	for _, tc := range cases {
		t.Run(tc.line, func(t *testing.T) {
			ep, ok := ParseLine(tc.line)
			if !ok {
				t.Fatal("expected parse success")
			}
			if ep.Protocol != tc.protocol || ep.Port != tc.port || ep.Label != tc.label {
				t.Fatalf("got %+v", ep)
			}
		})
	}
}

func TestParseContentIgnoresNonSubscriptionBase64(t *testing.T) {
	encoded := base64.StdEncoding.EncodeToString([]byte("just some text without endpoints"))
	if eps := ParseContent(encoded); len(eps) != 0 {
		t.Fatalf("expected no endpoints, got %+v", eps)
	}
}

func FuzzParseShareLineEdges(f *testing.F) {
	for _, seed := range []string{
		"vless://placeholder@192.0.2.1:443#seed",
		"trojan://secret@example.com:443#seed",
		"ss://" + base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm:pass")) + "@example.com:8388#seed",
		"vmess://" + strings.TrimRight(base64.StdEncoding.EncodeToString([]byte(`{"add":"192.0.2.1","port":"443"}`)), "="),
		"",
		"not a link",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, line string) {
		ep, ok := ParseLine(line)
		if !ok {
			return
		}
		if ep.Host == "" || ep.Port <= 0 || ep.Port > 65535 || ep.Protocol == "" {
			t.Fatalf("invalid parsed endpoint: %+v", ep)
		}
	})
}
