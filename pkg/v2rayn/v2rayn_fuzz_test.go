package v2rayn

import (
	"testing"
)

func FuzzParseLine(f *testing.F) {
	seeds := []string{
		"vmess://eyJhZGQiOiIxOTIuMC4yLjEiLCJwb3J0IjoiNDQzIiwicHMiOiJ0ZXN0In0=",
		"vless://user@192.0.2.1:443#label",
		"ss://YWVzLTI1Ni1nY206Y3JlZEBAMTkyLjAuMi4xOjgzODg=#label",
		"wireguard://192.0.2.1:51820#wg",
		"socks5://192.0.2.1:1080#socks",
		"hysteria2://user@192.0.2.1:443#hy2",
		"tuic://user@192.0.2.1:443#tuic",
		"anytls://user@192.0.2.1:443#anytls",
		"naive://user@192.0.2.1:443#naive",
		"",
		"# comment",
		"unknown://host:443",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, line string) {
		_, _ = ParseLine(line)
	})
}

func FuzzParseContent(f *testing.F) {
	seeds := []string{
		"vless://user@192.0.2.1:443#label\nvmess://eyJhZGQiOiIxOTIuMC4yLjEiLCJwb3J0IjoiNDQzIiwicHMiOiJ0ZXN0In0=",
		"[Peer]\nEndpoint = 192.0.2.1:51820",
		`[{"server":"192.0.2.1","server_port":8080}]`,
		"",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, content string) {
		_ = ParseContent(content)
	})
}
