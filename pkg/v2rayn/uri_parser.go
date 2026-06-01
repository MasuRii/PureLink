package v2rayn

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strconv"
	"strings"
)

func ParseContent(content string) []ImportedEndpoint {
	var out []ImportedEndpoint
	for _, ep := range parseSIP008(content) {
		out = append(out, ep)
	}
	if looksLikeWireGuardINI(content) {
		for _, ep := range ParseWireGuardINI(content) {
			out = append(out, ep)
		}
	}
	s := bufio.NewScanner(strings.NewReader(content))
	for s.Scan() {
		if ep, ok := ParseLine(s.Text()); ok {
			out = append(out, ep)
		}
	}
	return out
}

func ParseLine(line string) (ImportedEndpoint, bool) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return ImportedEndpoint{}, false
	}
	lower := strings.ToLower(line)
	switch {
	case strings.HasPrefix(lower, "vmess://"):
		return parseVMess(line)
	case strings.HasPrefix(lower, "v2rayn://"):
		return parseV2rayNInner(line)
	case strings.HasPrefix(lower, "ss://"):
		return parseSS(line)
	case strings.HasPrefix(lower, "wireguard://"):
		return parseStandard(line, "wireguard", 51820)
	case strings.Contains(line, "[Peer]") || strings.Contains(line, "Endpoint =") || strings.Contains(line, "Endpoint="):
		eps := ParseWireGuardINI(line)
		if len(eps) > 0 {
			return eps[0], true
		}
	case strings.HasPrefix(lower, "vless://"):
		return parseStandard(line, "vless", 443)
	case strings.HasPrefix(lower, "trojan://"):
		return parseStandard(line, "trojan", 443)
	case strings.HasPrefix(lower, "socks://") || strings.HasPrefix(lower, "socks5://") || strings.HasPrefix(lower, "socks4://"):
		return parseStandard(line, "socks", 1080)
	case strings.HasPrefix(lower, "http://"):
		return parseStandard(line, "http", 80)
	case strings.HasPrefix(lower, "hysteria2://") || strings.HasPrefix(lower, "hy2://"):
		return parseStandard(line, "hysteria2", 443)
	case strings.HasPrefix(lower, "tuic://"):
		return parseStandard(line, "tuic", 443)
	case strings.HasPrefix(lower, "anytls://"):
		return parseStandard(line, "anytls", 443)
	case strings.HasPrefix(lower, "naive://") || strings.HasPrefix(lower, "naive+https://") || strings.HasPrefix(lower, "naive+quic://"):
		return parseStandard(line, "naive", 443)
	}
	return ImportedEndpoint{}, false
}

func parseVMess(line string) (ImportedEndpoint, bool) {
	payload := strings.TrimPrefix(line, "vmess://")
	b, ok := decodeBase64(payload)
	if !ok {
		return ImportedEndpoint{}, false
	}
	var m map[string]interface{}
	if json.Unmarshal(b, &m) != nil {
		return ImportedEndpoint{}, false
	}
	host, _ := m["add"].(string)
	port, ok := parseAnyPort(m["port"])
	if !ok {
		return ImportedEndpoint{}, false
	}
	label, _ := m["ps"].(string)
	return NewImported("vmess", host, port, label, "", "link_file")
}

func parseV2rayNInner(line string) (ImportedEndpoint, bool) {
	payload := strings.TrimPrefix(line, "v2rayn://")
	b, ok := decodeBase64(payload)
	if !ok {
		return ImportedEndpoint{}, false
	}
	var m map[string]interface{}
	if json.Unmarshal(b, &m) != nil {
		return ImportedEndpoint{}, false
	}
	host, _ := firstString(m, "Address", "address")
	port, ok := parseAnyPort(firstValue(m, "Port", "port"))
	if !ok {
		return ImportedEndpoint{}, false
	}
	label, _ := firstString(m, "Remarks", "remarks")
	ct, _ := parseAnyPort(firstValue(m, "ConfigType", "configType"))
	protocol, ok := ProtocolForConfigType(ct)
	if !ok {
		protocol = "unknown"
	}
	return NewImported(protocol, host, port, label, "", "link_file")
}

func parseSS(line string) (ImportedEndpoint, bool) {
	if ep, ok := parseStandard(line, "shadowsocks", 8388); ok {
		return ep, true
	}
	payload := strings.TrimPrefix(line, "ss://")
	if i := strings.Index(payload, "#"); i >= 0 {
		payload = payload[:i]
	}
	b, ok := decodeBase64(payload)
	if !ok {
		return ImportedEndpoint{}, false
	}
	decoded := string(b)
	at := strings.LastIndex(decoded, "@")
	if at < 0 {
		return ImportedEndpoint{}, false
	}
	return parseHostPort(decoded[at+1:], "shadowsocks", 8388, "")
}

func parseStandard(line, protocol string, defaultPort int) (ImportedEndpoint, bool) {
	u, err := url.Parse(line)
	if err != nil {
		return ImportedEndpoint{}, false
	}
	host := u.Hostname()
	if host == "" {
		return ImportedEndpoint{}, false
	}
	port := defaultPort
	if u.Port() != "" {
		p, err := strconv.Atoi(u.Port())
		if err != nil {
			return ImportedEndpoint{}, false
		}
		port = p
	}
	label, _ := url.QueryUnescape(u.Fragment)
	return NewImported(protocol, host, port, label, "", "link_file")
}

func parseHostPort(hp, protocol string, defaultPort int, label string) (ImportedEndpoint, bool) {
	host := hp
	port := defaultPort
	if idx := strings.LastIndex(hp, ":"); idx >= 0 {
		host = strings.Trim(hp[:idx], "[]")
		p, err := strconv.Atoi(hp[idx+1:])
		if err != nil {
			return ImportedEndpoint{}, false
		}
		port = p
	}
	return NewImported(protocol, host, port, label, "", "link_file")
}

func looksLikeWireGuardINI(content string) bool {
	lower := strings.ToLower(content)
	return strings.Contains(lower, "[peer]") && strings.Contains(lower, "endpoint")
}

func ParseWireGuardINI(content string) []ImportedEndpoint {
	var out []ImportedEndpoint
	inPeer := false
	s := bufio.NewScanner(strings.NewReader(content))
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			inPeer = strings.EqualFold(line, "[Peer]")
			continue
		}
		if !inPeer || !strings.Contains(line, "=") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if strings.EqualFold(strings.TrimSpace(parts[0]), "Endpoint") {
			if ep, ok := parseHostPort(strings.TrimSpace(parts[1]), "wireguard", 51820, ""); ok {
				out = append(out, ep)
			}
		}
	}
	return out
}

func parseSIP008(content string) []ImportedEndpoint {
	var out []ImportedEndpoint
	var root interface{}
	if json.Unmarshal([]byte(strings.TrimSpace(content)), &root) != nil {
		return nil
	}
	var servers []interface{}
	switch v := root.(type) {
	case []interface{}:
		servers = v
	case map[string]interface{}:
		if s, ok := v["servers"].([]interface{}); ok {
			servers = s
		}
	}
	for _, item := range servers {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		host, _ := m["server"].(string)
		port, ok := parseAnyPort(m["server_port"])
		if !ok {
			continue
		}
		label, _ := m["remarks"].(string)
		if ep, ok := NewImported("shadowsocks", host, port, label, "", "link_file"); ok {
			out = append(out, ep)
		}
	}
	return out
}

func decodeBase64(s string) ([]byte, bool) {
	s = strings.TrimSpace(s)
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return b, true
	}
	if b, err := base64.URLEncoding.DecodeString(padBase64(s)); err == nil {
		return b, true
	}
	if b, err := base64.RawStdEncoding.DecodeString(s); err == nil {
		return b, true
	}
	if b, err := base64.StdEncoding.DecodeString(padBase64(s)); err == nil {
		return b, true
	}
	return nil, false
}

func padBase64(s string) string {
	if m := len(s) % 4; m != 0 {
		s += strings.Repeat("=", 4-m)
	}
	return s
}
func parseAnyPort(v interface{}) (int, bool) {
	switch x := v.(type) {
	case int:
		return x, x > 0 && x < 65536
	case float64:
		p := int(x)
		return p, p > 0 && p < 65536
	case string:
		p, err := strconv.Atoi(strings.TrimSpace(x))
		return p, err == nil && p > 0 && p < 65536
	default:
		return 0, false
	}
}
func firstValue(m map[string]interface{}, keys ...string) interface{} {
	for _, k := range keys {
		if v, ok := m[k]; ok {
			return v
		}
	}
	return nil
}
func firstString(m map[string]interface{}, keys ...string) (string, bool) {
	v := firstValue(m, keys...)
	s, ok := v.(string)
	return s, ok
}
