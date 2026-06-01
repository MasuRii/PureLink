package endpoint

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	plerrors "github.com/MasuRii/PureLink/pkg/errors"
)

const DefaultPort = 80

// Endpoint represents a canonical host:port pair.
type Endpoint struct {
	Host string `json:"host"`
	Port int    `json:"port"`
	Raw  string `json:"raw,omitempty"`
}

// Parse splits a raw endpoint string into host and port. Bare hosts default to port 80.
func Parse(raw string) (*Endpoint, error) {
	return ParseWithDefault(raw, DefaultPort)
}

// ParseWithDefault splits raw into host and port, applying defaultPort to bare hosts when > 0.
func ParseWithDefault(raw string, defaultPort int) (*Endpoint, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, fmt.Errorf("%w: %q", plerrors.ErrInvalidEndpoint, raw)
	}

	host, portStr, err := net.SplitHostPort(trimmed)
	if err != nil {
		if defaultPort <= 0 {
			return nil, fmt.Errorf("%w: %q", plerrors.ErrInvalidEndpoint, raw)
		}
		host = strings.Trim(trimmed, "[]")
		portStr = strconv.Itoa(defaultPort)
	} else {
		host = strings.Trim(host, "[]")
	}

	host = normalizeHost(host)
	if host == "" {
		return nil, fmt.Errorf("%w: %q", plerrors.ErrInvalidEndpoint, raw)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return nil, fmt.Errorf("%w: %q", plerrors.ErrInvalidEndpoint, raw)
	}
	return &Endpoint{Host: host, Port: port, Raw: raw}, nil
}

func normalizeHost(host string) string {
	host = strings.TrimSpace(host)
	if ip := net.ParseIP(host); ip != nil {
		return strings.ToLower(ip.String())
	}
	return strings.ToLower(host)
}

// String returns the endpoint in host:port format.
func (e Endpoint) String() string {
	return net.JoinHostPort(e.Host, strconv.Itoa(e.Port))
}

// IsIP reports whether the host is an IP address.
func (e Endpoint) IsIP() bool {
	return net.ParseIP(e.Host) != nil
}

// Normalize returns a canonical comparison key.
func (e Endpoint) Normalize() string {
	return net.JoinHostPort(normalizeHost(e.Host), strconv.Itoa(e.Port))
}
