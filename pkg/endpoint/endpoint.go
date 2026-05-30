package endpoint

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// Endpoint represents a host:port pair.
type Endpoint struct {
	Host string
	Port int
	Raw  string
}

// Parse splits a raw endpoint string into host and port.
func Parse(raw string) (*Endpoint, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, fmt.Errorf("invalid endpoint %q: empty string", raw)
	}
	host, portStr, err := net.SplitHostPort(raw)
	if err != nil {
		// Try appending default port
		host, portStr, err = net.SplitHostPort(raw + ":80")
		if err != nil {
			return nil, fmt.Errorf("invalid endpoint %q: %w", raw, err)
		}
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, fmt.Errorf("invalid port in %q", raw)
	}
	return &Endpoint{Host: host, Port: port, Raw: raw}, nil
}

// String returns the endpoint in host:port format.
func (e *Endpoint) String() string {
	return net.JoinHostPort(e.Host, strconv.Itoa(e.Port))
}

// IsIP reports whether the host is an IP address.
func (e *Endpoint) IsIP() bool {
	return net.ParseIP(e.Host) != nil
}

// Normalize returns a canonical form of the endpoint.
func (e *Endpoint) Normalize() string {
	h := strings.ToLower(e.Host)
	return net.JoinHostPort(h, strconv.Itoa(e.Port))
}
