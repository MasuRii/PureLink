package ip

import (
	"fmt"
	"net"
)

// Info provides metadata about an IP address.
type Info struct {
	IP      string
	IsV4    bool
	IsV6    bool
	Private bool
}

// Parse extracts Info from a raw string.
func Parse(s string) (*Info, error) {
	addr := net.ParseIP(s)
	if addr == nil {
		return nil, fmt.Errorf("invalid IP address: %s", s)
	}
	return &Info{
		IP:      s,
		IsV4:    addr.To4() != nil,
		IsV6:    addr.To4() == nil,
		Private: addr.IsPrivate(),
	}, nil
}
