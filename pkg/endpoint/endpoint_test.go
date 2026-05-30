package endpoint

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		wantErr bool
		host    string
		port    int
	}{
		{"valid ipv4 with port", "192.168.1.1:8080", false, "192.168.1.1", 8080},
		{"valid domain with port", "example.com:443", false, "example.com", 443},
		{"valid ipv6 with port", "[::1]:8080", false, "::1", 8080},
		{"no port appends 80", "10.0.0.1", false, "10.0.0.1", 80},
		{"empty string", "", true, "", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ep, err := Parse(tt.raw)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.host, ep.Host)
			assert.Equal(t, tt.port, ep.Port)
		})
	}
}

func TestEndpoint_IsIP(t *testing.T) {
	tests := []struct {
		raw string
		ip  bool
	}{
		{"192.168.1.1:80", true},
		{"example.com:443", false},
		{"[::1]:80", true},
	}

	for _, tt := range tests {
		t.Run(tt.raw, func(t *testing.T) {
			ep, err := Parse(tt.raw)
			require.NoError(t, err)
			assert.Equal(t, tt.ip, ep.IsIP())
		})
	}
}
