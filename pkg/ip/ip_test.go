package ip

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantErr   bool
		isV4      bool
		isV6      bool
		isPrivate bool
	}{
		{"valid ipv4", "8.8.8.8", false, true, false, false},
		{"valid ipv6", "2001:4860:4860::8888", false, false, true, false},
		{"private ipv4", "192.168.1.1", false, true, false, true},
		{"invalid", "not-an-ip", true, false, false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info, err := Parse(tt.input)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.isV4, info.IsV4)
			assert.Equal(t, tt.isV6, info.IsV6)
			assert.Equal(t, tt.isPrivate, info.Private)
		})
	}
}
