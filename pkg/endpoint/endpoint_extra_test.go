package endpoint

import "testing"

func TestParseWithDefaultStrictAndCanonicalForms(t *testing.T) {
	tests := []struct {
		name        string
		raw         string
		defaultPort int
		wantHost    string
		wantPort    int
		wantErr     bool
	}{
		{"strict rejects bare host", "example.com", 0, "", 0, true},
		{"custom default", "Example.COM", 8443, "example.com", 8443, false},
		{"bracketed ipv6 default", "[2001:db8::1]", 443, "2001:db8::1", 443, false},
		{"port zero", "example.com:0", 80, "", 0, true},
		{"port high", "example.com:65536", 80, "", 0, true},
		{"blank host", ":443", 80, "", 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ep, err := ParseWithDefault(tt.raw, tt.defaultPort)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got %+v", ep)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if ep.Host != tt.wantHost || ep.Port != tt.wantPort || ep.Normalize() != ep.String() {
				t.Fatalf("unexpected endpoint: %+v string=%s normalize=%s", ep, ep.String(), ep.Normalize())
			}
		})
	}
}
