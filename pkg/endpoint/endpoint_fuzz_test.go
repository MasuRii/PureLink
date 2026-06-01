package endpoint

import "testing"

func FuzzParse(f *testing.F) {
	seeds := []string{
		"192.0.2.1:443",
		"example.com:8080",
		"[::1]:443",
		"10.0.0.1",
		"",
		"bad",
		"host:-1",
		"[::1",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		_, _ = Parse(raw)
	})
}
