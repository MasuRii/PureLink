package endpoint

import "testing"

func BenchmarkParse(b *testing.B) {
	inputs := []string{
		"192.0.2.1:443",
		"example.com:8080",
		"[::1]:443",
		"10.0.0.1",
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, in := range inputs {
			_, _ = Parse(in)
		}
	}
}

func BenchmarkNormalize(b *testing.B) {
	ep := Endpoint{Host: "Example.COM", Port: 443}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ep.Normalize()
	}
}
