package engine

import (
	"strings"
	"testing"
)

func FuzzParseReader(f *testing.F) {
	seeds := []string{
		"example.com:443\n",
		"# comment\n192.0.2.1:8080\n",
		`{"host":"192.0.2.2","port":8443}` + "\n",
		"192.0.2.3,443,label\n",
		"vless://placeholder@192.0.2.4:443#seed\n",
		"\n\t\n",
	}
	for _, seed := range seeds {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		_, _ = ParseReader(strings.NewReader(input), "fuzz")
	})
}
