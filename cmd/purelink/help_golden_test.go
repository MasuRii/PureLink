package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func assertCLIGolden(t *testing.T, name, got string) {
	t.Helper()
	want, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read golden %s: %v", name, err)
	}
	nGot := strings.ReplaceAll(got, "\r\n", "\n")
	nWant := strings.ReplaceAll(string(want), "\r\n", "\n")
	if !bytes.Equal([]byte(nGot), []byte(nWant)) {
		t.Fatalf("golden mismatch %s\n--- got ---\n%s\n--- want ---\n%s", name, nGot, nWant)
	}
}

func TestGoldenHelpText(t *testing.T) {
	tests := []struct {
		name   string
		args   []string
		golden string
	}{
		{"root", []string{"--help"}, "help.root.golden"},
		{"batch", []string{"batch", "--help"}, "help.batch.golden"},
		{"import-url", []string{"import", "url", "--help"}, "help.import.url.golden"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, _, err := execute(tt.args...)
			if err != nil {
				t.Fatal(err)
			}
			assertCLIGolden(t, tt.golden, out)
		})
	}
}
