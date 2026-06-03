package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	plerrors "github.com/MasuRii/PureLink/pkg/errors"
)

func TestLoadEnvOverride(t *testing.T) {
	t.Setenv("PURELINK_FORMAT", "json")
	t.Setenv("PURELINK_WORKERS", "3")
	t.Setenv("PURELINK_TIMEOUT", "2")
	t.Setenv("PURELINK_NO_COLOR", "true")
	v := NewViper()
	cfg, err := Load(v)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Format != "json" || cfg.Workers != 3 || cfg.Timeout != 2*time.Second || !cfg.NoColor {
		t.Fatalf("env overrides not loaded: %+v", cfg)
	}
}

func TestValidateAcceptsFormatsAndBoundaries(t *testing.T) {
	for _, format := range []string{"table", "json", "csv", "md"} {
		cfg := Default()
		cfg.Format = format
		cfg.Workers = 1
		cfg.Timeout = time.Second
		if err := Validate(cfg); err != nil {
			t.Fatalf("Validate minimum boundary format %s: %v", format, err)
		}
		cfg.Workers = 256
		cfg.Timeout = 5 * time.Minute
		if err := Validate(cfg); err != nil {
			t.Fatalf("Validate maximum boundary format %s: %v", format, err)
		}
	}
}

func TestValidateInvalidContent(t *testing.T) {
	cases := []struct {
		name  string
		mut   func(*Config)
		field string
	}{
		{"format", func(c *Config) { c.Format = "xml" }, "format"},
		{"workers low", func(c *Config) { c.Workers = 0 }, "workers"},
		{"workers high", func(c *Config) { c.Workers = 257 }, "workers"},
		{"timeout low", func(c *Config) { c.Timeout = time.Millisecond }, "timeout"},
		{"timeout high", func(c *Config) { c.Timeout = 6 * time.Minute }, "timeout"},
		{"unknown provider", func(c *Config) { c.Providers.Abuse = []string{"unknown-provider"} }, "providers"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Default()
			tc.mut(cfg)
			err := Validate(cfg)
			if !errors.Is(err, plerrors.ErrInvalidConfig) {
				t.Fatalf("expected ErrInvalidConfig, got %v", err)
			}
			var ve *plerrors.ValidationError
			if !errors.As(err, &ve) || ve.Field != tc.field {
				t.Fatalf("expected %s validation error, got %v", tc.field, err)
			}
		})
	}
}

func TestReadConfigAndLoadExplicitFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "purelink.yaml")
	body := strings.Join([]string{
		"format: csv",
		"timeout: 2s",
		"workers: 2",
		"no_color: true",
		"providers:",
		"  abuse: [ipapi.is, iplogs]",
		"  purity: [ipapi.is]",
		"",
	}, "\n")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	v := NewViper()
	if err := ReadConfig(v, path); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(v)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Format != "csv" || cfg.Timeout != 2*time.Second || cfg.Workers != 2 || !cfg.NoColor || len(cfg.Providers.Abuse) != 2 || cfg.Providers.Purity[0] != "ipapi.is" {
		t.Fatalf("unexpected config loaded from file: %+v", cfg)
	}
}

func TestReadConfigInvalidExplicitFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "broken.yaml")
	if err := os.WriteFile(path, []byte("format: [not-valid\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ReadConfig(NewViper(), path); !errors.Is(err, plerrors.ErrInvalidConfig) {
		t.Fatalf("expected invalid config error, got %v", err)
	}
}

func TestReadConfigMissingDefaultIsAllowed(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir)
	t.Chdir(dir)
	v := NewViper()
	v.SetConfigName("definitely-not-present")
	v.SetConfigType("yaml")
	v.AddConfigPath(t.TempDir())
	if err := ReadConfig(v, ""); err != nil {
		t.Fatalf("missing implicit config should be ignored: %v", err)
	}
}
