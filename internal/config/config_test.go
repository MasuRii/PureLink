package config

import (
	"errors"
	"testing"

	plerrors "github.com/MasuRii/PureLink/pkg/errors"
)

func TestLoadEnvOverride(t *testing.T) {
	t.Setenv("PURELINK_FORMAT", "json")
	v := NewViper()
	cfg, err := Load(v)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Format != "json" {
		t.Fatalf("format=%s", cfg.Format)
	}
}

func TestValidateInvalidWorkers(t *testing.T) {
	cfg := Default()
	cfg.Workers = 0
	err := Validate(cfg)
	if !errors.Is(err, plerrors.ErrInvalidConfig) {
		t.Fatalf("expected ErrInvalidConfig, got %v", err)
	}
	var ve *plerrors.ValidationError
	if !errors.As(err, &ve) || ve.Field != "workers" {
		t.Fatalf("expected workers validation error, got %v", err)
	}
}
