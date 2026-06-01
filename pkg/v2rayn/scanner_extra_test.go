package v2rayn

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	plerrors "github.com/MasuRii/PureLink/pkg/errors"
)

func TestDiscover_ConfigJSON(t *testing.T) {
	root := t.TempDir()
	guiDir := filepath.Join(root, "guiConfigs")
	if err := os.MkdirAll(guiDir, 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(guiDir, "guiNConfig.json")
	if err := os.WriteFile(cfg, []byte(`{"IndexId":"abc"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	disc, err := Discover(root)
	if err != nil {
		t.Fatal(err)
	}
	if !disc.Valid || disc.ConfigPath != cfg {
		t.Fatalf("got %+v", disc)
	}
}

func TestDiscover_BinConfig(t *testing.T) {
	root := t.TempDir()
	binDir := filepath.Join(root, "binConfigs")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(binDir, "config.json")
	if err := os.WriteFile(cfg, []byte(`{"outbounds":[{"protocol":"vmess"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	disc, err := Discover(root)
	if err != nil {
		t.Fatal(err)
	}
	if !disc.Valid || disc.BinConfig != cfg {
		t.Fatalf("got %+v", disc)
	}
}

func TestDiscover_NotFound(t *testing.T) {
	_, err := Discover("/nonexistent/path")
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, plerrors.ErrDirectoryNotFound) {
		t.Fatalf("expected ErrDirectoryNotFound, got %v", err)
	}
}

func TestDiscover_FileNotDir(t *testing.T) {
	f := filepath.Join(t.TempDir(), "file.txt")
	if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Discover(f)
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, plerrors.ErrDirectoryNotFound) {
		t.Fatalf("expected ErrDirectoryNotFound, got %v", err)
	}
}
