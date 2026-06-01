package v2rayn

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDiscoverSQLite(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "guiConfigs")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	dbPath := filepath.Join(dir, "guiNDB.db")
	if err := os.WriteFile(dbPath, append([]byte("SQLite format 3\x00"), []byte("rest")...), 0o600); err != nil {
		t.Fatal(err)
	}
	disc, err := Discover(root)
	if err != nil {
		t.Fatal(err)
	}
	if !disc.Valid || disc.DBPath != dbPath {
		t.Fatalf("got %+v", disc)
	}
}
