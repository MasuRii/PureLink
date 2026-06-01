package v2rayn

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	plerrors "github.com/MasuRii/PureLink/pkg/errors"
)

type Discovery struct {
	Root       string
	DBPath     string
	ConfigPath string
	BinConfig  string
	Valid      bool
}

func Discover(root string) (Discovery, error) {
	info, err := os.Stat(root)
	if err != nil {
		if os.IsNotExist(err) {
			return Discovery{}, fmt.Errorf("%w: %s", plerrors.ErrDirectoryNotFound, root)
		}
		return Discovery{}, err
	}
	if !info.IsDir() {
		return Discovery{}, fmt.Errorf("%w: %s", plerrors.ErrDirectoryNotFound, root)
	}
	root = filepath.Clean(root)
	db := filepath.Join(root, "guiConfigs", "guiNDB.db")
	if hasSQLiteMagic(db) {
		return Discovery{Root: root, DBPath: db, Valid: true}, nil
	}
	cfg := filepath.Join(root, "guiConfigs", "guiNConfig.json")
	if hasJSONKey(cfg, "IndexId") {
		return Discovery{Root: root, ConfigPath: cfg, Valid: true}, nil
	}
	bin := filepath.Join(root, "binConfigs", "config.json")
	if hasJSONKey(bin, "outbounds") || hasJSONKey(bin, "inbounds") {
		return Discovery{Root: root, BinConfig: bin, Valid: true}, nil
	}
	return Discovery{}, fmt.Errorf("%w: %s", plerrors.ErrV2rayNNotDetected, root)
}

func hasSQLiteMagic(path string) bool {
	f, err := os.Open(path) // #nosec G304 -- CLI v2rayN scan intentionally reads discovered config files from user-specified directory.
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	buf := make([]byte, 16)
	_, err = f.Read(buf)
	return err == nil && bytes.Equal(buf, []byte("SQLite format 3\x00"))
}

func hasJSONKey(path, key string) bool {
	b, err := os.ReadFile(path) // #nosec G304 -- CLI v2rayN scan intentionally reads discovered config files from user-specified directory.
	if err != nil {
		return false
	}
	var m map[string]interface{}
	if json.Unmarshal(b, &m) != nil {
		return false
	}
	_, ok := m[key]
	return ok
}
