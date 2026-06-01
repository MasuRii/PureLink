package importer

import (
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"testing"

	plerrors "github.com/MasuRii/PureLink/pkg/errors"
	"github.com/MasuRii/PureLink/pkg/v2rayn"
	_ "modernc.org/sqlite"
)

func TestImportLinkFile_Success(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "links.txt")
	content := `vmess://eyJhZGQiOiIxOTIuMC4yLjEiLCJwb3J0IjoiNDQzIiwicHMiOiJ0ZXN0In0=
vless://placeholder@192.0.2.2:443#test-vless
trojan://cred@192.0.2.3:443#test-trojan
ss://YWVzLTI1Ni1nY206Y3JlZEBAMTkyLjAuMi40OjgzODg=#test-ss
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	eps, err := ImportLinkFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(eps) != 4 {
		t.Fatalf("expected 4 endpoints, got %d", len(eps))
	}
	protocols := map[string]int{}
	for _, ep := range eps {
		protocols[ep.Protocol]++
	}
	if protocols["vmess"] != 1 || protocols["vless"] != 1 || protocols["trojan"] != 1 || protocols["shadowsocks"] != 1 {
		t.Fatalf("unexpected protocols: %v", protocols)
	}
}

func TestImportLinkFile_NotFound(t *testing.T) {
	_, err := ImportLinkFile("/nonexistent/path/links.txt")
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, plerrors.ErrFileNotFound) {
		t.Fatalf("expected ErrFileNotFound, got %v", err)
	}
}

func TestImportLinkFile_Dedup(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dup.txt")
	content := `vless://a@192.0.2.1:443#label1
vless://b@192.0.2.1:443#label2
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	eps, err := ImportLinkFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(eps) != 1 {
		t.Fatalf("expected 1 deduped endpoint, got %d", len(eps))
	}
}

func TestDeduplicateImported(t *testing.T) {
	eps := []v2rayn.ImportedEndpoint{
		{Protocol: "vless", Host: "192.0.2.1", Port: 443, Source: "s1"},
		{Protocol: "vless", Host: "192.0.2.1", Port: 443, Source: "s2"},
		{Protocol: "vmess", Host: "192.0.2.2", Port: 443, Source: "s3"},
	}
	got := DeduplicateImported(eps)
	if len(got) != 2 {
		t.Fatalf("expected 2 unique, got %d", len(got))
	}
}

func TestImportV2rayN_Success(t *testing.T) {
	root := t.TempDir()
	guiDir := filepath.Join(root, "guiConfigs")
	if err := os.MkdirAll(guiDir, 0o755); err != nil {
		t.Fatal(err)
	}
	dbPath := filepath.Join(guiDir, "guiNDB.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	ddl := []string{
		`CREATE TABLE ProfileItem (IndexId TEXT PRIMARY KEY, ConfigType INTEGER NOT NULL, Address TEXT NOT NULL, Port INTEGER NOT NULL, Remarks TEXT NOT NULL, Subid TEXT NOT NULL, Network TEXT NOT NULL, StreamSecurity TEXT, Password TEXT NOT NULL, Username TEXT NOT NULL, ProtoExtra TEXT, TransportExtra TEXT);`,
		`CREATE TABLE SubItem (Id TEXT PRIMARY KEY, Remarks TEXT, Url TEXT NOT NULL, Enabled INTEGER NOT NULL DEFAULT 1);`,
		`INSERT INTO SubItem (Id, Remarks, Url, Enabled) VALUES ('sub1', 'TestSub', 'https://example.com/placeholder', 1);`,
		`INSERT INTO ProfileItem (IndexId, ConfigType, Address, Port, Remarks, Subid, Network, Password, Username, ProtoExtra, TransportExtra) VALUES ('p1', 5, '192.0.2.10', 8443, 'test-vless', 'sub1', 'tcp', '', '', '', '');`,
		`INSERT INTO ProfileItem (IndexId, ConfigType, Address, Port, Remarks, Subid, Network, Password, Username, ProtoExtra, TransportExtra) VALUES ('p2', 2, '/tmp/custom', 0, 'skip', '', '', '', '', '', '');`,
	}
	for _, stmt := range ddl {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatal(err)
		}
	}
	_ = db.Close()

	eps, err := ImportV2rayN(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(eps) != 1 {
		t.Fatalf("expected 1 endpoint, got %d", len(eps))
	}
	if eps[0].Protocol != "vless" || eps[0].Host != "192.0.2.10" || eps[0].Port != 8443 || eps[0].SubGroup != "TestSub" {
		t.Fatalf("unexpected endpoint: %+v", eps[0])
	}
}

func TestImportV2rayN_NoDB(t *testing.T) {
	root := t.TempDir()
	guiDir := filepath.Join(root, "guiConfigs")
	if err := os.MkdirAll(guiDir, 0o755); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(guiDir, "guiNConfig.json")
	if err := os.WriteFile(cfgPath, []byte(`{"IndexId":"x"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	eps, err := ImportV2rayN(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(eps) != 0 {
		t.Fatalf("expected 0 endpoints, got %d", len(eps))
	}
}

func TestImportV2rayN_NotDetected(t *testing.T) {
	root := t.TempDir()
	_, err := ImportV2rayN(root)
	if err == nil {
		t.Fatal("expected error for undetected v2rayN dir")
	}
	if !errors.Is(err, plerrors.ErrV2rayNNotDetected) {
		t.Fatalf("expected ErrV2rayNNotDetected, got %v", err)
	}
}
