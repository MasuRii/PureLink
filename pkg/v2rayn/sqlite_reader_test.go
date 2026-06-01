package v2rayn

import (
	"database/sql"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

func TestReadProfilesSynthetic(t *testing.T) {
	path := filepath.Join(t.TempDir(), "guiNDB.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ddl := []string{
		`CREATE TABLE ProfileItem (IndexId TEXT PRIMARY KEY, ConfigType INTEGER NOT NULL, Address TEXT NOT NULL, Port INTEGER NOT NULL, Remarks TEXT NOT NULL, Subid TEXT NOT NULL, Network TEXT NOT NULL, StreamSecurity TEXT, Password TEXT NOT NULL, Username TEXT NOT NULL, ProtoExtra TEXT, TransportExtra TEXT);`,
		`CREATE TABLE SubItem (Id TEXT PRIMARY KEY, Remarks TEXT, Url TEXT NOT NULL, Enabled INTEGER NOT NULL DEFAULT 1);`,
		`INSERT INTO SubItem (Id, Remarks, Url, Enabled) VALUES ('sub1', 'TestSub', 'https://example.com/placeholder', 1);`,
		`INSERT INTO ProfileItem (IndexId, ConfigType, Address, Port, Remarks, Subid, Network, Password, Username, ProtoExtra, TransportExtra) VALUES ('test-001', 1, '192.0.2.1', 443, 'test-vmess', 'sub1', 'ws', 'PLACEHOLDER', 'user', '{"key":"PLACEHOLDER"}', '{"path":"/placeholder"}');`,
		`INSERT INTO ProfileItem (IndexId, ConfigType, Address, Port, Remarks, Subid, Network, Password, Username, ProtoExtra, TransportExtra) VALUES ('skip-custom', 2, '/tmp/custom.json', 0, 'skip-me', '', '', '', '', '', '');`,
	}
	for _, stmt := range ddl {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatal(err)
		}
	}
	_ = db.Close()
	eps, err := ReadProfiles(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(eps) != 1 {
		t.Fatalf("expected 1 endpoint, got %d", len(eps))
	}
	got := eps[0]
	if got.Protocol != "vmess" || got.Host != "192.0.2.1" || got.Port != 443 || got.SubGroup != "TestSub" {
		t.Fatalf("got %+v", got)
	}
}
