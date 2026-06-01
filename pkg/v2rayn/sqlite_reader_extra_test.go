package v2rayn

import (
	"database/sql"
	"errors"
	"path/filepath"
	"testing"

	plerrors "github.com/MasuRii/PureLink/pkg/errors"
	_ "modernc.org/sqlite"
)

func TestReadProfiles_MissingDB(t *testing.T) {
	_, err := ReadProfiles("/nonexistent/db.db")
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, plerrors.ErrV2rayNDBNotFound) {
		t.Fatalf("expected ErrV2rayNDBNotFound, got %v", err)
	}
}

func TestReadProfiles_Empty(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE ProfileItem (IndexId TEXT PRIMARY KEY, ConfigType INTEGER NOT NULL, Address TEXT NOT NULL, Port INTEGER NOT NULL, Remarks TEXT NOT NULL, Subid TEXT NOT NULL, Network TEXT NOT NULL, StreamSecurity TEXT, Password TEXT NOT NULL, Username TEXT NOT NULL, ProtoExtra TEXT, TransportExtra TEXT);`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE SubItem (Id TEXT PRIMARY KEY, Remarks TEXT, Url TEXT NOT NULL, Enabled INTEGER NOT NULL DEFAULT 1);`); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()

	eps, err := ReadProfiles(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(eps) != 0 {
		t.Fatalf("expected 0 endpoints, got %d", len(eps))
	}
}

func TestReadProfiles_MultipleAndFilter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "multi.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	ddl := []string{
		`CREATE TABLE ProfileItem (IndexId TEXT PRIMARY KEY, ConfigType INTEGER NOT NULL, Address TEXT NOT NULL, Port INTEGER NOT NULL, Remarks TEXT NOT NULL, Subid TEXT NOT NULL, Network TEXT NOT NULL, StreamSecurity TEXT, Password TEXT NOT NULL, Username TEXT NOT NULL, ProtoExtra TEXT, TransportExtra TEXT);`,
		`CREATE TABLE SubItem (Id TEXT PRIMARY KEY, Remarks TEXT, Url TEXT NOT NULL, Enabled INTEGER NOT NULL DEFAULT 1);`,
		`INSERT INTO SubItem (Id, Remarks, Url, Enabled) VALUES ('sub1', 'GroupA', 'https://example.com', 1);`,
		`INSERT INTO ProfileItem (IndexId, ConfigType, Address, Port, Remarks, Subid, Network, Password, Username, ProtoExtra, TransportExtra) VALUES ('p1', 1, '192.0.2.1', 443, 'vmess1', 'sub1', 'ws', '', '', '', '');`,
		`INSERT INTO ProfileItem (IndexId, ConfigType, Address, Port, Remarks, Subid, Network, Password, Username, ProtoExtra, TransportExtra) VALUES ('p2', 5, '192.0.2.2', 443, 'vless1', 'sub1', 'tcp', '', '', '', '');`,
		`INSERT INTO ProfileItem (IndexId, ConfigType, Address, Port, Remarks, Subid, Network, Password, Username, ProtoExtra, TransportExtra) VALUES ('p3', 2, '/tmp/custom', 0, 'skip', '', '', '', '', '', '');`,
		`INSERT INTO ProfileItem (IndexId, ConfigType, Address, Port, Remarks, Subid, Network, Password, Username, ProtoExtra, TransportExtra) VALUES ('p4', 101, '192.0.2.4', 443, 'policy', '', '', '', '', '', '');`,
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
	if len(eps) != 2 {
		t.Fatalf("expected 2 endpoints, got %d", len(eps))
	}
}
