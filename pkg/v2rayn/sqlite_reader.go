package v2rayn

import (
	"database/sql"
	"fmt"
	"os"

	plerrors "github.com/MasuRii/PureLink/pkg/errors"
	_ "modernc.org/sqlite"
)

func ReadProfiles(dbPath string) ([]ImportedEndpoint, error) {
	if _, err := os.Stat(dbPath); err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("%w: %s", plerrors.ErrV2rayNDBNotFound, dbPath)
		}
		return nil, err
	}
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	defer func() { _ = db.Close() }()

	subs := map[string]string{}
	if rows, err := db.Query(`SELECT Id, Remarks, Enabled FROM SubItem WHERE Enabled = 1`); err == nil {
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var id, remarks string
			var enabled int
			if rows.Scan(&id, &remarks, &enabled) == nil && enabled == 1 {
				subs[id] = remarks
			}
		}
	}

	rows, err := db.Query(`SELECT ConfigType, Address, Port, Remarks, Subid FROM ProfileItem WHERE ConfigType NOT IN (2, 101, 102) AND Address IS NOT NULL AND Address != '' AND Port > 0 AND Port < 65536`)
	if err != nil {
		return nil, fmt.Errorf("read profiles: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []ImportedEndpoint
	for rows.Next() {
		var configType, port int
		var address, remarks, subid string
		if err := rows.Scan(&configType, &address, &port, &remarks, &subid); err != nil {
			return nil, fmt.Errorf("scan profile: %w", err)
		}
		protocol, ok := ProtocolForConfigType(configType)
		if !ok {
			continue
		}
		if ep, ok := NewImported(protocol, address, port, remarks, subs[subid], "v2rayn_db"); ok {
			out = append(out, ep)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate profiles: %w", err)
	}
	return out, nil
}
