package engine

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/MasuRii/PureLink/pkg/endpoint"
	plerrors "github.com/MasuRii/PureLink/pkg/errors"
	"github.com/MasuRii/PureLink/pkg/v2rayn"
)

func ParseReader(r io.Reader, sourceName string) ([]SourceEndpoint, error) {
	var out []SourceEndpoint
	s := bufio.NewScanner(r)
	lineNo := 0
	for s.Scan() {
		lineNo++
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		eps, err := parseLine(line)
		if err != nil {
			return nil, fmt.Errorf("%w: %s:%d", err, sourceName, lineNo)
		}
		for _, ep := range eps {
			out = append(out, SourceEndpoint{Endpoint: ep, Source: CollisionSource{File: sourceName, Line: lineNo}})
		}
	}
	if err := s.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, plerrors.ErrBatchEmpty
	}
	return out, nil
}

func ParseFile(path string) ([]SourceEndpoint, error) {
	f, err := os.Open(path) // #nosec G304 -- CLI batch intentionally reads user-specified endpoint files.
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("%w: %s", plerrors.ErrFileNotFound, path)
		}
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return ParseReader(f, path)
}

func parseLine(line string) ([]endpoint.Endpoint, error) {
	if strings.Contains(line, "://") || strings.Contains(line, "[Peer]") {
		if imported := v2rayn.ParseContent(line); len(imported) > 0 {
			out := make([]endpoint.Endpoint, 0, len(imported))
			for _, im := range imported {
				out = append(out, im.ToEndpoint())
			}
			return out, nil
		}
	}
	if strings.HasPrefix(line, "{") {
		var row struct {
			Host string `json:"host"`
			Port int    `json:"port"`
		}
		if json.Unmarshal([]byte(line), &row) == nil && row.Host != "" && row.Port > 0 {
			ep, err := endpoint.ParseWithDefault(fmt.Sprintf("%s:%d", row.Host, row.Port), 0)
			if err == nil {
				return []endpoint.Endpoint{*ep}, nil
			}
		}
	}
	if strings.Contains(line, ",") {
		rec, err := csv.NewReader(strings.NewReader(line)).Read()
		if err == nil && len(rec) >= 2 {
			p, err := strconv.Atoi(strings.TrimSpace(rec[1]))
			if err == nil {
				ep, err := endpoint.ParseWithDefault(fmt.Sprintf("%s:%d", strings.TrimSpace(rec[0]), p), 0)
				if err == nil {
					return []endpoint.Endpoint{*ep}, nil
				}
			}
		}
	}
	ep, err := endpoint.Parse(line)
	if err != nil {
		return nil, err
	}
	return []endpoint.Endpoint{*ep}, nil
}
