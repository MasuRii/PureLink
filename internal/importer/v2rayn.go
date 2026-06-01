package importer

import (
	"github.com/MasuRii/PureLink/pkg/v2rayn"
)

func ImportV2rayN(dir string) ([]v2rayn.ImportedEndpoint, error) {
	disc, err := v2rayn.Discover(dir)
	if err != nil {
		return nil, err
	}
	if disc.DBPath == "" {
		return []v2rayn.ImportedEndpoint{}, nil
	}
	eps, err := v2rayn.ReadProfiles(disc.DBPath)
	if err != nil {
		return nil, err
	}
	return DeduplicateImported(eps), nil
}

func DeduplicateImported(eps []v2rayn.ImportedEndpoint) []v2rayn.ImportedEndpoint {
	seen := map[string]struct{}{}
	out := []v2rayn.ImportedEndpoint{}
	for _, ep := range eps {
		key := ep.ToEndpoint().Normalize()
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, ep)
	}
	return out
}
