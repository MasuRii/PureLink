package engine

import "github.com/MasuRii/PureLink/pkg/endpoint"

func Dedupe(inputs []SourceEndpoint) DedupeResult {
	seen := map[string]int{}
	unique := []endpoint.Endpoint{}
	collisions := map[string][]CollisionSource{}
	for _, item := range inputs {
		key := item.Endpoint.Normalize()
		if first, ok := seen[key]; ok {
			if _, exists := collisions[key]; !exists {
				collisions[key] = []CollisionSource{inputs[first].Source}
			}
			collisions[key] = append(collisions[key], item.Source)
			continue
		}
		seen[key] = len(unique)
		unique = append(unique, item.Endpoint)
	}
	if len(collisions) == 0 {
		collisions = nil
	}
	return DedupeResult{Unique: unique, Collisions: collisions, UniqueCount: len(unique), TotalCount: len(inputs)}
}

func DedupeFiles(paths []string) (DedupeResult, error) {
	var all []SourceEndpoint
	for _, path := range paths {
		eps, err := ParseFile(path)
		if err != nil {
			return DedupeResult{}, err
		}
		all = append(all, eps...)
	}
	return Dedupe(all), nil
}
