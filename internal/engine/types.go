package engine

import "github.com/MasuRii/PureLink/pkg/endpoint"

type BatchItem struct {
	Endpoint     endpoint.Endpoint `json:"endpoint"`
	Reachable    bool              `json:"reachable"`
	LatencyMs    int64             `json:"latency_ms"`
	AbuseScore   int               `json:"abuse_score"`
	Purity       string            `json:"purity"`
	ProviderErrs []string          `json:"provider_errors,omitempty"`
}

type BatchSummary struct {
	Total       int   `json:"total"`
	Processed   int   `json:"processed"`
	Reachable   int   `json:"reachable"`
	Unreachable int   `json:"unreachable"`
	Abusive     int   `json:"abusive"`
	Suspicious  int   `json:"suspicious"`
	Clean       int   `json:"clean"`
	AvgLatency  int64 `json:"avg_latency_ms"`
	Errors      int   `json:"errors"`
}

type BatchResult struct {
	Items   []BatchItem  `json:"items"`
	Summary BatchSummary `json:"summary"`
}

type CollisionSource struct {
	File string `json:"file"`
	Line int    `json:"line"`
}

type DedupeResult struct {
	Unique      []endpoint.Endpoint          `json:"unique"`
	Collisions  map[string][]CollisionSource `json:"collisions,omitempty"`
	UniqueCount int                          `json:"unique_count"`
	TotalCount  int                          `json:"total_count"`
}

type SourceEndpoint struct {
	Endpoint endpoint.Endpoint
	Source   CollisionSource
}
