package engine

import (
	"github.com/MasuRii/PureLink/pkg/abuse"
	"github.com/MasuRii/PureLink/pkg/endpoint"
)

type BatchItem struct {
	Endpoint endpoint.Endpoint `json:"endpoint"`
	Protocol string            `json:"protocol,omitempty"`
	// RawURI stores an original proxy share link only for explicit share-link
	// exports. It is excluded from JSON to avoid leaking embedded credentials.
	RawURI                  string                 `json:"-"`
	Country                 string                 `json:"country,omitempty"`
	CountryCode             string                 `json:"country_code,omitempty"`
	Reachable               bool                   `json:"reachable"`
	LatencyMs               int64                  `json:"latency_ms"`
	AbuseScore              int                    `json:"abuse_score"`
	Purity                  string                 `json:"purity"`
	SpeedMbps               float64                `json:"speed_mbps,omitempty"`
	ProviderSuccesses       int                    `json:"provider_successes,omitempty"`
	ProviderTotal           int                    `json:"provider_total,omitempty"`
	ProviderErrs            []string               `json:"provider_errors,omitempty"`
	ProviderResults         []abuse.ProviderResult `json:"-"`
	PendingProviderRetries  []string               `json:"-"`
	ProviderResolvedAddress string                 `json:"-"`
}

type BatchSummary struct {
	Total       int     `json:"total"`
	Processed   int     `json:"processed"`
	Reachable   int     `json:"reachable"`
	Unreachable int     `json:"unreachable"`
	Abusive     int     `json:"abusive"`
	Suspicious  int     `json:"suspicious"`
	Clean       int     `json:"clean"`
	AvgLatency  int64   `json:"avg_latency_ms"`
	SpeedMbps   float64 `json:"speed_mbps,omitempty"`
	Errors      int     `json:"errors"`
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
