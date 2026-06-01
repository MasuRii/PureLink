package abuse

import "context"

// Result contains legacy aggregate abuse reputation data.
type Result struct {
	Score      int      `json:"score"`
	Reports    int      `json:"reports"`
	Categories []string `json:"categories,omitempty"`
	LastReport string   `json:"last_report,omitempty"`
	Confidence float64  `json:"confidence"`
}

// Reporter provides a backward-compatible zero-network abuse lookup.
type Reporter struct{}

func NewReporter() *Reporter { return &Reporter{} }

func (r *Reporter) Check(ip string) (*Result, error) {
	return &Result{Score: 0, Reports: 0, Categories: []string{}, Confidence: 1.0}, nil
}

func (r *Reporter) CheckContext(ctx context.Context, ip string) (*ProviderResult, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
		return &ProviderResult{Score: 0, Confidence: 1.0}, nil
	}
}
