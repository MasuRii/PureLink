package abuse

// Reporter provides abuse reputation lookups.
type Reporter struct{}

// Result contains abuse reputation data.
type Result struct {
	Score      int // 0-100, higher means more abusive
	Reports    int // number of abuse reports
	Categories []string
	LastReport string
	Confidence float64
}

// NewReporter creates a new abuse reporter.
func NewReporter() *Reporter {
	return &Reporter{}
}

// Check returns a mock abuse result for the given IP.
func (r *Reporter) Check(ip string) (*Result, error) {
	// Placeholder: integrate with AbuseIPDB, VirusTotal, etc.
	return &Result{
		Score:      0,
		Reports:    0,
		Categories: []string{},
		Confidence: 1.0,
	}, nil
}
