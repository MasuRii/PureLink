package engine

func Summarize(items []BatchItem) BatchSummary {
	s := BatchSummary{Total: len(items), Processed: len(items)}
	var latencyTotal int64
	for _, item := range items {
		if item.Reachable {
			s.Reachable++
			latencyTotal += item.LatencyMs
		} else {
			s.Unreachable++
		}
		if item.AbuseScore >= 50 {
			s.Abusive++
		}
		switch item.Purity {
		case "clean":
			if item.AbuseScore < 50 {
				s.Clean++
			}
		case "suspicious", "vpn_likely", "vpn_detected":
			s.Suspicious++
		}
		if len(item.ProviderErrs) > 0 || !item.Reachable {
			s.Errors++
		}
	}
	if s.Reachable > 0 {
		s.AvgLatency = latencyTotal / int64(s.Reachable)
	}
	return s
}
