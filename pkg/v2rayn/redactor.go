package v2rayn

import "regexp"

const redacted = "***REDACTED***"

var redactPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(password|passwd|token|secret|key|uuid|id)=([^&\s]+)`),
	regexp.MustCompile(`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`),
	regexp.MustCompile(`(?i)https?://[^\s]+(?:subscribe|token|key|uuid)[^\s]*`),
}

func Redact(input string) string {
	out := input
	for _, re := range redactPatterns {
		out = re.ReplaceAllString(out, redacted)
	}
	return out
}
