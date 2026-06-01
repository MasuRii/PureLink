package app

import (
	"context"
	stderrors "errors"
	"log/slog"
	"os"
	"regexp"
	"strings"
)

func NewLogger(verbose bool, format string) *slog.Logger {
	level := slog.LevelInfo
	if verbose {
		level = slog.LevelDebug
	}
	opts := &slog.HandlerOptions{Level: level}
	if format == "json" {
		return slog.New(slog.NewJSONHandler(os.Stderr, opts))
	}
	return slog.New(slog.NewTextHandler(os.Stderr, opts))
}

func SanitizeForLog(args ...any) []any {
	out := make([]any, len(args))
	redactNext := false
	for i, arg := range args {
		if redactNext {
			out[i] = redactedValue(arg)
			redactNext = false
			continue
		}
		switch v := arg.(type) {
		case string:
			out[i] = redactString(v)
			redactNext = isSensitiveKey(v)
		case error:
			out[i] = stderrors.New(redactString(v.Error()))
		case slog.Attr:
			out[i] = sanitizeAttr(v)
		default:
			out[i] = arg
		}
	}
	return out
}

var logPatterns = []*regexp.Regexp{
	regexp.MustCompile(`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`),
	regexp.MustCompile(`(?i)(https?://)[^\s]*(subscribe|token|key|uuid)[^\s]*`),
	regexp.MustCompile(`(?i)(password|token|key|secret)[=:]\S+`),
}

func redactString(s string) string {
	for _, re := range logPatterns {
		s = re.ReplaceAllString(s, "[REDACTED]")
	}
	return s
}

func isSensitiveKey(key string) bool {
	normalized := strings.ToLower(strings.TrimSpace(key))
	normalized = strings.Trim(normalized, "-_. ")
	if normalized == "key" || strings.HasSuffix(normalized, "_key") || strings.HasSuffix(normalized, "-key") || strings.HasSuffix(normalized, ".key") {
		return true
	}
	return strings.Contains(normalized, "password") || strings.Contains(normalized, "token") || strings.Contains(normalized, "secret")
}

func redactedValue(v any) any {
	switch v.(type) {
	case error:
		return stderrors.New("[REDACTED]")
	case slog.Attr:
		return slog.String("[REDACTED]", "[REDACTED]")
	default:
		return "[REDACTED]"
	}
}

func sanitizeAttr(attr slog.Attr) slog.Attr {
	if isSensitiveKey(attr.Key) {
		attr.Value = slog.StringValue("[REDACTED]")
		return attr
	}
	if attr.Value.Kind() == slog.KindString {
		attr.Value = slog.StringValue(redactString(attr.Value.String()))
	}
	return attr
}

func Debug(logger *slog.Logger, msg string, args ...any) {
	logger.DebugContext(context.Background(), msg, SanitizeForLog(args...)...)
}
func Warn(logger *slog.Logger, msg string, args ...any) {
	logger.WarnContext(context.Background(), msg, SanitizeForLog(args...)...)
}
