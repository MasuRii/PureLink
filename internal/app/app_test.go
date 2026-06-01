package app

import (
	"bytes"
	"errors"
	"log/slog"
	"strings"
	"testing"
)

func TestNewLogger_NoPanic(t *testing.T) {
	cases := []struct {
		verbose bool
		format  string
	}{
		{false, "json"},
		{true, "json"},
		{false, "text"},
		{true, "text"},
	}
	for _, c := range cases {
		logger := NewLogger(c.verbose, c.format)
		if logger == nil {
			t.Fatal("expected non-nil logger")
		}
	}
}

func TestSanitizeForLog_RedactsUUID(t *testing.T) {
	uuid := "12345678-1234-1234-1234-123456789abc"
	got := SanitizeForLog("id", uuid)
	if len(got) != 2 {
		t.Fatalf("expected 2 args, got %d", len(got))
	}
	s, ok := got[1].(string)
	if !ok {
		t.Fatalf("expected string, got %T", got[1])
	}
	if !strings.Contains(s, "[REDACTED]") {
		t.Fatalf("expected redaction, got %q", s)
	}
}

func TestSanitizeForLog_RedactsURL(t *testing.T) {
	in := "https://example.com/subscribe?token=SECRET"
	got := SanitizeForLog("url", in)
	s := got[1].(string)
	if strings.Contains(s, "SECRET") {
		t.Fatalf("secret leaked in %q", s)
	}
}

func TestSanitizeForLog_RedactsPassword(t *testing.T) {
	in := "password=SuperSecret123"
	got := SanitizeForLog("pw", in)
	s := got[1].(string)
	if !strings.Contains(s, "[REDACTED]") {
		t.Fatalf("expected redaction, got %q", s)
	}
}

func TestSanitizeForLog_PassesErrors(t *testing.T) {
	err := errors.New("password=secret123")
	got := SanitizeForLog(err)
	if len(got) != 1 {
		t.Fatal("expected 1 arg")
	}
	e, ok := got[0].(error)
	if !ok {
		t.Fatalf("expected error, got %T", got[0])
	}
	if !strings.Contains(e.Error(), "[REDACTED]") {
		t.Fatalf("expected redacted error, got %q", e.Error())
	}
}

func TestSanitizeForLog_RedactsSeparateKeyValuePairs(t *testing.T) {
	got := SanitizeForLog("password", "SuperSecret123", "count", 3, "api_key", "token-value")
	if got[1] != "[REDACTED]" || got[5] != "[REDACTED]" {
		t.Fatalf("expected structured secret values to be redacted: %+v", got)
	}
	if got[3] != 3 {
		t.Fatalf("non-sensitive structured value changed: %+v", got)
	}
}

func TestSanitizeForLog_RedactsSensitiveSlogAttr(t *testing.T) {
	got := SanitizeForLog(slog.String("token", "SecretToken123"))
	attr, ok := got[0].(slog.Attr)
	if !ok {
		t.Fatalf("expected slog.Attr, got %T", got[0])
	}
	if attr.Value.String() != "[REDACTED]" {
		t.Fatalf("expected attr value redacted, got %q", attr.Value.String())
	}
}

func TestSanitizeForLog_PassesOtherTypes(t *testing.T) {
	got := SanitizeForLog(42, true)
	if len(got) != 2 {
		t.Fatal("expected 2 args")
	}
	if got[0] != 42 || got[1] != true {
		t.Fatalf("unexpected values: %+v", got)
	}
}

func TestDebug_RedactsSeparateKeyValue(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	Debug(logger, "test", "password", "SuperSecret123")
	out := buf.String()
	if !strings.Contains(out, "[REDACTED]") {
		t.Fatalf("expected redaction in %q", out)
	}
	if strings.Contains(out, "SuperSecret123") {
		t.Fatalf("secret leaked in %q", out)
	}
}

func TestDebug_RedactsURL(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	Debug(logger, "test", "url", "https://example.com/subscribe?token=SECRET")
	out := buf.String()
	if !strings.Contains(out, "[REDACTED]") {
		t.Fatalf("expected redaction in %q", out)
	}
	if strings.Contains(out, "SECRET") {
		t.Fatalf("secret leaked in %q", out)
	}
}

func TestWarn_RedactsPassword(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))
	Warn(logger, "alert", "payload", "password=SuperSecret123")
	out := buf.String()
	if !strings.Contains(out, "[REDACTED]") {
		t.Fatalf("expected redaction in %q", out)
	}
	if strings.Contains(out, "SuperSecret123") {
		t.Fatalf("secret leaked in %q", out)
	}
}
