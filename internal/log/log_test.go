package log

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
)

func TestRedact(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"supersecret", "[REDACTED]"},
		{"token-abc-123", "[REDACTED]"},
		{"", ""},
	}
	for _, tt := range tests {
		got := Redact(tt.input)
		if got != tt.want {
			t.Errorf("Redact(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestRedactKey(t *testing.T) {
	tests := []struct {
		key  []byte
		want string
	}{
		{[]byte("0123456789abcdef"), "[REDACTED:16 bytes]"},
		{make([]byte, 32), "[REDACTED:32 bytes]"},
		{[]byte{}, "[REDACTED:0 bytes]"},
		{nil, "[REDACTED:0 bytes]"},
	}
	for _, tt := range tests {
		got := RedactKey(tt.key)
		if got != tt.want {
			t.Errorf("RedactKey(%d bytes) = %q, want %q", len(tt.key), got, tt.want)
		}
	}
}

// TestLogPEMRedaction asserts that log helpers do not emit PEM key material.
// The log package uses slog, which writes to the default handler (stderr).
// We replace the default slog handler with one backed by a bytes.Buffer so we
// can inspect the output without relying on OS-level stderr capture.
func TestLogPEMRedaction(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})
	old := slog.Default()
	slog.SetDefault(slog.New(handler))
	defer slog.SetDefault(old)

	// fakePEM is a sentinel that actually looks like PEM key material.
	// Using a real PEM-shaped value ensures the absence assertion is not vacuously
	// true — Redact() must do real work to remove it.
	fakePEM := "-----BEGIN FAKE PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7\n-----END FAKE PRIVATE KEY-----"
	ctx := context.Background()

	// Log the fake PEM through Redact() — the test checks both that the PEM
	// sentinel is gone (redaction worked) and that a [REDACTED] marker appears
	// (Redact() is not a no-op that silently swallows input).
	Info(ctx, "test", "private_key", Redact(fakePEM))
	Warn(ctx, "test", "private_key", Redact(fakePEM))
	Error(ctx, "test", "private_key", Redact(fakePEM))
	Debug(ctx, "test", "private_key", Redact(fakePEM))

	output := buf.String()
	if strings.Contains(output, "-----BEGIN") {
		t.Errorf("log output contains PEM header (secret leaked):\n%s", output)
	}
	if strings.Contains(output, "PRIVATE KEY") {
		t.Errorf("log output contains PRIVATE KEY text (secret leaked):\n%s", output)
	}
	if !strings.Contains(output, "[REDACTED]") {
		t.Errorf("log output missing [REDACTED] marker — Redact() may be a no-op:\n%s", output)
	}
}

func TestLogFunctions_DoNotPanic(t *testing.T) {
	ctx := context.Background()
	// These should not panic; they delegate to slog which writes to discard by default in tests
	Info(ctx, "info message", "key", "value")
	Warn(ctx, "warn message", "key", "value")
	Error(ctx, "error message", "key", "value")
	Debug(ctx, "debug message", "key", "value")
}
