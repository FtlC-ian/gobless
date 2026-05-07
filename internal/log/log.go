// Package log provides a thin structured logging wrapper over log/slog with
// context-aware helpers and utilities for redacting sensitive values from logs.
package log

import (
	"context"
	"fmt"
	"log/slog"
)

// Info logs a message at INFO level with optional key-value pairs.
func Info(ctx context.Context, msg string, args ...any) {
	slog.InfoContext(ctx, msg, args...)
}

// Warn logs a message at WARN level with optional key-value pairs.
func Warn(ctx context.Context, msg string, args ...any) {
	slog.WarnContext(ctx, msg, args...)
}

// Error logs a message at ERROR level with optional key-value pairs.
func Error(ctx context.Context, msg string, args ...any) {
	slog.ErrorContext(ctx, msg, args...)
}

// Debug logs a message at DEBUG level with optional key-value pairs.
func Debug(ctx context.Context, msg string, args ...any) {
	slog.DebugContext(ctx, msg, args...)
}

// Redact returns "[REDACTED]" for any non-empty string. This should be used
// whenever key material, tokens, secrets, or other sensitive strings would
// otherwise appear in a log line.
//
// An empty string is returned as-is to preserve the signal that a value was
// absent (e.g. an unset config field).
func Redact(s string) string {
	if s == "" {
		return s
	}
	return "[REDACTED]"
}

// RedactKey redacts key bytes from log output, showing only the length.
// Use this when logging operations involving key material.
//
// Example output: "[REDACTED:32 bytes]"
func RedactKey(key []byte) string {
	if len(key) == 0 {
		return "[REDACTED:0 bytes]"
	}
	return fmt.Sprintf("[REDACTED:%d bytes]", len(key))
}
