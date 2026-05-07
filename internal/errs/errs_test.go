package errs

import (
	"errors"
	"strings"
	"testing"
)

func TestSentinelErrors(t *testing.T) {
	sentinels := []struct {
		name string
		err  error
	}{
		{"ErrUnauthorized", ErrUnauthorized},
		{"ErrInvalidRequest", ErrInvalidRequest},
		{"ErrInternalError", ErrInternalError},
		{"ErrAuditFailure", ErrAuditFailure},
	}
	for _, s := range sentinels {
		if s.err == nil {
			t.Errorf("%s is nil", s.name)
		}
	}
}

func TestWrap(t *testing.T) {
	base := errors.New("base error")
	wrapped := Wrap(base, "context message")

	if !errors.Is(wrapped, base) {
		t.Error("Wrap: wrapped error should unwrap to base via errors.Is")
	}
	if !strings.Contains(wrapped.Error(), "context message") {
		t.Errorf("Wrap: expected 'context message' in error string, got %q", wrapped.Error())
	}
	if !strings.Contains(wrapped.Error(), "base error") {
		t.Errorf("Wrap: expected 'base error' in error string, got %q", wrapped.Error())
	}
}

func TestWrap_NilError(t *testing.T) {
	got := Wrap(nil, "should be nil")
	if got != nil {
		t.Errorf("Wrap(nil, ...) = %v, want nil", got)
	}
}

func TestWrap_SentinelUnwrap(t *testing.T) {
	wrapped := Wrap(ErrInternalError, "database unavailable")
	if !errors.Is(wrapped, ErrInternalError) {
		t.Error("wrapped ErrInternalError should be detectable via errors.Is")
	}
}

func TestSafeMessage_InternalError(t *testing.T) {
	err := Wrap(ErrInternalError, "db: connection refused at /internal/path/db.go:42")
	msg := SafeMessage(err)
	if msg != "an internal error occurred" {
		t.Errorf("SafeMessage(ErrInternalError wrapped) = %q, want %q", msg, "an internal error occurred")
	}
	// Internal details must not leak
	if strings.Contains(msg, "connection refused") || strings.Contains(msg, "/internal/path") {
		t.Errorf("SafeMessage leaked internal detail: %q", msg)
	}
}

func TestSafeMessage_Unauthorized(t *testing.T) {
	msg := SafeMessage(ErrUnauthorized)
	if msg != "unauthorized" {
		t.Errorf("SafeMessage(ErrUnauthorized) = %q, want %q", msg, "unauthorized")
	}
}

func TestSafeMessage_InvalidRequest(t *testing.T) {
	msg := SafeMessage(ErrInvalidRequest)
	if msg != "invalid request" {
		t.Errorf("SafeMessage(ErrInvalidRequest) = %q, want %q", msg, "invalid request")
	}
}

func TestSafeMessage_AuditFailure(t *testing.T) {
	msg := SafeMessage(ErrAuditFailure)
	if msg != "audit failure" {
		t.Errorf("SafeMessage(ErrAuditFailure) = %q, want %q", msg, "audit failure")
	}
}

func TestSafeMessage_Nil(t *testing.T) {
	msg := SafeMessage(nil)
	if msg != "" {
		t.Errorf("SafeMessage(nil) = %q, want empty string", msg)
	}
}

func TestSafeMessage_UnknownError(t *testing.T) {
	err := errors.New("something went wrong")
	msg := SafeMessage(err)
	if msg != "something went wrong" {
		t.Errorf("SafeMessage(unknown) = %q, want %q", msg, "something went wrong")
	}
}
