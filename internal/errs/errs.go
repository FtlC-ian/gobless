// Package errs provides sentinel errors, error wrapping utilities, and safe
// error message sanitization for the gobless service.
//
// The SafeMessage function ensures that internal details, stack traces, and
// file paths are never exposed to external callers.
package errs

import (
	"errors"
	"fmt"
)

// Sentinel errors for common failure categories.
var (
	// ErrUnauthorized indicates the caller is not authorized to perform the action.
	ErrUnauthorized = errors.New("unauthorized")

	// ErrInvalidRequest indicates the request is malformed or contains invalid fields.
	ErrInvalidRequest = errors.New("invalid request")

	// ErrInternalError indicates an unexpected internal failure.
	ErrInternalError = errors.New("internal error")

	// ErrAuditFailure indicates that an audit log write or verification failed.
	ErrAuditFailure = errors.New("audit failure")
)

// Wrap wraps err with a contextual message using fmt.Errorf with %w.
// The wrapped error can be unwrapped with errors.Is / errors.As.
func Wrap(err error, msg string) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", msg, err)
}

// SafeMessage returns a user-safe error message for the given error.
// For errors that wrap ErrInternalError, the internal detail is stripped
// and a generic message is returned. Stack traces and internal paths are
// never included.
//
// For other error types, the top-level message is returned as-is.
func SafeMessage(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, ErrInternalError) {
		return "an internal error occurred"
	}
	if errors.Is(err, ErrUnauthorized) {
		return "unauthorized"
	}
	if errors.Is(err, ErrInvalidRequest) {
		return "invalid request"
	}
	if errors.Is(err, ErrAuditFailure) {
		return "audit failure"
	}
	// For unknown errors, return the top-level message only (do not expose wrapped chain).
	return err.Error()
}
