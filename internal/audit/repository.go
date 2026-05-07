package audit

import "context"

// Repository stores audit events.
type Repository interface {
	Write(ctx context.Context, event *Event) error
}

// NoopRepository silently discards events. Used when audit is disabled.
type NoopRepository struct{}

func (n *NoopRepository) Write(ctx context.Context, event *Event) error { return nil }
