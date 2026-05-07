package audit

import (
	"crypto/rand"
	"fmt"
	"strings"
	"time"
)

type EventType string

const (
	EventTypeSigningRequest  EventType = "signing_request"
	EventTypeSigningApproved EventType = "signing_approved"
	EventTypeSigningDenied   EventType = "signing_denied"
	EventTypeSigningError    EventType = "signing_error"
)

const redacted = "REDACTED"

// Event is the structured audit record for a certificate-signing decision.
// It deliberately stores only sanitized copies of request fields and never raw
// public key bytes, private key material, credentials, or full request payloads.
type Event struct {
	EventID   string // UUID
	EventType EventType
	Timestamp time.Time

	IAMCallerARN string // REDACTED if contains sensitive patterns
	IAMAccountID string
	RequestID    string // Lambda request ID or generated

	// Request fields (from policy.Request) — redacted/sanitized copies.
	CertType      string
	Principals    []string
	TTLSeconds    int64
	SourceAddress string
	KeyID         string // from generated KeyID

	// Decision fields.
	Approved     bool
	DenialReason string // safe message only

	// Result fields (populated after signing).
	CertSerial    uint64
	CertNotBefore time.Time
	CertNotAfter  time.Time

	// Metadata.
	LambdaRegion string
	LambdaFnName string
}

// NewEvent returns an audit event with a UUID EventID and UTC timestamp.
func NewEvent(eventType EventType) (*Event, error) {
	eventID, err := newUUID()
	if err != nil {
		return nil, err
	}
	return &Event{
		EventID:   eventID,
		EventType: eventType,
		Timestamp: time.Now().UTC(),
	}, nil
}

func ensureEventDefaults(event *Event) error {
	if event.EventID == "" {
		eventID, err := newUUID()
		if err != nil {
			return err
		}
		event.EventID = eventID
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}
	event.IAMCallerARN = redactIfSensitive("IAMCallerARN", event.IAMCallerARN)
	return nil
}

// redactIfSensitive redacts values whose field name is secret-like. The Event
// schema is intentionally narrow, but this helper documents and centralizes the
// redaction rule for future copied fields.
func redactIfSensitive(fieldName, value string) string {
	name := strings.ToLower(fieldName)
	for _, marker := range []string{"key", "secret", "token", "password"} {
		if strings.Contains(name, marker) {
			return redacted
		}
	}
	return value
}

func newUUID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("audit: generate event UUID: %w", err)
	}
	b[6] = (b[6] & 0x0f) | 0x40 // Version 4.
	b[8] = (b[8] & 0x3f) | 0x80 // Variant is 10.
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}
