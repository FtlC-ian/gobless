package audit

import (
	"context"
	"errors"
	"regexp"
	"strconv"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

type mockDynamoClient struct {
	putItemCalls int
	input        *dynamodb.PutItemInput
	err          error
}

func (m *mockDynamoClient) PutItem(ctx context.Context, params *dynamodb.PutItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error) {
	m.putItemCalls++
	m.input = params
	if m.err != nil {
		return nil, m.err
	}
	return &dynamodb.PutItemOutput{}, nil
}

func TestDynamoRepositoryWriteSucceeds(t *testing.T) {
	client := &mockDynamoClient{}
	repo := NewDynamoRepository("audit-events", client, false)
	event := testEvent()

	if err := repo.Write(context.Background(), event); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if client.putItemCalls != 1 {
		t.Fatalf("PutItem calls = %d, want 1", client.putItemCalls)
	}
	if client.input == nil || client.input.TableName == nil || *client.input.TableName != "audit-events" {
		t.Fatalf("TableName = %#v, want audit-events", client.input)
	}
}

func TestDynamoRepositoryWriteFailOpenSuppressesPutItemError(t *testing.T) {
	client := &mockDynamoClient{err: errors.New("boom")}
	repo := NewDynamoRepository("audit-events", client, true)

	if err := repo.Write(context.Background(), testEvent()); err != nil {
		t.Fatalf("Write() error = %v, want nil", err)
	}
}

func TestDynamoRepositoryWriteFailClosedReturnsPutItemError(t *testing.T) {
	client := &mockDynamoClient{err: errors.New("boom")}
	repo := NewDynamoRepository("audit-events", client, false)

	if err := repo.Write(context.Background(), testEvent()); err == nil {
		t.Fatal("Write() error = nil, want error")
	}
}

func TestEventIDIsNonEmptyUUIDOnEachEvent(t *testing.T) {
	e1, err := NewEvent(EventTypeSigningRequest)
	if err != nil {
		t.Fatalf("NewEvent 1: %v", err)
	}
	e2, err := NewEvent(EventTypeSigningRequest)
	if err != nil {
		t.Fatalf("NewEvent 2: %v", err)
	}
	uuidRE := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	if !uuidRE.MatchString(e1.EventID) {
		t.Fatalf("EventID %q is not a v4 UUID", e1.EventID)
	}
	if !uuidRE.MatchString(e2.EventID) {
		t.Fatalf("EventID %q is not a v4 UUID", e2.EventID)
	}
	if e1.EventID == e2.EventID {
		t.Fatalf("EventIDs are equal: %q", e1.EventID)
	}
}

func TestDynamoRepositoryAddsExpiresAtNinetyDaysFromTimestamp(t *testing.T) {
	client := &mockDynamoClient{}
	repo := NewDynamoRepository("audit-events", client, false)
	event := testEvent()

	if err := repo.Write(context.Background(), event); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	attr, ok := client.input.Item["ExpiresAt"].(*types.AttributeValueMemberN)
	if !ok {
		t.Fatalf("ExpiresAt attr = %#v, want number", client.input.Item["ExpiresAt"])
	}
	got, err := strconv.ParseInt(attr.Value, 10, 64)
	if err != nil {
		t.Fatalf("ExpiresAt parse: %v", err)
	}
	want := event.Timestamp.Add(90 * 24 * time.Hour).Unix()
	if got < want-1 || got > want+1 {
		t.Fatalf("ExpiresAt = %d, want ~%d", got, want)
	}
}

func TestNoopRepositoryWriteAlwaysReturnsNil(t *testing.T) {
	repo := &NoopRepository{}
	if err := repo.Write(context.Background(), nil); err != nil {
		t.Fatalf("Write(nil) error = %v", err)
	}
	if err := repo.Write(context.Background(), testEvent()); err != nil {
		t.Fatalf("Write(event) error = %v", err)
	}
}

func testEvent() *Event {
	return &Event{
		EventID:       "11111111-2222-4333-8444-555555555555",
		EventType:     EventTypeSigningApproved,
		Timestamp:     time.Date(2026, 5, 6, 15, 0, 0, 0, time.UTC),
		IAMCallerARN:  "arn:aws:iam::111122223333:user/alice",
		IAMAccountID:  "111122223333",
		RequestID:     "request-1",
		CertType:      "user",
		Principals:    []string{"alice"},
		TTLSeconds:    3600,
		SourceAddress: "10.0.0.0/8",
		KeyID:         "gobless-user-alice-1778080000-deadbeef",
		Approved:      true,
		CertSerial:    42,
		CertNotBefore: time.Date(2026, 5, 6, 15, 0, 0, 0, time.UTC),
		CertNotAfter:  time.Date(2026, 5, 6, 16, 0, 0, 0, time.UTC),
		LambdaRegion:  "us-east-1",
		LambdaFnName:  "gobless",
	}
}
