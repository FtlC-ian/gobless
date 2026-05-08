// concurrency_test.go verifies that audit.NoopRepository and DynamoRepository
// are safe for concurrent use (no data races, no panics).
package audit

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
)

// concurrentMockDynamoClient is a DynamoClient mock safe for concurrent use.
type concurrentMockDynamoClient struct {
	calls atomic.Int64
}

func (m *concurrentMockDynamoClient) PutItem(_ context.Context, _ *dynamodb.PutItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error) {
	m.calls.Add(1)
	return &dynamodb.PutItemOutput{}, nil
}

func (m *concurrentMockDynamoClient) Count() int {
	return int(m.calls.Load())
}

// TestNoopRepository_ConcurrentWrite verifies that NoopRepository.Write can
// be called from many goroutines simultaneously without a race or panic.
func TestNoopRepository_ConcurrentWrite(t *testing.T) {
	repo := &NoopRepository{}
	const n = 20

	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			ev, err := NewEvent(EventTypeSigningRequest)
			if err != nil {
				t.Errorf("NewEvent: %v", err)
				return
			}
			if writeErr := repo.Write(context.Background(), ev); writeErr != nil {
				t.Errorf("Write: %v", writeErr)
			}
		}()
	}
	wg.Wait()
}

// TestDynamoRepository_ConcurrentWrite verifies that DynamoRepository.Write can
// be called from many goroutines simultaneously without a data race or panic.
func TestDynamoRepository_ConcurrentWrite(t *testing.T) {
	client := &concurrentMockDynamoClient{}
	repo := NewDynamoRepository("audit-events", client, false)
	const n = 20

	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			ev, err := NewEvent(EventTypeSigningApproved)
			if err != nil {
				t.Errorf("NewEvent: %v", err)
				return
			}
			if writeErr := repo.Write(context.Background(), ev); writeErr != nil {
				t.Errorf("Write: %v", writeErr)
			}
		}()
	}
	wg.Wait()

	got := client.Count()
	if got != n {
		t.Errorf("PutItem called %d times, want %d", got, n)
	}
}

// TestNewEvent_Concurrent verifies that NewEvent is safe for concurrent use
// and that every generated EventID is unique.
func TestNewEvent_Concurrent(t *testing.T) {
	const n = 40
	ids := make(chan string, n)

	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			ev, err := NewEvent(EventTypeSigningRequest)
			if err != nil {
				t.Errorf("NewEvent: %v", err)
				return
			}
			ids <- ev.EventID
		}()
	}
	wg.Wait()
	close(ids)

	seen := make(map[string]struct{}, n)
	for id := range ids {
		if _, dup := seen[id]; dup {
			t.Errorf("duplicate EventID %q", id)
		}
		seen[id] = struct{}{}
	}
}
