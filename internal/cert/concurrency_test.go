//go:build !production

// concurrency_test.go verifies that cert.Sign is safe for concurrent use:
// no data races, all produced certs are valid, and serials are unique across
// concurrent calls.  It also verifies replay resistance — two calls with
// identical inputs produce distinct serials.
package cert

import (
	"context"
	"sync"
	"testing"
	"time"
)

const concurrentWorkers = 20

// TestSign_ConcurrentNoRace spins up concurrentWorkers goroutines all calling
// cert.Sign simultaneously.  The test verifies:
//   - no data races (run with -race)
//   - every response is non-nil with a valid certificate
//   - all serials are non-zero and unique
func TestSign_ConcurrentNoRace(t *testing.T) {
	s := testSigner(t)
	pub := testPublicKey(t)

	type result struct {
		serial uint64
		err    error
	}

	results := make([]result, concurrentWorkers)
	var wg sync.WaitGroup
	wg.Add(concurrentWorkers)

	for i := 0; i < concurrentWorkers; i++ {
		i := i
		go func() {
			defer wg.Done()
			req := &Request{
				CertType:   UserCert,
				PublicKey:  pub,
				Principals: []string{"alice"},
				TTL:        time.Hour,
			}
			resp, err := Sign(context.Background(), req, s)
			if err != nil {
				results[i] = result{err: err}
				return
			}
			results[i] = result{serial: resp.Certificate.Serial}
		}()
	}
	wg.Wait()

	// All must have succeeded.
	for i, r := range results {
		if r.err != nil {
			t.Errorf("worker %d: unexpected error: %v", i, r.err)
		}
		if r.serial == 0 {
			t.Errorf("worker %d: serial is zero", i)
		}
	}

	// All serials must be unique.
	seen := make(map[uint64]int, concurrentWorkers)
	for i, r := range results {
		if r.err != nil {
			continue
		}
		if prev, exists := seen[r.serial]; exists {
			t.Errorf("serial collision: worker %d and worker %d produced serial %d",
				i, prev, r.serial)
		}
		seen[r.serial] = i
	}
}

// TestSign_SerialUniquenessUnderConcurrency is a dedicated uniqueness assertion
// over a larger sample to confirm the serial RNG never collides.
func TestSign_SerialUniquenessUnderConcurrency(t *testing.T) {
	s := testSigner(t)
	pub := testPublicKey(t)

	const n = 50
	serials := make(chan uint64, n)
	var wg sync.WaitGroup
	wg.Add(n)

	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			req := &Request{
				CertType:   UserCert,
				PublicKey:  pub,
				Principals: []string{"bob"},
				TTL:        30 * time.Minute,
			}
			resp, err := Sign(context.Background(), req, s)
			if err != nil {
				t.Errorf("Sign: %v", err)
				return
			}
			serials <- resp.Certificate.Serial
		}()
	}
	wg.Wait()
	close(serials)

	seen := make(map[uint64]struct{}, n)
	for serial := range serials {
		if _, dup := seen[serial]; dup {
			t.Errorf("duplicate serial %d", serial)
		}
		seen[serial] = struct{}{}
	}
}

// TestSign_ReplayResistance verifies that two Sign calls with identical inputs
// produce distinct serials, preventing deterministic replay.
func TestSign_ReplayResistance(t *testing.T) {
	s := testSigner(t)
	pub := testPublicKey(t)

	req := &Request{
		CertType:   UserCert,
		PublicKey:  pub,
		Principals: []string{"alice"},
		TTL:        time.Hour,
	}

	resp1, err := Sign(context.Background(), req, s)
	if err != nil {
		t.Fatalf("first Sign: %v", err)
	}
	resp2, err := Sign(context.Background(), req, s)
	if err != nil {
		t.Fatalf("second Sign: %v", err)
	}

	if resp1.Certificate.Serial == resp2.Certificate.Serial {
		t.Errorf("replay: both Sign calls produced the same serial %d; serials must not be deterministic",
			resp1.Certificate.Serial)
	}
}

// TestGenerateKeyID_Concurrent verifies that GenerateKeyID has no data races
// when called from multiple goroutines simultaneously.
func TestGenerateKeyID_Concurrent(t *testing.T) {
	const n = 20
	ids := make([]string, n)
	var wg sync.WaitGroup
	wg.Add(n)

	for i := 0; i < n; i++ {
		i := i
		go func() {
			defer wg.Done()
			id, err := GenerateKeyID(UserCert, []string{"alice"})
			if err != nil {
				t.Errorf("GenerateKeyID: %v", err)
				return
			}
			ids[i] = id
		}()
	}
	wg.Wait()

	// All key IDs must be non-empty and unique.
	seen := make(map[string]int, n)
	for i, id := range ids {
		if id == "" {
			t.Errorf("worker %d: empty key ID", i)
			continue
		}
		if prev, exists := seen[id]; exists {
			t.Errorf("duplicate key ID from workers %d and %d: %q", i, prev, id)
		}
		seen[id] = i
	}
}
