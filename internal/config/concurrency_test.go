// concurrency_test.go verifies that config.Load (and the resulting *Config)
// can be accessed from multiple goroutines without data races.
package config

import (
	"os"
	"sync"
	"testing"
)

// TestLoad_ConcurrentReads verifies that once a *Config is loaded it can be
// read from many goroutines concurrently without data races.
func TestLoad_ConcurrentReads(t *testing.T) {
	// Build a minimal config file.
	f, err := os.CreateTemp(t.TempDir(), "gobless-*.conf")
	if err != nil {
		t.Fatalf("create temp config: %v", err)
	}
	_, _ = f.WriteString(`
[ca]
signer_type = rsa
private_key_file = /tmp/dummy.pem
default_ttl = 3600
max_ttl = 86400

[logging]
level = info
`)
	f.Close()

	cfg, err := Load(f.Name())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	const n = 20
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			// Read several fields simultaneously — the race detector will
			// catch any concurrent read/write on Config's fields.
			_ = cfg.CA.SignerType
			_ = cfg.CA.DefaultTTL
			_ = cfg.CA.MaxTTL
			_ = cfg.Logging.Level
			_ = cfg.Principal.Allowed
		}()
	}
	wg.Wait()
}

// TestLoad_ConcurrentLoads verifies that calling Load from multiple goroutines
// simultaneously is race-free (each goroutine gets its own *Config).
func TestLoad_ConcurrentLoads(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "gobless-*.conf")
	if err != nil {
		t.Fatalf("create temp config: %v", err)
	}
	_, _ = f.WriteString(`
[ca]
signer_type = rsa
private_key_file = /tmp/dummy.pem
default_ttl = 3600
max_ttl = 86400

[logging]
level = info
`)
	f.Close()

	const n = 10
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			cfg, loadErr := Load(f.Name())
			if loadErr != nil {
				t.Errorf("Load: %v", loadErr)
				return
			}
			if cfg == nil {
				t.Error("Load returned nil config")
			}
		}()
	}
	wg.Wait()
}
