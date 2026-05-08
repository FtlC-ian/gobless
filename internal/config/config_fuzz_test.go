package config

import (
	"os"
	"path/filepath"
	"testing"
)

func FuzzConfigLoad(f *testing.F) {
	// Seed corpus with known INI-like config patterns
	f.Add([]byte(""))
	f.Add([]byte("[CA]\nPrivateKeyFile = /tmp/ca.pem\nMaxTTL = 3600\n"))
	f.Add([]byte("[CA]\nPrivateKeyFile = \x00evil\nMaxTTL = -1\n"))
	f.Add([]byte("[Principal]\nAllowed = alice,bob\nEnforceIAMBinding = true\n"))
	f.Add([]byte("[CA]\nMaxTTL = 99999999999999999999\n"))
	f.Add([]byte("not_a_section\nkey_without_equals\n"))
	f.Add([]byte("[CA]\n[Principal]\n[CA]\n")) // repeated sections
	f.Add([]byte("MaxTTL = 3600"))             // no section header
	f.Add([]byte("[CA]\nSignerType = kms\nKMSKeyID = \n"))

	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("config.Load panicked: %v", r)
			}
		}()

		dir := t.TempDir()
		cfgPath := filepath.Join(dir, "gobless.conf")
		if err := os.WriteFile(cfgPath, data, 0600); err != nil {
			t.Fatalf("write config: %v", err)
		}

		// Load must never panic — error is acceptable
		_, _ = Load(cfgPath)
	})
}
