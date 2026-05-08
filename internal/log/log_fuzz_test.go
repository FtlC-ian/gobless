package log

import (
	"testing"
)

func FuzzRedact(f *testing.F) {
	// Seed corpus
	f.Add("")
	f.Add("secret-token-abc123")
	f.Add("ssh-rsa AAAAB3NzaC1yc2EAAAA...")
	f.Add("\x00")
	f.Add("a")
	f.Add("password\nwith\nnewlines")
	f.Add("unicode: 日本語テスト")
	f.Add(string(make([]byte, 1024))) // long zero-filled string

	f.Fuzz(func(t *testing.T, s string) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("Redact panicked: %v", r)
			}
		}()

		result := Redact(s)

		// Non-empty input must never return an empty string
		if s != "" && result == "" {
			t.Fatalf("Redact(%q) returned empty string for non-empty input", s)
		}

		// Empty input must return empty string (preserve absent-value signal)
		if s == "" && result != "" {
			t.Fatalf("Redact(%q) returned non-empty string for empty input: %q", s, result)
		}
	})
}
