package policy_test

import (
	"context"
	"strings"
	"testing"

	"github.com/FtlC-ian/gobless/internal/config"
	"github.com/FtlC-ian/gobless/internal/policy"
)

func FuzzPolicyEvaluate(f *testing.F) {
	// Seed corpus with known edge cases
	f.Add("alice", int64(3600), "user", "123456789012")
	f.Add("", int64(0), "", "")
	f.Add("root\x00", int64(-1), "host", "bad")
	f.Add(strings.Repeat("a", 300), int64(86400), "user", "123456789012")
	f.Add("bob", int64(1), "user", "")
	f.Add("alice", int64(9999999), "USER", "123456789012")
	f.Add("root", int64(3600), "user", "123456789012")
	f.Add("alice@example.com", int64(3600), "user", "123456789012")

	cfg := &config.Config{}
	cfg.CA.MaxTTL = 86400
	cfg.CA.RSAMinKeyBits = 2048

	f.Fuzz(func(t *testing.T, principal string, ttl int64, certType string, accountID string) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("policy.Evaluate panicked: %v", r)
			}
		}()

		req := &policy.Request{
			IAMCallerARN:        "arn:aws:iam::" + accountID + ":user/" + principal,
			IAMAccountID:        accountID,
			IAMUsername:         principal,
			PublicKey:           "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl test@fuzz",
			CertType:            certType,
			RequestedPrincipals: []string{principal},
			TTLSeconds:          ttl,
		}

		// Result must be either (Decision, nil) or (nil, non-nil-error).
		// No panics allowed.
		d, err := policy.Evaluate(context.Background(), req, cfg)
		if err != nil {
			// internal error is acceptable — must not be a panic
			return
		}
		if d == nil {
			t.Fatal("policy.Evaluate returned nil Decision and nil error")
		}
	})
}
