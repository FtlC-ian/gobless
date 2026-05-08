package policy_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/FtlC-ian/gobless/internal/cert"
	"github.com/FtlC-ian/gobless/internal/config"
	"github.com/FtlC-ian/gobless/internal/policy"
)

// ---- fixture types ----

type fixturePolicy struct {
	ExpectedAccountID         string   `json:"expected_account_id"`
	MaxTTLSeconds             int      `json:"max_ttl_seconds"`
	AllowPrivilegedPrincipals []string `json:"allow_privileged_principals"`
}

type fixtureIAMContext struct {
	ARN       string `json:"arn"`
	AccountID string `json:"account_id"`
	Username  string `json:"username"`
}

type fixtureRequest struct {
	CertType        string            `json:"cert_type"`
	Handler         string            `json:"handler"`    // "user_cert" signals AllowedCertTypes restriction
	Principals      []string          `json:"principals"` // may be null
	TTLSeconds      int64             `json:"ttl_seconds"`
	CriticalOptions map[string]string `json:"critical_options"`
	PublicKey       string            `json:"public_key"`
}

type fixtureExpected struct {
	Decision         string   `json:"decision"`
	Reason           string   `json:"reason"`
	NoLeakAssertions []string `json:"no_leak_assertions"`
}

type fixture struct {
	Name                 string            `json:"name"`
	Description          string            `json:"description"`
	Request              fixtureRequest    `json:"request"`
	IAMContext           fixtureIAMContext `json:"iam_context"`
	Policy               fixturePolicy     `json:"policy"`
	ExpectedDenialReason string            `json:"expected_denial_reason"`
	Expected             fixtureExpected   `json:"expected"`
}

// buildConfig builds a config.Config from fixture policy and expected reason.
func buildConfig(f *fixture) *config.Config {
	cfg := &config.Config{}
	cfg.CA.SignerType = "rsa"
	cfg.CA.PrivateKeyFile = "placeholder"
	cfg.CA.RSAMinKeyBits = 2048
	cfg.CA.DefaultTTL = 3600
	if f.Policy.MaxTTLSeconds > 0 {
		cfg.CA.MaxTTL = f.Policy.MaxTTLSeconds
	} else {
		cfg.CA.MaxTTL = 3600
	}

	cfg.Principal.ExpectedAccountID = f.Policy.ExpectedAccountID

	// If allow_privileged_principals is non-empty, set as the Allowed list.
	if len(f.Policy.AllowPrivilegedPrincipals) > 0 {
		cfg.Principal.Allowed = f.Policy.AllowPrivilegedPrincipals
	}

	// Enable IAM binding for identity-mismatch cases.
	if f.Expected.Reason == "principal_identity_mismatch" || f.ExpectedDenialReason == "principal_identity_mismatch" {
		cfg.Principal.EnforceIAMBinding = true
	}

	// Restrict cert type if the handler is "user_cert" (simulates user path).
	if strings.ToLower(f.Request.Handler) == "user_cert" {
		cfg.Principal.AllowedCertTypes = []string{"user"}
	}

	return cfg
}

// buildRequest builds a policy.Request from fixture data.
func buildRequest(f *fixture) *policy.Request {
	sourceAddr := ""
	if f.Request.CriticalOptions != nil {
		sourceAddr = f.Request.CriticalOptions["source-address"]
	}
	publicKey := f.Request.PublicKey
	if strings.Contains(publicKey, "TestFixtureOnly") {
		publicKey = testED25519PubKey
	}

	return &policy.Request{
		IAMCallerARN:        f.IAMContext.ARN,
		IAMAccountID:        f.IAMContext.AccountID,
		IAMUsername:         f.IAMContext.Username,
		PublicKey:           publicKey,
		CertType:            f.Request.CertType,
		RequestedPrincipals: f.Request.Principals,
		TTLSeconds:          f.Request.TTLSeconds,
		SourceAddress:       sourceAddr,
	}
}

// ---- negative fixture tests ----

func TestNegativeFixtures(t *testing.T) {
	entries, err := filepath.Glob("../../testdata/policy/negative/*.json")
	if err != nil || len(entries) == 0 {
		t.Fatalf("no negative fixtures found: %v", err)
	}

	for _, path := range entries {
		path := path
		t.Run(filepath.Base(path), func(t *testing.T) {
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read fixture: %v", err)
			}
			var f fixture
			if err := json.Unmarshal(data, &f); err != nil {
				t.Fatalf("parse fixture: %v", err)
			}
			if f.Expected.Decision != "deny" {
				t.Skipf("not a deny fixture (decision=%q)", f.Expected.Decision)
			}

			cfg := buildConfig(&f)
			req := buildRequest(&f)

			dec, err := policy.Evaluate(context.Background(), req, cfg)
			if err != nil {
				t.Fatalf("Evaluate returned unexpected error: %v", err)
			}
			if dec.Approved {
				t.Errorf("fixture %q: expected denial but got approval (KeyID=%q)", f.Name, dec.KeyID)
			}

			wantReason := f.ExpectedDenialReason
			if strings.Contains(wantReason, "_") {
				wantReason = reasonLabelSubstring(wantReason)
			}
			if wantReason == "" {
				wantReason = reasonLabelSubstring(f.Expected.Reason)
			}
			if wantReason != "" && !strings.Contains(dec.DenialReason, wantReason) {
				t.Errorf("fixture %q: denial reason %q does not contain %q", f.Name, dec.DenialReason, wantReason)
			}
			for _, forbidden := range f.Expected.NoLeakAssertions {
				if strings.Contains(dec.DenialReason, forbidden) {
					t.Errorf("fixture %q: denial reason leaked forbidden substring %q", f.Name, forbidden)
				}
			}
		})
	}
}

func reasonLabelSubstring(label string) string {
	switch label {
	case "invalid_source_address":
		return "invalid source address"
	case "privileged_principal_not_allowed":
		return "privileged principal"
	case "empty_principals", "missing_principals":
		return "principals"
	case "ttl_not_positive":
		return "TTL must be positive"
	case "ttl_exceeds_max":
		return "TTL exceeds maximum"
	case "principal_identity_mismatch":
		return "principal does not match IAM identity"
	case "iam_account_mismatch", "iam_partial_match":
		return "IAM account mismatch"
	case "invalid_principal", "confusable_principal":
		return "invalid principal"
	case "duplicate_principal":
		return "duplicate principal"
	case "cert_type_not_allowed":
		return "certificate type not allowed"
	default:
		return strings.ReplaceAll(label, "_", " ")
	}
}

// ---- positive tests ----

const testED25519PubKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOkkLvDF4PjeXYPE8IEasqJ6+AkJlQwmvKiHepno8Mh/ test@test"

func baseConfig() *config.Config {
	cfg := &config.Config{}
	cfg.CA.SignerType = "rsa"
	cfg.CA.PrivateKeyFile = "placeholder"
	cfg.CA.RSAMinKeyBits = 2048
	cfg.CA.DefaultTTL = 3600
	cfg.CA.MaxTTL = 7200
	return cfg
}

func TestValidUserCert(t *testing.T) {
	cfg := baseConfig()
	req := &policy.Request{
		IAMCallerARN:        "arn:aws:iam::111122223333:user/alice",
		IAMAccountID:        "111122223333",
		IAMUsername:         "alice",
		PublicKey:           testED25519PubKey,
		CertType:            "user",
		RequestedPrincipals: []string{"alice"},
		TTLSeconds:          3600,
	}
	dec, err := policy.Evaluate(context.Background(), req, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !dec.Approved {
		t.Errorf("expected approval, got denial: %q", dec.DenialReason)
	}
	if dec.CertType != cert.UserCert {
		t.Errorf("expected UserCert, got %v", dec.CertType)
	}
	if dec.KeyID == "" {
		t.Error("expected non-empty KeyID")
	}
}

func TestValidHostCert(t *testing.T) {
	cfg := baseConfig()
	req := &policy.Request{
		IAMCallerARN:        "arn:aws:iam::111122223333:user/alice",
		IAMAccountID:        "111122223333",
		IAMUsername:         "alice",
		PublicKey:           testED25519PubKey,
		CertType:            "host",
		RequestedPrincipals: []string{"host.example.internal"},
		TTLSeconds:          3600,
	}
	dec, err := policy.Evaluate(context.Background(), req, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !dec.Approved {
		t.Errorf("expected approval, got denial: %q", dec.DenialReason)
	}
	if dec.CertType != cert.HostCert {
		t.Errorf("expected HostCert, got %v", dec.CertType)
	}
}

func TestIAMBindingEnforced_Approved(t *testing.T) {
	cfg := baseConfig()
	cfg.Principal.EnforceIAMBinding = true
	req := &policy.Request{
		IAMCallerARN:        "arn:aws:iam::111122223333:user/alice",
		IAMAccountID:        "111122223333",
		IAMUsername:         "alice",
		PublicKey:           testED25519PubKey,
		CertType:            "user",
		RequestedPrincipals: []string{"alice"},
		TTLSeconds:          3600,
	}
	dec, err := policy.Evaluate(context.Background(), req, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !dec.Approved {
		t.Errorf("expected approval (IAM username matches), got denial: %q", dec.DenialReason)
	}
}

func TestIAMBindingEnforced_Denied(t *testing.T) {
	cfg := baseConfig()
	cfg.Principal.EnforceIAMBinding = true
	req := &policy.Request{
		IAMCallerARN:        "arn:aws:iam::111122223333:user/bob",
		IAMAccountID:        "111122223333",
		IAMUsername:         "bob",
		PublicKey:           testED25519PubKey,
		CertType:            "user",
		RequestedPrincipals: []string{"alice"},
		TTLSeconds:          3600,
	}
	dec, err := policy.Evaluate(context.Background(), req, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dec.Approved {
		t.Error("expected denial when IAM username doesn't match any principal")
	}
}

func TestAllowedPrincipalList_Denied(t *testing.T) {
	cfg := baseConfig()
	cfg.Principal.Allowed = []string{"alice", "bob"}
	req := &policy.Request{
		IAMCallerARN:        "arn:aws:iam::111122223333:user/charlie",
		IAMAccountID:        "111122223333",
		IAMUsername:         "charlie",
		PublicKey:           testED25519PubKey,
		CertType:            "user",
		RequestedPrincipals: []string{"charlie"},
		TTLSeconds:          3600,
	}
	dec, err := policy.Evaluate(context.Background(), req, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dec.Approved {
		t.Error("expected denial when principal not in allowed list")
	}
}

func TestMaxTTLBoundary_ExactlyMaxTTL_Approved(t *testing.T) {
	cfg := baseConfig()
	cfg.CA.MaxTTL = 7200
	req := &policy.Request{
		IAMCallerARN:        "arn:aws:iam::111122223333:user/alice",
		IAMAccountID:        "111122223333",
		IAMUsername:         "alice",
		PublicKey:           testED25519PubKey,
		CertType:            "user",
		RequestedPrincipals: []string{"alice"},
		TTLSeconds:          7200,
	}
	dec, err := policy.Evaluate(context.Background(), req, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !dec.Approved {
		t.Errorf("expected approval at exact MaxTTL, got denial: %q", dec.DenialReason)
	}
}

func TestMaxTTLBoundary_MaxTTLPlusOne_Denied(t *testing.T) {
	cfg := baseConfig()
	cfg.CA.MaxTTL = 7200
	req := &policy.Request{
		IAMCallerARN:        "arn:aws:iam::111122223333:user/alice",
		IAMAccountID:        "111122223333",
		IAMUsername:         "alice",
		PublicKey:           testED25519PubKey,
		CertType:            "user",
		RequestedPrincipals: []string{"alice"},
		TTLSeconds:          7201,
	}
	dec, err := policy.Evaluate(context.Background(), req, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dec.Approved {
		t.Error("expected denial when TTL exceeds MaxTTL by 1")
	}
}

func expectDeniedPrincipal(t *testing.T, principal string, wantReason string) {
	t.Helper()
	cfg := baseConfig()
	req := &policy.Request{
		IAMCallerARN:        "arn:aws:iam::111122223333:user/alice",
		IAMAccountID:        "111122223333",
		IAMUsername:         "alice",
		PublicKey:           testED25519PubKey,
		CertType:            "user",
		RequestedPrincipals: []string{principal},
		TTLSeconds:          3600,
	}

	dec, err := policy.Evaluate(context.Background(), req, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dec.Approved {
		t.Fatalf("expected denial for principal %q", principal)
	}
	if dec.DenialReason != wantReason {
		t.Fatalf("DenialReason = %q, want %q", dec.DenialReason, wantReason)
	}
}

func TestPrincipalControlCharactersDenied(t *testing.T) {
	tests := []struct {
		name      string
		principal string
	}{
		{name: "newline", principal: "alice\nroot"},
		{name: "carriage return", principal: "alice\rroot"},
		{name: "null byte", principal: "alice\x00root"},
		{name: "tab", principal: "alice\troot"},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			expectDeniedPrincipal(t, tc.principal, "invalid principal")
		})
	}
}

func TestDuplicatePrincipalsDenied(t *testing.T) {
	tests := []struct {
		name       string
		principals []string
	}{
		{name: "exact duplicate", principals: []string{"alice", "alice"}},
		{name: "case-insensitive duplicate", principals: []string{"Alice", "alice"}},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			cfg := baseConfig()
			req := &policy.Request{
				IAMCallerARN:        "arn:aws:iam::111122223333:user/alice",
				IAMAccountID:        "111122223333",
				IAMUsername:         "alice",
				PublicKey:           testED25519PubKey,
				CertType:            "user",
				RequestedPrincipals: tc.principals,
				TTLSeconds:          3600,
			}

			dec, err := policy.Evaluate(context.Background(), req, cfg)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if dec.Approved {
				t.Fatalf("expected duplicate principals %q to be denied", tc.principals)
			}
			if dec.DenialReason != "duplicate principal" {
				t.Fatalf("DenialReason = %q, want duplicate principal", dec.DenialReason)
			}
		})
	}
}

func TestEmptyPrincipalAmongValidPrincipalsDenied(t *testing.T) {
	cfg := baseConfig()
	req := &policy.Request{
		IAMCallerARN:        "arn:aws:iam::111122223333:user/alice",
		IAMAccountID:        "111122223333",
		IAMUsername:         "alice",
		PublicKey:           testED25519PubKey,
		CertType:            "user",
		RequestedPrincipals: []string{"alice", ""},
		TTLSeconds:          3600,
	}

	dec, err := policy.Evaluate(context.Background(), req, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dec.Approved {
		t.Fatal("expected empty principal among valid principals to be denied")
	}
	if dec.DenialReason != "invalid principal" {
		t.Fatalf("DenialReason = %q, want invalid principal", dec.DenialReason)
	}
}

func TestUnicodeHomoglyphPrincipalsDenied(t *testing.T) {
	tests := []struct {
		name      string
		principal string
	}{
		{name: "root with Greek omicron", principal: "rοοt"},
		{name: "admin with Greek omicron", principal: "admοn"},
		{name: "admin with fullwidth latin a", principal: "ａdmin"},
		{name: "root with mathematical bold o", principal: "r𝐨𝐨t"},
		{name: "admin with Cyrillic dze", principal: "aԁmin"},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			expectDeniedPrincipal(t, tc.principal, "invalid principal")
		})
	}
}

func TestWhitespaceOnlyPrincipalDenied(t *testing.T) {
	for _, principal := range []string{" ", "\t", "\n", "\r\n", " \t \n "} {
		principal := principal
		t.Run(strings.ReplaceAll(principal, "\n", `\n`), func(t *testing.T) {
			expectDeniedPrincipal(t, principal, "invalid principal")
		})
	}
}

func TestOverlyLongPrincipalDenied(t *testing.T) {
	expectDeniedPrincipal(t, strings.Repeat("a", 1001), "invalid principal")
}

func TestEncodedNullBytePrincipalsDenied(t *testing.T) {
	for _, principal := range []string{"alice%00root", `alice\u0000root`} {
		principal := principal
		t.Run(principal, func(t *testing.T) {
			expectDeniedPrincipal(t, principal, "invalid principal")
		})
	}
}

func TestNewPrivilegedPrincipalsDeniedWithoutAllowlist(t *testing.T) {
	for _, principal := range []string{"ssm-user", "opc", "azureuser", "centos", "fedora", "bitnami", "clouduser", "core"} {
		principal := principal
		t.Run(principal, func(t *testing.T) {
			cfg := baseConfig()
			req := &policy.Request{
				IAMCallerARN:        "arn:aws:iam::111122223333:user/alice",
				IAMAccountID:        "111122223333",
				IAMUsername:         "alice",
				PublicKey:           testED25519PubKey,
				CertType:            "user",
				RequestedPrincipals: []string{principal},
				TTLSeconds:          3600,
			}

			dec, err := policy.Evaluate(context.Background(), req, cfg)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if dec.Approved {
				t.Fatalf("expected denial for privileged principal %q without allowlist", principal)
			}
			if dec.DenialReason != "privileged principal not in allowed list" {
				t.Fatalf("DenialReason = %q, want privileged principal not in allowed list", dec.DenialReason)
			}
		})
	}
}
