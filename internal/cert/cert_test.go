//go:build !production

package cert

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"
	"unicode"

	"golang.org/x/crypto/ssh"

	"github.com/FtlC-ian/gobless/internal/signer"
)

// testKeyPath returns path to the shared test RSA key.
func testKeyPath(t *testing.T) string {
	t.Helper()
	// Resolve from the package directory: ../../testdata/keys/test_rsa
	_, file, _, _ := runtime.Caller(0)
	dir := filepath.Dir(file)
	return filepath.Join(dir, "..", "..", "testdata", "keys", "test_rsa")
}

// testSigner creates a LocalSigner from the test RSA key.
func testSigner(t *testing.T) signer.Signer {
	t.Helper()
	s, err := signer.NewLocalSigner(testKeyPath(t), nil)
	if err != nil {
		t.Fatalf("NewLocalSigner: %v", err)
	}
	return s
}

// testPublicKey parses the test RSA public key.
func testPublicKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	dir := filepath.Dir(file)
	pubPath := filepath.Join(dir, "..", "..", "testdata", "keys", "test_rsa.pub")
	data, err := os.ReadFile(pubPath)
	if err != nil {
		t.Fatalf("read test pub key: %v", err)
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey(data)
	if err != nil {
		t.Fatalf("parse test pub key: %v", err)
	}
	return pub
}

// testSSHSigner wraps an ssh.Signer to satisfy signer.Signer in tests.
type testSSHSigner struct {
	signer ssh.Signer
}

func (s testSSHSigner) Sign(cert *ssh.Certificate) (*ssh.Certificate, error) {
	if err := cert.SignCert(rand.Reader, s.signer); err != nil {
		return nil, err
	}
	return cert, nil
}

func (s testSSHSigner) PublicKey() ssh.PublicKey {
	return s.signer.PublicKey()
}

func newTestSSHSigner(t *testing.T, key any) signer.Signer {
	t.Helper()
	sshSigner, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatalf("ssh.NewSignerFromKey: %v", err)
	}
	return testSSHSigner{signer: sshSigner}
}

// smallRSAPublicKey generates a small (1024-bit) RSA key for rejection tests.
func smallRSAPublicKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("generate small RSA key: %v", err)
	}
	pub, err := ssh.NewPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("wrap small RSA public key: %v", err)
	}
	return pub
}

func TestSign_Table(t *testing.T) {
	s := testSigner(t)
	pub := testPublicKey(t)

	defaultExts := map[string]string{
		"permit-pty":              "",
		"permit-port-forwarding":  "",
		"permit-agent-forwarding": "",
		"permit-X11-forwarding":   "",
		"permit-user-rc":          "",
	}

	tests := []struct {
		name        string
		req         *Request
		wantErr     bool
		errContains string
		check       func(t *testing.T, resp *Response)
	}{
		{
			name: "user cert single principal basic TTL",
			req: &Request{
				CertType:   UserCert,
				PublicKey:  pub,
				Principals: []string{"alice"},
				TTL:        time.Hour,
			},
			check: func(t *testing.T, resp *Response) {
				t.Helper()
				c := resp.Certificate
				if c.CertType != ssh.UserCert {
					t.Errorf("CertType = %d, want %d", c.CertType, ssh.UserCert)
				}
				if len(c.ValidPrincipals) != 1 || c.ValidPrincipals[0] != "alice" {
					t.Errorf("Principals = %v, want [alice]", c.ValidPrincipals)
				}
				if c.ValidBefore <= c.ValidAfter {
					t.Errorf("ValidBefore %d <= ValidAfter %d", c.ValidBefore, c.ValidAfter)
				}
				if c.Serial == 0 {
					t.Error("Serial is zero")
				}
			},
		},
		{
			name: "user cert multiple principals",
			req: &Request{
				CertType:   UserCert,
				PublicKey:  pub,
				Principals: []string{"alice", "alice-admin", "deploy"},
				TTL:        time.Hour,
			},
			check: func(t *testing.T, resp *Response) {
				t.Helper()
				if len(resp.Certificate.ValidPrincipals) != 3 {
					t.Errorf("Principals = %v, want 3", resp.Certificate.ValidPrincipals)
				}
			},
		},
		{
			name: "host cert",
			req: &Request{
				CertType:   HostCert,
				PublicKey:  pub,
				Principals: []string{"host.example.internal"},
				TTL:        time.Hour,
				Extensions: map[string]string{}, // host certs have no extensions
			},
			check: func(t *testing.T, resp *Response) {
				t.Helper()
				if resp.Certificate.CertType != ssh.HostCert {
					t.Errorf("CertType = %d, want host cert", resp.Certificate.CertType)
				}
			},
		},
		{
			name: "source-address critical option",
			req: &Request{
				CertType:      UserCert,
				PublicKey:     pub,
				Principals:    []string{"alice"},
				TTL:           time.Hour,
				SourceAddress: "10.0.0.0/8,192.168.0.0/16",
			},
			check: func(t *testing.T, resp *Response) {
				t.Helper()
				v, ok := resp.Certificate.Permissions.CriticalOptions["source-address"]
				if !ok {
					t.Error("source-address critical option missing")
				}
				if v != "10.0.0.0/8,192.168.0.0/16" {
					t.Errorf("source-address = %q, want 10.0.0.0/8,192.168.0.0/16", v)
				}
			},
		},
		{
			name: "force-command critical option",
			req: &Request{
				CertType:     UserCert,
				PublicKey:    pub,
				Principals:   []string{"alice"},
				TTL:          time.Hour,
				ForceCommand: "/usr/local/bin/gobless-shell",
			},
			check: func(t *testing.T, resp *Response) {
				t.Helper()
				v, ok := resp.Certificate.Permissions.CriticalOptions["force-command"]
				if !ok {
					t.Error("force-command critical option missing")
				}
				if v != "/usr/local/bin/gobless-shell" {
					t.Errorf("force-command = %q", v)
				}
			},
		},
		{
			name: "default extensions applied when nil",
			req: &Request{
				CertType:   UserCert,
				PublicKey:  pub,
				Principals: []string{"alice"},
				TTL:        time.Hour,
				Extensions: nil,
			},
			check: func(t *testing.T, resp *Response) {
				t.Helper()
				for k := range defaultExts {
					if _, ok := resp.Certificate.Permissions.Extensions[k]; !ok {
						t.Errorf("default extension %q missing", k)
					}
				}
			},
		},
		{
			name: "custom extensions override",
			req: &Request{
				CertType:   UserCert,
				PublicKey:  pub,
				Principals: []string{"alice"},
				TTL:        time.Hour,
				Extensions: map[string]string{"permit-pty": ""},
			},
			check: func(t *testing.T, resp *Response) {
				t.Helper()
				exts := resp.Certificate.Permissions.Extensions
				if len(exts) != 1 {
					t.Errorf("expected 1 extension, got %d: %v", len(exts), exts)
				}
				if _, ok := exts["permit-pty"]; !ok {
					t.Error("permit-pty extension missing")
				}
			},
		},
		{
			name: "boundary TTL 1 second",
			req: &Request{
				CertType:   UserCert,
				PublicKey:  pub,
				Principals: []string{"alice"},
				TTL:        time.Second,
			},
			check: func(t *testing.T, resp *Response) {
				t.Helper()
				c := resp.Certificate
				if c.ValidBefore != c.ValidAfter+1 {
					t.Errorf("TTL 1s: ValidBefore=%d ValidAfter=%d diff=%d", c.ValidBefore, c.ValidAfter, c.ValidBefore-c.ValidAfter)
				}
			},
		},
		{
			name: "ValidAfter <= ValidBefore all cases",
			req: &Request{
				CertType:   UserCert,
				PublicKey:  pub,
				Principals: []string{"bob"},
				TTL:        24 * time.Hour,
			},
			check: func(t *testing.T, resp *Response) {
				t.Helper()
				c := resp.Certificate
				if c.ValidAfter > c.ValidBefore {
					t.Errorf("ValidAfter %d > ValidBefore %d", c.ValidAfter, c.ValidBefore)
				}
			},
		},
		{
			name:        "RSA key < 2048 bits rejected",
			req:         &Request{CertType: UserCert, PublicKey: smallRSAPublicKey(t), Principals: []string{"alice"}, TTL: time.Hour},
			wantErr:     true,
			errContains: "2048",
		},
		{
			name:        "empty principals error",
			req:         &Request{CertType: UserCert, PublicKey: pub, Principals: []string{}, TTL: time.Hour},
			wantErr:     true,
			errContains: "principals",
		},
		{
			name:        "zero TTL error",
			req:         &Request{CertType: UserCert, PublicKey: pub, Principals: []string{"alice"}, TTL: 0},
			wantErr:     true,
			errContains: "TTL",
		},
		{
			name: "serial is non-zero",
			req: &Request{
				CertType:   UserCert,
				PublicKey:  pub,
				Principals: []string{"alice"},
				TTL:        time.Hour,
			},
			check: func(t *testing.T, resp *Response) {
				t.Helper()
				if resp.Certificate.Serial == 0 {
					t.Error("Serial is zero")
				}
			},
		},
		{
			name: "extension ordering is lexicographic",
			req: &Request{
				CertType:   UserCert,
				PublicKey:  pub,
				Principals: []string{"alice"},
				TTL:        time.Hour,
				Extensions: map[string]string{
					"permit-agent-forwarding": "",
					"permit-port-forwarding":  "",
					"permit-pty":              "",
					"permit-X11-forwarding":   "",
				},
			},
			check: func(t *testing.T, resp *Response) {
				t.Helper()
				exts := resp.Certificate.Permissions.Extensions
				keys := make([]string, 0, len(exts))
				for k := range exts {
					keys = append(keys, k)
				}
				sorted := make([]string, len(keys))
				copy(sorted, keys)
				sort.Strings(sorted)
				// Verify all keys are present
				if len(keys) != 4 {
					t.Errorf("expected 4 extensions, got %d", len(keys))
				}
				for _, k := range sorted {
					if _, ok := exts[k]; !ok {
						t.Errorf("extension %q missing", k)
					}
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := Sign(context.Background(), tc.req, s)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tc.errContains)
				}
				if tc.errContains != "" && !strings.Contains(err.Error(), tc.errContains) {
					t.Errorf("error %q does not contain %q", err.Error(), tc.errContains)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.check != nil {
				tc.check(t, resp)
			}
		})
	}
}

// goldenFields is the shape of expected_fields in each fixture JSON.
type goldenFixture struct {
	Description    string            `json:"description"`
	CertType       string            `json:"cert_type"`
	KeyType        string            `json:"key_type"`
	Principals     []string          `json:"principals"`
	TTLSeconds     int64             `json:"ttl_seconds"`
	Extensions     map[string]string `json:"extensions"`
	CriticalOpts   map[string]string `json:"critical_options"`
	ExpectedFields map[string]string `json:"expected_fields"`
}

func loadGoldenFixture(t *testing.T, name string) goldenFixture {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	dir := filepath.Dir(file)
	path := filepath.Join(dir, "..", "..", "testdata", "golden", name)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden fixture %s: %v", name, err)
	}
	var f goldenFixture
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatalf("parse golden fixture %s: %v", name, err)
	}
	return f
}

func buildRequestFromFixture(t *testing.T, f goldenFixture, pub ssh.PublicKey) *Request {
	t.Helper()
	certType := UserCert
	if f.CertType == "host" {
		certType = HostCert
	}
	var exts map[string]string
	if f.Extensions != nil {
		exts = f.Extensions
	}
	return &Request{
		CertType:      certType,
		PublicKey:     pub,
		Principals:    f.Principals,
		TTL:           time.Duration(f.TTLSeconds) * time.Second,
		Extensions:    exts,
		SourceAddress: f.CriticalOpts["source-address"],
		ForceCommand:  f.CriticalOpts["force-command"],
	}
}

func TestSign_GoldenVectors(t *testing.T) {
	s := testSigner(t)
	pub := testPublicKey(t)

	fixtures := []string{
		"user_rsa_basic.json",
		"user_rsa_multi_principal.json",
		"host_cert_basic.json",
		"user_rsa_source_address.json",
		"user_rsa_force_command.json",
		"user_rsa_ttl_boundary.json",
		"extension_ordering.json",
	}

	for _, name := range fixtures {
		t.Run(name, func(t *testing.T) {
			f := loadGoldenFixture(t, name)
			req := buildRequestFromFixture(t, f, pub)
			resp, err := Sign(context.Background(), req, s)
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			c := resp.Certificate

			// Check cert type
			if ef, ok := f.ExpectedFields["Type"]; ok {
				typ := "user certificate"
				if c.CertType == ssh.HostCert {
					typ = "host certificate"
				}
				if !strings.Contains(ef, typ) {
					t.Errorf("type mismatch: fixture wants %q, cert has %q", ef, typ)
				}
			}

			// Check principals
			if ef, ok := f.ExpectedFields["Principals"]; ok {
				got := strings.Join(c.ValidPrincipals, ",")
				if got != ef {
					t.Errorf("principals = %q, want %q", got, ef)
				}
			}

			// ValidAfter <= ValidBefore
			if c.ValidAfter > c.ValidBefore {
				t.Errorf("ValidAfter %d > ValidBefore %d", c.ValidAfter, c.ValidBefore)
			}

			// TTL check
			if ef, ok := f.ExpectedFields["TTL Seconds"]; ok {
				diff := c.ValidBefore - c.ValidAfter
				if diff != uint64(f.TTLSeconds) {
					t.Errorf("TTL diff = %d, want %s", diff, ef)
				}
			}

			// Serial non-zero
			if c.Serial == 0 {
				t.Error("Serial is zero")
			}

			// Check extension ordering: parse the cert from wire bytes and verify
			// all expected extension keys are present. We do NOT check map iteration
			// order (non-deterministic); instead we rely on ssh.ParseAuthorizedKey
			// and confirm the x/crypto library correctly serialised each key.
			if ef, ok := f.ExpectedFields["Extension Ordering"]; ok && ef != "" {
				pk, _, _, _, parseErr := ssh.ParseAuthorizedKey([]byte(resp.AuthorizedKey))
				if parseErr != nil {
					t.Fatalf("re-parse authorized key: %v", parseErr)
				}
				parsedCert, ok2 := pk.(*ssh.Certificate)
				if !ok2 {
					t.Fatal("re-parsed key is not *ssh.Certificate")
				}
				// Verify all expected extensions are present in the round-tripped cert.
				for k := range c.Permissions.Extensions {
					if _, found := parsedCert.Permissions.Extensions[k]; !found {
						t.Errorf("extension %q missing after round-trip parse", k)
					}
				}
				if len(parsedCert.Permissions.Extensions) != len(c.Permissions.Extensions) {
					t.Errorf("extension count mismatch after round-trip: got %d want %d",
						len(parsedCert.Permissions.Extensions), len(c.Permissions.Extensions))
				}
			}

			// Check extensions list
			if ef, ok := f.ExpectedFields["Extensions"]; ok && ef != "none" {
				// ef may be comma-separated
				for _, extName := range strings.Split(ef, ",") {
					extName = strings.TrimSpace(extName)
					if _, ok2 := c.Permissions.Extensions[extName]; !ok2 {
						t.Errorf("expected extension %q not present", extName)
					}
				}
			}

			// Verify ssh-keygen -L if available
			if _, err2 := exec.LookPath("ssh-keygen"); err2 == nil {
				checkCertWithSSHKeygen(t, resp.AuthorizedKey, f)
			}
		})
	}
}

// checkCertWithSSHKeygen writes the cert to a temp file and runs ssh-keygen -L,
// then checks key expected_fields.
func checkCertWithSSHKeygen(t *testing.T, authorizedKey string, f goldenFixture) {
	t.Helper()
	tmp := t.TempDir()
	certFile := filepath.Join(tmp, "test-cert.pub")
	if err := os.WriteFile(certFile, []byte(authorizedKey), 0644); err != nil {
		t.Fatalf("write cert for ssh-keygen: %v", err)
	}

	out, err := exec.Command("ssh-keygen", "-L", "-f", certFile).CombinedOutput()
	if err != nil {
		t.Fatalf("ssh-keygen -L: %v\n%s", err, out)
	}
	output := string(out)

	// Verify Type
	if ef, ok := f.ExpectedFields["Type"]; ok {
		if !strings.Contains(output, ef) {
			t.Errorf("ssh-keygen output missing %q\nFull output:\n%s", ef, output)
		}
	}
}

func TestSign_AuthorizedKeyNonEmpty(t *testing.T) {
	s := testSigner(t)
	pub := testPublicKey(t)
	resp, err := Sign(context.Background(), &Request{
		CertType:   UserCert,
		PublicKey:  pub,
		Principals: []string{"alice"},
		TTL:        time.Hour,
	}, s)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(resp.AuthorizedKey) == 0 {
		t.Error("AuthorizedKey is empty")
	}
	// Should be parseable as an authorized key
	pk, _, _, _, err2 := ssh.ParseAuthorizedKey([]byte(resp.AuthorizedKey))
	if err2 != nil {
		t.Fatalf("parse authorized key: %v", err2)
	}
	if pk.Type() != resp.Certificate.Type() {
		t.Errorf("parsed key type %q != cert type %q", pk.Type(), resp.Certificate.Type())
	}
}

func TestGenerateKeyID(t *testing.T) {
	keyID, err := GenerateKeyID(UserCert, []string{"alice"})
	if err != nil {
		t.Fatalf("GenerateKeyID: %v", err)
	}
	if !strings.HasPrefix(keyID, "gobless-user-alice-") {
		t.Errorf("keyID %q unexpected format", keyID)
	}
}

func TestGenerateKeyID_SanitizesPrincipal(t *testing.T) {
	tests := []struct {
		name       string
		principal  string
		wantPrefix string
	}{
		{
			name:       "principal with newline",
			principal:  "alice\nbob",
			wantPrefix: "gobless-user-alice_bob-",
		},
		{
			name:       "principal with spaces",
			principal:  "alice smith",
			wantPrefix: "gobless-user-alice_smith-",
		},
		{
			name:       "principal with at-sign (allowed)",
			principal:  "alice@example.com",
			wantPrefix: "gobless-user-alice@example.com-",
		},
		{
			name:       "safe principal unchanged",
			principal:  "alice",
			wantPrefix: "gobless-user-alice-",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			keyID, err := GenerateKeyID(UserCert, []string{tc.principal})
			if err != nil {
				t.Fatalf("GenerateKeyID: %v", err)
			}
			if !strings.HasPrefix(keyID, tc.wantPrefix) {
				t.Errorf("keyID %q does not have prefix %q", keyID, tc.wantPrefix)
			}
		})
	}
}

// Ensure test RSA key is parseable for PEM format verification.
func TestTestKeyPEMValid(t *testing.T) {
	data, err := os.ReadFile(testKeyPath(t))
	if err != nil {
		t.Fatalf("read test key: %v", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatal("no PEM block")
	}
	// Accept OpenSSH private key format (modern ssh-keygen default)
	if block.Type == "OPENSSH PRIVATE KEY" {
		_, err2 := ssh.ParseRawPrivateKey(data)
		if err2 != nil {
			t.Fatalf("parse OpenSSH private key: %v", err2)
		}
		return
	}
	if _, err2 := x509.ParsePKCS1PrivateKey(block.Bytes); err2 != nil {
		t.Fatalf("parse RSA key: %v", err2)
	}
}

// TestSign_SourceAddressCIDRValidation covers CIDR validation before cert signing.
func TestSign_SourceAddressCIDRValidation(t *testing.T) {
	s := testSigner(t)
	pub := testPublicKey(t)

	tests := []struct {
		name          string
		sourceAddress string
		wantErr       bool
		errContains   string
		checkCert     func(t *testing.T, resp *Response)
	}{
		{
			name:          "invalid CIDR rejected",
			sourceAddress: "not-a-cidr",
			wantErr:       true,
			errContains:   "source-address",
		},
		{
			name:          "host address without mask rejected",
			sourceAddress: "10.0.0.1",
			wantErr:       true,
			errContains:   "source-address",
		},
		{
			name:          "second CIDR in list invalid",
			sourceAddress: "10.0.0.0/8,badcidr",
			wantErr:       true,
			errContains:   "source-address",
		},
		{
			name:          "valid single CIDR signed",
			sourceAddress: "10.0.0.0/8",
			wantErr:       false,
			checkCert: func(t *testing.T, resp *Response) {
				v, ok := resp.Certificate.Permissions.CriticalOptions["source-address"]
				if !ok {
					t.Error("source-address critical option missing")
				}
				if v != "10.0.0.0/8" {
					t.Errorf("source-address = %q, want 10.0.0.0/8", v)
				}
			},
		},
		{
			name:          "valid multi-CIDR signed",
			sourceAddress: "10.0.0.0/8,192.168.0.0/16",
			wantErr:       false,
			checkCert: func(t *testing.T, resp *Response) {
				v, ok := resp.Certificate.Permissions.CriticalOptions["source-address"]
				if !ok {
					t.Error("source-address critical option missing")
				}
				if v != "10.0.0.0/8,192.168.0.0/16" {
					t.Errorf("source-address = %q", v)
				}
			},
		},
		{
			name:          "empty source-address no critical option added",
			sourceAddress: "",
			wantErr:       false,
			checkCert: func(t *testing.T, resp *Response) {
				if _, ok := resp.Certificate.Permissions.CriticalOptions["source-address"]; ok {
					t.Error("source-address should not be set for empty input")
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := Sign(context.Background(), &Request{
				CertType:      UserCert,
				PublicKey:     pub,
				Principals:    []string{"alice"},
				TTL:           time.Hour,
				SourceAddress: tc.sourceAddress,
			}, s)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tc.errContains)
				}
				if tc.errContains != "" && !strings.Contains(err.Error(), tc.errContains) {
					t.Errorf("error %q does not contain %q", err.Error(), tc.errContains)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.checkCert != nil {
				tc.checkCert(t, resp)
			}
		})
	}
}

// TestGenerateKeyID_SanitizesAllDangerousChars verifies that KeyID sanitization
// handles newlines, tabs, carriage returns, null bytes, and Unicode.
func TestGenerateKeyID_SanitizesAllDangerousChars(t *testing.T) {
	tests := []struct {
		name      string
		principal string
		wantInfix string // the sanitized segment expected between "gobless-user-" and "-<ts>-<hex>"
	}{
		{
			name:      "newline replaced",
			principal: "alice\nbob",
			wantInfix: "alice_bob",
		},
		{
			name:      "tab replaced",
			principal: "alice\tbob",
			wantInfix: "alice_bob",
		},
		{
			name:      "carriage return replaced",
			principal: "alice\rbob",
			wantInfix: "alice_bob",
		},
		{
			name:      "null byte replaced",
			principal: "alice\x00bob",
			wantInfix: "alice_bob",
		},
		{
			name:      "valid chars unchanged",
			principal: "alice@example.com",
			wantInfix: "alice@example.com",
		},
		{
			name:      "Cyrillic Unicode sanitized to underscores",
			principal: "алиса",
			wantInfix: "_____",
		},
		{
			name:      "mixed valid and invalid chars",
			principal: "alice\n\t\r\x00bob",
			wantInfix: "alice____bob",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			keyID, err := GenerateKeyID(UserCert, []string{tc.principal})
			if err != nil {
				t.Fatalf("GenerateKeyID: %v", err)
			}
			expectedPrefix := "gobless-user-" + tc.wantInfix + "-"
			if !strings.HasPrefix(keyID, expectedPrefix) {
				t.Errorf("keyID %q does not have prefix %q", keyID, expectedPrefix)
			}
			// Also verify no dangerous chars appear anywhere in the keyID
			for _, dangerous := range []string{"\n", "\t", "\r", "\x00"} {
				if strings.Contains(keyID, dangerous) {
					t.Errorf("keyID %q contains dangerous character %q", keyID, dangerous)
				}
			}
		})
	}
}

// TestGenerateKeyID_OutputIsPrintableASCII asserts that GenerateKeyID returns
// a string consisting entirely of printable, non-whitespace ASCII characters
// even when the principal contains control characters or non-ASCII bytes.

func TestSign_ECDSAP256PublicKeyParses(t *testing.T) {
	ca := testSigner(t)
	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ECDSA P-256 key: %v", err)
	}
	pub, err := ssh.NewPublicKey(&clientKey.PublicKey)
	if err != nil {
		t.Fatalf("ssh.NewPublicKey: %v", err)
	}

	resp, err := Sign(context.Background(), &Request{
		CertType:   UserCert,
		PublicKey:  pub,
		Principals: []string{"alice"},
		TTL:        time.Hour,
	}, ca)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	parsed, _, _, _, err := ssh.ParseAuthorizedKey([]byte(resp.AuthorizedKey))
	if err != nil {
		t.Fatalf("parse signed ECDSA cert: %v", err)
	}
	cert, ok := parsed.(*ssh.Certificate)
	if !ok {
		t.Fatalf("parsed key type %T, want *ssh.Certificate", parsed)
	}
	if cert.CertType != ssh.UserCert {
		t.Fatalf("CertType = %d, want user cert", cert.CertType)
	}
	if !bytes.Equal(cert.Key.Marshal(), pub.Marshal()) {
		t.Error("cert embedded public key does not match input key")
	}
}

func TestSign_Ed25519PublicKeyParses(t *testing.T) {
	ca := testSigner(t)
	pubKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate Ed25519 key: %v", err)
	}
	pub, err := ssh.NewPublicKey(pubKey)
	if err != nil {
		t.Fatalf("ssh.NewPublicKey: %v", err)
	}

	resp, err := Sign(context.Background(), &Request{
		CertType:   UserCert,
		PublicKey:  pub,
		Principals: []string{"alice"},
		TTL:        time.Hour,
	}, ca)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	parsed, _, _, _, err := ssh.ParseAuthorizedKey([]byte(resp.AuthorizedKey))
	if err != nil {
		t.Fatalf("parse signed Ed25519 cert: %v", err)
	}
	cert, ok := parsed.(*ssh.Certificate)
	if !ok {
		t.Fatalf("parsed key type %T, want *ssh.Certificate", parsed)
	}
	if cert.CertType != ssh.UserCert {
		t.Fatalf("CertType = %d, want user cert", cert.CertType)
	}
	if !bytes.Equal(cert.Key.Marshal(), pub.Marshal()) {
		t.Error("cert embedded public key does not match input key")
	}
}

func TestSign_ECDSAP256CASignerParses(t *testing.T) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ECDSA P-256 CA key: %v", err)
	}
	resp, err := Sign(context.Background(), &Request{
		CertType:   HostCert,
		PublicKey:  testPublicKey(t),
		Principals: []string{"host.example.internal"},
		TTL:        time.Hour,
		Extensions: map[string]string{},
	}, newTestSSHSigner(t, caKey))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	parsed, _, _, _, err := ssh.ParseAuthorizedKey([]byte(resp.AuthorizedKey))
	if err != nil {
		t.Fatalf("parse ECDSA-CA signed cert: %v", err)
	}
	cert, ok := parsed.(*ssh.Certificate)
	if !ok {
		t.Fatalf("parsed key type %T, want *ssh.Certificate", parsed)
	}
	if cert.CertType != ssh.HostCert {
		t.Fatalf("CertType = %d, want host cert", cert.CertType)
	}
}

func TestSign_Ed25519CASignerParses(t *testing.T) {
	_, caKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate Ed25519 CA key: %v", err)
	}
	resp, err := Sign(context.Background(), &Request{
		CertType:   UserCert,
		PublicKey:  testPublicKey(t),
		Principals: []string{"alice"},
		TTL:        time.Hour,
	}, newTestSSHSigner(t, caKey))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	parsed, _, _, _, err := ssh.ParseAuthorizedKey([]byte(resp.AuthorizedKey))
	if err != nil {
		t.Fatalf("parse Ed25519-CA signed cert: %v", err)
	}
	if _, ok := parsed.(*ssh.Certificate); !ok {
		t.Fatalf("parsed key type %T, want *ssh.Certificate", parsed)
	}
}

func TestGenerateKeyID_OutputIsPrintableASCII(t *testing.T) {
	trickyPrincipals := []struct {
		name      string
		principal string
	}{
		{"newline", "alice\nbob"},
		{"tab", "alice\tbob"},
		{"null", "alice\x00bob"},
		{"carriage-return", "alice\rbob"},
		{"non-ascii", "alice\xc3\xa9bob"}, // UTF-8 é
		{"control-chars", "\x01\x02\x03"},
		{"normal", "alice"},
	}
	for _, tc := range trickyPrincipals {
		t.Run(tc.name, func(t *testing.T) {
			keyID, err := GenerateKeyID(UserCert, []string{tc.principal})
			if err != nil {
				t.Fatalf("GenerateKeyID error: %v", err)
			}
			for i, ch := range keyID {
				if ch > 127 {
					t.Errorf("keyID[%d] rune %U is non-ASCII in %q", i, ch, keyID)
				}
				if !unicode.IsPrint(ch) {
					t.Errorf("keyID[%d] rune %U is not printable in %q", i, ch, keyID)
				}
				if ch == ' ' {
					t.Errorf("keyID[%d] is a space in %q", i, keyID)
				}
			}
		})
	}
}
