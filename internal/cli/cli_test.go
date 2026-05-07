//go:build !production

package cli

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// generateTestRSAKey creates a 2048-bit RSA CA key for tests.
func generateTestRSAKey(t *testing.T, dir string) (keyPath, pubPath string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}

	keyPath = filepath.Join(dir, "test_rsa_ca")
	pubPath = filepath.Join(dir, "test_rsa_ca.pub")

	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	if err := os.WriteFile(keyPath, privPEM, 0600); err != nil {
		t.Fatalf("write private key: %v", err)
	}

	pub, err := ssh.NewPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("create ssh public key: %v", err)
	}
	if err := os.WriteFile(pubPath, ssh.MarshalAuthorizedKey(pub), 0644); err != nil {
		t.Fatalf("write public key: %v", err)
	}

	return keyPath, pubPath
}

// generateTestUserKey generates a user RSA key for signing.
func generateTestUserKey(t *testing.T, dir string) (pubPath string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate user RSA key: %v", err)
	}

	pubPath = filepath.Join(dir, "user_rsa.pub")
	pub, err := ssh.NewPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("create user ssh public key: %v", err)
	}
	if err := os.WriteFile(pubPath, ssh.MarshalAuthorizedKey(pub), 0644); err != nil {
		t.Fatalf("write user public key: %v", err)
	}
	return pubPath
}

// writeTestConfig writes a minimal valid config file.
func writeTestConfig(t *testing.T, dir, caKeyPath string) string {
	t.Helper()
	cfgPath := filepath.Join(dir, "test.cfg")
	content := fmt.Sprintf(`[CA]
private_key_file = %s
signer_type = rsa
default_ttl = 300
max_ttl = 3600
rsa_min_key_bits = 2048

[Principal]
allowed = testuser

[Lambda]
region = us-east-1
function_name = gobless-test

[Logging]
level = info
`, caKeyPath)
	if err := os.WriteFile(cfgPath, []byte(content), 0644); err != nil {
		t.Fatalf("write test config: %v", err)
	}
	return cfgPath
}

func TestRunVersion(t *testing.T) {
	var stdout bytes.Buffer
	RunVersion(&stdout)
	out := stdout.String()
	if !strings.Contains(out, "gobless") {
		t.Errorf("RunVersion output missing 'gobless': %q", out)
	}
	if !strings.Contains(out, Version) {
		t.Errorf("RunVersion output missing version %q: %q", Version, out)
	}
}

func TestRunSign_MissingConfig(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := RunSign([]string{}, &stdout, &stderr)
	if err == nil {
		t.Error("expected error when -config is missing, got nil")
	}
}

func TestRunCAPubKey_MissingConfig(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := RunCAPubKey([]string{}, &stdout, &stderr)
	if err == nil {
		t.Error("expected error when -config is missing, got nil")
	}
}

func TestRunSign_ValidConfigTestKey(t *testing.T) {
	dir := t.TempDir()
	caKeyPath, _ := generateTestRSAKey(t, dir)
	userPubPath := generateTestUserKey(t, dir)
	cfgPath := writeTestConfig(t, dir, caKeyPath)

	var stdout, stderr bytes.Buffer
	err := RunSign([]string{
		"-config", cfgPath,
		"-public-key", userPubPath,
		"-principals", "testuser",
		"-cert-type", "user",
		"-ttl", "300",
	}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("RunSign: unexpected error: %v", err)
	}

	certOut := stdout.String()
	if !strings.Contains(certOut, "cert-v01@openssh.com") {
		t.Errorf("expected cert in authorized-keys format, got: %q", certOut)
	}
}

func TestRunCAPubKey_ValidConfig(t *testing.T) {
	dir := t.TempDir()
	caKeyPath, _ := generateTestRSAKey(t, dir)
	cfgPath := writeTestConfig(t, dir, caKeyPath)

	var stdout, stderr bytes.Buffer
	err := RunCAPubKey([]string{
		"-config", cfgPath,
	}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("RunCAPubKey: unexpected error: %v", err)
	}

	out := stdout.String()
	if !strings.Contains(out, "ssh-rsa") {
		t.Errorf("expected RSA public key output, got: %q", out)
	}
}
