//go:build !production

package signer

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// generateTestRSAKey creates a 2048-bit RSA key and writes PEM files to dir.
// Returns the key path (private) and pub path (public).
func generateTestRSAKey(t *testing.T, dir string) (keyPath, pubPath string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}

	keyPath = filepath.Join(dir, "test_rsa")
	pubPath = filepath.Join(dir, "test_rsa.pub")

	// Write private key
	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	if err := os.WriteFile(keyPath, privPEM, 0600); err != nil {
		t.Fatalf("write private key: %v", err)
	}

	// Write public key in SSH authorized_keys format
	pub, err := ssh.NewPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("create ssh public key: %v", err)
	}
	if err := os.WriteFile(pubPath, ssh.MarshalAuthorizedKey(pub), 0644); err != nil {
		t.Fatalf("write public key: %v", err)
	}

	return keyPath, pubPath
}

func TestLocalSigner_InterfaceSatisfied(t *testing.T) {
	dir := t.TempDir()
	keyPath, _ := generateTestRSAKey(t, dir)

	ls, err := NewLocalSigner(keyPath, nil)
	if err != nil {
		t.Fatalf("NewLocalSigner: %v", err)
	}

	// Compile-time check: *LocalSigner must satisfy Signer
	var _ Signer = ls
}

func TestLocalSigner_Sign(t *testing.T) {
	dir := t.TempDir()
	keyPath, _ := generateTestRSAKey(t, dir)

	ls, err := NewLocalSigner(keyPath, nil)
	if err != nil {
		t.Fatalf("NewLocalSigner: %v", err)
	}

	// Create a minimal SSH certificate
	pub := ls.PublicKey()
	cert := &ssh.Certificate{
		CertType:        ssh.UserCert,
		Key:             pub,
		ValidPrincipals: []string{"testuser"},
		ValidAfter:      uint64(time.Now().Unix()),
		ValidBefore:     uint64(time.Now().Add(time.Hour).Unix()),
	}

	signed, err := ls.Sign(cert)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if signed == nil {
		t.Fatal("Sign returned nil certificate")
	}
	if signed.Signature == nil {
		t.Error("Signature field is nil after signing")
	}
}

func TestLocalSigner_PublicKey(t *testing.T) {
	dir := t.TempDir()
	keyPath, _ := generateTestRSAKey(t, dir)

	ls, err := NewLocalSigner(keyPath, nil)
	if err != nil {
		t.Fatalf("NewLocalSigner: %v", err)
	}

	if ls.PublicKey() == nil {
		t.Error("PublicKey returned nil")
	}
}

func TestLocalSigner_BadKeyFilePath(t *testing.T) {
	_, err := NewLocalSigner("/nonexistent/path/to/key", nil)
	if err == nil {
		t.Fatal("expected error for missing key file, got nil")
	}
}

func TestLocalSigner_BadPEM(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "bad.pem")
	if err := os.WriteFile(keyPath, []byte("not a PEM file"), 0600); err != nil {
		t.Fatalf("write bad pem: %v", err)
	}

	_, err := NewLocalSigner(keyPath, nil)
	if err == nil {
		t.Fatal("expected error for bad PEM, got nil")
	}
	if !strings.Contains(err.Error(), "no PEM block") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestLocalSigner_UnsupportedPEMType(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "unknown.pem")
	data := pem.EncodeToMemory(&pem.Block{
		Type:  "UNKNOWN KEY TYPE",
		Bytes: []byte("garbage"),
	})
	if err := os.WriteFile(keyPath, data, 0600); err != nil {
		t.Fatalf("write pem: %v", err)
	}

	_, err := NewLocalSigner(keyPath, nil)
	if err == nil {
		t.Fatal("expected error for unsupported PEM type, got nil")
	}
	if !strings.Contains(err.Error(), "unsupported PEM type") {
		t.Errorf("unexpected error message: %v", err)
	}
}
