//go:build !production

package cert

import (
	"context"
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

	"github.com/FtlC-ian/gobless/internal/signer"
)

func fuzzTestSigner(f *testing.F) signer.Signer {
	f.Helper()
	dir := f.TempDir()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		f.Fatalf("generate RSA key: %v", err)
	}
	keyPath := filepath.Join(dir, "ca")
	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	if err := os.WriteFile(keyPath, privPEM, 0600); err != nil {
		f.Fatalf("write key: %v", err)
	}
	s, err := signer.NewLocalSigner(keyPath, nil)
	if err != nil {
		f.Fatalf("NewLocalSigner: %v", err)
	}
	return s
}

func fuzzTestClientKey(f *testing.F) ssh.PublicKey {
	f.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		f.Fatalf("generate client RSA key: %v", err)
	}
	pub, err := ssh.NewPublicKey(&key.PublicKey)
	if err != nil {
		f.Fatalf("wrap public key: %v", err)
	}
	return pub
}

func FuzzCertSign(f *testing.F) {
	// Seed corpus with known edge cases
	f.Add("alice", int64(3600), "user")
	f.Add("", int64(0), "")
	f.Add("root", int64(-1), "host")
	f.Add(strings.Repeat("x", 300), int64(86400), "user")
	f.Add("alice", int64(1), "host")
	f.Add("bob@example.com", int64(7200), "user")

	s := fuzzTestSigner(f)
	pub := fuzzTestClientKey(f)

	f.Fuzz(func(t *testing.T, principal string, ttlSecs int64, certTypeStr string) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("cert.Sign panicked: %v", r)
			}
		}()

		var ct CertType
		switch strings.ToLower(strings.TrimSpace(certTypeStr)) {
		case "host":
			ct = HostCert
		default:
			ct = UserCert
		}

		principals := []string{"fuzz-principal"}
		if strings.TrimSpace(principal) != "" {
			principals = []string{principal}
		}

		ttl := time.Duration(ttlSecs) * time.Second
		if ttl <= 0 {
			ttl = time.Second
		}

		req := &Request{
			CertType:   ct,
			PublicKey:  pub,
			Principals: principals,
			TTL:        ttl,
			KeyID:      "fuzz-key-id",
		}

		resp, err := Sign(context.Background(), req, s)
		if err != nil {
			// Errors are acceptable — no panics allowed
			return
		}
		if resp == nil {
			t.Fatal("Sign returned nil Response and nil error")
		}
		if resp.Certificate == nil {
			t.Fatal("Sign returned Response with nil Certificate")
		}
	})
}
