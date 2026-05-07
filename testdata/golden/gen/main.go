//go:build ignore

// DO NOT USE IN PRODUCTION.
//
// This program creates deterministic-looking test fixtures and test-only keys for
// GoBless golden-vector development. It is intentionally excluded from normal
// builds. Generated private keys are for local tests only, must never be reused,
// and must never be copied into production systems.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/ssh"
)

type goldenVector struct {
	Description     string            `json:"description"`
	CertType        string            `json:"cert_type"`
	KeyType         string            `json:"key_type"`
	Principals      []string          `json:"principals"`
	TTLSeconds      int64             `json:"ttl_seconds"`
	Extensions      map[string]string `json:"extensions"`
	CriticalOptions map[string]string `json:"critical_options"`
	ExpectedFields  map[string]string `json:"expected_fields"`
}

func main() {
	root := filepath.Clean(filepath.Join("testdata"))
	if err := os.MkdirAll(filepath.Join(root, "keys"), 0o755); err != nil {
		log.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "golden"), 0o755); err != nil {
		log.Fatal(err)
	}

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}
	writePEM(filepath.Join(root, "keys", "test_rsa_ca.pem"), "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(rsaKey))
	pubRSA, err := ssh.NewPublicKey(&rsaKey.PublicKey)
	if err != nil {
		log.Fatal(err)
	}
	writeFile(filepath.Join(root, "keys", "test_rsa_ca.pub"), ssh.MarshalAuthorizedKey(pubRSA))

	_, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	edBytes, err := x509.MarshalPKCS8PrivateKey(edPriv)
	if err != nil {
		log.Fatal(err)
	}
	writePEM(filepath.Join(root, "keys", "test_ed25519_ca.pem"), "PRIVATE KEY", edBytes)
	edPub, err := ssh.NewPublicKey(edPriv.Public())
	if err != nil {
		log.Fatal(err)
	}
	writeFile(filepath.Join(root, "keys", "test_ed25519_ca.pub"), ssh.MarshalAuthorizedKey(edPub))

	validAfter := uint64(time.Unix(1_700_000_000, 0).Unix())
	validBefore := validAfter + 3600
	_ = &ssh.Certificate{
		Key:             pubRSA,
		Serial:          1,
		CertType:        ssh.UserCert,
		KeyId:           "golden-user-rsa-basic",
		ValidPrincipals: []string{"alice"},
		ValidAfter:      validAfter,
		ValidBefore:     validBefore,
		Permissions: ssh.Permissions{Extensions: map[string]string{
			"permit-pty": "",
		}},
	}

	stub := goldenVector{
		Description:     "user cert, RSA key, single principal, 1h TTL",
		CertType:        "user",
		KeyType:         "rsa",
		Principals:      []string{"alice"},
		TTLSeconds:      3600,
		Extensions:      map[string]string{"permit-pty": ""},
		CriticalOptions: map[string]string{},
		ExpectedFields: map[string]string{
			"Type":         "ssh-rsa-cert-v01@openssh.com user certificate",
			"Key ID":       "golden-user-rsa-basic",
			"Principals":   "alice",
			"Valid":        "pattern:^from .* to .*$",
			"Extensions":   "permit-pty",
			"CriticalOpts": "none",
		},
	}
	b, err := json.MarshalIndent(stub, "", "  ")
	if err != nil {
		log.Fatal(err)
	}
	writeFile(filepath.Join(root, "golden", "user_rsa_basic.generated.json"), append(b, '\n'))
	fmt.Println("wrote test-only keys and sample generated golden stub")
}

func writePEM(path, typ string, der []byte) {
	writeFile(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}))
}

func writeFile(path string, data []byte) {
	if err := os.WriteFile(path, data, 0o600); err != nil {
		log.Fatal(err)
	}
}
