//go:build !production

// Package signer provides CA signer implementations.
// This file contains the local file-based signer intended ONLY for development,
// testing, and fixture generation. It MUST NOT be used in production deployments.
package signer

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"

	"golang.org/x/crypto/ssh"
)

// LocalSigner loads a private key from a PEM file and implements Signer.
// WARNING: This signer is NOT FOR PRODUCTION USE. It is intended only for
// local development, tests, and fixture generation.
type LocalSigner struct {
	signer ssh.Signer
}

// NewLocalSigner creates a LocalSigner from a PEM-encoded private key file.
// If the PEM block is encrypted, provide the passphrase; otherwise pass nil.
//
// WARNING: local file signer active — NOT FOR PRODUCTION USE.
func NewLocalSigner(keyPath string, passphrase []byte) (*LocalSigner, error) {
	log.Println("WARNING: local file signer active — NOT FOR PRODUCTION USE")

	data, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("local signer: read key file: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("local signer: no PEM block found in %s", keyPath)
	}

	// Handle OpenSSH private key format directly via x/crypto/ssh.
	if block.Type == "OPENSSH PRIVATE KEY" {
		rawKey, err := ssh.ParseRawPrivateKey(data)
		if err != nil {
			return nil, fmt.Errorf("local signer: parse OpenSSH private key: %w", err)
		}
		sshSigner, err := ssh.NewSignerFromKey(rawKey)
		if err != nil {
			return nil, fmt.Errorf("local signer: create ssh signer from OpenSSH key: %w", err)
		}
		return &LocalSigner{signer: sshSigner}, nil
	}

	var rawKey interface{}

	//nolint:staticcheck // x/crypto/ssh EncryptedPEMBlock is acceptable for dev-only signer
	if x509.IsEncryptedPEMBlock(block) { //nolint:staticcheck
		if passphrase == nil {
			return nil, fmt.Errorf("local signer: key is password-protected but no passphrase provided")
		}
		decrypted, decryptErr := x509.DecryptPEMBlock(block, passphrase) //nolint:staticcheck
		if decryptErr != nil {
			return nil, fmt.Errorf("local signer: decrypt PEM block: %w", decryptErr)
		}
		rawKey, err = parsePrivateKeyBytes(block.Type, decrypted)
		if err != nil {
			return nil, err
		}
	} else {
		rawKey, err = parsePrivateKeyBytes(block.Type, block.Bytes)
		if err != nil {
			return nil, err
		}
	}

	sshSigner, err := ssh.NewSignerFromKey(rawKey)
	if err != nil {
		return nil, fmt.Errorf("local signer: create ssh signer: %w", err)
	}

	return &LocalSigner{signer: sshSigner}, nil
}

// parsePrivateKeyBytes parses DER-encoded key bytes based on PEM type.
func parsePrivateKeyBytes(pemType string, der []byte) (interface{}, error) {
	switch pemType {
	case "RSA PRIVATE KEY":
		key, err := x509.ParsePKCS1PrivateKey(der)
		if err != nil {
			return nil, fmt.Errorf("local signer: parse RSA PKCS1 key: %w", err)
		}
		return key, nil
	case "EC PRIVATE KEY":
		key, err := x509.ParseECPrivateKey(der)
		if err != nil {
			return nil, fmt.Errorf("local signer: parse EC key: %w", err)
		}
		return key, nil
	case "PRIVATE KEY":
		// PKCS#8 — may be RSA, EC, or Ed25519
		key, err := x509.ParsePKCS8PrivateKey(der)
		if err != nil {
			return nil, fmt.Errorf("local signer: parse PKCS8 key: %w", err)
		}
		return key, nil
	default:
		return nil, fmt.Errorf("local signer: unsupported PEM type %q", pemType)
	}
}

// Sign signs the given SSH certificate using the loaded private key.
func (l *LocalSigner) Sign(cert *ssh.Certificate) (*ssh.Certificate, error) {
	if err := cert.SignCert(rand.Reader, l.signer); err != nil {
		return nil, fmt.Errorf("local signer: sign cert: %w", err)
	}
	return cert, nil
}

// PublicKey returns the CA public key.
func (l *LocalSigner) PublicKey() ssh.PublicKey {
	return l.signer.PublicKey()
}
