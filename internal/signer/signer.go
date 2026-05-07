// Package signer defines the CA signer interface and its implementations.
package signer

import "golang.org/x/crypto/ssh"

// Signer is the interface for CA signing operations.
type Signer interface {
	// Sign signs the given SSH certificate and returns the signed certificate.
	Sign(cert *ssh.Certificate) (*ssh.Certificate, error)

	// PublicKey returns the CA public key.
	PublicKey() ssh.PublicKey
}
