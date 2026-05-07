// Package signer provides CA signer implementations.
package signer

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"io"

	"golang.org/x/crypto/ssh"

	"github.com/FtlC-ian/gobless/internal/errs"
)

// KMSClient is a minimal interface over the AWS KMS API calls used by KMSSigner.
// It is defined here so KMSSigner is testable without a live AWS connection.
type KMSClient interface {
	Sign(ctx context.Context, input *KMSSignInput) (*KMSSignOutput, error)
	GetPublicKey(ctx context.Context, input *KMSGetPublicKeyInput) (*KMSGetPublicKeyOutput, error)
}

// KMSSignInput holds the parameters for a KMS Sign call.
type KMSSignInput struct {
	KeyID            string
	Message          []byte
	MessageType      string // "RAW" or "DIGEST"
	SigningAlgorithm string
}

// KMSSignOutput holds the result of a KMS Sign call.
type KMSSignOutput struct {
	Signature        []byte
	SigningAlgorithm string
}

// KMSGetPublicKeyInput holds the parameters for a KMS GetPublicKey call.
type KMSGetPublicKeyInput struct {
	KeyID string
}

// KMSGetPublicKeyOutput holds the result of a KMS GetPublicKey call.
type KMSGetPublicKeyOutput struct {
	// PublicKeyDER is the DER-encoded SubjectPublicKeyInfo.
	PublicKeyDER      []byte
	KeySpec           string // e.g. "RSA_2048", "ECC_NIST_P256"
	SigningAlgorithms []string
}

// KMSSigner implements Signer using AWS KMS asymmetric signing.
// The CA private key never leaves KMS.
type KMSSigner struct {
	keyID  string
	client KMSClient
}

// NewKMSSigner creates a KMSSigner for the given KMS key ID and client.
func NewKMSSigner(keyID string, client KMSClient) *KMSSigner {
	return &KMSSigner{keyID: keyID, client: client}
}

// PublicKey returns the CA public key by fetching the DER-encoded public key
// from KMS and parsing it.
func (k *KMSSigner) PublicKey() ssh.PublicKey {
	pub, err := k.publicKey(context.Background())
	if err != nil {
		return nil
	}
	return pub
}

// publicKey fetches and parses the KMS public key, returning an ssh.PublicKey.
func (k *KMSSigner) publicKey(ctx context.Context) (ssh.PublicKey, error) {
	out, err := k.client.GetPublicKey(ctx, &KMSGetPublicKeyInput{KeyID: k.keyID})
	if err != nil {
		return nil, errs.Wrap(errs.ErrInternalError, fmt.Sprintf("kms signer: get public key: %v", err))
	}
	cryptoPub, err := x509.ParsePKIXPublicKey(out.PublicKeyDER)
	if err != nil {
		return nil, errs.Wrap(errs.ErrInternalError, fmt.Sprintf("kms signer: parse public key DER: %v", err))
	}
	sshPub, err := ssh.NewPublicKey(cryptoPub)
	if err != nil {
		return nil, errs.Wrap(errs.ErrInternalError, fmt.Sprintf("kms signer: convert to ssh public key: %v", err))
	}
	return sshPub, nil
}

// Sign signs the given SSH certificate using KMS and returns the signed certificate.
func (k *KMSSigner) Sign(cert *ssh.Certificate) (*ssh.Certificate, error) {
	ctx := context.Background()

	// Fetch public key to determine key type and select signing algorithm.
	pubOut, err := k.client.GetPublicKey(ctx, &KMSGetPublicKeyInput{KeyID: k.keyID})
	if err != nil {
		return nil, errs.Wrap(errs.ErrInternalError, fmt.Sprintf("kms signer: get public key for sign: %v", err))
	}

	cryptoPub, err := x509.ParsePKIXPublicKey(pubOut.PublicKeyDER)
	if err != nil {
		return nil, errs.Wrap(errs.ErrInternalError, fmt.Sprintf("kms signer: parse public key DER for sign: %v", err))
	}

	sshPub, err := ssh.NewPublicKey(cryptoPub)
	if err != nil {
		return nil, errs.Wrap(errs.ErrInternalError, fmt.Sprintf("kms signer: convert to ssh public key for sign: %v", err))
	}

	// Build a crypto.Signer that delegates to KMS.
	cs := &kmsCryptoSigner{
		keyID:     k.keyID,
		client:    k.client,
		publicKey: cryptoPub,
	}

	// Use x/crypto/ssh to create a signer from our crypto.Signer.
	// We select the SSH algorithm based on the key type.
	var sshSigner ssh.Signer
	switch cryptoPub.(type) {
	case *rsa.PublicKey:
		// Use RSA-SHA512 for strong security.
		sshSigner, err = ssh.NewSignerFromSigner(cs)
		if err != nil {
			return nil, errs.Wrap(errs.ErrInternalError, fmt.Sprintf("kms signer: create rsa ssh signer: %v", err))
		}
		// Upgrade to rsa-sha2-512 algorithm signer.
		sshSigner = newAlgorithmSigner(sshSigner, ssh.KeyAlgoRSASHA512)
	case *ecdsa.PublicKey:
		sshSigner, err = ssh.NewSignerFromSigner(cs)
		if err != nil {
			return nil, errs.Wrap(errs.ErrInternalError, fmt.Sprintf("kms signer: create ecdsa ssh signer: %v", err))
		}
	default:
		return nil, errs.Wrap(errs.ErrInvalidRequest, fmt.Sprintf("kms signer: unsupported key type %T", cryptoPub))
	}

	_ = sshPub // used implicitly — public key type confirmed above

	if err := cert.SignCert(rand.Reader, sshSigner); err != nil {
		return nil, errs.Wrap(errs.ErrInternalError, fmt.Sprintf("kms signer: sign cert: %v", err))
	}

	return cert, nil
}

// kmsCryptoSigner satisfies crypto.Signer by delegating Sign calls to AWS KMS.
type kmsCryptoSigner struct {
	keyID     string
	client    KMSClient
	publicKey crypto.PublicKey
}

// Public returns the crypto.PublicKey for this signer.
func (s *kmsCryptoSigner) Public() crypto.PublicKey {
	return s.publicKey
}

// Sign delegates the signing operation to AWS KMS.
// opts must be *rsa.PSSOptions, *rsa.PKCS1v15SignOptions (as crypto.Hash), or nil for ECDSA.
func (s *kmsCryptoSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	ctx := context.Background()

	algo, err := kmsSigningAlgorithm(s.publicKey, opts)
	if err != nil {
		return nil, err
	}

	out, err := s.client.Sign(ctx, &KMSSignInput{
		KeyID:            s.keyID,
		Message:          digest,
		MessageType:      "DIGEST",
		SigningAlgorithm: algo,
	})
	if err != nil {
		return nil, errs.Wrap(errs.ErrInternalError, fmt.Sprintf("kms signer: kms sign call: %v", err))
	}

	return out.Signature, nil
}

// kmsSigningAlgorithm selects the KMS signing algorithm string based on the key type and opts.
func kmsSigningAlgorithm(pub crypto.PublicKey, opts crypto.SignerOpts) (string, error) {
	switch pub.(type) {
	case *rsa.PublicKey:
		hash := crypto.SHA512
		if opts != nil {
			hash = opts.HashFunc()
		}
		switch hash {
		case crypto.SHA256:
			return "RSASSA_PKCS1_V1_5_SHA_256", nil
		case crypto.SHA384:
			return "RSASSA_PKCS1_V1_5_SHA_384", nil
		case crypto.SHA512:
			return "RSASSA_PKCS1_V1_5_SHA_512", nil
		default:
			return "RSASSA_PKCS1_V1_5_SHA_512", nil
		}
	case *ecdsa.PublicKey:
		ecPub := pub.(*ecdsa.PublicKey)
		switch ecPub.Curve.Params().BitSize {
		case 256:
			return "ECDSA_SHA_256", nil
		case 384:
			return "ECDSA_SHA_384", nil
		case 521:
			return "ECDSA_SHA_512", nil
		default:
			return "ECDSA_SHA_256", nil
		}
	default:
		return "", errs.Wrap(errs.ErrInvalidRequest, fmt.Sprintf("kms signer: unsupported key type for algorithm selection: %T", pub))
	}
}

// algorithmSigner wraps an ssh.Signer and overrides the algorithm used for signing.
// This is used to select rsa-sha2-512 instead of the default ssh-rsa for RSA keys.
type algorithmSigner struct {
	signer    ssh.Signer
	algorithm string
}

func newAlgorithmSigner(s ssh.Signer, algorithm string) ssh.Signer {
	if as, ok := s.(ssh.AlgorithmSigner); ok {
		return &wrappedAlgorithmSigner{AlgorithmSigner: as, algorithm: algorithm}
	}
	return s
}

// wrappedAlgorithmSigner wraps an ssh.AlgorithmSigner and fixes the signing algorithm.
type wrappedAlgorithmSigner struct {
	ssh.AlgorithmSigner
	algorithm string
}

// Sign uses the fixed algorithm for signing.
func (w *wrappedAlgorithmSigner) Sign(rand io.Reader, data []byte) (*ssh.Signature, error) {
	return w.AlgorithmSigner.SignWithAlgorithm(rand, data, w.algorithm)
}
