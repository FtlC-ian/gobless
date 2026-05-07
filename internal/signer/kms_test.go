package signer

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// mockKMSClient implements KMSClient for testing.
type mockKMSClient struct {
	signFunc         func(ctx context.Context, in *KMSSignInput) (*KMSSignOutput, error)
	getPublicKeyFunc func(ctx context.Context, in *KMSGetPublicKeyInput) (*KMSGetPublicKeyOutput, error)
}

func (m *mockKMSClient) Sign(ctx context.Context, in *KMSSignInput) (*KMSSignOutput, error) {
	return m.signFunc(ctx, in)
}

func (m *mockKMSClient) GetPublicKey(ctx context.Context, in *KMSGetPublicKeyInput) (*KMSGetPublicKeyOutput, error) {
	return m.getPublicKeyFunc(ctx, in)
}

// generateRSATestKey generates a 2048-bit RSA key pair for tests.
func generateRSATestKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA test key: %v", err)
	}
	return key
}

// generateECTestKey generates an ECDSA P-256 key pair for tests.
func generateECTestKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate EC test key: %v", err)
	}
	return key
}

// publicKeyDER returns the DER-encoded SubjectPublicKeyInfo for a key.
func publicKeyDER(t *testing.T, pub interface{}) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	return der
}

// realSignFunc returns a signFunc that signs the digest with the given private key
// and returns the raw bytes as KMS would.
func realRSASignFunc(t *testing.T, key *rsa.PrivateKey) func(ctx context.Context, in *KMSSignInput) (*KMSSignOutput, error) {
	t.Helper()
	return func(ctx context.Context, in *KMSSignInput) (*KMSSignOutput, error) {
		sig, err := rsa.SignPKCS1v15(rand.Reader, key, 0, in.Message)
		if err != nil {
			return nil, err
		}
		return &KMSSignOutput{Signature: sig, SigningAlgorithm: in.SigningAlgorithm}, nil
	}
}

// realECSignFunc returns a signFunc that signs the digest with the given EC key.
func realECSignFunc(t *testing.T, key *ecdsa.PrivateKey) func(ctx context.Context, in *KMSSignInput) (*KMSSignOutput, error) {
	t.Helper()
	return func(ctx context.Context, in *KMSSignInput) (*KMSSignOutput, error) {
		r, s, err := ecdsa.Sign(rand.Reader, key, in.Message)
		if err != nil {
			return nil, err
		}
		// Return ASN.1 DER encoding as KMS does.
		sig, err := asn1.Marshal(struct{ R, S *big.Int }{r, s})
		if err != nil {
			return nil, err
		}
		return &KMSSignOutput{Signature: sig, SigningAlgorithm: in.SigningAlgorithm}, nil
	}
}

// makeMinimalCert builds a minimal unsigned SSH user cert for testing.
func makeMinimalCert(pub ssh.PublicKey) *ssh.Certificate {
	now := uint64(time.Now().Unix())
	return &ssh.Certificate{
		CertType:        ssh.UserCert,
		Key:             pub,
		ValidPrincipals: []string{"testuser"},
		ValidAfter:      now,
		ValidBefore:     now + 3600,
		KeyId:           "test-key-id",
	}
}

// TestKMSSigner_InterfaceSatisfied verifies *KMSSigner satisfies the Signer interface.
func TestKMSSigner_InterfaceSatisfied(t *testing.T) {
	rsaKey := generateRSATestKey(t)
	der := publicKeyDER(t, &rsaKey.PublicKey)
	client := &mockKMSClient{
		getPublicKeyFunc: func(_ context.Context, _ *KMSGetPublicKeyInput) (*KMSGetPublicKeyOutput, error) {
			return &KMSGetPublicKeyOutput{PublicKeyDER: der, KeySpec: "RSA_2048"}, nil
		},
		signFunc: realRSASignFunc(t, rsaKey),
	}
	var _ Signer = NewKMSSigner("key-id", client)
}

// TestKMSSigner_SignRSA_ReturnsCert verifies Sign returns a signed certificate for an RSA KMS key.
func TestKMSSigner_SignRSA_ReturnsCert(t *testing.T) {
	rsaKey := generateRSATestKey(t)
	der := publicKeyDER(t, &rsaKey.PublicKey)

	client := &mockKMSClient{
		getPublicKeyFunc: func(_ context.Context, _ *KMSGetPublicKeyInput) (*KMSGetPublicKeyOutput, error) {
			return &KMSGetPublicKeyOutput{PublicKeyDER: der, KeySpec: "RSA_2048"}, nil
		},
		signFunc: realRSASignFunc(t, rsaKey),
	}

	sshPub, err := ssh.NewPublicKey(&rsaKey.PublicKey)
	if err != nil {
		t.Fatalf("ssh.NewPublicKey: %v", err)
	}

	s := NewKMSSigner("test-key-id", client)
	cert := makeMinimalCert(sshPub)

	signed, err := s.Sign(cert)
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

// TestKMSSigner_PublicKey_RSA verifies PublicKey returns a non-nil RSA public key.
func TestKMSSigner_PublicKey_RSA(t *testing.T) {
	rsaKey := generateRSATestKey(t)
	der := publicKeyDER(t, &rsaKey.PublicKey)

	client := &mockKMSClient{
		getPublicKeyFunc: func(_ context.Context, _ *KMSGetPublicKeyInput) (*KMSGetPublicKeyOutput, error) {
			return &KMSGetPublicKeyOutput{PublicKeyDER: der, KeySpec: "RSA_2048"}, nil
		},
	}

	s := NewKMSSigner("test-key-id", client)
	pub := s.PublicKey()
	if pub == nil {
		t.Fatal("PublicKey returned nil")
	}
	if !strings.HasPrefix(pub.Type(), "ssh-rsa") {
		t.Errorf("unexpected key type: %s", pub.Type())
	}
}

// TestKMSSigner_PublicKey_ECDSA verifies PublicKey returns a non-nil ECDSA public key.
func TestKMSSigner_PublicKey_ECDSA(t *testing.T) {
	ecKey := generateECTestKey(t)
	der := publicKeyDER(t, &ecKey.PublicKey)

	client := &mockKMSClient{
		getPublicKeyFunc: func(_ context.Context, _ *KMSGetPublicKeyInput) (*KMSGetPublicKeyOutput, error) {
			return &KMSGetPublicKeyOutput{PublicKeyDER: der, KeySpec: "ECC_NIST_P256"}, nil
		},
	}

	s := NewKMSSigner("test-key-id", client)
	pub := s.PublicKey()
	if pub == nil {
		t.Fatal("PublicKey returned nil")
	}
}

// TestKMSSigner_SignError_KMSSignFails verifies Sign wraps and returns KMS signing errors.
func TestKMSSigner_SignError_KMSSignFails(t *testing.T) {
	rsaKey := generateRSATestKey(t)
	der := publicKeyDER(t, &rsaKey.PublicKey)
	kmsErr := errors.New("kms: access denied")

	client := &mockKMSClient{
		getPublicKeyFunc: func(_ context.Context, _ *KMSGetPublicKeyInput) (*KMSGetPublicKeyOutput, error) {
			return &KMSGetPublicKeyOutput{PublicKeyDER: der, KeySpec: "RSA_2048"}, nil
		},
		signFunc: func(_ context.Context, _ *KMSSignInput) (*KMSSignOutput, error) {
			return nil, kmsErr
		},
	}

	sshPub, err := ssh.NewPublicKey(&rsaKey.PublicKey)
	if err != nil {
		t.Fatalf("ssh.NewPublicKey: %v", err)
	}

	s := NewKMSSigner("test-key-id", client)
	cert := makeMinimalCert(sshPub)

	_, err = s.Sign(cert)
	if err == nil {
		t.Fatal("expected error from Sign when KMS Sign fails, got nil")
	}
	// Should not expose raw AWS error text directly — it should be wrapped.
	if !strings.Contains(err.Error(), "kms signer") {
		t.Errorf("error should mention 'kms signer', got: %v", err)
	}
}

// TestKMSSigner_PublicKeyError_GetPublicKeyFails verifies PublicKey returns nil when KMS GetPublicKey fails.
func TestKMSSigner_PublicKeyError_GetPublicKeyFails(t *testing.T) {
	kmsErr := errors.New("kms: not authorized")

	client := &mockKMSClient{
		getPublicKeyFunc: func(_ context.Context, _ *KMSGetPublicKeyInput) (*KMSGetPublicKeyOutput, error) {
			return nil, kmsErr
		},
	}

	s := NewKMSSigner("test-key-id", client)
	pub := s.PublicKey()
	// PublicKey() returns nil on error (ssh.PublicKey interface).
	if pub != nil {
		t.Errorf("expected nil PublicKey on KMS error, got %v", pub)
	}
}

// TestKMSSigner_SignError_GetPublicKeyFailsOnSign verifies Sign returns error when GetPublicKey fails during sign.
func TestKMSSigner_SignError_GetPublicKeyFailsOnSign(t *testing.T) {
	kmsErr := errors.New("kms: throttled")
	rsaKey := generateRSATestKey(t)
	sshPub, err := ssh.NewPublicKey(&rsaKey.PublicKey)
	if err != nil {
		t.Fatalf("ssh.NewPublicKey: %v", err)
	}

	client := &mockKMSClient{
		getPublicKeyFunc: func(_ context.Context, _ *KMSGetPublicKeyInput) (*KMSGetPublicKeyOutput, error) {
			return nil, kmsErr
		},
	}

	s := NewKMSSigner("test-key-id", client)
	cert := makeMinimalCert(sshPub)

	_, err = s.Sign(cert)
	if err == nil {
		t.Fatal("expected error from Sign when GetPublicKey fails, got nil")
	}
}
