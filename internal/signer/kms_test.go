package signer

import (
	"context"
	"crypto"
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

// realRSASignFunc returns a signFunc that signs the digest with the given private key
// and returns the raw bytes as KMS would. The Message is a pre-hashed SHA-512
// digest (MessageType=DIGEST), so we sign with crypto.SHA512 to produce the
// correct PKCS1v15 signature DigestInfo encoding that SSH can verify.
func realRSASignFunc(t *testing.T, key *rsa.PrivateKey) func(ctx context.Context, in *KMSSignInput) (*KMSSignOutput, error) {
	t.Helper()
	return func(ctx context.Context, in *KMSSignInput) (*KMSSignOutput, error) {
		// KMS receives a pre-hashed digest (MessageType=DIGEST) for
		// RSASSA_PKCS1_V1_5_SHA_512, so we must pass crypto.SHA512 here so
		// that the PKCS1v15 DigestInfo header is encoded correctly.
		sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA512, in.Message)
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

// TestKMSSigner_SignRSA_VerifiesCert verifies that an RSA cert signed via the
// KMS signer path actually passes ssh.CertChecker verification. This is the
// critical regression test for the rsa-sha2-512 signing bug: it checks that
// (a) the CA public key parses, (b) the cert signature format is rsa-sha2-512,
// and (c) the cert verifies against the CA.
func TestKMSSigner_SignRSA_VerifiesCert(t *testing.T) {
	// CA key (simulates the KMS key)
	caKey := generateRSATestKey(t)
	// User key to be certified
	userKey := generateRSATestKey(t)

	der := publicKeyDER(t, &caKey.PublicKey)
	client := &mockKMSClient{
		getPublicKeyFunc: func(_ context.Context, _ *KMSGetPublicKeyInput) (*KMSGetPublicKeyOutput, error) {
			return &KMSGetPublicKeyOutput{PublicKeyDER: der, KeySpec: "RSA_2048"}, nil
		},
		signFunc: realRSASignFunc(t, caKey),
	}

	userSSHPub, err := ssh.NewPublicKey(&userKey.PublicKey)
	if err != nil {
		t.Fatalf("ssh.NewPublicKey for user key: %v", err)
	}

	s := NewKMSSigner("test-ca-key-id", client)
	cert := makeMinimalCert(userSSHPub)

	signed, err := s.Sign(cert)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if signed == nil {
		t.Fatal("Sign returned nil certificate")
	}

	// Assert the cert uses rsa-sha2-512 (not the deprecated ssh-rsa/SHA1).
	if signed.Signature == nil {
		t.Fatal("Signature is nil")
	}
	if signed.Signature.Format != ssh.KeyAlgoRSASHA512 {
		t.Errorf("expected signature format %q, got %q", ssh.KeyAlgoRSASHA512, signed.Signature.Format)
	}

	// Parse the CA public key and build a cert checker.
	caPubSSH, err := ssh.NewPublicKey(&caKey.PublicKey)
	if err != nil {
		t.Fatalf("ssh.NewPublicKey for CA key: %v", err)
	}
	caPubBytes := caPubSSH.Marshal()
	caPubParsed, err := ssh.ParsePublicKey(caPubBytes)
	if err != nil {
		t.Fatalf("ssh.ParsePublicKey CA: %v", err)
	}

	certChecker := &ssh.CertChecker{
		IsUserAuthority: func(auth ssh.PublicKey) bool {
			return auth.Type() == caPubParsed.Type() &&
				string(auth.Marshal()) == string(caPubParsed.Marshal())
		},
	}

	// Round-trip the cert through wire encoding to mimic real SSH handshake parsing.
	certLine := ssh.MarshalAuthorizedKey(signed)
	parsedKey, _, _, _, err := ssh.ParseAuthorizedKey(certLine)
	if err != nil {
		t.Fatalf("parse signed cert authorized key line: %v", err)
	}
	parsedCert, ok := parsedKey.(*ssh.Certificate)
	if !ok {
		t.Fatalf("expected *ssh.Certificate after parse, got %T", parsedKey)
	}

	if err := certChecker.CheckCert("testuser", parsedCert); err != nil {
		t.Errorf("cert verification failed: %v", err)
	}
}

// TestKMSSigner_SignECDSA_VerifiesCert verifies that an ECDSA cert signed via the
// KMS signer path also passes ssh.CertChecker verification, ensuring the ECDSA
// path is unaffected by RSA fixes.
func TestKMSSigner_SignECDSA_VerifiesCert(t *testing.T) {
	caKey := generateECTestKey(t)
	userKey := generateECTestKey(t)

	der := publicKeyDER(t, &caKey.PublicKey)
	client := &mockKMSClient{
		getPublicKeyFunc: func(_ context.Context, _ *KMSGetPublicKeyInput) (*KMSGetPublicKeyOutput, error) {
			return &KMSGetPublicKeyOutput{PublicKeyDER: der, KeySpec: "ECC_NIST_P256"}, nil
		},
		signFunc: realECSignFunc(t, caKey),
	}

	userSSHPub, err := ssh.NewPublicKey(&userKey.PublicKey)
	if err != nil {
		t.Fatalf("ssh.NewPublicKey for user key: %v", err)
	}

	s := NewKMSSigner("test-ca-ec-key-id", client)
	cert := makeMinimalCert(userSSHPub)

	signed, err := s.Sign(cert)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if signed == nil {
		t.Fatal("Sign returned nil certificate")
	}

	// Build cert checker using ECDSA CA public key.
	caPubSSH, err := ssh.NewPublicKey(&caKey.PublicKey)
	if err != nil {
		t.Fatalf("ssh.NewPublicKey for CA key: %v", err)
	}
	caPubBytes := caPubSSH.Marshal()
	caPubParsed, err := ssh.ParsePublicKey(caPubBytes)
	if err != nil {
		t.Fatalf("ssh.ParsePublicKey CA: %v", err)
	}

	certChecker := &ssh.CertChecker{
		IsUserAuthority: func(auth ssh.PublicKey) bool {
			return auth.Type() == caPubParsed.Type() &&
				string(auth.Marshal()) == string(caPubParsed.Marshal())
		},
	}

	certLine := ssh.MarshalAuthorizedKey(signed)
	parsedKey, _, _, _, err := ssh.ParseAuthorizedKey(certLine)
	if err != nil {
		t.Fatalf("parse signed cert: %v", err)
	}
	parsedCert, ok := parsedKey.(*ssh.Certificate)
	if !ok {
		t.Fatalf("expected *ssh.Certificate, got %T", parsedKey)
	}

	if err := certChecker.CheckCert("testuser", parsedCert); err != nil {
		t.Errorf("ECDSA cert verification failed: %v", err)
	}
}
