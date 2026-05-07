//go:build e2e

package e2e_test

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/FtlC-ian/gobless/internal/cli"
)

// requireSSHKeygen skips the test if ssh-keygen is not found in PATH.
func requireSSHKeygen(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen not found in PATH; skipping")
	}
}

// testEnv holds keys and config generated during TestMain setup.
var testEnv struct {
	configPath  string
	userPubPath string
	caPrivPath  string
	caPubKey    ssh.PublicKey
}

func TestMain(m *testing.M) {
	tmpDir, err := os.MkdirTemp("", "gobless-e2e-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create tmpdir: %v\n", err)
		os.Exit(1)
	}
	defer os.RemoveAll(tmpDir)

	// Generate CA key (RSA 4096).
	caKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to generate CA key: %v\n", err)
		os.Exit(1)
	}
	caPrivPath := filepath.Join(tmpDir, "ca_rsa")
	caPrivPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(caKey),
	})
	if err := os.WriteFile(caPrivPath, caPrivPEM, 0600); err != nil {
		fmt.Fprintf(os.Stderr, "failed to write CA private key: %v\n", err)
		os.Exit(1)
	}

	caPub, err := ssh.NewPublicKey(&caKey.PublicKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to derive CA public key: %v\n", err)
		os.Exit(1)
	}

	// Generate user key (RSA 2048).
	userKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to generate user key: %v\n", err)
		os.Exit(1)
	}
	userPubSSH, err := ssh.NewPublicKey(&userKey.PublicKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to derive user public key: %v\n", err)
		os.Exit(1)
	}
	userPubPath := filepath.Join(tmpDir, "user_rsa.pub")
	if err := os.WriteFile(userPubPath, ssh.MarshalAuthorizedKey(userPubSSH), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "failed to write user public key: %v\n", err)
		os.Exit(1)
	}

	// Write minimal config.
	configPath := filepath.Join(tmpDir, "gobless.cfg")
	configContent := fmt.Sprintf(`[CA]
private_key_file = %s
signer_type = rsa
default_ttl = 300
max_ttl = 86400
rsa_min_key_bits = 2048

[Principal]
allowed = testuser,example.com
enforce_iam_binding = false

[Lambda]
region = us-east-1
function_name = gobless-e2e-test

[Logging]
level = info
audit_enabled = false
`, caPrivPath)
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "failed to write config: %v\n", err)
		os.Exit(1)
	}

	testEnv.configPath = configPath
	testEnv.userPubPath = userPubPath
	testEnv.caPrivPath = caPrivPath
	testEnv.caPubKey = caPub

	os.Exit(m.Run())
}

// signCert calls cli.RunSign and returns the certificate string or error.
func signCert(t *testing.T, certType string, principals []string, ttl int) (string, error) {
	t.Helper()
	args := []string{
		"-config", testEnv.configPath,
		"-public-key", testEnv.userPubPath,
		"-cert-type", certType,
		"-principals", joinPrincipals(principals),
		"-ttl", fmt.Sprintf("%d", ttl),
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	// Redirect stderr to a buffer (RunSign writes flag errors there)
	err := cli.RunSign(args, &stdout, &stderr)
	if err != nil {
		return "", err
	}
	return stdout.String(), nil
}

func joinPrincipals(ps []string) string {
	result := ""
	for i, p := range ps {
		if i > 0 {
			result += ","
		}
		result += p
	}
	return result
}

// parseCert parses an authorized-key formatted certificate from a string.
func parseCert(t *testing.T, certStr string) *ssh.Certificate {
	t.Helper()
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(certStr))
	if err != nil {
		t.Fatalf("failed to parse authorized key: %v", err)
	}
	cert, ok := pub.(*ssh.Certificate)
	if !ok {
		t.Fatalf("parsed key is not a certificate, got %T", pub)
	}
	return cert
}

// writeCertFile writes a certificate to a temp file and returns the path.
func writeCertFile(t *testing.T, certStr string) string {
	t.Helper()
	f, err := os.CreateTemp("", "gobless-cert-*.pub")
	if err != nil {
		t.Fatalf("failed to create cert tmpfile: %v", err)
	}
	t.Cleanup(func() { os.Remove(f.Name()) })
	if _, err := f.WriteString(certStr); err != nil {
		t.Fatalf("failed to write cert: %v", err)
	}
	f.Close()
	return f.Name()
}

// sshKeygenL runs ssh-keygen -L -f <path> and asserts exit 0.
func sshKeygenL(t *testing.T, certPath string) {
	t.Helper()
	requireSSHKeygen(t)
	cmd := exec.Command("ssh-keygen", "-L", "-f", certPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("ssh-keygen -L failed: %v\noutput: %s", err, out)
	}
}

// ---- Tests ----

func TestSignAndVerify_UserCert(t *testing.T) {
	certStr, err := signCert(t, "user", []string{"testuser"}, 300)
	if err != nil {
		t.Fatalf("RunSign failed: %v", err)
	}

	cert := parseCert(t, certStr)

	if cert.CertType != ssh.UserCert {
		t.Errorf("expected UserCert (%d), got %d", ssh.UserCert, cert.CertType)
	}
	if len(cert.ValidPrincipals) != 1 || cert.ValidPrincipals[0] != "testuser" {
		t.Errorf("expected principals [testuser], got %v", cert.ValidPrincipals)
	}
	if cert.ValidBefore <= cert.ValidAfter {
		t.Errorf("expected ValidBefore > ValidAfter, got before=%d after=%d", cert.ValidBefore, cert.ValidAfter)
	}
	if _, ok := cert.Extensions["permit-pty"]; !ok {
		t.Errorf("expected permit-pty extension, extensions: %v", cert.Extensions)
	}

	certPath := writeCertFile(t, certStr)
	sshKeygenL(t, certPath)
}

func TestSignAndVerify_HostCert(t *testing.T) {
	certStr, err := signCert(t, "host", []string{"example.com"}, 300)
	if err != nil {
		t.Fatalf("RunSign failed: %v", err)
	}

	cert := parseCert(t, certStr)

	if cert.CertType != ssh.HostCert {
		t.Errorf("expected HostCert (%d), got %d", ssh.HostCert, cert.CertType)
	}
	if len(cert.ValidPrincipals) != 1 || cert.ValidPrincipals[0] != "example.com" {
		t.Errorf("expected principals [example.com], got %v", cert.ValidPrincipals)
	}

	certPath := writeCertFile(t, certStr)
	sshKeygenL(t, certPath)
}

func TestExpiredCert_Rejected(t *testing.T) {
	certStr, err := signCert(t, "user", []string{"testuser"}, 1)
	if err != nil {
		t.Fatalf("RunSign failed: %v", err)
	}

	// Wait for TTL to elapse.
	time.Sleep(2 * time.Second)

	cert := parseCert(t, certStr)

	now := time.Now().Unix()
	if int64(cert.ValidBefore) >= now {
		t.Errorf("expected cert to be expired: ValidBefore=%d, now=%d", cert.ValidBefore, now)
	}

	// ssh-keygen -L should still parse it successfully (expiry enforcement is sshd's job).
	certPath := writeCertFile(t, certStr)
	sshKeygenL(t, certPath)
}

func TestInvalidPrincipal_Denied(t *testing.T) {
	_, err := signCert(t, "user", []string{"root"}, 300)
	if err == nil {
		t.Fatal("expected RunSign to return an error for principal 'root', but got nil")
	}
	// Assert specifically that this is a policy denial (ErrorType == "Denied"), not a
	// config error, signing error, or panic. cli.RunSign formats the error as
	// "gobless sign: <ErrorType>: <ErrorMsg>" so we check for the "Denied:" token.
	if !strings.Contains(err.Error(), "Denied:") {
		t.Fatalf("expected a policy denial error (containing \"Denied:\"), got: %v", err)
	}
}

func TestCAPublicKey_Roundtrip(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	err := cli.RunCAPubKey([]string{"-config", testEnv.configPath}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("RunCAPubKey failed: %v", err)
	}

	pub, _, _, _, err := ssh.ParseAuthorizedKey(stdout.Bytes())
	if err != nil {
		t.Fatalf("failed to parse CA public key output: %v", err)
	}

	if !bytes.Equal(pub.Marshal(), testEnv.caPubKey.Marshal()) {
		t.Error("CA public key from RunCAPubKey does not match the key generated in setup")
	}
}
