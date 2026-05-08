//go:build !production

// Package cert contains wire-format and OpenSSH interoperability tests.
// These tests validate signed certificates at the byte/wire level using
// golang.org/x/crypto/ssh, NOT just Go struct field inspection.
package cert

import (
	"context"
	"os"
	"os/exec"
	"sort"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// --------------------------------------------------------------------------
// 1. Round-trip wire validation
// --------------------------------------------------------------------------

func TestWireFormat_RoundTrip_UserCert(t *testing.T) {
	s := testSigner(t)
	pub := testPublicKey(t)

	keyID, err := GenerateKeyID(UserCert, []string{"alice"})
	if err != nil {
		t.Fatalf("GenerateKeyID: %v", err)
	}

	before := time.Now()
	resp, err := Sign(context.Background(), &Request{
		CertType:   UserCert,
		PublicKey:  pub,
		Principals: []string{"alice", "alice-admin"},
		TTL:        time.Hour,
		KeyID:      keyID,
	}, s)
	after := time.Now()
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// Marshal to wire bytes via the authorized-key form and parse back.
	wireBytes := resp.Certificate.Marshal()
	parsed, err := ssh.ParsePublicKey(wireBytes)
	if err != nil {
		t.Fatalf("ssh.ParsePublicKey: %v", err)
	}

	wireCert, ok := parsed.(*ssh.Certificate)
	if !ok {
		t.Fatalf("parsed key is %T, want *ssh.Certificate", parsed)
	}

	// Cert type
	if wireCert.CertType != ssh.UserCert {
		t.Errorf("CertType = %d, want %d (UserCert)", wireCert.CertType, ssh.UserCert)
	}

	// Principals
	if len(wireCert.ValidPrincipals) != 2 ||
		wireCert.ValidPrincipals[0] != "alice" ||
		wireCert.ValidPrincipals[1] != "alice-admin" {
		t.Errorf("ValidPrincipals = %v, want [alice alice-admin]", wireCert.ValidPrincipals)
	}

	// ValidAfter <= now, ValidBefore >= now+TTL-epsilon (5 s tolerance)
	epsilon := 5 * time.Second
	// Allow 1-second slack for Unix second-boundary rollover between before capture and Sign() call
	if wireCert.ValidAfter > uint64(before.Unix()+1) {
		t.Errorf("ValidAfter %d > before+1 %d", wireCert.ValidAfter, before.Unix()+1)
	}
	if wireCert.ValidBefore < uint64(after.Add(time.Hour).Add(-epsilon).Unix()) {
		t.Errorf("ValidBefore %d too small (after=%d ttl=1h eps=5s)", wireCert.ValidBefore, after.Unix())
	}

	// Serial non-zero
	if wireCert.Serial == 0 {
		t.Error("Serial is zero after wire round-trip")
	}

	// KeyId matches expected format  (gobless-user-<principal>-<ts>-<hex>)
	if !strings.HasPrefix(wireCert.KeyId, "gobless-user-alice-") {
		t.Errorf("KeyId = %q, want prefix gobless-user-alice-", wireCert.KeyId)
	}

	// Default extensions present
	expectedExts := []string{
		"permit-pty",
		"permit-user-rc",
		"permit-port-forwarding",
		"permit-agent-forwarding",
		"permit-X11-forwarding",
	}
	for _, ext := range expectedExts {
		if _, ok := wireCert.Permissions.Extensions[ext]; !ok {
			t.Errorf("default extension %q missing from wire-parsed cert", ext)
		}
	}
}

func TestWireFormat_RoundTrip_HostCert(t *testing.T) {
	s := testSigner(t)
	pub := testPublicKey(t)

	resp, err := Sign(context.Background(), &Request{
		CertType:   HostCert,
		PublicKey:  pub,
		Principals: []string{"host.example.internal"},
		TTL:        24 * time.Hour,
		Extensions: map[string]string{}, // host certs have no extensions
	}, s)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	wireBytes := resp.Certificate.Marshal()
	parsed, err := ssh.ParsePublicKey(wireBytes)
	if err != nil {
		t.Fatalf("ssh.ParsePublicKey: %v", err)
	}

	wireCert, ok := parsed.(*ssh.Certificate)
	if !ok {
		t.Fatalf("parsed key is %T, want *ssh.Certificate", parsed)
	}

	if wireCert.CertType != ssh.HostCert {
		t.Errorf("CertType = %d, want %d (HostCert)", wireCert.CertType, ssh.HostCert)
	}
	if len(wireCert.ValidPrincipals) != 1 || wireCert.ValidPrincipals[0] != "host.example.internal" {
		t.Errorf("ValidPrincipals = %v, want [host.example.internal]", wireCert.ValidPrincipals)
	}
	if wireCert.Serial == 0 {
		t.Error("Serial is zero after wire round-trip")
	}
}

// --------------------------------------------------------------------------
// 2. ssh-keygen compatibility
// --------------------------------------------------------------------------

func TestWireFormat_SSHKeygenVerify(t *testing.T) {
	sshKeygen, err := exec.LookPath("ssh-keygen")
	if err != nil {
		t.Skip("ssh-keygen not found on PATH; skipping interoperability test")
	}

	s := testSigner(t)
	pub := testPublicKey(t)

	resp, err := Sign(context.Background(), &Request{
		CertType:   UserCert,
		PublicKey:  pub,
		Principals: []string{"alice", "bob"},
		TTL:        time.Hour,
	}, s)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// Write cert to temp file in authorized_keys format.
	certFile, err := os.CreateTemp(t.TempDir(), "test_cert-*.pub")
	if err != nil {
		t.Fatalf("create temp cert file: %v", err)
	}
	if _, err := certFile.WriteString(resp.AuthorizedKey); err != nil {
		t.Fatalf("write cert file: %v", err)
	}
	certFile.Close()

	// Run ssh-keygen -L -f <cert-file>
	out, err := exec.Command(sshKeygen, "-L", "-f", certFile.Name()).CombinedOutput()
	if err != nil {
		t.Fatalf("ssh-keygen -L failed: %v\noutput:\n%s", err, out)
	}

	outStr := string(out)

	// Assert output contains cert type indication
	if !strings.Contains(outStr, "user certificate") {
		t.Errorf("ssh-keygen output does not contain 'user certificate':\n%s", outStr)
	}

	// Assert output contains principals
	for _, principal := range []string{"alice", "bob"} {
		if !strings.Contains(outStr, principal) {
			t.Errorf("ssh-keygen output does not contain principal %q:\n%s", principal, outStr)
		}
	}
}

// --------------------------------------------------------------------------
// 3. Extension ordering — lexicographic order required by OpenSSH wire format
// --------------------------------------------------------------------------

func TestWireFormat_ExtensionOrdering(t *testing.T) {
	s := testSigner(t)
	pub := testPublicKey(t)

	resp, err := Sign(context.Background(), &Request{
		CertType:   UserCert,
		PublicKey:  pub,
		Principals: []string{"alice"},
		TTL:        time.Hour,
	}, s)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// Parse back from wire to get what OpenSSH would see.
	wireBytes := resp.Certificate.Marshal()
	parsed, err := ssh.ParsePublicKey(wireBytes)
	if err != nil {
		t.Fatalf("ssh.ParsePublicKey: %v", err)
	}
	wireCert := parsed.(*ssh.Certificate)

	// The OpenSSH wire format requires extensions be encoded in lexicographic
	// order. Verify by checking the byte positions of extension names in the
	// raw wire bytes appear in sorted order.
	extKeys := make([]string, 0, len(wireCert.Permissions.Extensions))
	for k := range wireCert.Permissions.Extensions {
		extKeys = append(extKeys, k)
	}
	sortedKeys := make([]string, len(extKeys))
	copy(sortedKeys, extKeys)
	sort.Strings(sortedKeys)

	lastPos := -1
	for _, k := range sortedKeys {
		pos := strings.Index(string(wireBytes), k)
		if pos < 0 {
			t.Errorf("extension %q not found in wire bytes", k)
			continue
		}
		if pos <= lastPos {
			t.Errorf("extension %q not in lexicographic order in wire bytes (pos=%d, lastPos=%d)", k, pos, lastPos)
		}
		lastPos = pos
	}
}

func TestWireFormat_CriticalOptionOrdering(t *testing.T) {
	s := testSigner(t)
	pub := testPublicKey(t)

	resp, err := Sign(context.Background(), &Request{
		CertType:      UserCert,
		PublicKey:     pub,
		Principals:    []string{"alice"},
		TTL:           time.Hour,
		SourceAddress: "10.0.0.0/8",
		ForceCommand:  "/bin/sh",
	}, s)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	wireBytes := resp.Certificate.Marshal()
	parsed, err := ssh.ParsePublicKey(wireBytes)
	if err != nil {
		t.Fatalf("ssh.ParsePublicKey: %v", err)
	}
	wireCert := parsed.(*ssh.Certificate)

	critKeys := make([]string, 0, len(wireCert.Permissions.CriticalOptions))
	for k := range wireCert.Permissions.CriticalOptions {
		critKeys = append(critKeys, k)
	}
	sortedKeys := make([]string, len(critKeys))
	copy(sortedKeys, critKeys)
	sort.Strings(sortedKeys)

	// Check positions in wire bytes are in sorted order.
	wireBytes2 := resp.Certificate.Marshal()
	lastPos := -1
	for _, k := range sortedKeys {
		pos := strings.Index(string(wireBytes2), k)
		if pos < 0 {
			t.Errorf("critical option %q not found in wire bytes", k)
			continue
		}
		if pos <= lastPos {
			t.Errorf("critical option %q not in lexicographic order in wire bytes (pos=%d, lastPos=%d)", k, pos, lastPos)
		}
		lastPos = pos
	}
}

// --------------------------------------------------------------------------
// 4. Cert type normalization at wire level
// --------------------------------------------------------------------------

func TestWireFormat_CertTypeNormalization(t *testing.T) {
	s := testSigner(t)
	pub := testPublicKey(t)

	tests := []struct {
		name         string
		reqCertType  CertType
		wantWireType uint32
		extensions   map[string]string
	}{
		{
			name:         "user produces ssh.UserCert at wire level",
			reqCertType:  UserCert,
			wantWireType: ssh.UserCert,
		},
		{
			name:         "host produces ssh.HostCert at wire level",
			reqCertType:  HostCert,
			wantWireType: ssh.HostCert,
			extensions:   map[string]string{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := Sign(context.Background(), &Request{
				CertType:   tc.reqCertType,
				PublicKey:  pub,
				Principals: []string{"test-principal"},
				TTL:        time.Hour,
				Extensions: tc.extensions,
			}, s)
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}

			wireBytes := resp.Certificate.Marshal()
			parsed, err := ssh.ParsePublicKey(wireBytes)
			if err != nil {
				t.Fatalf("ssh.ParsePublicKey: %v", err)
			}
			wireCert, ok := parsed.(*ssh.Certificate)
			if !ok {
				t.Fatalf("parsed key is %T, want *ssh.Certificate", parsed)
			}

			if wireCert.CertType != tc.wantWireType {
				t.Errorf("wire CertType = %d, want %d", wireCert.CertType, tc.wantWireType)
			}
		})
	}
}

// --------------------------------------------------------------------------
// 5. ValidBefore/ValidAfter — TTL encoded correctly at wire level
// --------------------------------------------------------------------------

func TestWireFormat_ValidBeforeAfter(t *testing.T) {
	s := testSigner(t)
	pub := testPublicKey(t)

	ttl := 2 * time.Hour
	epsilon := 5 * time.Second

	before := time.Now()
	resp, err := Sign(context.Background(), &Request{
		CertType:   UserCert,
		PublicKey:  pub,
		Principals: []string{"alice"},
		TTL:        ttl,
	}, s)
	after := time.Now()
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	wireBytes := resp.Certificate.Marshal()
	parsed, err := ssh.ParsePublicKey(wireBytes)
	if err != nil {
		t.Fatalf("ssh.ParsePublicKey: %v", err)
	}
	wireCert := parsed.(*ssh.Certificate)

	// ValidAfter <= now (at call time); allow 1-second slack for Unix second-boundary rollover
	if wireCert.ValidAfter > uint64(before.Unix()+1) {
		t.Errorf("ValidAfter %d > before+1 %d (cert not yet valid at signing time)", wireCert.ValidAfter, before.Unix()+1)
	}

	// ValidBefore >= now + TTL - epsilon
	minValidBefore := uint64(after.Add(ttl).Add(-epsilon).Unix())
	if wireCert.ValidBefore < minValidBefore {
		t.Errorf("ValidBefore %d < %d (now+TTL-eps); TTL not encoded correctly", wireCert.ValidBefore, minValidBefore)
	}

	// Sanity: ValidBefore - ValidAfter is approximately TTL
	duration := time.Duration(wireCert.ValidBefore-wireCert.ValidAfter) * time.Second
	if duration < ttl-epsilon || duration > ttl+epsilon {
		t.Errorf("wire TTL duration = %v, want ~%v (±%v)", duration, ttl, epsilon)
	}
}

func TestWireFormat_TTL_Boundary_OneSecond(t *testing.T) {
	s := testSigner(t)
	pub := testPublicKey(t)

	resp, err := Sign(context.Background(), &Request{
		CertType:   UserCert,
		PublicKey:  pub,
		Principals: []string{"alice"},
		TTL:        time.Second,
	}, s)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	wireBytes := resp.Certificate.Marshal()
	parsed, err := ssh.ParsePublicKey(wireBytes)
	if err != nil {
		t.Fatalf("ssh.ParsePublicKey: %v", err)
	}
	wireCert := parsed.(*ssh.Certificate)

	diff := wireCert.ValidBefore - wireCert.ValidAfter
	if diff != 1 {
		t.Errorf("TTL=1s: wire ValidBefore-ValidAfter = %d, want 1", diff)
	}
}
