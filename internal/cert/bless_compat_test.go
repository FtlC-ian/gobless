//go:build !production

// Package cert – BLESS golden compatibility harness.
//
// Netflix BLESS (https://github.com/Netflix/bless) was an AWS Lambda-based SSH
// CA written in Python.  GoBless is a Go reimplementation that aims to be
// wire-compatible with the certificates BLESS produced.
//
// This file documents and asserts the compatibility points so that regressions
// are caught immediately.
package cert

import (
	"bytes"
	"context"
	"maps"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// blessDefaultExtensions is the exact set of extensions that Netflix BLESS
// inserts into every user cert.  They are the same five permit-* keys that
// OpenSSH uses as defaults, in lexicographic order (BLESS sorts them).
var blessDefaultExtensions = map[string]string{
	"permit-X11-forwarding":   "",
	"permit-agent-forwarding": "",
	"permit-port-forwarding":  "",
	"permit-pty":              "",
	"permit-user-rc":          "",
}

// TestBLESSCompatUserCert validates that a GoBless user cert matches the BLESS
// wire-level shape.
func TestBLESSCompatUserCert(t *testing.T) {
	s := testSigner(t)
	pub := testPublicKey(t)

	// TTL = 240s  (BLESS default: validity_before_seconds=120 + validity_after_seconds=120).
	// GoBless uses now/now+TTL; BLESS backdates ValidAfter by validity_before_seconds.
	// Both produce a cert that is valid "now", which is what matters operationally.
	req := &Request{
		CertType:   UserCert,
		PublicKey:  pub,
		Principals: []string{"alice"},
		TTL:        240 * time.Second,
		// source-address is required in BLESS user certs; it is enforced by
		// policy config in GoBless (see docs/BLESS_COMPATIBILITY.md).
		SourceAddress: "10.0.0.0/8",
		// Extensions nil → GoBless applies the five BLESS defaults automatically.
		Extensions: nil,
		KeyID:      "gobless-user-alice-test",
	}

	resp, err := Sign(context.Background(), req, s)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	c := resp.Certificate

	// CertType must be UserCert.
	if c.CertType != ssh.UserCert {
		t.Errorf("CertType = %d, want ssh.UserCert (%d)", c.CertType, ssh.UserCert)
	}

	// Principals must round-trip unchanged.
	if len(c.ValidPrincipals) != 1 || c.ValidPrincipals[0] != "alice" {
		t.Errorf("ValidPrincipals = %v, want [alice]", c.ValidPrincipals)
	}

	// Extensions must exactly match the BLESS set.
	if !maps.Equal(c.Permissions.Extensions, blessDefaultExtensions) {
		t.Errorf("Extensions = %v, want %v", c.Permissions.Extensions, blessDefaultExtensions)
	}

	// source-address critical option must be present.
	if got, ok := c.Permissions.CriticalOptions["source-address"]; !ok {
		t.Error("source-address critical option missing")
	} else if got != "10.0.0.0/8" {
		t.Errorf("source-address = %q, want 10.0.0.0/8", got)
	}

	// Serial: BLESS always emits serial=0.  GoBless intentionally uses a
	// non-zero random serial to support revocation and audit log correlation
	// (see docs/adr/003-serial-generation.md).  This is a deliberate
	// improvement; operators should be aware of the difference.
	if c.Serial == 0 {
		t.Error("Serial is zero; GoBless must generate a non-zero random serial")
	}

	// KeyID: BLESS uses a structured string embedding bastion metadata.
	// GoBless uses a different format (gobless-<type>-<principal>-<ts>-<random>).
	// Both are non-empty opaque strings for sshd audit logs; exact format intentionally differs.
	// See docs/BLESS_COMPATIBILITY.md § KeyID Format.
	if c.KeyId == "" {
		t.Error("KeyId is empty; must be non-empty for audit traceability")
	}

	// Validity window: GoBless sets ValidAfter=now, ValidBefore=now+TTL.
	// BLESS sets ValidAfter=now-validity_before_seconds.
	// Both produce a cert that is valid at the current moment.
	now := uint64(time.Now().Unix())
	if c.ValidAfter > now {
		t.Errorf("ValidAfter %d is in the future (now=%d); cert is not yet valid", c.ValidAfter, now)
	}
	if c.ValidBefore < now {
		t.Errorf("ValidBefore %d is in the past (now=%d); cert has already expired", c.ValidBefore, now)
	}
}

// TestBLESSCompatHostCert validates that a GoBless host cert has NO extensions,
// matching BLESS behaviour for host certs.  This test also exercises the bug
// fix in cert.go that prevents user-cert default extensions from leaking into
// host certs when Extensions is nil.
func TestBLESSCompatHostCert(t *testing.T) {
	s := testSigner(t)
	pub := testPublicKey(t)

	req := &Request{
		CertType:   HostCert,
		PublicKey:  pub,
		Principals: []string{"web01.example.internal"},
		TTL:        365 * 24 * time.Hour,
		// Extensions deliberately nil – the bug fix must default to empty for host certs.
		Extensions: nil,
		KeyID:      "gobless-host-web01-test",
	}

	resp, err := Sign(context.Background(), req, s)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	c := resp.Certificate

	if c.CertType != ssh.HostCert {
		t.Errorf("CertType = %d, want ssh.HostCert (%d)", c.CertType, ssh.HostCert)
	}

	// Host certs MUST have zero extensions (BLESS and OpenSSH both require this).
	if len(c.Permissions.Extensions) != 0 {
		t.Errorf("host cert Extensions = %v, want empty map", c.Permissions.Extensions)
	}

	if len(c.ValidPrincipals) != 1 || c.ValidPrincipals[0] != "web01.example.internal" {
		t.Errorf("ValidPrincipals = %v, want [web01.example.internal]", c.ValidPrincipals)
	}

	// Same serial improvement as user certs.
	if c.Serial == 0 {
		t.Error("Serial is zero; GoBless must generate a non-zero random serial")
	}
}

// TestBLESSCompatExtensionsExact asserts byte-for-byte that the marshalled
// extension map in a GoBless user cert equals BLESS's five-extension set.
// This catches any future drift (added extensions, removed extensions, or
// value changes).
func TestBLESSCompatExtensionsExact(t *testing.T) {
	s := testSigner(t)
	pub := testPublicKey(t)

	resp, err := Sign(context.Background(), &Request{
		CertType:   UserCert,
		PublicKey:  pub,
		Principals: []string{"alice"},
		TTL:        time.Hour,
		Extensions: nil, // use defaults
	}, s)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	got := resp.Certificate.Permissions.Extensions
	if len(got) != len(blessDefaultExtensions) {
		t.Fatalf("Extensions len = %d, want %d; got %v", len(got), len(blessDefaultExtensions), got)
	}

	// Encode both maps to a canonical byte representation and compare.
	// ssh.Certificate marshals extensions in sorted key order.
	gotBytes := marshalExtensions(got)
	wantBytes := marshalExtensions(blessDefaultExtensions)
	if !bytes.Equal(gotBytes, wantBytes) {
		t.Errorf("marshalled extensions differ:\n  got:  %x\n  want: %x", gotBytes, wantBytes)
	}
}

// marshalExtensions encodes a string→string map as a canonical sorted-key
// byte sequence (key\x00value\x00 pairs) for comparison purposes.
func marshalExtensions(m map[string]string) []byte {
	// Use ssh.Certificate's own marshalling indirectly via sortedKeys.
	keys := sortedKeys(m)
	var buf bytes.Buffer
	for _, k := range keys {
		buf.WriteString(k)
		buf.WriteByte(0)
		buf.WriteString(m[k])
		buf.WriteByte(0)
	}
	return buf.Bytes()
}

// TestBLESSCompatSourceAddressRequired documents and tests that BLESS-compatible
// user certs always carry the source-address critical option.
//
// In BLESS this is hard-coded: every user cert includes bastion_ips as the
// source-address.  In GoBless the field is caller-supplied; operators MUST
// set it in their policy/handler to achieve the same security property.
//
// This test signs a cert with source-address and verifies the critical option
// is present in the issued cert.
func TestBLESSCompatSourceAddressRequired(t *testing.T) {
	s := testSigner(t)
	pub := testPublicKey(t)

	bastionIPs := "10.10.0.0/16,172.16.0.0/12"
	resp, err := Sign(context.Background(), &Request{
		CertType:      UserCert,
		PublicKey:     pub,
		Principals:    []string{"bob"},
		TTL:           240 * time.Second,
		SourceAddress: bastionIPs,
	}, s)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	c := resp.Certificate
	sa, ok := c.Permissions.CriticalOptions["source-address"]
	if !ok {
		t.Fatal("source-address critical option missing; BLESS-compatible certs must include it")
	}
	if sa != bastionIPs {
		t.Errorf("source-address = %q, want %q", sa, bastionIPs)
	}

	// source-address is a critical option; sshd will reject the cert if it
	// does not understand it.  Confirm it is NOT in extensions (wrong bucket).
	if _, inExt := c.Permissions.Extensions["source-address"]; inExt {
		t.Error("source-address must be in CriticalOptions, not Extensions")
	}
}

// TestHostCertExplicitExtensionsIgnored verifies that a non-empty Extensions
// map passed with a host cert request is silently discarded. Host certs must
// have zero extensions per the OpenSSH spec and BLESS compatibility.
func TestHostCertExplicitExtensionsIgnored(t *testing.T) {
	s := testSigner(t)
	pub := testPublicKey(t)

	req := &Request{
		CertType:   HostCert,
		PublicKey:  pub,
		Principals: []string{"db01.example.internal"},
		TTL:        365 * 24 * time.Hour,
		// Explicitly pass non-empty extensions — cert layer must ignore them.
		Extensions: map[string]string{
			"permit-pty":             "",
			"permit-port-forwarding": "",
		},
		KeyID: "gobless-host-db01-test",
	}

	resp, err := Sign(context.Background(), req, s)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// Regardless of what the caller passed, host cert MUST have zero extensions.
	if got := resp.Certificate.Permissions.Extensions; len(got) != 0 {
		t.Errorf("host cert Extensions = %v, want empty map (explicit caller extensions must be ignored)", got)
	}
}

// TestHostCertNilExtensionsEmpty confirms the existing nil-extensions behavior:
// a host cert request with Extensions=nil produces a cert with zero extensions.
func TestHostCertNilExtensionsEmpty(t *testing.T) {
	s := testSigner(t)
	pub := testPublicKey(t)

	req := &Request{
		CertType:   HostCert,
		PublicKey:  pub,
		Principals: []string{"web02.example.internal"},
		TTL:        365 * 24 * time.Hour,
		Extensions: nil,
		KeyID:      "gobless-host-web02-test",
	}

	resp, err := Sign(context.Background(), req, s)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	if got := resp.Certificate.Permissions.Extensions; len(got) != 0 {
		t.Errorf("host cert Extensions = %v, want empty map", got)
	}
}

// TestHostCertEmptyMapExtensionsEmpty confirms that an explicit empty
// Extensions map on a host cert also produces a cert with zero extensions.
func TestHostCertEmptyMapExtensionsEmpty(t *testing.T) {
	s := testSigner(t)
	pub := testPublicKey(t)

	req := &Request{
		CertType:   HostCert,
		PublicKey:  pub,
		Principals: []string{"cache01.example.internal"},
		TTL:        365 * 24 * time.Hour,
		Extensions: map[string]string{}, // explicit empty map
		KeyID:      "gobless-host-cache01-test",
	}

	resp, err := Sign(context.Background(), req, s)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	if got := resp.Certificate.Permissions.Extensions; len(got) != 0 {
		t.Errorf("host cert Extensions = %v, want empty map", got)
	}
}
