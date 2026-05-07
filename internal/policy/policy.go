// Package policy implements the GoBless request validation and signing policy engine.
// It sits between the Lambda handler (untrusted input) and the cert signer (trusted output).
// FAIL CLOSED — any ambiguity is a deny.
package policy

import (
	"context"
	"net"
	"regexp"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/FtlC-ian/gobless/internal/cert"
	"github.com/FtlC-ian/gobless/internal/config"
)

// Request holds the raw (untrusted) input for a certificate signing operation.
type Request struct {
	// IAM context — populated by Lambda handler from trusted AWS context
	IAMCallerARN string // full ARN of the invoking principal
	IAMAccountID string // AWS account ID
	IAMUsername  string // username portion (from ARN or session name)

	// Cert request — from untrusted request body
	PublicKey           string // raw authorized-keys line
	CertType            string // "user" or "host"
	RequestedPrincipals []string
	TTLSeconds          int64
	SourceAddress       string            // optional
	ForceCommand        string            // optional
	Extensions          map[string]string // optional, nil=defaults

	// Request metadata
	RemoteAddr string // Lambda source context if available
}

// Decision is the result of policy evaluation.
type Decision struct {
	Approved     bool
	DenialReason string // safe to return to caller (no internal detail)

	// Validated/sanitized fields ready for cert.Request
	Principals    []string
	TTL           time.Duration
	CertType      cert.CertType
	PublicKey     ssh.PublicKey
	SourceAddress string
	ForceCommand  string
	Extensions    map[string]string
	KeyID         string
}

// validPrincipalRE matches only safe principal characters.
var validPrincipalRE = regexp.MustCompile(`^[a-zA-Z0-9._@-]+$`)

// privilegedPrincipals lists well-known system/cloud accounts that must not be granted without an explicit allowlist.
var privilegedPrincipals = map[string]bool{
	"root":      true,
	"ec2-user":  true,
	"ubuntu":    true,
	"admin":     true,
	"ssm-user":  true,
	"opc":       true,
	"azureuser": true,
	"centos":    true,
	"fedora":    true,
	"bitnami":   true,
	"clouduser": true,
	"core":      true,
	"hadoop":    true,
}

// deny returns a Decision with Approved=false and the given safe reason string.
func deny(reason string) (*Decision, error) {
	return &Decision{Approved: false, DenialReason: reason}, nil
}

// Evaluate validates and authorises a signing request against the given config.
// It returns (Decision{Approved:true, ...}, nil) on success, or
// (Decision{Approved:false, DenialReason:"..."}, nil) on any policy rejection.
// An error is returned only for unexpected internal failures (e.g. key ID generation).
func Evaluate(ctx context.Context, req *Request, cfg *config.Config) (*Decision, error) {
	// 1. Parse and validate public key.
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(req.PublicKey))
	if err != nil || pub == nil {
		return deny("invalid public key")
	}

	// 2. Reject RSA keys below cfg.CA.RSAMinKeyBits (belt-and-suspenders; cert.Sign also checks).
	minBits := cfg.CA.RSAMinKeyBits
	if minBits == 0 {
		minBits = 2048
	}
	if strings.HasPrefix(pub.Type(), "ssh-rsa") {
		bits := rsaPublicKeyBits(pub)
		if bits > 0 && bits < minBits {
			return deny("RSA key too small")
		}
	}

	// 3. Validate and normalize CertType.
	var certType cert.CertType
	switch strings.ToLower(strings.TrimSpace(req.CertType)) {
	case "user":
		certType = cert.UserCert
	case "host":
		certType = cert.HostCert
	default:
		return deny("invalid certificate type")
	}

	// If AllowedCertTypes is configured, enforce it.
	if len(cfg.Principal.AllowedCertTypes) > 0 {
		normalised := strings.ToLower(strings.TrimSpace(req.CertType))
		allowed := false
		for _, t := range cfg.Principal.AllowedCertTypes {
			if strings.ToLower(strings.TrimSpace(t)) == normalised {
				allowed = true
				break
			}
		}
		if !allowed {
			return deny("certificate type not allowed")
		}
	}

	// 4. Validate TTLSeconds.
	if req.TTLSeconds <= 0 {
		return deny("TTL must be positive")
	}
	maxTTL := int64(cfg.CA.MaxTTL)
	if maxTTL > 0 && req.TTLSeconds > maxTTL {
		return deny("TTL exceeds maximum")
	}
	ttl := time.Duration(req.TTLSeconds) * time.Second

	// 5. Validate principals.
	if len(req.RequestedPrincipals) == 0 {
		return deny("principals must not be empty")
	}
	seen := make(map[string]bool, len(req.RequestedPrincipals))
	for _, p := range req.RequestedPrincipals {
		// Reject empty / whitespace-only.
		if strings.TrimSpace(p) == "" {
			return deny("invalid principal")
		}
		// Strict allowlist: only [a-zA-Z0-9._@-].
		// This also rejects NUL bytes, newlines, Unicode homoglyphs, etc.
		if !validPrincipalRE.MatchString(p) {
			return deny("invalid principal")
		}
		// Reject duplicates.
		lo := strings.ToLower(p)
		if seen[lo] {
			return deny("duplicate principal")
		}
		seen[lo] = true
	}

	// IAM account ID check (if configured).
	if cfg.Principal.ExpectedAccountID != "" {
		if req.IAMAccountID != cfg.Principal.ExpectedAccountID {
			return deny("IAM account mismatch")
		}
	}

	// IAM username binding (if enforced).
	if cfg.Principal.EnforceIAMBinding {
		matched := false
		for _, p := range req.RequestedPrincipals {
			if strings.EqualFold(p, req.IAMUsername) {
				matched = true
				break
			}
		}
		if !matched {
			return deny("principal does not match IAM identity")
		}
	}

	// 6. Allowed principal allowlist.
	if len(cfg.Principal.Allowed) > 0 {
		allowedSet := make(map[string]bool, len(cfg.Principal.Allowed))
		for _, a := range cfg.Principal.Allowed {
			allowedSet[strings.ToLower(a)] = true
		}
		for _, p := range req.RequestedPrincipals {
			if !allowedSet[strings.ToLower(p)] {
				return deny("principal not in allowed list")
			}
		}
	} else {
		// No explicit allowlist — still reject well-known privileged principals.
		for _, p := range req.RequestedPrincipals {
			if privilegedPrincipals[strings.ToLower(p)] {
				return deny("privileged principal not in allowed list")
			}
		}
	}

	// 7. Validate SourceAddress if non-empty.
	sourceAddress := req.SourceAddress
	if sourceAddress != "" {
		parts := strings.Split(sourceAddress, ",")
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if _, _, err := net.ParseCIDR(part); err != nil {
				return deny("invalid source address")
			}
		}
	}

	// 8. Generate KeyID.
	keyID, err := cert.GenerateKeyID(certType, req.RequestedPrincipals)
	if err != nil {
		// internal failure
		return nil, err
	}

	// 9. Return approval.
	return &Decision{
		Approved:      true,
		Principals:    req.RequestedPrincipals,
		TTL:           ttl,
		CertType:      certType,
		PublicKey:     pub,
		SourceAddress: sourceAddress,
		ForceCommand:  req.ForceCommand,
		Extensions:    req.Extensions,
		KeyID:         keyID,
	}, nil
}

// rsaPublicKeyBits returns the RSA modulus bit-length from the ssh.PublicKey wire encoding.
// Returns 0 if the key is not RSA or cannot be parsed.
func rsaPublicKeyBits(pub ssh.PublicKey) int {
	wire := pub.Marshal()
	if len(wire) < 4 {
		return 0
	}
	nameLen := int(wire[0])<<24 | int(wire[1])<<16 | int(wire[2])<<8 | int(wire[3])
	if len(wire) < 4+nameLen+4 {
		return 0
	}
	off := 4 + nameLen
	eLen := int(wire[off])<<24 | int(wire[off+1])<<16 | int(wire[off+2])<<8 | int(wire[off+3])
	off += 4 + eLen
	if len(wire) < off+4 {
		return 0
	}
	nLen := int(wire[off])<<24 | int(wire[off+1])<<16 | int(wire[off+2])<<8 | int(wire[off+3])
	off += 4
	if len(wire) < off+nLen {
		return 0
	}
	nBytes := wire[off : off+nLen]
	if len(nBytes) > 0 && nBytes[0] == 0 {
		nBytes = nBytes[1:]
	}
	if len(nBytes) == 0 {
		return 0
	}
	topByte := nBytes[0]
	topBits := 0
	for topByte > 0 {
		topBits++
		topByte >>= 1
	}
	return (len(nBytes)-1)*8 + topBits
}
