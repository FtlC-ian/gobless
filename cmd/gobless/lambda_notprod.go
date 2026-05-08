//go:build !production

package main

import (
	"log"

	"github.com/FtlC-ian/gobless/internal/audit"
	gobconfig "github.com/FtlC-ian/gobless/internal/config"
	"github.com/FtlC-ian/gobless/internal/signer"
)

// mustSigner returns a signer.Signer or fatals.
// In non-production builds, this always fatals to prevent accidental use without a real signer.
func mustSigner(cfg *gobconfig.Config) signer.Signer {
	log.Fatalf("gobless: mustSigner: wire a signer implementation before deploying (cfg.CA.SignerType=%q)", cfg.CA.SignerType)
	return nil // unreachable
}

// mustAuditRepo returns an audit.Repository or fatals.
func mustAuditRepo(cfg *gobconfig.Config) audit.Repository {
	if !cfg.Logging.AuditEnabled {
		return &audit.NoopRepository{}
	}
	log.Fatalf("gobless: mustAuditRepo: wire a DynamoDB audit repository before deploying")
	return nil // unreachable
}
