//go:build !production

package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/user"
	"strings"

	"github.com/FtlC-ian/gobless/internal/audit"
	"github.com/FtlC-ian/gobless/internal/config"
	gobless "github.com/FtlC-ian/gobless/internal/lambda"
	"github.com/FtlC-ian/gobless/internal/signer"
)

// RunSign implements the `gobless sign` subcommand.
func RunSign(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("gobless sign", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", "", "path to config file (required)")
	publicKeyPath := fs.String("public-key", "", "path to SSH public key file to sign")
	principalsStr := fs.String("principals", "", "comma-separated list of principals")
	certType := fs.String("cert-type", "user", `cert type: "user" or "host"`)
	ttl := fs.Int("ttl", 3600, "TTL in seconds")
	sourceAddress := fs.String("source-address", "", "optional CIDR source address")
	outPath := fs.String("out", "", "output file path (default: stdout)")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *configPath == "" {
		fmt.Fprintln(stderr, "gobless sign: -config is required")
		fs.Usage()
		return fmt.Errorf("missing required flag: -config")
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return fmt.Errorf("gobless sign: load config: %w", err)
	}

	s, err := buildLocalSigner(cfg)
	if err != nil {
		return fmt.Errorf("gobless sign: build signer: %w", err)
	}

	auditRepo := &audit.NoopRepository{}
	handler := gobless.NewHandler(cfg, s, auditRepo)

	var pubKeyData string
	if *publicKeyPath != "" {
		data, err := os.ReadFile(*publicKeyPath)
		if err != nil {
			return fmt.Errorf("gobless sign: read public key: %w", err)
		}
		pubKeyData = strings.TrimSpace(string(data))
	}

	var principals []string
	if *principalsStr != "" {
		for _, p := range strings.Split(*principalsStr, ",") {
			p = strings.TrimSpace(p)
			if p != "" {
				principals = append(principals, p)
			}
		}
	}

	username := osUsername()
	iamCtx := gobless.IAMContext{
		CallerARN: "local",
		AccountID: "local",
		Username:  username,
	}
	req := &gobless.Request{
		PublicKey:     pubKeyData,
		CertType:      *certType,
		Principals:    principals,
		TTLSeconds:    int64(*ttl),
		SourceAddress: *sourceAddress,
	}

	resp := handler.Handle(context.Background(), iamCtx, req)
	if resp.ErrorType != "" {
		return fmt.Errorf("gobless sign: %s: %s", resp.ErrorType, resp.ErrorMsg)
	}

	out := stdout
	if *outPath != "" {
		f, err := os.Create(*outPath)
		if err != nil {
			return fmt.Errorf("gobless sign: create output file: %w", err)
		}
		defer f.Close()
		out = f
	}

	fmt.Fprint(out, resp.Certificate)
	return nil
}

// buildLocalSigner creates a LocalSigner from the config's CA.PrivateKeyFile.
func buildLocalSigner(cfg *config.Config) (signer.Signer, error) {
	keyPath := cfg.CA.PrivateKeyFile
	if keyPath == "" {
		return nil, fmt.Errorf("CA.PrivateKeyFile must be set for local signing")
	}
	return signer.NewLocalSigner(keyPath, nil)
}

// osUsername returns the current OS username or "unknown" on error.
func osUsername() string {
	u, err := user.Current()
	if err != nil {
		return "unknown"
	}
	return u.Username
}
