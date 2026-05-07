//go:build !production

package cli

import (
	"flag"
	"fmt"
	"io"

	"github.com/FtlC-ian/gobless/internal/config"
	"golang.org/x/crypto/ssh"
)

// RunCAPubKey implements the `gobless ca-pubkey` subcommand.
func RunCAPubKey(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("gobless ca-pubkey", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", "", "path to config file (required)")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *configPath == "" {
		fmt.Fprintln(stderr, "gobless ca-pubkey: -config is required")
		fs.Usage()
		return fmt.Errorf("missing required flag: -config")
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return fmt.Errorf("gobless ca-pubkey: load config: %w", err)
	}

	s, err := buildLocalSigner(cfg)
	if err != nil {
		return fmt.Errorf("gobless ca-pubkey: build signer: %w", err)
	}

	pubKey := s.PublicKey()
	fmt.Fprint(stdout, string(ssh.MarshalAuthorizedKey(pubKey)))
	return nil
}
