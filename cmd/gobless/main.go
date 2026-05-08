// gobless is the entry point for the GoBless certificate authority service.
//
// Subcommands:
//
//	gobless [lambda]   Run as AWS Lambda handler (default)
//	gobless sign       Sign an SSH public key using the local signer (dev/test only)
//	gobless ca-pubkey  Print the CA public key to stdout (dev/test only)
//	gobless version    Print version and exit
//	gobless help       Print usage and exit
//
// See internal/lambda/handler.go for the core Handler.
// See internal/cli/ for CLI subcommand implementations.
package main

import (
	"fmt"
	"log"
	"os"

	gobconfig "github.com/FtlC-ian/gobless/internal/config"
	gobless "github.com/FtlC-ian/gobless/internal/lambda"
)

const usageText = `gobless — SSH certificate authority service

Usage:
  gobless [lambda]                 Run as AWS Lambda handler (default)
  gobless sign [flags]             Sign an SSH public key (dev/test; requires !production build)
  gobless ca-pubkey [flags]        Print CA public key (dev/test; requires !production build)
  gobless version                  Print version and exit
  gobless help | -h | --help       Print this help

Run 'gobless <subcommand> -h' for subcommand flags.
`

func main() {
	if len(os.Args) < 2 {
		runLambda()
		return
	}

	sub := os.Args[1]
	switch sub {
	case "lambda":
		runLambda()
	case "sign":
		runSign(os.Args[2:])
	case "ca-pubkey":
		runCAPubKey(os.Args[2:])
	case "version":
		runVersion()
	case "help", "-h", "--help":
		fmt.Print(usageText)
		os.Exit(0)
	default:
		fmt.Fprintf(os.Stderr, "gobless: unknown subcommand %q\n\n%s", sub, usageText)
		os.Exit(2)
	}
}

func runLambda() {
	cfg, err := gobconfig.Load(os.Getenv("GOBLESS_CONFIG"))
	if err != nil {
		log.Fatalf("gobless: load config: %v", err)
	}

	s := mustSigner(cfg)
	auditRepo := mustAuditRepo(cfg)

	handler := gobless.NewHandler(cfg, s, auditRepo)
	handler.Start()
}
