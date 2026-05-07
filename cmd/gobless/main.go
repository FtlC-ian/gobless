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
	"context"
	"fmt"
	"log"
	"os"

	"github.com/FtlC-ian/gobless/internal/audit"
	gobconfig "github.com/FtlC-ian/gobless/internal/config"
	gobless "github.com/FtlC-ian/gobless/internal/lambda"
	"github.com/FtlC-ian/gobless/internal/signer"
	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/kms"
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

	awsCfg, err := awsconfig.LoadDefaultConfig(context.Background(), awsconfig.WithRegion(cfg.Lambda.Region))
	if err != nil {
		log.Fatalf("gobless: load AWS config: %v", err)
	}

	s := mustSigner(cfg, awsCfg)
	auditRepo := mustAuditRepo(cfg, awsCfg)

	handler := gobless.NewHandler(cfg, s, auditRepo)
	handler.Start()
}

// mustSigner returns the configured Lambda certificate signer or fatals.
func mustSigner(cfg *gobconfig.Config, awsCfg aws.Config) signer.Signer {
	switch cfg.CA.SignerType {
	case "kms":
		return signer.NewKMSSigner(cfg.CA.KMSKeyID, signer.NewAWSKMSClient(kms.NewFromConfig(awsCfg)))
	default:
		log.Fatalf("gobless: unsupported Lambda signer type %q", cfg.CA.SignerType)
		return nil // unreachable
	}
}

// mustAuditRepo returns an audit.Repository or fatals.
func mustAuditRepo(cfg *gobconfig.Config, awsCfg aws.Config) audit.Repository {
	if !cfg.Logging.AuditEnabled {
		return &audit.NoopRepository{}
	}
	return audit.NewDynamoRepository(cfg.CA.DynamoDBTable, dynamodb.NewFromConfig(awsCfg), cfg.Logging.AuditFailOpen)
}
