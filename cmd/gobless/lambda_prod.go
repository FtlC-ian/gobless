//go:build production

package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/aws/aws-sdk-go-v2/config"
	awskms "github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb"

	"github.com/FtlC-ian/gobless/internal/audit"
	gobconfig "github.com/FtlC-ian/gobless/internal/config"
	"github.com/FtlC-ian/gobless/internal/signer"
)

// mustSigner constructs a KMS-backed signer using cfg.CA.KMSKeyID and the
// AWS region sourced from cfg.Lambda.Region or the AWS_REGION environment variable.
func mustSigner(cfg *gobconfig.Config) signer.Signer {
	if cfg.CA.KMSKeyID == "" {
		log.Fatalf("gobless: mustSigner: cfg.CA.KMSKeyID is required for production KMS signer")
	}

	region := cfg.Lambda.Region
	if region == "" {
		region = os.Getenv("AWS_REGION")
	}
	if region == "" {
		log.Fatalf("gobless: mustSigner: AWS region not set; provide GOBLESS_LAMBDA_REGION or AWS_REGION")
	}

	awsCfg, err := config.LoadDefaultConfig(context.Background(),
		config.WithRegion(region),
	)
	if err != nil {
		log.Fatalf("gobless: mustSigner: load AWS config: %v", err)
	}

	kmsClient := awskms.NewFromConfig(awsCfg)
	return signer.NewKMSSigner(cfg.CA.KMSKeyID, &kmsClientAdapter{client: kmsClient})
}

// mustAuditRepo constructs a DynamoDB audit repository or returns a no-op repo
// when audit logging is disabled.
func mustAuditRepo(cfg *gobconfig.Config) audit.Repository {
	if !cfg.Logging.AuditEnabled {
		return &audit.NoopRepository{}
	}

	tableName := cfg.CA.DynamoDBTable
	if tableName == "" {
		log.Fatalf("gobless: mustAuditRepo: cfg.CA.DynamoDBTable is required when audit logging is enabled (set GOBLESS_CA_DYNAMODB_TABLE)")
	}

	region := cfg.Lambda.Region
	if region == "" {
		region = os.Getenv("AWS_REGION")
	}
	if region == "" {
		log.Fatalf("gobless: mustAuditRepo: AWS region not set; provide GOBLESS_LAMBDA_REGION or AWS_REGION")
	}

	awsCfg, err := config.LoadDefaultConfig(context.Background(),
		config.WithRegion(region),
	)
	if err != nil {
		log.Fatalf("gobless: mustAuditRepo: load AWS config: %v", err)
	}

	dynamoClient := dynamodb.NewFromConfig(awsCfg)
	return audit.NewDynamoRepository(tableName, dynamoClient, cfg.Logging.AuditFailOpen)
}

// kmsClientAdapter adapts the real aws-sdk-go-v2 KMS client to the signer.KMSClient interface.
type kmsClientAdapter struct {
	client *awskms.Client
}

func (a *kmsClientAdapter) Sign(ctx context.Context, input *signer.KMSSignInput) (*signer.KMSSignOutput, error) {
	out, err := a.client.Sign(ctx, &awskms.SignInput{
		KeyId:            &input.KeyID,
		Message:          input.Message,
		MessageType:      kmstypes.MessageType(input.MessageType),
		SigningAlgorithm: kmstypes.SigningAlgorithmSpec(input.SigningAlgorithm),
	})
	if err != nil {
		return nil, fmt.Errorf("kms sign: %w", err)
	}
	return &signer.KMSSignOutput{
		Signature:        out.Signature,
		SigningAlgorithm: string(out.SigningAlgorithm),
	}, nil
}

func (a *kmsClientAdapter) GetPublicKey(ctx context.Context, input *signer.KMSGetPublicKeyInput) (*signer.KMSGetPublicKeyOutput, error) {
	out, err := a.client.GetPublicKey(ctx, &awskms.GetPublicKeyInput{
		KeyId: &input.KeyID,
	})
	if err != nil {
		return nil, fmt.Errorf("kms get public key: %w", err)
	}

	signingAlgorithms := make([]string, len(out.SigningAlgorithms))
	for i, sa := range out.SigningAlgorithms {
		signingAlgorithms[i] = string(sa)
	}

	return &signer.KMSGetPublicKeyOutput{
		PublicKeyDER:      out.PublicKey,
		KeySpec:           string(out.KeySpec),
		SigningAlgorithms: signingAlgorithms,
	}, nil
}
