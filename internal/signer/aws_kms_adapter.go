package signer

import (
	"context"

	awskms "github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
)

type awsKMSAPIClient interface {
	Sign(ctx context.Context, input *awskms.SignInput, optFns ...func(*awskms.Options)) (*awskms.SignOutput, error)
	GetPublicKey(ctx context.Context, input *awskms.GetPublicKeyInput, optFns ...func(*awskms.Options)) (*awskms.GetPublicKeyOutput, error)
}

// AWSKMSClient adapts the AWS SDK KMS client to the package-local KMSClient interface.
type AWSKMSClient struct {
	client awsKMSAPIClient
}

// NewAWSKMSClient wraps an AWS SDK KMS client.
func NewAWSKMSClient(client *awskms.Client) *AWSKMSClient {
	return newAWSKMSClient(client)
}

func newAWSKMSClient(client awsKMSAPIClient) *AWSKMSClient {
	return &AWSKMSClient{client: client}
}

func (c *AWSKMSClient) Sign(ctx context.Context, input *KMSSignInput) (*KMSSignOutput, error) {
	out, err := c.client.Sign(ctx, &awskms.SignInput{
		KeyId:            &input.KeyID,
		Message:          input.Message,
		MessageType:      kmstypes.MessageType(input.MessageType),
		SigningAlgorithm: kmstypes.SigningAlgorithmSpec(input.SigningAlgorithm),
	})
	if err != nil {
		return nil, err
	}
	return &KMSSignOutput{
		Signature:        out.Signature,
		SigningAlgorithm: string(out.SigningAlgorithm),
	}, nil
}

func (c *AWSKMSClient) GetPublicKey(ctx context.Context, input *KMSGetPublicKeyInput) (*KMSGetPublicKeyOutput, error) {
	out, err := c.client.GetPublicKey(ctx, &awskms.GetPublicKeyInput{KeyId: &input.KeyID})
	if err != nil {
		return nil, err
	}
	algorithms := make([]string, 0, len(out.SigningAlgorithms))
	for _, algorithm := range out.SigningAlgorithms {
		algorithms = append(algorithms, string(algorithm))
	}
	return &KMSGetPublicKeyOutput{
		PublicKeyDER:      out.PublicKey,
		KeySpec:           string(out.KeySpec),
		SigningAlgorithms: algorithms,
	}, nil
}
