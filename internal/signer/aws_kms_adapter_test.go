package signer

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	awskms "github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
)

type captureKMSAPIClient struct {
	signInput         *awskms.SignInput
	getPublicKeyInput *awskms.GetPublicKeyInput
}

func (c *captureKMSAPIClient) Sign(_ context.Context, input *awskms.SignInput, _ ...func(*awskms.Options)) (*awskms.SignOutput, error) {
	c.signInput = input
	return &awskms.SignOutput{
		Signature:        []byte("signature"),
		SigningAlgorithm: input.SigningAlgorithm,
	}, nil
}

func (c *captureKMSAPIClient) GetPublicKey(_ context.Context, input *awskms.GetPublicKeyInput, _ ...func(*awskms.Options)) (*awskms.GetPublicKeyOutput, error) {
	c.getPublicKeyInput = input
	return &awskms.GetPublicKeyOutput{
		PublicKey:         []byte("der"),
		KeySpec:           kmstypes.KeySpecRsa4096,
		SigningAlgorithms: []kmstypes.SigningAlgorithmSpec{kmstypes.SigningAlgorithmSpecRsassaPkcs1V15Sha512},
	}, nil
}

func TestAWSKMSClientSignMapsInputAndOutput(t *testing.T) {
	api := &captureKMSAPIClient{}
	client := newAWSKMSClient(api)

	out, err := client.Sign(context.Background(), &KMSSignInput{
		KeyID:            "key-123",
		Message:          []byte("digest"),
		MessageType:      "DIGEST",
		SigningAlgorithm: "RSASSA_PKCS1_V1_5_SHA_512",
	})
	if err != nil {
		t.Fatalf("Sign returned error: %v", err)
	}
	if got := aws.ToString(api.signInput.KeyId); got != "key-123" {
		t.Fatalf("KeyId = %q", got)
	}
	if string(api.signInput.Message) != "digest" {
		t.Fatalf("Message = %q", api.signInput.Message)
	}
	if api.signInput.MessageType != kmstypes.MessageTypeDigest {
		t.Fatalf("MessageType = %q", api.signInput.MessageType)
	}
	if api.signInput.SigningAlgorithm != kmstypes.SigningAlgorithmSpecRsassaPkcs1V15Sha512 {
		t.Fatalf("SigningAlgorithm = %q", api.signInput.SigningAlgorithm)
	}
	if string(out.Signature) != "signature" || out.SigningAlgorithm != "RSASSA_PKCS1_V1_5_SHA_512" {
		t.Fatalf("unexpected output: %#v", out)
	}
}

func TestAWSKMSClientGetPublicKeyMapsInputAndOutput(t *testing.T) {
	api := &captureKMSAPIClient{}
	client := newAWSKMSClient(api)

	out, err := client.GetPublicKey(context.Background(), &KMSGetPublicKeyInput{KeyID: "key-123"})
	if err != nil {
		t.Fatalf("GetPublicKey returned error: %v", err)
	}
	if got := aws.ToString(api.getPublicKeyInput.KeyId); got != "key-123" {
		t.Fatalf("KeyId = %q", got)
	}
	if string(out.PublicKeyDER) != "der" {
		t.Fatalf("PublicKeyDER = %q", out.PublicKeyDER)
	}
	if out.KeySpec != "RSA_4096" {
		t.Fatalf("KeySpec = %q", out.KeySpec)
	}
	if len(out.SigningAlgorithms) != 1 || out.SigningAlgorithms[0] != "RSASSA_PKCS1_V1_5_SHA_512" {
		t.Fatalf("SigningAlgorithms = %#v", out.SigningAlgorithms)
	}
}
