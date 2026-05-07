package audit

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

const auditRetention = 90 * 24 * time.Hour

// DynamoClient is the small subset of the DynamoDB client used by DynamoRepository.
type DynamoClient interface {
	PutItem(ctx context.Context, params *dynamodb.PutItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error)
}

// DynamoRepository writes audit events to DynamoDB.
type DynamoRepository struct {
	tableName     string
	client        DynamoClient
	auditFailOpen bool
}

// NewDynamoRepository creates a DynamoDB-backed audit repository.
func NewDynamoRepository(tableName string, client DynamoClient, auditFailOpen bool) *DynamoRepository {
	return &DynamoRepository{tableName: tableName, client: client, auditFailOpen: auditFailOpen}
}

// Write stores an audit event in DynamoDB. It adds ExpiresAt as a Unix epoch
// timestamp 90 days after Event.Timestamp for operators who enable DynamoDB TTL.
func (r *DynamoRepository) Write(ctx context.Context, event *Event) error {
	if r == nil {
		return fmt.Errorf("audit: nil DynamoRepository")
	}
	if r.client == nil {
		return fmt.Errorf("audit: nil DynamoDB client")
	}
	if r.tableName == "" {
		return fmt.Errorf("audit: DynamoDB table name is required")
	}
	if event == nil {
		return fmt.Errorf("audit: event is nil")
	}
	if err := ensureEventDefaults(event); err != nil {
		return err
	}

	item, err := attributevalue.MarshalMap(event)
	if err != nil {
		return fmt.Errorf("audit: marshal event: %w", err)
	}
	item["ExpiresAt"] = &types.AttributeValueMemberN{Value: fmt.Sprintf("%d", event.Timestamp.Add(auditRetention).Unix())}

	_, err = r.client.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: &r.tableName,
		Item:      item,
	})
	if err != nil {
		if r.auditFailOpen {
			log.Printf("WARNING: audit DynamoDB PutItem failed; continuing because audit fail-open is enabled: %v", err)
			return nil
		}
		return fmt.Errorf("audit: dynamodb put item: %w", err)
	}
	return nil
}
