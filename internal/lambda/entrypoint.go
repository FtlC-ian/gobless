package lambda

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/aws/aws-lambda-go/events"
	awslambda "github.com/aws/aws-lambda-go/lambda"
)

// apiGatewayEvent is the event shape received from API Gateway (proxy integration).
type apiGatewayEvent struct {
	Body           string                               `json:"body"`
	RequestContext events.APIGatewayProxyRequestContext `json:"requestContext"`
}

// LambdaHandler is the AWS Lambda handler function. It extracts IAM context from
// the API Gateway request context (populated by a Lambda authorizer or IAM auth),
// decodes the request body, and delegates to Handle.
func (h *Handler) LambdaHandler(ctx context.Context, event apiGatewayEvent) (*Response, error) {
	iamCtx := extractIAMContext(event.RequestContext)

	var req Request
	if err := json.NewDecoder(strings.NewReader(event.Body)).Decode(&req); err != nil {
		return errorResponse("BadRequest", "invalid request body"), nil
	}

	resp := h.Handle(ctx, iamCtx, &req)
	return resp, nil
}

// extractIAMContext pulls the trusted IAM identity from an APIGatewayProxyRequestContext.
// The identity is populated when the API Gateway method uses AWS_IAM authorization.
func extractIAMContext(rc events.APIGatewayProxyRequestContext) IAMContext {
	arn := rc.Identity.UserArn
	accountID := rc.AccountID

	// Derive a short username from the caller ARN:
	//   arn:aws:iam::123456789012:user/alice   -> alice
	//   arn:aws:sts::123456789012:assumed-role/RoleName/session -> session
	username := ""
	if arn != "" {
		parts := strings.Split(arn, "/")
		if len(parts) > 0 {
			username = parts[len(parts)-1]
		}
	}

	return IAMContext{
		CallerARN: arn,
		AccountID: accountID,
		Username:  username,
	}
}

// Start wires the Handler as an AWS Lambda function. Call this from main().
func (h *Handler) Start() {
	awslambda.Start(h.LambdaHandler)
}
