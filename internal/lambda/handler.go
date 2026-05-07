package lambda

import (
	"context"
	"log"

	"github.com/FtlC-ian/gobless/internal/audit"
	"github.com/FtlC-ian/gobless/internal/cert"
	gblog "github.com/FtlC-ian/gobless/internal/log"
	"github.com/FtlC-ian/gobless/internal/policy"
	"github.com/FtlC-ian/gobless/internal/signer"

	"github.com/FtlC-ian/gobless/internal/config"
)

// PolicyEvaluator abstracts policy.Evaluate for testability.
type PolicyEvaluator interface {
	Evaluate(ctx context.Context, req *policy.Request, cfg *config.Config) (*policy.Decision, error)
}

// Request is the JSON body sent by callers (BLESS-compatible).
type Request struct {
	PublicKey     string            `json:"public_key"`
	CertType      string            `json:"cert_type"` // "user" or "host"
	Principals    []string          `json:"principals"`
	TTLSeconds    int64             `json:"ttl_seconds"`
	SourceAddress string            `json:"source_address,omitempty"`
	ForceCommand  string            `json:"force_command,omitempty"`
	Extensions    map[string]string `json:"extensions,omitempty"`
}

// Response is what the handler returns.
type Response struct {
	Certificate string `json:"certificate,omitempty"` // signed cert in authorized-keys format
	ErrorType   string `json:"error_type,omitempty"`
	ErrorMsg    string `json:"error_msg,omitempty"`
}

// IAMContext is the trusted caller identity extracted from Lambda context.
// In production this comes from the Lambda authorizer / context.
type IAMContext struct {
	CallerARN string
	AccountID string
	Username  string
}

// Handler holds dependencies.
type Handler struct {
	cfg    *config.Config
	signer signer.Signer
	audit  audit.Repository
	policy PolicyEvaluator // nil = use default policy.Evaluate
}

// NewHandler creates a new Handler with the given dependencies.
func NewHandler(cfg *config.Config, s signer.Signer, a audit.Repository) *Handler {
	if cfg != nil && cfg.CA.SignerType == "kms" && len(cfg.Principal.AllowedCertTypes) == 0 {
		log.Printf("WARNING: AllowedCertTypes is not configured; both user and host certs will be issued")
	}
	return &Handler{cfg: cfg, signer: s, audit: a}
}

// Handle processes a signing request end-to-end:
//  1. Build audit event (EventTypeSigningRequest)
//  2. Call policy.Evaluate
//  3. On denial: write audit event (EventTypeSigningDenied), return error response
//  4. On approval: call signer.Sign
//  5. On sign error: write audit event (EventTypeSigningError), return error response
//  6. On success: write audit event (EventTypeSigningApproved), return cert response
//
// The handler NEVER returns a bare Go error to the caller — always a Response.
// Audit write errors on fail-open config are logged but don't fail the request.
// Under fail-closed config, terminal audit write failures always return an error.
func (h *Handler) Handle(ctx context.Context, iamCtx IAMContext, req *Request) *Response {
	if req == nil {
		return &Response{ErrorType: "InternalError", ErrorMsg: "internal error"}
	}

	// 1. Build initial audit event for the signing request.
	requestEvent, err := audit.NewEvent(audit.EventTypeSigningRequest)
	if err != nil {
		gblog.Error(ctx, "audit: failed to create signing request event", "error", err)
		return errorResponse("AuditError", "internal error")
	}
	populateAuditEvent(requestEvent, iamCtx, req, h.cfg)

	if auditErr := h.audit.Write(ctx, requestEvent); auditErr != nil {
		gblog.Error(ctx, "audit: failed to write signing request event", "error", auditErr)
		if !h.cfg.Logging.AuditFailOpen {
			return errorResponse("AuditError", "audit write failed")
		}
	}

	// 2. Evaluate policy.
	policyReq := &policy.Request{
		IAMCallerARN:        iamCtx.CallerARN,
		IAMAccountID:        iamCtx.AccountID,
		IAMUsername:         iamCtx.Username,
		PublicKey:           req.PublicKey,
		CertType:            req.CertType,
		RequestedPrincipals: req.Principals,
		TTLSeconds:          req.TTLSeconds,
		SourceAddress:       req.SourceAddress,
		ForceCommand:        req.ForceCommand,
		Extensions:          req.Extensions,
	}

	eval := h.policy
	if eval == nil {
		eval = defaultPolicyEvaluator{}
	}
	decision, err := eval.Evaluate(ctx, policyReq, h.cfg)
	if err != nil {
		gblog.Error(ctx, "policy: internal evaluation error", "error", err)
		h.writeAuditResult(ctx, iamCtx, req, audit.EventTypeSigningError, "", "", 0, 0, 0, err.Error())
		return errorResponse("InternalError", "policy evaluation failed")
	}

	// Fix 2: Nil Decision without error is a defensive guard.
	if decision == nil {
		gblog.Error(ctx, "policy: Evaluate returned nil Decision without error")
		h.writeAuditResult(ctx, iamCtx, req, audit.EventTypeSigningError, "", "", 0, 0, 0, "nil decision")
		return errorResponse("InternalError", "internal error")
	}

	// 3. Policy denied.
	if !decision.Approved {
		gblog.Info(ctx, "policy: signing denied", "reason", decision.DenialReason, "iam_arn", iamCtx.CallerARN)
		h.writeAuditResult(ctx, iamCtx, req, audit.EventTypeSigningDenied, decision.KeyID, decision.DenialReason, 0, 0, 0, "")
		return errorResponse("Denied", decision.DenialReason)
	}

	// 4. Sign the certificate.
	certReq := &cert.Request{
		CertType:      decision.CertType,
		PublicKey:     decision.PublicKey,
		Principals:    decision.Principals,
		TTL:           decision.TTL,
		SourceAddress: decision.SourceAddress,
		ForceCommand:  decision.ForceCommand,
		Extensions:    decision.Extensions,
		KeyID:         decision.KeyID,
	}

	certResp, err := cert.Sign(ctx, certReq, h.signer)
	if err != nil {
		gblog.Error(ctx, "signer: cert signing failed", "error", err)
		h.writeAuditResult(ctx, iamCtx, req, audit.EventTypeSigningError, decision.KeyID, "", 0, 0, 0, err.Error())
		return errorResponse("SigningError", "certificate signing failed")
	}

	// Fix 2: nil Certificate from Sign without error.
	if certResp == nil || certResp.Certificate == nil {
		gblog.Error(ctx, "signer: cert.Sign returned nil certificate without error")
		h.writeAuditResult(ctx, iamCtx, req, audit.EventTypeSigningError, decision.KeyID, "", 0, 0, 0, "nil certificate")
		return errorResponse("SigningError", "internal error")
	}

	// Fix 2: Empty authorized key output.
	if certResp.AuthorizedKey == "" {
		gblog.Error(ctx, "signer: cert.Sign returned empty authorized key")
		h.writeAuditResult(ctx, iamCtx, req, audit.EventTypeSigningError, decision.KeyID, "", 0, 0, 0, "empty authorized key")
		return errorResponse("SigningError", "internal error")
	}

	// 6. Signing success — write approved audit event.
	if auditErr := h.writeAuditResultChecked(ctx, iamCtx, req, audit.EventTypeSigningApproved, decision.KeyID, "",
		certResp.Certificate.Serial,
		int64(certResp.Certificate.ValidAfter),
		int64(certResp.Certificate.ValidBefore),
		""); auditErr != nil {
		// Fail closed: if we can't audit the approval, don't return the cert.
		gblog.Error(ctx, "audit: failed to write signing_approved event; fail-closed: rejecting", "error", auditErr)
		return errorResponse("AuditError", "audit write failed")
	}

	return &Response{Certificate: certResp.AuthorizedKey}
}

// writeAuditResult writes a terminal audit event (approved/denied/error).
// Errors from audit.Write are logged. Use writeAuditResultChecked when the
// caller needs to act on the error (fail-closed enforcement).
func (h *Handler) writeAuditResult(ctx context.Context, iamCtx IAMContext, req *Request,
	eventType audit.EventType, keyID, denialReason string,
	serial uint64, notBefore, notAfter int64, errMsg string) {
	_ = h.writeAuditResultChecked(ctx, iamCtx, req, eventType, keyID, denialReason,
		serial, notBefore, notAfter, errMsg)
}

// writeAuditResultChecked writes a terminal audit event and returns any write
// error to the caller when fail-closed is configured. On fail-open, errors are
// logged and nil is returned.
func (h *Handler) writeAuditResultChecked(ctx context.Context, iamCtx IAMContext, req *Request,
	eventType audit.EventType, keyID, denialReason string,
	serial uint64, notBefore, notAfter int64, errMsg string) error {
	event, err := audit.NewEvent(eventType)
	if err != nil {
		gblog.Error(ctx, "audit: failed to create event", "event_type", string(eventType), "error", err)
		if !h.cfg.Logging.AuditFailOpen {
			return err
		}
		return nil
	}
	populateAuditEvent(event, iamCtx, req, h.cfg)
	event.KeyID = keyID
	if eventType == audit.EventTypeSigningApproved {
		event.Approved = true
		event.CertSerial = serial
	}
	if denialReason != "" {
		event.DenialReason = denialReason
	}
	_ = errMsg // logged separately; not stored in audit for security

	if auditErr := h.audit.Write(ctx, event); auditErr != nil {
		gblog.Error(ctx, "audit: failed to write event", "event_type", string(eventType), "error", auditErr)
		if !h.cfg.Logging.AuditFailOpen {
			return auditErr
		}
	}
	return nil
}

func populateAuditEvent(event *audit.Event, iamCtx IAMContext, req *Request, cfg *config.Config) {
	event.IAMCallerARN = iamCtx.CallerARN
	event.IAMAccountID = iamCtx.AccountID
	event.CertType = req.CertType
	event.Principals = req.Principals
	event.TTLSeconds = req.TTLSeconds
	event.SourceAddress = req.SourceAddress
	event.LambdaRegion = cfg.Lambda.Region
	event.LambdaFnName = cfg.Lambda.FunctionName
}

func errorResponse(errorType, msg string) *Response {
	return &Response{ErrorType: errorType, ErrorMsg: msg}
}

// defaultPolicyEvaluator wraps the package-level policy.Evaluate.
type defaultPolicyEvaluator struct{}

func (defaultPolicyEvaluator) Evaluate(ctx context.Context, req *policy.Request, cfg *config.Config) (*policy.Decision, error) {
	return policy.Evaluate(ctx, req, cfg)
}
