package lambda

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/FtlC-ian/gobless/internal/audit"
	"github.com/FtlC-ian/gobless/internal/config"
	"github.com/FtlC-ian/gobless/internal/policy"
	"github.com/aws/aws-lambda-go/events"
)

// ---------------------------------------------------------------------------
// Test doubles
// ---------------------------------------------------------------------------

// fakeSigner implements signer.Signer using an in-memory ed25519 CA key.
type fakeSigner struct {
	caKey ssh.Signer
	err   error
}

func newFakeSigner(t *testing.T) *fakeSigner {
	t.Helper()
	_, caPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	caSSH, err := ssh.NewSignerFromKey(caPriv)
	if err != nil {
		t.Fatalf("wrap CA key: %v", err)
	}
	return &fakeSigner{caKey: caSSH}
}

func (f *fakeSigner) Sign(cert *ssh.Certificate) (*ssh.Certificate, error) {
	if f.err != nil {
		return nil, f.err
	}
	if err := cert.SignCert(rand.Reader, f.caKey); err != nil {
		return nil, err
	}
	return cert, nil
}

func (f *fakeSigner) PublicKey() ssh.PublicKey { return f.caKey.PublicKey() }

// fakeAuditRepo records Write calls.
type fakeAuditRepo struct {
	events []*audit.Event
	err    error
}

func (f *fakeAuditRepo) Write(_ context.Context, event *audit.Event) error {
	if f.err != nil {
		return f.err
	}
	f.events = append(f.events, event)
	return nil
}

// fakeAuditRepoOnce returns err on the first Write call, then succeeds.
type fakeAuditRepoOnce struct {
	calls int
	err   error
}

func (f *fakeAuditRepoOnce) Write(_ context.Context, event *audit.Event) error {
	f.calls++
	if f.calls == 1 {
		return f.err
	}
	return nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func testConfig(t *testing.T) *config.Config {
	t.Helper()
	// Build a minimal valid config inline to avoid I/O.
	cfg := &config.Config{}
	cfg.CA.SignerType = "rsa"
	cfg.CA.PrivateKeyFile = "/dev/null" // passes validation since file check is skipped in tests
	cfg.CA.DefaultTTL = 3600
	cfg.CA.MaxTTL = 86400
	cfg.CA.RSAMinKeyBits = 2048
	cfg.Lambda.Region = "us-east-1"
	cfg.Lambda.FunctionName = "gobless-test"
	cfg.Logging.AuditEnabled = true
	return cfg
}

func generateUserPublicKey(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate user key: %v", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("wrap user key: %v", err)
	}
	return string(ssh.MarshalAuthorizedKey(sshPub))
}

func testIAMCtx() IAMContext {
	return IAMContext{
		CallerARN: "arn:aws:iam::111122223333:user/alice",
		AccountID: "111122223333",
		Username:  "alice",
	}
}

func validRequest(t *testing.T) *Request {
	return &Request{
		PublicKey:  generateUserPublicKey(t),
		CertType:   "user",
		Principals: []string{"alice"},
		TTLSeconds: 3600,
	}
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// TestHandleHappyPath verifies a valid request produces a signed cert and writes
// an approved audit event.
func TestHandleHappyPath(t *testing.T) {
	cfg := testConfig(t)
	auditRepo := &fakeAuditRepo{}
	h := NewHandler(cfg, newFakeSigner(t), auditRepo)

	resp := h.Handle(context.Background(), testIAMCtx(), validRequest(t))

	if resp.ErrorType != "" || resp.ErrorMsg != "" {
		t.Fatalf("unexpected error response: type=%q msg=%q", resp.ErrorType, resp.ErrorMsg)
	}
	if resp.Certificate == "" {
		t.Fatal("expected certificate in response, got empty string")
	}

	// Verify the returned string is a valid authorized-keys line.
	pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(resp.Certificate))
	if err != nil || pk == nil {
		t.Fatalf("response certificate is not a valid authorized-keys line: %v", err)
	}

	// At least one approved event should have been written.
	approvedFound := false
	for _, e := range auditRepo.events {
		if e.EventType == audit.EventTypeSigningApproved {
			approvedFound = true
			if !e.Approved {
				t.Error("approved audit event has Approved=false")
			}
			if e.CertSerial == 0 {
				t.Error("approved audit event has zero CertSerial")
			}
		}
	}
	if !approvedFound {
		t.Error("no signing_approved audit event written")
	}
}

// TestHandlePolicyDenial verifies that an invalid TTL results in a denial
// response, a denied audit event, and no certificate.
func TestHandlePolicyDenial(t *testing.T) {
	cfg := testConfig(t)
	cfg.CA.MaxTTL = 60 // set tight cap

	auditRepo := &fakeAuditRepo{}
	h := NewHandler(cfg, newFakeSigner(t), auditRepo)

	req := validRequest(t)
	req.TTLSeconds = 9999999 // far exceeds MaxTTL

	resp := h.Handle(context.Background(), testIAMCtx(), req)

	if resp.ErrorType == "" {
		t.Fatal("expected error response on policy denial, got none")
	}
	if resp.Certificate != "" {
		t.Fatalf("expected no certificate on denial, got %q", resp.Certificate)
	}

	deniedFound := false
	for _, e := range auditRepo.events {
		if e.EventType == audit.EventTypeSigningDenied {
			deniedFound = true
		}
	}
	if !deniedFound {
		t.Error("no signing_denied audit event written")
	}

	// Ensure no signing_approved event was written.
	for _, e := range auditRepo.events {
		if e.EventType == audit.EventTypeSigningApproved {
			t.Error("signing_approved audit event written on denial — should not happen")
		}
	}
}

// TestHandleSignerError verifies that a signer failure produces an error response
// and a signing_error audit event.
func TestHandleSignerError(t *testing.T) {
	cfg := testConfig(t)
	auditRepo := &fakeAuditRepo{}

	badSigner := newFakeSigner(t)
	badSigner.err = errors.New("KMS unavailable")

	h := NewHandler(cfg, badSigner, auditRepo)
	resp := h.Handle(context.Background(), testIAMCtx(), validRequest(t))

	if resp.ErrorType == "" {
		t.Fatal("expected error response on signer failure, got none")
	}
	if resp.Certificate != "" {
		t.Fatalf("expected no certificate on signer error, got %q", resp.Certificate)
	}

	errFound := false
	for _, e := range auditRepo.events {
		if e.EventType == audit.EventTypeSigningError {
			errFound = true
		}
	}
	if !errFound {
		t.Error("no signing_error audit event written")
	}
}

// TestHandleAuditFailOpen verifies that when AuditFailOpen=true and the audit
// repository returns an error, the request still succeeds.
func TestHandleAuditFailOpen(t *testing.T) {
	cfg := testConfig(t)
	cfg.Logging.AuditFailOpen = true

	alwaysFail := &fakeAuditRepo{err: errors.New("dynamo down")}
	h := NewHandler(cfg, newFakeSigner(t), alwaysFail)

	resp := h.Handle(context.Background(), testIAMCtx(), validRequest(t))

	if resp.ErrorType != "" {
		t.Fatalf("expected success on audit fail-open, got error: type=%q msg=%q", resp.ErrorType, resp.ErrorMsg)
	}
	if resp.Certificate == "" {
		t.Fatal("expected certificate in response on audit fail-open, got empty string")
	}
}

// TestHandleAuditFailClosed verifies that when AuditFailOpen=false and the
// initial audit write fails, the request fails.
func TestHandleAuditFailClosed(t *testing.T) {
	cfg := testConfig(t)
	cfg.Logging.AuditFailOpen = false

	alwaysFail := &fakeAuditRepo{err: errors.New("dynamo down")}
	h := NewHandler(cfg, newFakeSigner(t), alwaysFail)

	resp := h.Handle(context.Background(), testIAMCtx(), validRequest(t))

	if resp.ErrorType == "" {
		t.Fatal("expected error response on audit fail-closed, got success")
	}
	if resp.Certificate != "" {
		t.Fatalf("expected no certificate on audit fail-closed, got %q", resp.Certificate)
	}
}

// TestHandleCertTTL verifies the cert validity window matches the requested TTL.
func TestHandleCertTTL(t *testing.T) {
	cfg := testConfig(t)
	auditRepo := &fakeAuditRepo{}
	h := NewHandler(cfg, newFakeSigner(t), auditRepo)

	req := validRequest(t)
	req.TTLSeconds = 7200

	before := time.Now().Unix()
	resp := h.Handle(context.Background(), testIAMCtx(), req)
	after := time.Now().Unix()

	if resp.ErrorType != "" {
		t.Fatalf("unexpected error: %q %q", resp.ErrorType, resp.ErrorMsg)
	}

	pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(resp.Certificate))
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	cert, ok := pk.(*ssh.Certificate)
	if !ok {
		t.Fatalf("expected *ssh.Certificate, got %T", pk)
	}

	wantDuration := int64(7200)
	gotDuration := int64(cert.ValidBefore) - int64(cert.ValidAfter)
	if gotDuration < wantDuration-2 || gotDuration > wantDuration+2 {
		t.Errorf("cert TTL = %ds, want ~%ds", gotDuration, wantDuration)
	}
	if int64(cert.ValidAfter) < before-1 || int64(cert.ValidAfter) > after+1 {
		t.Errorf("cert ValidAfter %d out of expected range [%d, %d]", cert.ValidAfter, before-1, after+1)
	}
}

// ---------------------------------------------------------------------------
// New tests for blocking fixes
// ---------------------------------------------------------------------------

// nilDecisionEvaluator returns a nil *Decision with no error — simulates a
// defensive edge case that should never occur in production but must not panic.
type nilDecisionEvaluator struct{}

func (nilDecisionEvaluator) Evaluate(_ context.Context, _ *policy.Request, _ *config.Config) (*policy.Decision, error) {
	return nil, nil
}

// TestHandleNilDecisionNoPanic verifies that a nil *Decision from policy
// evaluation does not cause a panic and instead returns an internal error response.
func TestHandleNilDecisionNoPanic(t *testing.T) {
	cfg := testConfig(t)
	auditRepo := &fakeAuditRepo{}
	h := NewHandler(cfg, newFakeSigner(t), auditRepo)
	h.policy = nilDecisionEvaluator{}

	var resp *Response
	// Ensure there is no panic.
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("Handle panicked with nil Decision: %v", r)
			}
		}()
		resp = h.Handle(context.Background(), testIAMCtx(), validRequest(t))
	}()

	if resp == nil {
		t.Fatal("expected non-nil response, got nil")
	}
	if resp.ErrorType == "" {
		t.Fatalf("expected error response for nil Decision, got success: cert=%q", resp.Certificate)
	}
	if resp.Certificate != "" {
		t.Fatalf("expected no certificate for nil Decision, got %q", resp.Certificate)
	}
}

// fakeAuditRepoApprovedFail succeeds on all writes except EventTypeSigningApproved.
type fakeAuditRepoApprovedFail struct {
	events []*audit.Event
	err    error
}

func (f *fakeAuditRepoApprovedFail) Write(_ context.Context, event *audit.Event) error {
	if event.EventType == audit.EventTypeSigningApproved {
		return f.err
	}
	f.events = append(f.events, event)
	return nil
}

// TestHandleTerminalAuditFailClosed verifies that when AuditFailOpen=false and
// the terminal (signing_approved) audit write fails, the handler returns an error
// response and does NOT return the certificate.
func TestHandleTerminalAuditFailClosed(t *testing.T) {
	cfg := testConfig(t)
	cfg.Logging.AuditFailOpen = false

	auditRepo := &fakeAuditRepoApprovedFail{err: errors.New("dynamo timeout")}
	h := NewHandler(cfg, newFakeSigner(t), auditRepo)

	resp := h.Handle(context.Background(), testIAMCtx(), validRequest(t))

	if resp.ErrorType == "" {
		t.Fatal("expected error response when terminal audit fails under fail-closed, got success")
	}
	if resp.Certificate != "" {
		t.Fatalf("expected no certificate when terminal audit fails under fail-closed, got %q", resp.Certificate)
	}
}

// TestHandleNilRequest verifies that passing nil req does not panic and returns an error response.
func TestHandleNilRequest(t *testing.T) {
	cfg := testConfig(t)
	auditRepo := &fakeAuditRepo{}
	h := NewHandler(cfg, newFakeSigner(t), auditRepo)

	var resp *Response
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("Handle panicked with nil req: %v", r)
			}
		}()
		resp = h.Handle(context.Background(), testIAMCtx(), nil)
	}()

	if resp == nil {
		t.Fatal("expected non-nil response for nil req")
	}
	if resp.ErrorType == "" {
		t.Fatalf("expected error response for nil req, got success: cert=%q", resp.Certificate)
	}
	if resp.Certificate != "" {
		t.Fatalf("expected no certificate for nil req, got %q", resp.Certificate)
	}
}

// nilCertSigner is a signer that returns (nil, nil) — no cert, no error.
type nilCertSigner struct {
	caKey ssh.Signer
}

func newNilCertSigner(t *testing.T) *nilCertSigner {
	t.Helper()
	_, caPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	caSSH, err := ssh.NewSignerFromKey(caPriv)
	if err != nil {
		t.Fatalf("wrap CA key: %v", err)
	}
	return &nilCertSigner{caKey: caSSH}
}

func (s *nilCertSigner) Sign(_ *ssh.Certificate) (*ssh.Certificate, error) { return nil, nil }
func (s *nilCertSigner) PublicKey() ssh.PublicKey                          { return s.caKey.PublicKey() }

// TestHandleNilCertNoError verifies that when the signer returns (nil, nil),
// the handler returns an error response and does not panic.
func TestHandleNilCertNoError(t *testing.T) {
	cfg := testConfig(t)
	auditRepo := &fakeAuditRepo{}
	h := NewHandler(cfg, newNilCertSigner(t), auditRepo)

	var resp *Response
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("Handle panicked with nil cert no error: %v", r)
			}
		}()
		resp = h.Handle(context.Background(), testIAMCtx(), validRequest(t))
	}()

	if resp == nil {
		t.Fatal("expected non-nil response for nil cert")
	}
	if resp.ErrorType == "" {
		t.Fatalf("expected error response for nil cert, got success: cert=%q", resp.Certificate)
	}
	if resp.Certificate != "" {
		t.Fatalf("expected no certificate for nil cert, got %q", resp.Certificate)
	}
}

// TestLambdaHandlerIAMExtraction verifies that LambdaHandler correctly extracts
// CallerARN, AccountID, and Username from an APIGatewayProxyRequest.
func TestLambdaHandlerIAMExtraction(t *testing.T) {
	cfg := testConfig(t)
	auditRepo := &fakeAuditRepo{}
	h := NewHandler(cfg, newFakeSigner(t), auditRepo)

	// Build a valid request body.
	req := validRequest(t)
	bodyBytes, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	event := apiGatewayEvent{
		Body: string(bodyBytes),
		RequestContext: events.APIGatewayProxyRequestContext{
			AccountID: "111122223333",
			Identity: events.APIGatewayRequestIdentity{
				UserArn: "arn:aws:iam::111122223333:user/testuser",
			},
		},
	}

	resp, err := h.LambdaHandler(context.Background(), event)
	if err != nil {
		t.Fatalf("LambdaHandler returned error: %v", err)
	}
	if resp == nil {
		t.Fatal("LambdaHandler returned nil response")
	}
	if resp.ErrorType != "" {
		t.Fatalf("unexpected error response: type=%q msg=%q", resp.ErrorType, resp.ErrorMsg)
	}
	if resp.Certificate == "" {
		t.Fatal("expected certificate in response, got empty string")
	}

	// Verify audit events captured the correct IAM identity.
	var approvedEvent *audit.Event
	for _, e := range auditRepo.events {
		if e.EventType == audit.EventTypeSigningApproved {
			approvedEvent = e
		}
	}
	if approvedEvent == nil {
		t.Fatal("no signing_approved audit event written")
	}
	if approvedEvent.IAMCallerARN != "arn:aws:iam::111122223333:user/testuser" {
		t.Errorf("IAMCallerARN = %q, want arn:aws:iam::111122223333:user/testuser", approvedEvent.IAMCallerARN)
	}
	if approvedEvent.IAMAccountID != "111122223333" {
		t.Errorf("IAMAccountID = %q, want 111122223333", approvedEvent.IAMAccountID)
	}

	// Verify username extraction from ARN (last segment after /).
	iamCtx := extractIAMContext(event.RequestContext)
	if iamCtx.Username != "testuser" {
		t.Errorf("Username = %q, want testuser", iamCtx.Username)
	}
	// Assumed-role ARN: arn:aws:sts::123:assumed-role/RoleName/session -> session
	rcAssumed := events.APIGatewayProxyRequestContext{
		AccountID: "123456789012",
		Identity: events.APIGatewayRequestIdentity{
			UserArn: "arn:aws:sts::123456789012:assumed-role/MyRole/mysession",
		},
	}
	iamCtxAssumed := extractIAMContext(rcAssumed)
	if iamCtxAssumed.Username != "mysession" {
		t.Errorf("assumed-role Username = %q, want mysession", iamCtxAssumed.Username)
	}
	_ = strings.Contains // suppress import "strings" unused if not needed elsewhere
}

// ---------------------------------------------------------------------------
// No-secret-leak / redaction tests (#33)
// ---------------------------------------------------------------------------

// TestConfigErrorRedaction asserts that when PrivateKeyB64 contains invalid
// base64, the error message does NOT echo back the raw secret value.
func TestConfigErrorRedaction(t *testing.T) {
	// A long random-looking base64 string that is NOT valid base64.
	fakeB64 := "AAAA/SuperSecretKeyMaterialThatMustNotAppearInErrors+ZZZZ!@#"

	// Set env vars so config.Load picks up our values without a file.
	t.Setenv("GOBLESS_CA_PRIVATE_KEY_B64", fakeB64)
	t.Setenv("GOBLESS_CA_SIGNER_TYPE", "rsa")
	t.Setenv("GOBLESS_CA_DEFAULT_TTL", "3600")
	t.Setenv("GOBLESS_CA_MAX_TTL", "86400")

	_, err := config.Load("")
	if err == nil {
		t.Fatal("expected error from invalid base64, got nil")
	}
	errStr := err.Error()
	if strings.Contains(errStr, fakeB64) {
		t.Errorf("config error leaks raw base64 secret: %q", errStr)
	}
}

// TestLambdaDenyResponseNoSecretLeak asserts that a policy-denied Lambda
// response does not contain key material, KMS key IDs, or internal stack info.
func TestLambdaDenyResponseNoSecretLeak(t *testing.T) {
	cfg := testConfig(t)
	// Set a KMS key ID that must NOT appear in external error responses.
	cfg.CA.KMSKeyID = "arn:aws:kms:us-east-1:123456789012:key/mrk-super-secret-key-id"

	auditRepo := &fakeAuditRepo{}
	denyingPolicy := &staticPolicyEvaluator{
		decision: &policy.Decision{
			Approved:     false,
			DenialReason: "principal not allowed",
		},
	}

	_, caPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	sk := newFakeSigner(t)
	_ = sk
	_ = caPriv

	h := &Handler{cfg: cfg, signer: newFakeSigner(t), audit: auditRepo, policy: denyingPolicy}
	resp := h.Handle(context.Background(), testIAMCtx(), validRequest(t))

	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if resp.ErrorType == "" {
		t.Fatal("expected error response for denied request")
	}

	// Serialise to JSON like the real Lambda runtime would.
	respJSON, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal response: %v", err)
	}
	respStr := string(respJSON)

	// Must not contain the KMS key ID.
	if strings.Contains(respStr, "mrk-super-secret-key-id") {
		t.Errorf("response leaks KMS key ID: %s", respStr)
	}
	// Must not contain goroutine / stack-trace markers.
	if strings.Contains(respStr, "goroutine") || strings.Contains(respStr, ".go:") {
		t.Errorf("response leaks internal stack info: %s", respStr)
	}
	// Must not contain PEM markers.
	if strings.Contains(respStr, "-----BEGIN") {
		t.Errorf("response leaks PEM key material: %s", respStr)
	}
}

// staticPolicyEvaluator always returns the given decision.
type staticPolicyEvaluator struct {
	decision *policy.Decision
	err      error
}

func (s *staticPolicyEvaluator) Evaluate(_ context.Context, _ *policy.Request, _ *config.Config) (*policy.Decision, error) {
	return s.decision, s.err
}
