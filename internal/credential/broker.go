package credential

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aiops-system/control-plane/internal/action"
	"github.com/aiops-system/control-plane/internal/policy"
)

const MaxPolicyDecisionAge = 5 * time.Second

var (
	ErrCredentialDenied      = errors.New("credential issuance denied")
	ErrUnsafeCredentialLease = errors.New("credential issuer returned an unsafe lease")
)

type PolicyGate interface {
	EvaluateCredentialIssue(context.Context, action.Envelope) (policy.Decision, error)
}

type DynamicIssuer interface {
	Issue(context.Context, IssueRequest) (IssuedLease, error)
	Revoke(context.Context, string) error
}

type IssueRequest struct {
	ActionID       string
	IdempotencyKey string
	ConnectorID    string
	Permission     string
	Resource       string
	TTL            time.Duration
	ExpiresAt      time.Time
}

type IssuedLease struct {
	LeaseID   string
	Secret    []byte
	ExpiresAt time.Time
}

type Credential struct {
	LeaseID   string    `json:"lease_id"`
	ExpiresAt time.Time `json:"expires_at"`
	secret    []byte
}

func (credential *Credential) Secret() []byte {
	if credential == nil {
		return nil
	}
	return bytes.Clone(credential.secret)
}

func (credential *Credential) Destroy() {
	if credential == nil {
		return
	}
	clear(credential.secret)
	credential.secret = nil
}

type Broker struct {
	gate   PolicyGate
	issuer DynamicIssuer
	clock  func() time.Time
}

func NewBroker(gate PolicyGate, issuer DynamicIssuer, clock func() time.Time) (*Broker, error) {
	if gate == nil || issuer == nil {
		return nil, fmt.Errorf("policy gate and dynamic credential issuer are required")
	}
	if clock == nil {
		clock = time.Now
	}
	return &Broker{gate: gate, issuer: issuer, clock: clock}, nil
}

func (broker *Broker) Issue(ctx context.Context, envelope action.Envelope) (Credential, error) {
	if err := ctx.Err(); err != nil {
		return Credential{}, err
	}
	now := broker.clock().UTC()
	if now.IsZero() || envelope.PlanHash == "" || envelope.Signature.Value == "" || envelope.ValidateAt(now) != nil {
		return Credential{}, ErrCredentialDenied
	}
	decision, err := broker.gate.EvaluateCredentialIssue(ctx, envelope)
	if err != nil {
		if ctx.Err() != nil {
			return Credential{}, ctx.Err()
		}
		return Credential{}, ErrCredentialDenied
	}
	if !validDecision(decision, envelope, now) {
		return Credential{}, ErrCredentialDenied
	}
	ttl := decision.CredentialExpiresAt.Sub(now)
	request := IssueRequest{
		ActionID: envelope.ActionID, IdempotencyKey: envelope.IdempotencyKey,
		ConnectorID: envelope.CredentialScope.ConnectorID, Permission: envelope.CredentialScope.Permission,
		Resource: envelope.CredentialScope.Resource, TTL: ttl, ExpiresAt: decision.CredentialExpiresAt,
	}
	issued, err := broker.issuer.Issue(ctx, request)
	if err != nil {
		clear(issued.Secret)
		return Credential{}, fmt.Errorf("issue dynamic credential: %w", err)
	}
	if !validIssuedLease(issued, now, decision.CredentialExpiresAt) {
		clear(issued.Secret)
		if issued.LeaseID != "" {
			_ = broker.issuer.Revoke(ctx, issued.LeaseID)
		}
		return Credential{}, ErrUnsafeCredentialLease
	}
	secret := bytes.Clone(issued.Secret)
	clear(issued.Secret)
	return Credential{LeaseID: issued.LeaseID, ExpiresAt: issued.ExpiresAt.UTC(), secret: secret}, nil
}

func validDecision(decision policy.Decision, envelope action.Envelope, now time.Time) bool {
	return decision.Outcome == policy.OutcomeAllow && decision.Stage == policy.StageCredentialIssue &&
		decision.PolicyVersion == envelope.PolicyVersion && decision.PlanHash == envelope.PlanHash &&
		decision.SafetyRevision != "" && decision.TargetRevision != "" && decision.RiskRevision != "" &&
		decision.LimitsRevision != "" &&
		!decision.EvaluatedAt.IsZero() && !decision.EvaluatedAt.After(now.Add(time.Second)) &&
		now.Sub(decision.EvaluatedAt) <= MaxPolicyDecisionAge &&
		decision.CredentialExpiresAt.After(now) && !decision.CredentialExpiresAt.After(envelope.ExpiresAt)
}

func validIssuedLease(lease IssuedLease, now, requestedExpiry time.Time) bool {
	return lease.LeaseID != "" && len(lease.LeaseID) <= 256 && strings.TrimSpace(lease.LeaseID) == lease.LeaseID &&
		len(lease.Secret) > 0 && len(lease.Secret) <= 64<<10 && lease.ExpiresAt.After(now) && !lease.ExpiresAt.After(requestedExpiry)
}
