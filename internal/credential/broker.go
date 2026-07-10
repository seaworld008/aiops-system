package credential

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/aiops-system/control-plane/internal/action"
	"github.com/aiops-system/control-plane/internal/policy"
)

const MaxPolicyDecisionAge = 5 * time.Second

var (
	ErrCredentialDenied      = errors.New("credential issuance denied")
	ErrCredentialUnavailable = errors.New("credential issuance dependency unavailable")
	ErrInvalidCredential     = errors.New("invalid managed credential")
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
	state     *credentialState
}

type revokeState uint8

const (
	revokePending revokeState = iota
	revokeInProgress
	revokeSucceeded
)

type credentialState struct {
	mu         sync.Mutex
	owner      *Broker
	leaseID    string
	expiresAt  time.Time
	secret     []byte
	revoke     revokeState
	revokeDone chan struct{}
}

func (credential *Credential) Secret() []byte {
	if credential == nil || credential.state == nil {
		return nil
	}
	credential.state.mu.Lock()
	defer credential.state.mu.Unlock()
	return bytes.Clone(credential.state.secret)
}

func (credential *Credential) Destroy() {
	if credential == nil || credential.state == nil {
		return
	}
	credential.state.mu.Lock()
	defer credential.state.mu.Unlock()
	destroySecret(credential.state)
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
		return Credential{}, fmt.Errorf("%w: policy evaluation failed: %v", ErrCredentialUnavailable, err)
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
		if ctx.Err() != nil {
			return Credential{}, ctx.Err()
		}
		return Credential{}, fmt.Errorf("%w: dynamic issue failed: %v", ErrCredentialUnavailable, err)
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
	expiresAt := issued.ExpiresAt.UTC()
	return Credential{
		LeaseID:   issued.LeaseID,
		ExpiresAt: expiresAt,
		state: &credentialState{
			owner: broker, leaseID: issued.LeaseID, expiresAt: expiresAt, secret: secret,
		},
	}, nil
}

// Revoke destroys the local secret before attempting remote lease revocation.
// A failed remote call leaves the managed credential retryable, while a
// successful call is remembered across all value copies of the Credential.
func (broker *Broker) Revoke(ctx context.Context, credential *Credential) error {
	if credential == nil || credential.state == nil {
		return ErrInvalidCredential
	}
	state := credential.state
	for {
		state.mu.Lock()
		destroySecret(state)
		if !validManagedCredential(broker, ctx, credential, state) {
			state.mu.Unlock()
			return ErrInvalidCredential
		}
		switch state.revoke {
		case revokeSucceeded:
			state.mu.Unlock()
			return nil
		case revokeInProgress:
			done := state.revokeDone
			state.mu.Unlock()
			select {
			case <-done:
				continue
			case <-ctx.Done():
				return ctx.Err()
			}
		case revokePending:
			done := make(chan struct{})
			state.revoke = revokeInProgress
			state.revokeDone = done
			leaseID := state.leaseID
			state.mu.Unlock()

			err := broker.issuer.Revoke(ctx, leaseID)
			state.mu.Lock()
			if err == nil {
				state.revoke = revokeSucceeded
			} else {
				state.revoke = revokePending
			}
			state.revokeDone = nil
			close(done)
			state.mu.Unlock()
			if err != nil {
				return fmt.Errorf("revoke dynamic credential: %w", err)
			}
			return nil
		default:
			state.mu.Unlock()
			return ErrInvalidCredential
		}
	}
}

func validManagedCredential(broker *Broker, ctx context.Context, credential *Credential, state *credentialState) bool {
	return broker != nil && broker.issuer != nil && ctx != nil && state.owner == broker &&
		validLeaseID(state.leaseID) && credential.LeaseID == state.leaseID &&
		!state.expiresAt.IsZero() && credential.ExpiresAt.Equal(state.expiresAt)
}

func destroySecret(state *credentialState) {
	clear(state.secret)
	state.secret = nil
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
	return validLeaseID(lease.LeaseID) &&
		len(lease.Secret) > 0 && len(lease.Secret) <= 64<<10 && lease.ExpiresAt.After(now) && !lease.ExpiresAt.After(requestedExpiry)
}

func validLeaseID(leaseID string) bool {
	return leaseID != "" && len(leaseID) <= 256 && strings.TrimSpace(leaseID) == leaseID &&
		!strings.ContainsFunc(leaseID, unicode.IsControl)
}
