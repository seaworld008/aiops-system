package credential

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"testing"
	"time"
)

const (
	durableTestRevocationID = "30000000-0000-4000-8000-000000000020"
	durableTestActionID     = "30000000-0000-4000-8000-000000000010"
)

func TestDurableBrokerIssuesOnlyAfterAnchoredInspectionAndActiveACK(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 10, 10, 0, 0, 0, time.UTC)
	fence := durableTestFence()
	selection := durableTestSelection()
	profile := DurableIssuerProfile{
		IssuerID: "vault-database-nonprod", Revision: "rev-17", CredentialTTL: 5 * time.Minute,
	}
	permit := &ChildCreatePermit{RevocationID: durableTestRevocationID, Token: "single-use-create-permit"}
	accessor, err := NewSensitiveReference([]byte("vault-accessor-canary"))
	if err != nil {
		t.Fatalf("NewSensitiveReference() error = %v", err)
	}
	childToken, err := NewSensitiveValue([]byte("vault-child-token-canary"))
	if err != nil {
		t.Fatalf("NewSensitiveValue(child token) error = %v", err)
	}
	secret, err := NewSensitiveValue([]byte("dynamic-secret-canary"))
	if err != nil {
		t.Fatalf("NewSensitiveValue(secret) error = %v", err)
	}

	var order []string
	record := func(step string) { order = append(order, step) }
	issuer := &durableIssuerStub{
		validateManager: func(context.Context) error {
			record("manager")
			return nil
		},
		createChild: func(ctx context.Context, request DurableChildCreateRequest) (DurableChild, error) {
			record("create-child")
			if got := ctx.Value(durableTimeoutContextKey{}); got != "authorize-create" {
				t.Fatalf("CreateChild context marker = %v", got)
			}
			if request.RevocationID != durableTestRevocationID || request.ProfileRevision != profile.Revision ||
				request.DatabaseAuthorizedAt != now.Add(time.Second) || request.TTL != 4*time.Minute ||
				request.CredentialExpiresAt != now.Add(profile.CredentialTTL) {
				t.Fatalf("CreateChild request = %#v", request)
			}
			return DurableChild{Token: childToken, Accessor: accessor, ExpiresAt: request.CredentialExpiresAt}, nil
		},
		inspectChild: func(_ context.Context, got *SensitiveReference, request DurableChildInspectionRequest) error {
			record("inspect-child")
			if got != accessor || request.RevocationID != durableTestRevocationID ||
				request.ProfileRevision != profile.Revision || request.ExpectedTTL != 4*time.Minute ||
				request.CredentialExpiresAt != now.Add(profile.CredentialTTL) {
				t.Fatalf("InspectChild request = accessor %p, %#v", got, request)
			}
			return nil
		},
		issueDynamic: func(_ context.Context, token SensitiveValue, request DurableDynamicIssueRequest) (DurableDynamicSecret, error) {
			record("issue-dynamic")
			if got := string(token.Bytes()); got != "vault-child-token-canary" {
				t.Fatalf("IssueDynamic token = %q", got)
			}
			if request.RevocationID != durableTestRevocationID || request.ProfileRevision != profile.Revision ||
				request.CredentialExpiresAt != now.Add(profile.CredentialTTL) {
				t.Fatalf("IssueDynamic request = %#v", request)
			}
			return DurableDynamicSecret{Secret: secret, ExpiresAt: now.Add(3 * time.Minute)}, nil
		},
	}
	repository := &durableBrokerRepositoryStub{
		prepare: func(_ context.Context, request PrepareRequest) (PrepareResult, error) {
			record("prepare")
			if request.RevocationID != durableTestRevocationID || request.Fence != fence ||
				request.Issuer != profile.IssuerID || request.CredentialExpiresAt != now.Add(profile.CredentialTTL) {
				t.Fatalf("Prepare request = %#v", request)
			}
			return PrepareResult{
				Created: true, Permit: permit,
				Revocation: durablePreparedRevocation(now, selection, profile),
			}, nil
		},
		authorizeChildCreate: func(ctx context.Context, request AuthorizeChildCreateRequest) (ChildCreateAuthorization, error) {
			record("authorize")
			if got := ctx.Value(durableTimeoutContextKey{}); got != "authorize-create" {
				t.Fatalf("AuthorizeChildCreate context marker = %v", got)
			}
			if request.Permit != *permit || request.Fence != fence {
				t.Fatalf("AuthorizeChildCreate request = %#v", request)
			}
			revocation := durablePreparedRevocation(now, selection, profile)
			revocation.Version = 2
			revocation.UpdatedAt = now.Add(time.Second)
			return ChildCreateAuthorization{
				Revocation: revocation, DatabaseAuthorizedAt: now.Add(time.Second),
				CredentialExpiresAt: revocation.CredentialExpiresAt, TTL: 4 * time.Minute,
				VaultCallBudget: ChildCreateVaultCallBudget,
			}, nil
		},
		recordAnchor: func(ctx context.Context, request RecordAnchorRequest) (Revocation, error) {
			record("anchor")
			assertUsableBoundedContext(t, ctx, PostDispatchPersistenceTimeout)
			if request.RevocationID != durableTestRevocationID || request.Fence != fence || request.Accessor != accessor {
				t.Fatalf("RecordAnchor request = %#v", request)
			}
			revocation := durablePreparedRevocation(now, selection, profile)
			revocation.Status = StatusAnchored
			revocation.AccessorPresent = true
			revocation.Version = 3
			revocation.AnchoredAt = now.Add(2 * time.Second)
			revocation.UpdatedAt = revocation.AnchoredAt
			return revocation, nil
		},
		activate: func(ctx context.Context, request ActionTransitionRequest) (Revocation, error) {
			record("activate")
			assertUsableBoundedContext(t, ctx, PostDispatchPersistenceTimeout)
			if got := childToken.Bytes(); len(got) != 0 {
				t.Fatalf("child token still present before Activate: %q", got)
			}
			revocation := durablePreparedRevocation(now, selection, profile)
			revocation.Status = StatusActive
			revocation.AccessorPresent = true
			revocation.Version = 4
			revocation.AnchoredAt = now.Add(2 * time.Second)
			revocation.ActivatedAt = now.Add(3 * time.Second)
			revocation.UpdatedAt = revocation.ActivatedAt
			return revocation, nil
		},
	}
	resolver := &durableIssuerResolverStub{
		resolve: func(_ context.Context, request DurableIssuerResolveRequest) (ResolvedDurableIssuer, error) {
			record("resolve")
			if request != selection {
				t.Fatalf("ResolveDurableIssuer request = %#v", request)
			}
			return ResolvedDurableIssuer{Profile: profile, Issuer: issuer}, nil
		},
	}
	finalizeCalls := 0
	broker, err := NewDurableBroker(repository, resolver, DurableBrokerOptions{
		UUIDSource: func() (string, error) { return durableTestRevocationID, nil },
		Clock:      func() time.Time { return now },
		TimeoutSource: func(parent context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
			if timeout != ChildCreateVaultCallBudget {
				t.Fatalf("timeout = %s, want %s", timeout, ChildCreateVaultCallBudget)
			}
			bounded, cancel := context.WithTimeout(parent, timeout)
			return context.WithValue(bounded, durableTimeoutContextKey{}, "authorize-create"), cancel
		},
		FinalizeContextSource: func(parent context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
			if timeout != PostDispatchPersistenceTimeout {
				t.Fatalf("finalize timeout = %s, want %s", timeout, PostDispatchPersistenceTimeout)
			}
			finalizeCalls++
			return context.WithTimeout(context.WithoutCancel(parent), timeout)
		},
	})
	if err != nil {
		t.Fatalf("NewDurableBroker() error = %v", err)
	}

	credential, err := broker.Issue(context.Background(), IssueDurableCredentialRequest{Fence: fence, Selection: selection})
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}
	t.Cleanup(credential.Destroy)
	if credential.RevocationID() != durableTestRevocationID || credential.ExpiresAt() != now.Add(3*time.Minute) {
		t.Fatalf("credential metadata = %q/%s", credential.RevocationID(), credential.ExpiresAt())
	}
	if got := string(credential.Secret()); got != "dynamic-secret-canary" {
		t.Fatalf("credential secret = %q", got)
	}
	if finalizeCalls != 3 {
		t.Fatalf("FinalizeContextSource calls = %d, want 3", finalizeCalls)
	}
	if want := []string{"resolve", "manager", "prepare", "authorize", "create-child", "anchor", "inspect-child", "issue-dynamic", "activate"}; !reflect.DeepEqual(order, want) {
		t.Fatalf("operation order = %v, want %v", order, want)
	}
}

func TestDurableBrokerClearsMaterialBeforePersistingPostAnchorFailure(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		failAt string
	}{
		{name: "create response after accessor", failAt: "create"},
		{name: "anchor acknowledgment", failAt: "anchor"},
		{name: "manager inspection", failAt: "inspect"},
		{name: "dynamic response", failAt: "issue"},
		{name: "active acknowledgment", failAt: "activate"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			harness := newDurableBrokerHarness(t)
			switch test.failAt {
			case "create":
				harness.createErr = errors.New("upstream create response lost child-token-canary")
			case "anchor":
				harness.anchorErr = errors.New("database anchor acknowledgment lost accessor-canary")
			case "inspect":
				harness.inspectErr = errors.New("unsafe child child-token-canary")
			case "issue":
				harness.issueErr = errors.New("ambiguous leased response dynamic-secret-canary")
			case "activate":
				harness.activateErr = errors.New("database active acknowledgment lost dynamic-secret-canary")
			}
			harness.onRequestRevocation = func() {
				if token := harness.child.Token.Bytes(); len(token) != 0 {
					t.Fatalf("child token present when revocation intent persisted: %q", token)
				}
				if secret := harness.dynamic.Secret.Bytes(); harness.calls["issue-dynamic"] > 0 && len(secret) != 0 {
					t.Fatalf("dynamic secret present when revocation intent persisted: %q", secret)
				}
			}

			credential, err := harness.broker.Issue(context.Background(), harness.request)
			if !errors.Is(err, ErrDurableCredentialIssuance) {
				t.Fatalf("Issue() error = %v", err)
			}
			if credential.Secret() != nil {
				t.Fatalf("Issue() exposed secret after %s failure", test.failAt)
			}
			if got := harness.calls["request-revocation"]; got != 1 {
				t.Fatalf("RequestRevocation calls = %d, want 1", got)
			}
			if got := harness.calls["create-child"]; got != 1 {
				t.Fatalf("CreateChild calls = %d, want 1", got)
			}
			if got := harness.calls["anchor"]; got != 1 {
				t.Fatalf("RecordAnchor calls = %d, want 1", got)
			}
			if test.failAt == "create" || test.failAt == "anchor" {
				if got := harness.calls["issue-dynamic"]; got != 0 {
					t.Fatalf("IssueDynamic calls after %s failure = %d, want 0", test.failAt, got)
				}
			}
			if rendered := err.Error(); containsAny(rendered,
				"child-token-canary", "accessor-canary", "dynamic-secret-canary") {
				t.Fatalf("error rendered sensitive material: %q", rendered)
			}
		})
	}
}

func TestDurableBrokerRejectsUnsafeProfileAndStaleIssuerResponses(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name             string
		mutate           func(*durableBrokerHarness)
		wantPrepareCalls int
		wantRevokeCalls  int
	}{
		{
			name: "profile cannot fit fixed creation reserve",
			mutate: func(harness *durableBrokerHarness) {
				harness.profile.CredentialTTL = ChildCreateExpiryReserve
			},
			wantPrepareCalls: 0,
		},
		{
			name: "prepared row cannot switch to production",
			mutate: func(harness *durableBrokerHarness) {
				harness.prepared.Revocation.Production = true
			},
			wantPrepareCalls: 1,
			wantRevokeCalls:  0,
		},
		{
			name: "created prepare must be initial version",
			mutate: func(harness *durableBrokerHarness) {
				harness.prepared.Revocation.Version = 2
			},
			wantPrepareCalls: 1,
			wantRevokeCalls:  0,
		},
		{
			name: "prepared row must match signed resource",
			mutate: func(harness *durableBrokerHarness) {
				harness.prepared.Revocation.Resource = "postgres://attacker/other"
			},
			wantPrepareCalls: 1,
			wantRevokeCalls:  0,
		},
		{
			name: "child expiry must be after database authorization",
			mutate: func(harness *durableBrokerHarness) {
				harness.child.ExpiresAt = harness.authorization.DatabaseAuthorizedAt
			},
			wantPrepareCalls: 1,
			wantRevokeCalls:  1,
		},
		{
			name: "dynamic expiry cannot exceed inspected child",
			mutate: func(harness *durableBrokerHarness) {
				harness.child.ExpiresAt = harness.now.Add(2 * time.Minute)
				harness.dynamic.ExpiresAt = harness.now.Add(3 * time.Minute)
			},
			wantPrepareCalls: 1,
			wantRevokeCalls:  1,
		},
		{
			name: "authorization must advance prepared version",
			mutate: func(harness *durableBrokerHarness) {
				harness.authorization.Revocation.Version = harness.prepared.Revocation.Version
			},
			wantPrepareCalls: 1,
			wantRevokeCalls:  0,
		},
		{
			name: "authorization cannot skip an audit version",
			mutate: func(harness *durableBrokerHarness) {
				harness.authorization.Revocation.Version = harness.prepared.Revocation.Version + 2
			},
			wantPrepareCalls: 1,
			wantRevokeCalls:  0,
		},
		{
			name: "authorization cannot change frozen target",
			mutate: func(harness *durableBrokerHarness) {
				harness.authorization.Revocation.TargetKey = "database/attacker/other"
			},
			wantPrepareCalls: 1,
			wantRevokeCalls:  0,
		},
		{
			name: "anchor must advance authorized version",
			mutate: func(harness *durableBrokerHarness) {
				harness.anchored.Version = harness.authorization.Revocation.Version
			},
			wantPrepareCalls: 1,
			wantRevokeCalls:  1,
		},
		{
			name: "anchor cannot skip an outbox version",
			mutate: func(harness *durableBrokerHarness) {
				harness.anchored.Version = harness.authorization.Revocation.Version + 2
			},
			wantPrepareCalls: 1,
			wantRevokeCalls:  1,
		},
		{
			name: "anchor cannot change frozen issuer",
			mutate: func(harness *durableBrokerHarness) {
				harness.anchored.Issuer = "vault-attacker"
			},
			wantPrepareCalls: 1,
			wantRevokeCalls:  1,
		},
		{
			name: "anchor acknowledgment requires anchored timestamp",
			mutate: func(harness *durableBrokerHarness) {
				harness.anchored.AnchoredAt = time.Time{}
			},
			wantPrepareCalls: 1,
			wantRevokeCalls:  1,
		},
		{
			name: "active cannot skip an outbox version",
			mutate: func(harness *durableBrokerHarness) {
				harness.active.Version = harness.anchored.Version + 2
			},
			wantPrepareCalls: 1,
			wantRevokeCalls:  1,
		},
		{
			name: "active cannot change frozen workspace",
			mutate: func(harness *durableBrokerHarness) {
				harness.active.WorkspaceID = "workspace-attacker"
			},
			wantPrepareCalls: 1,
			wantRevokeCalls:  1,
		},
		{
			name: "active acknowledgment must advance anchor version",
			mutate: func(harness *durableBrokerHarness) {
				harness.active.Version = harness.anchored.Version
			},
			wantPrepareCalls: 1,
			wantRevokeCalls:  1,
		},
		{
			name: "dynamic expiry is canonical",
			mutate: func(harness *durableBrokerHarness) {
				harness.dynamic.ExpiresAt = harness.dynamic.ExpiresAt.Add(time.Nanosecond)
			},
			wantPrepareCalls: 1,
			wantRevokeCalls:  1,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			harness := newDurableBrokerHarness(t)
			test.mutate(harness)

			credential, err := harness.broker.Issue(context.Background(), harness.request)
			if !errors.Is(err, ErrDurableCredentialIssuance) {
				t.Fatalf("Issue() error = %v", err)
			}
			if credential.Secret() != nil {
				t.Fatal("Issue() exposed a secret from an unsafe response")
			}
			if got := harness.calls["prepare"]; got != test.wantPrepareCalls {
				t.Fatalf("Prepare calls = %d, want %d", got, test.wantPrepareCalls)
			}
			if got := harness.calls["request-revocation"]; got != test.wantRevokeCalls {
				t.Fatalf("RequestRevocation calls = %d, want %d", got, test.wantRevokeCalls)
			}
		})
	}
}

func TestDurableBrokerNeverCreatesWithoutUniquePreparedAuthorization(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		mutate        func(*durableBrokerHarness)
		wantResolve   int
		wantManager   int
		wantPrepare   int
		wantAuthorize int
	}{
		{
			name: "invalid trusted selection",
			mutate: func(harness *durableBrokerHarness) {
				harness.request.Selection.Resource = "\nattacker-body"
			},
		},
		{
			name: "production selection is unavailable",
			mutate: func(harness *durableBrokerHarness) {
				harness.request.Selection.Production = true
			},
		},
		{
			name: "policy resolver error",
			mutate: func(harness *durableBrokerHarness) {
				harness.resolveErr = errors.New("resolver-canary")
			},
			wantResolve: 1,
		},
		{
			name: "manager profile validation error",
			mutate: func(harness *durableBrokerHarness) {
				harness.managerErr = errors.New("manager-token-canary")
			},
			wantResolve: 1, wantManager: 1,
		},
		{
			name: "identifier allocation error",
			mutate: func(harness *durableBrokerHarness) {
				harness.broker.uuidSource = func() (string, error) { return "", errors.New("uuid-canary") }
			},
			wantResolve: 1, wantManager: 1,
		},
		{
			name: "prepare error",
			mutate: func(harness *durableBrokerHarness) {
				harness.prepareErr = errors.New("action-fence-token")
			},
			wantResolve: 1, wantManager: 1, wantPrepare: 1,
		},
		{
			name: "prepare replay even if active",
			mutate: func(harness *durableBrokerHarness) {
				harness.prepared.Created = false
				harness.prepared.Revocation = harness.active
			},
			wantResolve: 1, wantManager: 1, wantPrepare: 1,
		},
		{
			name: "creator response without permit",
			mutate: func(harness *durableBrokerHarness) {
				harness.prepared.Permit = nil
			},
			wantResolve: 1, wantManager: 1, wantPrepare: 1,
		},
		{
			name: "database authorization error",
			mutate: func(harness *durableBrokerHarness) {
				harness.authorizeErr = errors.New("permit-canary")
			},
			wantResolve: 1, wantManager: 1, wantPrepare: 1, wantAuthorize: 1,
		},
		{
			name: "database authorization unsafe ttl",
			mutate: func(harness *durableBrokerHarness) {
				harness.authorization.TTL = 0
			},
			wantResolve: 1, wantManager: 1, wantPrepare: 1, wantAuthorize: 1,
		},
		{
			name: "timeout source cannot create context",
			mutate: func(harness *durableBrokerHarness) {
				harness.broker.timeoutSource = func(context.Context, time.Duration) (context.Context, context.CancelFunc) {
					return nil, nil
				}
			},
			wantResolve: 1, wantManager: 1, wantPrepare: 1,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			harness := newDurableBrokerHarness(t)
			test.mutate(harness)
			credential, err := harness.broker.Issue(context.Background(), harness.request)
			if err == nil {
				t.Fatal("Issue() error = nil")
			}
			if credential.Secret() != nil {
				t.Fatal("Issue() exposed secret")
			}
			if harness.calls["resolve"] != test.wantResolve || harness.calls["manager"] != test.wantManager ||
				harness.calls["prepare"] != test.wantPrepare || harness.calls["authorize"] != test.wantAuthorize {
				t.Fatalf("calls = %v, want resolve=%d manager=%d prepare=%d authorize=%d",
					harness.calls, test.wantResolve, test.wantManager, test.wantPrepare, test.wantAuthorize)
			}
			if got := harness.calls["create-child"]; got != 0 {
				t.Fatalf("CreateChild calls = %d, want 0", got)
			}
			if containsAny(err.Error(), "resolver-canary", "manager-token-canary", "uuid-canary", "action-fence-token", "permit-canary") {
				t.Fatalf("error rendered upstream material: %q", err)
			}
		})
	}
}

func TestDurableBrokerRejectsInvalidCreateContextBeforeDatabaseAuthorization(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		source func(context.Context, time.Duration) (context.Context, context.CancelFunc)
	}{
		{
			name: "done without deadline",
			source: func(parent context.Context, _ time.Duration) (context.Context, context.CancelFunc) {
				return context.WithCancel(parent)
			},
		},
		{
			name: "deadline beyond fixed budget",
			source: func(parent context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
				return context.WithTimeout(parent, 2*timeout)
			},
		},
		{
			name: "already expired deadline",
			source: func(parent context.Context, _ time.Duration) (context.Context, context.CancelFunc) {
				return context.WithDeadline(parent, time.Now().Add(-time.Second))
			},
		},
		{
			name: "deadline without done channel",
			source: func(parent context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
				return deadlineWithoutDoneContext{Context: parent, deadline: time.Now().Add(timeout / 2)}, func() {}
			},
		},
		{
			name: "wall clock only deadline",
			source: func(parent context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
				wallDeadline := time.Unix(0, time.Now().Add(timeout/2).UnixNano())
				return context.WithDeadline(parent, wallDeadline)
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			harness := newDurableBrokerHarness(t)
			harness.broker.timeoutSource = test.source

			credential, err := harness.broker.Issue(context.Background(), harness.request)
			if !errors.Is(err, ErrDurableCredentialIssuance) {
				t.Fatalf("Issue() error = %v", err)
			}
			if credential.Secret() != nil {
				t.Fatal("Issue() exposed secret")
			}
			if got := harness.calls["authorize"]; got != 0 {
				t.Fatalf("AuthorizeChildCreate calls = %d, want 0", got)
			}
			if got := harness.calls["create-child"]; got != 0 {
				t.Fatalf("CreateChild calls = %d, want 0", got)
			}
		})
	}
}

func TestDurableBrokerCanceledCallerAfterChildDispatchStillAnchorsAndPersistsRevocation(t *testing.T) {
	harness := newDurableBrokerHarness(t)
	callerCtx, cancelCaller := context.WithCancel(context.Background())
	harness.issuer.createChild = func(context.Context, DurableChildCreateRequest) (DurableChild, error) {
		harness.calls["create-child"]++
		cancelCaller()
		return harness.child, nil
	}
	harness.repository.recordAnchor = func(ctx context.Context, request RecordAnchorRequest) (Revocation, error) {
		harness.calls["anchor"]++
		assertUsableBoundedContext(t, ctx, PostDispatchPersistenceTimeout)
		if request.Accessor != harness.child.Accessor {
			t.Fatal("RecordAnchor did not receive returned accessor")
		}
		return harness.anchored, nil
	}
	harness.repository.requestRevocation = func(ctx context.Context, _ ActionTransitionRequest) (Revocation, error) {
		harness.calls["request-revocation"]++
		assertUsableBoundedContext(t, ctx, PostDispatchPersistenceTimeout)
		if token := harness.child.Token.Bytes(); len(token) != 0 {
			t.Fatalf("child token present before revocation persistence: %q", token)
		}
		return harness.pending, nil
	}

	credential, err := harness.broker.Issue(callerCtx, harness.request)
	if !errors.Is(err, ErrDurableCredentialIssuance) {
		t.Fatalf("Issue() error = %v", err)
	}
	if credential.Secret() != nil {
		t.Fatal("Issue() exposed secret after caller cancellation")
	}
	if callerCtx.Err() != context.Canceled {
		t.Fatalf("caller context error = %v", callerCtx.Err())
	}
	if got := harness.calls["anchor"]; got != 1 {
		t.Fatalf("RecordAnchor calls = %d, want 1", got)
	}
	if got := harness.calls["request-revocation"]; got != 1 {
		t.Fatalf("RequestRevocation calls = %d, want 1", got)
	}
	if got := harness.calls["inspect-child"]; got != 0 {
		t.Fatalf("InspectChild calls = %d, want 0", got)
	}
	if got := harness.calls["issue-dynamic"]; got != 0 {
		t.Fatalf("IssueDynamic calls = %d, want 0", got)
	}
}

func TestDurableBrokerRejectsInvalidFinalizeContextBeforeAuthorization(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		source BoundedContextSource
	}{
		{
			name: "done without deadline",
			source: func(parent context.Context, _ time.Duration) (context.Context, context.CancelFunc) {
				return context.WithCancel(parent)
			},
		},
		{
			name: "deadline beyond fixed budget",
			source: func(parent context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
				return context.WithTimeout(parent, 2*timeout)
			},
		},
		{
			name: "already expired deadline",
			source: func(parent context.Context, _ time.Duration) (context.Context, context.CancelFunc) {
				return context.WithDeadline(parent, time.Now().Add(-time.Second))
			},
		},
		{
			name: "deadline without done channel",
			source: func(parent context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
				return deadlineWithoutDoneContext{Context: parent, deadline: time.Now().Add(timeout / 2)}, func() {}
			},
		},
		{
			name: "wall clock only deadline",
			source: func(parent context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
				wallDeadline := time.Unix(0, time.Now().Add(timeout/2).UnixNano())
				return context.WithDeadline(parent, wallDeadline)
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			harness := newDurableBrokerHarness(t)
			harness.broker.finalizeContextSource = test.source

			credential, err := harness.broker.Issue(context.Background(), harness.request)
			if !errors.Is(err, ErrDurableCredentialIssuance) {
				t.Fatalf("Issue() error = %v", err)
			}
			if credential.Secret() != nil {
				t.Fatal("Issue() exposed secret")
			}
			if got := harness.calls["prepare"]; got != 0 {
				t.Fatalf("Prepare calls = %d, want 0", got)
			}
			if got := harness.calls["authorize"]; got != 0 {
				t.Fatalf("AuthorizeChildCreate calls = %d, want 0", got)
			}
			if got := harness.calls["create-child"]; got != 0 {
				t.Fatalf("CreateChild calls = %d, want 0", got)
			}
			if got := harness.calls["anchor"]; got != 0 {
				t.Fatalf("RecordAnchor calls = %d, want 0", got)
			}
			if got := harness.calls["inspect-child"]; got != 0 {
				t.Fatalf("InspectChild calls = %d, want 0", got)
			}
			if got := harness.calls["issue-dynamic"]; got != 0 {
				t.Fatalf("IssueDynamic calls = %d, want 0", got)
			}
		})
	}
}

func TestDurableBrokerFallsBackWhenFinalizeSourceFailsAfterPreflight(t *testing.T) {
	harness := newDurableBrokerHarness(t)
	callerCtx, cancelCaller := context.WithCancel(context.Background())
	harness.issuer.createChild = func(context.Context, DurableChildCreateRequest) (DurableChild, error) {
		harness.calls["create-child"]++
		cancelCaller()
		return harness.child, nil
	}
	finalizeCalls := 0
	harness.broker.finalizeContextSource = func(parent context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
		finalizeCalls++
		if finalizeCalls == 1 {
			return context.WithTimeout(context.WithoutCancel(parent), timeout)
		}
		return context.WithCancel(context.WithoutCancel(parent))
	}
	harness.repository.recordAnchor = func(ctx context.Context, request RecordAnchorRequest) (Revocation, error) {
		harness.calls["anchor"]++
		assertUsableBoundedContext(t, ctx, PostDispatchPersistenceTimeout)
		if request.Accessor != harness.child.Accessor {
			t.Fatal("RecordAnchor did not receive the only returned accessor")
		}
		return harness.anchored, nil
	}
	harness.repository.requestRevocation = func(ctx context.Context, _ ActionTransitionRequest) (Revocation, error) {
		harness.calls["request-revocation"]++
		assertUsableBoundedContext(t, ctx, PostDispatchPersistenceTimeout)
		return harness.pending, nil
	}

	credential, err := harness.broker.Issue(callerCtx, harness.request)
	if !errors.Is(err, ErrDurableCredentialIssuance) {
		t.Fatalf("Issue() error = %v", err)
	}
	if credential.Secret() != nil {
		t.Fatal("Issue() exposed secret")
	}
	if got := harness.calls["create-child"]; got != 1 {
		t.Fatalf("CreateChild calls = %d, want 1", got)
	}
	if got := harness.calls["anchor"]; got != 1 {
		t.Fatalf("RecordAnchor calls = %d, want 1", got)
	}
	if got := harness.calls["request-revocation"]; got != 1 {
		t.Fatalf("RequestRevocation calls = %d, want 1", got)
	}
	if got := harness.calls["inspect-child"]; got != 0 {
		t.Fatalf("InspectChild calls = %d, want 0", got)
	}
	if got := harness.calls["issue-dynamic"]; got != 0 {
		t.Fatalf("IssueDynamic calls = %d, want 0", got)
	}
	if finalizeCalls != 3 {
		t.Fatalf("FinalizeContextSource calls = %d, want 3", finalizeCalls)
	}
}

func TestDurableBrokerAmbiguousCreateWithoutAccessorRemainsPrepared(t *testing.T) {
	t.Parallel()

	harness := newDurableBrokerHarness(t)
	harness.child.Accessor = nil
	harness.createErr = errors.New("Vault may have committed but returned no accessor")

	credential, err := harness.broker.Issue(context.Background(), harness.request)
	if !errors.Is(err, ErrDurableCredentialIssuance) {
		t.Fatalf("Issue() error = %v", err)
	}
	if credential.Secret() != nil {
		t.Fatal("Issue() exposed secret")
	}
	if got := harness.calls["anchor"]; got != 0 {
		t.Fatalf("RecordAnchor calls = %d, want 0", got)
	}
	if got := harness.calls["request-revocation"]; got != 0 {
		t.Fatalf("RequestRevocation calls = %d, want 0", got)
	}
	if token := harness.child.Token.Bytes(); len(token) != 0 {
		t.Fatalf("child token was not destroyed: %q", token)
	}
}

func TestDurableCredentialFormattingCopiesAndDestroyAreSafe(t *testing.T) {
	t.Parallel()

	harness := newDurableBrokerHarness(t)
	credential, err := harness.broker.Issue(context.Background(), harness.request)
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}
	copy := credential
	secret := credential.Secret()
	secret[0] = 'X'
	if got := string(copy.Secret()); got != "dynamic-secret-canary" {
		t.Fatalf("Secret() did not clone: %q", got)
	}
	rendered := fmt.Sprintf("%v %+v %#v", credential, credential, credential)
	encoded, err := json.Marshal(credential)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	if containsAny(rendered+string(encoded), "dynamic-secret-canary", "vault-child-token-canary", "vault-accessor-canary", harness.fence.Token) {
		t.Fatalf("credential rendered sensitive material: %s / %s", rendered, encoded)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &fields); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if len(fields) != 2 || fields["revocation_id"] == nil || fields["expires_at"] == nil {
		t.Fatalf("credential JSON fields = %v", fields)
	}
	var decoded DurableCredential
	if err := json.Unmarshal(encoded, &decoded); !errors.Is(err, ErrDurableCredentialState) {
		t.Fatalf("json.Unmarshal(DurableCredential) error = %v", err)
	}
	copy.Destroy()
	if got := credential.Secret(); got != nil {
		t.Fatalf("Destroy(copy) left original secret = %q", got)
	}
}

func TestDurableCredentialSecretFailsClosedAfterExpiry(t *testing.T) {
	t.Parallel()

	harness := newDurableBrokerHarness(t)
	credential, err := harness.broker.Issue(context.Background(), harness.request)
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}
	if got := credential.Secret(); len(got) == 0 {
		t.Fatal("Secret() was empty before expiry")
	} else {
		clear(got)
	}
	harness.broker.clock = func() time.Time { return credential.ExpiresAt() }
	if got := credential.Secret(); got != nil {
		clear(got)
		t.Fatalf("Secret() at expiry = %q, want nil", got)
	}
	harness.broker.clock = func() time.Time { return harness.now }
	if got := credential.Secret(); got != nil {
		clear(got)
		t.Fatalf("Secret() after expiry cleanup was reconstructed: %q", got)
	}
}

func TestIssueDurableCredentialRequestNeverRendersBearerOrAcceptsWirePayload(t *testing.T) {
	t.Parallel()

	request := IssueDurableCredentialRequest{Fence: durableTestFence(), Selection: durableTestSelection()}
	rendered := fmt.Sprintf("%v %+v %#v", request, request, request)
	encoded, err := json.Marshal(request)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	if containsAny(rendered+string(encoded), request.Fence.Token) {
		t.Fatalf("request rendered bearer token: %s / %s", rendered, encoded)
	}
	if !containsAny(rendered+string(encoded), "REDACTED", "fence_token_redacted") {
		t.Fatalf("request did not make redaction explicit: %s / %s", rendered, encoded)
	}
	for _, forbidden := range []string{`"url"`, `"path"`, `"method"`, `"body"`} {
		if containsAny(string(encoded), forbidden) {
			t.Fatalf("request JSON contains issuer-controlled field %s: %s", forbidden, encoded)
		}
	}
	var decoded IssueDurableCredentialRequest
	if err := json.Unmarshal([]byte(`{"path":"sys/raw","method":"POST","body":{"token":"attacker"}}`), &decoded); !errors.Is(err, ErrInvalidDurableCredentialRequest) {
		t.Fatalf("json.Unmarshal(untrusted request) error = %v", err)
	}
}

func TestDurableBrokerRequestRevocationAcceptsRevokedWithoutAccessorAndRejectsWrongRow(t *testing.T) {
	t.Parallel()

	t.Run("revoked", func(t *testing.T) {
		harness := newDurableBrokerHarness(t)
		credential, err := harness.broker.Issue(context.Background(), harness.request)
		if err != nil {
			t.Fatalf("Issue() error = %v", err)
		}
		revoked := harness.pending
		revoked.Status = StatusRevoked
		revoked.AccessorPresent = false
		revoked.Version++
		revoked.RevokedAt = harness.now.Add(5 * time.Second)
		revoked.UpdatedAt = revoked.RevokedAt
		harness.pending = revoked

		result, err := harness.broker.RequestRevocation(context.Background(), credential)
		if err != nil {
			t.Fatalf("RequestRevocation() error = %v", err)
		}
		if result.Status != StatusRevoked || result.AccessorPresent {
			t.Fatalf("RequestRevocation() = %#v", result)
		}
		if credential.Secret() != nil {
			t.Fatal("RequestRevocation() did not destroy secret")
		}
	})

	t.Run("wrong frozen workspace", func(t *testing.T) {
		harness := newDurableBrokerHarness(t)
		credential, err := harness.broker.Issue(context.Background(), harness.request)
		if err != nil {
			t.Fatalf("Issue() error = %v", err)
		}
		harness.pending.WorkspaceID = "workspace-attacker"

		if _, err := harness.broker.RequestRevocation(context.Background(), credential); !errors.Is(err, ErrDurableCredentialIssuance) {
			t.Fatalf("RequestRevocation() error = %v", err)
		}
		if credential.Secret() != nil {
			t.Fatal("failed RequestRevocation() did not destroy secret")
		}
	})

	t.Run("tampered handle", func(t *testing.T) {
		harness := newDurableBrokerHarness(t)
		credential, err := harness.broker.Issue(context.Background(), harness.request)
		if err != nil {
			t.Fatalf("Issue() error = %v", err)
		}
		tampered := credential
		tampered.revocationID = "40000000-0000-4000-8000-000000000099"
		if _, err := harness.broker.RequestRevocation(context.Background(), tampered); !errors.Is(err, ErrDurableCredentialState) {
			t.Fatalf("RequestRevocation(tampered) error = %v", err)
		}
		if credential.Secret() != nil {
			t.Fatal("tampered RequestRevocation() did not first destroy shared secret")
		}
		if got := harness.calls["request-revocation"]; got != 0 {
			t.Fatalf("repository calls = %d, want 0", got)
		}
	})
}

func TestDurableBrokerRequestRevocationWaiterHonorsContext(t *testing.T) {
	harness := newDurableBrokerHarness(t)
	credential, err := harness.broker.Issue(context.Background(), harness.request)
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}
	entered := make(chan struct{})
	release := make(chan struct{})
	harness.repository.requestRevocation = func(context.Context, ActionTransitionRequest) (Revocation, error) {
		if harness.calls["request-revocation"] == 0 {
			harness.calls["request-revocation"]++
			close(entered)
			<-release
			return harness.pending, nil
		}
		harness.calls["request-revocation"]++
		return harness.pending, nil
	}
	firstResult := make(chan error, 1)
	go func() {
		_, callErr := harness.broker.RequestRevocation(context.Background(), credential)
		firstResult <- callErr
	}()
	<-entered
	waiterCtx, cancel := context.WithCancel(context.Background())
	waiterResult := make(chan error, 1)
	go func() {
		_, callErr := harness.broker.RequestRevocation(waiterCtx, credential)
		waiterResult <- callErr
	}()
	cancel()
	select {
	case callErr := <-waiterResult:
		if !errors.Is(callErr, context.Canceled) {
			close(release)
			<-firstResult
			t.Fatalf("waiting RequestRevocation() error = %v", callErr)
		}
	case <-time.After(100 * time.Millisecond):
		close(release)
		<-firstResult
		t.Fatal("waiting RequestRevocation() ignored its canceled context")
	}
	close(release)
	if callErr := <-firstResult; callErr != nil {
		t.Fatalf("first RequestRevocation() error = %v", callErr)
	}
	if got := harness.calls["request-revocation"]; got != 1 {
		t.Fatalf("repository calls = %d, want 1", got)
	}
}

func TestDurableBrokerRequestRevocationCachesSuccessAndRetriesFailure(t *testing.T) {
	t.Run("concurrent success is persisted once", func(t *testing.T) {
		harness := newDurableBrokerHarness(t)
		credential, err := harness.broker.Issue(context.Background(), harness.request)
		if err != nil {
			t.Fatalf("Issue() error = %v", err)
		}
		entered := make(chan struct{})
		release := make(chan struct{})
		var once sync.Once
		var calls int
		var callsMu sync.Mutex
		harness.repository.requestRevocation = func(context.Context, ActionTransitionRequest) (Revocation, error) {
			callsMu.Lock()
			calls++
			callsMu.Unlock()
			once.Do(func() { close(entered) })
			<-release
			return harness.pending, nil
		}
		const workers = 8
		errorsByWorker := make(chan error, workers)
		for range workers {
			go func() {
				_, callErr := harness.broker.RequestRevocation(context.Background(), credential)
				errorsByWorker <- callErr
			}()
		}
		<-entered
		close(release)
		for range workers {
			if callErr := <-errorsByWorker; callErr != nil {
				t.Fatalf("RequestRevocation() error = %v", callErr)
			}
		}
		callsMu.Lock()
		defer callsMu.Unlock()
		if calls != 1 {
			t.Fatalf("repository calls = %d, want 1", calls)
		}
	})

	t.Run("failure remains retryable", func(t *testing.T) {
		harness := newDurableBrokerHarness(t)
		credential, err := harness.broker.Issue(context.Background(), harness.request)
		if err != nil {
			t.Fatalf("Issue() error = %v", err)
		}
		calls := 0
		harness.repository.requestRevocation = func(context.Context, ActionTransitionRequest) (Revocation, error) {
			calls++
			if calls == 1 {
				return Revocation{}, errors.New("database response lost secret-canary")
			}
			return harness.pending, nil
		}
		if _, err := harness.broker.RequestRevocation(context.Background(), credential); !errors.Is(err, ErrDurableCredentialIssuance) {
			t.Fatalf("RequestRevocation(first) error = %v", err)
		}
		if _, err := harness.broker.RequestRevocation(context.Background(), credential); err != nil {
			t.Fatalf("RequestRevocation(retry) error = %v", err)
		}
		if calls != 2 {
			t.Fatalf("repository calls = %d, want 2", calls)
		}
	})
}

type durableBrokerHarness struct {
	t                   *testing.T
	now                 time.Time
	fence               ActionFence
	selection           DurableIssuerResolveRequest
	profile             DurableIssuerProfile
	request             IssueDurableCredentialRequest
	prepared            PrepareResult
	authorization       ChildCreateAuthorization
	child               DurableChild
	anchored            Revocation
	dynamic             DurableDynamicSecret
	active              Revocation
	pending             Revocation
	resolveErr          error
	managerErr          error
	prepareErr          error
	authorizeErr        error
	createErr           error
	anchorErr           error
	inspectErr          error
	issueErr            error
	activateErr         error
	revocationErr       error
	calls               map[string]int
	onRequestRevocation func()
	broker              *DurableBroker
	repository          *durableBrokerRepositoryStub
	issuer              *durableIssuerStub
}

func newDurableBrokerHarness(t *testing.T) *durableBrokerHarness {
	t.Helper()
	now := time.Date(2026, 7, 10, 11, 0, 0, 0, time.UTC)
	fence := durableTestFence()
	selection := durableTestSelection()
	profile := DurableIssuerProfile{IssuerID: "vault-database-nonprod", Revision: "rev-17", CredentialTTL: 5 * time.Minute}
	preparedRevocation := durablePreparedRevocation(now, selection, profile)
	permit := &ChildCreatePermit{RevocationID: durableTestRevocationID, Token: "single-use-create-permit"}
	accessor, err := NewSensitiveReference([]byte("vault-accessor-canary"))
	if err != nil {
		t.Fatalf("NewSensitiveReference() error = %v", err)
	}
	childToken, err := NewSensitiveValue([]byte("vault-child-token-canary"))
	if err != nil {
		t.Fatalf("NewSensitiveValue(child token) error = %v", err)
	}
	secret, err := NewSensitiveValue([]byte("dynamic-secret-canary"))
	if err != nil {
		t.Fatalf("NewSensitiveValue(secret) error = %v", err)
	}
	authorizedRevocation := preparedRevocation
	authorizedRevocation.Version = 2
	authorizedRevocation.UpdatedAt = now.Add(time.Second)
	anchored := authorizedRevocation
	anchored.Status = StatusAnchored
	anchored.AccessorPresent = true
	anchored.Version = 3
	anchored.AnchoredAt = now.Add(2 * time.Second)
	anchored.UpdatedAt = anchored.AnchoredAt
	active := anchored
	active.Status = StatusActive
	active.Version = 4
	active.ActivatedAt = now.Add(3 * time.Second)
	active.UpdatedAt = active.ActivatedAt
	pending := active
	pending.Status = StatusRevocationPending
	pending.Version = 5
	pending.RevocationRequestedAt = now.Add(4 * time.Second)
	pending.UpdatedAt = pending.RevocationRequestedAt
	harness := &durableBrokerHarness{
		t: t, now: now, fence: fence, selection: selection, profile: profile,
		request:  IssueDurableCredentialRequest{Fence: fence, Selection: selection},
		prepared: PrepareResult{Revocation: preparedRevocation, Created: true, Permit: permit},
		authorization: ChildCreateAuthorization{
			Revocation: authorizedRevocation, DatabaseAuthorizedAt: now.Add(time.Second),
			CredentialExpiresAt: preparedRevocation.CredentialExpiresAt, TTL: 4 * time.Minute,
			VaultCallBudget: ChildCreateVaultCallBudget,
		},
		child:    DurableChild{Token: childToken, Accessor: accessor, ExpiresAt: preparedRevocation.CredentialExpiresAt},
		dynamic:  DurableDynamicSecret{Secret: secret, ExpiresAt: now.Add(3 * time.Minute)},
		anchored: anchored, active: active, pending: pending, calls: make(map[string]int),
	}
	issuer := &durableIssuerStub{
		validateManager: func(context.Context) error {
			harness.calls["manager"]++
			return harness.managerErr
		},
		createChild: func(context.Context, DurableChildCreateRequest) (DurableChild, error) {
			harness.calls["create-child"]++
			return harness.child, harness.createErr
		},
		inspectChild: func(context.Context, *SensitiveReference, DurableChildInspectionRequest) error {
			harness.calls["inspect-child"]++
			return harness.inspectErr
		},
		issueDynamic: func(context.Context, SensitiveValue, DurableDynamicIssueRequest) (DurableDynamicSecret, error) {
			harness.calls["issue-dynamic"]++
			return harness.dynamic, harness.issueErr
		},
	}
	resolver := &durableIssuerResolverStub{resolve: func(context.Context, DurableIssuerResolveRequest) (ResolvedDurableIssuer, error) {
		harness.calls["resolve"]++
		return ResolvedDurableIssuer{Profile: harness.profile, Issuer: issuer}, harness.resolveErr
	}}
	repository := &durableBrokerRepositoryStub{
		prepare: func(context.Context, PrepareRequest) (PrepareResult, error) {
			harness.calls["prepare"]++
			return harness.prepared, harness.prepareErr
		},
		authorizeChildCreate: func(context.Context, AuthorizeChildCreateRequest) (ChildCreateAuthorization, error) {
			harness.calls["authorize"]++
			return harness.authorization, harness.authorizeErr
		},
		recordAnchor: func(context.Context, RecordAnchorRequest) (Revocation, error) {
			harness.calls["anchor"]++
			return harness.anchored, harness.anchorErr
		},
		activate: func(context.Context, ActionTransitionRequest) (Revocation, error) {
			harness.calls["activate"]++
			return harness.active, harness.activateErr
		},
		requestRevocation: func(_ context.Context, request ActionTransitionRequest) (Revocation, error) {
			harness.calls["request-revocation"]++
			if request.RevocationID != durableTestRevocationID || request.Fence != (ActionFence{}) {
				t.Fatalf("system recovery RequestRevocation request = %#v", request)
			}
			if harness.onRequestRevocation != nil {
				harness.onRequestRevocation()
			}
			return harness.pending, harness.revocationErr
		},
	}
	broker, err := NewDurableBroker(repository, resolver, DurableBrokerOptions{
		UUIDSource: func() (string, error) { return durableTestRevocationID, nil },
		Clock:      func() time.Time { return now },
		TimeoutSource: func(parent context.Context, _ time.Duration) (context.Context, context.CancelFunc) {
			return context.WithTimeout(parent, ChildCreateVaultCallBudget)
		},
	})
	if err != nil {
		t.Fatalf("NewDurableBroker() error = %v", err)
	}
	harness.broker = broker
	harness.repository = repository
	harness.issuer = issuer
	return harness
}

func containsAny(value string, candidates ...string) bool {
	for _, candidate := range candidates {
		if len(candidate) > 0 && len(value) >= len(candidate) {
			for start := 0; start+len(candidate) <= len(value); start++ {
				if value[start:start+len(candidate)] == candidate {
					return true
				}
			}
		}
	}
	return false
}

type durableTimeoutContextKey struct{}

func assertUsableBoundedContext(t *testing.T, ctx context.Context, maximum time.Duration) {
	t.Helper()
	if ctx.Err() != nil || ctx.Done() == nil {
		t.Fatalf("context is not usable: err=%v done=%v", ctx.Err(), ctx.Done())
	}
	deadline, ok := ctx.Deadline()
	if !ok || !deadline.After(time.Now()) || time.Until(deadline) > maximum {
		t.Fatalf("context deadline = %s, ok=%t, maximum=%s", deadline, ok, maximum)
	}
}

type deadlineWithoutDoneContext struct {
	context.Context
	deadline time.Time
}

func (ctx deadlineWithoutDoneContext) Deadline() (time.Time, bool) { return ctx.deadline, true }

func durableTestFence() ActionFence {
	return ActionFence{ActionID: durableTestActionID, RunnerID: "write-runner-nonprod-1", Token: "action-fence-token", Epoch: 12}
}

func durableTestSelection() DurableIssuerResolveRequest {
	return DurableIssuerResolveRequest{
		ProfileID: "database-readwrite-nonprod", WorkspaceID: "workspace-1", EnvironmentID: "staging-1",
		ActionType: "database.credentials", ConnectorID: "postgres-staging", Permission: "database.readwrite",
		Resource: "postgres://inventory/orders",
	}
}

func durablePreparedRevocation(now time.Time, selection DurableIssuerResolveRequest, profile DurableIssuerProfile) Revocation {
	return Revocation{
		ID: durableTestRevocationID, TenantID: "tenant-1", WorkspaceID: selection.WorkspaceID,
		EnvironmentID: selection.EnvironmentID, ActionID: durableTestActionID, TargetKey: "database/inventory/orders",
		RunnerID: durableTestFence().RunnerID, ActionLeaseEpoch: durableTestFence().Epoch,
		Issuer: profile.IssuerID, ConnectorID: selection.ConnectorID, Permission: selection.Permission,
		Resource: selection.Resource, CredentialExpiresAt: now.Add(profile.CredentialTTL), Status: StatusPrepared,
		CreatedAt: now, UpdatedAt: now, AvailableAt: now, Version: 1,
	}
}

type durableIssuerResolverStub struct {
	resolve func(context.Context, DurableIssuerResolveRequest) (ResolvedDurableIssuer, error)
}

func (resolver *durableIssuerResolverStub) ResolveDurableIssuer(
	ctx context.Context,
	request DurableIssuerResolveRequest,
) (ResolvedDurableIssuer, error) {
	if resolver.resolve == nil {
		return ResolvedDurableIssuer{}, errors.New("unexpected resolver call")
	}
	return resolver.resolve(ctx, request)
}

type durableIssuerStub struct {
	validateManager func(context.Context) error
	createChild     func(context.Context, DurableChildCreateRequest) (DurableChild, error)
	inspectChild    func(context.Context, *SensitiveReference, DurableChildInspectionRequest) error
	issueDynamic    func(context.Context, SensitiveValue, DurableDynamicIssueRequest) (DurableDynamicSecret, error)
}

func (issuer *durableIssuerStub) ValidateManager(ctx context.Context) error {
	if issuer.validateManager == nil {
		return errors.New("unexpected ValidateManager call")
	}
	return issuer.validateManager(ctx)
}

func (issuer *durableIssuerStub) CreateChild(ctx context.Context, request DurableChildCreateRequest) (DurableChild, error) {
	if issuer.createChild == nil {
		return DurableChild{}, errors.New("unexpected CreateChild call")
	}
	return issuer.createChild(ctx, request)
}

func (issuer *durableIssuerStub) InspectChild(
	ctx context.Context,
	accessor *SensitiveReference,
	request DurableChildInspectionRequest,
) error {
	if issuer.inspectChild == nil {
		return errors.New("unexpected InspectChild call")
	}
	return issuer.inspectChild(ctx, accessor, request)
}

func (issuer *durableIssuerStub) IssueDynamic(
	ctx context.Context,
	token SensitiveValue,
	request DurableDynamicIssueRequest,
) (DurableDynamicSecret, error) {
	if issuer.issueDynamic == nil {
		return DurableDynamicSecret{}, errors.New("unexpected IssueDynamic call")
	}
	return issuer.issueDynamic(ctx, token, request)
}

type durableBrokerRepositoryStub struct {
	Repository
	prepare              func(context.Context, PrepareRequest) (PrepareResult, error)
	authorizeChildCreate func(context.Context, AuthorizeChildCreateRequest) (ChildCreateAuthorization, error)
	recordAnchor         func(context.Context, RecordAnchorRequest) (Revocation, error)
	activate             func(context.Context, ActionTransitionRequest) (Revocation, error)
	requestRevocation    func(context.Context, ActionTransitionRequest) (Revocation, error)
}

func (repository *durableBrokerRepositoryStub) Prepare(ctx context.Context, request PrepareRequest) (PrepareResult, error) {
	if repository.prepare == nil {
		return PrepareResult{}, fmt.Errorf("unexpected Prepare call")
	}
	return repository.prepare(ctx, request)
}

func (repository *durableBrokerRepositoryStub) AuthorizeChildCreate(
	ctx context.Context,
	request AuthorizeChildCreateRequest,
) (ChildCreateAuthorization, error) {
	if repository.authorizeChildCreate == nil {
		return ChildCreateAuthorization{}, fmt.Errorf("unexpected AuthorizeChildCreate call")
	}
	return repository.authorizeChildCreate(ctx, request)
}

func (repository *durableBrokerRepositoryStub) RecordAnchor(
	ctx context.Context,
	request RecordAnchorRequest,
) (Revocation, error) {
	if repository.recordAnchor == nil {
		return Revocation{}, fmt.Errorf("unexpected RecordAnchor call")
	}
	return repository.recordAnchor(ctx, request)
}

func (repository *durableBrokerRepositoryStub) Activate(
	ctx context.Context,
	request ActionTransitionRequest,
) (Revocation, error) {
	if repository.activate == nil {
		return Revocation{}, fmt.Errorf("unexpected Activate call")
	}
	return repository.activate(ctx, request)
}

func (repository *durableBrokerRepositoryStub) RequestRevocation(
	ctx context.Context,
	request ActionTransitionRequest,
) (Revocation, error) {
	if repository.requestRevocation == nil {
		return Revocation{}, fmt.Errorf("unexpected RequestRevocation call")
	}
	return repository.requestRevocation(ctx, request)
}

var (
	_ DurableIssuerResolver = (*durableIssuerResolverStub)(nil)
	_ DurableIssuer         = (*durableIssuerStub)(nil)
	_ Repository            = (*durableBrokerRepositoryStub)(nil)
	_                       = sync.Once{}
)
