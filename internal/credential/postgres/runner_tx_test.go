package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/pashagolub/pgxmock/v4"
	"github.com/seaworld008/aiops-system/internal/credential"
	"github.com/seaworld008/aiops-system/internal/execution"
	"github.com/seaworld008/aiops-system/internal/executionlease"
)

func TestPrepareRunnerTxUsesCallerTransactionAndReturnsPermitOnlyToUniqueCreator(t *testing.T) {
	t.Parallel()
	database, err := pgxmock.NewPool()
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	permitCalls := 0
	repository, err := New(database, repositoryTestProtector(t), Options{PermitSource: func() (string, error) {
		permitCalls++
		return "runner-child-create-permit", nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 11, 8, 0, 0, 0, time.UTC)
	fence := runnerCredentialFence()
	request := credential.PrepareRequest{
		RevocationID: postgresTestRevocationID, Fence: fence,
		Issuer: "vault-production", IssuerRevision: "rev-1", CredentialExpiresAt: now.Add(5 * time.Minute),
	}
	tokenDigest := credential.SHA256Hex([]byte(fence.Token))
	permitDigest := credential.SHA256Hex([]byte("runner-child-create-permit"))

	database.ExpectBegin()
	tx, err := database.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	expectRunnerPrepareAction(database, now, fence)
	database.ExpectQuery("SELECT .* FROM credential_revocations.*WHERE action_id = \\$1 AND action_lease_epoch = \\$2.*FOR SHARE").
		WithArgs(fence.ActionID, fence.Epoch).
		WillReturnRows(pgxmock.NewRows(storedRevocationColumns()))
	database.ExpectQuery("INSERT INTO credential_revocations").
		WithArgs(
			request.RevocationID, postgresTestTenantID, postgresTestWorkspaceID, postgresTestEnvironment,
			fence.ActionID, "cluster-a/payments", false, fence.RunnerID, fence.Epoch, tokenDigest,
			request.Issuer, request.IssuerRevision, "KUBERNETES_ROLLOUT_RESTART", "kubernetes-prod",
			"PATCH_DEPLOYMENT_RESTART", "cluster-a/payments/deployment/api", int32(600),
			request.CredentialExpiresAt, permitDigest,
		).
		WillReturnRows(pgxmock.NewRows([]string{"status", "available_at", "created_at", "updated_at", "version"}).
			AddRow("PREPARED", now, now, now, int64(1)))
	expectActionCredentialMarker(database, fence, tokenDigest)
	expectRunnerStateChange(database, fence.RunnerID, "credential.revocation.prepared",
		"credential.revocation.prepared.v1", 1)
	expectRunnerPrepareAction(database, now, fence)

	created, err := repository.PrepareRunnerTx(context.Background(), tx, runnerCredentialScope(t, executionlease.PoolWrite), request)
	if err != nil || !created.Created || created.Permit == nil || created.Permit.Token != "runner-child-create-permit" {
		t.Fatalf("PrepareRunnerTx(create) = %#v, %v", created, err)
	}

	// The same caller-owned transaction observes an idempotent replay. It must
	// never mint or return a second raw permit.
	expectRunnerPrepareAction(database, now, fence)
	database.ExpectQuery("SELECT .* FROM credential_revocations.*WHERE action_id = \\$1 AND action_lease_epoch = \\$2.*FOR SHARE").
		WithArgs(fence.ActionID, fence.Epoch).
		WillReturnRows(storedRevocationRows(now, storedRowOptions{
			Status: credential.StatusPrepared, AvailableAt: now, Version: 1,
			CredentialExpiresAt: request.CredentialExpiresAt, ChildCreatePermitSHA256: permitDigest,
		}))
	expectActionCredentialMarker(database, fence, tokenDigest)
	expectRunnerPrepareAction(database, now, fence)
	replayed, err := repository.PrepareRunnerTx(context.Background(), tx, runnerCredentialScope(t, executionlease.PoolWrite), request)
	if err != nil || replayed.Created || replayed.Permit != nil || replayed.Revocation.ID != request.RevocationID {
		t.Fatalf("PrepareRunnerTx(replay) = %#v, %v", replayed, err)
	}
	if permitCalls != 1 {
		t.Fatalf("PermitSource calls = %d, want 1", permitCalls)
	}

	// No method-owned Commit is expected. A rollback remains available to the
	// caller, proving the transaction was not consumed.
	database.ExpectRollback()
	if err := tx.Rollback(context.Background()); err != nil {
		t.Fatalf("caller Rollback() error = %v", err)
	}
	if err := database.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet pgx expectations: %v", err)
	}
}

func TestRunnerCredentialTxRejectsReadProductionOutOfScopeAndStaleEpoch(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 11, 8, 5, 0, 0, time.UTC)
	for _, test := range []struct {
		name        string
		scope       func(*testing.T) execution.RunnerScope
		rows        *pgxmock.Rows
		want        error
		queryAction bool
	}{
		{name: "READ pool", scope: func(t *testing.T) execution.RunnerScope {
			return runnerCredentialScope(t, executionlease.PoolRead)
		}, want: credential.ErrInvalidRevocationRequest},
		{name: "non UUID tenant", scope: func(t *testing.T) execution.RunnerScope {
			registration := runnerCredentialRegistration(executionlease.PoolWrite)
			registration.TenantID = "tenant-not-a-uuid"
			scope, err := registration.Scope()
			if err != nil {
				t.Fatal(err)
			}
			return scope
		}, want: credential.ErrInvalidRevocationRequest},
		{name: "non UUID exact binding", scope: func(t *testing.T) execution.RunnerScope {
			registration := runnerCredentialRegistration(executionlease.PoolWrite)
			registration.ScopeBindings[0].WorkspaceID = "workspace-not-a-uuid"
			scope, err := registration.Scope()
			if err != nil {
				t.Fatal(err)
			}
			return scope
		}, want: credential.ErrInvalidRevocationRequest},
		{name: "production action", scope: func(t *testing.T) execution.RunnerScope {
			return runnerCredentialScope(t, executionlease.PoolWrite)
		}, rows: runnerActionMetadataRows(now, runnerCredentialFence(), true, postgresTestWorkspaceID, postgresTestEnvironment, 7),
			want: credential.ErrInvalidRevocationRequest, queryAction: true},
		{name: "exact pair denied", scope: func(t *testing.T) execution.RunnerScope {
			registration := runnerCredentialRegistration(executionlease.PoolWrite)
			registration.ScopeBindings = []execution.RunnerScopeBinding{{
				WorkspaceID: postgresTestWorkspaceID, EnvironmentID: "50000000-0000-4000-8000-000000000099",
			}}
			scope, err := registration.Scope()
			if err != nil {
				t.Fatal(err)
			}
			return scope
		}, rows: runnerActionMetadataRows(now, runnerCredentialFence(), false, postgresTestWorkspaceID, postgresTestEnvironment, 7),
			want: credential.ErrStaleActionFence, queryAction: true},
		{name: "stale scope revision", scope: func(t *testing.T) execution.RunnerScope {
			registration := runnerCredentialRegistration(executionlease.PoolWrite)
			registration.ScopeRevision = 8
			scope, err := registration.Scope()
			if err != nil {
				t.Fatal(err)
			}
			return scope
		}, rows: runnerActionMetadataRows(now, runnerCredentialFence(), false, postgresTestWorkspaceID, postgresTestEnvironment, 7),
			want: credential.ErrStaleActionFence, queryAction: true},
		{name: "old epoch", scope: func(t *testing.T) execution.RunnerScope {
			return runnerCredentialScope(t, executionlease.PoolWrite)
		}, rows: pgxmock.NewRows([]string{
			"action_id", "tenant_id", "workspace_id", "environment_id", "target_key", "production", "runner_id",
			"lease_epoch", "status", "lease_expires_at", "authorization_expires_at", "runner_pool", "scope_revision",
			"cancel_requested_at", "action_type", "connector_id", "permission", "resource", "credential_ttl_seconds", "database_now",
		}), want: credential.ErrStaleActionFence, queryAction: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			database, err := pgxmock.NewPool()
			if err != nil {
				t.Fatal(err)
			}
			defer database.Close()
			repository, err := New(database, repositoryTestProtector(t), Options{})
			if err != nil {
				t.Fatal(err)
			}
			database.ExpectBegin()
			tx, err := database.Begin(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			fence := runnerCredentialFence()
			if test.queryAction {
				database.ExpectQuery("SELECT action_id, runner_tenant_id::text.*FOR UPDATE").
					WithArgs(fence.ActionID, fence.RunnerID, fence.Epoch, credential.SHA256Hex([]byte(fence.Token))).
					WillReturnRows(test.rows)
			}
			result, callErr := repository.PrepareRunnerTx(context.Background(), tx, test.scope(t), credential.PrepareRequest{
				RevocationID: postgresTestRevocationID, Fence: fence, Issuer: "vault-production",
				IssuerRevision: "rev-1", CredentialExpiresAt: now.Add(time.Minute),
			})
			if !errors.Is(callErr, test.want) || result != (credential.PrepareResult{}) {
				t.Fatalf("PrepareRunnerTx() = %#v, %v, want %v", result, callErr, test.want)
			}
			database.ExpectRollback()
			if err := tx.Rollback(context.Background()); err != nil {
				t.Fatal(err)
			}
			if err := database.ExpectationsWereMet(); err != nil {
				t.Fatalf("unmet pgx expectations: %v", err)
			}
		})
	}
}

func TestAuthorizeChildCreateRunnerTxConsumesPermitAndDefersCommitLatencyDecision(t *testing.T) {
	t.Parallel()
	database, err := pgxmock.NewPool()
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	now := time.Date(2026, 7, 11, 8, 10, 0, 0, time.UTC)
	clock := now
	protector := repositoryTestProtector(t)
	repository, err := New(database, protector, Options{MonotonicNow: func() time.Time { return clock }})
	if err != nil {
		t.Fatal(err)
	}
	fence := runnerCredentialFence()
	permit := credential.ChildCreatePermit{RevocationID: postgresTestRevocationID, Token: "child-create-permit"}
	permitDigest := credential.SHA256Hex([]byte(permit.Token))
	database.ExpectBegin()
	tx, err := database.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	expectRunnerPrepareAction(database, now, fence)
	database.ExpectQuery("SELECT .* FROM credential_revocations.*FOR UPDATE").
		WithArgs(postgresTestRevocationID).
		WillReturnRows(storedRevocationRows(now, storedRowOptions{
			Status: credential.StatusPrepared, AvailableAt: now, Version: 1,
			CredentialExpiresAt: now.Add(time.Minute), ChildCreatePermitSHA256: permitDigest,
		}))
	database.ExpectQuery("SELECT clock_timestamp\\(\\)").
		WillReturnRows(pgxmock.NewRows([]string{"database_now"}).AddRow(now))
	database.ExpectQuery("UPDATE credential_revocations SET child_create_authorized_at").
		WithArgs(postgresTestRevocationID, now, int32(45), permitDigest).
		WillReturnRows(storedRevocationRows(now, storedRowOptions{
			Status: credential.StatusPrepared, AvailableAt: now, Version: 2,
			CredentialExpiresAt: now.Add(time.Minute), ChildCreatePermitSHA256: permitDigest,
			ChildCreateAuthorizedAt: now, ChildCreateTTLSeconds: 45,
		}))
	expectRunnerStateChange(database, fence.RunnerID, "credential.revocation.child_create_authorized",
		"credential.revocation.child_create_authorized.v1", 2)
	ticket, err := repository.AuthorizeChildCreateRunnerTx(context.Background(), tx,
		runnerCredentialScope(t, executionlease.PoolWrite), credential.AuthorizeChildCreateRequest{Permit: permit, Fence: fence})
	if err != nil || ticket == nil {
		t.Fatalf("AuthorizeChildCreateRunnerTx() = %#v, %v", ticket, err)
	}
	if _, err := json.Marshal(ticket); !errors.Is(err, credential.ErrInvalidRevocationRequest) {
		t.Fatalf("json.Marshal(ticket) error = %v", err)
	}
	if rendered := fmt.Sprintf("%#v", ticket); strings.Contains(rendered, postgresTestRevocationID) ||
		strings.Contains(rendered, "vault-production") {
		t.Fatalf("ticket formatting leaked authorization: %s", rendered)
	}

	// A replay sees the consumed timestamp and cannot authorize a second Vault
	// call, even before the caller commits the encompassing transaction.
	expectRunnerPrepareAction(database, now, fence)
	database.ExpectQuery("SELECT .* FROM credential_revocations.*FOR UPDATE").
		WithArgs(postgresTestRevocationID).
		WillReturnRows(storedRevocationRows(now, storedRowOptions{
			Status: credential.StatusPrepared, AvailableAt: now, Version: 2,
			CredentialExpiresAt: now.Add(time.Minute), ChildCreatePermitSHA256: permitDigest,
			ChildCreateAuthorizedAt: now, ChildCreateTTLSeconds: 45,
		}))
	second, err := repository.AuthorizeChildCreateRunnerTx(context.Background(), tx,
		runnerCredentialScope(t, executionlease.PoolWrite), credential.AuthorizeChildCreateRequest{Permit: permit, Fence: fence})
	if !errors.Is(err, credential.ErrChildCreateAlreadyAuthorized) || second != nil {
		t.Fatalf("AuthorizeChildCreateRunnerTx(replay) = %#v, %v", second, err)
	}

	// Only the caller commits. Before that point the opaque ticket exposes no
	// ChildCreateAuthorization. After commit, only the creating Repository and
	// its monotonic clock can release it.
	database.ExpectCommit()
	if err := tx.Commit(context.Background()); err != nil {
		t.Fatal(err)
	}
	otherRepository, err := New(database, protector, Options{MonotonicNow: func() time.Time { return clock }})
	if err != nil {
		t.Fatal(err)
	}
	if result, err := otherRepository.FinalizeChildCreateAuthorizationAfterCommit(ticket); !errors.Is(err, credential.ErrInvalidRevocationRequest) ||
		result != (credential.ChildCreateAuthorization{}) {
		t.Fatalf("cross-repository finalize = %#v, %v", result, err)
	}
	expiredTicket := &RunnerChildCreateAuthorizationTicket{
		owner: repository, authorization: ticket.authorization, commitWindowStarted: ticket.commitWindowStarted,
	}
	clock = now.Add(credential.MaxChildCreateDBCommitLatency + time.Nanosecond)
	if result, err := repository.FinalizeChildCreateAuthorizationAfterCommit(expiredTicket); !errors.Is(err, credential.ErrChildCreateWindowExpired) || result != (credential.ChildCreateAuthorization{}) {
		t.Fatalf("expired finalize = %#v, %v", result, err)
	}
	clock = now
	if _, err := repository.FinalizeChildCreateAuthorizationAfterCommit(expiredTicket); !errors.Is(err, credential.ErrInvalidRevocationRequest) {
		t.Fatalf("expired ticket reuse error = %v", err)
	}
	clock = now.Add(credential.MaxChildCreateDBCommitLatency)
	authorized, err := repository.FinalizeChildCreateAuthorizationAfterCommit(ticket)
	if err != nil || authorized.TTL != 45*time.Second || authorized.VaultCallBudget != credential.ChildCreateVaultCallBudget {
		t.Fatalf("FinalizeChildCreateAuthorizationAfterCommit() = %#v, %v", authorized, err)
	}
	if _, err := repository.FinalizeChildCreateAuthorizationAfterCommit(ticket); !errors.Is(err, credential.ErrInvalidRevocationRequest) {
		t.Fatalf("finalized ticket reuse error = %v", err)
	}
	if result, err := repository.FinalizeChildCreateAuthorizationAfterCommit(nil); !errors.Is(err, credential.ErrInvalidRevocationRequest) ||
		result != (credential.ChildCreateAuthorization{}) {
		t.Fatalf("nil ticket finalize = %#v, %v", result, err)
	}
	if err := database.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet pgx expectations: %v", err)
	}
}

func TestRunnerCredentialTxAnchorActivateAndRequestRevocationShareCallerTransaction(t *testing.T) {
	t.Parallel()
	database, err := pgxmock.NewPool()
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	protector := repositoryTestProtector(t)
	repository, err := New(database, protector, Options{})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 11, 8, 15, 0, 0, time.UTC)
	fence := runnerCredentialFence()
	scope := runnerCredentialScope(t, executionlease.PoolWrite)
	accessor, err := credential.NewSensitiveReference([]byte("runner-transaction-accessor"))
	if err != nil {
		t.Fatal(err)
	}
	defer accessor.Destroy()
	protected := protectTestReference(t, protector, []byte("runner-transaction-accessor"))

	database.ExpectBegin()
	tx, err := database.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	expectRunnerActionInspection(database, now, fence)
	database.ExpectQuery("SELECT .* FROM credential_revocations.*FOR UPDATE").
		WithArgs(postgresTestRevocationID).
		WillReturnRows(storedRevocationRows(now, storedRowOptions{
			Status: credential.StatusPrepared, AvailableAt: now, Version: 2,
			ChildCreateAuthorizedAt: now.Add(-time.Second), ChildCreateTTLSeconds: 585,
		}))
	database.ExpectQuery("UPDATE credential_revocations SET status = 'ANCHORED'").
		WithArgs(postgresTestRevocationID, pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).
		WillReturnRows(storedRevocationRows(now, storedRowOptions{
			Status: credential.StatusAnchored, Protected: protected, AvailableAt: now, Version: 3,
		}))
	expectRunnerStateChange(database, fence.RunnerID, "credential.revocation.anchored",
		"credential.revocation.anchored.v1", 3)
	database.ExpectQuery("SELECT statement_timestamp\\(\\)").
		WillReturnRows(pgxmock.NewRows([]string{"database_now"}).AddRow(now))
	anchored, err := repository.RecordAnchorRunnerTx(context.Background(), tx, scope, credential.RecordAnchorRequest{
		RevocationID: postgresTestRevocationID, Fence: fence, Accessor: accessor,
	})
	if err != nil || anchored.Status != credential.StatusAnchored || !anchored.AccessorPresent {
		t.Fatalf("RecordAnchorRunnerTx() = %#v, %v", anchored, err)
	}

	expectRunnerActionInspection(database, now, fence)
	database.ExpectQuery("SELECT .* FROM credential_revocations.*FOR UPDATE").
		WithArgs(postgresTestRevocationID).
		WillReturnRows(storedRevocationRows(now, storedRowOptions{
			Status: credential.StatusAnchored, Protected: protected, AvailableAt: now, Version: 3,
		}))
	database.ExpectQuery("UPDATE credential_revocations SET status = 'ACTIVE'").
		WithArgs(postgresTestRevocationID).
		WillReturnRows(storedRevocationRows(now, storedRowOptions{
			Status: credential.StatusActive, Protected: protected, AvailableAt: now, Version: 4,
		}))
	expectRunnerStateChange(database, fence.RunnerID, "credential.revocation.active",
		"credential.revocation.active.v1", 4)
	database.ExpectQuery("SELECT statement_timestamp\\(\\)").
		WillReturnRows(pgxmock.NewRows([]string{"database_now"}).AddRow(now))
	active, err := repository.ActivateRunnerTx(context.Background(), tx, scope, credential.ActionTransitionRequest{
		RevocationID: postgresTestRevocationID, Fence: fence,
	})
	if err != nil || active.Status != credential.StatusActive {
		t.Fatalf("ActivateRunnerTx() = %#v, %v", active, err)
	}

	expectRunnerPrepareAction(database, now, fence)
	database.ExpectQuery("SELECT .* FROM credential_revocations.*FOR UPDATE").
		WithArgs(postgresTestRevocationID).
		WillReturnRows(storedRevocationRows(now, storedRowOptions{
			Status: credential.StatusActive, Protected: protected, AvailableAt: now, Version: 4,
		}))
	database.ExpectQuery("UPDATE credential_revocations.*SET status = 'REVOCATION_PENDING'").
		WithArgs(postgresTestRevocationID).
		WillReturnRows(storedRevocationRows(now, storedRowOptions{
			Status: credential.StatusRevocationPending, Protected: protected, AvailableAt: now, Version: 5,
		}))
	expectRunnerStateChange(database, fence.RunnerID, "credential.revocation.requested",
		"credential.revocation.requested.v1", 5)
	pending, err := repository.RequestRevocationRunnerTx(context.Background(), tx, scope, credential.ActionTransitionRequest{
		RevocationID: postgresTestRevocationID, Fence: fence,
	})
	if err != nil || pending.Status != credential.StatusRevocationPending {
		t.Fatalf("RequestRevocationRunnerTx() = %#v, %v", pending, err)
	}

	database.ExpectRollback()
	if err := tx.Rollback(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := database.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet pgx expectations: %v", err)
	}
}

func TestRecordAnchorRunnerTxPersistsAndRevokesAfterScopeOrRegistrationLoss(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 11, 8, 16, 0, 0, time.UTC)
	for _, test := range []struct {
		name              string
		enabled           bool
		registrationScope int64
		actionScope       int64
		bindingCurrent    *bool
		scope             func(*testing.T) execution.RunnerScope
	}{
		{
			name: "scope revision bumped", enabled: true, registrationScope: 8, actionScope: 7,
			scope: func(t *testing.T) execution.RunnerScope {
				registration := runnerCredentialRegistration(executionlease.PoolWrite)
				registration.ScopeRevision = 8
				scope, err := registration.Scope()
				if err != nil {
					t.Fatal(err)
				}
				return scope
			},
		},
		{
			name: "runner disabled", enabled: false, registrationScope: 7, actionScope: 7,
			scope: func(t *testing.T) execution.RunnerScope {
				return runnerCredentialScope(t, executionlease.PoolWrite)
			},
		},
		{
			name: "exact pair removed", enabled: true, registrationScope: 7, actionScope: 7,
			bindingCurrent: boolPointer(false),
			scope: func(t *testing.T) execution.RunnerScope {
				registration := runnerCredentialRegistration(executionlease.PoolWrite)
				registration.ScopeBindings = []execution.RunnerScopeBinding{{
					WorkspaceID:   postgresTestWorkspaceID,
					EnvironmentID: "50000000-0000-4000-8000-000000000099",
				}}
				scope, err := registration.Scope()
				if err != nil {
					t.Fatal(err)
				}
				return scope
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			database, err := pgxmock.NewPool()
			if err != nil {
				t.Fatal(err)
			}
			defer database.Close()
			protector := repositoryTestProtector(t)
			repository, err := New(database, protector, Options{})
			if err != nil {
				t.Fatal(err)
			}
			fence := runnerCredentialFence()
			accessor, err := credential.NewSensitiveReference([]byte("late-runner-anchor"))
			if err != nil {
				t.Fatal(err)
			}
			defer accessor.Destroy()
			protected := protectTestReference(t, protector, []byte("late-runner-anchor"))
			database.ExpectBegin()
			tx, err := database.Begin(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			database.ExpectQuery("SELECT tenant_id::text, runner_pool, enabled, scope_revision.*FOR SHARE").
				WithArgs(fence.RunnerID).
				WillReturnRows(runnerRegistrationRows(test.enabled, "WRITE", test.registrationScope))
			database.ExpectQuery("SELECT action.action_id, workspace.tenant_id::text").
				WithArgs(fence.ActionID).
				WillReturnRows(actionInspectionRowsForState(now, fence, "RUNNING", time.Time{}, test.actionScope))
			if test.bindingCurrent != nil {
				database.ExpectQuery("SELECT EXISTS.*FROM runner_scope_bindings").
					WithArgs(fence.RunnerID, postgresTestTenantID, postgresTestWorkspaceID, postgresTestEnvironment).
					WillReturnRows(pgxmock.NewRows([]string{"exists"}).AddRow(*test.bindingCurrent))
			}
			database.ExpectQuery("SELECT .* FROM credential_revocations.*FOR UPDATE").
				WithArgs(postgresTestRevocationID).
				WillReturnRows(storedRevocationRows(now, storedRowOptions{
					Status: credential.StatusPrepared, AvailableAt: now, Version: 2,
					ChildCreateAuthorizedAt: now.Add(-time.Second), ChildCreateTTLSeconds: 585,
				}))
			database.ExpectQuery("UPDATE credential_revocations SET status = 'ANCHORED'").
				WithArgs(postgresTestRevocationID, pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).
				WillReturnRows(storedRevocationRows(now, storedRowOptions{
					Status: credential.StatusAnchored, Protected: protected, AvailableAt: now, Version: 3,
				}))
			expectRunnerStateChange(database, fence.RunnerID, "credential.revocation.anchored",
				"credential.revocation.anchored.v1", 3)
			database.ExpectQuery("UPDATE credential_revocations SET status = 'REVOCATION_PENDING'").
				WithArgs(postgresTestRevocationID).
				WillReturnRows(storedRevocationRows(now, storedRowOptions{
					Status: credential.StatusRevocationPending, Protected: protected, AvailableAt: now, Version: 4,
				}))
			expectRunnerStateChange(database, fence.RunnerID, "credential.revocation.requested",
				"credential.revocation.requested.v1", 4)
			anchored, err := repository.RecordAnchorRunnerTx(context.Background(), tx, test.scope(t), credential.RecordAnchorRequest{
				RevocationID: postgresTestRevocationID, Fence: fence, Accessor: accessor,
			})
			if err != nil || anchored.Status != credential.StatusRevocationPending || !anchored.AccessorPresent {
				t.Fatalf("RecordAnchorRunnerTx(stale authorization) = %#v, %v", anchored, err)
			}
			database.ExpectRollback()
			if err := tx.Rollback(context.Background()); err != nil {
				t.Fatal(err)
			}
			if err := database.ExpectationsWereMet(); err != nil {
				t.Fatalf("unmet pgx expectations: %v", err)
			}
		})
	}
}

func TestRecordNoCredentialRunnerTxIsIdempotentWithoutReleasingCallerTransaction(t *testing.T) {
	t.Parallel()
	database, err := pgxmock.NewPool()
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	repository, err := New(database, repositoryTestProtector(t), Options{})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 11, 8, 17, 0, 0, time.UTC)
	fence := runnerCredentialFence()
	scope := runnerCredentialScope(t, executionlease.PoolWrite)
	request := credential.ActionTransitionRequest{RevocationID: postgresTestRevocationID, Fence: fence}
	database.ExpectBegin()
	tx, err := database.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	expectRunnerPrepareAction(database, now, fence)
	database.ExpectQuery("SELECT .* FROM credential_revocations.*FOR UPDATE").
		WithArgs(postgresTestRevocationID).
		WillReturnRows(storedRevocationRows(now, storedRowOptions{
			Status: credential.StatusPrepared, AvailableAt: now, Version: 1,
		}))
	database.ExpectQuery("UPDATE credential_revocations.*SET status = 'NO_CREDENTIAL'").
		WithArgs(postgresTestRevocationID).
		WillReturnRows(storedRevocationRows(now, storedRowOptions{
			Status: credential.StatusNoCredential, AvailableAt: now, Version: 2,
		}))
	expectRunnerStateChange(database, fence.RunnerID, "credential.revocation.no_credential",
		"credential.revocation.no_credential.v1", 2)
	first, err := repository.RecordNoCredentialRunnerTx(context.Background(), tx, scope, request)
	if err != nil || first.Status != credential.StatusNoCredential {
		t.Fatalf("RecordNoCredentialRunnerTx() = %#v, %v", first, err)
	}

	expectRunnerPrepareAction(database, now, fence)
	database.ExpectQuery("SELECT .* FROM credential_revocations.*FOR UPDATE").
		WithArgs(postgresTestRevocationID).
		WillReturnRows(storedRevocationRows(now, storedRowOptions{
			Status: credential.StatusNoCredential, AvailableAt: now, Version: 2,
		}))
	replay, err := repository.RecordNoCredentialRunnerTx(context.Background(), tx, scope, request)
	if err != nil || replay.Status != credential.StatusNoCredential || replay.Version != 2 {
		t.Fatalf("RecordNoCredentialRunnerTx(replay) = %#v, %v", replay, err)
	}
	database.ExpectRollback()
	if err := tx.Rollback(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := database.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet pgx expectations: %v", err)
	}
}

func TestEnsureCompletionCleanupRunnerTxDerivesFenceAndKeepsTargetGateClosed(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 11, 8, 20, 0, 0, time.UTC)
	for _, test := range []struct {
		name         string
		status       credential.RevocationStatus
		authorized   bool
		wantStatus   credential.RevocationStatus
		wantTerminal bool
		transition   string
		auditAction  string
		eventType    string
	}{
		{name: "prepared no child", status: credential.StatusPrepared, wantStatus: credential.StatusNoCredential,
			wantTerminal: true, transition: "NO_CREDENTIAL", auditAction: "credential.revocation.no_credential",
			eventType: "credential.revocation.no_credential.v1"},
		{name: "prepared child ambiguous", status: credential.StatusPrepared, authorized: true, wantStatus: credential.StatusPrepared},
		{name: "anchored", status: credential.StatusAnchored, wantStatus: credential.StatusRevocationPending,
			transition: "REVOCATION_PENDING", auditAction: "credential.revocation.requested",
			eventType: "credential.revocation.requested.v1"},
		{name: "active", status: credential.StatusActive, wantStatus: credential.StatusRevocationPending,
			transition: "REVOCATION_PENDING", auditAction: "credential.revocation.requested",
			eventType: "credential.revocation.requested.v1"},
		{name: "pending", status: credential.StatusRevocationPending, wantStatus: credential.StatusRevocationPending},
		{name: "revoking", status: credential.StatusRevoking, wantStatus: credential.StatusRevoking},
		{name: "manual", status: credential.StatusManualRequired, wantStatus: credential.StatusManualRequired},
		{name: "no credential", status: credential.StatusNoCredential, wantStatus: credential.StatusNoCredential, wantTerminal: true},
		{name: "revoked", status: credential.StatusRevoked, wantStatus: credential.StatusRevoked, wantTerminal: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			database, err := pgxmock.NewPool()
			if err != nil {
				t.Fatal(err)
			}
			defer database.Close()
			repository, err := New(database, repositoryTestProtector(t), Options{})
			if err != nil {
				t.Fatal(err)
			}
			fence := executionlease.LeaseIdentity{
				ExecutionID: postgresTestActionID, RunnerID: "runner-write-1", Token: "action-token", Epoch: 4,
			}
			database.ExpectBegin()
			tx, err := database.Begin(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			expectRunnerFinalizingAction(database, fence, 4)
			options := storedRowOptions{Status: test.status, AvailableAt: now, Version: 3}
			if test.authorized {
				options.ChildCreateAuthorizedAt = now.Add(-time.Minute)
				options.ChildCreateTTLSeconds = 60
			}
			database.ExpectQuery("SELECT .* FROM credential_revocations.*WHERE action_id = \\$1 AND action_lease_epoch = \\$2.*FOR UPDATE").
				WithArgs(fence.ExecutionID, fence.Epoch).
				WillReturnRows(storedRevocationRows(now, options))
			if test.transition != "" {
				updated := options
				updated.Status = test.wantStatus
				updated.Version++
				database.ExpectQuery("UPDATE credential_revocations.*SET status = '" + test.transition + "'").
					WithArgs(postgresTestRevocationID).
					WillReturnRows(storedRevocationRows(now, updated))
				expectRunnerStateChange(database, fence.RunnerID, test.auditAction, test.eventType, updated.Version)
			}
			cleanup, err := repository.EnsureCompletionCleanupRunnerTx(context.Background(), tx,
				runnerCredentialScope(t, executionlease.PoolWrite), fence)
			if err != nil || cleanup.Revocation.Status != test.wantStatus || cleanup.Terminal != test.wantTerminal {
				t.Fatalf("EnsureCompletionCleanupRunnerTx() = %#v, %v, want status=%s terminal=%t",
					cleanup, err, test.wantStatus, test.wantTerminal)
			}
			database.ExpectRollback()
			if err := tx.Rollback(context.Background()); err != nil {
				t.Fatal(err)
			}
			if err := database.ExpectationsWereMet(); err != nil {
				t.Fatalf("unmet pgx expectations: %v", err)
			}
		})
	}
}

func TestEnsureCompletionCleanupRunnerTxRejectsOldCompletedEpochBeforeCredentialLookup(t *testing.T) {
	t.Parallel()
	database, err := pgxmock.NewPool()
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	repository, err := New(database, repositoryTestProtector(t), Options{})
	if err != nil {
		t.Fatal(err)
	}
	fence := executionlease.LeaseIdentity{
		ExecutionID: postgresTestActionID, RunnerID: "runner-write-1", Token: "action-token", Epoch: 4,
	}
	database.ExpectBegin()
	tx, err := database.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	expectRunnerFinalizingAction(database, fence, 5)
	cleanup, err := repository.EnsureCompletionCleanupRunnerTx(context.Background(), tx,
		runnerCredentialScope(t, executionlease.PoolWrite), fence)
	if !errors.Is(err, credential.ErrStaleActionFence) || cleanup != (RunnerCompletionCleanup{}) {
		t.Fatalf("EnsureCompletionCleanupRunnerTx(old epoch) = %#v, %v", cleanup, err)
	}
	database.ExpectRollback()
	if err := tx.Rollback(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := database.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet pgx expectations: %v", err)
	}
}

func runnerCredentialRegistration(pool executionlease.Pool) execution.RunnerRegistration {
	return execution.RunnerRegistration{
		RunnerID: "runner-write-1", TenantID: postgresTestTenantID, Pool: pool, Enabled: true,
		ScopeRevision: 7, MaxConcurrency: 1,
		ScopeBindings: []execution.RunnerScopeBinding{{
			WorkspaceID: postgresTestWorkspaceID, EnvironmentID: postgresTestEnvironment,
		}},
	}
}

func runnerCredentialScope(t *testing.T, pool executionlease.Pool) execution.RunnerScope {
	t.Helper()
	scope, err := runnerCredentialRegistration(pool).Scope()
	if err != nil {
		t.Fatalf("RunnerRegistration.Scope() error = %v", err)
	}
	return scope
}

func runnerCredentialFence() credential.ActionFence {
	return credential.ActionFence{
		ActionID: postgresTestActionID, RunnerID: "runner-write-1", Token: "action-token", Epoch: 4,
	}
}

func expectRunnerPrepareAction(database pgxmock.PgxPoolIface, now time.Time, fence credential.ActionFence) {
	database.ExpectQuery("SELECT action_id, runner_tenant_id::text.*FOR UPDATE").
		WithArgs(fence.ActionID, fence.RunnerID, fence.Epoch, credential.SHA256Hex([]byte(fence.Token))).
		WillReturnRows(actionMetadataRows(now, fence, now.Add(10*time.Minute)))
}

func expectRunnerActionInspection(database pgxmock.PgxPoolIface, now time.Time, fence credential.ActionFence) {
	database.ExpectQuery("SELECT tenant_id::text, runner_pool, enabled, scope_revision.*FOR SHARE").
		WithArgs(fence.RunnerID).
		WillReturnRows(runnerRegistrationRows(true, "WRITE", 7))
	database.ExpectQuery("SELECT action.action_id, workspace.tenant_id::text").
		WithArgs(fence.ActionID).
		WillReturnRows(actionInspectionRows(now, fence, true))
	database.ExpectQuery("SELECT EXISTS.*FROM runner_scope_bindings").
		WithArgs(fence.RunnerID, postgresTestTenantID, postgresTestWorkspaceID, postgresTestEnvironment).
		WillReturnRows(pgxmock.NewRows([]string{"exists"}).AddRow(true))
}

func runnerActionMetadataRows(
	now time.Time,
	fence credential.ActionFence,
	production bool,
	workspaceID, environmentID string,
	scopeRevision int64,
) *pgxmock.Rows {
	return pgxmock.NewRows([]string{
		"action_id", "tenant_id", "workspace_id", "environment_id", "target_key", "production", "runner_id",
		"lease_epoch", "status", "lease_expires_at", "authorization_expires_at", "runner_pool", "scope_revision",
		"cancel_requested_at", "action_type", "connector_id", "permission", "resource", "credential_ttl_seconds", "database_now",
	}).AddRow(
		fence.ActionID, postgresTestTenantID, workspaceID, environmentID, "cluster-a/payments", production,
		fence.RunnerID, fence.Epoch, "RUNNING", now.Add(time.Minute), now.Add(10*time.Minute), "WRITE", scopeRevision,
		nil, "KUBERNETES_ROLLOUT_RESTART", "kubernetes-prod", "PATCH_DEPLOYMENT_RESTART",
		"cluster-a/payments/deployment/api", int64(600), now,
	)
}

func expectRunnerStateChange(
	database pgxmock.PgxPoolIface,
	runnerID, auditAction, eventType string,
	version int64,
) {
	database.ExpectExec("INSERT INTO audit_records").
		WithArgs(pgxmock.AnyArg(), postgresTestTenantID, postgresTestWorkspaceID,
			"RUNNER", runnerID, auditAction, postgresTestRevocationID,
			pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))
	database.ExpectExec("INSERT INTO outbox_events").
		WithArgs(pgxmock.AnyArg(), postgresTestTenantID, postgresTestWorkspaceID,
			postgresTestRevocationID, version, eventType, pgxmock.AnyArg()).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))
}

func expectRunnerFinalizingAction(database pgxmock.PgxPoolIface, fence executionlease.LeaseIdentity, completedEpoch int64) {
	columns := []string{
		"action_id", "tenant_id", "workspace_id", "environment_id", "target_key", "production",
		"runner_id", "runner_pool", "lease_epoch", "scope_revision", "status", "completed_lease_epoch",
		"completed_lease_token_sha256", "credential_expected", "credential_lease_epoch",
	}
	database.ExpectQuery(strings.Join([]string{
		"SELECT action_id, runner_tenant_id::text, runner_workspace_id::text, runner_environment_id::text,",
		"target_key, production, runner_id, runner_pool, lease_epoch, scope_revision, status,",
		"completed_lease_epoch, completed_lease_token_sha256,",
		"credential_expected, credential_lease_epoch",
		"FROM action_queue",
		"WHERE action_id = \\$1",
		"FOR UPDATE",
	}, ".*")).WithArgs(fence.ExecutionID).WillReturnRows(pgxmock.NewRows(columns).AddRow(
		fence.ExecutionID, postgresTestTenantID, postgresTestWorkspaceID, postgresTestEnvironment,
		"cluster-a/payments", false, fence.RunnerID, "WRITE", completedEpoch, int64(7), "FINALIZING",
		completedEpoch, credential.SHA256Hex([]byte(fence.Token)), true, completedEpoch,
	))
}
