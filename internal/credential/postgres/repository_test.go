package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pashagolub/pgxmock/v4"
	"github.com/seaworld008/aiops-system/internal/credential"
)

const (
	postgresTestRevocationID = "10000000-0000-4000-8000-000000000020"
	postgresTestActionID     = "20000000-0000-4000-8000-000000000020"
	postgresTestTenantID     = "30000000-0000-4000-8000-000000000020"
	postgresTestWorkspaceID  = "40000000-0000-4000-8000-000000000020"
	postgresTestEnvironment  = "50000000-0000-4000-8000-000000000020"
)

func TestPrepareDerivesTrustedActionScopeAndPersistsOnlyFenceDigest(t *testing.T) {
	t.Parallel()

	database, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("pgxmock.NewPool() error = %v", err)
	}
	defer database.Close()
	protector := repositoryTestProtector(t)
	permitToken := "child-create-permit"
	repository, err := New(database, protector, Options{
		TokenSource:  func() (string, error) { return "claim-token", nil },
		PermitSource: func() (string, error) { return permitToken, nil },
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	now := time.Date(2026, 7, 10, 15, 0, 0, 0, time.UTC)
	actionToken := "plaintext-action-fence-token"
	tokenSum := sha256.Sum256([]byte(actionToken))
	tokenDigest := hex.EncodeToString(tokenSum[:])
	fence := credential.ActionFence{
		ActionID: postgresTestActionID, RunnerID: "runner-write-1", Token: actionToken, Epoch: 4,
	}
	request := credential.PrepareRequest{
		RevocationID: postgresTestRevocationID, Fence: fence,
		Issuer: "vault-production", IssuerRevision: "rev-1", CredentialExpiresAt: now.Add(5*time.Minute + 999*time.Nanosecond),
	}
	canonicalExpiry := credential.CanonicalCredentialExpiry(request.CredentialExpiresAt)

	database.ExpectBegin()
	database.ExpectQuery("SELECT action_id, runner_tenant_id::text.*FOR UPDATE").
		WithArgs(fence.ActionID, fence.RunnerID, fence.Epoch, tokenDigest).
		WillReturnRows(pgxmock.NewRows([]string{
			"action_id", "tenant_id", "workspace_id", "environment_id", "target_key", "production", "runner_id",
			"lease_epoch", "status", "lease_expires_at", "authorization_expires_at", "runner_pool", "scope_revision",
			"cancel_requested_at", "action_type", "connector_id", "permission", "resource", "credential_ttl_seconds", "database_now",
		}).AddRow(
			fence.ActionID,
			postgresTestTenantID,
			postgresTestWorkspaceID,
			postgresTestEnvironment,
			"cluster-a/payments", false, fence.RunnerID, fence.Epoch, "RUNNING", now.Add(time.Minute), now.Add(10*time.Minute),
			"WRITE", int64(7), nil, "KUBERNETES_ROLLOUT_RESTART", "kubernetes-prod", "PATCH_DEPLOYMENT_RESTART",
			"cluster-a/payments/deployment/api", int64(600), now,
		))
	database.ExpectQuery("SELECT .* FROM credential_revocations.*WHERE action_id = \\$1 AND action_lease_epoch = \\$2.*FOR SHARE").
		WithArgs(fence.ActionID, fence.Epoch).
		WillReturnRows(pgxmock.NewRows(storedRevocationColumns()))
	database.ExpectQuery("INSERT INTO credential_revocations").
		WithArgs(
			request.RevocationID,
			postgresTestTenantID,
			postgresTestWorkspaceID,
			postgresTestEnvironment,
			fence.ActionID, "cluster-a/payments", false, fence.RunnerID, fence.Epoch, tokenDigest,
			request.Issuer, request.IssuerRevision, "KUBERNETES_ROLLOUT_RESTART", "kubernetes-prod", "PATCH_DEPLOYMENT_RESTART",
			"cluster-a/payments/deployment/api", int32(600), canonicalExpiry, credential.SHA256Hex([]byte(permitToken)),
		).
		WillReturnRows(pgxmock.NewRows([]string{"status", "available_at", "created_at", "updated_at", "version"}).
			AddRow("PREPARED", now, now, now, int64(1)))
	expectActionCredentialMarker(database, fence, tokenDigest)
	database.ExpectExec("INSERT INTO audit_records").
		WithArgs(pgxmock.AnyArg(), postgresTestTenantID, postgresTestWorkspaceID,
			"RUNNER", fence.RunnerID, "credential.revocation.prepared", request.RevocationID,
			pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))
	database.ExpectExec("INSERT INTO outbox_events").
		WithArgs(pgxmock.AnyArg(), postgresTestTenantID, postgresTestWorkspaceID,
			request.RevocationID, int64(1), "credential.revocation.prepared.v1", pgxmock.AnyArg()).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))
	database.ExpectQuery("SELECT action_id, runner_tenant_id::text").
		WithArgs(fence.ActionID, fence.RunnerID, fence.Epoch, tokenDigest).
		WillReturnRows(actionMetadataRows(now, fence, now.Add(10*time.Minute)))
	database.ExpectCommit()

	prepared, err := repository.Prepare(context.Background(), request)
	if err != nil {
		t.Fatalf("Prepare() error = %v; expectations=%v", err, database.ExpectationsWereMet())
	}
	if !prepared.Created || prepared.Permit == nil || prepared.Permit.Token != permitToken ||
		prepared.Revocation.Status != credential.StatusPrepared ||
		prepared.Revocation.IssuerRevision != request.IssuerRevision ||
		prepared.Revocation.WorkspaceID != postgresTestWorkspaceID ||
		prepared.Revocation.EnvironmentID != postgresTestEnvironment || prepared.Revocation.TargetKey != "cluster-a/payments" ||
		prepared.Revocation.ActionType != "KUBERNETES_ROLLOUT_RESTART" || prepared.Revocation.CredentialTTLSeconds != 600 ||
		prepared.Revocation.ConnectorID != "kubernetes-prod" ||
		!prepared.Revocation.CredentialExpiresAt.Equal(canonicalExpiry) {
		t.Fatalf("prepared = %#v", prepared)
	}
	if err := database.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet pgx expectations: %v", err)
	}
}

func TestPrepareRejectsProductionActionMetadata(t *testing.T) {
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
	now := time.Date(2026, 7, 10, 15, 5, 0, 0, time.UTC)
	fence := credential.ActionFence{
		ActionID: postgresTestActionID, RunnerID: "runner-write-1", Token: "action-token", Epoch: 4,
	}
	database.ExpectBegin()
	database.ExpectQuery("SELECT action_id, runner_tenant_id::text").
		WithArgs(fence.ActionID, fence.RunnerID, fence.Epoch, credential.SHA256Hex([]byte(fence.Token))).
		WillReturnRows(pgxmock.NewRows([]string{
			"action_id", "tenant_id", "workspace_id", "environment_id", "target_key", "production", "runner_id",
			"lease_epoch", "status", "lease_expires_at", "authorization_expires_at", "runner_pool", "scope_revision",
			"cancel_requested_at", "action_type", "connector_id", "permission", "resource", "credential_ttl_seconds", "database_now",
		}).AddRow(
			fence.ActionID, postgresTestTenantID, postgresTestWorkspaceID, postgresTestEnvironment,
			"cluster-a/payments", true, fence.RunnerID, fence.Epoch, "RUNNING", now.Add(time.Minute), now.Add(10*time.Minute),
			"WRITE", int64(7), nil, "KUBERNETES_ROLLOUT_RESTART", "kubernetes-prod", "PATCH_DEPLOYMENT_RESTART",
			"cluster-a/payments/deployment/api", int64(600), now,
		))
	database.ExpectRollback()

	result, err := repository.Prepare(context.Background(), credential.PrepareRequest{
		RevocationID: postgresTestRevocationID, Fence: fence,
		Issuer: "vault-production", IssuerRevision: "rev-1", CredentialExpiresAt: now.Add(time.Minute),
	})
	if !errors.Is(err, credential.ErrInvalidRevocationRequest) || result != (credential.PrepareResult{}) {
		t.Fatalf("Prepare(production action) = %#v, %v, want ErrInvalidRevocationRequest", result, err)
	}
	if err := database.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet pgx expectations: %v", err)
	}
}

func TestPrepareRejectsExpiryBeyondSignedCredentialTTL(t *testing.T) {
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
	now := time.Date(2026, 7, 10, 15, 5, 30, 0, time.UTC)
	fence := credential.ActionFence{
		ActionID: postgresTestActionID, RunnerID: "runner-write-1", Token: "action-token", Epoch: 4,
	}
	database.ExpectBegin()
	database.ExpectQuery("SELECT action_id, runner_tenant_id::text").
		WithArgs(fence.ActionID, fence.RunnerID, fence.Epoch, credential.SHA256Hex([]byte(fence.Token))).
		WillReturnRows(actionMetadataRowsWithBinding(now, fence, now.Add(time.Minute), now.Add(10*time.Minute),
			"KUBERNETES_ROLLOUT_RESTART", 60))
	database.ExpectRollback()

	result, err := repository.Prepare(context.Background(), credential.PrepareRequest{
		RevocationID: postgresTestRevocationID, Fence: fence,
		Issuer: "vault-production", IssuerRevision: "rev-1", CredentialExpiresAt: now.Add(60*time.Second + time.Microsecond),
	})
	if !errors.Is(err, credential.ErrInvalidRevocationRequest) || result != (credential.PrepareResult{}) {
		t.Fatalf("Prepare(expiry beyond signed TTL) = %#v, %v", result, err)
	}
	if err := database.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet pgx expectations: %v", err)
	}
}

func TestPrepareRejectsMalformedTrustedActionCredentialBinding(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name       string
		actionType string
		ttlSeconds int32
	}{
		{name: "missing action type", actionType: "", ttlSeconds: 60},
		{name: "invalid action type", actionType: "KUBERNETES RESTART", ttlSeconds: 60},
		{name: "zero signed ttl", actionType: "KUBERNETES_ROLLOUT_RESTART", ttlSeconds: 0},
		{name: "oversized signed ttl", actionType: "KUBERNETES_ROLLOUT_RESTART", ttlSeconds: 901},
	} {
		t.Run(test.name, func(t *testing.T) {
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
			now := time.Date(2026, 7, 10, 15, 5, 45, 0, time.UTC)
			fence := credential.ActionFence{
				ActionID: postgresTestActionID, RunnerID: "runner-write-1", Token: "action-token", Epoch: 4,
			}
			database.ExpectBegin()
			database.ExpectQuery("SELECT action_id, runner_tenant_id::text").
				WithArgs(fence.ActionID, fence.RunnerID, fence.Epoch, credential.SHA256Hex([]byte(fence.Token))).
				WillReturnRows(actionMetadataRowsWithBinding(now, fence, now.Add(time.Minute), now.Add(10*time.Minute),
					test.actionType, test.ttlSeconds))
			database.ExpectRollback()

			_, err = repository.Prepare(context.Background(), credential.PrepareRequest{
				RevocationID: postgresTestRevocationID, Fence: fence,
				Issuer: "vault-production", IssuerRevision: "rev-1", CredentialExpiresAt: now.Add(30 * time.Second),
			})
			if !errors.Is(err, credential.ErrStaleActionFence) {
				t.Fatalf("Prepare(malformed trusted binding) error = %v", err)
			}
			if err := database.ExpectationsWereMet(); err != nil {
				t.Fatalf("unmet pgx expectations: %v", err)
			}
		})
	}
}

func TestPrepareRollsBackWhenActionCredentialMarkerCannotBeSet(t *testing.T) {
	t.Parallel()
	database, err := pgxmock.NewPool()
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	repository, err := New(database, repositoryTestProtector(t), Options{
		PermitSource: func() (string, error) { return "child-create-permit", nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 10, 15, 6, 0, 0, time.UTC)
	fence := credential.ActionFence{
		ActionID: postgresTestActionID, RunnerID: "runner-write-1", Token: "action-token", Epoch: 4,
	}
	tokenDigest := credential.SHA256Hex([]byte(fence.Token))
	request := credential.PrepareRequest{
		RevocationID: postgresTestRevocationID, Fence: fence,
		Issuer: "vault-non-production", IssuerRevision: "rev-1", CredentialExpiresAt: now.Add(time.Minute),
	}
	database.ExpectBegin()
	database.ExpectQuery("SELECT action_id, runner_tenant_id::text.*FOR UPDATE").
		WithArgs(fence.ActionID, fence.RunnerID, fence.Epoch, tokenDigest).
		WillReturnRows(actionMetadataRows(now, fence, now.Add(10*time.Minute)))
	database.ExpectQuery("SELECT .* FROM credential_revocations.*WHERE action_id = \\$1 AND action_lease_epoch = \\$2.*FOR SHARE").
		WithArgs(fence.ActionID, fence.Epoch).
		WillReturnRows(pgxmock.NewRows(storedRevocationColumns()))
	database.ExpectQuery("INSERT INTO credential_revocations").
		WithArgs(
			request.RevocationID, postgresTestTenantID, postgresTestWorkspaceID, postgresTestEnvironment,
			fence.ActionID, "cluster-a/payments", false, fence.RunnerID, fence.Epoch, tokenDigest,
			request.Issuer, request.IssuerRevision, "KUBERNETES_ROLLOUT_RESTART", "kubernetes-prod",
			"PATCH_DEPLOYMENT_RESTART", "cluster-a/payments/deployment/api", int32(600),
			request.CredentialExpiresAt, credential.SHA256Hex([]byte("child-create-permit")),
		).
		WillReturnRows(pgxmock.NewRows([]string{"status", "available_at", "created_at", "updated_at", "version"}).
			AddRow("PREPARED", now, now, now, int64(1)))
	expectActionCredentialMarkerRows(database, fence, tokenDigest, 0)
	database.ExpectRollback()

	result, err := repository.Prepare(context.Background(), request)
	if !errors.Is(err, credential.ErrStaleActionFence) || result != (credential.PrepareResult{}) {
		t.Fatalf("Prepare(marker miss) = %#v, %v, want ErrStaleActionFence", result, err)
	}
	if err := database.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet pgx expectations: %v", err)
	}
}

func TestPrepareReplayRollsBackWhenExistingActionMarkerCannotBeRepaired(t *testing.T) {
	t.Parallel()
	database, err := pgxmock.NewPool()
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	permitCalls := 0
	repository, err := New(database, repositoryTestProtector(t), Options{
		PermitSource: func() (string, error) {
			permitCalls++
			return "unused", nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 10, 15, 7, 0, 0, time.UTC)
	fence := credential.ActionFence{
		ActionID: postgresTestActionID, RunnerID: "runner-write-1", Token: "action-token", Epoch: 4,
	}
	tokenDigest := credential.SHA256Hex([]byte(fence.Token))
	request := credential.PrepareRequest{
		RevocationID: postgresTestRevocationID, Fence: fence,
		Issuer: "vault-production", IssuerRevision: "rev-1", CredentialExpiresAt: now.Add(time.Minute),
	}
	database.ExpectBegin()
	database.ExpectQuery("SELECT action_id, runner_tenant_id::text.*FOR UPDATE").
		WithArgs(fence.ActionID, fence.RunnerID, fence.Epoch, tokenDigest).
		WillReturnRows(actionMetadataRows(now, fence, now.Add(10*time.Minute)))
	database.ExpectQuery("SELECT .* FROM credential_revocations.*WHERE action_id = \\$1 AND action_lease_epoch = \\$2.*FOR SHARE").
		WithArgs(fence.ActionID, fence.Epoch).
		WillReturnRows(storedRevocationRows(now, storedRowOptions{
			Status: credential.StatusPrepared, AvailableAt: now, Version: 1,
			CredentialExpiresAt: request.CredentialExpiresAt,
		}))
	expectActionCredentialMarkerRows(database, fence, tokenDigest, 0)
	database.ExpectRollback()

	result, err := repository.Prepare(context.Background(), request)
	if !errors.Is(err, credential.ErrStaleActionFence) || result != (credential.PrepareResult{}) {
		t.Fatalf("Prepare(existing marker miss) = %#v, %v, want ErrStaleActionFence", result, err)
	}
	if permitCalls != 0 {
		t.Fatalf("Prepare(existing marker miss) PermitSource calls = %d, want 0", permitCalls)
	}
	if err := database.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet pgx expectations: %v", err)
	}
}

func TestAuthorizeChildCreateUsesDatabaseTimeAndConsumesPermitOnce(t *testing.T) {
	t.Parallel()
	database, err := pgxmock.NewPool()
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	now := time.Date(2026, 7, 10, 15, 10, 0, 0, time.UTC)
	repository, err := New(database, repositoryTestProtector(t), Options{
		PermitSource: func() (string, error) { return "unused", nil },
		MonotonicNow: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	fence := credential.ActionFence{
		ActionID: postgresTestActionID, RunnerID: "runner-write-1", Token: "action-token", Epoch: 4,
	}
	permit := credential.ChildCreatePermit{RevocationID: postgresTestRevocationID, Token: "child-create-permit"}
	permitDigest := credential.SHA256Hex([]byte(permit.Token))

	database.ExpectBegin()
	database.ExpectQuery("SELECT tenant_id::text, runner_pool, enabled, scope_revision.*FOR SHARE").
		WithArgs(fence.RunnerID).
		WillReturnRows(runnerRegistrationRows(true, "WRITE", 7))
	database.ExpectQuery("SELECT action_id, runner_tenant_id::text.*FOR SHARE").
		WithArgs(fence.ActionID, fence.RunnerID, fence.Epoch, credential.SHA256Hex([]byte(fence.Token))).
		WillReturnRows(actionMetadataRowsForState(now, fence, "RUNNING", time.Time{}, 7))
	database.ExpectQuery("SELECT EXISTS.*FROM runner_scope_bindings").
		WithArgs(fence.RunnerID, postgresTestTenantID, postgresTestWorkspaceID, postgresTestEnvironment).
		WillReturnRows(pgxmock.NewRows([]string{"exists"}).AddRow(true))
	database.ExpectQuery("SELECT .* FROM credential_revocations.*FOR UPDATE").
		WithArgs(postgresTestRevocationID).
		WillReturnRows(storedRevocationRows(now, storedRowOptions{
			Status: credential.StatusPrepared, AvailableAt: now, Version: 1, CredentialExpiresAt: now.Add(time.Minute),
			ChildCreatePermitSHA256: permitDigest,
		}))
	database.ExpectQuery("SELECT clock_timestamp\\(\\)").
		WillReturnRows(pgxmock.NewRows([]string{"database_now"}).AddRow(now))
	database.ExpectQuery("UPDATE credential_revocations SET child_create_authorized_at").
		WithArgs(postgresTestRevocationID, now, int32(45), permitDigest).
		WillReturnRows(storedRevocationRows(now, storedRowOptions{
			Status: credential.StatusPrepared, AvailableAt: now, Version: 2, CredentialExpiresAt: now.Add(time.Minute),
			ChildCreatePermitSHA256: permitDigest, ChildCreateAuthorizedAt: now, ChildCreateTTLSeconds: 45,
		}))
	database.ExpectExec("INSERT INTO audit_records").
		WithArgs(pgxmock.AnyArg(), postgresTestTenantID, postgresTestWorkspaceID,
			"RUNNER", fence.RunnerID, "credential.revocation.child_create_authorized", postgresTestRevocationID,
			pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))
	database.ExpectExec("INSERT INTO outbox_events").
		WithArgs(pgxmock.AnyArg(), postgresTestTenantID, postgresTestWorkspaceID,
			postgresTestRevocationID, int64(2), "credential.revocation.child_create_authorized.v1", pgxmock.AnyArg()).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))
	database.ExpectCommit()

	authorized, err := repository.AuthorizeChildCreate(context.Background(), credential.AuthorizeChildCreateRequest{
		Permit: permit, Fence: fence,
	})
	if err != nil || authorized.TTL != 45*time.Second || authorized.VaultCallBudget != 12*time.Second ||
		authorized.Revocation.Version != 2 || !authorized.DatabaseAuthorizedAt.Equal(now) ||
		authorized.DatabaseAuthorizedAt.Add(authorized.TTL+credential.ChildCreateExpiryReserve).After(authorized.CredentialExpiresAt) {
		t.Fatalf("AuthorizeChildCreate() = %#v, %v; expectations=%v", authorized, err, database.ExpectationsWereMet())
	}
	if err := database.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet pgx expectations: %v", err)
	}
}

func TestAuthorizeChildCreateRejectsCredentialExpiryBeyondActionAuthorization(t *testing.T) {
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
	now := time.Date(2026, 7, 10, 15, 10, 30, 0, time.UTC)
	fence := credential.ActionFence{
		ActionID: postgresTestActionID, RunnerID: "runner-write-1", Token: "action-token", Epoch: 4,
	}
	permit := credential.ChildCreatePermit{RevocationID: postgresTestRevocationID, Token: "child-create-permit"}

	database.ExpectBegin()
	database.ExpectQuery("SELECT tenant_id::text, runner_pool, enabled, scope_revision.*FOR SHARE").
		WithArgs(fence.RunnerID).
		WillReturnRows(runnerRegistrationRows(true, "WRITE", 7))
	database.ExpectQuery("SELECT action_id, runner_tenant_id::text.*FOR SHARE").
		WithArgs(fence.ActionID, fence.RunnerID, fence.Epoch, credential.SHA256Hex([]byte(fence.Token))).
		WillReturnRows(actionMetadataRowsWithLease(now, fence, now.Add(time.Minute), now.Add(30*time.Second)))
	database.ExpectQuery("SELECT EXISTS.*FROM runner_scope_bindings").
		WithArgs(fence.RunnerID, postgresTestTenantID, postgresTestWorkspaceID, postgresTestEnvironment).
		WillReturnRows(pgxmock.NewRows([]string{"exists"}).AddRow(true))
	database.ExpectQuery("SELECT .* FROM credential_revocations.*FOR UPDATE").
		WithArgs(postgresTestRevocationID).
		WillReturnRows(storedRevocationRows(now, storedRowOptions{
			Status: credential.StatusPrepared, AvailableAt: now, Version: 1,
			CredentialExpiresAt:     now.Add(time.Minute),
			ChildCreatePermitSHA256: credential.SHA256Hex([]byte(permit.Token)),
		}))
	database.ExpectRollback()

	authorized, err := repository.AuthorizeChildCreate(context.Background(), credential.AuthorizeChildCreateRequest{
		Permit: permit, Fence: fence,
	})
	if !errors.Is(err, credential.ErrStaleActionFence) || authorized != (credential.ChildCreateAuthorization{}) {
		t.Fatalf("AuthorizeChildCreate(expiry beyond action authorization) = %#v, %v", authorized, err)
	}
	if err := database.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet pgx expectations: %v", err)
	}
}

func TestAuthorizeChildCreateRejectsLeasedActionBeforeConsumingPermit(t *testing.T) {
	t.Parallel()
	database, err := pgxmock.NewPool()
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	now := time.Date(2026, 7, 10, 15, 11, 0, 0, time.UTC)
	repository, err := New(database, repositoryTestProtector(t), Options{})
	if err != nil {
		t.Fatal(err)
	}
	fence := credential.ActionFence{
		ActionID: postgresTestActionID, RunnerID: "runner-write-1", Token: "action-token", Epoch: 4,
	}
	permit := credential.ChildCreatePermit{RevocationID: postgresTestRevocationID, Token: "child-create-permit"}
	database.ExpectBegin()
	database.ExpectQuery("SELECT tenant_id::text, runner_pool, enabled, scope_revision.*FOR SHARE").
		WithArgs(fence.RunnerID).
		WillReturnRows(runnerRegistrationRows(true, "WRITE", 7))
	database.ExpectQuery("SELECT action_id, runner_tenant_id::text.*FOR SHARE").
		WithArgs(fence.ActionID, fence.RunnerID, fence.Epoch, credential.SHA256Hex([]byte(fence.Token))).
		WillReturnRows(actionMetadataRowsForState(now, fence, "LEASED", time.Time{}, 7))
	database.ExpectRollback()

	_, err = repository.AuthorizeChildCreate(context.Background(), credential.AuthorizeChildCreateRequest{
		Permit: permit, Fence: fence,
	})
	if !errors.Is(err, credential.ErrStaleActionFence) {
		t.Fatalf("AuthorizeChildCreate(LEASED) error = %v, want ErrStaleActionFence", err)
	}
	if err := database.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet pgx expectations: %v", err)
	}
}

func TestAuthorizeChildCreateRequiresCurrentWriteRunnerAndExactScopeBinding(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 10, 15, 11, 30, 0, time.UTC)
	for _, test := range []struct {
		name              string
		enabled           bool
		pool              string
		registrationScope int64
		actionScope       int64
		cancelRequestedAt time.Time
		bindingResult     *bool
	}{
		{name: "cancel requested", enabled: true, pool: "WRITE", registrationScope: 7, actionScope: 7, cancelRequestedAt: now},
		{name: "runner disabled", enabled: false, pool: "WRITE", registrationScope: 7, actionScope: 7},
		{name: "read runner", enabled: true, pool: "READ", registrationScope: 7, actionScope: 7},
		{name: "scope revision changed", enabled: true, pool: "WRITE", registrationScope: 8, actionScope: 7},
		{name: "exact binding removed", enabled: true, pool: "WRITE", registrationScope: 7, actionScope: 7, bindingResult: boolPointer(false)},
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
			fence := credential.ActionFence{
				ActionID: postgresTestActionID, RunnerID: "runner-write-1", Token: "action-token", Epoch: 4,
			}
			database.ExpectBegin()
			database.ExpectQuery("SELECT tenant_id::text, runner_pool, enabled, scope_revision.*FOR SHARE").
				WithArgs(fence.RunnerID).
				WillReturnRows(runnerRegistrationRows(test.enabled, test.pool, test.registrationScope))
			database.ExpectQuery("SELECT action_id, runner_tenant_id::text.*FOR SHARE").
				WithArgs(fence.ActionID, fence.RunnerID, fence.Epoch, credential.SHA256Hex([]byte(fence.Token))).
				WillReturnRows(actionMetadataRowsForState(now, fence, "RUNNING", test.cancelRequestedAt, test.actionScope))
			if test.bindingResult != nil {
				database.ExpectQuery("SELECT EXISTS.*FROM runner_scope_bindings").
					WithArgs(fence.RunnerID, postgresTestTenantID, postgresTestWorkspaceID, postgresTestEnvironment).
					WillReturnRows(pgxmock.NewRows([]string{"exists"}).AddRow(*test.bindingResult))
			}
			database.ExpectRollback()

			_, err = repository.AuthorizeChildCreate(context.Background(), credential.AuthorizeChildCreateRequest{
				Permit: credential.ChildCreatePermit{RevocationID: postgresTestRevocationID, Token: "child-create-permit"},
				Fence:  fence,
			})
			if !errors.Is(err, credential.ErrStaleActionFence) {
				t.Fatalf("AuthorizeChildCreate(%s) error = %v, want ErrStaleActionFence", test.name, err)
			}
			if err := database.ExpectationsWereMet(); err != nil {
				t.Fatalf("unmet pgx expectations: %v", err)
			}
		})
	}
}

func TestAuthorizeChildCreateNeverReturnsAuthorizationAfterSlowCommit(t *testing.T) {
	t.Parallel()
	database, err := pgxmock.NewPool()
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	now := time.Date(2026, 7, 10, 15, 12, 0, 0, time.UTC)
	monotonic := []time.Time{now, now.Add(credential.MaxChildCreateDBCommitLatency + time.Microsecond)}
	monotonicIndex := 0
	repository, err := New(database, repositoryTestProtector(t), Options{MonotonicNow: func() time.Time {
		value := monotonic[monotonicIndex]
		monotonicIndex++
		return value
	}})
	if err != nil {
		t.Fatal(err)
	}
	fence := credential.ActionFence{ActionID: postgresTestActionID, RunnerID: "runner-write-1", Token: "action-token", Epoch: 4}
	permit := credential.ChildCreatePermit{RevocationID: postgresTestRevocationID, Token: "child-create-permit"}
	permitDigest := credential.SHA256Hex([]byte(permit.Token))
	database.ExpectBegin()
	database.ExpectQuery("SELECT tenant_id::text, runner_pool, enabled, scope_revision.*FOR SHARE").
		WithArgs(fence.RunnerID).
		WillReturnRows(runnerRegistrationRows(true, "WRITE", 7))
	database.ExpectQuery("SELECT action_id, runner_tenant_id::text.*FOR SHARE").
		WithArgs(fence.ActionID, fence.RunnerID, fence.Epoch, credential.SHA256Hex([]byte(fence.Token))).
		WillReturnRows(actionMetadataRows(now, fence, now.Add(10*time.Minute)))
	database.ExpectQuery("SELECT EXISTS.*FROM runner_scope_bindings").
		WithArgs(fence.RunnerID, postgresTestTenantID, postgresTestWorkspaceID, postgresTestEnvironment).
		WillReturnRows(pgxmock.NewRows([]string{"exists"}).AddRow(true))
	database.ExpectQuery("SELECT .* FROM credential_revocations.*FOR UPDATE").
		WithArgs(postgresTestRevocationID).
		WillReturnRows(storedRevocationRows(now, storedRowOptions{
			Status: credential.StatusPrepared, AvailableAt: now, Version: 1, CredentialExpiresAt: now.Add(time.Minute),
			ChildCreatePermitSHA256: permitDigest,
		}))
	database.ExpectQuery("SELECT clock_timestamp\\(\\)").
		WillReturnRows(pgxmock.NewRows([]string{"database_now"}).AddRow(now))
	database.ExpectQuery("UPDATE credential_revocations SET child_create_authorized_at").
		WithArgs(postgresTestRevocationID, now, int32(45), permitDigest).
		WillReturnRows(storedRevocationRows(now, storedRowOptions{
			Status: credential.StatusPrepared, AvailableAt: now, Version: 2, CredentialExpiresAt: now.Add(time.Minute),
			ChildCreatePermitSHA256: permitDigest, ChildCreateAuthorizedAt: now, ChildCreateTTLSeconds: 45,
		}))
	database.ExpectExec("INSERT INTO audit_records").
		WithArgs(pgxmock.AnyArg(), postgresTestTenantID, postgresTestWorkspaceID,
			"RUNNER", fence.RunnerID, "credential.revocation.child_create_authorized", postgresTestRevocationID,
			pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))
	database.ExpectExec("INSERT INTO outbox_events").
		WithArgs(pgxmock.AnyArg(), postgresTestTenantID, postgresTestWorkspaceID,
			postgresTestRevocationID, int64(2), "credential.revocation.child_create_authorized.v1", pgxmock.AnyArg()).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))
	database.ExpectCommit()

	authorized, err := repository.AuthorizeChildCreate(context.Background(), credential.AuthorizeChildCreateRequest{
		Permit: permit, Fence: fence,
	})
	if !errors.Is(err, credential.ErrChildCreateWindowExpired) || authorized != (credential.ChildCreateAuthorization{}) {
		t.Fatalf("AuthorizeChildCreate(slow commit) = %#v, %v", authorized, err)
	}
	if err := database.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet pgx expectations: %v", err)
	}
}

func TestAuthorizeChildCreateChecksPermitBeforeAlreadyAuthorizedState(t *testing.T) {
	t.Parallel()
	database, err := pgxmock.NewPool()
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	now := time.Date(2026, 7, 10, 15, 13, 0, 0, time.UTC)
	repository, err := New(database, repositoryTestProtector(t), Options{})
	if err != nil {
		t.Fatal(err)
	}
	fence := credential.ActionFence{ActionID: postgresTestActionID, RunnerID: "runner-write-1", Token: "action-token", Epoch: 4}
	database.ExpectBegin()
	database.ExpectQuery("SELECT tenant_id::text, runner_pool, enabled, scope_revision.*FOR SHARE").
		WithArgs(fence.RunnerID).
		WillReturnRows(runnerRegistrationRows(true, "WRITE", 7))
	database.ExpectQuery("SELECT action_id, runner_tenant_id::text.*FOR SHARE").
		WithArgs(fence.ActionID, fence.RunnerID, fence.Epoch, credential.SHA256Hex([]byte(fence.Token))).
		WillReturnRows(actionMetadataRows(now, fence, now.Add(10*time.Minute)))
	database.ExpectQuery("SELECT EXISTS.*FROM runner_scope_bindings").
		WithArgs(fence.RunnerID, postgresTestTenantID, postgresTestWorkspaceID, postgresTestEnvironment).
		WillReturnRows(pgxmock.NewRows([]string{"exists"}).AddRow(true))
	database.ExpectQuery("SELECT .* FROM credential_revocations.*FOR UPDATE").
		WithArgs(postgresTestRevocationID).
		WillReturnRows(storedRevocationRows(now, storedRowOptions{
			Status: credential.StatusPrepared, AvailableAt: now, Version: 2,
			ChildCreatePermitSHA256: credential.SHA256Hex([]byte("correct-permit")),
			ChildCreateAuthorizedAt: now.Add(-time.Second), ChildCreateTTLSeconds: 585,
		}))
	database.ExpectRollback()

	_, err = repository.AuthorizeChildCreate(context.Background(), credential.AuthorizeChildCreateRequest{
		Permit: credential.ChildCreatePermit{RevocationID: postgresTestRevocationID, Token: "wrong-permit"}, Fence: fence,
	})
	if !errors.Is(err, credential.ErrStaleChildCreatePermit) {
		t.Fatalf("AuthorizeChildCreate(wrong permit after authorization) error = %v", err)
	}
	if err := database.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet pgx expectations: %v", err)
	}
}

func TestAuthorizeChildCreateEnforcesActionFenceReserveBoundary(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 10, 15, 14, 0, 0, time.UTC)
	for _, test := range []struct {
		name    string
		window  time.Duration
		wantErr error
	}{
		{name: "exact boundary", window: credential.ChildCreateExpiryReserve + credential.MinPostChildFenceWindow},
		{name: "one microsecond short", window: credential.ChildCreateExpiryReserve + credential.MinPostChildFenceWindow - time.Microsecond, wantErr: credential.ErrStaleActionFence},
	} {
		t.Run(test.name, func(t *testing.T) {
			database, err := pgxmock.NewPool()
			if err != nil {
				t.Fatal(err)
			}
			defer database.Close()
			repository, err := New(database, repositoryTestProtector(t), Options{MonotonicNow: func() time.Time { return now }})
			if err != nil {
				t.Fatal(err)
			}
			fence := credential.ActionFence{ActionID: postgresTestActionID, RunnerID: "runner-write-1", Token: "action-token", Epoch: 4}
			permit := credential.ChildCreatePermit{RevocationID: postgresTestRevocationID, Token: "boundary-permit"}
			permitDigest := credential.SHA256Hex([]byte(permit.Token))
			database.ExpectBegin()
			database.ExpectQuery("SELECT tenant_id::text, runner_pool, enabled, scope_revision.*FOR SHARE").
				WithArgs(fence.RunnerID).
				WillReturnRows(runnerRegistrationRows(true, "WRITE", 7))
			database.ExpectQuery("SELECT action_id, runner_tenant_id::text.*FOR SHARE").
				WithArgs(fence.ActionID, fence.RunnerID, fence.Epoch, credential.SHA256Hex([]byte(fence.Token))).
				WillReturnRows(actionMetadataRowsWithLease(now, fence, now.Add(test.window), now.Add(test.window)))
			database.ExpectQuery("SELECT EXISTS.*FROM runner_scope_bindings").
				WithArgs(fence.RunnerID, postgresTestTenantID, postgresTestWorkspaceID, postgresTestEnvironment).
				WillReturnRows(pgxmock.NewRows([]string{"exists"}).AddRow(true))
			database.ExpectQuery("SELECT .* FROM credential_revocations.*FOR UPDATE").
				WithArgs(postgresTestRevocationID).
				WillReturnRows(storedRevocationRows(now, storedRowOptions{
					Status: credential.StatusPrepared, AvailableAt: now, Version: 1, CredentialExpiresAt: now.Add(test.window),
					ChildCreatePermitSHA256: permitDigest,
				}))
			database.ExpectQuery("SELECT clock_timestamp\\(\\)").
				WillReturnRows(pgxmock.NewRows([]string{"database_now"}).AddRow(now))
			if test.wantErr == nil {
				database.ExpectQuery("UPDATE credential_revocations SET child_create_authorized_at").
					WithArgs(postgresTestRevocationID, now, int32(1), permitDigest).
					WillReturnRows(storedRevocationRows(now, storedRowOptions{
						Status: credential.StatusPrepared, AvailableAt: now, Version: 2, CredentialExpiresAt: now.Add(test.window),
						ChildCreatePermitSHA256: permitDigest, ChildCreateAuthorizedAt: now, ChildCreateTTLSeconds: 1,
					}))
				database.ExpectExec("INSERT INTO audit_records").
					WithArgs(pgxmock.AnyArg(), postgresTestTenantID, postgresTestWorkspaceID,
						"RUNNER", fence.RunnerID, "credential.revocation.child_create_authorized", postgresTestRevocationID,
						pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).
					WillReturnResult(pgxmock.NewResult("INSERT", 1))
				database.ExpectExec("INSERT INTO outbox_events").
					WithArgs(pgxmock.AnyArg(), postgresTestTenantID, postgresTestWorkspaceID,
						postgresTestRevocationID, int64(2), "credential.revocation.child_create_authorized.v1", pgxmock.AnyArg()).
					WillReturnResult(pgxmock.NewResult("INSERT", 1))
				database.ExpectCommit()
			} else {
				database.ExpectRollback()
			}

			authorized, err := repository.AuthorizeChildCreate(context.Background(), credential.AuthorizeChildCreateRequest{
				Permit: permit, Fence: fence,
			})
			if !errors.Is(err, test.wantErr) || (test.wantErr == nil && authorized.TTL != credential.MinPostChildFenceWindow) {
				t.Fatalf("AuthorizeChildCreate(action boundary) = %#v, %v, want %v", authorized, err, test.wantErr)
			}
			if err := database.ExpectationsWereMet(); err != nil {
				t.Fatalf("unmet pgx expectations: %v", err)
			}
		})
	}
}

func TestPrepareCommitResponseLossNeverAuthorizesChildCreationAndRetryIsNotCreated(t *testing.T) {
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

	now := time.Date(2026, 7, 10, 15, 15, 0, 0, time.UTC)
	fence := credential.ActionFence{
		ActionID: postgresTestActionID, RunnerID: "runner-write-1", Token: "action-token", Epoch: 4,
	}
	request := credential.PrepareRequest{
		RevocationID: postgresTestRevocationID, Fence: fence, Issuer: "vault-production", IssuerRevision: "rev-1",
		CredentialExpiresAt: now.Add(10 * time.Minute),
	}
	tokenDigest := credential.SHA256Hex([]byte(fence.Token))
	expectResolve := func() {
		database.ExpectQuery("SELECT action_id, runner_tenant_id::text").
			WithArgs(fence.ActionID, fence.RunnerID, fence.Epoch, tokenDigest).
			WillReturnRows(actionMetadataRows(now, fence, now.Add(15*time.Minute)))
	}
	expectInsert := func(rows *pgxmock.Rows) {
		database.ExpectQuery("INSERT INTO credential_revocations").
			WithArgs(
				request.RevocationID, postgresTestTenantID, postgresTestWorkspaceID, postgresTestEnvironment,
				fence.ActionID, "cluster-a/payments", false, fence.RunnerID, fence.Epoch, tokenDigest,
				request.Issuer, request.IssuerRevision, "KUBERNETES_ROLLOUT_RESTART", "kubernetes-prod",
				"PATCH_DEPLOYMENT_RESTART", "cluster-a/payments/deployment/api", int32(600),
				request.CredentialExpiresAt, pgxmock.AnyArg(),
			).
			WillReturnRows(rows)
	}
	expectExisting := func(rows *pgxmock.Rows) {
		database.ExpectQuery("SELECT .* FROM credential_revocations.*WHERE action_id = \\$1 AND action_lease_epoch = \\$2.*FOR SHARE").
			WithArgs(fence.ActionID, fence.Epoch).
			WillReturnRows(rows)
	}

	database.ExpectBegin()
	expectResolve()
	expectExisting(pgxmock.NewRows(storedRevocationColumns()))
	expectInsert(pgxmock.NewRows([]string{"status", "available_at", "created_at", "updated_at", "version"}).
		AddRow("PREPARED", now, now, now, int64(1)))
	expectActionCredentialMarker(database, fence, tokenDigest)
	database.ExpectExec("INSERT INTO audit_records").
		WithArgs(pgxmock.AnyArg(), postgresTestTenantID, postgresTestWorkspaceID,
			"RUNNER", fence.RunnerID, "credential.revocation.prepared", request.RevocationID,
			pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))
	database.ExpectExec("INSERT INTO outbox_events").
		WithArgs(pgxmock.AnyArg(), postgresTestTenantID, postgresTestWorkspaceID,
			request.RevocationID, int64(1), "credential.revocation.prepared.v1", pgxmock.AnyArg()).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))
	expectResolve()
	database.ExpectCommit().WillReturnError(errors.New("commit response lost"))
	database.ExpectRollback()

	first, firstErr := repository.Prepare(context.Background(), request)
	if firstErr == nil || first.Created || first.Permit != nil {
		t.Fatalf("Prepare(ambiguous commit) = %#v, %v", first, firstErr)
	}

	database.ExpectBegin()
	expectResolve()
	expectExisting(storedRevocationRows(now, storedRowOptions{
		Status: credential.StatusPrepared, AvailableAt: now, Version: 2,
		ChildCreateAuthorizedAt: now.Add(-30 * time.Second), ChildCreateTTLSeconds: 600,
	}))
	expectActionCredentialMarker(database, fence, tokenDigest)
	expectResolve()
	database.ExpectCommit()

	retry, retryErr := repository.Prepare(context.Background(), request)
	if retryErr != nil || retry.Created || retry.Revocation.ID != request.RevocationID {
		t.Fatalf("Prepare(retry after ambiguous commit) = %#v, %v", retry, retryErr)
	}
	if err := database.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet pgx expectations: %v", err)
	}
}

func TestPrepareReplayDoesNotDependOnPermitSourceAvailability(t *testing.T) {
	t.Parallel()
	database, err := pgxmock.NewPool()
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	permitCalls := 0
	repository, err := New(database, repositoryTestProtector(t), Options{PermitSource: func() (string, error) {
		permitCalls++
		return "", errors.New("random source unavailable")
	}})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 10, 15, 17, 0, 0, time.UTC)
	fence := credential.ActionFence{
		ActionID: postgresTestActionID, RunnerID: "runner-write-1", Token: "action-token", Epoch: 4,
	}
	request := credential.PrepareRequest{
		RevocationID: postgresTestRevocationID, Fence: fence, Issuer: "vault-production", IssuerRevision: "rev-1",
		CredentialExpiresAt: now.Add(10 * time.Minute),
	}
	tokenDigest := credential.SHA256Hex([]byte(fence.Token))
	database.ExpectBegin()
	database.ExpectQuery("SELECT action_id, runner_tenant_id::text").
		WithArgs(fence.ActionID, fence.RunnerID, fence.Epoch, tokenDigest).
		WillReturnRows(actionMetadataRows(now, fence, now.Add(15*time.Minute)))
	database.ExpectQuery("SELECT .* FROM credential_revocations.*WHERE action_id = \\$1 AND action_lease_epoch = \\$2.*FOR SHARE").
		WithArgs(fence.ActionID, fence.Epoch).
		WillReturnRows(storedRevocationRows(now, storedRowOptions{
			Status: credential.StatusPrepared, AvailableAt: now, Version: 1,
			CredentialExpiresAt: request.CredentialExpiresAt,
		}))
	expectActionCredentialMarker(database, fence, tokenDigest)
	database.ExpectQuery("SELECT action_id, runner_tenant_id::text").
		WithArgs(fence.ActionID, fence.RunnerID, fence.Epoch, tokenDigest).
		WillReturnRows(actionMetadataRows(now, fence, now.Add(15*time.Minute)))
	database.ExpectCommit()

	replayed, err := repository.Prepare(context.Background(), request)
	if err != nil || replayed.Created || replayed.Permit != nil || replayed.Revocation.ID != postgresTestRevocationID {
		t.Fatalf("Prepare(replay with failed permit source) = %#v, %v", replayed, err)
	}
	if permitCalls != 0 {
		t.Fatalf("Prepare(replay) PermitSource calls = %d, want 0", permitCalls)
	}
	if err := database.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet pgx expectations: %v", err)
	}
}

func TestPrepareReplayReturnsCanonicalIDUnlessCandidateIsAlreadyOccupied(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name              string
		candidateID       string
		candidateOccupied bool
	}{
		{name: "new candidate reuses canonical", candidateID: "10000000-0000-4000-8000-000000000021"},
		{name: "occupied candidate conflicts", candidateID: "10000000-0000-4000-8000-000000000022", candidateOccupied: true},
	} {
		test := test
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
			now := time.Date(2026, 7, 10, 15, 20, 0, 0, time.UTC)
			fence := credential.ActionFence{
				ActionID: postgresTestActionID, RunnerID: "runner-write-1", Token: "action-token", Epoch: 4,
			}
			request := credential.PrepareRequest{
				RevocationID: test.candidateID, Fence: fence, Issuer: "vault-production", IssuerRevision: "rev-1",
				CredentialExpiresAt: now.Add(10 * time.Minute),
			}
			database.ExpectBegin()
			database.ExpectQuery("SELECT action_id, runner_tenant_id::text").
				WithArgs(fence.ActionID, fence.RunnerID, fence.Epoch, credential.SHA256Hex([]byte(fence.Token))).
				WillReturnRows(actionMetadataRows(now, fence, now.Add(15*time.Minute)))
			database.ExpectQuery("SELECT .* FROM credential_revocations.*WHERE action_id = \\$1 AND action_lease_epoch = \\$2.*FOR SHARE").
				WithArgs(fence.ActionID, fence.Epoch).
				WillReturnRows(storedRevocationRows(now, storedRowOptions{
					Status: credential.StatusPrepared, AvailableAt: now, Version: 1,
				}))
			database.ExpectQuery("SELECT EXISTS").
				WithArgs(request.RevocationID).
				WillReturnRows(pgxmock.NewRows([]string{"exists"}).AddRow(test.candidateOccupied))
			if test.candidateOccupied {
				database.ExpectRollback()
			} else {
				expectActionCredentialMarker(database, fence, credential.SHA256Hex([]byte(fence.Token)))
				database.ExpectQuery("SELECT action_id, runner_tenant_id::text").
					WithArgs(fence.ActionID, fence.RunnerID, fence.Epoch, credential.SHA256Hex([]byte(fence.Token))).
					WillReturnRows(actionMetadataRows(now, fence, now.Add(15*time.Minute)))
				database.ExpectCommit()
			}

			result, prepareErr := repository.Prepare(context.Background(), request)
			if test.candidateOccupied {
				if !errors.Is(prepareErr, credential.ErrIdempotencyConflict) || result.Created {
					t.Fatalf("Prepare(occupied candidate) = %#v, %v", result, prepareErr)
				}
			} else if prepareErr != nil || result.Created || result.Revocation.ID != postgresTestRevocationID {
				t.Fatalf("Prepare(canonical replay) = %#v, %v", result, prepareErr)
			}
			if err := database.ExpectationsWereMet(); err != nil {
				t.Fatalf("unmet pgx expectations: %v", err)
			}
		})
	}
}

func TestPostgresErrorsNeverRenderFenceReferenceOrCiphertextMaterial(t *testing.T) {
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
	secretFence := "plaintext-action-fence-token-must-not-render"
	ciphertextMarker := "ciphertext-deadbeef-must-not-render"
	now := time.Date(2026, 7, 10, 15, 30, 0, 0, time.UTC)
	request := credential.PrepareRequest{
		RevocationID: postgresTestRevocationID,
		Fence: credential.ActionFence{
			ActionID: postgresTestActionID, RunnerID: "runner-write-1", Token: secretFence, Epoch: 4,
		},
		Issuer: "vault-production", IssuerRevision: "rev-1", CredentialExpiresAt: now.Add(time.Minute),
	}
	database.ExpectBegin()
	database.ExpectQuery("SELECT action_id, runner_tenant_id::text").
		WithArgs(request.Fence.ActionID, request.Fence.RunnerID, request.Fence.Epoch,
			credential.SHA256Hex([]byte(secretFence))).
		WillReturnError(errors.New("driver detail included " + secretFence + " and " + ciphertextMarker))
	database.ExpectRollback()

	_, prepareErr := repository.Prepare(context.Background(), request)
	if prepareErr == nil {
		t.Fatal("Prepare() error = nil")
	}
	if strings.Contains(prepareErr.Error(), secretFence) || strings.Contains(prepareErr.Error(), ciphertextMarker) {
		t.Fatalf("Prepare() leaked protected material in error: %v", prepareErr)
	}
	if !errors.Is(prepareErr, credential.ErrRevocationPersistence) {
		t.Fatalf("Prepare() error = %v, want ErrRevocationPersistence", prepareErr)
	}
	if err := database.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet pgx expectations: %v", err)
	}
}

func TestRecordAnchorIdempotencyAuthenticatesHMACWithoutDecryptingStoredAccessor(t *testing.T) {
	t.Parallel()
	database, err := pgxmock.NewPool()
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	spy := &spyingReferenceProtector{delegate: repositoryTestProtector(t)}
	repository, err := New(database, spy, Options{})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 10, 15, 35, 0, 0, time.UTC)
	fence := credential.ActionFence{
		ActionID: postgresTestActionID, RunnerID: "runner-write-1", Token: "action-token", Epoch: 4,
	}
	accessorValue := []byte("idempotent-postgres-accessor")
	protected := protectTestReference(t, spy, accessorValue)
	accessor, err := credential.NewSensitiveReference(accessorValue)
	if err != nil {
		t.Fatal(err)
	}
	defer accessor.Destroy()

	database.ExpectBegin()
	database.ExpectQuery("SELECT tenant_id::text, runner_pool, enabled, scope_revision.*FOR SHARE").
		WithArgs(fence.RunnerID).
		WillReturnRows(runnerRegistrationRows(true, "WRITE", 7))
	database.ExpectQuery("SELECT action.action_id, workspace.tenant_id::text").
		WithArgs(fence.ActionID).
		WillReturnRows(actionInspectionRows(now, fence, true))
	database.ExpectQuery("SELECT EXISTS.*FROM runner_scope_bindings").
		WithArgs(fence.RunnerID, postgresTestTenantID, postgresTestWorkspaceID, postgresTestEnvironment).
		WillReturnRows(pgxmock.NewRows([]string{"exists"}).AddRow(true))
	database.ExpectQuery("SELECT .* FROM credential_revocations").
		WithArgs(postgresTestRevocationID).
		WillReturnRows(storedRevocationRows(now, storedRowOptions{
			Status: credential.StatusAnchored, Protected: protected, AvailableAt: now, Version: 3,
		}))
	database.ExpectQuery("SELECT statement_timestamp\\(\\)").
		WillReturnRows(pgxmock.NewRows([]string{"database_now"}).AddRow(now))
	database.ExpectCommit()

	anchored, err := repository.RecordAnchor(context.Background(), credential.RecordAnchorRequest{
		RevocationID: postgresTestRevocationID, Fence: fence, Accessor: accessor,
	})
	if err != nil || anchored.Status != credential.StatusAnchored {
		t.Fatalf("RecordAnchor(idempotent) = %#v, %v", anchored, err)
	}
	matches, opens := spy.Calls()
	if matches != 1 || opens != 0 {
		t.Fatalf("RecordAnchor protector calls = matches %d, Unprotect %d", matches, opens)
	}
	if err := database.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet pgx expectations: %v", err)
	}
}

func TestRecordAnchorRejectsPreparedWithoutChildCreateAuthorization(t *testing.T) {
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
	now := time.Date(2026, 7, 10, 15, 37, 0, 0, time.UTC)
	fence := credential.ActionFence{ActionID: postgresTestActionID, RunnerID: "runner-write-1", Token: "action-token", Epoch: 4}
	accessor, _ := credential.NewSensitiveReference([]byte("must-not-be-protected"))
	defer accessor.Destroy()
	database.ExpectBegin()
	database.ExpectQuery("SELECT tenant_id::text, runner_pool, enabled, scope_revision.*FOR SHARE").
		WithArgs(fence.RunnerID).
		WillReturnRows(runnerRegistrationRows(true, "WRITE", 7))
	database.ExpectQuery("SELECT action.action_id, workspace.tenant_id::text").
		WithArgs(fence.ActionID).
		WillReturnRows(actionInspectionRows(now, fence, true))
	database.ExpectQuery("SELECT EXISTS.*FROM runner_scope_bindings").
		WithArgs(fence.RunnerID, postgresTestTenantID, postgresTestWorkspaceID, postgresTestEnvironment).
		WillReturnRows(pgxmock.NewRows([]string{"exists"}).AddRow(true))
	database.ExpectQuery("SELECT .* FROM credential_revocations.*FOR UPDATE").
		WithArgs(postgresTestRevocationID).
		WillReturnRows(storedRevocationRows(now, storedRowOptions{
			Status: credential.StatusPrepared, AvailableAt: now, Version: 1,
		}))
	database.ExpectRollback()

	_, err = repository.RecordAnchor(context.Background(), credential.RecordAnchorRequest{
		RevocationID: postgresTestRevocationID, Fence: fence, Accessor: accessor,
	})
	if !errors.Is(err, credential.ErrInvalidTransition) {
		t.Fatalf("RecordAnchor(without child authorization) error = %v", err)
	}
	if err := database.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet pgx expectations: %v", err)
	}
}

func TestRecordAnchorCancellationAtomicallyAnchorsAndRequestsRevocation(t *testing.T) {
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
	now := time.Date(2026, 7, 10, 15, 40, 0, 0, time.UTC)
	fence := credential.ActionFence{
		ActionID: postgresTestActionID, RunnerID: "runner-write-1", Token: "action-token", Epoch: 4,
	}
	accessor, _ := credential.NewSensitiveReference([]byte("nacked-action-accessor"))
	defer accessor.Destroy()
	protected := protectTestReference(t, protector, []byte("nacked-action-accessor"))

	database.ExpectBegin()
	database.ExpectQuery("SELECT tenant_id::text, runner_pool, enabled, scope_revision.*FOR SHARE").
		WithArgs(fence.RunnerID).
		WillReturnRows(runnerRegistrationRows(true, "WRITE", 7))
	database.ExpectQuery("SELECT action.action_id, workspace.tenant_id::text").
		WithArgs(fence.ActionID).
		WillReturnRows(actionInspectionRowsForState(now, fence, "RUNNING", now, 7))
	database.ExpectQuery("SELECT EXISTS.*FROM runner_scope_bindings").
		WithArgs(fence.RunnerID, postgresTestTenantID, postgresTestWorkspaceID, postgresTestEnvironment).
		WillReturnRows(pgxmock.NewRows([]string{"exists"}).AddRow(true))
	database.ExpectQuery("SELECT .* FROM credential_revocations").
		WithArgs(postgresTestRevocationID).
		WillReturnRows(storedRevocationRows(now, storedRowOptions{
			Status: credential.StatusPrepared, AvailableAt: now, Version: 2,
			ChildCreateAuthorizedAt: now.Add(-30 * time.Second), ChildCreateTTLSeconds: 600,
		}))
	database.ExpectQuery("UPDATE credential_revocations SET status = 'ANCHORED'").
		WithArgs(postgresTestRevocationID, pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).
		WillReturnRows(storedRevocationRows(now, storedRowOptions{
			Status: credential.StatusAnchored, Protected: protected, AvailableAt: now, Version: 3,
		}))
	database.ExpectExec("INSERT INTO audit_records").
		WithArgs(pgxmock.AnyArg(), postgresTestTenantID, postgresTestWorkspaceID,
			"RUNNER", fence.RunnerID, "credential.revocation.anchored", postgresTestRevocationID,
			pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))
	database.ExpectExec("INSERT INTO outbox_events").
		WithArgs(pgxmock.AnyArg(), postgresTestTenantID, postgresTestWorkspaceID,
			postgresTestRevocationID, int64(3), "credential.revocation.anchored.v1", pgxmock.AnyArg()).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))
	database.ExpectQuery("UPDATE credential_revocations SET status = 'REVOCATION_PENDING'").
		WithArgs(postgresTestRevocationID).
		WillReturnRows(storedRevocationRows(now, storedRowOptions{
			Status: credential.StatusRevocationPending, Protected: protected, AvailableAt: now, Version: 4,
		}))
	database.ExpectExec("INSERT INTO audit_records").
		WithArgs(pgxmock.AnyArg(), postgresTestTenantID, postgresTestWorkspaceID,
			"RUNNER", fence.RunnerID, "credential.revocation.requested", postgresTestRevocationID,
			pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))
	database.ExpectExec("INSERT INTO outbox_events").
		WithArgs(pgxmock.AnyArg(), postgresTestTenantID, postgresTestWorkspaceID,
			postgresTestRevocationID, int64(4), "credential.revocation.requested.v1", pgxmock.AnyArg()).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))
	database.ExpectCommit()

	anchored, err := repository.RecordAnchor(context.Background(), credential.RecordAnchorRequest{
		RevocationID: postgresTestRevocationID, Fence: fence, Accessor: accessor,
	})
	if err != nil || anchored.Status != credential.StatusRevocationPending || !anchored.AccessorPresent || anchored.Version != 4 {
		t.Fatalf("RecordAnchor(cancelled action) = %#v, %v", anchored, err)
	}
	if err := database.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet pgx expectations: %v", err)
	}
}

func TestRecordAnchorReplayRequestsRevocationWhenRunnerScopeIsNoLongerCurrent(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 10, 15, 41, 0, 0, time.UTC)
	for _, test := range []struct {
		name              string
		registrationScope int64
		actionScope       int64
		bindingResult     *bool
	}{
		{name: "scope revision changed", registrationScope: 8, actionScope: 7},
		{name: "exact binding removed", registrationScope: 7, actionScope: 7, bindingResult: boolPointer(false)},
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
			fence := credential.ActionFence{
				ActionID: postgresTestActionID, RunnerID: "runner-write-1", Token: "action-token", Epoch: 4,
			}
			accessorValue := []byte("scope-invalidated-anchor-accessor")
			accessor, err := credential.NewSensitiveReference(accessorValue)
			if err != nil {
				t.Fatal(err)
			}
			defer accessor.Destroy()
			protected := protectTestReference(t, protector, accessorValue)

			database.ExpectBegin()
			database.ExpectQuery("SELECT tenant_id::text, runner_pool, enabled, scope_revision.*FOR SHARE").
				WithArgs(fence.RunnerID).
				WillReturnRows(runnerRegistrationRows(true, "WRITE", test.registrationScope))
			database.ExpectQuery("SELECT action.action_id, workspace.tenant_id::text").
				WithArgs(fence.ActionID).
				WillReturnRows(actionInspectionRowsForState(now, fence, "RUNNING", time.Time{}, test.actionScope))
			if test.bindingResult != nil {
				database.ExpectQuery("SELECT EXISTS.*FROM runner_scope_bindings").
					WithArgs(fence.RunnerID, postgresTestTenantID, postgresTestWorkspaceID, postgresTestEnvironment).
					WillReturnRows(pgxmock.NewRows([]string{"exists"}).AddRow(*test.bindingResult))
			}
			database.ExpectQuery("SELECT .* FROM credential_revocations").
				WithArgs(postgresTestRevocationID).
				WillReturnRows(storedRevocationRows(now, storedRowOptions{
					Status: credential.StatusAnchored, Protected: protected, AvailableAt: now, Version: 3,
				}))
			database.ExpectQuery("UPDATE credential_revocations SET status = 'REVOCATION_PENDING'").
				WithArgs(postgresTestRevocationID).
				WillReturnRows(storedRevocationRows(now, storedRowOptions{
					Status: credential.StatusRevocationPending, Protected: protected, AvailableAt: now, Version: 4,
				}))
			database.ExpectExec("INSERT INTO audit_records").
				WithArgs(pgxmock.AnyArg(), postgresTestTenantID, postgresTestWorkspaceID,
					"RUNNER", fence.RunnerID, "credential.revocation.requested", postgresTestRevocationID,
					pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).
				WillReturnResult(pgxmock.NewResult("INSERT", 1))
			database.ExpectExec("INSERT INTO outbox_events").
				WithArgs(pgxmock.AnyArg(), postgresTestTenantID, postgresTestWorkspaceID,
					postgresTestRevocationID, int64(4), "credential.revocation.requested.v1", pgxmock.AnyArg()).
				WillReturnResult(pgxmock.NewResult("INSERT", 1))
			database.ExpectCommit()

			anchored, err := repository.RecordAnchor(context.Background(), credential.RecordAnchorRequest{
				RevocationID: postgresTestRevocationID, Fence: fence, Accessor: accessor,
			})
			if err != nil || anchored.Status != credential.StatusRevocationPending || anchored.Version != 4 {
				t.Fatalf("RecordAnchor(%s) = %#v, %v", test.name, anchored, err)
			}
			if err := database.ExpectationsWereMet(); err != nil {
				t.Fatalf("unmet pgx expectations: %v", err)
			}
		})
	}
}

func TestRecordAnchorRechecksDatabaseCommitWindowForNewAndIdempotentPaths(t *testing.T) {
	t.Parallel()
	for _, idempotent := range []bool{false, true} {
		name := "new"
		if idempotent {
			name = "idempotent"
		}
		t.Run(name, func(t *testing.T) {
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
			now := time.Date(2026, 7, 10, 15, 42, 0, 0, time.UTC)
			fence := credential.ActionFence{
				ActionID: postgresTestActionID, RunnerID: "runner-write-1", Token: "action-token", Epoch: 4,
			}
			accessorValue := []byte("anchor-commit-window-accessor")
			accessor, _ := credential.NewSensitiveReference(accessorValue)
			defer accessor.Destroy()
			protected := protectTestReference(t, protector, accessorValue)

			database.ExpectBegin()
			database.ExpectQuery("SELECT tenant_id::text, runner_pool, enabled, scope_revision.*FOR SHARE").
				WithArgs(fence.RunnerID).
				WillReturnRows(runnerRegistrationRows(true, "WRITE", 7))
			database.ExpectQuery("SELECT action.action_id, workspace.tenant_id::text").
				WithArgs(fence.ActionID).
				WillReturnRows(actionInspectionRows(now, fence, true))
			database.ExpectQuery("SELECT EXISTS.*FROM runner_scope_bindings").
				WithArgs(fence.RunnerID, postgresTestTenantID, postgresTestWorkspaceID, postgresTestEnvironment).
				WillReturnRows(pgxmock.NewRows([]string{"exists"}).AddRow(true))
			status, version := credential.StatusPrepared, int64(2)
			storedProtected := credential.ProtectedReference{}
			if idempotent {
				status, version, storedProtected = credential.StatusAnchored, 3, protected
			}
			database.ExpectQuery("SELECT .* FROM credential_revocations").
				WithArgs(postgresTestRevocationID).
				WillReturnRows(storedRevocationRows(now, storedRowOptions{
					Status: status, Protected: storedProtected, AvailableAt: now, Version: version,
					ChildCreateAuthorizedAt: now.Add(-30 * time.Second), ChildCreateTTLSeconds: 600,
				}))
			if !idempotent {
				database.ExpectQuery("UPDATE credential_revocations SET status = 'ANCHORED'").
					WithArgs(postgresTestRevocationID, pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).
					WillReturnRows(storedRevocationRows(now, storedRowOptions{
						Status: credential.StatusAnchored, Protected: protected, AvailableAt: now, Version: 3,
					}))
				database.ExpectExec("INSERT INTO audit_records").
					WithArgs(pgxmock.AnyArg(), postgresTestTenantID, postgresTestWorkspaceID,
						"RUNNER", fence.RunnerID, "credential.revocation.anchored", postgresTestRevocationID,
						pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).
					WillReturnResult(pgxmock.NewResult("INSERT", 1))
				database.ExpectExec("INSERT INTO outbox_events").
					WithArgs(pgxmock.AnyArg(), postgresTestTenantID, postgresTestWorkspaceID,
						postgresTestRevocationID, int64(3), "credential.revocation.anchored.v1", pgxmock.AnyArg()).
					WillReturnResult(pgxmock.NewResult("INSERT", 1))
			}
			database.ExpectQuery("SELECT statement_timestamp\\(\\)").
				WillReturnRows(pgxmock.NewRows([]string{"database_now"}).AddRow(now.Add(59*time.Second + 500*time.Millisecond)))
			database.ExpectQuery("UPDATE credential_revocations SET status = 'REVOCATION_PENDING'").
				WithArgs(postgresTestRevocationID).
				WillReturnRows(storedRevocationRows(now, storedRowOptions{
					Status: credential.StatusRevocationPending, Protected: protected, AvailableAt: now, Version: 4,
				}))
			database.ExpectExec("INSERT INTO audit_records").
				WithArgs(pgxmock.AnyArg(), postgresTestTenantID, postgresTestWorkspaceID,
					"RUNNER", fence.RunnerID, "credential.revocation.requested", postgresTestRevocationID,
					pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).
				WillReturnResult(pgxmock.NewResult("INSERT", 1))
			database.ExpectExec("INSERT INTO outbox_events").
				WithArgs(pgxmock.AnyArg(), postgresTestTenantID, postgresTestWorkspaceID,
					postgresTestRevocationID, int64(4), "credential.revocation.requested.v1", pgxmock.AnyArg()).
				WillReturnResult(pgxmock.NewResult("INSERT", 1))
			database.ExpectCommit()

			anchored, err := repository.RecordAnchor(context.Background(), credential.RecordAnchorRequest{
				RevocationID: postgresTestRevocationID, Fence: fence, Accessor: accessor,
			})
			if err != nil || anchored.Status != credential.StatusRevocationPending || !anchored.AccessorPresent {
				t.Fatalf("RecordAnchor(%s commit window) = %#v, %v", name, anchored, err)
			}
			if err := database.ExpectationsWereMet(); err != nil {
				t.Fatalf("unmet pgx expectations: %v", err)
			}
		})
	}
}

func TestActivateUsesFrozenInspectionAndRequestsRevocationWhenCommitWindowExpires(t *testing.T) {
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
	now := time.Date(2026, 7, 10, 15, 43, 0, 0, time.UTC)
	fence := credential.ActionFence{
		ActionID: postgresTestActionID, RunnerID: "runner-write-1", Token: "action-token", Epoch: 4,
	}
	protected := protectTestReference(t, protector, []byte("activate-commit-window-accessor"))

	database.ExpectBegin()
	database.ExpectQuery("SELECT tenant_id::text, runner_pool, enabled, scope_revision.*FOR SHARE").
		WithArgs(fence.RunnerID).
		WillReturnRows(runnerRegistrationRows(true, "WRITE", 7))
	database.ExpectQuery("SELECT action.action_id, workspace.tenant_id::text").
		WithArgs(fence.ActionID).
		WillReturnRows(actionInspectionRows(now, fence, true))
	database.ExpectQuery("SELECT EXISTS.*FROM runner_scope_bindings").
		WithArgs(fence.RunnerID, postgresTestTenantID, postgresTestWorkspaceID, postgresTestEnvironment).
		WillReturnRows(pgxmock.NewRows([]string{"exists"}).AddRow(true))
	database.ExpectQuery("SELECT .* FROM credential_revocations").
		WithArgs(postgresTestRevocationID).
		WillReturnRows(storedRevocationRows(now, storedRowOptions{
			Status: credential.StatusAnchored, Protected: protected, AvailableAt: now, Version: 2,
		}))
	database.ExpectQuery("UPDATE credential_revocations SET status = 'ACTIVE'").
		WithArgs(postgresTestRevocationID).
		WillReturnRows(storedRevocationRows(now, storedRowOptions{
			Status: credential.StatusActive, Protected: protected, AvailableAt: now, Version: 3,
		}))
	database.ExpectExec("INSERT INTO audit_records").
		WithArgs(pgxmock.AnyArg(), postgresTestTenantID, postgresTestWorkspaceID,
			"RUNNER", fence.RunnerID, "credential.revocation.active", postgresTestRevocationID,
			pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))
	database.ExpectExec("INSERT INTO outbox_events").
		WithArgs(pgxmock.AnyArg(), postgresTestTenantID, postgresTestWorkspaceID,
			postgresTestRevocationID, int64(3), "credential.revocation.active.v1", pgxmock.AnyArg()).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))
	database.ExpectQuery("SELECT statement_timestamp\\(\\)").
		WillReturnRows(pgxmock.NewRows([]string{"database_now"}).AddRow(now.Add(59*time.Second + 500*time.Millisecond)))
	database.ExpectQuery("UPDATE credential_revocations SET status = 'REVOCATION_PENDING'").
		WithArgs(postgresTestRevocationID).
		WillReturnRows(storedRevocationRows(now, storedRowOptions{
			Status: credential.StatusRevocationPending, Protected: protected, AvailableAt: now, Version: 4,
		}))
	database.ExpectExec("INSERT INTO audit_records").
		WithArgs(pgxmock.AnyArg(), postgresTestTenantID, postgresTestWorkspaceID,
			"RUNNER", fence.RunnerID, "credential.revocation.requested", postgresTestRevocationID,
			pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))
	database.ExpectExec("INSERT INTO outbox_events").
		WithArgs(pgxmock.AnyArg(), postgresTestTenantID, postgresTestWorkspaceID,
			postgresTestRevocationID, int64(4), "credential.revocation.requested.v1", pgxmock.AnyArg()).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))
	database.ExpectCommit()

	activated, err := repository.Activate(context.Background(), credential.ActionTransitionRequest{
		RevocationID: postgresTestRevocationID, Fence: fence,
	})
	if err != nil || activated.Status != credential.StatusRevocationPending {
		t.Fatalf("Activate(commit window expired) = %#v, %v", activated, err)
	}
	if err := database.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet pgx expectations: %v", err)
	}
}

func TestActivateActiveReplayImmediatelyRequestsWhenRunnerIsDisabled(t *testing.T) {
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
	now := time.Date(2026, 7, 10, 15, 44, 0, 0, time.UTC)
	fence := credential.ActionFence{
		ActionID: postgresTestActionID, RunnerID: "runner-write-1", Token: "action-token", Epoch: 4,
	}
	protected := protectTestReference(t, protector, []byte("activate-invalid-inspection-accessor"))
	database.ExpectBegin()
	database.ExpectQuery("SELECT tenant_id::text, runner_pool, enabled, scope_revision.*FOR SHARE").
		WithArgs(fence.RunnerID).
		WillReturnRows(runnerRegistrationRows(false, "WRITE", 7))
	database.ExpectQuery("SELECT action.action_id, workspace.tenant_id::text").
		WithArgs(fence.ActionID).
		WillReturnRows(actionInspectionRows(now, fence, true))
	database.ExpectQuery("SELECT .* FROM credential_revocations").
		WithArgs(postgresTestRevocationID).
		WillReturnRows(storedRevocationRows(now, storedRowOptions{
			Status: credential.StatusActive, Protected: protected, AvailableAt: now, Version: 3,
		}))
	database.ExpectQuery("UPDATE credential_revocations SET status = 'REVOCATION_PENDING'").
		WithArgs(postgresTestRevocationID).
		WillReturnRows(storedRevocationRows(now, storedRowOptions{
			Status: credential.StatusRevocationPending, Protected: protected, AvailableAt: now, Version: 4,
		}))
	database.ExpectExec("INSERT INTO audit_records").
		WithArgs(pgxmock.AnyArg(), postgresTestTenantID, postgresTestWorkspaceID,
			"RUNNER", fence.RunnerID, "credential.revocation.requested", postgresTestRevocationID,
			pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))
	database.ExpectExec("INSERT INTO outbox_events").
		WithArgs(pgxmock.AnyArg(), postgresTestTenantID, postgresTestWorkspaceID,
			postgresTestRevocationID, int64(4), "credential.revocation.requested.v1", pgxmock.AnyArg()).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))
	database.ExpectCommit()

	activated, err := repository.Activate(context.Background(), credential.ActionTransitionRequest{
		RevocationID: postgresTestRevocationID, Fence: fence,
	})
	if err != nil || activated.Status != credential.StatusRevocationPending {
		t.Fatalf("Activate(disabled runner) = %#v, %v", activated, err)
	}
	if err := database.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet pgx expectations: %v", err)
	}
}

func TestPrepareClassifiesCredentialExpiryBeyondAuthorizationAsInvalidRequest(t *testing.T) {
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
	now := time.Date(2026, 7, 10, 15, 45, 0, 0, time.UTC)
	request := credential.PrepareRequest{
		RevocationID: postgresTestRevocationID,
		Fence: credential.ActionFence{
			ActionID: postgresTestActionID, RunnerID: "runner-write-1", Token: "action-token", Epoch: 4,
		},
		Issuer: "vault-production", IssuerRevision: "rev-1", CredentialExpiresAt: now.Add(5 * time.Minute),
	}
	database.ExpectBegin()
	database.ExpectQuery("SELECT action_id, runner_tenant_id::text").
		WithArgs(request.Fence.ActionID, request.Fence.RunnerID, request.Fence.Epoch,
			credential.SHA256Hex([]byte(request.Fence.Token))).
		WillReturnRows(actionMetadataRows(now, request.Fence, now.Add(time.Minute)))
	database.ExpectRollback()

	_, prepareErr := repository.Prepare(context.Background(), request)
	if !errors.Is(prepareErr, credential.ErrInvalidRevocationRequest) {
		t.Fatalf("Prepare(expiry beyond authorization) error = %v", prepareErr)
	}
	if err := database.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet pgx expectations: %v", err)
	}
}

func TestPrepareRevalidatesFenceWindowImmediatelyBeforeCommit(t *testing.T) {
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
	base := time.Date(2026, 7, 10, 15, 50, 0, 0, time.UTC)
	fence := credential.ActionFence{
		ActionID: postgresTestActionID, RunnerID: "runner-write-1", Token: "action-token", Epoch: 4,
	}
	request := credential.PrepareRequest{
		RevocationID: postgresTestRevocationID, Fence: fence, Issuer: "vault-production", IssuerRevision: "rev-1",
		CredentialExpiresAt: base.Add(1800 * time.Millisecond),
	}
	tokenDigest := credential.SHA256Hex([]byte(fence.Token))
	database.ExpectBegin()
	database.ExpectQuery("SELECT action_id, runner_tenant_id::text").
		WithArgs(fence.ActionID, fence.RunnerID, fence.Epoch, tokenDigest).
		WillReturnRows(actionMetadataRows(base, fence, base.Add(2*time.Second)))
	database.ExpectQuery("SELECT .* FROM credential_revocations.*WHERE action_id = \\$1 AND action_lease_epoch = \\$2.*FOR SHARE").
		WithArgs(fence.ActionID, fence.Epoch).
		WillReturnRows(pgxmock.NewRows(storedRevocationColumns()))
	database.ExpectQuery("INSERT INTO credential_revocations").
		WithArgs(
			request.RevocationID, postgresTestTenantID, postgresTestWorkspaceID, postgresTestEnvironment,
			fence.ActionID, "cluster-a/payments", false, fence.RunnerID, fence.Epoch, tokenDigest,
			request.Issuer, request.IssuerRevision, "KUBERNETES_ROLLOUT_RESTART", "kubernetes-prod",
			"PATCH_DEPLOYMENT_RESTART", "cluster-a/payments/deployment/api", int32(600),
			credential.CanonicalCredentialExpiry(request.CredentialExpiresAt), pgxmock.AnyArg(),
		).
		WillReturnRows(pgxmock.NewRows([]string{"status", "available_at", "created_at", "updated_at", "version"}).
			AddRow("PREPARED", base, base, base, int64(1)))
	expectActionCredentialMarker(database, fence, tokenDigest)
	database.ExpectExec("INSERT INTO audit_records").
		WithArgs(pgxmock.AnyArg(), postgresTestTenantID, postgresTestWorkspaceID,
			"RUNNER", fence.RunnerID, "credential.revocation.prepared", request.RevocationID,
			pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))
	database.ExpectExec("INSERT INTO outbox_events").
		WithArgs(pgxmock.AnyArg(), postgresTestTenantID, postgresTestWorkspaceID,
			request.RevocationID, int64(1), "credential.revocation.prepared.v1", pgxmock.AnyArg()).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))
	database.ExpectQuery("SELECT action_id, runner_tenant_id::text").
		WithArgs(fence.ActionID, fence.RunnerID, fence.Epoch, tokenDigest).
		WillReturnRows(actionMetadataRows(base.Add(1500*time.Millisecond), fence, base.Add(2*time.Second)))
	database.ExpectRollback()

	result, prepareErr := repository.Prepare(context.Background(), request)
	if !errors.Is(prepareErr, credential.ErrStaleActionFence) || result.Created || result.Permit != nil {
		t.Fatalf("Prepare(commit window elapsed) = %#v, %v", result, prepareErr)
	}
	if err := database.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet pgx expectations: %v", err)
	}
}

func TestRecoverPreparedUsesDatabaseBoundaryAndWritesAuditableTerminalState(t *testing.T) {
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
	now := time.Date(2026, 7, 10, 16, 10, 0, 0, time.UTC)
	database.ExpectBegin()
	database.ExpectQuery("SELECT .* FROM credential_revocations.*credential_expires_at <= statement_timestamp\\(\\) - interval '1 minute'.*ORDER BY credential_expires_at, revocation_id.*FOR UPDATE SKIP LOCKED").
		WithArgs(10).
		WillReturnRows(storedRevocationRows(now, storedRowOptions{
			Status: credential.StatusPrepared, AvailableAt: now, Version: 1,
		}))
	database.ExpectQuery("UPDATE credential_revocations SET status = 'NO_CREDENTIAL'.*credential_expires_at <= statement_timestamp\\(\\) - interval '1 minute'").
		WithArgs(postgresTestRevocationID).
		WillReturnRows(storedRevocationRows(now, storedRowOptions{
			Status: credential.StatusNoCredential, AvailableAt: now, Version: 2,
		}))
	database.ExpectExec("INSERT INTO audit_records").
		WithArgs(pgxmock.AnyArg(), postgresTestTenantID, postgresTestWorkspaceID,
			"SYSTEM", "credential-prepared-recovery", "credential.revocation.prepared_expired", postgresTestRevocationID,
			pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))
	database.ExpectExec("INSERT INTO outbox_events").
		WithArgs(pgxmock.AnyArg(), postgresTestTenantID, postgresTestWorkspaceID,
			postgresTestRevocationID, int64(2), "credential.revocation.prepared_expired.v1", pgxmock.AnyArg()).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))
	database.ExpectCommit()

	recovered, err := repository.RecoverPrepared(context.Background(), credential.RecoverPreparedRequest{Limit: 10})
	if err != nil || len(recovered) != 1 || recovered[0].Status != credential.StatusNoCredential || recovered[0].Version != 2 {
		t.Fatalf("RecoverPrepared() = %#v, %v", recovered, err)
	}

	database.ExpectBegin()
	database.ExpectQuery("SELECT .* FROM credential_revocations.*credential_expires_at <= statement_timestamp\\(\\) - interval '1 minute'.*ORDER BY credential_expires_at, revocation_id.*FOR UPDATE SKIP LOCKED").
		WithArgs(10).
		WillReturnRows(pgxmock.NewRows(storedRevocationColumns()))
	database.ExpectCommit()
	replayed, err := repository.RecoverPrepared(context.Background(), credential.RecoverPreparedRequest{Limit: 10})
	if err != nil || len(replayed) != 0 {
		t.Fatalf("RecoverPrepared(replay) = %#v, %v", replayed, err)
	}
	if err := database.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet pgx expectations: %v", err)
	}
}

func TestRecordNoCredentialRejectsConsumedChildCreateAuthorization(t *testing.T) {
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
	now := time.Date(2026, 7, 10, 16, 12, 0, 0, time.UTC)
	fence := credential.ActionFence{ActionID: postgresTestActionID, RunnerID: "runner-write-1", Token: "action-token", Epoch: 4}
	database.ExpectBegin()
	database.ExpectQuery("SELECT action_id, runner_tenant_id::text.*FOR SHARE").
		WithArgs(fence.ActionID, fence.RunnerID, fence.Epoch, credential.SHA256Hex([]byte(fence.Token))).
		WillReturnRows(actionMetadataRows(now, fence, now.Add(10*time.Minute)))
	database.ExpectQuery("SELECT .* FROM credential_revocations.*FOR UPDATE").
		WithArgs(postgresTestRevocationID).
		WillReturnRows(storedRevocationRows(now, storedRowOptions{
			Status: credential.StatusPrepared, AvailableAt: now, Version: 2,
			ChildCreateAuthorizedAt: now.Add(-time.Second), ChildCreateTTLSeconds: 585,
		}))
	database.ExpectRollback()

	_, err = repository.RecordNoCredential(context.Background(), credential.ActionTransitionRequest{
		RevocationID: postgresTestRevocationID, Fence: fence,
	})
	if !errors.Is(err, credential.ErrInvalidTransition) {
		t.Fatalf("RecordNoCredential(after child authorization) error = %v", err)
	}
	if err := database.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet pgx expectations: %v", err)
	}
}

func TestClaimRevocationsStoresOnlyRandomTokenDigestAndReturnsDecryptedAccessor(t *testing.T) {
	t.Parallel()
	database, err := pgxmock.NewPool()
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	protector := repositoryTestProtector(t)
	claimToken := "random-claim-token-never-persisted"
	repository, err := New(database, protector, Options{TokenSource: func() (string, error) { return claimToken, nil }})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 10, 16, 0, 0, 0, time.UTC)
	referenceContext := credential.ReferenceContext{
		RevocationID: postgresTestRevocationID, ActionID: postgresTestActionID, ActionEpoch: 4, Issuer: "vault-production", IssuerRevision: "rev-1",
	}
	accessor, _ := credential.NewSensitiveReference([]byte("vault/accessor-claim-test"))
	protected, err := protector.Protect(referenceContext, accessor)
	if err != nil {
		t.Fatal(err)
	}
	claimSum := sha256.Sum256([]byte(claimToken))
	claimDigest := hex.EncodeToString(claimSum[:])

	database.ExpectBegin()
	database.ExpectQuery("SELECT revocation_id::text, tenant_id::text").
		WithArgs(1, credential.MaxRevocationAttempts, credential.MaxRevocationElapsed.Seconds()).
		WillReturnRows(storedRevocationRows(now, storedRowOptions{
			Status: credential.StatusRevocationPending, Protected: protected, AvailableAt: now.Add(-time.Second), Version: 4,
		}))
	database.ExpectQuery("UPDATE credential_revocations SET status = 'REVOKING'").
		WithArgs(postgresTestRevocationID, "revoker-1", claimDigest, 30.0,
			credential.MaxRevocationAttempts, credential.MaxRevocationElapsed.Seconds()).
		WillReturnRows(storedRevocationRows(now, storedRowOptions{
			Status: credential.StatusRevoking, Protected: protected, AvailableAt: now.Add(-time.Second), Version: 5,
			ClaimEpoch: 1, ClaimedBy: "revoker-1", ClaimTokenSHA256: claimDigest,
			ClaimedAt: now, ClaimExpiresAt: now.Add(30 * time.Second), HeartbeatAt: now, Attempt: 1,
		}))
	database.ExpectExec("INSERT INTO audit_records").
		WithArgs(pgxmock.AnyArg(), postgresTestTenantID, postgresTestWorkspaceID, "SYSTEM", "revoker-1",
			"credential.revocation.claimed", postgresTestRevocationID,
			pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))
	database.ExpectExec("INSERT INTO outbox_events").
		WithArgs(pgxmock.AnyArg(), postgresTestTenantID, postgresTestWorkspaceID, postgresTestRevocationID,
			int64(5), "credential.revocation.claimed.v1", pgxmock.AnyArg()).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))
	database.ExpectCommit()

	claims, err := repository.ClaimRevocations(context.Background(), credential.ClaimRevocationsRequest{
		WorkerID: "revoker-1", Limit: 1, LeaseDuration: 30 * time.Second,
	})
	if err != nil || len(claims) != 1 {
		t.Fatalf("ClaimRevocations() = %#v, %v", claims, err)
	}
	defer claims[0].Accessor.Destroy()
	if claims[0].Fence.Token != claimToken || claims[0].Fence.Epoch != 1 ||
		string(claims[0].Accessor.Bytes()) != "vault/accessor-claim-test" {
		t.Fatalf("claim = %#v", claims[0])
	}
	if err := database.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet pgx expectations: %v", err)
	}
}

func TestRetryRevocationUsesDatabaseRelativeDelayAndNeverPersistsFailureBody(t *testing.T) {
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
	now := time.Date(2026, 7, 10, 17, 0, 0, 0, time.UTC)
	claimToken := "retry-claim-token"
	claimDigest := credential.SHA256Hex([]byte(claimToken))
	failureBody := []byte("upstream body with credential-shaped private detail")
	detailHash := credential.SHA256Hex(failureBody)
	delay := 45 * time.Second
	protected := protectTestReference(t, protector, []byte("retry-accessor"))

	database.ExpectBegin()
	database.ExpectQuery("UPDATE credential_revocations SET status = CASE").
		WithArgs(postgresTestRevocationID, "revoker-1", claimDigest, int64(2), string(credential.FailureIssuerUnavailable), detailHash,
			45.0, credential.MaxRevocationAttempts, credential.MaxRevocationElapsed.Seconds()).
		WillReturnRows(storedRevocationRows(now, storedRowOptions{
			Status: credential.StatusRevocationPending, Protected: protected, AvailableAt: now.Add(delay), Version: 8,
			ClaimEpoch: 2, Attempt: 2, FailureCount: 1, FailureCode: credential.FailureIssuerUnavailable,
			FailureDetailSHA256: detailHash,
		}))
	payload := `{"action_id":"` + postgresTestActionID + `","attempt":2,"detail_hash":"` + detailHash +
		`","failure_code":"ISSUER_UNAVAILABLE","failure_count":1,"issuer":"vault-production","issuer_revision":"rev-1","revocation_id":"` + postgresTestRevocationID +
		`","workspace_id":"` + postgresTestWorkspaceID + `"}`
	database.ExpectExec("INSERT INTO audit_records").
		WithArgs(pgxmock.AnyArg(), postgresTestTenantID, postgresTestWorkspaceID, "SYSTEM", "revoker-1",
			"credential.revocation.failed", postgresTestRevocationID,
			pgxmock.AnyArg(), pgxmock.AnyArg(), credential.SHA256Hex([]byte(payload)), payload).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))
	database.ExpectExec("INSERT INTO outbox_events").
		WithArgs(pgxmock.AnyArg(), postgresTestTenantID, postgresTestWorkspaceID, postgresTestRevocationID,
			int64(8), "credential.revocation.failed.v1", payload).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))
	database.ExpectCommit()

	retried, err := repository.RetryRevocation(context.Background(), credential.RetryRevocationRequest{
		Fence: credential.ClaimFence{RevocationID: postgresTestRevocationID, WorkerID: "revoker-1", Token: claimToken, Epoch: 2},
		Delay: delay, FailureCode: credential.FailureIssuerUnavailable, FailureDetail: failureBody,
	})
	if err != nil {
		t.Fatalf("RetryRevocation() error = %v", err)
	}
	if retried.Status != credential.StatusRevocationPending || retried.FailureDetailSHA256 != detailHash ||
		!retried.AvailableAt.Equal(now.Add(delay)) {
		t.Fatalf("retried = %#v", retried)
	}
	if err := database.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet pgx expectations: %v", err)
	}
}

func TestCompleteRevocationClearsDecryptableReferenceAndReplaysSameCompletionFence(t *testing.T) {
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
	now := time.Date(2026, 7, 10, 18, 0, 0, 0, time.UTC)
	claimToken := "completion-claim-token"
	claimDigest := credential.SHA256Hex([]byte(claimToken))
	protected := protectTestReference(t, repository.protector, []byte("completion-accessor"))
	completedShape := credential.ProtectedReference{AccessorHMAC: protected.AccessorHMAC}
	rowOptions := storedRowOptions{
		Status: credential.StatusRevoked, Protected: completedShape, AvailableAt: now.Add(-time.Minute), Version: 12,
		ClaimEpoch: 3, Attempt: 3, CompletedClaimEpoch: 3, CompletedClaimTokenSHA256: claimDigest,
		CompletedClaimedBy: "revoker-complete", RevokedAt: now,
	}
	fence := credential.ClaimFence{
		RevocationID: postgresTestRevocationID, WorkerID: "revoker-complete", Token: claimToken, Epoch: 3,
	}

	database.ExpectBegin()
	database.ExpectQuery("UPDATE credential_revocations SET status = 'REVOKED'").
		WithArgs(postgresTestRevocationID, fence.WorkerID, claimDigest, int64(3)).
		WillReturnRows(storedRevocationRows(now, rowOptions))
	database.ExpectExec("INSERT INTO audit_records").
		WithArgs(pgxmock.AnyArg(), postgresTestTenantID, postgresTestWorkspaceID, "SYSTEM", fence.WorkerID,
			"credential.revocation.completed", postgresTestRevocationID,
			pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))
	database.ExpectExec("INSERT INTO outbox_events").
		WithArgs(pgxmock.AnyArg(), postgresTestTenantID, postgresTestWorkspaceID, postgresTestRevocationID,
			int64(12), "credential.revocation.completed.v1", pgxmock.AnyArg()).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))
	database.ExpectCommit()

	completed, err := repository.CompleteRevocation(context.Background(), credential.CompleteRevocationRequest{Fence: fence})
	if err != nil || completed.Status != credential.StatusRevoked || completed.AccessorPresent ||
		completed.EncryptionKeyID != "" || len(completed.AccessorHMAC) != 64 {
		t.Fatalf("CompleteRevocation() = %#v, %v", completed, err)
	}

	database.ExpectBegin()
	database.ExpectQuery("UPDATE credential_revocations SET status = 'REVOKED'").
		WithArgs(postgresTestRevocationID, fence.WorkerID, claimDigest, int64(3)).
		WillReturnRows(pgxmock.NewRows(storedRevocationColumns()))
	database.ExpectQuery("SELECT revocation_id::text, tenant_id::text").
		WithArgs(postgresTestRevocationID).
		WillReturnRows(storedRevocationRows(now, rowOptions))
	database.ExpectCommit()
	if _, err := repository.CompleteRevocation(context.Background(), credential.CompleteRevocationRequest{Fence: fence}); err != nil {
		t.Fatalf("CompleteRevocation(idempotent) error = %v", err)
	}
	if err := database.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet pgx expectations: %v", err)
	}
}

func TestRequestRevocationRecoversAnchoredRecordWithoutActionBearer(t *testing.T) {
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
	now := time.Date(2026, 7, 10, 18, 30, 0, 0, time.UTC)
	protected := protectTestReference(t, repository.protector, []byte("recovery-accessor"))
	database.ExpectBegin()
	database.ExpectQuery("SELECT revocation_id::text, tenant_id::text").
		WithArgs(postgresTestRevocationID).
		WillReturnRows(storedRevocationRows(now, storedRowOptions{
			Status: credential.StatusAnchored, Protected: protected, AvailableAt: now.Add(-time.Minute), Version: 3,
		}))
	database.ExpectQuery("UPDATE credential_revocations SET status = 'REVOCATION_PENDING'").
		WithArgs(postgresTestRevocationID).
		WillReturnRows(storedRevocationRows(now, storedRowOptions{
			Status: credential.StatusRevocationPending, Protected: protected, AvailableAt: now, Version: 4,
		}))
	database.ExpectExec("INSERT INTO audit_records").
		WithArgs(pgxmock.AnyArg(), postgresTestTenantID, postgresTestWorkspaceID, "SYSTEM", "credential-repository",
			"credential.revocation.requested", postgresTestRevocationID,
			pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))
	database.ExpectExec("INSERT INTO outbox_events").
		WithArgs(pgxmock.AnyArg(), postgresTestTenantID, postgresTestWorkspaceID, postgresTestRevocationID,
			int64(4), "credential.revocation.requested.v1", pgxmock.AnyArg()).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))
	database.ExpectCommit()

	recovered, err := repository.RequestRevocation(context.Background(), credential.ActionTransitionRequest{RevocationID: postgresTestRevocationID})
	if err != nil || recovered.Status != credential.StatusRevocationPending {
		t.Fatalf("RequestRevocation(recovery) = %#v, %v", recovered, err)
	}
	if err := database.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet pgx expectations: %v", err)
	}
}

func TestSecondExternalConfirmationAtomicallyRequiresMatchingAdminEvidenceAndRevokes(t *testing.T) {
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
	now := time.Date(2026, 7, 10, 19, 0, 0, 0, time.UTC)
	evidence := strings.Repeat("a", 64)
	protected := protectTestReference(t, repository.protector, []byte("manual-accessor"))
	manualOptions := storedRowOptions{
		Status: credential.StatusManualRequired, Protected: protected, AvailableAt: now.Add(-time.Minute), Version: 14,
		ClaimEpoch: 4, Attempt: 4, FailureCount: 2, FailureCode: credential.FailurePermissionDenied,
		FailureDetailSHA256: strings.Repeat("b", 64), EvidenceHash: evidence, ManualAt: now.Add(-time.Minute),
	}
	revokedOptions := manualOptions
	revokedOptions.Status = credential.StatusRevoked
	revokedOptions.Protected = credential.ProtectedReference{AccessorHMAC: protected.AccessorHMAC}
	revokedOptions.Version = 15
	revokedOptions.RevokedAt = now

	database.ExpectBegin()
	database.ExpectQuery("SELECT revocation_id::text, tenant_id::text").
		WithArgs(postgresTestRevocationID).
		WillReturnRows(storedRevocationRows(now, manualOptions))
	database.ExpectQuery("SELECT subject, evidence_hash, platform_admin, created_at").
		WithArgs(postgresTestRevocationID).
		WillReturnRows(pgxmock.NewRows([]string{"subject", "evidence_hash", "platform_admin", "created_at"}).
			AddRow("oidc:operator-1", evidence, false, now.Add(-time.Minute)))
	database.ExpectQuery("INSERT INTO credential_revocation_confirmations").
		WithArgs(postgresTestRevocationID, "oidc:platform-admin-1", evidence, true).
		WillReturnRows(pgxmock.NewRows([]string{"created_at"}).AddRow(now))
	database.ExpectQuery("UPDATE credential_revocations SET status = 'REVOKED'").
		WithArgs(postgresTestRevocationID, evidence).
		WillReturnRows(storedRevocationRows(now, revokedOptions))
	database.ExpectExec("INSERT INTO audit_records").
		WithArgs(pgxmock.AnyArg(), postgresTestTenantID, postgresTestWorkspaceID, "USER", "oidc:platform-admin-1",
			"credential.revocation.externally_confirmed", postgresTestRevocationID,
			pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))
	database.ExpectExec("INSERT INTO outbox_events").
		WithArgs(pgxmock.AnyArg(), postgresTestTenantID, postgresTestWorkspaceID, postgresTestRevocationID,
			int64(15), "credential.revocation.externally_confirmed.v1", pgxmock.AnyArg()).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))
	database.ExpectCommit()

	result, err := repository.SubmitExternalConfirmation(context.Background(), credential.ExternalConfirmationRequest{
		RevocationID: postgresTestRevocationID, Subject: "oidc:platform-admin-1", EvidenceHash: evidence, PlatformAdmin: true,
	})
	if err != nil || result.Revocation.Status != credential.StatusRevoked || result.Revocation.AccessorPresent ||
		len(result.Confirmations) != 2 {
		t.Fatalf("SubmitExternalConfirmation(second) = %#v, %v", result, err)
	}
	if err := database.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet pgx expectations: %v", err)
	}
}

type storedRowOptions struct {
	RevocationID              string
	ActionID                  string
	RunnerID                  string
	ActionLeaseEpoch          int64
	ActionToken               string
	ActionType                string
	CredentialTTLSeconds      int32
	Status                    credential.RevocationStatus
	CredentialExpiresAt       time.Time
	ChildCreatePermitSHA256   string
	ChildCreateAuthorizedAt   time.Time
	ChildCreateTTLSeconds     int32
	Protected                 credential.ProtectedReference
	AvailableAt               time.Time
	Version                   int64
	ClaimEpoch                int64
	ClaimedBy                 string
	ClaimTokenSHA256          string
	ClaimedAt                 time.Time
	ClaimExpiresAt            time.Time
	HeartbeatAt               time.Time
	Attempt                   int
	RetryCycleAttemptBase     int
	RetryCycleStartedAt       time.Time
	FailureCount              int
	FailureCode               credential.FailureCode
	FailureDetailSHA256       string
	CompletedClaimEpoch       int64
	CompletedClaimTokenSHA256 string
	CompletedClaimedBy        string
	EvidenceHash              string
	ManualAt                  time.Time
	RevokedAt                 time.Time
}

type spyingReferenceProtector struct {
	delegate credential.ReferenceProtector
	mu       sync.Mutex
	matches  int
	opens    int
}

func (protector *spyingReferenceProtector) Protect(ctx credential.ReferenceContext, reference *credential.SensitiveReference) (credential.ProtectedReference, error) {
	return protector.delegate.Protect(ctx, reference)
}

func (protector *spyingReferenceProtector) Matches(ctx credential.ReferenceContext, protected credential.ProtectedReference, reference *credential.SensitiveReference) (bool, error) {
	protector.mu.Lock()
	protector.matches++
	protector.mu.Unlock()
	return protector.delegate.Matches(ctx, protected, reference)
}

func (protector *spyingReferenceProtector) Unprotect(ctx credential.ReferenceContext, protected credential.ProtectedReference) (*credential.SensitiveReference, error) {
	protector.mu.Lock()
	protector.opens++
	protector.mu.Unlock()
	return protector.delegate.Unprotect(ctx, protected)
}

func (protector *spyingReferenceProtector) Calls() (matches, opens int) {
	protector.mu.Lock()
	defer protector.mu.Unlock()
	return protector.matches, protector.opens
}

func storedRevocationRows(now time.Time, options storedRowOptions) *pgxmock.Rows {
	rows := pgxmock.NewRows(storedRevocationColumns())
	return addStoredRevocationRow(rows, now, options)
}

func addStoredRevocationRow(rows *pgxmock.Rows, now time.Time, options storedRowOptions) *pgxmock.Rows {
	if options.RevocationID == "" {
		options.RevocationID = postgresTestRevocationID
	}
	if options.ActionID == "" {
		options.ActionID = postgresTestActionID
	}
	if options.RunnerID == "" {
		options.RunnerID = "runner-write-1"
	}
	if options.ActionLeaseEpoch == 0 {
		options.ActionLeaseEpoch = 4
	}
	if options.ActionToken == "" {
		options.ActionToken = "action-token"
	}
	if options.ActionType == "" {
		options.ActionType = "KUBERNETES_ROLLOUT_RESTART"
	}
	if options.CredentialTTLSeconds == 0 {
		options.CredentialTTLSeconds = 600
	}
	permitDigest := options.ChildCreatePermitSHA256
	if permitDigest == "" {
		permitDigest = credential.SHA256Hex([]byte("child-create-permit"))
	}
	credentialExpiresAt := options.CredentialExpiresAt
	if credentialExpiresAt.IsZero() {
		credentialExpiresAt = now.Add(10 * time.Minute)
	}
	if options.ChildCreateAuthorizedAt.IsZero() && options.Status != credential.StatusPrepared &&
		options.Status != credential.StatusNoCredential {
		options.ChildCreateAuthorizedAt = now.Add(-30 * time.Second)
		options.ChildCreateTTLSeconds = 600
	}
	if options.RetryCycleStartedAt.IsZero() && options.Status != credential.StatusPrepared &&
		options.Status != credential.StatusNoCredential && options.Status != credential.StatusAnchored &&
		options.Status != credential.StatusActive {
		options.RetryCycleStartedAt = now.Add(-time.Minute)
	}
	return rows.AddRow(
		options.RevocationID, postgresTestTenantID, postgresTestWorkspaceID, postgresTestEnvironment,
		options.ActionID, "cluster-a/payments", false, options.RunnerID, options.ActionLeaseEpoch,
		credential.SHA256Hex([]byte(options.ActionToken)),
		"vault-production", "rev-1", options.ActionType, "kubernetes-prod", "PATCH_DEPLOYMENT_RESTART",
		"cluster-a/payments/deployment/api", int64(options.CredentialTTLSeconds), credentialExpiresAt, permitDigest,
		nullableTime(options.ChildCreateAuthorizedAt), nullableInt32(options.ChildCreateTTLSeconds),
		string(options.Status), nullableBytes(options.Protected.Ciphertext), nullableBytes(options.Protected.AccessorHMAC),
		nullableString(options.Protected.KeyID), options.ClaimEpoch, nullableString(options.ClaimedBy), nullableString(options.ClaimTokenSHA256),
		nullableTime(options.ClaimedAt), nullableTime(options.ClaimExpiresAt), nullableTime(options.HeartbeatAt),
		nullableInt64(options.CompletedClaimEpoch), nullableString(options.CompletedClaimTokenSHA256), nullableString(options.CompletedClaimedBy),
		options.Attempt, options.RetryCycleAttemptBase, nullableTime(options.RetryCycleStartedAt),
		options.FailureCount, nullableString(string(options.FailureCode)),
		nullableString(options.FailureDetailSHA256), options.AvailableAt, nullableString(options.EvidenceHash), now.Add(-time.Minute), now.Add(-time.Minute),
		now.Add(-time.Minute), nullableTime(options.ManualAt), nullableTime(options.RevokedAt), options.Version, now.Add(-2*time.Minute), now,
	)
}

func storedRevocationColumns() []string {
	return []string{
		"revocation_id", "tenant_id", "workspace_id", "environment_id", "action_id", "target_key", "production",
		"runner_id", "action_lease_epoch", "action_lease_token_sha256", "issuer", "issuer_revision", "action_type", "connector_id",
		"scope_permission", "scope_resource", "credential_ttl_seconds", "credential_expires_at", "child_create_permit_sha256", "child_create_authorized_at",
		"child_create_ttl_seconds", "status", "accessor_ciphertext", "accessor_hmac", "encryption_key_id",
		"claim_epoch", "claimed_by", "claim_token_sha256", "claimed_at", "claim_expires_at", "last_heartbeat_at",
		"completed_claim_epoch", "completed_claim_token_sha256", "completed_claimed_by", "attempt",
		"retry_cycle_attempt_base", "retry_cycle_started_at", "failure_count",
		"failure_code", "failure_detail_sha256", "available_at", "evidence_hash", "anchored_at", "activated_at",
		"revocation_requested_at", "manual_required_at", "revoked_at", "version", "created_at", "updated_at",
	}
}

func protectTestReference(t *testing.T, protector credential.ReferenceProtector, value []byte) credential.ProtectedReference {
	return protectTestReferenceFor(t, protector, postgresTestRevocationID, postgresTestActionID, 4, value)
}

func protectTestReferenceFor(
	t *testing.T,
	protector credential.ReferenceProtector,
	revocationID, actionID string,
	actionEpoch int64,
	value []byte,
) credential.ProtectedReference {
	t.Helper()
	reference, err := credential.NewSensitiveReference(value)
	if err != nil {
		t.Fatal(err)
	}
	defer reference.Destroy()
	protected, err := protector.Protect(credential.ReferenceContext{
		RevocationID: revocationID, ActionID: actionID, ActionEpoch: actionEpoch,
		Issuer: "vault-production", IssuerRevision: "rev-1",
	}, reference)
	if err != nil {
		t.Fatal(err)
	}
	return protected
}

func nullableString(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func boolPointer(value bool) *bool { return &value }

func nullableBytes(value []byte) any {
	if len(value) == 0 {
		return nil
	}
	return value
}

func nullableTime(value time.Time) any {
	if value.IsZero() {
		return nil
	}
	return value
}

func nullableInt64(value int64) any {
	if value == 0 {
		return nil
	}
	return value
}

func nullableInt32(value int32) any {
	if value == 0 {
		return nil
	}
	return int64(value)
}

func repositoryTestProtector(t *testing.T) credential.ReferenceProtector {
	t.Helper()
	protector, err := credential.NewAESGCMProtector(credential.KeyRing{
		ActiveKeyID: "postgres-key",
		Keys: map[string]credential.ProtectionKey{
			"postgres-key": {
				EncryptionKey: bytes.Repeat([]byte{0x71}, 32),
				HMACKey:       bytes.Repeat([]byte{0x72}, 32),
			},
		},
	})
	if err != nil {
		t.Fatalf("NewAESGCMProtector() error = %v", err)
	}
	t.Cleanup(protector.Destroy)
	return protector
}

func actionMetadataRows(now time.Time, fence credential.ActionFence, authorizationExpiresAt time.Time) *pgxmock.Rows {
	return actionMetadataRowsWithLease(now, fence, now.Add(time.Minute), authorizationExpiresAt)
}

func expectActionCredentialMarker(database pgxmock.PgxPoolIface, fence credential.ActionFence, tokenDigest string) {
	expectActionCredentialMarkerRows(database, fence, tokenDigest, 1)
}

func expectActionCredentialMarkerRows(
	database pgxmock.PgxPoolIface,
	fence credential.ActionFence,
	tokenDigest string,
	rowsAffected int64,
) {
	database.ExpectExec(actionCredentialMarkerUpdatePattern()).
		WithArgs(
			fence.ActionID, postgresTestTenantID, postgresTestWorkspaceID, postgresTestEnvironment,
			"cluster-a/payments", false, fence.RunnerID, fence.Epoch, tokenDigest,
		).
		WillReturnResult(pgxmock.NewResult("UPDATE", rowsAffected))
}

func actionCredentialMarkerUpdatePattern() string {
	query := strings.Join(strings.Fields(`
		UPDATE action_queue
		SET credential_expected = true,
			credential_lease_epoch = $8,
			updated_at = statement_timestamp()
		WHERE action_id = $1
		  AND runner_tenant_id = $2::uuid
		  AND runner_workspace_id = $3::uuid
		  AND runner_environment_id = $4::uuid
		  AND target_key = $5
		  AND production = $6
		  AND runner_id = $7
		  AND lease_epoch = $8
		  AND lease_token_sha256 = $9
		  AND runner_pool = 'WRITE'
		  AND status IN ('LEASED', 'RUNNING')
		  AND (
			(credential_expected = false AND credential_lease_epoch IS NULL) OR
			(credential_expected = true AND credential_lease_epoch = $8)
		  )
	`), " ")
	return "^" + regexp.QuoteMeta(query) + "$"
}

func runnerRegistrationRows(enabled bool, pool string, scopeRevision int64) *pgxmock.Rows {
	return pgxmock.NewRows([]string{"tenant_id", "runner_pool", "enabled", "scope_revision"}).
		AddRow(postgresTestTenantID, pool, enabled, scopeRevision)
}

func actionMetadataRowsForState(
	now time.Time,
	fence credential.ActionFence,
	status string,
	cancelRequestedAt time.Time,
	scopeRevision int64,
) *pgxmock.Rows {
	return pgxmock.NewRows([]string{
		"action_id", "tenant_id", "workspace_id", "environment_id", "target_key", "production", "runner_id",
		"lease_epoch", "status", "lease_expires_at", "authorization_expires_at", "runner_pool", "scope_revision",
		"cancel_requested_at", "action_type", "connector_id", "permission", "resource", "credential_ttl_seconds", "database_now",
	}).AddRow(
		fence.ActionID, postgresTestTenantID, postgresTestWorkspaceID, postgresTestEnvironment,
		"cluster-a/payments", false, fence.RunnerID, fence.Epoch, status, now.Add(time.Minute), now.Add(10*time.Minute),
		"WRITE", scopeRevision, nullableTime(cancelRequestedAt), "KUBERNETES_ROLLOUT_RESTART", "kubernetes-prod",
		"PATCH_DEPLOYMENT_RESTART", "cluster-a/payments/deployment/api", int64(600), now,
	)
}

func actionMetadataRowsWithLease(
	now time.Time,
	fence credential.ActionFence,
	leaseExpiresAt, authorizationExpiresAt time.Time,
) *pgxmock.Rows {
	return actionMetadataRowsWithBinding(now, fence, leaseExpiresAt, authorizationExpiresAt,
		"KUBERNETES_ROLLOUT_RESTART", 600)
}

func actionMetadataRowsWithBinding(
	now time.Time,
	fence credential.ActionFence,
	leaseExpiresAt, authorizationExpiresAt time.Time,
	actionType string,
	credentialTTLSeconds int32,
) *pgxmock.Rows {
	return pgxmock.NewRows([]string{
		"action_id", "tenant_id", "workspace_id", "environment_id", "target_key", "production", "runner_id",
		"lease_epoch", "status", "lease_expires_at", "authorization_expires_at", "runner_pool", "scope_revision",
		"cancel_requested_at", "action_type", "connector_id", "permission", "resource", "credential_ttl_seconds", "database_now",
	}).AddRow(
		fence.ActionID, postgresTestTenantID, postgresTestWorkspaceID, postgresTestEnvironment,
		"cluster-a/payments", false, fence.RunnerID, fence.Epoch, "RUNNING", leaseExpiresAt, authorizationExpiresAt,
		"WRITE", int64(7), nil, actionType, "kubernetes-prod", "PATCH_DEPLOYMENT_RESTART",
		"cluster-a/payments/deployment/api", int64(credentialTTLSeconds), now,
	)
}

func actionInspectionRows(now time.Time, fence credential.ActionFence, current bool) *pgxmock.Rows {
	runnerID := any(fence.RunnerID)
	leaseEpoch := any(fence.Epoch)
	status := any("RUNNING")
	leaseTokenDigest := any(credential.SHA256Hex([]byte(fence.Token)))
	leaseExpiresAt := any(now.Add(time.Minute))
	scopeRevision := any(int64(7))
	if !current {
		runnerID = nil
		leaseEpoch = int64(fence.Epoch)
		status = "QUEUED"
		leaseTokenDigest = nil
		leaseExpiresAt = nil
		scopeRevision = nil
	}
	return pgxmock.NewRows([]string{
		"action_id", "tenant_id", "workspace_id", "environment_id", "target_key", "production",
		"runner_id", "lease_epoch", "status", "lease_token_sha256", "lease_expires_at", "authorization_expires_at",
		"runner_pool", "scope_revision", "cancel_requested_at", "action_type", "connector_id", "permission", "resource",
		"credential_ttl_seconds", "database_now",
	}).AddRow(
		fence.ActionID, postgresTestTenantID, postgresTestWorkspaceID, postgresTestEnvironment,
		"cluster-a/payments", false, runnerID, leaseEpoch, status, leaseTokenDigest, leaseExpiresAt, now.Add(15*time.Minute),
		"WRITE", scopeRevision, nil, "KUBERNETES_ROLLOUT_RESTART", "kubernetes-prod", "PATCH_DEPLOYMENT_RESTART",
		"cluster-a/payments/deployment/api", int64(600), now,
	)
}

func actionInspectionRowsForState(
	now time.Time,
	fence credential.ActionFence,
	status string,
	cancelRequestedAt time.Time,
	scopeRevision int64,
) *pgxmock.Rows {
	return pgxmock.NewRows([]string{
		"action_id", "tenant_id", "workspace_id", "environment_id", "target_key", "production",
		"runner_id", "lease_epoch", "status", "lease_token_sha256", "lease_expires_at", "authorization_expires_at",
		"runner_pool", "scope_revision", "cancel_requested_at", "action_type", "connector_id", "permission", "resource",
		"credential_ttl_seconds", "database_now",
	}).AddRow(
		fence.ActionID, postgresTestTenantID, postgresTestWorkspaceID, postgresTestEnvironment,
		"cluster-a/payments", false, fence.RunnerID, fence.Epoch, status, credential.SHA256Hex([]byte(fence.Token)),
		now.Add(time.Minute), now.Add(15*time.Minute), "WRITE", scopeRevision, nullableTime(cancelRequestedAt),
		"KUBERNETES_ROLLOUT_RESTART", "kubernetes-prod", "PATCH_DEPLOYMENT_RESTART",
		"cluster-a/payments/deployment/api", int64(600), now,
	)
}
