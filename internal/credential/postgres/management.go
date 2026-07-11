package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/seaworld008/aiops-system/internal/credential"
	"github.com/seaworld008/aiops-system/internal/ids"
	"github.com/seaworld008/aiops-system/internal/requestmeta"
)

// managementProjection is intentionally independent from revocationProjection.
// The OIDC-facing store must never select protected references, bearer/claim
// digests, encryption metadata, or worker identity into its process.
const managementProjection = `
	revocation.tenant_id::text,
	revocation.revocation_id::text, revocation.workspace_id::text, revocation.environment_id::text,
	revocation.action_id, revocation.target_key, revocation.action_type, revocation.connector_id,
	revocation.status,
	(revocation.status IN ('ANCHORED', 'ACTIVE', 'REVOCATION_PENDING', 'REVOKING', 'MANUAL_REQUIRED')) AS accessor_present,
	revocation.credential_expires_at, revocation.attempt, revocation.failure_count,
	revocation.failure_code, revocation.failure_detail_sha256, revocation.available_at, revocation.evidence_hash,
	(SELECT count(*)::integer FROM credential_revocation_confirmations AS confirmation
	 WHERE confirmation.revocation_id = revocation.revocation_id) AS confirmation_count,
	COALESCE((SELECT bool_or(confirmation.platform_admin) FROM credential_revocation_confirmations AS confirmation
	 WHERE confirmation.revocation_id = revocation.revocation_id), false) AS platform_admin_confirmed,
	revocation.manual_required_at, revocation.revoked_at, revocation.version,
	revocation.created_at, revocation.updated_at
`

type Management struct {
	database DB
}

var _ credential.ManagementStore = (*Management)(nil)

type storedManagement struct {
	tenantID string
	record   credential.ManagementRecord
}

func NewManagement(database DB) (*Management, error) {
	if database == nil {
		return nil, credential.ErrInvalidRevocationRequest
	}
	return &Management{database: database}, nil
}

func (store *Management) GetManagement(
	ctx context.Context,
	request credential.ManagementGetRequest,
) (credential.ManagementRecord, error) {
	if err := validateContext(ctx); err != nil {
		return credential.ManagementRecord{}, err
	}
	if !validManagementRequest(request.Scope, request.Actor) || !credential.ValidRevocationID(request.RevocationID) {
		return credential.ManagementRecord{}, credential.ErrInvalidRevocationRequest
	}
	tx, err := store.database.Begin(ctx)
	if err != nil {
		return credential.ManagementRecord{}, databaseError("begin credential revocation management get", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()
	tenantID, err := resolveManagementTenant(ctx, tx, request.Scope)
	if err != nil {
		return credential.ManagementRecord{}, err
	}

	stored, err := selectManagement(ctx, tx, `
		SELECT `+managementProjection+`
		FROM credential_revocations AS revocation
		WHERE revocation.revocation_id = $1
		  AND revocation.workspace_id = $2::uuid
		  AND revocation.environment_id = $3::uuid
	`, request.RevocationID, request.Scope.WorkspaceID, request.Scope.EnvironmentID)
	if errors.Is(err, pgx.ErrNoRows) {
		if err := writeManagementAttemptAudit(ctx, tx, tenantID, request.Scope, request.Actor,
			request.RevocationID, "credential.revocation.management.read_not_found", "NOT_FOUND", ""); err != nil {
			return credential.ManagementRecord{}, err
		}
		if err := tx.Commit(ctx); err != nil {
			return credential.ManagementRecord{}, databaseError("commit credential revocation management get not found audit", err)
		}
		committed = true
		return credential.ManagementRecord{}, credential.ErrRevocationNotFound
	}
	if err != nil {
		return credential.ManagementRecord{}, databaseError("read credential revocation management record", err)
	}
	if !validStoredManagement(stored, request.Scope, tenantID) {
		return credential.ManagementRecord{}, credential.ErrRevocationPersistence
	}
	if err := writeManagementAudit(ctx, tx, stored.tenantID, request.Actor,
		"credential.revocation.management.read", stored.record.ID, managementRecordDetails(stored.record, request.Actor)); err != nil {
		return credential.ManagementRecord{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return credential.ManagementRecord{}, databaseError("commit credential revocation management get", err)
	}
	committed = true
	return stored.record, nil
}

func validManagementRequest(scope credential.ManagementScope, actor credential.ManagementActor) bool {
	return credential.ValidManagementScope(scope) && credential.ValidManagementActor(actor)
}

func resolveManagementTenant(ctx context.Context, tx pgx.Tx, scope credential.ManagementScope) (string, error) {
	var tenantID string
	err := tx.QueryRow(ctx, `
		SELECT tenant_id::text
		FROM environments
		WHERE workspace_id = $1::uuid AND id = $2::uuid
	`, scope.WorkspaceID, scope.EnvironmentID).Scan(&tenantID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", credential.ErrRevocationNotFound
	}
	if err != nil {
		return "", databaseError("resolve credential revocation management scope", err)
	}
	if !credential.ValidRevocationID(tenantID) {
		return "", credential.ErrRevocationPersistence
	}
	return tenantID, nil
}

func selectManagement(ctx context.Context, querier rowQuerier, query string, args ...any) (*storedManagement, error) {
	return scanManagement(querier.QueryRow(ctx, query, args...))
}

func scanManagement(row rowScanner) (*storedManagement, error) {
	var stored storedManagement
	var status string
	var failureCode, failureDetail, evidence pgtype.Text
	var manualAt, revokedAt pgtype.Timestamptz
	var attempt, failureCount, confirmationCount int32
	if err := row.Scan(
		&stored.tenantID,
		&stored.record.ID, &stored.record.WorkspaceID, &stored.record.EnvironmentID,
		&stored.record.ActionID, &stored.record.TargetKey, &stored.record.ActionType, &stored.record.ConnectorID,
		&status, &stored.record.AccessorPresent, &stored.record.CredentialExpiresAt,
		&attempt, &failureCount, &failureCode, &failureDetail,
		&stored.record.AvailableAt, &evidence, &confirmationCount, &stored.record.PlatformAdminConfirmed,
		&manualAt, &revokedAt, &stored.record.Version, &stored.record.CreatedAt, &stored.record.UpdatedAt,
	); err != nil {
		return nil, err
	}
	stored.record.Status = credential.RevocationStatus(status)
	stored.record.Attempt = int(attempt)
	stored.record.FailureCount = int(failureCount)
	stored.record.FailureCode = credential.FailureCode(textValue(failureCode))
	stored.record.FailureDetailSHA256 = textValue(failureDetail)
	stored.record.EvidenceHash = textValue(evidence)
	stored.record.ConfirmationCount = int(confirmationCount)
	stored.record.ManualRequiredAt = timeValue(manualAt)
	stored.record.RevokedAt = timeValue(revokedAt)
	canonicalizeManagementTimes(&stored.record)
	return &stored, nil
}

func canonicalizeManagementTimes(record *credential.ManagementRecord) {
	record.CredentialExpiresAt = record.CredentialExpiresAt.UTC()
	record.AvailableAt = record.AvailableAt.UTC()
	record.CreatedAt = record.CreatedAt.UTC()
	record.UpdatedAt = record.UpdatedAt.UTC()
}

func managementRecordDetails(record credential.ManagementRecord, actor credential.ManagementActor) map[string]any {
	return map[string]any{
		"revocation_id":            record.ID,
		"workspace_id":             record.WorkspaceID,
		"environment_id":           record.EnvironmentID,
		"status":                   record.Status,
		"version":                  record.Version,
		"evidence_hash":            record.EvidenceHash,
		"confirmation_count":       record.ConfirmationCount,
		"platform_admin_confirmed": record.PlatformAdminConfirmed,
		"actor_platform_admin":     actor.PlatformAdmin,
		"failure_count":            record.FailureCount,
		"failure_code":             record.FailureCode,
		"failure_detail_sha256":    record.FailureDetailSHA256,
	}
}

func writeManagementAttemptAudit(
	ctx context.Context,
	tx pgx.Tx,
	tenantID string,
	scope credential.ManagementScope,
	actor credential.ManagementActor,
	revocationID string,
	action string,
	decision string,
	evidenceHash string,
) error {
	details := map[string]any{
		"revocation_id":            revocationID,
		"workspace_id":             scope.WorkspaceID,
		"environment_id":           scope.EnvironmentID,
		"decision":                 decision,
		"status":                   "",
		"version":                  int64(0),
		"evidence_hash":            evidenceHash,
		"confirmation_count":       0,
		"platform_admin_confirmed": false,
		"actor_platform_admin":     actor.PlatformAdmin,
		"failure_count":            0,
		"failure_code":             "",
		"failure_detail_sha256":    "",
	}
	return writeManagementAudit(ctx, tx, tenantID, actor, action, revocationID, details)
}

func writeManagementRejectedAudit(
	ctx context.Context,
	tx pgx.Tx,
	stored *storedManagement,
	actor credential.ManagementActor,
	action string,
	reason string,
) error {
	details := managementRecordDetails(stored.record, actor)
	details["decision"] = "REJECTED"
	details["reason"] = reason
	return writeManagementAudit(ctx, tx, stored.tenantID, actor, action, stored.record.ID, details)
}

func writeManagementAudit(
	ctx context.Context,
	tx pgx.Tx,
	tenantID string,
	actor credential.ManagementActor,
	action string,
	resourceID string,
	details map[string]any,
) error {
	encoded, err := json.Marshal(details)
	if err != nil {
		return fmt.Errorf("encode credential revocation management audit: %w", err)
	}
	metadata := requestmeta.From(ctx)
	if metadata.RequestID == "" {
		metadata.RequestID = ids.NewUUID()
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO audit_records (
			id, tenant_id, workspace_id, actor_type, actor_id, action,
			resource_type, resource_id, request_id, trace_id, payload_hash, details
		) VALUES ($1, $2, $3, $4, $5, $6, 'CREDENTIAL_REVOCATION', $7, $8, $9, $10, $11)
	`, ids.NewUUID(), tenantID, details["workspace_id"], "USER", actor.Subject, action, resourceID,
		metadata.RequestID, nullableText(metadata.TraceID), credential.SHA256Hex(encoded), string(encoded))
	if err != nil {
		return databaseError("insert credential revocation management audit", err)
	}
	return nil
}

func (store *Management) ListManagement(
	ctx context.Context,
	request credential.ManagementListRequest,
) (credential.ManagementPage, error) {
	if err := validateContext(ctx); err != nil {
		return credential.ManagementPage{}, err
	}
	if !validManagementRequest(request.Scope, request.Actor) || !credential.ValidRevocationStatus(request.Status) ||
		request.Limit < 0 || request.Limit > credential.MaxManagementPageSize || !credential.ValidManagementCursor(request.After) {
		return credential.ManagementPage{}, credential.ErrInvalidRevocationRequest
	}
	limit := request.Limit
	if limit == 0 {
		limit = credential.DefaultManagementPageSize
	}
	tx, err := store.database.Begin(ctx)
	if err != nil {
		return credential.ManagementPage{}, databaseError("begin credential revocation management list", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()

	tenantID, err := resolveManagementTenant(ctx, tx, request.Scope)
	if err != nil {
		return credential.ManagementPage{}, err
	}
	var afterTime any
	var afterID any
	if request.After != nil {
		afterTime = request.After.CreatedAt.UTC()
		afterID = request.After.RevocationID
	}
	rows, err := tx.Query(ctx, `
		SELECT `+managementProjection+`
		FROM credential_revocations AS revocation
		WHERE revocation.workspace_id = $1::uuid
		  AND revocation.environment_id = $2::uuid
		  AND revocation.status = $3
		  AND ($4::timestamptz IS NULL OR
		       (revocation.created_at, revocation.revocation_id) < ($4::timestamptz, $5::uuid))
		ORDER BY revocation.created_at DESC, revocation.revocation_id DESC
		LIMIT $6
	`, request.Scope.WorkspaceID, request.Scope.EnvironmentID, string(request.Status), afterTime, afterID, limit+1)
	if err != nil {
		return credential.ManagementPage{}, databaseError("list credential revocation management records", err)
	}
	defer rows.Close()
	items := make([]credential.ManagementRecord, 0, limit+1)
	for rows.Next() {
		stored, scanErr := scanManagement(rows)
		if scanErr != nil {
			return credential.ManagementPage{}, databaseError("scan credential revocation management list", scanErr)
		}
		if !validStoredManagement(stored, request.Scope, tenantID) || stored.record.Status != request.Status {
			return credential.ManagementPage{}, credential.ErrRevocationPersistence
		}
		items = append(items, stored.record)
	}
	if err := rows.Err(); err != nil {
		return credential.ManagementPage{}, databaseError("iterate credential revocation management list", err)
	}
	hasNext := len(items) > limit
	if hasNext {
		items = items[:limit]
	}
	page := credential.ManagementPage{Items: items}
	if hasNext {
		last := items[len(items)-1]
		page.Next = &credential.ManagementCursor{CreatedAt: last.CreatedAt, RevocationID: last.ID}
	}
	details := map[string]any{
		"workspace_id":             request.Scope.WorkspaceID,
		"environment_id":           request.Scope.EnvironmentID,
		"status":                   request.Status,
		"version":                  int64(0),
		"evidence_hash":            "",
		"confirmation_count":       0,
		"platform_admin_confirmed": false,
		"failure_count":            0,
		"failure_code":             "",
		"failure_detail_sha256":    "",
		"returned_count":           len(items),
		"next_page":                hasNext,
		"actor_platform_admin":     request.Actor.PlatformAdmin,
		"records":                  managementRecordsDetails(items),
	}
	if err := writeManagementAudit(ctx, tx, tenantID, request.Actor,
		"credential.revocation.management.list", request.Scope.EnvironmentID, details); err != nil {
		return credential.ManagementPage{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return credential.ManagementPage{}, databaseError("commit credential revocation management list", err)
	}
	committed = true
	return page, nil
}

func managementRecordsDetails(records []credential.ManagementRecord) []map[string]any {
	details := make([]map[string]any, 0, len(records))
	for _, record := range records {
		details = append(details, managementRecordDetails(record, credential.ManagementActor{}))
	}
	return details
}

func (store *Management) RequeueManagement(
	ctx context.Context,
	request credential.ManagementRequeueRequest,
) (credential.ManagementRecord, error) {
	if err := validateContext(ctx); err != nil {
		return credential.ManagementRecord{}, err
	}
	if !validManagementRequest(request.Scope, request.Actor) || !request.Actor.PlatformAdmin ||
		!credential.ValidRevocationID(request.RevocationID) {
		return credential.ManagementRecord{}, credential.ErrInvalidRevocationRequest
	}
	tx, err := store.database.Begin(ctx)
	if err != nil {
		return credential.ManagementRecord{}, databaseError("begin credential revocation management requeue", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()
	tenantID, err := resolveManagementTenant(ctx, tx, request.Scope)
	if err != nil {
		return credential.ManagementRecord{}, err
	}

	var changedID string
	err = tx.QueryRow(ctx, `
		UPDATE credential_revocations AS revocation
		SET status = 'REVOCATION_PENDING', available_at = statement_timestamp(),
			retry_cycle_attempt_base = attempt, retry_cycle_started_at = statement_timestamp(),
			updated_at = statement_timestamp(), version = version + 1
		WHERE revocation.revocation_id = $1
		  AND revocation.workspace_id = $2::uuid
		  AND revocation.environment_id = $3::uuid
		  AND revocation.status = 'MANUAL_REQUIRED'
		  AND revocation.evidence_hash IS NULL
		  AND NOT EXISTS (
			SELECT 1 FROM credential_revocation_confirmations AS confirmation
			WHERE confirmation.revocation_id = revocation.revocation_id
		  )
		RETURNING revocation.revocation_id::text
	`, request.RevocationID, request.Scope.WorkspaceID, request.Scope.EnvironmentID).Scan(&changedID)
	changed := err == nil
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return credential.ManagementRecord{}, databaseError("requeue credential revocation management record", err)
	}
	if err := lockScopedManagement(ctx, tx, request.Scope, request.RevocationID); err != nil {
		if errors.Is(err, credential.ErrRevocationNotFound) {
			if err := writeManagementAttemptAudit(ctx, tx, tenantID, request.Scope, request.Actor,
				request.RevocationID, "credential.revocation.requeue_not_found", "NOT_FOUND", ""); err != nil {
				return credential.ManagementRecord{}, err
			}
			if err := tx.Commit(ctx); err != nil {
				return credential.ManagementRecord{}, databaseError("commit credential revocation management requeue not found audit", err)
			}
			committed = true
		}
		return credential.ManagementRecord{}, err
	}
	stored, readErr := getScopedManagement(ctx, tx, request.Scope, request.RevocationID)
	if readErr != nil {
		return credential.ManagementRecord{}, readErr
	}
	if !validStoredManagement(stored, request.Scope, tenantID) {
		return credential.ManagementRecord{}, credential.ErrRevocationPersistence
	}
	if !changed {
		if stored.record.Status != credential.StatusRevocationPending || stored.record.EvidenceHash != "" ||
			stored.record.ConfirmationCount != 0 {
			if err := writeManagementRejectedAudit(ctx, tx, stored, request.Actor,
				"credential.revocation.requeue_rejected", "INVALID_TRANSITION"); err != nil {
				return credential.ManagementRecord{}, err
			}
			if err := tx.Commit(ctx); err != nil {
				return credential.ManagementRecord{}, databaseError("commit credential revocation management requeue rejection audit", err)
			}
			committed = true
			return credential.ManagementRecord{}, credential.ErrInvalidTransition
		}
		if err := writeManagementAudit(ctx, tx, stored.tenantID, request.Actor,
			"credential.revocation.requeue_replayed", stored.record.ID,
			managementRecordDetails(stored.record, request.Actor)); err != nil {
			return credential.ManagementRecord{}, err
		}
		if err := tx.Commit(ctx); err != nil {
			return credential.ManagementRecord{}, databaseError("commit idempotent credential revocation management requeue", err)
		}
		committed = true
		return stored.record, nil
	}
	if changedID != stored.record.ID || stored.record.Status != credential.StatusRevocationPending ||
		stored.record.EvidenceHash != "" || stored.record.ConfirmationCount != 0 {
		return credential.ManagementRecord{}, credential.ErrRevocationPersistence
	}
	if err := writeManagementStateChange(ctx, tx, stored, request.Actor,
		"credential.revocation.requeued", "credential.revocation.requeued.v1"); err != nil {
		return credential.ManagementRecord{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return credential.ManagementRecord{}, databaseError("commit credential revocation management requeue", err)
	}
	committed = true
	return stored.record, nil
}

func (store *Management) ConfirmManagement(
	ctx context.Context,
	request credential.ManagementConfirmationRequest,
) (credential.ManagementRecord, error) {
	if err := validateContext(ctx); err != nil {
		return credential.ManagementRecord{}, err
	}
	if !validManagementRequest(request.Scope, request.Actor) || !credential.ValidRevocationID(request.RevocationID) ||
		!credential.ValidSHA256(request.EvidenceHash) {
		return credential.ManagementRecord{}, credential.ErrInvalidRevocationRequest
	}
	tx, err := store.database.Begin(ctx)
	if err != nil {
		return credential.ManagementRecord{}, databaseError("begin credential revocation management confirmation", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()
	tenantID, err := resolveManagementTenant(ctx, tx, request.Scope)
	if err != nil {
		return credential.ManagementRecord{}, err
	}

	if err := lockScopedManagement(ctx, tx, request.Scope, request.RevocationID); err != nil {
		if !errors.Is(err, credential.ErrRevocationNotFound) {
			return credential.ManagementRecord{}, err
		}
		if err := writeManagementAttemptAudit(ctx, tx, tenantID, request.Scope, request.Actor,
			request.RevocationID, "credential.revocation.confirmation_not_found", "NOT_FOUND", request.EvidenceHash); err != nil {
			return credential.ManagementRecord{}, err
		}
		if err := tx.Commit(ctx); err != nil {
			return credential.ManagementRecord{}, databaseError("commit credential revocation management confirmation not found audit", err)
		}
		committed = true
		return credential.ManagementRecord{}, credential.ErrRevocationNotFound
	}
	stored, err := getScopedManagement(ctx, tx, request.Scope, request.RevocationID)
	if err != nil {
		return credential.ManagementRecord{}, err
	}
	if !validStoredManagement(stored, request.Scope, tenantID) {
		return credential.ManagementRecord{}, credential.ErrRevocationPersistence
	}
	if stored.record.Status != credential.StatusManualRequired && stored.record.Status != credential.StatusRevoked {
		if err := writeManagementRejectedAudit(ctx, tx, stored, request.Actor,
			"credential.revocation.confirmation_rejected", "INVALID_TRANSITION"); err != nil {
			return credential.ManagementRecord{}, err
		}
		if err := tx.Commit(ctx); err != nil {
			return credential.ManagementRecord{}, databaseError("commit credential revocation management confirmation rejection audit", err)
		}
		committed = true
		return credential.ManagementRecord{}, credential.ErrInvalidTransition
	}
	if stored.record.EvidenceHash != "" && stored.record.EvidenceHash != request.EvidenceHash {
		if err := writeManagementRejectedAudit(ctx, tx, stored, request.Actor,
			"credential.revocation.confirmation_rejected", "EVIDENCE_CONFLICT"); err != nil {
			return credential.ManagementRecord{}, err
		}
		if err := tx.Commit(ctx); err != nil {
			return credential.ManagementRecord{}, databaseError("commit credential revocation management evidence rejection audit", err)
		}
		committed = true
		return credential.ManagementRecord{}, credential.ErrEvidenceConflict
	}
	confirmations, err := readManagementConfirmations(ctx, tx, request.Scope, request.RevocationID)
	if err != nil {
		return credential.ManagementRecord{}, err
	}
	count, adminConfirmed := confirmationSummary(confirmations)
	if count != stored.record.ConfirmationCount || adminConfirmed != stored.record.PlatformAdminConfirmed {
		return credential.ManagementRecord{}, credential.ErrRevocationPersistence
	}
	for _, confirmation := range confirmations {
		if confirmation.Subject != request.Actor.Subject {
			continue
		}
		if confirmation.EvidenceHash != request.EvidenceHash || confirmation.PlatformAdmin != request.Actor.PlatformAdmin {
			if err := writeManagementRejectedAudit(ctx, tx, stored, request.Actor,
				"credential.revocation.confirmation_rejected", "EVIDENCE_CONFLICT"); err != nil {
				return credential.ManagementRecord{}, err
			}
			if err := tx.Commit(ctx); err != nil {
				return credential.ManagementRecord{}, databaseError("commit credential revocation management replay rejection audit", err)
			}
			committed = true
			return credential.ManagementRecord{}, credential.ErrEvidenceConflict
		}
		if err := writeManagementAudit(ctx, tx, stored.tenantID, request.Actor,
			"credential.revocation.confirmation_replayed", stored.record.ID,
			managementRecordDetails(stored.record, request.Actor)); err != nil {
			return credential.ManagementRecord{}, err
		}
		if err := tx.Commit(ctx); err != nil {
			return credential.ManagementRecord{}, databaseError("commit idempotent credential revocation management confirmation", err)
		}
		committed = true
		return stored.record, nil
	}
	if stored.record.Status == credential.StatusRevoked || len(confirmations) >= 2 {
		if err := writeManagementRejectedAudit(ctx, tx, stored, request.Actor,
			"credential.revocation.confirmation_rejected", "INVALID_TRANSITION"); err != nil {
			return credential.ManagementRecord{}, err
		}
		if err := tx.Commit(ctx); err != nil {
			return credential.ManagementRecord{}, databaseError("commit credential revocation management terminal rejection audit", err)
		}
		committed = true
		return credential.ManagementRecord{}, credential.ErrInvalidTransition
	}
	if len(confirmations) == 1 && !request.Actor.PlatformAdmin && !confirmations[0].PlatformAdmin {
		if err := writeManagementRejectedAudit(ctx, tx, stored, request.Actor,
			"credential.revocation.confirmation_rejected", "PLATFORM_ADMIN_REQUIRED"); err != nil {
			return credential.ManagementRecord{}, err
		}
		if err := tx.Commit(ctx); err != nil {
			return credential.ManagementRecord{}, databaseError("commit credential revocation management admin rejection audit", err)
		}
		committed = true
		return credential.ManagementRecord{}, credential.ErrPlatformAdminRequired
	}
	if len(confirmations) == 0 {
		var changedID string
		err = tx.QueryRow(ctx, `
			UPDATE credential_revocations AS revocation
			SET evidence_hash = $4, updated_at = statement_timestamp(), version = version + 1
			WHERE revocation.revocation_id = $1
			  AND revocation.workspace_id = $2::uuid
			  AND revocation.environment_id = $3::uuid
			  AND revocation.status = 'MANUAL_REQUIRED'
			  AND revocation.evidence_hash IS NULL
			RETURNING revocation.revocation_id::text
		`, request.RevocationID, request.Scope.WorkspaceID, request.Scope.EnvironmentID, request.EvidenceHash).Scan(&changedID)
		if errors.Is(err, pgx.ErrNoRows) {
			return credential.ManagementRecord{}, credential.ErrInvalidTransition
		}
		if err != nil {
			return credential.ManagementRecord{}, databaseError("record credential revocation management evidence", err)
		}
		if changedID != request.RevocationID {
			return credential.ManagementRecord{}, credential.ErrRevocationPersistence
		}
	}
	var confirmationCreatedAt time.Time
	err = tx.QueryRow(ctx, `
		INSERT INTO credential_revocation_confirmations (
			revocation_id, subject, evidence_hash, platform_admin
		)
		SELECT revocation.revocation_id, $4, $5, $6
		FROM credential_revocations AS revocation
		WHERE revocation.revocation_id = $1
		  AND revocation.workspace_id = $2::uuid
		  AND revocation.environment_id = $3::uuid
		  AND revocation.status = 'MANUAL_REQUIRED'
		  AND revocation.evidence_hash = $5
		RETURNING created_at
	`, request.RevocationID, request.Scope.WorkspaceID, request.Scope.EnvironmentID,
		request.Actor.Subject, request.EvidenceHash, request.Actor.PlatformAdmin).Scan(&confirmationCreatedAt)
	if isUniqueViolation(err) {
		return credential.ManagementRecord{}, credential.ErrEvidenceConflict
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return credential.ManagementRecord{}, credential.ErrInvalidTransition
	}
	if err != nil {
		return credential.ManagementRecord{}, databaseError("insert credential revocation management confirmation", err)
	}
	confirmationCreatedAt = confirmationCreatedAt.UTC()
	if len(confirmations) == 1 {
		var changedID string
		err = tx.QueryRow(ctx, `
			UPDATE credential_revocations AS revocation
			SET status = 'REVOKED', accessor_ciphertext = NULL, encryption_key_id = NULL,
				revoked_at = statement_timestamp(), updated_at = statement_timestamp(), version = version + 1
			WHERE revocation.revocation_id = $1
			  AND revocation.workspace_id = $2::uuid
			  AND revocation.environment_id = $3::uuid
			  AND revocation.status = 'MANUAL_REQUIRED'
			  AND revocation.evidence_hash = $4
			RETURNING revocation.revocation_id::text
		`, request.RevocationID, request.Scope.WorkspaceID, request.Scope.EnvironmentID, request.EvidenceHash).Scan(&changedID)
		if errors.Is(err, pgx.ErrNoRows) {
			return credential.ManagementRecord{}, credential.ErrInvalidTransition
		}
		if err != nil {
			return credential.ManagementRecord{}, databaseError("complete credential revocation management confirmation", err)
		}
		if changedID != request.RevocationID {
			return credential.ManagementRecord{}, credential.ErrRevocationPersistence
		}
	}
	stored, err = getScopedManagement(ctx, tx, request.Scope, request.RevocationID)
	if err != nil {
		return credential.ManagementRecord{}, err
	}
	if !validStoredManagement(stored, request.Scope, tenantID) || stored.record.EvidenceHash != request.EvidenceHash ||
		stored.record.ConfirmationCount != len(confirmations)+1 {
		return credential.ManagementRecord{}, credential.ErrRevocationPersistence
	}
	auditAction := "credential.revocation.confirmation_recorded"
	eventType := "credential.revocation.confirmation_recorded.v1"
	if len(confirmations) == 1 {
		if stored.record.Status != credential.StatusRevoked || stored.record.AccessorPresent ||
			!stored.record.PlatformAdminConfirmed {
			return credential.ManagementRecord{}, credential.ErrRevocationPersistence
		}
		auditAction = "credential.revocation.externally_confirmed"
		eventType = "credential.revocation.externally_confirmed.v1"
	} else if stored.record.Status != credential.StatusManualRequired {
		return credential.ManagementRecord{}, credential.ErrRevocationPersistence
	}
	if err := writeManagementStateChange(ctx, tx, stored, request.Actor, auditAction, eventType); err != nil {
		return credential.ManagementRecord{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return credential.ManagementRecord{}, databaseError("commit credential revocation management confirmation", err)
	}
	committed = true
	return stored.record, nil
}

func readManagementConfirmations(
	ctx context.Context,
	tx pgx.Tx,
	scope credential.ManagementScope,
	revocationID string,
) ([]credential.ExternalConfirmation, error) {
	rows, err := tx.Query(ctx, `
		SELECT confirmation.subject, confirmation.evidence_hash,
			confirmation.platform_admin, confirmation.created_at
		FROM credential_revocation_confirmations AS confirmation
		JOIN credential_revocations AS revocation
		  ON revocation.revocation_id = confirmation.revocation_id
		WHERE confirmation.revocation_id = $1
		  AND revocation.workspace_id = $2::uuid
		  AND revocation.environment_id = $3::uuid
		ORDER BY confirmation.created_at, confirmation.subject
	`, revocationID, scope.WorkspaceID, scope.EnvironmentID)
	if err != nil {
		return nil, databaseError("read scoped credential revocation management confirmations", err)
	}
	defer rows.Close()
	confirmations := make([]credential.ExternalConfirmation, 0, 2)
	for rows.Next() {
		var confirmation credential.ExternalConfirmation
		if err := rows.Scan(&confirmation.Subject, &confirmation.EvidenceHash,
			&confirmation.PlatformAdmin, &confirmation.CreatedAt); err != nil {
			return nil, databaseError("scan credential revocation management confirmation", err)
		}
		confirmation.CreatedAt = confirmation.CreatedAt.UTC()
		if !credential.ValidConfirmationSubject(confirmation.Subject) || !credential.ValidSHA256(confirmation.EvidenceHash) {
			return nil, credential.ErrRevocationPersistence
		}
		confirmations = append(confirmations, confirmation)
	}
	if err := rows.Err(); err != nil {
		return nil, databaseError("iterate credential revocation management confirmations", err)
	}
	return confirmations, nil
}

func confirmationSummary(confirmations []credential.ExternalConfirmation) (int, bool) {
	admin := false
	for _, confirmation := range confirmations {
		admin = admin || confirmation.PlatformAdmin
	}
	return len(confirmations), admin
}

func getScopedManagement(
	ctx context.Context,
	tx pgx.Tx,
	scope credential.ManagementScope,
	revocationID string,
) (*storedManagement, error) {
	stored, err := selectManagement(ctx, tx, `
		SELECT `+managementProjection+`
		FROM credential_revocations AS revocation
		WHERE revocation.revocation_id = $1
		  AND revocation.workspace_id = $2::uuid
		  AND revocation.environment_id = $3::uuid
	`, revocationID, scope.WorkspaceID, scope.EnvironmentID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, credential.ErrRevocationNotFound
	}
	if err != nil {
		return nil, databaseError("read scoped credential revocation management record", err)
	}
	return stored, nil
}

func lockScopedManagement(
	ctx context.Context,
	tx pgx.Tx,
	scope credential.ManagementScope,
	revocationID string,
) error {
	var lockedID string
	err := tx.QueryRow(ctx, `
		SELECT revocation.revocation_id::text
		FROM credential_revocations AS revocation
		WHERE revocation.revocation_id = $1
		  AND revocation.workspace_id = $2::uuid
		  AND revocation.environment_id = $3::uuid
		FOR UPDATE OF revocation
	`, revocationID, scope.WorkspaceID, scope.EnvironmentID).Scan(&lockedID)
	if errors.Is(err, pgx.ErrNoRows) {
		return credential.ErrRevocationNotFound
	}
	if err != nil {
		return databaseError("lock scoped credential revocation management record", err)
	}
	if lockedID != revocationID {
		return credential.ErrRevocationPersistence
	}
	return nil
}

func validStoredManagement(stored *storedManagement, scope credential.ManagementScope, tenantID string) bool {
	if stored == nil || !credential.ValidRevocationID(stored.tenantID) ||
		stored.record.WorkspaceID != scope.WorkspaceID || stored.record.EnvironmentID != scope.EnvironmentID ||
		(tenantID != "" && stored.tenantID != tenantID) {
		return false
	}
	return credential.ValidManagementRecord(stored.record)
}

func writeManagementStateChange(
	ctx context.Context,
	tx pgx.Tx,
	stored *storedManagement,
	actor credential.ManagementActor,
	auditAction string,
	eventType string,
) error {
	details := managementRecordDetails(stored.record, actor)
	if err := writeManagementAudit(ctx, tx, stored.tenantID, actor, auditAction, stored.record.ID, details); err != nil {
		return err
	}
	encoded, err := json.Marshal(details)
	if err != nil {
		return fmt.Errorf("encode credential revocation management outbox: %w", err)
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO outbox_events (
			id, tenant_id, workspace_id, aggregate_type, aggregate_id, aggregate_version,
			event_type, payload, created_at, available_at
		) VALUES ($1, $2, $3, 'CREDENTIAL_REVOCATION', $4, $5, $6, $7,
			statement_timestamp(), statement_timestamp())
	`, ids.NewUUID(), stored.tenantID, stored.record.WorkspaceID, stored.record.ID,
		stored.record.Version, eventType, string(encoded))
	if err != nil {
		return databaseError("insert credential revocation management outbox event", err)
	}
	return nil
}
