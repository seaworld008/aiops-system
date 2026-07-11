package postgres

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/seaworld008/aiops-system/internal/store"
)

const (
	operationCreateInvestigation   = "create_investigation"
	operationCompleteTask          = "complete_task"
	operationStartModel            = "start_model"
	operationFinalizeInvestigation = "finalize_investigation"
	operationFailInvestigation     = "fail_investigation"
	operationRecordFeedback        = "record_feedback"

	requestVersionCreateInvestigation   = "investigation.create.v1"
	requestVersionCompleteTask          = "investigation.complete-task.v1"
	requestVersionStartModel            = "investigation.start-model.v1"
	requestVersionFinalizeInvestigation = "investigation.finalize.v1"
	requestVersionFailInvestigation     = "investigation.fail.v1"
	requestVersionRecordFeedback        = "investigation.feedback.v1"

	snapshotVersionStartModel = "investigation.start-model-result.v1"
	snapshotVersionFinalize   = "investigation.finalize-result.v1"
)

type idempotencyRecord struct {
	operation       string
	requestHash     string
	requestVersion  string
	resourceType    string
	resourceID      string
	resultSnapshot  []byte
	snapshotDigest  string
	snapshotVersion string
}

func lockIdempotencyKey(
	ctx context.Context,
	tx pgx.Tx,
	tenantID, workspaceID, idempotencyKey string,
) error {
	result, err := tx.Exec(ctx, `
		SELECT pg_catalog.pg_advisory_xact_lock(
			pg_catalog.hashtextextended(
				'investigation-idempotency.v1:' || workspace.tenant_id::text || ':' ||
				workspace.id::text || ':' || $3::text,
				0
			)
		)
		FROM workspaces AS workspace
		WHERE workspace.tenant_id = $1 AND workspace.id = $2
	`, tenantID, workspaceID, idempotencyKey)
	if err != nil {
		return databaseError("lock investigation idempotency key", err)
	}
	if result.RowsAffected() != 1 {
		return store.ErrNotFound
	}
	return nil
}

func readIdempotencyRecord(
	ctx context.Context,
	tx pgx.Tx,
	tenantID, workspaceID, idempotencyKey string,
) (idempotencyRecord, error) {
	var record idempotencyRecord
	var snapshotDigest, snapshotVersion pgtype.Text
	err := tx.QueryRow(ctx, `
		SELECT operation, request_hash, request_hash_version, resource_type, resource_id::text,
		       result_snapshot, result_snapshot_sha256, result_snapshot_version
		FROM investigation_idempotency_records
		WHERE tenant_id = $1 AND workspace_id = $2 AND idempotency_key = $3
		FOR SHARE
	`, tenantID, workspaceID, idempotencyKey).Scan(
		&record.operation, &record.requestHash, &record.requestVersion,
		&record.resourceType, &record.resourceID, &record.resultSnapshot,
		&snapshotDigest, &snapshotVersion,
	)
	if err != nil {
		return idempotencyRecord{}, err
	}
	snapshotAbsent := len(record.resultSnapshot) == 0 && !snapshotDigest.Valid && !snapshotVersion.Valid
	snapshotPresent := len(record.resultSnapshot) > 0 && snapshotDigest.Valid && snapshotVersion.Valid
	if !snapshotAbsent && !snapshotPresent {
		return idempotencyRecord{}, fmt.Errorf("investigation persistence failure")
	}
	if len(record.resultSnapshot) > 0 {
		if len(record.resultSnapshot) > maxSnapshotBytes ||
			subtle.ConstantTimeCompare([]byte(snapshotSHA256Hex(record.resultSnapshot)), []byte(snapshotDigest.String)) != 1 {
			return idempotencyRecord{}, fmt.Errorf("investigation persistence failure")
		}
		record.snapshotDigest = snapshotDigest.String
		record.snapshotVersion = snapshotVersion.String
	}
	return record, nil
}

func requireIdempotencyReplay(
	record idempotencyRecord,
	operation, requestHash, requestVersion string,
) error {
	if record.operation != operation || record.requestHash != requestHash || record.requestVersion != requestVersion {
		return store.ErrIdempotencyConflict
	}
	return nil
}

func insertIdempotencyRecord(
	ctx context.Context,
	tx pgx.Tx,
	tenantID, workspaceID, idempotencyKey string,
	record idempotencyRecord,
) error {
	var snapshot, snapshotDigest, snapshotVersion any
	if len(record.resultSnapshot) > 0 {
		if len(record.resultSnapshot) > maxSnapshotBytes ||
			snapshotSHA256Hex(record.resultSnapshot) != record.snapshotDigest || record.snapshotVersion == "" {
			return fmt.Errorf("investigation persistence failure")
		}
		snapshot = record.resultSnapshot
		snapshotDigest = record.snapshotDigest
		snapshotVersion = record.snapshotVersion
	}
	result, err := tx.Exec(ctx, `
		INSERT INTO investigation_idempotency_records (
			tenant_id, workspace_id, idempotency_key, operation,
			request_hash, request_hash_version, resource_type, resource_id,
			result_snapshot, result_snapshot_sha256, result_snapshot_version
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		ON CONFLICT (workspace_id, idempotency_key) DO NOTHING
	`, tenantID, workspaceID, idempotencyKey, record.operation,
		record.requestHash, record.requestVersion, record.resourceType, record.resourceID,
		snapshot, snapshotDigest, snapshotVersion)
	if err != nil {
		return databaseError("insert investigation idempotency record", err)
	}
	if result.RowsAffected() != 1 {
		existing, readErr := readIdempotencyRecord(ctx, tx, tenantID, workspaceID, idempotencyKey)
		if readErr != nil {
			if errors.Is(readErr, pgx.ErrNoRows) {
				return store.ErrIdempotencyConflict
			}
			return databaseError("read concurrent investigation idempotency record", readErr)
		}
		if err := requireIdempotencyReplay(existing, record.operation, record.requestHash, record.requestVersion); err != nil {
			return err
		}
		return store.ErrIdempotencyConflict
	}
	return nil
}
