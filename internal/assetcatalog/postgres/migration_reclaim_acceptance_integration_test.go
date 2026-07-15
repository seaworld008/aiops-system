package postgres_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

const reclaimAcceptanceRunID = "8fa00000-0000-4000-8000-000000000001"

func TestAssetCatalogReclaimAcceptanceDelayedRunRequiresReceiptedCleanupBeforeFreshClaim(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedClosureAuthoritativeCompleteCatalog(t, harness.db)
	seedReclaimAcceptanceQueuedRun(t, harness.db, fixture)
	claimReclaimAcceptanceRun(t, harness.db, "reclaim-worker-old", "1", "5 minutes")

	execAssetSQL(t, harness.db, `
		UPDATE asset_source_runs
		SET cleanup_status='PENDING',
			cleanup_attempt_id='8fa00000-0000-4000-8000-000000000101',
			cleanup_attempt_epoch=fence_epoch,version=version+1
		WHERE id=$1
	`, reclaimAcceptanceRunID)
	execAssetSQL(t, harness.db, closureExactDelayIntentSQL,
		reclaimAcceptanceRunID, "200 milliseconds")

	cleanupDigest := strings.Repeat("2", 64)
	tx, err := harness.db.BeginTx(context.Background(), pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		t.Fatalf("begin exact cleanup receipt transaction: %v", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	insertCleanupAudit(t, tx, fixture, reclaimAcceptanceRunID, 1, cleanupDigest)
	execAssetSQL(t, tx, `
		UPDATE asset_source_runs
		SET cleanup_status='REVOKED',cleanup_digest=$2,version=version+1
		WHERE id=$1
	`, reclaimAcceptanceRunID, cleanupDigest)
	if err := tx.Commit(context.Background()); err != nil {
		t.Fatalf("commit exact cleanup receipt transaction: %v", err)
	}

	assertReclaimAcceptanceReceipt(t, harness.db, fixture, reclaimAcceptanceRunID,
		"reclaim-worker-old", "ATTEMPT_CLEANED",
		"source-attempt:"+reclaimAcceptanceRunID+":1", cleanupDigest)
	execAssetSQL(t, harness.db, `
		UPDATE asset_source_runs
		SET status='DELAYED',stage_code='DELAYED',pending_transition=NULL,
			pending_transition_reason=NULL,pending_transition_not_before=NULL,
			pending_transition_digest=NULL,lease_owner=NULL,lease_expires_at=NULL,
			fence_token_hash=NULL,version=version+1
		WHERE id=$1
	`, reclaimAcceptanceRunID)

	execAssetSQL(t, harness.db, `SELECT pg_sleep(0.25)`)
	claimReclaimAcceptanceRun(t, harness.db, "reclaim-worker-fresh", "3", "5 minutes")

	var status, stage, owner, token, cleanup string
	var fence, heartbeat int64
	var pendingCount int
	if err := harness.db.QueryRow(context.Background(), `
		SELECT status,stage_code,lease_owner,fence_token_hash,fence_epoch,
			heartbeat_sequence,cleanup_status,
			num_nonnulls(pending_transition,pending_transition_reason,
				pending_transition_not_before,pending_transition_digest)
		FROM asset_source_runs WHERE id=$1
	`, reclaimAcceptanceRunID).Scan(&status, &stage, &owner, &token, &fence,
		&heartbeat, &cleanup, &pendingCount); err != nil {
		t.Fatalf("read fresh delayed-run claim: %v", err)
	}
	if status != "RUNNING" || stage != "READING" || owner != "reclaim-worker-fresh" ||
		token != strings.Repeat("3", 64) || fence != 2 || heartbeat != 2 ||
		cleanup != "NOT_OPENED" || pendingCount != 0 {
		t.Fatalf("fresh claim shape=%s/%s owner=%s token=%s fence=%d heartbeat=%d cleanup=%s pending=%d",
			status, stage, owner, token, fence, heartbeat, cleanup, pendingCount)
	}
}

func TestAssetCatalogReclaimAcceptanceExpiredRunningSourceDriftFailsWithoutCredentialCleanup(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedClosureAuthoritativeCompleteCatalog(t, harness.db)
	seedReclaimAcceptanceQueuedRun(t, harness.db, fixture)
	claimReclaimAcceptanceRun(t, harness.db, "drift-worker-old", "4", "100 milliseconds")

	execAssetSQL(t, harness.db, `
		UPDATE asset_sources SET status='PAUSED',version=version+1 WHERE id=$1
	`, fixture.sourceID)
	execAssetSQL(t, harness.db, `SELECT pg_sleep(0.15)`)
	execAssetSQL(t, harness.db, `
		UPDATE asset_source_runs
		SET stage_code='CLEANING_UP',lease_owner='drift-reaper',
			lease_expires_at=statement_timestamp()+interval '5 minutes',
			fence_epoch=fence_epoch+1,fence_token_hash=repeat('5',64),
			heartbeat_sequence=heartbeat_sequence+1,version=version+1
		WHERE id=$1
	`, reclaimAcceptanceRunID)

	var status, stage, cleanup, sourceStatus, gateStatus, gateReason string
	var fence, heartbeat, page, checkpoint int64
	var cursorBefore, cursorAfter *string
	if err := harness.db.QueryRow(context.Background(), `
		SELECT run.status,run.stage_code,run.cleanup_status,run.fence_epoch,
			run.heartbeat_sequence,run.page_sequence,run.checkpoint_version,
			run.cursor_before_sha256,run.cursor_after_sha256,
			source.status,source.gate_status,source.gate_reason_code
		FROM asset_source_runs AS run
		JOIN asset_sources AS source ON source.id=run.source_id
		WHERE run.id=$1
	`, reclaimAcceptanceRunID).Scan(&status, &stage, &cleanup, &fence, &heartbeat,
		&page, &checkpoint, &cursorBefore, &cursorAfter, &sourceStatus, &gateStatus,
		&gateReason); err != nil {
		t.Fatalf("read cleanup-only drift reclaim: %v", err)
	}
	if status != "RUNNING" || stage != "CLEANING_UP" || cleanup != "NOT_OPENED" ||
		fence != 2 || heartbeat != 2 || page != 0 || cursorBefore == nil ||
		cursorAfter != nil || sourceStatus != "PAUSED" || gateStatus != "UNAVAILABLE" ||
		gateReason != "SOURCE_NOT_ACTIVE" {
		t.Fatalf("drift reclaim shape=%s/%s cleanup=%s fence=%d heartbeat=%d page=%d checkpoint=%d cursor=%v/%v source=%s gate=%s/%s",
			status, stage, cleanup, fence, heartbeat, page, checkpoint, cursorBefore,
			cursorAfter, sourceStatus, gateStatus, gateReason)
	}

	workDigest := strings.Repeat("6", 64)
	execAssetSQL(t, harness.db, `
		UPDATE asset_source_runs
		SET status='FINALIZING',stage_code='CLEANING_UP',
			work_result_kind='FAILURE_INTENT',work_result_status='FAILED',
			work_result_digest=$2,failure_code='SOURCE_DRIFT',version=version+1
		WHERE id=$1
	`, reclaimAcceptanceRunID, workDigest)

	tx, err := harness.db.BeginTx(context.Background(), pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		t.Fatalf("begin drift terminal closure: %v", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	terminalDigest := reclaimAcceptanceDirectFailureDigest(t, tx, reclaimAcceptanceRunID)
	if functionDigest := sourceRunTerminalDigest(t, tx, reclaimAcceptanceRunID,
		"FAILED", "SOURCE_DRIFT"); functionDigest != terminalDigest {
		t.Fatalf("NOT_OPENED terminal digest=%s, want exact framed digest %s",
			functionDigest, terminalDigest)
	}
	insertTerminalAudit(t, tx, fixture, reclaimAcceptanceRunID, terminalDigest)
	if _, err := tx.Exec(context.Background(), `
		UPDATE asset_source_runs
		SET status='FAILED',stage_code='COMPLETED',terminal_command_sha256=$2,
			version=version+1
		WHERE id=$1
	`, reclaimAcceptanceRunID, terminalDigest); err != nil {
		failReclaimAcceptanceDatabaseError(t, "commit NOT_OPENED drift failure", err)
	}
	if err := tx.Commit(context.Background()); err != nil {
		failReclaimAcceptanceDatabaseError(t, "commit NOT_OPENED drift failure", err)
	}

	assertReclaimAcceptanceReceipt(t, harness.db, fixture, reclaimAcceptanceRunID,
		"drift-reaper", "TERMINAL_COMMITTED",
		"source-terminal:"+reclaimAcceptanceRunID, terminalDigest)
	if err := harness.db.QueryRow(context.Background(), `
		SELECT run.status,run.stage_code,run.cleanup_status,source.status,
			source.gate_status,source.gate_reason_code
		FROM asset_source_runs AS run
		JOIN asset_sources AS source ON source.id=run.source_id
		WHERE run.id=$1
	`, reclaimAcceptanceRunID).Scan(&status, &stage, &cleanup, &sourceStatus,
		&gateStatus, &gateReason); err != nil {
		t.Fatalf("read direct drift failure closure: %v", err)
	}
	if status != "FAILED" || stage != "COMPLETED" || cleanup != "NOT_OPENED" ||
		sourceStatus != "PAUSED" || gateStatus != "UNAVAILABLE" ||
		gateReason != "SOURCE_NOT_ACTIVE" {
		t.Fatalf("direct drift closure=%s/%s cleanup=%s source=%s gate=%s/%s",
			status, stage, cleanup, sourceStatus, gateStatus, gateReason)
	}
}

func TestAssetCatalogReclaimAcceptanceAdmittedRunCannotFailWithoutCredentialCleanup(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedClosureAuthoritativeCompleteCatalog(t, harness.db)
	seedReclaimAcceptanceQueuedRun(t, harness.db, fixture)
	claimReclaimAcceptanceRun(t, harness.db, "admitted-failure-worker", "7", "5 minutes")
	execAssetSQL(t, harness.db, `
		UPDATE asset_source_runs
		SET status='FINALIZING',stage_code='CLEANING_UP',
			work_result_kind='FAILURE_INTENT',work_result_status='FAILED',
			work_result_digest=repeat('8',64),failure_code='PROVIDER_FAILED',
			version=version+1
		WHERE id=$1
	`, reclaimAcceptanceRunID)
	expectClosureStatementError(t, harness.db, "55000",
		"asset_source_runs_finalizing_mutation_guard", `
		UPDATE asset_source_runs SET version=version+1 WHERE id=$1
	`, reclaimAcceptanceRunID)

	expectClosureCommitError(t, harness.db, pgx.Serializable, "55000",
		"asset_source_runs_terminal_receipt_guard", func(tx pgx.Tx) error {
			terminalDigest := sourceRunTerminalDigest(t, tx, reclaimAcceptanceRunID,
				"FAILED", "PROVIDER_FAILED")
			insertTerminalAudit(t, tx, fixture, reclaimAcceptanceRunID, terminalDigest)
			_, err := tx.Exec(context.Background(), `
				UPDATE asset_source_runs
				SET status='FAILED',stage_code='COMPLETED',terminal_command_sha256=$2,
					version=version+1
				WHERE id=$1
			`, reclaimAcceptanceRunID, terminalDigest)
			return err
		})

	var status, cleanup string
	var terminalReceipts int
	if err := harness.db.QueryRow(context.Background(), `
		SELECT run.status,run.cleanup_status,
			(SELECT count(*)::integer FROM audit_records AS audit
			 WHERE audit.resource_type='ASSET_SOURCE_RUN'
			   AND audit.resource_id=run.id::text
			   AND audit.action='TERMINAL_COMMITTED')
		FROM asset_source_runs AS run WHERE run.id=$1
	`, reclaimAcceptanceRunID).Scan(&status, &cleanup, &terminalReceipts); err != nil {
		t.Fatalf("read admitted direct-failure rollback: %v", err)
	}
	if status != "FINALIZING" || cleanup != "NOT_OPENED" || terminalReceipts != 0 {
		t.Fatalf("admitted direct-failure rollback=%s cleanup=%s receipts=%d",
			status, cleanup, terminalReceipts)
	}
}

func TestAssetCatalogReclaimAcceptanceExpiredRunningPendingReclaimsCleanupOnly(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedClosureAuthoritativeCompleteCatalog(t, harness.db)
	seedReclaimAcceptanceQueuedRun(t, harness.db, fixture)
	claimReclaimAcceptanceRun(t, harness.db, "pending-worker-old", "9", "100 milliseconds")
	execAssetSQL(t, harness.db, `
		UPDATE asset_source_runs
		SET cleanup_status='PENDING',
			cleanup_attempt_id='8fa00000-0000-4000-8000-000000000102',
			cleanup_attempt_epoch=fence_epoch,version=version+1
		WHERE id=$1
	`, reclaimAcceptanceRunID)
	execAssetSQL(t, harness.db, `SELECT pg_sleep(0.15)`)
	execAssetSQL(t, harness.db, `
		UPDATE asset_source_runs
		SET stage_code='CLEANING_UP',lease_owner='pending-reaper',
			lease_expires_at=statement_timestamp()+interval '5 minutes',
			fence_epoch=fence_epoch+1,fence_token_hash=repeat('a',64),
			heartbeat_sequence=heartbeat_sequence+1,version=version+1
		WHERE id=$1
	`, reclaimAcceptanceRunID)

	var status, stage, owner, token, cleanup, attemptID string
	var fence, heartbeat, attemptEpoch, page, checkpoint int64
	var cursorBefore, cursorAfter *string
	if err := harness.db.QueryRow(context.Background(), `
		SELECT status,stage_code,lease_owner,fence_token_hash,cleanup_status,
			cleanup_attempt_id::text,fence_epoch,heartbeat_sequence,
			cleanup_attempt_epoch,page_sequence,checkpoint_version,
			cursor_before_sha256,cursor_after_sha256
		FROM asset_source_runs WHERE id=$1
	`, reclaimAcceptanceRunID).Scan(&status, &stage, &owner, &token, &cleanup,
		&attemptID, &fence, &heartbeat, &attemptEpoch, &page, &checkpoint,
		&cursorBefore, &cursorAfter); err != nil {
		t.Fatalf("read expired PENDING cleanup reclaim: %v", err)
	}
	if status != "RUNNING" || stage != "CLEANING_UP" || owner != "pending-reaper" ||
		token != strings.Repeat("a", 64) || cleanup != "PENDING" ||
		attemptID != "8fa00000-0000-4000-8000-000000000102" || fence != 2 ||
		heartbeat != 2 || attemptEpoch != 1 || page != 0 || cursorBefore == nil ||
		cursorAfter != nil {
		t.Fatalf("PENDING reclaim=%s/%s owner=%s token=%s cleanup=%s/%s/%d fence=%d heartbeat=%d page=%d checkpoint=%d cursor=%v/%v",
			status, stage, owner, token, cleanup, attemptID, attemptEpoch, fence,
			heartbeat, page, checkpoint, cursorBefore, cursorAfter)
	}

	staleTag, err := harness.db.Exec(context.Background(), `
		UPDATE asset_source_runs
		SET stage_code='NORMALIZING',heartbeat_sequence=heartbeat_sequence+1,
			lease_expires_at=lease_expires_at+interval '1 minute',version=version+1
		WHERE id=$1 AND lease_owner='pending-worker-old' AND fence_epoch=1
		  AND fence_token_hash=repeat('9',64)
	`, reclaimAcceptanceRunID)
	if err != nil {
		failReclaimAcceptanceDatabaseError(t, "reject stale-fence provider continuation", err)
	}
	if staleTag.RowsAffected() != 0 {
		t.Fatalf("stale old fence mutated %d run rows, want 0", staleTag.RowsAffected())
	}
	expectClosureStatementError(t, harness.db, "55000", "asset_source_runs_reclaim_guard", `
		UPDATE asset_source_runs
		SET lease_owner='pending-worker-old',fence_token_hash=repeat('9',64),
			fence_epoch=1,heartbeat_sequence=heartbeat_sequence+1,
			lease_expires_at=statement_timestamp()+interval '5 minutes',version=version+1
		WHERE id=$1
	`, reclaimAcceptanceRunID)

	execAssetSQL(t, harness.db, closureExactDelayIntentSQL,
		reclaimAcceptanceRunID, "200 milliseconds")
	cleanupDigest := strings.Repeat("b", 64)
	tx, err := harness.db.BeginTx(context.Background(), pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		t.Fatalf("begin reclaimed PENDING cleanup receipt: %v", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	insertCleanupAudit(t, tx, fixture, reclaimAcceptanceRunID, 1, cleanupDigest)
	execAssetSQL(t, tx, `
		UPDATE asset_source_runs
		SET cleanup_status='REVOKED',cleanup_digest=$2,version=version+1
		WHERE id=$1
	`, reclaimAcceptanceRunID, cleanupDigest)
	if err := tx.Commit(context.Background()); err != nil {
		failReclaimAcceptanceDatabaseError(t, "commit reclaimed PENDING cleanup", err)
	}
	assertReclaimAcceptanceReceipt(t, harness.db, fixture, reclaimAcceptanceRunID,
		"pending-reaper", "ATTEMPT_CLEANED",
		"source-attempt:"+reclaimAcceptanceRunID+":1", cleanupDigest)
	execAssetSQL(t, harness.db, `
		UPDATE asset_source_runs
		SET status='DELAYED',stage_code='DELAYED',pending_transition=NULL,
			pending_transition_reason=NULL,pending_transition_not_before=NULL,
			pending_transition_digest=NULL,lease_owner=NULL,lease_expires_at=NULL,
			fence_token_hash=NULL,version=version+1
		WHERE id=$1
	`, reclaimAcceptanceRunID)
	var activeFacts int
	if err := harness.db.QueryRow(context.Background(), `
		SELECT status,stage_code,cleanup_status,fence_epoch,heartbeat_sequence,
			num_nonnulls(lease_owner,lease_expires_at,fence_token_hash,pending_transition)
		FROM asset_source_runs WHERE id=$1
	`, reclaimAcceptanceRunID).Scan(&status, &stage, &cleanup, &fence, &heartbeat,
		&activeFacts); err != nil {
		t.Fatalf("read reclaimed PENDING delayed closure: %v", err)
	}
	if status != "DELAYED" || stage != "DELAYED" || cleanup != "REVOKED" ||
		fence != 2 || heartbeat != 2 || activeFacts != 0 {
		t.Fatalf("reclaimed PENDING delay=%s/%s cleanup=%s fence=%d heartbeat=%d active=%d",
			status, stage, cleanup, fence, heartbeat, activeFacts)
	}
}

func TestAssetCatalogReclaimAcceptanceExpiredFinalizingConsumesReceiptedWorkResult(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedClosureAuthoritativeCompleteCatalog(t, harness.db)
	seedReclaimAcceptanceQueuedRun(t, harness.db, fixture)
	claimReclaimAcceptanceRun(t, harness.db, "finalizing-worker-old", "c", "750 milliseconds")
	execAssetSQL(t, harness.db, `
		UPDATE asset_source_runs
		SET cleanup_status='PENDING',
			cleanup_attempt_id='8fa00000-0000-4000-8000-000000000103',
			cleanup_attempt_epoch=fence_epoch,version=version+1
		WHERE id=$1
	`, reclaimAcceptanceRunID)
	workDigest := strings.Repeat("d", 64)
	execAssetSQL(t, harness.db, `
		UPDATE asset_source_runs
		SET status='FINALIZING',stage_code='CLEANING_UP',
			work_result_kind='FAILURE_INTENT',work_result_status='FAILED',
			work_result_digest=$2,failure_code='PROVIDER_FAILED',version=version+1
		WHERE id=$1
	`, reclaimAcceptanceRunID, workDigest)
	cleanupDigest := strings.Repeat("e", 64)
	cleanupTx, err := harness.db.BeginTx(context.Background(), pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		t.Fatalf("begin FINALIZING cleanup receipt: %v", err)
	}
	defer func() { _ = cleanupTx.Rollback(context.Background()) }()
	insertCleanupAudit(t, cleanupTx, fixture, reclaimAcceptanceRunID, 1, cleanupDigest)
	execAssetSQL(t, cleanupTx, `
		UPDATE asset_source_runs
		SET cleanup_status='REVOKED',cleanup_digest=$2,version=version+1
		WHERE id=$1
	`, reclaimAcceptanceRunID, cleanupDigest)
	if err := cleanupTx.Commit(context.Background()); err != nil {
		failReclaimAcceptanceDatabaseError(t, "commit FINALIZING cleanup receipt", err)
	}
	assertReclaimAcceptanceReceipt(t, harness.db, fixture, reclaimAcceptanceRunID,
		"finalizing-worker-old", "ATTEMPT_CLEANED",
		"source-attempt:"+reclaimAcceptanceRunID+":1", cleanupDigest)

	execAssetSQL(t, harness.db, `SELECT pg_sleep(0.8)`)
	if _, err := harness.db.Exec(context.Background(), `
		UPDATE asset_source_runs
		SET stage_code='CLEANING_UP',lease_owner='finalizing-reaper',
			lease_expires_at=statement_timestamp()+interval '100 milliseconds',
			fence_epoch=fence_epoch+1,fence_token_hash=repeat('f',64),
			heartbeat_sequence=heartbeat_sequence+1,version=version+1
		WHERE id=$1
	`, reclaimAcceptanceRunID); err != nil {
		failReclaimAcceptanceDatabaseError(t, "reclaim receipted FINALIZING work", err)
	}

	var status, stage, owner, cleanup, resultKind, resultStatus, resultDigest string
	var fence, heartbeat, page int64
	if err := harness.db.QueryRow(context.Background(), `
		SELECT status,stage_code,lease_owner,cleanup_status,work_result_kind,
			work_result_status,work_result_digest,fence_epoch,heartbeat_sequence,page_sequence
		FROM asset_source_runs WHERE id=$1
	`, reclaimAcceptanceRunID).Scan(&status, &stage, &owner, &cleanup, &resultKind,
		&resultStatus, &resultDigest, &fence, &heartbeat, &page); err != nil {
		t.Fatalf("read reclaimed FINALIZING work: %v", err)
	}
	if status != "FINALIZING" || stage != "CLEANING_UP" ||
		owner != "finalizing-reaper" || cleanup != "REVOKED" ||
		resultKind != "FAILURE_INTENT" || resultStatus != "FAILED" ||
		resultDigest != workDigest || fence != 2 || heartbeat != 2 || page != 0 {
		t.Fatalf("FINALIZING reclaim=%s/%s owner=%s cleanup=%s result=%s/%s/%s fence=%d heartbeat=%d page=%d",
			status, stage, owner, cleanup, resultKind, resultStatus, resultDigest,
			fence, heartbeat, page)
	}
	expectClosureStatementError(t, harness.db, "55000",
		"asset_source_runs_work_result_immutable_guard", `
		UPDATE asset_source_runs
		SET work_result_digest=repeat('0',64),version=version+1 WHERE id=$1
	`, reclaimAcceptanceRunID)
	execAssetSQL(t, harness.db, `SELECT pg_sleep(0.15)`)
	if _, err := harness.db.Exec(context.Background(), `
		UPDATE asset_source_runs
		SET stage_code='CLEANING_UP',lease_owner='finalizing-reaper-two',
			lease_expires_at=statement_timestamp()+interval '5 minutes',
			fence_epoch=fence_epoch+1,fence_token_hash=repeat('0',64),
			heartbeat_sequence=heartbeat_sequence+1,version=version+1
		WHERE id=$1
	`, reclaimAcceptanceRunID); err != nil {
		failReclaimAcceptanceDatabaseError(t, "reclaim receipted FINALIZING work twice", err)
	}
	if err := harness.db.QueryRow(context.Background(), `
		SELECT status,stage_code,lease_owner,cleanup_status,work_result_kind,
			work_result_status,work_result_digest,fence_epoch,heartbeat_sequence,page_sequence
		FROM asset_source_runs WHERE id=$1
	`, reclaimAcceptanceRunID).Scan(&status, &stage, &owner, &cleanup, &resultKind,
		&resultStatus, &resultDigest, &fence, &heartbeat, &page); err != nil {
		t.Fatalf("read twice-reclaimed FINALIZING work: %v", err)
	}
	if status != "FINALIZING" || stage != "CLEANING_UP" ||
		owner != "finalizing-reaper-two" || cleanup != "REVOKED" ||
		resultKind != "FAILURE_INTENT" || resultStatus != "FAILED" ||
		resultDigest != workDigest || fence != 3 || heartbeat != 3 || page != 0 {
		t.Fatalf("twice-reclaimed FINALIZING=%s/%s owner=%s cleanup=%s result=%s/%s/%s fence=%d heartbeat=%d page=%d",
			status, stage, owner, cleanup, resultKind, resultStatus, resultDigest,
			fence, heartbeat, page)
	}

	terminalTx, err := harness.db.BeginTx(context.Background(), pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		t.Fatalf("begin reclaimed FINALIZING terminal closure: %v", err)
	}
	defer func() { _ = terminalTx.Rollback(context.Background()) }()
	terminalDigest := sourceRunTerminalDigest(t, terminalTx, reclaimAcceptanceRunID,
		"FAILED", "PROVIDER_FAILED")
	insertTerminalAudit(t, terminalTx, fixture, reclaimAcceptanceRunID, terminalDigest)
	execAssetSQL(t, terminalTx, `
		UPDATE asset_source_runs
		SET status='FAILED',stage_code='COMPLETED',terminal_command_sha256=$2,
			version=version+1
		WHERE id=$1
	`, reclaimAcceptanceRunID, terminalDigest)
	if err := terminalTx.Commit(context.Background()); err != nil {
		failReclaimAcceptanceDatabaseError(t, "commit reclaimed FINALIZING failure", err)
	}
	assertReclaimAcceptanceReceipt(t, harness.db, fixture, reclaimAcceptanceRunID,
		"finalizing-reaper-two", "TERMINAL_COMMITTED",
		"source-terminal:"+reclaimAcceptanceRunID, terminalDigest)
	if err := harness.db.QueryRow(context.Background(), `
		SELECT status,stage_code,lease_owner,cleanup_status,work_result_digest,
			fence_epoch,heartbeat_sequence FROM asset_source_runs WHERE id=$1
	`, reclaimAcceptanceRunID).Scan(&status, &stage, &owner, &cleanup, &resultDigest,
		&fence, &heartbeat); err != nil {
		t.Fatalf("read consumed FINALIZING failure: %v", err)
	}
	if status != "FAILED" || stage != "COMPLETED" || owner != "finalizing-reaper-two" ||
		cleanup != "REVOKED" || resultDigest != workDigest || fence != 3 || heartbeat != 3 {
		t.Fatalf("consumed FINALIZING=%s/%s owner=%s cleanup=%s result=%s fence=%d heartbeat=%d",
			status, stage, owner, cleanup, resultDigest, fence, heartbeat)
	}
}

func TestAssetCatalogReclaimAcceptanceExpiredRunningConsumesHistoricalCleanupReceiptToDelay(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedClosureAuthoritativeCompleteCatalog(t, harness.db)
	seedReclaimAcceptanceQueuedRun(t, harness.db, fixture)
	claimReclaimAcceptanceRun(t, harness.db, "delay-worker-old", "1", "500 milliseconds")
	execAssetSQL(t, harness.db, `
		UPDATE asset_source_runs
		SET cleanup_status='PENDING',
			cleanup_attempt_id='8fa00000-0000-4000-8000-000000000106',
			cleanup_attempt_epoch=fence_epoch,version=version+1
		WHERE id=$1
	`, reclaimAcceptanceRunID)
	execAssetSQL(t, harness.db, closureExactDelayIntentSQL,
		reclaimAcceptanceRunID, "2 seconds")
	cleanupDigest := strings.Repeat("7", 64)
	cleanupTx, err := harness.db.BeginTx(context.Background(), pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		t.Fatalf("begin pre-expiry delay cleanup receipt: %v", err)
	}
	defer func() { _ = cleanupTx.Rollback(context.Background()) }()
	insertCleanupAudit(t, cleanupTx, fixture, reclaimAcceptanceRunID, 1, cleanupDigest)
	execAssetSQL(t, cleanupTx, `
		UPDATE asset_source_runs
		SET cleanup_status='REVOKED',cleanup_digest=$2,version=version+1 WHERE id=$1
	`, reclaimAcceptanceRunID, cleanupDigest)
	if err := cleanupTx.Commit(context.Background()); err != nil {
		failReclaimAcceptanceDatabaseError(t, "commit pre-expiry delay cleanup receipt", err)
	}
	assertReclaimAcceptanceReceipt(t, harness.db, fixture, reclaimAcceptanceRunID,
		"delay-worker-old", "ATTEMPT_CLEANED",
		"source-attempt:"+reclaimAcceptanceRunID+":1", cleanupDigest)

	execAssetSQL(t, harness.db, `SELECT pg_sleep(0.55)`)
	execAssetSQL(t, harness.db, `
		UPDATE asset_source_runs
		SET stage_code='CLEANING_UP',lease_owner='delay-reaper',
			lease_expires_at=statement_timestamp()+interval '5 minutes',
			fence_epoch=fence_epoch+1,fence_token_hash=repeat('8',64),
			heartbeat_sequence=heartbeat_sequence+1,version=version+1
		WHERE id=$1
	`, reclaimAcceptanceRunID)
	var status, stage, owner, cleanup, pending string
	var fence, heartbeat, attemptEpoch int64
	if err := harness.db.QueryRow(context.Background(), `
		SELECT status,stage_code,lease_owner,cleanup_status,pending_transition,
			fence_epoch,heartbeat_sequence,cleanup_attempt_epoch
		FROM asset_source_runs WHERE id=$1
	`, reclaimAcceptanceRunID).Scan(&status, &stage, &owner, &cleanup, &pending,
		&fence, &heartbeat, &attemptEpoch); err != nil {
		t.Fatalf("read receipted RUNNING delay reclaim: %v", err)
	}
	if status != "RUNNING" || stage != "CLEANING_UP" || owner != "delay-reaper" ||
		cleanup != "REVOKED" || pending != "DELAY" || fence != 2 || heartbeat != 2 ||
		attemptEpoch != 1 {
		t.Fatalf("receipted RUNNING reclaim=%s/%s owner=%s cleanup=%s pending=%s fence=%d heartbeat=%d epoch=%d",
			status, stage, owner, cleanup, pending, fence, heartbeat, attemptEpoch)
	}
	if _, err := harness.db.Exec(context.Background(), `
		UPDATE asset_source_runs
		SET status='DELAYED',stage_code='DELAYED',pending_transition=NULL,
			pending_transition_reason=NULL,pending_transition_not_before=NULL,
			pending_transition_digest=NULL,lease_owner=NULL,lease_expires_at=NULL,
			fence_token_hash=NULL,version=version+1
		WHERE id=$1
	`, reclaimAcceptanceRunID); err != nil {
		failReclaimAcceptanceDatabaseError(t, "consume historical cleanup receipt into DELAYED", err)
	}
	if err := harness.db.QueryRow(context.Background(), `
		SELECT status,stage_code,cleanup_status,fence_epoch,heartbeat_sequence
		FROM asset_source_runs WHERE id=$1
	`, reclaimAcceptanceRunID).Scan(&status, &stage, &cleanup, &fence, &heartbeat); err != nil {
		t.Fatalf("read historical-receipt delayed run: %v", err)
	}
	if status != "DELAYED" || stage != "DELAYED" || cleanup != "REVOKED" ||
		fence != 2 || heartbeat != 2 {
		t.Fatalf("historical-receipt delay=%s/%s cleanup=%s fence=%d heartbeat=%d",
			status, stage, cleanup, fence, heartbeat)
	}
}

func TestAssetCatalogReclaimAcceptanceRunStateShapeNegatives(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedClosureAuthoritativeCompleteCatalog(t, harness.db)
	seedReclaimAcceptanceQueuedRun(t, harness.db, fixture)

	expectClosureStatementError(t, harness.db, "55000", "asset_source_runs_claim_guard", `
		UPDATE asset_source_runs
		SET observed_count=1,version=version+1 WHERE id=$1
	`, reclaimAcceptanceRunID)
	claimReclaimAcceptanceRun(t, harness.db, "shape-worker-old", "1", "5 minutes")
	expectClosureStatementError(t, harness.db, "55000",
		"asset_source_runs_running_mutation_guard", `
		UPDATE asset_source_runs
		SET work_result_kind='FAILURE_INTENT',work_result_status='FAILED',
			work_result_digest=repeat('1',64),failure_code='FORGED_RUNNING_RESULT',
			version=version+1
		WHERE id=$1
	`, reclaimAcceptanceRunID)
	expectClosureStatementError(t, harness.db, "23514", "asset_source_runs_state_guard", `
		UPDATE asset_source_runs
		SET status='FAILED',stage_code='COMPLETED',version=version+1 WHERE id=$1
	`, reclaimAcceptanceRunID)

	execAssetSQL(t, harness.db, `
		UPDATE asset_source_runs
		SET cleanup_status='PENDING',
			cleanup_attempt_id='8fa00000-0000-4000-8000-000000000104',
			cleanup_attempt_epoch=fence_epoch,version=version+1
		WHERE id=$1
	`, reclaimAcceptanceRunID)
	execAssetSQL(t, harness.db, closureExactDelayIntentSQL,
		reclaimAcceptanceRunID, "200 milliseconds")
	wrongActorDigest := strings.Repeat("a", 64)
	expectClosureCommitError(t, harness.db, pgx.Serializable, "55000",
		"asset_source_runs_cleanup_transition_guard", func(tx pgx.Tx) error {
			if _, err := tx.Exec(context.Background(), `
				INSERT INTO audit_records (
					id,tenant_id,workspace_id,actor_type,actor_id,action,resource_type,
					resource_id,request_id,trace_id,payload_hash
				) VALUES (
					gen_random_uuid(),$1,$2,'SYSTEM','wrong-cleanup-worker','ATTEMPT_CLEANED',
					'ASSET_SOURCE_RUN',$3,'source-attempt:'||$3||':1',
					'wrong-cleanup-actor-trace',$4
				)
			`, fixture.tenantID, fixture.workspaceID, reclaimAcceptanceRunID,
				wrongActorDigest); err != nil {
				return err
			}
			_, err := tx.Exec(context.Background(), `
				UPDATE asset_source_runs
				SET cleanup_status='REVOKED',cleanup_digest=$2,version=version+1
				WHERE id=$1
			`, reclaimAcceptanceRunID, wrongActorDigest)
			return err
		})
	var wrongActorReceipts int
	if err := harness.db.QueryRow(context.Background(), `
		SELECT count(*)::integer FROM audit_records
		WHERE resource_type='ASSET_SOURCE_RUN' AND resource_id=$1
		  AND action='ATTEMPT_CLEANED' AND actor_id='wrong-cleanup-worker'
		  AND request_id='source-attempt:'||$1||':1' AND payload_hash=$2
	`, reclaimAcceptanceRunID, wrongActorDigest).Scan(&wrongActorReceipts); err != nil {
		t.Fatalf("read wrong-owner cleanup receipt rollback: %v", err)
	}
	if wrongActorReceipts != 0 {
		t.Fatalf("wrong-owner cleanup receipts=%d, want rollback to zero", wrongActorReceipts)
	}
	firstCleanupDigest := strings.Repeat("2", 64)
	firstCleanupTx, err := harness.db.BeginTx(context.Background(), pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		t.Fatalf("begin state-shape first cleanup: %v", err)
	}
	defer func() { _ = firstCleanupTx.Rollback(context.Background()) }()
	insertCleanupAudit(t, firstCleanupTx, fixture, reclaimAcceptanceRunID, 1, firstCleanupDigest)
	execAssetSQL(t, firstCleanupTx, `
		UPDATE asset_source_runs
		SET cleanup_status='REVOKED',cleanup_digest=$2,version=version+1 WHERE id=$1
	`, reclaimAcceptanceRunID, firstCleanupDigest)
	if err := firstCleanupTx.Commit(context.Background()); err != nil {
		failReclaimAcceptanceDatabaseError(t, "commit state-shape first cleanup", err)
	}
	execAssetSQL(t, harness.db, `
		UPDATE asset_source_runs
		SET status='DELAYED',stage_code='DELAYED',pending_transition=NULL,
			pending_transition_reason=NULL,pending_transition_not_before=NULL,
			pending_transition_digest=NULL,lease_owner=NULL,lease_expires_at=NULL,
			fence_token_hash=NULL,version=version+1
		WHERE id=$1
	`, reclaimAcceptanceRunID)
	expectClosureStatementError(t, harness.db, "55000", "asset_source_runs_claim_guard", `
		UPDATE asset_source_runs
		SET work_result_kind='FAILURE_INTENT',work_result_status='FAILED',
			work_result_digest=repeat('3',64),failure_code='FORGED_DELAYED_RESULT',
			version=version+1
		WHERE id=$1
	`, reclaimAcceptanceRunID)
	expectClosureStatementError(t, harness.db, "23514", "asset_source_runs_state_guard", `
		UPDATE asset_source_runs
		SET status='FINALIZING',stage_code='CLEANING_UP',version=version+1 WHERE id=$1
	`, reclaimAcceptanceRunID)

	execAssetSQL(t, harness.db, `SELECT pg_sleep(0.25)`)
	claimReclaimAcceptanceRun(t, harness.db, "shape-worker-fresh", "4", "5 minutes")
	execAssetSQL(t, harness.db, `
		UPDATE asset_source_runs
		SET cleanup_status='PENDING',
			cleanup_attempt_id='8fa00000-0000-4000-8000-000000000105',
			cleanup_attempt_epoch=fence_epoch,version=version+1
		WHERE id=$1
	`, reclaimAcceptanceRunID)
	workDigest := strings.Repeat("5", 64)
	execAssetSQL(t, harness.db, `
		UPDATE asset_source_runs
		SET status='FINALIZING',stage_code='CLEANING_UP',
			work_result_kind='FAILURE_INTENT',work_result_status='FAILED',
			work_result_digest=$2,failure_code='SHAPE_FAILURE',version=version+1
		WHERE id=$1
	`, reclaimAcceptanceRunID, workDigest)
	secondCleanupDigest := strings.Repeat("6", 64)
	secondCleanupTx, err := harness.db.BeginTx(context.Background(), pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		t.Fatalf("begin state-shape second cleanup: %v", err)
	}
	defer func() { _ = secondCleanupTx.Rollback(context.Background()) }()
	insertCleanupAudit(t, secondCleanupTx, fixture, reclaimAcceptanceRunID, 2, secondCleanupDigest)
	execAssetSQL(t, secondCleanupTx, `
		UPDATE asset_source_runs
		SET cleanup_status='REVOKED',cleanup_digest=$2,version=version+1 WHERE id=$1
	`, reclaimAcceptanceRunID, secondCleanupDigest)
	if err := secondCleanupTx.Commit(context.Background()); err != nil {
		failReclaimAcceptanceDatabaseError(t, "commit state-shape second cleanup", err)
	}
	expectClosureStatementError(t, harness.db, "55000",
		"asset_source_runs_work_result_immutable_guard", `
		UPDATE asset_source_runs
		SET work_result_status='SUCCEEDED',version=version+1 WHERE id=$1
	`, reclaimAcceptanceRunID)
	expectClosureStatementError(t, harness.db, "55000",
		"asset_source_runs_cleanup_transition_guard", `
		UPDATE asset_source_runs SET observed_count=1,version=version+1 WHERE id=$1
	`, reclaimAcceptanceRunID)

	terminalTx, err := harness.db.BeginTx(context.Background(), pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		t.Fatalf("begin state-shape terminal closure: %v", err)
	}
	defer func() { _ = terminalTx.Rollback(context.Background()) }()
	terminalDigest := sourceRunTerminalDigest(t, terminalTx, reclaimAcceptanceRunID,
		"FAILED", "SHAPE_FAILURE")
	insertTerminalAudit(t, terminalTx, fixture, reclaimAcceptanceRunID, terminalDigest)
	execAssetSQL(t, terminalTx, `
		UPDATE asset_source_runs
		SET status='FAILED',stage_code='COMPLETED',terminal_command_sha256=$2,
			version=version+1 WHERE id=$1
	`, reclaimAcceptanceRunID, terminalDigest)
	if err := terminalTx.Commit(context.Background()); err != nil {
		failReclaimAcceptanceDatabaseError(t, "commit state-shape terminal closure", err)
	}
	expectClosureStatementError(t, harness.db, "55000", "asset_source_runs_terminal_guard", `
		UPDATE asset_source_runs SET failure_code='TERMINAL_REWRITE',version=version+1 WHERE id=$1
	`, reclaimAcceptanceRunID)
}

func seedReclaimAcceptanceQueuedRun(
	t *testing.T,
	database *pgxpool.Pool,
	fixture assetCatalogFixture,
) {
	t.Helper()
	execAssetSQL(t, database, `
		INSERT INTO asset_source_runs (
			id,tenant_id,workspace_id,source_id,source_revision,source_revision_digest,
			run_kind,trigger_type,gate_revision,idempotency_key,request_hash,
			checkpoint_version,cursor_before_sha256
		) SELECT $1,$2,$3,$4,published_revision,published_revision_digest,
			'DISCOVERY','SCHEDULED',gate_revision,'reclaim-acceptance-run',repeat('a',64),
			checkpoint_version,checkpoint_sha256
		FROM asset_sources WHERE id=$4
	`, reclaimAcceptanceRunID, fixture.tenantID, fixture.workspaceID, fixture.sourceID)
}

func claimReclaimAcceptanceRun(
	t *testing.T,
	database *pgxpool.Pool,
	owner string,
	tokenDigit string,
	leaseDuration string,
) {
	t.Helper()
	execAssetSQL(t, database, `
		UPDATE asset_source_runs
		SET status='RUNNING',stage_code='READING',lease_owner=$2,
			lease_expires_at=statement_timestamp()+$3::interval,
			fence_epoch=fence_epoch+1,fence_token_hash=repeat($4,64),
			heartbeat_sequence=heartbeat_sequence+1,cleanup_status='NOT_OPENED',
			cleanup_attempt_id=NULL,cleanup_attempt_epoch=0,cleanup_digest=NULL,
			version=version+1
		WHERE id=$1
	`, reclaimAcceptanceRunID, owner, leaseDuration, tokenDigit)
}

func assertReclaimAcceptanceReceipt(
	t *testing.T,
	database *pgxpool.Pool,
	fixture assetCatalogFixture,
	runID string,
	actorID string,
	action string,
	requestID string,
	digest string,
) {
	t.Helper()
	var count int
	if err := database.QueryRow(context.Background(), `
		SELECT count(*)::integer FROM audit_records
		WHERE tenant_id=$1 AND workspace_id=$2 AND actor_type='SYSTEM' AND actor_id=$3
		  AND action=$4 AND resource_type='ASSET_SOURCE_RUN' AND resource_id=$5
		  AND request_id=$6 AND payload_hash=$7
	`, fixture.tenantID, fixture.workspaceID, actorID, action, runID,
		requestID, digest).Scan(&count); err != nil {
		t.Fatalf("read exact %s receipt: %v", action, err)
	}
	if count != 1 {
		t.Fatalf("exact %s receipt count=%d, want 1", action, count)
	}
}

func reclaimAcceptanceDirectFailureDigest(
	t *testing.T,
	database assetSQLQuerier,
	runID string,
) string {
	t.Helper()
	var digest string
	if err := database.QueryRow(context.Background(), `
		SELECT encode(sha256(
			asset_catalog_framed_value_v1(convert_to('asset-run-terminal.v1','UTF8')) ||
			asset_catalog_framed_value_v1(convert_to(run.id::text,'UTF8')) ||
			asset_catalog_framed_value_v1(convert_to('FAILED','UTF8')) ||
			asset_catalog_framed_value_v1(convert_to(run.work_result_kind,'UTF8')) ||
			asset_catalog_framed_value_v1(decode(run.work_result_digest,'hex')) ||
			asset_catalog_framed_value_v1(convert_to(run.cleanup_status,'UTF8')) ||
			asset_catalog_framed_value_v1(NULL::bytea) ||
			asset_catalog_framed_value_v1(NULL::bytea) ||
			asset_catalog_framed_value_v1(NULL::bytea) ||
			asset_catalog_framed_value_v1(convert_to(run.failure_code,'UTF8'))
		),'hex')
		FROM asset_source_runs AS run WHERE run.id=$1
	`, runID).Scan(&digest); err != nil {
		t.Fatalf("derive exact NOT_OPENED direct-failure digest: %v", err)
	}
	return digest
}

func failReclaimAcceptanceDatabaseError(t *testing.T, operation string, err error) {
	t.Helper()
	var databaseError *pgconn.PgError
	if errors.As(err, &databaseError) {
		t.Fatalf("%s: SQLSTATE %s constraint %s: %s", operation, databaseError.Code,
			databaseError.ConstraintName, databaseError.Message)
	}
	t.Fatalf("%s: %v", operation, err)
}
