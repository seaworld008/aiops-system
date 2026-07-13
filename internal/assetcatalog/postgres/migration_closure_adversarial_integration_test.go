package postgres_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestAssetCatalogValidationCleanupUncertainRequiresSourceSuspension(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedDraftAssetCatalog(t, harness.db)
	fixture = seedClosureExternalValidationOnFixture(t, harness.db, fixture)
	prepareCleanupUncertainValidationRun(t, harness.db, fixture)

	expectClosureCommitError(t, harness.db, pgx.Serializable, "55000",
		"asset_source_runs_cleanup_uncertain_closure_guard", func(tx pgx.Tx) error {
			cleanupDigest := strings.Repeat("a", 64)
			insertCleanupAudit(t, tx, fixture, fixture.validationRunID, 1, cleanupDigest)
			if _, err := tx.Exec(context.Background(), `
				UPDATE asset_source_runs
				SET cleanup_status='UNCERTAIN',cleanup_digest=$2,version=version+1
				WHERE id=$1
			`, fixture.validationRunID, cleanupDigest); err != nil {
				return err
			}
			var overrideDigest string
			if err := tx.QueryRow(context.Background(), `
				SELECT asset_catalog_source_run_failure_override_digest(run,'CLEANUP_UNCERTAIN')
				FROM asset_source_runs AS run WHERE id=$1
			`, fixture.validationRunID).Scan(&overrideDigest); err != nil {
				return err
			}
			if _, err := tx.Exec(context.Background(), `
				UPDATE asset_source_runs
				SET failure_code='CLEANUP_UNCERTAIN',
					terminal_failure_override='CLEANUP_UNCERTAIN',
					terminal_failure_override_digest=$2,version=version+1
				WHERE id=$1
			`, fixture.validationRunID, overrideDigest); err != nil {
				return err
			}
			terminalDigest := sourceRunTerminalDigest(
				t, tx, fixture.validationRunID, "FAILED", "CLEANUP_UNCERTAIN",
			)
			insertTerminalAudit(t, tx, fixture, fixture.validationRunID, terminalDigest)
			if _, err := tx.Exec(context.Background(), `
				UPDATE asset_source_runs
				SET status='FAILED',stage_code='COMPLETED',terminal_command_sha256=$2,
					version=version+1
				WHERE id=$1
			`, fixture.validationRunID, terminalDigest); err != nil {
				return err
			}
			_, err := tx.Exec(context.Background(), `
				UPDATE asset_source_revisions
				SET state='REJECTED',validation_digest=$2,version=version+1
				WHERE id=$1
			`, fixture.revisionID, overrideDigest)
			return err
		})
}

func TestAssetCatalogTerminalDataRunRejectsSourceGateDrift(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedClosureAuthoritativeCompleteCatalog(t, harness.db)
	run := startRuntimeContractManualRun(t, harness.db, fixture)
	finalizeClosureEmptyManualPage(t, harness.db, fixture, run)
	execAssetSQL(t, harness.db, `
		UPDATE asset_sources
		SET gate_status='UNAVAILABLE',gate_reason_code='CLOSURE_DRIFT',
			gate_revision=gate_revision+1,version=version+1
		WHERE id=$1
	`, fixture.sourceID)

	expectClosureCommitError(t, harness.db, pgx.Serializable, "55000",
		"asset_source_runs_source_closure_guard", func(tx pgx.Tx) error {
			return closeClosureManualRun(t, tx, fixture, run.id)
		})
}

func TestAssetCatalogRunPageRejectsSourceAdmissionLostBeforeCommit(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedClosureAuthoritativeCompleteCatalog(t, harness.db)
	run := startRuntimeContractManualRun(t, harness.db, fixture)

	expectClosureCommitError(t, harness.db, pgx.Serializable, "55000",
		"asset_source_runs_page_closure_guard", func(tx pgx.Tx) error {
			pageDigest := strings.Repeat("c", 64)
			if err := insertClosurePageReceipt(tx, fixture, run.id, 1, pageDigest); err != nil {
				return err
			}
			if _, err := tx.Exec(context.Background(), `
				WITH envelope AS (
					SELECT decode('01'||repeat('09',12)||repeat('0a',16),'hex') AS ciphertext
				)
				UPDATE asset_sources AS source
				SET checkpoint_ciphertext=envelope.ciphertext,checkpoint_key_id='opaque-page-key',
					checkpoint_sha256=encode(sha256(envelope.ciphertext),'hex'),
					checkpoint_version=source.checkpoint_version+1,version=source.version+1
				FROM envelope WHERE source.id=$1
			`, fixture.sourceID); err != nil {
				return err
			}
			if _, err := tx.Exec(context.Background(), `
				UPDATE asset_source_runs
				SET stage_code='APPLYING',page_sequence=page_sequence+1,page_digest=$2,
					checkpoint_version=checkpoint_version+1,
					cursor_after_sha256=(SELECT checkpoint_sha256 FROM asset_sources WHERE id=$3),
					heartbeat_sequence=heartbeat_sequence+1,
					heartbeat_at=statement_timestamp(),
					lease_expires_at=lease_expires_at+interval '1 minute',version=version+1
				WHERE id=$1
			`, run.id, pageDigest, fixture.sourceID); err != nil {
				return err
			}
			_, err := tx.Exec(context.Background(), `
				UPDATE asset_sources SET status='PAUSED',version=version+1 WHERE id=$1
			`, fixture.sourceID)
			return err
		})
}

func TestAssetCatalogOwnedFunctionsUseCatalogFirstSearchPath(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)

	var total int
	var unsafeFunctions string
	if err := harness.db.QueryRow(context.Background(), `
		SELECT count(*)::integer,
			COALESCE(string_agg(p.oid::regprocedure::text, ',' ORDER BY p.oid::regprocedure::text)
				FILTER (WHERE p.proconfig IS DISTINCT FROM
					ARRAY['search_path=pg_catalog, public']::text[]), '')
		FROM pg_catalog.pg_proc AS p
		JOIN pg_catalog.pg_namespace AS n ON n.oid=p.pronamespace
		WHERE n.nspname='public' AND (
			p.proname LIKE 'asset_catalog_%' OR
			p.proname LIKE 'enforce_asset_%' OR
			p.proname LIKE 'validate_asset_%' OR
			p.proname LIKE 'reject_asset_catalog_%'
		)
	`).Scan(&total, &unsafeFunctions); err != nil {
		t.Fatalf("read 000015 function search paths: %v", err)
	}
	if total < 31 {
		t.Fatalf("000015 owned function count=%d, want at least 31", total)
	}
	if unsafeFunctions != "" {
		t.Fatalf("000015 functions without fixed catalog-first search_path: %s", unsafeFunctions)
	}
}

func TestAssetCatalogClockShadowCannotExpireLiveRun(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedClosureAuthoritativeCompleteCatalog(t, harness.db)
	run := startRuntimeContractManualRun(t, harness.db, fixture)

	connection, err := pgx.ConnectConfig(context.Background(), harness.db.Config().ConnConfig.Copy())
	if err != nil {
		t.Fatalf("connect fresh hostile-search-path session: %v", err)
	}
	defer func() { _ = connection.Close(context.Background()) }()
	if _, err := connection.Exec(context.Background(), `
		CREATE FUNCTION public.clock_timestamp() RETURNS timestamptz
		LANGUAGE sql VOLATILE
		AS $$ SELECT pg_catalog.clock_timestamp()+interval '100 years' $$
	`); err != nil {
		t.Fatalf("create hostile public.clock_timestamp(): %v", err)
	}
	if _, err := connection.Exec(context.Background(), `
		UPDATE asset_source_runs SET stage_code='APPLYING',version=version+1 WHERE id=$1
	`, run.id); err != nil {
		t.Fatalf("catalog-first trigger rejected a live legal stage mutation: %v", err)
	}
}

func TestAssetCatalogRunningCleanupUncertainCannotCommitWithoutClosure(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedClosureAuthoritativeCompleteCatalog(t, harness.db)
	run := startRuntimeContractManualRun(t, harness.db, fixture)
	reserveClosureCleanupAttempt(t, harness.db, run.id)

	expectClosureCommitError(t, harness.db, pgx.Serializable, "55000",
		"asset_source_runs_cleanup_uncertain_closure_guard", func(tx pgx.Tx) error {
			cleanupDigest := strings.Repeat("a", 64)
			insertCleanupAudit(t, tx, fixture, run.id, run.fenceEpoch, cleanupDigest)
			_, err := tx.Exec(context.Background(), `
				UPDATE asset_source_runs
				SET status='FINALIZING',work_result_kind='FAILURE_INTENT',
					work_result_status='FAILED',work_result_digest=repeat('b',64),
					work_result_recorded_at=statement_timestamp(),
					cleanup_status='UNCERTAIN',cleanup_digest=$2,version=version+1
				WHERE id=$1
			`, run.id, cleanupDigest)
			return err
		})
}

func TestAssetCatalogCleanupProofRequiresCleanupStageAndSealedNextPath(t *testing.T) {
	t.Run("proof outside cleanup stage", func(t *testing.T) {
		harness := newAssetCatalogHarness(t)
		harness.applyThroughAssetCatalog(t)
		fixture := seedClosureAuthoritativeCompleteCatalog(t, harness.db)
		run := startRuntimeContractManualRun(t, harness.db, fixture)
		execAssetSQL(t, harness.db, `
			UPDATE asset_source_runs
			SET cleanup_status='PENDING',cleanup_attempt_id=gen_random_uuid(),
				cleanup_attempt_epoch=fence_epoch,version=version+1 WHERE id=$1
		`, run.id)

		expectClosureCommitError(t, harness.db, pgx.Serializable, "55000",
			"asset_source_runs_cleanup_transition_guard", func(tx pgx.Tx) error {
				cleanupDigest := strings.Repeat("a", 64)
				insertCleanupAudit(t, tx, fixture, run.id, run.fenceEpoch, cleanupDigest)
				_, err := tx.Exec(context.Background(), `
					UPDATE asset_source_runs
					SET cleanup_status='REVOKED',cleanup_digest=$2,version=version+1
					WHERE id=$1
				`, run.id, cleanupDigest)
				return err
			})
	})

	t.Run("proof without sealed next path", func(t *testing.T) {
		harness := newAssetCatalogHarness(t)
		harness.applyThroughAssetCatalog(t)
		fixture := seedClosureAuthoritativeCompleteCatalog(t, harness.db)
		run := startRuntimeContractManualRun(t, harness.db, fixture)
		reserveClosureCleanupAttempt(t, harness.db, run.id)

		expectClosureCommitError(t, harness.db, pgx.Serializable, "55000",
			"asset_source_runs_cleanup_transition_guard", func(tx pgx.Tx) error {
				cleanupDigest := strings.Repeat("a", 64)
				insertCleanupAudit(t, tx, fixture, run.id, run.fenceEpoch, cleanupDigest)
				_, err := tx.Exec(context.Background(), `
					UPDATE asset_source_runs
					SET cleanup_status='REVOKED',cleanup_digest=$2,version=version+1
					WHERE id=$1
				`, run.id, cleanupDigest)
				return err
			})
	})
}

func TestAssetCatalogConsumedCleanupCannotHeartbeat(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedClosureAuthoritativeCompleteCatalog(t, harness.db)
	run := startRuntimeContractManualRun(t, harness.db, fixture)
	reserveClosureCleanupAttempt(t, harness.db, run.id)

	expectClosureCommitError(t, harness.db, pgx.Serializable, "55000",
		"asset_source_runs_cleanup_transition_guard", func(tx pgx.Tx) error {
			if _, err := tx.Exec(context.Background(), closureExactDelayIntentSQL,
				run.id, "30 seconds"); err != nil {
				return err
			}
			cleanupDigest := strings.Repeat("a", 64)
			insertCleanupAudit(t, tx, fixture, run.id, run.fenceEpoch, cleanupDigest)
			if _, err := tx.Exec(context.Background(), `
				UPDATE asset_source_runs
				SET cleanup_status='REVOKED',cleanup_digest=$2,version=version+1
				WHERE id=$1
			`, run.id, cleanupDigest); err != nil {
				return err
			}
			_, err := tx.Exec(context.Background(), `
				UPDATE asset_source_runs
				SET heartbeat_sequence=heartbeat_sequence+1,
					heartbeat_at=statement_timestamp(),
					lease_expires_at=lease_expires_at+interval '1 minute',version=version+1
				WHERE id=$1
			`, run.id)
			return err
		})
}

func TestAssetCatalogDelayIntentAndCleanupCoordinatesAreAtomic(t *testing.T) {
	t.Run("intent sealed before attempt cannot survive reserve", func(t *testing.T) {
		harness := newAssetCatalogHarness(t)
		harness.applyThroughAssetCatalog(t)
		runID := seedClosureExternalValidationRun(t, harness.db)
		expectClosureStatementError(t, harness.db, "55000",
			"asset_source_runs_pending_transition_guard", closureExactDelayIntentSQL,
			runID, "30 seconds")
	})

	t.Run("cleanup proof cannot precede delay intent", func(t *testing.T) {
		harness := newAssetCatalogHarness(t)
		harness.applyThroughAssetCatalog(t)
		fixture := seedClosureAuthoritativeCompleteCatalog(t, harness.db)
		run := startRuntimeContractManualRun(t, harness.db, fixture)
		reserveClosureCleanupAttempt(t, harness.db, run.id)
		expectClosureCommitError(t, harness.db, pgx.Serializable, "55000",
			"asset_source_runs_cleanup_transition_guard", func(tx pgx.Tx) error {
				cleanupDigest := strings.Repeat("a", 64)
				insertCleanupAudit(t, tx, fixture, run.id, run.fenceEpoch, cleanupDigest)
				if _, err := tx.Exec(context.Background(), `
					UPDATE asset_source_runs SET cleanup_status='REVOKED',cleanup_digest=$2,
						version=version+1 WHERE id=$1
				`, run.id, cleanupDigest); err != nil {
					return err
				}
				_, err := tx.Exec(context.Background(), closureExactDelayIntentSQL,
					run.id, "30 seconds")
				return err
			})
	})

	t.Run("pending delay excludes failure finalization", func(t *testing.T) {
		harness := newAssetCatalogHarness(t)
		harness.applyThroughAssetCatalog(t)
		fixture := seedClosureAuthoritativeCompleteCatalog(t, harness.db)
		run := startRuntimeContractManualRun(t, harness.db, fixture)
		reserveClosureCleanupAttempt(t, harness.db, run.id)
		execAssetSQL(t, harness.db, closureExactDelayIntentSQL, run.id, "30 seconds")
		expectClosureStatementError(t, harness.db, "55000",
			"asset_source_runs_finalization_guard", `
			UPDATE asset_source_runs
			SET status='FINALIZING',work_result_kind='FAILURE_INTENT',
				work_result_status='FAILED',work_result_digest=repeat('f',64),
				work_result_recorded_at=statement_timestamp(),version=version+1
			WHERE id=$1
		`, run.id)
	})
}

func TestAssetCatalogExternalValidationCanAtomicallyAbandonDelayForCleanupUncertain(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	runID := seedClosureExternalValidationRun(t, harness.db)
	fixture := newAssetCatalogFixture()
	fixture.sourceID = closureExternalSourceID
	fixture.revisionID = closureExternalRevisionID
	fixture.validationRunID = runID
	execAssetSQL(t, harness.db, `
		UPDATE asset_source_runs
		SET stage_code='CLEANING_UP',cleanup_status='PENDING',
			cleanup_attempt_id='8d000000-0000-4000-8000-000000000004',
			cleanup_attempt_epoch=fence_epoch,version=version+1
		WHERE id=$1
	`, runID)
	execAssetSQL(t, harness.db, closureExactDelayIntentSQL, runID, "30 seconds")

	tx, err := harness.db.BeginTx(context.Background(), pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		t.Fatalf("begin cleanup-uncertain delay abandonment: %v", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	cleanupDigest := strings.Repeat("a", 64)
	insertCleanupAudit(t, tx, fixture, runID, 1, cleanupDigest)
	if _, err := tx.Exec(context.Background(), `
		UPDATE asset_source_runs
		SET status='FINALIZING',pending_transition=NULL,pending_transition_reason=NULL,
			pending_transition_not_before=NULL,pending_transition_digest=NULL,
			work_result_kind='FAILURE_INTENT',work_result_status='FAILED',
			work_result_digest=repeat('b',64),work_result_recorded_at=statement_timestamp(),
			cleanup_status='UNCERTAIN',cleanup_digest=$2,version=version+1
		WHERE id=$1
	`, runID, cleanupDigest); err != nil {
		t.Fatalf("atomically abandon delay into uncertain failure intent: %v", err)
	}
	var overrideDigest string
	if err := tx.QueryRow(context.Background(), `
		SELECT asset_catalog_source_run_failure_override_digest(run,'CLEANUP_UNCERTAIN')
		FROM asset_source_runs AS run WHERE id=$1
	`, runID).Scan(&overrideDigest); err != nil {
		t.Fatalf("derive cleanup-uncertain override: %v", err)
	}
	if _, err := tx.Exec(context.Background(), `
		UPDATE asset_source_runs
		SET failure_code='CLEANUP_UNCERTAIN',terminal_failure_override='CLEANUP_UNCERTAIN',
			terminal_failure_override_digest=$2,version=version+1 WHERE id=$1
	`, runID, overrideDigest); err != nil {
		t.Fatalf("seal cleanup-uncertain override: %v", err)
	}
	terminalDigest := sourceRunTerminalDigest(t, tx, runID, "FAILED", "CLEANUP_UNCERTAIN")
	insertTerminalAudit(t, tx, fixture, runID, terminalDigest)
	if _, err := tx.Exec(context.Background(), `
		UPDATE asset_source_runs
		SET status='FAILED',stage_code='COMPLETED',terminal_command_sha256=$2,
			version=version+1 WHERE id=$1
	`, runID, terminalDigest); err != nil {
		t.Fatalf("fail cleanup-uncertain validation: %v", err)
	}
	if _, err := tx.Exec(context.Background(), `
		UPDATE asset_sources
		SET gate_status='SUSPENDED',gate_reason_code='CLEANUP_UNCERTAIN',
			gate_revision=gate_revision+1,version=version+1 WHERE id=$1
	`, fixture.sourceID); err != nil {
		t.Fatalf("suspend cleanup-uncertain source: %v", err)
	}
	if _, err := tx.Exec(context.Background(), `
		UPDATE asset_source_revisions
		SET state='REJECTED',validation_digest=$2,version=version+1 WHERE id=$1
	`, fixture.revisionID, overrideDigest); err != nil {
		t.Fatalf("reject cleanup-uncertain revision: %v", err)
	}
	if err := tx.Commit(context.Background()); err != nil {
		t.Fatalf("commit cleanup-uncertain delay abandonment: %v", err)
	}
}

func TestAssetCatalogManualProfileIsClosed(t *testing.T) {
	t.Run("manual source requires MANUAL_V1 provider", func(t *testing.T) {
		harness := newAssetCatalogHarness(t)
		harness.applyThroughAssetCatalog(t)
		fixture := seedDraftAssetCatalog(t, harness.db)
		expectClosureStatementError(t, harness.db, "23514", "asset_sources_manual_provider_guard", `
			INSERT INTO asset_sources (
				id,tenant_id,workspace_id,source_kind,provider_kind,name,
				create_idempotency_key,create_request_hash
			) VALUES (
				'8e000000-0000-4000-8000-000000000001',$1,$2,'MANUAL','EXTERNAL_V1',
				'invalid manual source','invalid-manual-source',repeat('1',64)
			)
		`, fixture.tenantID, fixture.workspaceID)
	})

	t.Run("non-manual source rejects MANUAL_V1 provider", func(t *testing.T) {
		harness := newAssetCatalogHarness(t)
		harness.applyThroughAssetCatalog(t)
		fixture := seedDraftAssetCatalog(t, harness.db)
		expectClosureStatementError(t, harness.db, "23514", "asset_sources_manual_provider_guard", `
			INSERT INTO asset_sources (
				id,tenant_id,workspace_id,source_kind,provider_kind,name,
				create_idempotency_key,create_request_hash
			) VALUES (
				'8e000000-0000-4000-8000-000000000002',$1,$2,'EXTERNAL_CMDB','MANUAL_V1',
				'invalid external source','invalid-external-source',repeat('2',64)
			)
		`, fixture.tenantID, fixture.workspaceID)
	})

	for _, reference := range []string{
		"credential_reference_id", "trust_reference_id", "network_policy_reference_id",
	} {
		t.Run("manual revision rejects "+reference, func(t *testing.T) {
			harness := newAssetCatalogHarness(t)
			harness.applyThroughAssetCatalog(t)
			fixture := seedDraftAssetCatalog(t, harness.db)
			insertClosureManualRevisionExpectingError(t, harness.db, fixture,
				"MANUAL_V1", reference, "asset_source_revisions_manual_profile_guard")
		})
	}

	t.Run("manual revision requires MANUAL_V1 profile", func(t *testing.T) {
		harness := newAssetCatalogHarness(t)
		harness.applyThroughAssetCatalog(t)
		fixture := seedDraftAssetCatalog(t, harness.db)
		insertClosureManualRevisionExpectingError(t, harness.db, fixture,
			"EXTERNAL_V1", "", "asset_source_revisions_manual_profile_guard")
	})
}

func TestAssetCatalogManualValidationRejectsCredentialCleanupAttempt(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedDraftAssetCatalog(t, harness.db)
	expectClosureCommitError(t, harness.db, pgx.Serializable, "55000",
		"asset_source_runs_cleanup_transition_guard", func(tx pgx.Tx) error {
			startClosureManualValidationRunInTx(t, tx, fixture)
			_, err := tx.Exec(context.Background(), `
				UPDATE asset_source_runs
				SET stage_code='CLEANING_UP',cleanup_status='PENDING',
					cleanup_attempt_id=gen_random_uuid(),cleanup_attempt_epoch=fence_epoch,
					version=version+1
				WHERE id=$1
			`, fixture.validationRunID)
			return err
		})
}

func TestAssetCatalogManualQueuedRunCannotCommit(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedDraftAssetCatalog(t, harness.db)
	expectClosureCommitError(t, harness.db, pgx.Serializable, "55000",
		"asset_source_runs_manual_atomic_guard", func(tx pgx.Tx) error {
			_, err := tx.Exec(context.Background(), `
				INSERT INTO asset_source_runs (
					id,tenant_id,workspace_id,source_id,source_revision,source_revision_digest,
					run_kind,trigger_type,gate_revision,idempotency_key,request_hash,checkpoint_version
				) SELECT $1,$2,$3,$4,1,$5,'VALIDATION','HUMAN',gate_revision,
					'manual-queued-atomic-red',repeat('1',64),0
				FROM asset_sources WHERE id=$4
			`, fixture.validationRunID, fixture.tenantID, fixture.workspaceID,
				fixture.sourceID, fixture.revisionDigest)
			return err
		})
}

func TestAssetCatalogManualMutationRejectsCredentialCleanupAttempt(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedGovernedManualCatalog(t, harness.db)
	expectClosureCommitError(t, harness.db, pgx.Serializable, "55000",
		"asset_source_runs_cleanup_transition_guard", func(tx pgx.Tx) error {
			run := startClosureManualMutationRunInTx(t, tx, fixture)
			_, err := tx.Exec(context.Background(), `
				UPDATE asset_source_runs
				SET stage_code='CLEANING_UP',cleanup_status='PENDING',
					cleanup_attempt_id=gen_random_uuid(),cleanup_attempt_epoch=fence_epoch,
					version=version+1
				WHERE id=$1
			`, run.id)
			return err
		})
}

func TestAssetCatalogManualRevokedCleanupCannotBeTerminallySealed(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedGovernedManualCatalog(t, harness.db)
	run := seedForgedLegacyManualFinalizingRun(t, harness.db, fixture)
	execAssetSQL(t, harness.db,
		`ALTER TABLE asset_source_runs DISABLE TRIGGER asset_source_runs_terminal_closure_guard`)
	execAssetSQL(t, harness.db,
		`ALTER TABLE asset_source_runs DISABLE TRIGGER asset_source_runs_mutation_guard`)
	t.Cleanup(func() {
		_, _ = harness.db.Exec(context.Background(),
			`ALTER TABLE asset_source_runs ENABLE TRIGGER asset_source_runs_mutation_guard`)
	})
	execAssetSQL(t, harness.db, `
		UPDATE asset_source_runs
		SET cleanup_status='REVOKED',
			cleanup_attempt_id='8f700000-0000-4000-8000-000000000001',
			cleanup_attempt_epoch=fence_epoch,cleanup_digest=repeat('e',64)
		WHERE id=$1
	`, run.id)
	execAssetSQL(t, harness.db,
		`ALTER TABLE asset_source_runs ENABLE TRIGGER asset_source_runs_mutation_guard`)
	execAssetSQL(t, harness.db,
		`ALTER TABLE asset_source_runs ENABLE TRIGGER asset_source_runs_terminal_closure_guard`)
	expectClosureCommitError(t, harness.db, pgx.Serializable, "55000",
		"asset_source_runs_cleanup_transition_guard", func(tx pgx.Tx) error {
			return closeClosureManualRun(t, tx, fixture, run.id)
		})
}

func TestAssetCatalogManualRunRejectsLineageRollover(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedGovernedManualCatalog(t, harness.db)

	expectClosureCommitError(t, harness.db, pgx.Serializable, "55000",
		"asset_source_runs_manual_rollover_guard", func(tx pgx.Tx) error {
			run := startClosureManualMutationRunInTx(t, tx, fixture)
			if _, err := tx.Exec(context.Background(), `
				INSERT INTO audit_records (
					id,tenant_id,workspace_id,actor_type,actor_id,action,resource_type,
					resource_id,request_id,trace_id,payload_hash
				) VALUES (
					gen_random_uuid(),$1,$2,'SYSTEM','runtime-manual-executor',
					'CHECKPOINT_LINEAGE_ROLLOVER_BOUND','ASSET_SOURCE_RUN',$3,
					'source-rollover:'||$3,'manual-rollover-trace',repeat('b',64)
				)
			`, fixture.tenantID, fixture.workspaceID, run.id); err != nil {
				return err
			}
			if _, err := tx.Exec(context.Background(), `
				UPDATE asset_sources
				SET gate_status='DEGRADED',gate_reason_code='CHECKPOINT_LINEAGE_ROLLOVER',
					gate_revision=gate_revision+1,version=version+1
				WHERE id=$1
			`, fixture.sourceID); err != nil {
				return err
			}
			_, err := tx.Exec(context.Background(), `
				UPDATE asset_source_runs
				SET lineage_rollover_reason='PROVIDER_CURSOR_EXPIRED',
					lineage_rollover_evidence_digest=repeat('b',64),version=version+1
				WHERE id=$1
			`, run.id)
			return err
		})
}

func TestAssetCatalogFailedRolloverRejectsNullSuspensionReason(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedClosureAuthoritativeCompleteCatalog(t, harness.db)
	run := startClosureExternalDiscoveryRun(t, harness.db, fixture)
	bindClosureExternalRollover(t, harness.db, fixture, run)
	execAssetSQL(t, harness.db, `
		UPDATE asset_source_runs
		SET stage_code='CLEANING_UP',cleanup_status='PENDING',
			cleanup_attempt_id=gen_random_uuid(),cleanup_attempt_epoch=fence_epoch,
			version=version+1
		WHERE id=$1
	`, run.id)
	execAssetSQL(t, harness.db, `
		UPDATE asset_source_runs
		SET status='FINALIZING',work_result_kind='FAILURE_INTENT',
			work_result_status='FAILED',work_result_digest=repeat('c',64),
			version=version+1
		WHERE id=$1
	`, run.id)
	revokeClosureAttempt(t, harness.db, fixture, run.id, strings.Repeat("d", 64))

	expectClosureCommitError(t, harness.db, pgx.Serializable, "55000",
		"asset_source_runs_rollover_closure_guard", func(tx pgx.Tx) error {
			terminalDigest := sourceRunTerminalDigest(t, tx, run.id, "FAILED", "ROLLOVER_FAILED")
			insertTerminalAudit(t, tx, fixture, run.id, terminalDigest)
			if _, err := tx.Exec(context.Background(), `
				UPDATE asset_source_runs
				SET status='FAILED',stage_code='COMPLETED',failure_code='ROLLOVER_FAILED',
					terminal_command_sha256=$2,version=version+1
				WHERE id=$1
			`, run.id, terminalDigest); err != nil {
				return err
			}
			_, err := tx.Exec(context.Background(), `
				UPDATE asset_sources
				SET gate_status='SUSPENDED',gate_reason_code=NULL,
					gate_revision=gate_revision+1,version=version+1
				WHERE id=$1
			`, fixture.sourceID)
			return err
		})
}

func TestAssetCatalogRunKindMatchesManualProfile(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedGovernedManualCatalog(t, harness.db)
	for _, runKind := range []string{"DISCOVERY", "CSV_IMPORT", "API_INGESTION"} {
		t.Run("manual rejects "+runKind, func(t *testing.T) {
			expectClosureStatementError(t, harness.db, "23514",
				"asset_source_runs_manual_profile_guard", `
				INSERT INTO asset_source_runs (
					id,tenant_id,workspace_id,source_id,source_revision,source_revision_digest,
					run_kind,trigger_type,gate_revision,idempotency_key,request_hash,
					checkpoint_version,cursor_before_sha256
				) SELECT '8f200000-0000-4000-8000-000000000001',$1,$2,$3,
					published_revision,published_revision_digest,$4,'HUMAN',gate_revision,
					'manual-forbidden-run',repeat('1',64),checkpoint_version,checkpoint_sha256
				FROM asset_sources WHERE id=$3
			`, fixture.tenantID, fixture.workspaceID, fixture.sourceID, runKind)
		})
	}

	t.Run("non-manual rejects MANUAL_MUTATION", func(t *testing.T) {
		externalHarness := newAssetCatalogHarness(t)
		externalHarness.applyThroughAssetCatalog(t)
		runID := seedClosureExternalValidationRun(t, externalHarness.db)
		expectClosureStatementError(t, externalHarness.db, "23514",
			"asset_source_runs_manual_profile_guard", `
			INSERT INTO asset_source_runs (
				id,tenant_id,workspace_id,source_id,source_revision,source_revision_digest,
				run_kind,trigger_type,gate_revision,idempotency_key,request_hash,checkpoint_version
			) SELECT '8f200000-0000-4000-8000-000000000002',tenant_id,workspace_id,
				source_id,source_revision,source_revision_digest,'MANUAL_MUTATION','HUMAN',
				gate_revision,'external-forbidden-manual-run',repeat('2',64),0
			FROM asset_source_runs WHERE id=$1
		`, runID)
	})
}

func TestAssetCatalogCleanupUncertainOverrideIsWriteOnce(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedDraftAssetCatalog(t, harness.db)
	fixture = seedClosureExternalValidationOnFixture(t, harness.db, fixture)
	prepareCleanupUncertainValidationRun(t, harness.db, fixture)

	expectClosureCommitError(t, harness.db, pgx.Serializable, "55000",
		"asset_source_runs_terminal_transition_guard", func(tx pgx.Tx) error {
			cleanupDigest := strings.Repeat("a", 64)
			insertCleanupAudit(t, tx, fixture, fixture.validationRunID, 1, cleanupDigest)
			if _, err := tx.Exec(context.Background(), `
				UPDATE asset_source_runs
				SET cleanup_status='UNCERTAIN',cleanup_digest=$2,version=version+1
				WHERE id=$1
			`, fixture.validationRunID, cleanupDigest); err != nil {
				return err
			}
			var digest string
			if err := tx.QueryRow(context.Background(), `
				SELECT asset_catalog_source_run_failure_override_digest(run,'CLEANUP_UNCERTAIN')
				FROM asset_source_runs AS run WHERE id=$1
			`, fixture.validationRunID).Scan(&digest); err != nil {
				return err
			}
			if _, err := tx.Exec(context.Background(), `
				UPDATE asset_source_runs
				SET failure_code='CLEANUP_UNCERTAIN',
					terminal_failure_override='CLEANUP_UNCERTAIN',
					terminal_failure_override_digest=$2,version=version+1
				WHERE id=$1
			`, fixture.validationRunID, digest); err != nil {
				return err
			}
			_, err := tx.Exec(context.Background(), `
				UPDATE asset_source_runs
				SET failure_code='REWRITTEN_FAILURE',terminal_failure_override_digest=repeat('f',64),
					version=version+1 WHERE id=$1
			`, fixture.validationRunID)
			return err
		})
}

func TestAssetCatalogFailedTerminalCannotExploitNullOverride(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedClosureAuthoritativeCompleteCatalog(t, harness.db)
	run := startRuntimeContractManualRun(t, harness.db, fixture)
	finalizeClosureEmptyManualPage(t, harness.db, fixture, run)

	expectClosureCommitError(t, harness.db, pgx.Serializable, "55000",
		"asset_source_runs_terminal_transition_guard", func(tx pgx.Tx) error {
			terminalDigest := sourceRunTerminalDigest(t, tx, run.id, "FAILED", "FORGED_FAILED")
			insertTerminalAudit(t, tx, fixture, run.id, terminalDigest)
			_, err := tx.Exec(context.Background(), `
				UPDATE asset_source_runs
				SET status='FAILED',stage_code='COMPLETED',failure_code='FORGED_FAILED',
					terminal_command_sha256=$2,version=version+1
				WHERE id=$1
			`, run.id, terminalDigest)
			return err
		})
}

func TestAssetCatalogSuccessPointerCannotBeClearedOutsidePublication(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedGovernedManualCatalog(t, harness.db)
	expectClosureStatementError(t, harness.db, "55000", "asset_sources_last_success_guard", `
		UPDATE asset_sources
		SET last_success_run_id=NULL,last_success_at=NULL,version=version+1
		WHERE id=$1
	`, fixture.sourceID)
}

func TestAssetCatalogCompleteSnapshotPointerCannotBeClearedOutsidePublication(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedClosureAuthoritativeCompleteCatalog(t, harness.db)
	expectClosureStatementError(t, harness.db, "55000",
		"asset_sources_last_complete_snapshot_guard", `
		UPDATE asset_sources
		SET last_complete_snapshot_run_id=NULL,last_complete_snapshot_at=NULL,
			version=version+1
		WHERE id=$1
	`, fixture.sourceID)
}

func TestAssetCatalogSupersededCompleteRunCannotBeReattachedAfterPublication(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedClosureAuthoritativeCompleteCatalog(t, harness.db)
	oldCompleteRunID := fixture.runID
	publishClosureExternalSuccessor(t, harness.db, fixture)
	expectClosureStatementError(t, harness.db, "23514",
		"asset_sources_last_complete_snapshot_guard", `
		UPDATE asset_sources
		SET last_complete_snapshot_run_id=$2,
			last_complete_snapshot_at=(SELECT completed_at FROM asset_source_runs WHERE id=$2),
			version=version+1
		WHERE id=$1
	`, fixture.sourceID, oldCompleteRunID)
}

func TestAssetCatalogAdmittedQueuedDataRunCannotCancelIneligible(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedGovernedManualCatalog(t, harness.db)
	const runID = "8f300000-0000-4000-8000-000000000001"
	expectClosureCommitError(t, harness.db, pgx.Serializable, "55000",
		"asset_source_runs_cancel_guard", func(tx pgx.Tx) error {
			if _, err := tx.Exec(context.Background(), `
				INSERT INTO asset_source_runs (
					id,tenant_id,workspace_id,source_id,source_revision,source_revision_digest,
					run_kind,trigger_type,gate_revision,idempotency_key,request_hash,
					checkpoint_version,cursor_before_sha256
				) SELECT $1,$2,$3,$4,published_revision,published_revision_digest,
					'MANUAL_MUTATION','HUMAN',gate_revision,'admitted-cancel-ineligible',
					repeat('1',64),checkpoint_version,checkpoint_sha256
				FROM asset_sources WHERE id=$4
			`, runID, fixture.tenantID, fixture.workspaceID, fixture.sourceID); err != nil {
				return err
			}
			_, err := tx.Exec(context.Background(), `
				UPDATE asset_source_runs
				SET status='CANCELLED',stage_code='COMPLETED',version=version+1 WHERE id=$1
			`, runID)
			return err
		})
}

func TestAssetCatalogNullableShapeChecksFailClosed(t *testing.T) {
	tests := []struct {
		name       string
		constraint string
		mutation   string
	}{
		{
			name:       "data projection status cannot be null",
			constraint: "asset_source_runs_work_result_ck",
			mutation:   `UPDATE asset_source_runs SET work_result_status=NULL WHERE id=$1`,
		},
		{
			name:       "delay fields cannot exist without transition",
			constraint: "asset_source_runs_pending_transition_ck",
			mutation: `UPDATE asset_source_runs SET pending_transition=NULL,
				pending_transition_reason='TRANSPORT_BACKOFF',
				pending_transition_not_before=statement_timestamp()+interval '30 seconds',
				pending_transition_digest=repeat('a',64) WHERE id=$1`,
		},
		{
			name:       "override digest cannot exist without override",
			constraint: "asset_source_runs_terminal_override_ck",
			mutation: `UPDATE asset_source_runs SET terminal_failure_override=NULL,
				terminal_failure_override_digest=repeat('b',64) WHERE id=$1`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			harness := newAssetCatalogHarness(t)
			harness.applyThroughAssetCatalog(t)
			fixture := seedClosureAuthoritativeCompleteCatalog(t, harness.db)
			run := startRuntimeContractManualRun(t, harness.db, fixture)
			finalizeClosureEmptyManualPage(t, harness.db, fixture, run)
			execAssetSQL(t, harness.db,
				`ALTER TABLE asset_source_runs DISABLE TRIGGER asset_source_runs_mutation_guard`)
			t.Cleanup(func() {
				_, _ = harness.db.Exec(context.Background(),
					`ALTER TABLE asset_source_runs ENABLE TRIGGER asset_source_runs_mutation_guard`)
			})
			expectClosureStatementError(t, harness.db, "23514", test.constraint,
				test.mutation, run.id)
		})
	}
}

func TestAssetCatalogNullableRelationshipAndPublishedPointerChecksFailClosed(t *testing.T) {
	t.Run("discovered relationship requires source provenance", func(t *testing.T) {
		harness := newAssetCatalogHarness(t)
		harness.applyThroughAssetCatalog(t)
		fixture := seedGovernedManualCatalog(t, harness.db)
		execAssetSQL(t, harness.db,
			`ALTER TABLE asset_relationships DISABLE TRIGGER asset_relationships_mutation_guard`)
		t.Cleanup(func() {
			_, _ = harness.db.Exec(context.Background(),
				`ALTER TABLE asset_relationships ENABLE TRIGGER asset_relationships_mutation_guard`)
		})
		expectClosureStatementError(t, harness.db, "23514",
			"asset_relationships_provenance_ck", `
			UPDATE asset_relationships SET provenance_source_id=NULL WHERE id=$1
		`, fixture.relationshipID)
	})

	t.Run("published digest requires revision", func(t *testing.T) {
		harness := newAssetCatalogHarness(t)
		harness.applyThroughAssetCatalog(t)
		fixture := seedDraftAssetCatalog(t, harness.db)
		execAssetSQL(t, harness.db,
			`ALTER TABLE asset_sources DISABLE TRIGGER asset_sources_mutation_guard`)
		t.Cleanup(func() {
			_, _ = harness.db.Exec(context.Background(),
				`ALTER TABLE asset_sources ENABLE TRIGGER asset_sources_mutation_guard`)
		})
		expectClosureStatementError(t, harness.db, "23514",
			"asset_sources_published_pointer_ck", `
			UPDATE asset_sources SET published_revision=NULL,
				published_revision_digest=repeat('f',64) WHERE id=$1
		`, fixture.sourceID)
	})
}

func TestAssetCatalogDelayIntentIsExactAndBounded(t *testing.T) {
	t.Run("arbitrary digest is rejected", func(t *testing.T) {
		harness := newAssetCatalogHarness(t)
		harness.applyThroughAssetCatalog(t)
		runID := seedClosureExternalValidationCleanupAttempt(t, harness.db)
		expectClosureStatementError(t, harness.db, "55000",
			"asset_source_runs_pending_transition_guard", `
			WITH intent AS (SELECT statement_timestamp()+interval '30 seconds' AS not_before)
			UPDATE asset_source_runs AS run
			SET stage_code='CLEANING_UP',pending_transition='DELAY',
				pending_transition_reason='TRANSPORT_BACKOFF',
				pending_transition_not_before=intent.not_before,
				pending_transition_digest=repeat('a',64),version=run.version+1
			FROM intent WHERE run.id=$1
		`, runID)
	})

	t.Run("delay cannot exceed revision maximum", func(t *testing.T) {
		harness := newAssetCatalogHarness(t)
		harness.applyThroughAssetCatalog(t)
		runID := seedClosureExternalValidationCleanupAttempt(t, harness.db)
		expectClosureStatementError(t, harness.db, "55000",
			"asset_source_runs_pending_transition_guard", closureExactDelayIntentSQL,
			runID, "61 seconds")
	})

	t.Run("exact digest inside revision window is accepted", func(t *testing.T) {
		harness := newAssetCatalogHarness(t)
		harness.applyThroughAssetCatalog(t)
		runID := seedClosureExternalValidationCleanupAttempt(t, harness.db)
		if _, err := harness.db.Exec(context.Background(), closureExactDelayIntentSQL,
			runID, "30 seconds"); err != nil {
			t.Fatalf("persist exact bounded delay intent: %v", err)
		}
	})
}

func TestAssetCatalogManualRunRejectsDelayIntent(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedGovernedManualCatalog(t, harness.db)
	expectClosureCommitError(t, harness.db, pgx.Serializable, "55000",
		"asset_source_runs_pending_transition_guard", func(tx pgx.Tx) error {
			run := startClosureManualMutationRunInTx(t, tx, fixture)
			_, err := tx.Exec(context.Background(), closureExactDelayIntentSQL,
				run.id, "30 seconds")
			return err
		})
}

func TestAssetCatalogManualRunRejectsDelayedStates(t *testing.T) {
	t.Run("RUNNING cannot become DELAYED", func(t *testing.T) {
		harness := newAssetCatalogHarness(t)
		harness.applyThroughAssetCatalog(t)
		fixture := seedGovernedManualCatalog(t, harness.db)
		expectClosureCommitError(t, harness.db, pgx.Serializable, "55000",
			"asset_source_runs_pending_transition_guard", func(tx pgx.Tx) error {
				run := startClosureManualMutationRunInTx(t, tx, fixture)
				_, err := tx.Exec(context.Background(), `
					UPDATE asset_source_runs
					SET status='DELAYED',stage_code='DELAYED',lease_owner=NULL,
						lease_expires_at=NULL,fence_token_hash=NULL,version=version+1
					WHERE id=$1
				`, run.id)
				return err
			})
	})

	t.Run("FINALIZING cannot become DELAYED", func(t *testing.T) {
		harness := newAssetCatalogHarness(t)
		harness.applyThroughAssetCatalog(t)
		fixture := seedGovernedManualCatalog(t, harness.db)
		expectClosureCommitError(t, harness.db, pgx.Serializable, "55000",
			"asset_source_runs_pending_transition_guard", func(tx pgx.Tx) error {
				run := startClosureManualMutationRunInTx(t, tx, fixture)
				stageClosureManualEmptyPageInTx(t, tx, fixture, run)
				_, err := tx.Exec(context.Background(), `
					UPDATE asset_source_runs
					SET status='DELAYED',stage_code='DELAYED',lease_owner=NULL,
						lease_expires_at=NULL,fence_token_hash=NULL,version=version+1
					WHERE id=$1
				`, run.id)
				return err
			})
	})
}

func TestAssetCatalogManualNoCredentialCleanupCannotReset(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedGovernedManualCatalog(t, harness.db)
	run := seedForgedLegacyManualFinalizingRun(t, harness.db, fixture)
	execAssetSQL(t, harness.db,
		`ALTER TABLE asset_source_runs DISABLE TRIGGER asset_source_runs_terminal_closure_guard`)
	execAssetSQL(t, harness.db,
		`ALTER TABLE asset_source_runs DISABLE TRIGGER asset_source_runs_mutation_guard`)
	t.Cleanup(func() {
		_, _ = harness.db.Exec(context.Background(),
			`ALTER TABLE asset_source_runs ENABLE TRIGGER asset_source_runs_mutation_guard`)
	})
	execAssetSQL(t, harness.db, `
		UPDATE asset_source_runs
		SET status='DELAYED',stage_code='DELAYED',lease_owner=NULL,lease_expires_at=NULL,
			fence_token_hash=NULL,work_result_kind=NULL,work_result_status=NULL,
			work_result_digest=NULL,work_result_recorded_at=NULL,version=version+1
		WHERE id=$1
	`, run.id)
	execAssetSQL(t, harness.db,
		`ALTER TABLE asset_source_runs ENABLE TRIGGER asset_source_runs_mutation_guard`)
	execAssetSQL(t, harness.db,
		`ALTER TABLE asset_source_runs ENABLE TRIGGER asset_source_runs_terminal_closure_guard`)
	expectClosureCommitError(t, harness.db, pgx.Serializable, "55000",
		"asset_source_runs_cleanup_transition_guard", func(tx pgx.Tx) error {
			_, err := tx.Exec(context.Background(), `
				UPDATE asset_source_runs
				SET status='RUNNING',stage_code='READING',lease_owner='manual-reset-worker',
					lease_expires_at=statement_timestamp()+interval '5 minutes',
					fence_epoch=fence_epoch+1,fence_token_hash=repeat('f',64),
					heartbeat_sequence=heartbeat_sequence+1,cleanup_status='NOT_OPENED',
					cleanup_attempt_id=NULL,cleanup_attempt_epoch=0,cleanup_digest=NULL,
					version=version+1
				WHERE id=$1
			`, run.id)
			return err
		})
}

func TestAssetCatalogManualNoCredentialRequiresSameTransactionTerminalClosure(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedDraftAssetCatalog(t, harness.db)
	expectClosureCommitError(t, harness.db, pgx.Serializable, "55000",
		"asset_source_runs_manual_cleanup_closure_guard", func(tx pgx.Tx) error {
			startClosureManualValidationRunInTx(t, tx, fixture)
			cleanupDigest := sourceRunNoCredentialDigest(t, tx, fixture.validationRunID)
			insertCleanupAudit(t, tx, fixture, fixture.validationRunID, 0, cleanupDigest)
			_, err := tx.Exec(context.Background(), `
				UPDATE asset_source_runs
				SET status='FINALIZING',stage_code='CLEANING_UP',
					work_result_kind='VALIDATION_PROOF',work_result_status='SUCCEEDED',
					work_result_digest=repeat('a',64),validation_outcome='SUCCEEDED',
					validation_digest=repeat('a',64),validation_proof_digest=repeat('a',64),
					cleanup_status='NO_CREDENTIAL',cleanup_digest=$2,version=version+1
				WHERE id=$1
			`, fixture.validationRunID, cleanupDigest)
			return err
		})
}

func TestAssetCatalogTerminalClosureRequiresSerializableIsolation(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedClosureAuthoritativeCompleteCatalog(t, harness.db)
	run := startRuntimeContractManualRun(t, harness.db, fixture)
	finalizeClosureEmptyManualPage(t, harness.db, fixture, run)

	expectClosureCommitError(t, harness.db, pgx.ReadCommitted, "55000",
		"asset_source_runs_terminal_isolation_guard", func(tx pgx.Tx) error {
			return closeClosureManualRun(t, tx, fixture, run.id)
		})
}

func TestAssetCatalogQueuedValidationCancellationRequiresSerializableIsolation(t *testing.T) {
	t.Run("read committed is rejected", func(t *testing.T) {
		harness := newAssetCatalogHarness(t)
		harness.applyThroughAssetCatalog(t)
		fixture := prepareQueuedClosureValidation(t, harness.db)
		expectClosureCommitError(t, harness.db, pgx.ReadCommitted, "55000",
			"asset_source_runs_terminal_isolation_guard", func(tx pgx.Tx) error {
				return cancelQueuedClosureValidation(tx, fixture)
			})
	})

	t.Run("serializable closes the bound revision", func(t *testing.T) {
		harness := newAssetCatalogHarness(t)
		harness.applyThroughAssetCatalog(t)
		fixture := prepareQueuedClosureValidation(t, harness.db)
		tx, err := harness.db.BeginTx(context.Background(), pgx.TxOptions{IsoLevel: pgx.Serializable})
		if err != nil {
			t.Fatalf("begin serializable validation cancellation: %v", err)
		}
		defer func() { _ = tx.Rollback(context.Background()) }()
		if err := cancelQueuedClosureValidation(tx, fixture); err != nil {
			t.Fatalf("close queued validation cancellation: %v", err)
		}
		if err := tx.Commit(context.Background()); err != nil {
			t.Fatalf("commit serializable validation cancellation: %v", err)
		}
	})
}

func TestAssetCatalogQueuedManualMutationCancellationRequiresSerializableIsolation(t *testing.T) {
	t.Run("read committed is rejected", func(t *testing.T) {
		harness := newAssetCatalogHarness(t)
		harness.applyThroughAssetCatalog(t)
		fixture := seedGovernedManualCatalog(t, harness.db)
		expectClosureCommitError(t, harness.db, pgx.ReadCommitted, "55000",
			"asset_source_runs_terminal_isolation_guard", func(tx pgx.Tx) error {
				return createAndCancelIneligibleManualMutation(tx, fixture,
					"8f310000-0000-4000-8000-000000000001", "manual-cancel-read-committed")
			})
	})

	t.Run("serializable closes synchronously", func(t *testing.T) {
		harness := newAssetCatalogHarness(t)
		harness.applyThroughAssetCatalog(t)
		fixture := seedGovernedManualCatalog(t, harness.db)
		tx, err := harness.db.BeginTx(context.Background(), pgx.TxOptions{IsoLevel: pgx.Serializable})
		if err != nil {
			t.Fatalf("begin serializable manual mutation cancellation: %v", err)
		}
		defer func() { _ = tx.Rollback(context.Background()) }()
		if err := createAndCancelIneligibleManualMutation(tx, fixture,
			"8f310000-0000-4000-8000-000000000002", "manual-cancel-serializable"); err != nil {
			t.Fatalf("close queued manual mutation cancellation: %v", err)
		}
		if err := tx.Commit(context.Background()); err != nil {
			t.Fatalf("commit serializable manual mutation cancellation: %v", err)
		}
	})
}

func TestAssetCatalogIneligibleQueuedCancellationCannotInjectExecutionFacts(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := prepareQueuedClosureValidation(t, harness.db)

	tests := []struct {
		name     string
		mutation string
	}{
		{
			name: "started_at",
			mutation: `UPDATE asset_source_runs
				SET status='CANCELLED',stage_code='COMPLETED',started_at=statement_timestamp(),
					version=version+1 WHERE id=$1`,
		},
		{
			name: "heartbeat_at",
			mutation: `UPDATE asset_source_runs
				SET status='CANCELLED',stage_code='COMPLETED',heartbeat_at=statement_timestamp(),
					version=version+1 WHERE id=$1`,
		},
		{
			name: "fence_epoch",
			mutation: `UPDATE asset_source_runs
				SET status='CANCELLED',stage_code='COMPLETED',fence_epoch=1,
					version=version+1 WHERE id=$1`,
		},
		{
			name: "failure_code",
			mutation: `UPDATE asset_source_runs
				SET status='CANCELLED',stage_code='COMPLETED',failure_code='FORGED_FAILURE',
					version=version+1 WHERE id=$1`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			expectClosureCommitError(t, harness.db, pgx.Serializable, "55000",
				"asset_source_runs_cancel_guard", func(tx pgx.Tx) error {
					_, err := tx.Exec(context.Background(), test.mutation, fixture.validationRunID)
					return err
				})
		})
	}
}

func TestAssetCatalogValidationBindingIsImmutableWithinSameState(t *testing.T) {
	t.Run("VALIDATING cannot rebind", func(t *testing.T) {
		harness := newAssetCatalogHarness(t)
		harness.applyThroughAssetCatalog(t)
		fixture := prepareQueuedClosureValidation(t, harness.db)
		commitQueuedClosureCancellation(t, harness.db, fixture)
		execAssetSQL(t, harness.db, `
			UPDATE asset_sources SET status='ACTIVE',version=version+1 WHERE id=$1
		`, fixture.sourceID)
		const successorRunID = "8f400000-0000-4000-8000-000000000001"
		insertQueuedClosureValidationRun(t, harness.db, fixture, successorRunID,
			"closure-validation-successor")
		execAssetSQL(t, harness.db, `
			UPDATE asset_source_revisions
			SET state='VALIDATING',validation_run_id=$2,validation_digest=NULL,version=version+1
			WHERE id=$1
		`, fixture.revisionID, successorRunID)
		expectClosureStatementError(t, harness.db, "55000",
			"asset_source_revisions_validation_immutable_guard", `
			UPDATE asset_source_revisions
			SET validation_run_id=$2,version=version+1 WHERE id=$1
		`, fixture.revisionID, fixture.validationRunID)
	})

	t.Run("REJECTED cannot rewrite failure evidence", func(t *testing.T) {
		harness := newAssetCatalogHarness(t)
		harness.applyThroughAssetCatalog(t)
		fixture := prepareQueuedClosureValidation(t, harness.db)
		commitQueuedClosureCancellation(t, harness.db, fixture)
		execAssetSQL(t, harness.db, `
			UPDATE asset_sources SET status='ACTIVE',version=version+1 WHERE id=$1
		`, fixture.sourceID)
		const successorRunID = "8f400000-0000-4000-8000-000000000002"
		insertQueuedClosureValidationRun(t, harness.db, fixture, successorRunID,
			"closure-validation-rejected-rewrite")
		expectClosureStatementError(t, harness.db, "55000",
			"asset_source_revisions_validation_immutable_guard", `
			UPDATE asset_source_revisions
			SET validation_run_id=$2,validation_digest=repeat('2',64),version=version+1
			WHERE id=$1
		`, fixture.revisionID, successorRunID)
	})
}

func TestAssetCatalogObservationUsesTransactionTimestampAndCallerCanonicalProvenance(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedGovernedManualCatalog(t, harness.db)

	t.Run("canonical caller material is accepted", func(t *testing.T) {
		tx, err := harness.db.BeginTx(context.Background(), pgx.TxOptions{IsoLevel: pgx.Serializable})
		if err != nil {
			t.Fatalf("begin canonical observation transaction: %v", err)
		}
		defer func() { _ = tx.Rollback(context.Background()) }()
		run := startClosureManualMutationRunInTx(t, tx, fixture)
		acceptedAt := readClosureTransactionTimestamp(t, tx)
		if _, err := insertCanonicalClosureObservation(
			tx, fixture, run, "8f100000-0000-4000-8000-000000000001", acceptedAt,
		); err != nil {
			t.Fatalf("insert caller-canonical observation: %v", err)
		}
	})

	t.Run("non-transaction timestamp is rejected", func(t *testing.T) {
		tx, err := harness.db.BeginTx(context.Background(), pgx.TxOptions{IsoLevel: pgx.Serializable})
		if err != nil {
			t.Fatalf("begin drifted observation transaction: %v", err)
		}
		defer func() { _ = tx.Rollback(context.Background()) }()
		run := startClosureManualMutationRunInTx(t, tx, fixture)
		acceptedAt := readClosureTransactionTimestamp(t, tx).Add(time.Microsecond)
		_, err = insertCanonicalClosureObservation(
			tx, fixture, run, "8f100000-0000-4000-8000-000000000002", acceptedAt,
		)
		assertClosurePostgresError(t, err, "23514", "asset_observations_observed_at_guard")
	})
}

func TestAssetCatalogObservationRejectsNullProvenanceOwnership(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedGovernedManualCatalog(t, harness.db)
	nullOwnershipSQL := strings.Replace(
		insertRuntimeObservationSQL, "'ownership','SOURCE'", "'ownership',NULL", 1,
	)
	if nullOwnershipSQL == insertRuntimeObservationSQL {
		t.Fatal("runtime observation SQL no longer exposes the canonical ownership material")
	}
	expectClosureCommitError(t, harness.db, pgx.Serializable, "23514",
		"asset_observations_provenance_admission_guard", func(tx pgx.Tx) error {
			run := startClosureManualMutationRunInTx(t, tx, fixture)
			candidate := newRuntimeObservation(fixture, run,
				"8f100000-0000-4000-8000-000000000003", "null-provenance-ownership", "3")
			_, err := tx.Exec(context.Background(), nullOwnershipSQL,
				runtimeObservationArguments(candidate)...)
			return err
		})
}

const closureExactDelayIntentSQL = `
	WITH intent AS (
		SELECT statement_timestamp()+$2::interval AS not_before
	)
	UPDATE asset_source_runs AS run
	SET stage_code='CLEANING_UP',pending_transition='DELAY',
		pending_transition_reason='TRANSPORT_BACKOFF',
		pending_transition_not_before=intent.not_before,
		pending_transition_digest=asset_catalog_source_run_delay_intent_digest(
			run,'TRANSPORT_BACKOFF',intent.not_before
		),version=run.version+1
	FROM intent WHERE run.id=$1
`

const (
	closureExternalSourceID     = "8f000000-0000-4000-8000-000000000001"
	closureExternalRevisionID   = "8f000000-0000-4000-8000-000000000002"
	closureExternalValidationID = "8f000000-0000-4000-8000-000000000003"
)

func startClosureManualValidationRunInTx(
	t *testing.T,
	tx pgx.Tx,
	fixture assetCatalogFixture,
) {
	t.Helper()
	execAssetSQL(t, tx, `
		INSERT INTO asset_source_runs (
			id,tenant_id,workspace_id,source_id,source_revision,source_revision_digest,
			run_kind,trigger_type,gate_revision,idempotency_key,request_hash,checkpoint_version
		) SELECT $1,$2,$3,$4,1,$5,'VALIDATION','HUMAN',gate_revision,
			'closure-manual-cleanup-validation',repeat('1',64),0
		FROM asset_sources WHERE id=$4
	`, fixture.validationRunID, fixture.tenantID, fixture.workspaceID, fixture.sourceID,
		fixture.revisionDigest)
	execAssetSQL(t, tx, `
		UPDATE asset_source_revisions
		SET state='VALIDATING',validation_run_id=$2,version=version+1 WHERE id=$1
	`, fixture.revisionID, fixture.validationRunID)
	execAssetSQL(t, tx, `
		UPDATE asset_sources
		SET gate_status='VALIDATING',gate_revision=gate_revision+1,
			validated_run_id=$2,validation_digest=NULL,validated_binding_digest=NULL,
			version=version+1
		WHERE id=$1
	`, fixture.sourceID, fixture.validationRunID)
	execAssetSQL(t, tx, `
		UPDATE asset_source_runs
		SET status='RUNNING',stage_code='VALIDATING',lease_owner='closure-manual-validation',
			lease_expires_at=statement_timestamp()+interval '10 minutes',fence_epoch=1,
			fence_token_hash=repeat('2',64),heartbeat_sequence=1,
			heartbeat_at=statement_timestamp(),version=version+1
		WHERE id=$1
	`, fixture.validationRunID)
}

func startClosureManualMutationRunInTx(
	t *testing.T,
	tx pgx.Tx,
	fixture assetCatalogFixture,
) runtimeContractRun {
	t.Helper()
	run := runtimeContractRun{id: "8f700000-0000-4000-8000-000000000002"}
	var gateRevision int64
	var checkpointSHA *string
	if err := tx.QueryRow(context.Background(), `
		SELECT source.published_revision,source.published_revision_digest,
			revision.source_definition_digest,source.gate_revision,
			source.checkpoint_version,source.checkpoint_sha256,source.provider_kind
		FROM asset_sources AS source
		JOIN asset_source_revisions AS revision
		  ON revision.source_id=source.id AND revision.revision=source.published_revision
		WHERE source.id=$1
	`, fixture.sourceID).Scan(&run.revision, &run.revisionDigest,
		&run.sourceDefinitionDigest, &gateRevision, &run.checkpointVersion,
		&checkpointSHA, &run.providerKind); err != nil {
		t.Fatalf("read manual mutation admission: %v", err)
	}
	execAssetSQL(t, tx, `
		INSERT INTO asset_source_runs (
			id,tenant_id,workspace_id,source_id,source_revision,source_revision_digest,
			run_kind,trigger_type,gate_revision,idempotency_key,request_hash,
			cursor_before_sha256,checkpoint_version
		) VALUES ($1,$2,$3,$4,$5,$6,'MANUAL_MUTATION','HUMAN',$7,
			'closure-manual-atomic-mutation',repeat('1',64),$8,$9)
	`, run.id, fixture.tenantID, fixture.workspaceID, fixture.sourceID, run.revision,
		run.revisionDigest, gateRevision, checkpointSHA, run.checkpointVersion)
	execAssetSQL(t, tx, `
		UPDATE asset_source_runs
		SET status='RUNNING',stage_code='READING',lease_owner='runtime-manual-executor',
			lease_expires_at=statement_timestamp()+interval '10 minutes',fence_epoch=1,
			fence_token_hash=repeat('2',64),heartbeat_sequence=1,
			heartbeat_at=statement_timestamp(),version=version+1
		WHERE id=$1
	`, run.id)
	execAssetSQL(t, tx, `
		UPDATE asset_source_runs SET stage_code='NORMALIZING',version=version+1 WHERE id=$1
	`, run.id)
	if err := tx.QueryRow(context.Background(), `
		SELECT checkpoint_version,fence_epoch,page_sequence
		FROM asset_source_runs WHERE id=$1
	`, run.id).Scan(&run.checkpointVersion, &run.fenceEpoch, &run.pageSequence); err != nil {
		t.Fatalf("read manual mutation coordinates: %v", err)
	}
	return run
}

func stageClosureManualEmptyPageInTx(
	t *testing.T,
	tx pgx.Tx,
	fixture assetCatalogFixture,
	run runtimeContractRun,
) {
	t.Helper()
	pageDigest := strings.Repeat("c", 64)
	if err := insertClosurePageReceipt(tx, fixture, run.id, run.pageSequence+1, pageDigest); err != nil {
		t.Fatalf("insert manual closure page receipt: %v", err)
	}
	cleanupDigest := sourceRunNoCredentialDigest(t, tx, run.id)
	insertCleanupAudit(t, tx, fixture, run.id, 0, cleanupDigest)
	execAssetSQL(t, tx, `
		UPDATE asset_sources SET checkpoint_version=checkpoint_version+1,version=version+1
		WHERE id=$1
	`, fixture.sourceID)
	execAssetSQL(t, tx, `
		UPDATE asset_source_runs
		SET status='FINALIZING',stage_code='CLEANING_UP',
			page_sequence=page_sequence+1,page_digest=$2,
			checkpoint_version=checkpoint_version+1,final_page=true,
			complete_snapshot=false,effective_complete_snapshot=false,
			heartbeat_sequence=heartbeat_sequence+1,heartbeat_at=statement_timestamp(),
			lease_expires_at=lease_expires_at+interval '1 minute',
			work_result_kind='DATA_PROJECTION',work_result_status='SUCCEEDED',
			work_result_digest=repeat('d',64),work_result_recorded_at=statement_timestamp(),
			cleanup_status='NO_CREDENTIAL',cleanup_digest=$3,version=version+1
		WHERE id=$1
	`, run.id, pageDigest, cleanupDigest)
}

func seedForgedLegacyManualFinalizingRun(
	t *testing.T,
	database *pgxpool.Pool,
	fixture assetCatalogFixture,
) runtimeContractRun {
	t.Helper()
	execAssetSQL(t, database,
		`ALTER TABLE asset_source_runs DISABLE TRIGGER asset_source_runs_terminal_closure_guard`)
	t.Cleanup(func() {
		_, _ = database.Exec(context.Background(),
			`ALTER TABLE asset_source_runs ENABLE TRIGGER asset_source_runs_terminal_closure_guard`)
	})
	run := startRuntimeContractManualRun(t, database, fixture)
	tx, err := database.BeginTx(context.Background(), pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		t.Fatalf("begin forged legacy manual finalization: %v", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	stageClosureManualEmptyPageInTx(t, tx, fixture, run)
	if err := tx.Commit(context.Background()); err != nil {
		t.Fatalf("commit forged legacy manual finalization: %v", err)
	}
	execAssetSQL(t, database,
		`ALTER TABLE asset_source_runs ENABLE TRIGGER asset_source_runs_terminal_closure_guard`)
	return run
}

func prepareQueuedClosureValidation(t *testing.T, database *pgxpool.Pool) assetCatalogFixture {
	t.Helper()
	fixture := seedDraftAssetCatalog(t, database)
	fixture.sourceID = closureExternalSourceID
	fixture.revisionID = closureExternalRevisionID
	fixture.validationRunID = closureExternalValidationID
	fixture.revisionDigest = strings.Repeat("4", 64)
	execAssetSQL(t, database, `
		INSERT INTO asset_sources (
			id,tenant_id,workspace_id,source_kind,provider_kind,name,
			create_idempotency_key,create_request_hash
		) VALUES ($1,$2,$3,'EXTERNAL_CMDB','EXTERNAL_V1','queued validation source',
			'queued-validation-source',repeat('1',64))
	`, fixture.sourceID, fixture.tenantID, fixture.workspaceID)
	execAssetSQL(t, database, `
		INSERT INTO asset_source_revisions (
			id,tenant_id,workspace_id,source_id,revision,
			canonical_provider_schema,canonical_provider_schema_sha256,integration_id,sync_mode,
			authority_scope_digest,source_definition_digest,canonical_revision_digest,
			credential_reference_id,rate_limit_requests,rate_limit_window_seconds,
			backpressure_base_seconds,backpressure_max_seconds,profile_code,
			created_by,change_reason_code,expected_source_version
		) SELECT $1,$2,$3,$4,1,convert_to('{"type":"object"}','UTF8'),
			encode(sha256(convert_to('{"type":"object"}','UTF8')),'hex'),$5,'ON_DEMAND',
			repeat('2',64),repeat('3',64),$6,'opaque-credential',100,60,1,60,
			'EXTERNAL_V1','closure-test','INITIAL_CREATE',source.version
		FROM asset_sources AS source WHERE source.id=$4
	`, fixture.revisionID, fixture.tenantID, fixture.workspaceID, fixture.sourceID,
		fixture.integrationID, fixture.revisionDigest)
	execAssetSQL(t, database, `
		INSERT INTO asset_source_runs (
			id,tenant_id,workspace_id,source_id,source_revision,source_revision_digest,
			run_kind,trigger_type,gate_revision,idempotency_key,request_hash,checkpoint_version
		) SELECT $1,$2,$3,$4,1,$5,'VALIDATION','HUMAN',gate_revision,
			'closure-cancel-validation',repeat('1',64),0
		FROM asset_sources WHERE id=$4
	`, fixture.validationRunID, fixture.tenantID, fixture.workspaceID, fixture.sourceID,
		fixture.revisionDigest)
	execAssetSQL(t, database, `
		UPDATE asset_source_revisions
		SET state='VALIDATING',validation_run_id=$2,version=version+1 WHERE id=$1
	`, fixture.revisionID, fixture.validationRunID)
	execAssetSQL(t, database, `
		UPDATE asset_sources SET status='PAUSED',version=version+1 WHERE id=$1
	`, fixture.sourceID)
	return fixture
}

func cancelQueuedClosureValidation(tx pgx.Tx, fixture assetCatalogFixture) error {
	if _, err := tx.Exec(context.Background(), `
		UPDATE asset_source_runs
		SET status='CANCELLED',stage_code='COMPLETED',version=version+1 WHERE id=$1
	`, fixture.validationRunID); err != nil {
		return err
	}
	_, err := tx.Exec(context.Background(), `
		UPDATE asset_source_revisions
		SET state='REJECTED',validation_digest=repeat('1',64),version=version+1
		WHERE id=$1
	`, fixture.revisionID)
	return err
}

func createAndCancelIneligibleManualMutation(
	tx pgx.Tx,
	fixture assetCatalogFixture,
	runID string,
	idempotencyKey string,
) error {
	if _, err := tx.Exec(context.Background(), `
		INSERT INTO asset_source_runs (
			id,tenant_id,workspace_id,source_id,source_revision,source_revision_digest,
			run_kind,trigger_type,gate_revision,idempotency_key,request_hash,
			checkpoint_version,cursor_before_sha256
		) SELECT $1,$2,$3,$4,published_revision,published_revision_digest,
			'MANUAL_MUTATION','HUMAN',gate_revision,$5,repeat('1',64),
			checkpoint_version,checkpoint_sha256
		FROM asset_sources WHERE id=$4
	`, runID, fixture.tenantID, fixture.workspaceID, fixture.sourceID, idempotencyKey); err != nil {
		return err
	}
	if _, err := tx.Exec(context.Background(), `
		UPDATE asset_sources SET status='PAUSED',version=version+1 WHERE id=$1
	`, fixture.sourceID); err != nil {
		return err
	}
	_, err := tx.Exec(context.Background(), `
		UPDATE asset_source_runs
		SET status='CANCELLED',stage_code='COMPLETED',version=version+1 WHERE id=$1
	`, runID)
	return err
}

func commitQueuedClosureCancellation(
	t *testing.T,
	database *pgxpool.Pool,
	fixture assetCatalogFixture,
) {
	t.Helper()
	tx, err := database.BeginTx(context.Background(), pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		t.Fatalf("begin queued validation cancellation: %v", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if err := cancelQueuedClosureValidation(tx, fixture); err != nil {
		t.Fatalf("cancel queued validation: %v", err)
	}
	if err := tx.Commit(context.Background()); err != nil {
		t.Fatalf("commit queued validation cancellation: %v", err)
	}
}

func insertQueuedClosureValidationRun(
	t *testing.T,
	database assetSQLExecutor,
	fixture assetCatalogFixture,
	runID string,
	idempotencyKey string,
) {
	t.Helper()
	execAssetSQL(t, database, `
		INSERT INTO asset_source_runs (
			id,tenant_id,workspace_id,source_id,source_revision,source_revision_digest,
			run_kind,trigger_type,gate_revision,idempotency_key,request_hash,checkpoint_version
		) SELECT $1,$2,$3,$4,1,$5,'VALIDATION','HUMAN',gate_revision,$6,repeat('3',64),0
		FROM asset_sources WHERE id=$4
	`, runID, fixture.tenantID, fixture.workspaceID, fixture.sourceID,
		fixture.revisionDigest, idempotencyKey)
}

func readClosureTransactionTimestamp(t *testing.T, tx pgx.Tx) time.Time {
	t.Helper()
	var acceptedAt time.Time
	if err := tx.QueryRow(context.Background(), `SELECT transaction_timestamp()`).Scan(&acceptedAt); err != nil {
		t.Fatalf("read transaction timestamp: %v", err)
	}
	return acceptedAt
}

func insertCanonicalClosureObservation(
	tx pgx.Tx,
	fixture assetCatalogFixture,
	run runtimeContractRun,
	observationID string,
	acceptedAt time.Time,
) (pgconn.CommandTag, error) {
	provenance, err := json.Marshal(map[string]any{
		"display_name": map[string]any{
			"source_id":          fixture.sourceID,
			"provider_kind":      run.providerKind,
			"source_revision":    run.revision,
			"observed_at":        acceptedAt.UTC().Format("2006-01-02T15:04:05.000000Z"),
			"provider_path_code": "DISPLAY_NAME",
			"confidence":         100,
			"ownership":          "SOURCE",
		},
	})
	if err != nil {
		return pgconn.CommandTag{}, err
	}
	document := []byte(`{"display_name":"closure-observation"}`)
	documentDigest := sha256.Sum256(document)
	provenanceDigest := sha256.Sum256(provenance)
	return tx.Exec(context.Background(), `
		INSERT INTO asset_observations (
			id,tenant_id,workspace_id,environment_id,source_id,run_id,provider_kind,external_id,
			source_revision,canonical_revision_digest,source_definition_digest,observed_at,
			freshness_kind,freshness_order_sequence,provider_version_sha256,provider_fact_sha256,
			fingerprint_sha256,provider_provenance_sha256,observation_chain_sha256,
			accepted_checkpoint_version,run_fence_epoch,run_page_sequence,schema_version,
			normalized_document,document_sha256,field_provenance,field_provenance_sha256
		) VALUES (
			$1,$2,$3,$4,$5,$6,$7,'closure-canonical-observation',$8,$9,$10,$11,
			'CATALOG_SEQUENCE',$12,repeat('1',64),repeat('2',64),repeat('3',64),
			repeat('4',64),repeat('5',64),$12,$13,$14,'asset.v1',$15,$16,$17,$18
		)
	`, observationID, fixture.tenantID, fixture.workspaceID, fixture.environmentID,
		fixture.sourceID, run.id, run.providerKind, run.revision, run.revisionDigest,
		run.sourceDefinitionDigest, acceptedAt, run.checkpointVersion+1, run.fenceEpoch,
		run.pageSequence+1, document, hex.EncodeToString(documentDigest[:]), provenance,
		hex.EncodeToString(provenanceDigest[:]))
}

func seedClosureExternalValidationRun(t *testing.T, database *pgxpool.Pool) string {
	t.Helper()
	fixture := seedDraftAssetCatalog(t, database)
	fixture = seedClosureExternalValidationOnFixture(t, database, fixture)
	return fixture.validationRunID
}

func seedClosureExternalValidationCleanupAttempt(
	t *testing.T,
	database *pgxpool.Pool,
) string {
	t.Helper()
	fixture := seedDraftAssetCatalog(t, database)
	fixture = seedClosureExternalValidationOnFixture(t, database, fixture)
	reserveClosureCleanupAttempt(t, database, fixture.validationRunID)
	return fixture.validationRunID
}

func seedClosureExternalValidationOnFixture(
	t *testing.T,
	database *pgxpool.Pool,
	fixture assetCatalogFixture,
) assetCatalogFixture {
	t.Helper()
	fixture.sourceID = closureExternalSourceID
	fixture.revisionID = closureExternalRevisionID
	fixture.validationRunID = closureExternalValidationID
	fixture.revisionDigest = strings.Repeat("4", 64)
	execAssetSQL(t, database, `
		INSERT INTO asset_sources (
			id,tenant_id,workspace_id,source_kind,provider_kind,name,
			create_idempotency_key,create_request_hash
		) VALUES ($1,$2,$3,'EXTERNAL_CMDB','EXTERNAL_V1','closure external source',
			'closure-external-source',repeat('1',64))
	`, closureExternalSourceID, fixture.tenantID, fixture.workspaceID)
	execAssetSQL(t, database, `
		INSERT INTO asset_source_revisions (
			id,tenant_id,workspace_id,source_id,revision,
			canonical_provider_schema,canonical_provider_schema_sha256,integration_id,sync_mode,
			authority_scope_digest,source_definition_digest,canonical_revision_digest,
			credential_reference_id,rate_limit_requests,rate_limit_window_seconds,
			backpressure_base_seconds,backpressure_max_seconds,profile_code,
			created_by,change_reason_code,expected_source_version
		) SELECT $1,$2,$3,$4,1,convert_to('{"type":"object"}','UTF8'),
			encode(sha256(convert_to('{"type":"object"}','UTF8')),'hex'),$5,'ON_DEMAND',
			repeat('2',64),repeat('3',64),repeat('4',64),'opaque-credential',100,60,1,60,
			'EXTERNAL_V1','closure-test','INITIAL_CREATE',source.version
		FROM asset_sources AS source WHERE source.id=$4
	`, closureExternalRevisionID, fixture.tenantID, fixture.workspaceID,
		closureExternalSourceID, fixture.integrationID)
	execAssetSQL(t, database, `
		INSERT INTO asset_source_runs (
			id,tenant_id,workspace_id,source_id,source_revision,source_revision_digest,
			run_kind,trigger_type,gate_revision,idempotency_key,request_hash,checkpoint_version
		) SELECT $1,$2,$3,$4,1,repeat('4',64),'VALIDATION','HUMAN',gate_revision,
			'closure-external-validation',repeat('5',64),0
		FROM asset_sources WHERE id=$4
	`, closureExternalValidationID, fixture.tenantID, fixture.workspaceID, closureExternalSourceID)
	execAssetSQL(t, database, `
		UPDATE asset_source_revisions
		SET state='VALIDATING',validation_run_id=$2,version=version+1 WHERE id=$1
	`, closureExternalRevisionID, closureExternalValidationID)
	execAssetSQL(t, database, `
		UPDATE asset_sources
		SET gate_status='VALIDATING',gate_revision=gate_revision+1,
			validated_run_id=$2,validation_digest=NULL,validated_binding_digest=NULL,
			version=version+1
		WHERE id=$1
	`, closureExternalSourceID, closureExternalValidationID)
	var validationVisible bool
	if err := database.QueryRow(context.Background(), `
		SELECT source.gate_status='VALIDATING' AND
			source.gate_reason_code='VALIDATION_IN_PROGRESS' AND
			source.gate_revision=run.gate_revision+1 AND
			source.validated_run_id=run.id AND source.validation_digest IS NULL AND
			source.validated_binding_digest IS NULL AND revision.state='VALIDATING' AND
			revision.validation_run_id=run.id AND run.status='QUEUED' AND
			run.stage_code='WAITING'
		FROM asset_sources AS source
		JOIN asset_source_revisions AS revision ON revision.source_id=source.id
		JOIN asset_source_runs AS run ON run.id=revision.validation_run_id
		WHERE source.id=$1 AND revision.id=$2
	`, fixture.sourceID, fixture.revisionID).Scan(&validationVisible); err != nil {
		t.Fatalf("read visible external validation gate: %v", err)
	}
	if !validationVisible {
		t.Fatal("external validation did not expose the exact bound VALIDATING gate before claim")
	}
	execAssetSQL(t, database, `
		UPDATE asset_source_runs
		SET status='RUNNING',stage_code='VALIDATING',lease_owner='closure-external-worker',
			lease_expires_at=statement_timestamp()+interval '10 minutes',fence_epoch=1,
			fence_token_hash=repeat('6',64),heartbeat_sequence=1,
			heartbeat_at=statement_timestamp(),version=version+1
		WHERE id=$1
	`, closureExternalValidationID)
	return fixture
}

func seedClosureAuthoritativeCompleteCatalog(
	t *testing.T,
	database *pgxpool.Pool,
) assetCatalogFixture {
	t.Helper()
	fixture := seedDraftAssetCatalog(t, database)
	return seedClosureAuthoritativeCompleteCatalogOnFixture(t, database, fixture)
}

func seedClosureAuthoritativeCompleteCatalogOnFixture(
	t *testing.T,
	database *pgxpool.Pool,
	fixture assetCatalogFixture,
) assetCatalogFixture {
	t.Helper()
	fixture = seedClosureExternalValidationOnFixture(t, database, fixture)
	finishClosureExternalValidation(t, database, fixture, 1, strings.Repeat("7", 64))
	fixture.runID = "8f500000-0000-4000-8000-000000000001"
	execAssetSQL(t, database, `
		INSERT INTO asset_source_runs (
			id,tenant_id,workspace_id,source_id,source_revision,source_revision_digest,
			run_kind,trigger_type,gate_revision,idempotency_key,request_hash,
			checkpoint_version,cursor_before_sha256
		) SELECT $1,$2,$3,$4,published_revision,published_revision_digest,
			'DISCOVERY','SCHEDULED',gate_revision,'closure-authoritative-discovery',
			repeat('8',64),checkpoint_version,checkpoint_sha256
		FROM asset_sources WHERE id=$4
	`, fixture.runID, fixture.tenantID, fixture.workspaceID, fixture.sourceID)
	execAssetSQL(t, database, `
		UPDATE asset_source_runs
		SET status='RUNNING',stage_code='READING',lease_owner='closure-discovery-worker',
			lease_expires_at=statement_timestamp()+interval '10 minutes',fence_epoch=1,
			fence_token_hash=repeat('9',64),heartbeat_sequence=1,
			heartbeat_at=statement_timestamp(),version=version+1 WHERE id=$1
	`, fixture.runID)
	execAssetSQL(t, database, `
		UPDATE asset_source_runs SET stage_code='NORMALIZING',version=version+1 WHERE id=$1
	`, fixture.runID)
	execAssetSQL(t, database, `
		UPDATE asset_source_runs SET stage_code='APPLYING',version=version+1 WHERE id=$1
	`, fixture.runID)
	execAssetSQL(t, database, `
		UPDATE asset_source_runs
		SET cleanup_status='PENDING',cleanup_attempt_id=gen_random_uuid(),
			cleanup_attempt_epoch=fence_epoch,version=version+1 WHERE id=$1
	`, fixture.runID)

	pageTx, err := database.BeginTx(context.Background(), pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		t.Fatalf("begin authoritative source page: %v", err)
	}
	defer func() { _ = pageTx.Rollback(context.Background()) }()
	pageDigest := strings.Repeat("a", 64)
	if err := insertClosurePageReceipt(pageTx, fixture, fixture.runID, 1, pageDigest); err != nil {
		t.Fatalf("insert authoritative page receipt: %v", err)
	}
	relationDigest := strings.Repeat("d", 64)
	if err := insertClosureRelationPageReceipt(
		pageTx, fixture, fixture.runID, 1, relationDigest,
	); err != nil {
		t.Fatalf("insert authoritative relation page receipt: %v", err)
	}
	insertClosureExternalObservation(t, pageTx, fixture, fixture.observationID, fixture.assetID,
		"external-host-a", "closure-host-a", strings.Repeat("7", 64))
	insertClosureExternalObservation(t, pageTx, fixture, fixture.secondObservationID, fixture.secondAssetID,
		"external-host-b", "closure-host-b", strings.Repeat("8", 64))
	seedClosureExternalProjectionEdges(t, pageTx, fixture)
	execAssetSQL(t, pageTx, `
		WITH envelope AS (
			SELECT decode('01'||repeat('01',12)||repeat('02',16),'hex') AS ciphertext
		)
		UPDATE asset_sources AS source
		SET checkpoint_ciphertext=envelope.ciphertext,checkpoint_key_id='opaque-key-1',
			checkpoint_sha256=encode(sha256(envelope.ciphertext),'hex'),
			checkpoint_version=source.checkpoint_version+1,version=source.version+1
		FROM envelope WHERE source.id=$1
	`, fixture.sourceID)
	execAssetSQL(t, pageTx, `
		UPDATE asset_source_runs AS run
		SET status='FINALIZING',stage_code='CLEANING_UP',page_sequence=1,
			page_digest=$2,relation_page_sequence=1,relation_page_digest=$4,
			checkpoint_version=1,
			cursor_after_sha256=(SELECT checkpoint_sha256 FROM asset_sources WHERE id=$3),
			final_page=true,complete_snapshot=true,effective_complete_snapshot=true,
			observed_count=2,created_count=2,
			heartbeat_sequence=heartbeat_sequence+1,heartbeat_at=statement_timestamp(),
			lease_expires_at=lease_expires_at+interval '1 minute',
			work_result_kind='DATA_PROJECTION',work_result_status='SUCCEEDED',
			work_result_digest=repeat('b',64),work_result_recorded_at=statement_timestamp(),
			version=run.version+1 WHERE run.id=$1
	`, fixture.runID, pageDigest, fixture.sourceID, relationDigest)
	if err := pageTx.Commit(context.Background()); err != nil {
		t.Fatalf("commit authoritative source page: %v", err)
	}
	revokeClosureAttempt(t, database, fixture, fixture.runID, strings.Repeat("c", 64))
	terminalTx, err := database.BeginTx(context.Background(), pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		t.Fatalf("begin authoritative terminal closure: %v", err)
	}
	defer func() { _ = terminalTx.Rollback(context.Background()) }()
	terminalDigest := sourceRunTerminalDigest(t, terminalTx, fixture.runID, "SUCCEEDED", nil)
	insertTerminalAudit(t, terminalTx, fixture, fixture.runID, terminalDigest)
	execAssetSQL(t, terminalTx, `
		UPDATE asset_source_runs
		SET status='SUCCEEDED',stage_code='COMPLETED',terminal_command_sha256=$2,
			version=version+1 WHERE id=$1
	`, fixture.runID, terminalDigest)
	execAssetSQL(t, terminalTx, `
		UPDATE asset_sources
		SET last_success_run_id=$2,last_success_at=(SELECT completed_at FROM asset_source_runs WHERE id=$2),
			last_complete_snapshot_run_id=$2,
			last_complete_snapshot_at=(SELECT completed_at FROM asset_source_runs WHERE id=$2),
			version=version+1 WHERE id=$1
	`, fixture.sourceID, fixture.runID)
	if err := terminalTx.Commit(context.Background()); err != nil {
		t.Fatalf("commit authoritative terminal closure: %v", err)
	}
	return fixture
}

func insertClosureExternalObservation(
	t *testing.T,
	database assetSQLExecutor,
	fixture assetCatalogFixture,
	observationID string,
	assetID string,
	externalID string,
	displayName string,
	chain string,
) {
	t.Helper()
	execAssetSQL(t, database, `
		WITH accepted AS (SELECT transaction_timestamp() AS observed_at), payload AS (
			SELECT observed_at,
				convert_to(jsonb_build_object('display_name',$7,'kind','LINUX_VM')::text,'UTF8') AS document,
				convert_to(jsonb_build_object('display_name',jsonb_build_object(
					'source_id',$4::text,'provider_kind','EXTERNAL_V1','source_revision',1,
					'observed_at',to_char(observed_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
					'provider_path_code','external.display_name','confidence',100,'ownership','SOURCE'))::text,'UTF8') AS provenance
			FROM accepted
		), inserted AS (
			INSERT INTO asset_observations (
				id,tenant_id,workspace_id,environment_id,source_id,run_id,provider_kind,external_id,
				source_revision,canonical_revision_digest,source_definition_digest,observed_at,freshness_kind,
				freshness_order_sequence,provider_version_sha256,provider_fact_sha256,fingerprint_sha256,
				provider_provenance_sha256,observation_chain_sha256,accepted_checkpoint_version,
				run_fence_epoch,run_page_sequence,schema_version,normalized_document,document_sha256,
				field_provenance,field_provenance_sha256
			) SELECT $1,$2,$3,$5,$4,$6,'EXTERNAL_V1',$8,1,$9,repeat('3',64),observed_at,'OBJECT_SEQUENCE',1,
				repeat('1',64),repeat('2',64),repeat('3',64),repeat('4',64),$10,1,1,1,'asset.v1',document,
				encode(sha256(document),'hex'),provenance,encode(sha256(provenance),'hex') FROM payload
			RETURNING observed_at
		)
		INSERT INTO assets (
			id,tenant_id,workspace_id,environment_id,source_id,provider_kind,external_id,kind,display_name,
			last_observation_id,last_observation_chain_sha256,last_observed_at,last_source_revision,
			create_idempotency_key,create_request_hash
		) SELECT $11,$2,$3,$5,$4,'EXTERNAL_V1',$8,'LINUX_VM',$7,$1,$10,observed_at,1,
			'create-'||$8,repeat('5',64) FROM inserted
	`, observationID, fixture.tenantID, fixture.workspaceID, fixture.sourceID, fixture.environmentID,
		fixture.runID, displayName, externalID, fixture.revisionDigest, chain, assetID)
}

func seedClosureExternalProjectionEdges(
	t *testing.T,
	database assetSQLExecutor,
	fixture assetCatalogFixture,
) {
	t.Helper()
	details := []byte(`{"cpu_count":4}`)
	execAssetSQL(t, database, `
		INSERT INTO asset_type_details (
			id,tenant_id,workspace_id,environment_id,asset_id,source_id,provider_kind,external_id,
			source_revision,source_observed_at,source_observation_chain_sha256,revision,schema_version,
			source_observation_id,details_document,details_sha256,actor_id
		) SELECT $1,$2,$3,$4,$5,$6,'EXTERNAL_V1','external-host-a',1,o.observed_at,o.observation_chain_sha256,
			1,'linux-vm.v1',o.id,$7,encode(sha256($7),'hex'),'closure-worker'
		FROM asset_observations o WHERE o.id=$8
	`, fixture.typeDetailID, fixture.tenantID, fixture.workspaceID, fixture.environmentID,
		fixture.assetID, fixture.sourceID, details, fixture.observationID)
	execAssetSQL(t, database, `
		INSERT INTO asset_conflicts (
			id,tenant_id,workspace_id,environment_id,asset_id,candidate_asset_id,source_id,observation_id,
			conflict_type,status
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'FINGERPRINT_COLLISION','OPEN')
	`, fixture.conflictID, fixture.tenantID, fixture.workspaceID, fixture.environmentID,
		fixture.assetID, fixture.secondAssetID, fixture.sourceID, fixture.observationID)
	execAssetSQL(t, database, `
		INSERT INTO asset_relationships (
			id,tenant_id,workspace_id,source_id,source_revision,canonical_revision_digest,last_run_id,
			last_page_sequence,relation_page_sha256,accepted_checkpoint_version,run_fence_epoch,
			source_environment_id,target_environment_id,source_asset_id,target_asset_id,
			from_external_id,to_external_id,relationship_type,provider_path_code,confidence,freshness_kind,
			freshness_order_sequence,provider_version_sha256,relation_fact_sha256,provenance,
			provenance_source_id,status,idempotency_key,request_hash
		) VALUES ($1,$2,$3,$4,1,$5,$6,1,repeat('d',64),1,1,$7,$7,$8,$9,
			'external-host-a','external-host-b','DEPENDS_ON','external.depends_on',100,'OBJECT_SEQUENCE',1,
			repeat('7',64),repeat('8',64),'DISCOVERED',$4,'ACTIVE',
			'relationship-create-'||$4::text,repeat('9',64))
	`, fixture.relationshipID, fixture.tenantID, fixture.workspaceID, fixture.sourceID,
		fixture.revisionDigest, fixture.runID, fixture.environmentID, fixture.assetID, fixture.secondAssetID)
	execAssetSQL(t, database, `
		INSERT INTO service_asset_bindings (
			id,tenant_id,workspace_id,environment_id,service_id,asset_id,binding_role,mapping_status,
			provenance,provenance_source_id,status,idempotency_key,request_hash
		) VALUES ($1,$2,$3,$4,$5,$6,'PRIMARY_RUNTIME','EXACT','DISCOVERED',$7,'ACTIVE',
			'binding-create-'||$7::text,repeat('a',64))
	`, fixture.bindingID, fixture.tenantID, fixture.workspaceID, fixture.environmentID,
		fixture.serviceID, fixture.assetID, fixture.sourceID)
}

func startClosureExternalDiscoveryRun(
	t *testing.T,
	database *pgxpool.Pool,
	fixture assetCatalogFixture,
) runtimeContractRun {
	t.Helper()
	run := runtimeContractRun{id: "8f600000-0000-4000-8000-000000000001"}
	var gateRevision int64
	var checkpointSHA *string
	if err := database.QueryRow(context.Background(), `
		SELECT source.published_revision,source.published_revision_digest,
			revision.source_definition_digest,source.gate_revision,
			source.checkpoint_version,source.checkpoint_sha256,source.provider_kind
		FROM asset_sources AS source
		JOIN asset_source_revisions AS revision
		  ON revision.source_id=source.id AND revision.revision=source.published_revision
		WHERE source.id=$1
	`, fixture.sourceID).Scan(&run.revision, &run.revisionDigest,
		&run.sourceDefinitionDigest, &gateRevision, &run.checkpointVersion,
		&checkpointSHA, &run.providerKind); err != nil {
		t.Fatalf("read external discovery admission: %v", err)
	}
	execAssetSQL(t, database, `
		INSERT INTO asset_source_runs (
			id,tenant_id,workspace_id,source_id,source_revision,source_revision_digest,
			run_kind,trigger_type,gate_revision,idempotency_key,request_hash,
			cursor_before_sha256,checkpoint_version
		) VALUES ($1,$2,$3,$4,$5,$6,'DISCOVERY','SCHEDULED',$7,
			'closure-rollover-discovery',repeat('1',64),$8,$9)
	`, run.id, fixture.tenantID, fixture.workspaceID, fixture.sourceID, run.revision,
		run.revisionDigest, gateRevision, checkpointSHA, run.checkpointVersion)
	execAssetSQL(t, database, `
		UPDATE asset_source_runs
		SET status='RUNNING',stage_code='READING',lease_owner='closure-rollover-worker',
			lease_expires_at=statement_timestamp()+interval '10 minutes',fence_epoch=1,
			fence_token_hash=repeat('2',64),heartbeat_sequence=1,
			heartbeat_at=statement_timestamp(),version=version+1 WHERE id=$1
	`, run.id)
	execAssetSQL(t, database, `
		UPDATE asset_source_runs SET stage_code='NORMALIZING',version=version+1 WHERE id=$1
	`, run.id)
	if err := database.QueryRow(context.Background(), `
		SELECT checkpoint_version,fence_epoch,page_sequence
		FROM asset_source_runs WHERE id=$1
	`, run.id).Scan(&run.checkpointVersion, &run.fenceEpoch, &run.pageSequence); err != nil {
		t.Fatalf("read external discovery coordinates: %v", err)
	}
	return run
}

func bindClosureExternalRollover(
	t *testing.T,
	database *pgxpool.Pool,
	fixture assetCatalogFixture,
	run runtimeContractRun,
) {
	t.Helper()
	tx, err := database.BeginTx(context.Background(), pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		t.Fatalf("begin rollover binding: %v", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := tx.Exec(context.Background(), `
		INSERT INTO audit_records (
			id,tenant_id,workspace_id,actor_type,actor_id,action,resource_type,
			resource_id,request_id,trace_id,payload_hash
		) VALUES (
			gen_random_uuid(),$1,$2,'SYSTEM','closure-rollover-worker',
			'CHECKPOINT_LINEAGE_ROLLOVER_BOUND','ASSET_SOURCE_RUN',$3,
			'source-rollover:'||$3,'rollover-binding-trace',repeat('b',64)
		)
	`, fixture.tenantID, fixture.workspaceID, run.id); err != nil {
		t.Fatalf("insert rollover binding receipt: %v", err)
	}
	if _, err := tx.Exec(context.Background(), `
		UPDATE asset_sources
		SET gate_status='DEGRADED',gate_reason_code='CHECKPOINT_LINEAGE_ROLLOVER',
			gate_revision=gate_revision+1,version=version+1
		WHERE id=$1
	`, fixture.sourceID); err != nil {
		t.Fatalf("degrade source for rollover: %v", err)
	}
	if _, err := tx.Exec(context.Background(), `
		UPDATE asset_source_runs
		SET lineage_rollover_reason='PROVIDER_CURSOR_EXPIRED',
			lineage_rollover_evidence_digest=repeat('b',64),version=version+1
		WHERE id=$1
	`, run.id); err != nil {
		t.Fatalf("bind rollover evidence to immutable run admission: %v", err)
	}
	if err := tx.Commit(context.Background()); err != nil {
		t.Fatalf("commit rollover binding: %v", err)
	}
}

func assertClosureExternalObservationAcceptedInRolloverPage(
	t *testing.T,
	database *pgxpool.Pool,
	fixture assetCatalogFixture,
	run runtimeContractRun,
) {
	t.Helper()
	candidate := newRuntimeObservation(fixture, run,
		"8f600000-0000-4000-8000-000000000002", "rollover-external", "3")
	candidate.freshnessKind = "OBJECT_SEQUENCE"
	candidate.freshnessSequence = 1
	tx, err := database.BeginTx(context.Background(), pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		t.Fatalf("begin external rollover successor page: %v", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	execAssetSQL(t, tx, `
		UPDATE asset_source_runs
		SET cleanup_status='PENDING',cleanup_attempt_id=gen_random_uuid(),
			cleanup_attempt_epoch=fence_epoch,version=version+1
		WHERE id=$1
	`, run.id)
	if _, err := tx.Exec(context.Background(), insertRuntimeObservationSQL,
		runtimeObservationArguments(candidate)...); err != nil {
		t.Fatalf("insert external rollover observation: %v", err)
	}
	pageDigest := strings.Repeat("d", 64)
	if err := insertClosurePageReceipt(tx, fixture, run.id, run.pageSequence+1, pageDigest); err != nil {
		t.Fatalf("insert external rollover page receipt: %v", err)
	}
	relationDigest := strings.Repeat("e", 64)
	if err := insertClosureRelationPageReceipt(
		tx, fixture, run.id, 1, relationDigest,
	); err != nil {
		t.Fatalf("insert external rollover relation page receipt: %v", err)
	}
	execAssetSQL(t, tx, `
		WITH envelope AS (
			SELECT decode('01'||repeat('03',12)||repeat('04',16),'hex') AS ciphertext
		)
		UPDATE asset_sources AS source
		SET checkpoint_ciphertext=envelope.ciphertext,checkpoint_key_id='opaque-key-2',
			checkpoint_sha256=encode(sha256(envelope.ciphertext),'hex'),
			checkpoint_version=source.checkpoint_version+1,version=source.version+1
		FROM envelope WHERE source.id=$1
	`, fixture.sourceID)
	execAssetSQL(t, tx, `
		UPDATE asset_source_runs
		SET status='FINALIZING',stage_code='CLEANING_UP',
			page_sequence=page_sequence+1,page_digest=$2,
			relation_page_sequence=relation_page_sequence+1,relation_page_digest=$4,
			checkpoint_version=checkpoint_version+1,
			cursor_after_sha256=(SELECT checkpoint_sha256 FROM asset_sources WHERE id=$3),
			final_page=true,complete_snapshot=true,effective_complete_snapshot=true,
			observed_count=observed_count+1,heartbeat_sequence=heartbeat_sequence+1,
			heartbeat_at=statement_timestamp(),
			lease_expires_at=lease_expires_at+interval '1 minute',
			work_result_kind='DATA_PROJECTION',work_result_status='SUCCEEDED',
			work_result_digest=repeat('f',64),version=version+1
		WHERE id=$1
	`, run.id, pageDigest, fixture.sourceID, relationDigest)
	if err := tx.Commit(context.Background()); err != nil {
		t.Fatalf("commit external rollover successor page: %v", err)
	}
}

func closeClosureExternalRolloverRun(
	t *testing.T,
	database *pgxpool.Pool,
	fixture assetCatalogFixture,
	run runtimeContractRun,
) {
	t.Helper()
	revokeClosureAttempt(t, database, fixture, run.id, strings.Repeat("6", 64))
	tx, err := database.BeginTx(context.Background(), pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		t.Fatalf("begin external rollover terminal closure: %v", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	terminalDigest := sourceRunTerminalDigest(t, tx, run.id, "SUCCEEDED", nil)
	insertTerminalAudit(t, tx, fixture, run.id, terminalDigest)
	execAssetSQL(t, tx, `
		UPDATE asset_source_runs
		SET status='SUCCEEDED',stage_code='COMPLETED',terminal_command_sha256=$2,
			version=version+1
		WHERE id=$1
	`, run.id, terminalDigest)
	execAssetSQL(t, tx, `
		UPDATE asset_sources
		SET gate_status='AVAILABLE',gate_reason_code=NULL,gate_revision=gate_revision+1,
			last_success_run_id=$2,
			last_success_at=(SELECT completed_at FROM asset_source_runs WHERE id=$2),
			last_complete_snapshot_run_id=$2,
			last_complete_snapshot_at=(SELECT completed_at FROM asset_source_runs WHERE id=$2),
			version=version+1
		WHERE id=$1
	`, fixture.sourceID, run.id)
	if err := tx.Commit(context.Background()); err != nil {
		t.Fatalf("commit external rollover terminal closure: %v", err)
	}

	var closed bool
	if err := database.QueryRow(context.Background(), `
		SELECT run.status='SUCCEEDED' AND run.stage_code='COMPLETED' AND
			run.effective_complete_snapshot AND source.status='ACTIVE' AND
			source.gate_status='AVAILABLE' AND source.gate_reason_code IS NULL AND
			source.gate_revision=run.gate_revision+2 AND
			source.last_success_run_id=run.id AND source.last_success_at=run.completed_at AND
			source.last_complete_snapshot_run_id=run.id AND
			source.last_complete_snapshot_at=run.completed_at
		FROM asset_source_runs AS run
		JOIN asset_sources AS source ON source.id=run.source_id
		WHERE run.id=$1
	`, run.id).Scan(&closed); err != nil {
		t.Fatalf("read external rollover terminal closure: %v", err)
	}
	if !closed {
		t.Fatal("external rollover did not close with exact effective snapshot, pointers, and gate revision plus two")
	}
}

func finishClosureExternalValidation(
	t *testing.T,
	database *pgxpool.Pool,
	fixture assetCatalogFixture,
	revision int64,
	proof string,
) {
	t.Helper()
	execAssetSQL(t, database, `
		UPDATE asset_source_runs
		SET stage_code='CLEANING_UP',cleanup_status='PENDING',cleanup_attempt_id=gen_random_uuid(),
			cleanup_attempt_epoch=fence_epoch,version=version+1 WHERE id=$1
	`, fixture.validationRunID)
	execAssetSQL(t, database, `
		UPDATE asset_source_runs
		SET status='FINALIZING',work_result_kind='VALIDATION_PROOF',
			work_result_status='SUCCEEDED',work_result_digest=$2,
			work_result_recorded_at=statement_timestamp(),validation_outcome='SUCCEEDED',
			validation_digest=$2,validation_proof_digest=$2,version=version+1 WHERE id=$1
	`, fixture.validationRunID, proof)
	revokeClosureAttempt(t, database, fixture, fixture.validationRunID, strings.Repeat("6", 64))
	tx, err := database.BeginTx(context.Background(), pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		t.Fatalf("begin external validation terminal closure: %v", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	terminalDigest := sourceRunTerminalDigest(t, tx, fixture.validationRunID, "SUCCEEDED", nil)
	insertTerminalAudit(t, tx, fixture, fixture.validationRunID, terminalDigest)
	execAssetSQL(t, tx, `
		UPDATE asset_source_runs
		SET status='SUCCEEDED',stage_code='COMPLETED',terminal_command_sha256=$2,
			version=version+1 WHERE id=$1
	`, fixture.validationRunID, terminalDigest)
	execAssetSQL(t, tx, `
		UPDATE asset_source_revisions
		SET state='VALIDATED',validation_digest=$2,version=version+1 WHERE id=$1
	`, fixture.revisionID, proof)
	if err := tx.Commit(context.Background()); err != nil {
		t.Fatalf("commit external validation terminal closure: %v", err)
	}
	execAssetSQL(t, database, `
		UPDATE asset_source_revisions SET state='PUBLISHED',version=version+1 WHERE id=$1
	`, fixture.revisionID)
	var publicationClosed bool
	if err := database.QueryRow(context.Background(), `
		SELECT source.published_revision=$3 AND
			source.published_revision_digest=revision.canonical_revision_digest AND
			revision.state='PUBLISHED' AND source.gate_status='UNAVAILABLE' AND
			source.gate_reason_code='PUBLISHED_VALIDATION_REFERENCE_DRIFT' AND
			source.gate_revision=run.gate_revision+2 AND
			source.validated_run_id IS NULL AND source.validation_digest IS NULL AND
			source.validated_binding_digest IS NULL
		FROM asset_sources AS source
		JOIN asset_source_revisions AS revision ON revision.id=$2
		JOIN asset_source_runs AS run ON run.id=revision.validation_run_id
		WHERE source.id=$1
	`, fixture.sourceID, fixture.revisionID, revision).Scan(&publicationClosed); err != nil {
		t.Fatalf("read external publication fail-closed gate: %v", err)
	}
	if !publicationClosed {
		t.Fatal("external publication did not close the visible validation gate at its exact epoch")
	}
	execAssetSQL(t, database, `
		UPDATE asset_sources
		SET gate_status='AVAILABLE',gate_reason_code=NULL,gate_revision=gate_revision+1,
			validated_run_id=$2,validation_digest=$3,validated_binding_digest=$4,
			version=version+1 WHERE id=$1
	`, fixture.sourceID, fixture.validationRunID, proof, fixture.revisionDigest)
}

func revokeClosureAttempt(
	t *testing.T,
	database *pgxpool.Pool,
	fixture assetCatalogFixture,
	runID string,
	digest string,
) {
	t.Helper()
	tx, err := database.BeginTx(context.Background(), pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		t.Fatalf("begin external cleanup proof: %v", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	var epoch int64
	if err := tx.QueryRow(context.Background(), `
		SELECT cleanup_attempt_epoch FROM asset_source_runs WHERE id=$1
	`, runID).Scan(&epoch); err != nil {
		t.Fatalf("read external cleanup epoch: %v", err)
	}
	insertCleanupAudit(t, tx, fixture, runID, epoch, digest)
	execAssetSQL(t, tx, `
		UPDATE asset_source_runs
		SET cleanup_status='REVOKED',cleanup_digest=$2,version=version+1 WHERE id=$1
	`, runID, digest)
	if err := tx.Commit(context.Background()); err != nil {
		t.Fatalf("commit external cleanup proof: %v", err)
	}
}

func publishClosureExternalSuccessor(
	t *testing.T,
	database *pgxpool.Pool,
	fixture assetCatalogFixture,
) {
	t.Helper()
	fixture.revisionID = "8f500000-0000-4000-8000-000000000002"
	fixture.validationRunID = "8f500000-0000-4000-8000-000000000003"
	fixture.revisionDigest = strings.Repeat("d", 64)
	execAssetSQL(t, database, `
		INSERT INTO asset_source_revisions (
			id,tenant_id,workspace_id,source_id,revision,
			canonical_provider_schema,canonical_provider_schema_sha256,integration_id,sync_mode,
			authority_scope_digest,source_definition_digest,canonical_revision_digest,
			credential_reference_id,rate_limit_requests,rate_limit_window_seconds,
			backpressure_base_seconds,backpressure_max_seconds,profile_code,
			created_by,change_reason_code,expected_source_version
		) SELECT $1,$2,$3,$4,2,convert_to('{"type":"object","version":2}','UTF8'),
			encode(sha256(convert_to('{"type":"object","version":2}','UTF8')),'hex'),$5,
			'ON_DEMAND',repeat('a',64),repeat('b',64),$6,'opaque-credential',100,60,1,60,
			'EXTERNAL_V1','closure-test','DEFINITION_CHANGE',source.version
		FROM asset_sources AS source WHERE source.id=$4
	`, fixture.revisionID, fixture.tenantID, fixture.workspaceID, fixture.sourceID,
		fixture.integrationID, fixture.revisionDigest)
	execAssetSQL(t, database, `
		UPDATE asset_sources
		SET gate_status='UNAVAILABLE',gate_reason_code='VALIDATION_REQUESTED',
			gate_revision=gate_revision+1,version=version+1
		WHERE id=$1
	`, fixture.sourceID)
	execAssetSQL(t, database, `
		INSERT INTO asset_source_runs (
			id,tenant_id,workspace_id,source_id,source_revision,source_revision_digest,
			run_kind,trigger_type,gate_revision,idempotency_key,request_hash,checkpoint_version
		) SELECT $1,$2,$3,$4,2,$5,'VALIDATION','HUMAN',gate_revision,
			'closure-successor-validation',repeat('e',64),0 FROM asset_sources WHERE id=$4
	`, fixture.validationRunID, fixture.tenantID, fixture.workspaceID, fixture.sourceID,
		fixture.revisionDigest)
	execAssetSQL(t, database, `
		UPDATE asset_source_revisions
		SET state='VALIDATING',validation_run_id=$2,version=version+1 WHERE id=$1
	`, fixture.revisionID, fixture.validationRunID)
	execAssetSQL(t, database, `
		UPDATE asset_sources
		SET gate_status='VALIDATING',gate_revision=gate_revision+1,
			validated_run_id=$2,validation_digest=NULL,validated_binding_digest=NULL,
			version=version+1
		WHERE id=$1
	`, fixture.sourceID, fixture.validationRunID)
	execAssetSQL(t, database, `
		UPDATE asset_source_runs
		SET status='RUNNING',stage_code='VALIDATING',lease_owner='closure-successor-worker',
			lease_expires_at=statement_timestamp()+interval '10 minutes',fence_epoch=1,
			fence_token_hash=repeat('f',64),heartbeat_sequence=1,
			heartbeat_at=statement_timestamp(),version=version+1 WHERE id=$1
	`, fixture.validationRunID)
	finishClosureExternalValidation(t, database, fixture, 2, strings.Repeat("c", 64))
}

func prepareCleanupUncertainValidationRun(
	t *testing.T,
	database assetSQLExecutor,
	fixture assetCatalogFixture,
) {
	t.Helper()
	execAssetSQL(t, database, `
		UPDATE asset_source_runs
		SET stage_code='CLEANING_UP',cleanup_status='PENDING',
			cleanup_attempt_id='8d000000-0000-4000-8000-000000000001',
			cleanup_attempt_epoch=fence_epoch,version=version+1
		WHERE id=$1
	`, fixture.validationRunID)
	execAssetSQL(t, database, `
		UPDATE asset_source_runs
		SET status='FINALIZING',work_result_kind='VALIDATION_PROOF',
			work_result_status='FAILED',work_result_digest=repeat('f',64),
			work_result_recorded_at=statement_timestamp(),validation_outcome='FAILED',
			validation_digest=repeat('f',64),validation_proof_digest=repeat('f',64),
			version=version+1
		WHERE id=$1
	`, fixture.validationRunID)
}

func finalizeClosureEmptyManualPage(
	t *testing.T,
	database *pgxpool.Pool,
	fixture assetCatalogFixture,
	run runtimeContractRun,
) {
	t.Helper()
	tx, err := database.BeginTx(context.Background(), pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		t.Fatalf("begin closure empty final page: %v", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	pageDigest := strings.Repeat("c", 64)
	if err := insertClosurePageReceipt(tx, fixture, run.id, run.pageSequence+1, pageDigest); err != nil {
		t.Fatalf("insert closure page receipt: %v", err)
	}
	execAssetSQL(t, tx, `
		WITH envelope AS (
			SELECT decode('01'||repeat('07',12)||repeat('08',16),'hex') AS ciphertext
		)
		UPDATE asset_sources AS source
		SET checkpoint_ciphertext=envelope.ciphertext,checkpoint_key_id='opaque-closure-key',
			checkpoint_sha256=encode(sha256(envelope.ciphertext),'hex'),
			checkpoint_version=source.checkpoint_version+1,version=source.version+1
		FROM envelope WHERE source.id=$1
	`, fixture.sourceID)
	execAssetSQL(t, tx, `
		UPDATE asset_source_runs
		SET status='FINALIZING',stage_code='CLEANING_UP',
			page_sequence=page_sequence+1,page_digest=$2,
			checkpoint_version=checkpoint_version+1,final_page=true,
			cursor_after_sha256=(SELECT checkpoint_sha256 FROM asset_sources WHERE id=$3),
			complete_snapshot=false,effective_complete_snapshot=false,
			heartbeat_sequence=heartbeat_sequence+1,heartbeat_at=statement_timestamp(),
			lease_expires_at=lease_expires_at+interval '1 minute',
			work_result_kind='DATA_PROJECTION',work_result_status='SUCCEEDED',
			work_result_digest=repeat('d',64),work_result_recorded_at=statement_timestamp(),
			cleanup_status='PENDING',cleanup_attempt_id=gen_random_uuid(),
			cleanup_attempt_epoch=fence_epoch,version=version+1
		WHERE id=$1
	`, run.id, pageDigest, fixture.sourceID)
	if err := tx.Commit(context.Background()); err != nil {
		t.Fatalf("commit closure empty final page: %v", err)
	}
	revokeClosureAttempt(t, database, fixture, run.id, strings.Repeat("e", 64))
}

func reserveClosureCleanupAttempt(t *testing.T, database assetSQLExecutor, runID string) {
	t.Helper()
	execAssetSQL(t, database, `
		UPDATE asset_source_runs
		SET stage_code='CLEANING_UP',cleanup_status='PENDING',
			cleanup_attempt_id='8d000000-0000-4000-8000-000000000002',
			cleanup_attempt_epoch=fence_epoch,version=version+1
		WHERE id=$1
	`, runID)
}

func closeClosureManualRun(
	t *testing.T,
	tx pgx.Tx,
	fixture assetCatalogFixture,
	runID string,
) error {
	t.Helper()
	terminalDigest := sourceRunTerminalDigest(t, tx, runID, "SUCCEEDED", nil)
	insertTerminalAudit(t, tx, fixture, runID, terminalDigest)
	if _, err := tx.Exec(context.Background(), `
		UPDATE asset_source_runs
		SET status='SUCCEEDED',stage_code='COMPLETED',terminal_command_sha256=$2,
			version=version+1
		WHERE id=$1
	`, runID, terminalDigest); err != nil {
		return err
	}
	_, err := tx.Exec(context.Background(), `
		UPDATE asset_sources
		SET last_success_run_id=$2,
			last_success_at=(SELECT completed_at FROM asset_source_runs WHERE id=$2),
			version=version+1
		WHERE id=$1
	`, fixture.sourceID, runID)
	return err
}

func insertClosurePageReceipt(
	database assetSQLExecutor,
	fixture assetCatalogFixture,
	runID string,
	pageSequence int64,
	pageDigest string,
) error {
	_, err := database.Exec(context.Background(), `
		INSERT INTO audit_records (
			id,tenant_id,workspace_id,actor_type,actor_id,action,resource_type,
			resource_id,request_id,trace_id,payload_hash
		) SELECT gen_random_uuid(),$1,$2,'SYSTEM',run.lease_owner,'PAGE_APPLIED',
			'ASSET_SOURCE_RUN',$3,'source-page:'||$3||':'||$4,
			'closure-page-trace',$5
		FROM asset_source_runs AS run WHERE run.id=$3
	`, fixture.tenantID, fixture.workspaceID, runID, pageSequence, pageDigest)
	return err
}

func insertClosureRelationPageReceipt(
	database assetSQLExecutor,
	fixture assetCatalogFixture,
	runID string,
	pageSequence int64,
	pageDigest string,
) error {
	_, err := database.Exec(context.Background(), `
		INSERT INTO audit_records (
			id,tenant_id,workspace_id,actor_type,actor_id,action,resource_type,
			resource_id,request_id,trace_id,payload_hash
		) SELECT gen_random_uuid(),$1,$2,'SYSTEM',run.lease_owner,'RELATION_PAGE_COMMITTED',
			'ASSET_SOURCE_RUN',$3,'source-relation-page:'||$3||':'||$4,
			'closure-relation-page-trace',$5
		FROM asset_source_runs AS run WHERE run.id=$3
	`, fixture.tenantID, fixture.workspaceID, runID, pageSequence, pageDigest)
	return err
}

func insertClosureManualRevisionExpectingError(
	t *testing.T,
	database interface {
		Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
	},
	fixture assetCatalogFixture,
	profile string,
	referenceColumn string,
	constraint string,
) {
	t.Helper()
	credentialReference := "NULL"
	trustReference := "NULL"
	networkReference := "NULL"
	switch referenceColumn {
	case "credential_reference_id":
		credentialReference = "'opaque-credential'"
	case "trust_reference_id":
		trustReference = "'opaque-trust'"
	case "network_policy_reference_id":
		networkReference = "'opaque-network'"
	}
	query := `
		INSERT INTO asset_source_revisions (
			id,tenant_id,workspace_id,source_id,revision,
			canonical_provider_schema,canonical_provider_schema_sha256,integration_id,sync_mode,
			authority_scope_digest,source_definition_digest,canonical_revision_digest,
			credential_reference_id,trust_reference_id,network_policy_reference_id,
			rate_limit_requests,rate_limit_window_seconds,backpressure_base_seconds,
			backpressure_max_seconds,profile_code,created_by,change_reason_code,
			expected_source_version
		) SELECT '8e000000-0000-4000-8000-000000000010',$1,$2,$3,2,
			convert_to('{"type":"object"}','UTF8'),
			encode(sha256(convert_to('{"type":"object"}','UTF8')),'hex'),$4,'MANUAL',
			repeat('3',64),repeat('4',64),repeat('5',64),` + credentialReference + `,` +
		trustReference + `,` + networkReference + `,100,60,1,60,$5,
			'closure-test','PROFILE_CHANGE',source.version
		FROM asset_sources AS source WHERE source.id=$3
	`
	expectClosureStatementError(t, database, "23514", constraint, query,
		fixture.tenantID, fixture.workspaceID, fixture.sourceID, fixture.integrationID, profile)
}

type closureTxStarter interface {
	BeginTx(context.Context, pgx.TxOptions) (pgx.Tx, error)
}

func expectClosureCommitError(
	t *testing.T,
	database closureTxStarter,
	isolation pgx.TxIsoLevel,
	state string,
	constraint string,
	mutate func(pgx.Tx) error,
) {
	t.Helper()
	tx, err := database.BeginTx(context.Background(), pgx.TxOptions{IsoLevel: isolation})
	if err != nil {
		t.Fatalf("begin closure adversarial transaction: %v", err)
	}
	mutationErr := mutate(tx)
	if mutationErr == nil {
		mutationErr = tx.Commit(context.Background())
	} else {
		_ = tx.Rollback(context.Background())
	}
	assertClosurePostgresError(t, mutationErr, state, constraint)
}

func expectClosureStatementError(
	t *testing.T,
	database interface {
		Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
	},
	state string,
	constraint string,
	query string,
	arguments ...any,
) {
	t.Helper()
	_, err := database.Exec(context.Background(), query, arguments...)
	assertClosurePostgresError(t, err, state, constraint)
}

func assertClosurePostgresError(t *testing.T, err error, state string, constraint string) {
	t.Helper()
	if err == nil {
		t.Fatalf("SQL unexpectedly succeeded; want SQLSTATE %s constraint %s", state, constraint)
	}
	var databaseError *pgconn.PgError
	if !errors.As(err, &databaseError) {
		t.Fatalf("SQL error=%v, want PostgreSQL %s/%s", err, state, constraint)
	}
	if databaseError.Code != state || databaseError.ConstraintName != constraint {
		t.Fatalf("SQL error=%s/%s (%v), want %s/%s", databaseError.Code,
			databaseError.ConstraintName, err, state, constraint)
	}
}
