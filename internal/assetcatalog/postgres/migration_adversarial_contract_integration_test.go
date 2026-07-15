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

func TestAssetCatalogRejectsUnreceiptedCleanupProof(t *testing.T) {
	for _, test := range []struct {
		name               string
		insertForgery      bool
		preplantExactProof bool
	}{
		{name: "missing receipt"},
		{name: "receipt payload does not bind the run", insertForgery: true},
		{name: "exact receipt from an earlier transaction", preplantExactProof: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			harness := newAssetCatalogHarness(t)
			harness.applyThroughAssetCatalog(t)
			fixture := seedClosureAuthoritativeCompleteCatalog(t, harness.db)
			run := startRuntimeContractManualRun(t, harness.db, fixture)
			cleanupDigest := strings.Repeat("a", 64)
			if test.preplantExactProof {
				cleanupDigest = sourceRunNoCredentialDigest(t, harness.db, run.id)
			}
			if test.insertForgery || test.preplantExactProof {
				insertCleanupAudit(t, harness.db, fixture, run.id, 0, cleanupDigest)
			}
			expectRuntimeContractError(t, harness.db, "55000", "asset_source_runs_cleanup_transition_guard", `
				UPDATE asset_source_runs
				SET cleanup_status='NO_CREDENTIAL',cleanup_digest=$2,version=version+1
				WHERE id=$1
			`, run.id, cleanupDigest)
		})
	}
}

func TestAssetCatalogRejectsExpiredAndDriftedLeaseMutation(t *testing.T) {
	t.Run("expired holder cannot renew", func(t *testing.T) {
		harness := newAssetCatalogHarness(t)
		harness.applyThroughAssetCatalog(t)
		fixture := seedClosureAuthoritativeCompleteCatalog(t, harness.db)
		run := startAdversarialManualRun(t, harness.db, fixture, "250 milliseconds")
		execAssetSQL(t, harness.db, `SELECT pg_sleep(0.35)`)

		expectRuntimeContractError(t, harness.db, "55000", "asset_source_runs_lease_expired_guard", `
			UPDATE asset_source_runs
			SET heartbeat_sequence=heartbeat_sequence+1,heartbeat_at=statement_timestamp(),
				lease_expires_at=statement_timestamp()+interval '5 minutes',version=version+1
			WHERE id=$1
		`, run.id)
	})

	t.Run("source drift forbids heartbeat extension", func(t *testing.T) {
		harness := newAssetCatalogHarness(t)
		harness.applyThroughAssetCatalog(t)
		fixture := seedClosureAuthoritativeCompleteCatalog(t, harness.db)
		run := startRuntimeContractManualRun(t, harness.db, fixture)
		execAssetSQL(t, harness.db, `
			UPDATE asset_sources
			SET status='PAUSED',version=version+1
			WHERE id=$1
		`, fixture.sourceID)

		expectRuntimeContractError(t, harness.db, "55000", "asset_source_runs_source_admission_guard", `
			UPDATE asset_source_runs
			SET heartbeat_sequence=heartbeat_sequence+1,heartbeat_at=statement_timestamp(),
				lease_expires_at=lease_expires_at+interval '1 minute',version=version+1
			WHERE id=$1
		`, run.id)
	})
}

func TestAssetCatalogRejectsSnapshotFlagsWithoutAcceptedFinalPage(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedClosureAuthoritativeCompleteCatalog(t, harness.db)
	run := startRuntimeContractManualRun(t, harness.db, fixture)

	expectRuntimeContractError(t, harness.db, "55000", "asset_source_runs_snapshot_transition_guard", `
		UPDATE asset_source_runs
		SET final_page=true,complete_snapshot=true,effective_complete_snapshot=true,
			version=version+1
		WHERE id=$1
	`, run.id)
}

func TestAssetCatalogRejectsTerminalReceiptThatDoesNotBindTheCommand(t *testing.T) {
	for _, test := range []struct {
		name          string
		preplantExact bool
	}{
		{name: "payload does not bind the command"},
		{name: "exact receipt from an earlier transaction", preplantExact: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			harness := newAssetCatalogHarness(t)
			harness.applyThroughAssetCatalog(t)
			fixture := seedClosureAuthoritativeCompleteCatalog(t, harness.db)
			run := startRuntimeContractManualRun(t, harness.db, fixture)
			finalizeAdversarialFailureIntent(t, harness.db, fixture, run)

			terminalDigest := strings.Repeat("f", 64)
			if test.preplantExact {
				terminalDigest = sourceRunTerminalDigest(
					t, harness.db, run.id, "FAILED", "ADVERSARIAL_FAILURE",
				)
			}
			insertTerminalAudit(t, harness.db, fixture, run.id, terminalDigest)
			expectRuntimeContractError(t, harness.db, "55000", "asset_source_runs_terminal_receipt_guard", `
				UPDATE asset_source_runs
				SET status='FAILED',stage_code='COMPLETED',failure_code='ADVERSARIAL_FAILURE',
					terminal_command_sha256=$2,version=version+1
				WHERE id=$1
			`, run.id, terminalDigest)
		})
	}
}

func TestAssetCatalogRejectsIllegalRunStageJump(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedClosureAuthoritativeCompleteCatalog(t, harness.db)
	run := startRuntimeContractManualRun(t, harness.db, fixture)

	expectRuntimeContractError(t, harness.db, "55000", "asset_source_runs_stage_transition_guard", `
		UPDATE asset_source_runs
		SET stage_code='VALIDATING',version=version+1
		WHERE id=$1
	`, run.id)
}

func TestAssetCatalogRejectsUnexplainedSourceGateEpochAdvance(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedClosureAuthoritativeCompleteCatalog(t, harness.db)

	expectRuntimeContractError(t, harness.db, "55000", "asset_sources_gate_transition_guard", `
		UPDATE asset_sources
		SET gate_revision=gate_revision+1,version=version+1
		WHERE id=$1
	`, fixture.sourceID)
}

func TestAssetCatalogSuspendedSourceCannotReuseOldValidation(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedClosureAuthoritativeCompleteCatalog(t, harness.db)
	execAssetSQL(t, harness.db, `
		UPDATE asset_sources
		SET gate_status='UNAVAILABLE',gate_reason_code=NULL,
			gate_revision=gate_revision+1,version=version+1
		WHERE id=$1
	`, fixture.sourceID)

	expectRuntimeContractError(t, harness.db, "23514", "asset_sources_available_gate_guard", `
		UPDATE asset_sources AS source
		SET gate_status='AVAILABLE',gate_reason_code=NULL,
			gate_revision=source.gate_revision+1,
			validated_run_id=revision.validation_run_id,
			validation_digest=revision.validation_digest,
			validated_binding_digest=revision.canonical_revision_digest,
			version=source.version+1
		FROM asset_source_revisions AS revision
		WHERE source.id=$1 AND revision.source_id=source.id AND revision.state='PUBLISHED'
	`, fixture.sourceID)
}

func TestAssetCatalogSuccessfulTerminalRunRequiresAtomicSourcePointer(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedClosureAuthoritativeCompleteCatalog(t, harness.db)
	run := startRuntimeContractManualRun(t, harness.db, fixture)
	finalizeAdversarialEmptySuccessPage(t, harness.db, fixture, run)

	expectAdversarialCommitError(t, harness.db, "55000", "asset_source_runs_success_pointer_closure_guard",
		func(tx pgx.Tx) error {
			digest := sourceRunTerminalDigest(t, tx, run.id, "SUCCEEDED", nil)
			insertTerminalAudit(t, tx, fixture, run.id, digest)
			_, err := tx.Exec(context.Background(), `
				UPDATE asset_source_runs
				SET status='SUCCEEDED',stage_code='COMPLETED',terminal_command_sha256=$2,
					version=version+1
				WHERE id=$1
			`, run.id, digest)
			return err
		})
}

func TestAssetCatalogRunPageRequiresExactReceiptActorAndObservationCount(t *testing.T) {
	for _, test := range []struct {
		name          string
		pageActor     string
		observedCount int64
	}{
		{name: "receipt actor must own the live lease", pageActor: "unrelated-worker"},
		{name: "observed count must equal committed observations", pageActor: "runtime-manual-executor", observedCount: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			harness := newAssetCatalogHarness(t)
			harness.applyThroughAssetCatalog(t)
			fixture := seedClosureAuthoritativeCompleteCatalog(t, harness.db)
			run := startRuntimeContractManualRun(t, harness.db, fixture)
			expectAdversarialCommitError(t, harness.db, "55000", "asset_source_runs_page_closure_guard",
				func(tx pgx.Tx) error {
					return stageAdversarialEmptySuccessPage(
						t, tx, fixture, run, test.pageActor, test.observedCount, true,
					)
				})
		})
	}
}

func TestAssetCatalogAllowsConsecutiveCanonicalEmptyRelationPages(t *testing.T) {
	harness, fixture, run := prepareAdversarialExternalDataRun(t)

	if err := commitAdversarialRelationPage(
		harness.db, fixture, run, 1, strings.Repeat("1", 64),
		correctiveCanonicalEmptyRelationPageSHA256, false,
	); err != nil {
		t.Fatalf("commit first canonical empty relation page: %v", err)
	}
	if err := commitAdversarialRelationPage(
		harness.db, fixture, run, 2, strings.Repeat("2", 64),
		correctiveCanonicalEmptyRelationPageSHA256, true,
	); err != nil {
		t.Fatalf("commit second canonical empty relation page as final complete snapshot: %v", err)
	}

	var pageSequence, relationSequence, checkpointVersion int64
	var relationDigest string
	var finalPage, completeSnapshot, effectiveCompleteSnapshot bool
	if err := harness.db.QueryRow(context.Background(), `
		SELECT page_sequence,relation_page_sequence,relation_page_digest,checkpoint_version,
			final_page,complete_snapshot,effective_complete_snapshot
		FROM asset_source_runs WHERE id=$1
	`, run.id).Scan(&pageSequence, &relationSequence, &relationDigest, &checkpointVersion,
		&finalPage, &completeSnapshot, &effectiveCompleteSnapshot); err != nil {
		t.Fatalf("read consecutive empty relation-page coordinates: %v", err)
	}
	if pageSequence != 2 || relationSequence != 2 || checkpointVersion != run.checkpointVersion+2 ||
		relationDigest != correctiveCanonicalEmptyRelationPageSHA256 ||
		!finalPage || !completeSnapshot || !effectiveCompleteSnapshot {
		t.Fatalf("consecutive empty relation-page closure = page:%d relation:%d checkpoint:%d digest:%q final:%t complete:%t effective:%t",
			pageSequence, relationSequence, checkpointVersion, relationDigest,
			finalPage, completeSnapshot, effectiveCompleteSnapshot)
	}

	var requestIDs []string
	var payloads []string
	if err := harness.db.QueryRow(context.Background(), `
		SELECT array_agg(request_id ORDER BY request_id),array_agg(payload_hash ORDER BY request_id)
		FROM audit_records
		WHERE resource_type='ASSET_SOURCE_RUN' AND resource_id=$1
		  AND action='RELATION_PAGE_COMMITTED'
	`, run.id).Scan(&requestIDs, &payloads); err != nil {
		t.Fatalf("read consecutive empty relation-page receipts: %v", err)
	}
	wantRequest1 := "source-relation-page:" + run.id + ":1"
	wantRequest2 := "source-relation-page:" + run.id + ":2"
	if len(requestIDs) != 2 || requestIDs[0] != wantRequest1 || requestIDs[1] != wantRequest2 ||
		len(payloads) != 2 || payloads[0] != correctiveCanonicalEmptyRelationPageSHA256 ||
		payloads[1] != correctiveCanonicalEmptyRelationPageSHA256 {
		t.Fatalf("consecutive empty relation-page receipts = ids:%v payloads:%v, want distinct sequence identities and one canonical digest",
			requestIDs, payloads)
	}
}

func TestAssetCatalogRejectsInvalidSuccessorRelationPagesWithoutResidue(t *testing.T) {
	nonemptyDigest := strings.Repeat("a", 64)
	for _, test := range []struct {
		name                  string
		firstRelationDigest   string
		relationDigest        any
		relationReceiptMode   string
		relationReceiptDigest string
		relationSequenceDelta int64
		checkpointDelta       int64
		staleFence            bool
		state                 string
		constraint            string
	}{
		{
			name: "same nonempty relation digest", firstRelationDigest: nonemptyDigest,
			relationDigest: nonemptyDigest, relationReceiptMode: "exact",
			relationReceiptDigest: nonemptyDigest, relationSequenceDelta: 1, checkpointDelta: 1,
			state: "55000", constraint: "asset_source_runs_checkpoint_page_guard",
		},
		{
			name: "missing relation receipt", firstRelationDigest: correctiveCanonicalEmptyRelationPageSHA256,
			relationDigest: correctiveCanonicalEmptyRelationPageSHA256, relationReceiptMode: "missing",
			relationSequenceDelta: 1, checkpointDelta: 1,
			state: "55000", constraint: "asset_source_runs_page_closure_guard",
		},
		{
			name: "changed relation receipt payload", firstRelationDigest: correctiveCanonicalEmptyRelationPageSHA256,
			relationDigest: correctiveCanonicalEmptyRelationPageSHA256, relationReceiptMode: "changed",
			relationReceiptDigest: strings.Repeat("f", 64), relationSequenceDelta: 1, checkpointDelta: 1,
			state: "55000", constraint: "asset_source_runs_page_closure_guard",
		},
		{
			name: "null relation digest", firstRelationDigest: correctiveCanonicalEmptyRelationPageSHA256,
			relationDigest: nil, relationReceiptMode: "exact",
			relationReceiptDigest: correctiveCanonicalEmptyRelationPageSHA256,
			relationSequenceDelta: 1, checkpointDelta: 1,
			state: "55000", constraint: "asset_source_runs_checkpoint_page_guard",
		},
		{
			name: "invalid relation digest", firstRelationDigest: correctiveCanonicalEmptyRelationPageSHA256,
			relationDigest: "not-a-sha256", relationReceiptMode: "exact",
			relationReceiptDigest: "not-a-sha256",
			relationSequenceDelta: 1, checkpointDelta: 1,
			state: "23514", constraint: "asset_management_audit_shape_guard",
		},
		{
			name: "relation sequence jump", firstRelationDigest: correctiveCanonicalEmptyRelationPageSHA256,
			relationDigest: correctiveCanonicalEmptyRelationPageSHA256, relationReceiptMode: "exact",
			relationReceiptDigest: correctiveCanonicalEmptyRelationPageSHA256,
			relationSequenceDelta: 2, checkpointDelta: 1,
			state: "55000", constraint: "asset_source_runs_progress_guard",
		},
		{
			name: "stale fence", firstRelationDigest: correctiveCanonicalEmptyRelationPageSHA256,
			relationDigest: correctiveCanonicalEmptyRelationPageSHA256, relationReceiptMode: "exact",
			relationReceiptDigest: correctiveCanonicalEmptyRelationPageSHA256,
			relationSequenceDelta: 1, checkpointDelta: 1, staleFence: true,
			state: "55000", constraint: "asset_source_runs_fence_guard",
		},
		{
			name: "wrong checkpoint", firstRelationDigest: correctiveCanonicalEmptyRelationPageSHA256,
			relationDigest: correctiveCanonicalEmptyRelationPageSHA256, relationReceiptMode: "exact",
			relationReceiptDigest: correctiveCanonicalEmptyRelationPageSHA256,
			relationSequenceDelta: 1, checkpointDelta: 0,
			state: "55000", constraint: "asset_source_runs_source_admission_guard",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			harness, fixture, run := prepareAdversarialExternalDataRun(t)
			if err := commitAdversarialRelationPage(
				harness.db, fixture, run, 1, strings.Repeat("1", 64),
				test.firstRelationDigest, false,
			); err != nil {
				t.Fatalf("commit predecessor relation page: %v", err)
			}
			err := attemptAdversarialSuccessorRelationPage(harness.db, fixture, run,
				test.relationDigest, test.relationReceiptMode, test.relationReceiptDigest,
				test.relationSequenceDelta, test.checkpointDelta, test.staleFence)
			assertAdversarialPostgreSQLError(t, err, test.state, test.constraint)
			assertAdversarialSuccessorPageRolledBack(t, harness.db, fixture, run)
		})
	}
}

func TestAssetCatalogRejectsNonserializableTerminalAfterConsecutiveEmptyRelationPages(t *testing.T) {
	harness, fixture, run := prepareAdversarialExternalDataRun(t)
	if err := commitAdversarialRelationPage(
		harness.db, fixture, run, 1, strings.Repeat("1", 64),
		correctiveCanonicalEmptyRelationPageSHA256, false,
	); err != nil {
		t.Fatalf("commit first canonical empty relation page: %v", err)
	}
	if err := commitAdversarialRelationPage(
		harness.db, fixture, run, 2, strings.Repeat("2", 64),
		correctiveCanonicalEmptyRelationPageSHA256, true,
	); err != nil {
		t.Fatalf("commit final canonical empty relation page: %v", err)
	}
	revokeClosureAttempt(t, harness.db, fixture, run.id, strings.Repeat("9", 64))

	tx, err := harness.db.BeginTx(context.Background(), pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		t.Fatalf("begin nonserializable terminal closure: %v", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	terminalDigest := sourceRunTerminalDigest(t, tx, run.id, "SUCCEEDED", nil)
	insertTerminalAudit(t, tx, fixture, run.id, terminalDigest)
	_, mutationErr := tx.Exec(context.Background(), `
		UPDATE asset_source_runs
		SET status='SUCCEEDED',stage_code='COMPLETED',terminal_command_sha256=$2,
			version=version+1
		WHERE id=$1
	`, run.id, terminalDigest)
	if mutationErr == nil {
		mutationErr = tx.Commit(context.Background())
	} else {
		_ = tx.Rollback(context.Background())
	}
	assertAdversarialPostgreSQLError(t, mutationErr, "55000", "asset_source_runs_terminal_isolation_guard")

	var status string
	var terminalCommand *string
	var receiptCount int
	if err := harness.db.QueryRow(context.Background(), `
		SELECT run.status,run.terminal_command_sha256,
			(SELECT count(*) FROM audit_records AS audit
			 WHERE audit.resource_type='ASSET_SOURCE_RUN' AND audit.resource_id=run.id::text
			   AND audit.action='TERMINAL_COMMITTED')
		FROM asset_source_runs AS run WHERE run.id=$1
	`, run.id).Scan(&status, &terminalCommand, &receiptCount); err != nil {
		t.Fatalf("read nonserializable terminal rollback: %v", err)
	}
	if status != "FINALIZING" || terminalCommand != nil || receiptCount != 0 {
		t.Fatalf("nonserializable terminal residue = status:%q command:%v receipts:%d",
			status, terminalCommand, receiptCount)
	}
}

func TestAssetCatalogRejectsPreplantedPageReceipts(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedClosureAuthoritativeCompleteCatalog(t, harness.db)
	run := startRuntimeContractManualRun(t, harness.db, fixture)
	if err := insertAdversarialPageReceipts(
		harness.db, fixture, run, "runtime-manual-executor",
		strings.Repeat("d", 64), strings.Repeat("e", 64),
	); err != nil {
		t.Fatalf("preplant exact page receipts: %v", err)
	}
	expectAdversarialCommitError(t, harness.db, "55000", "asset_source_runs_page_closure_guard",
		func(tx pgx.Tx) error {
			return stageAdversarialEmptySuccessPage(
				t, tx, fixture, run, "runtime-manual-executor", 0, false,
			)
		})
}

func TestAssetCatalogRejectsUnreceiptedLineageRolloverBinding(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedClosureAuthoritativeCompleteCatalog(t, harness.db)
	run := startClosureExternalDiscoveryRun(t, harness.db, fixture)

	expectAdversarialCommitError(t, harness.db, "55000", "asset_source_runs_rollover_receipt_guard",
		func(tx pgx.Tx) error {
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

func TestAssetCatalogRolloverKeepsImmutableAdmissionRevisionAndAcceptsSuccessorPage(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedClosureAuthoritativeCompleteCatalog(t, harness.db)
	run := startClosureExternalDiscoveryRun(t, harness.db, fixture)
	bindClosureExternalRollover(t, harness.db, fixture, run)

	t.Run("live rollover rejects source deactivation", func(t *testing.T) {
		expectRuntimeContractError(t, harness.db, "55000", "asset_sources_rollover_gate_guard", `
			UPDATE asset_sources SET status='PAUSED',version=version+1 WHERE id=$1
		`, fixture.sourceID)
	})
	t.Run("live rollover rejects unavailable gate", func(t *testing.T) {
		expectRuntimeContractError(t, harness.db, "55000", "asset_sources_rollover_gate_guard", `
			UPDATE asset_sources
			SET gate_status='UNAVAILABLE',gate_revision=gate_revision+1,version=version+1
			WHERE id=$1
		`, fixture.sourceID)
	})

	if _, err := harness.db.Exec(context.Background(), `
		UPDATE asset_source_runs SET stage_code='APPLYING',version=version+1 WHERE id=$1
	`, run.id); err != nil {
		t.Fatalf("rollover run cannot reach successor apply stage: %v", err)
	}
	assertClosureExternalObservationAcceptedInRolloverPage(t, harness.db, fixture, run)
	closeClosureExternalRolloverRun(t, harness.db, fixture, run)
}

func TestAssetCatalogRelationshipRequiresLiveExactRunAndAtomicPageReceipt(t *testing.T) {
	t.Run("expired run cannot update relationship", func(t *testing.T) {
		harness := newAssetCatalogHarness(t)
		harness.applyThroughAssetCatalog(t)
		fixture := seedClosureAuthoritativeCompleteCatalog(t, harness.db)
		run := startAdversarialManualRun(t, harness.db, fixture, "250 milliseconds")
		execAssetSQL(t, harness.db, `SELECT pg_sleep(0.35)`)

		expectRuntimeContractError(t, harness.db, "55000", "asset_relationships_run_admission_guard",
			adversarialRelationshipUpdateSQL, run.id, run.pageSequence+1,
			run.checkpointVersion+1, fixture.relationshipID)
	})

	t.Run("relationship cannot commit before its run page", func(t *testing.T) {
		harness := newAssetCatalogHarness(t)
		harness.applyThroughAssetCatalog(t)
		fixture := seedClosureAuthoritativeCompleteCatalog(t, harness.db)
		run := startRuntimeContractManualRun(t, harness.db, fixture)

		expectAdversarialCommitError(t, harness.db, "55000", "asset_relationships_page_closure_guard",
			func(tx pgx.Tx) error {
				_, err := tx.Exec(context.Background(), adversarialRelationshipUpdateSQL,
					run.id, run.pageSequence+1, run.checkpointVersion+1, fixture.relationshipID)
				return err
			})
	})
}

func TestAssetCatalogObservationCannotCommitBeforeItsRunPage(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedClosureAuthoritativeCompleteCatalog(t, harness.db)
	run := startRuntimeContractManualRun(t, harness.db, fixture)
	candidate := newRuntimeObservation(fixture, run,
		"8b000000-0000-4000-8000-000000000001", "orphan-observation", "b")
	candidate.freshnessKind = "OBJECT_SEQUENCE"
	candidate.freshnessSequence = 1

	expectAdversarialCommitError(t, harness.db, "55000", "asset_observations_page_closure_guard",
		func(tx pgx.Tx) error {
			_, err := tx.Exec(context.Background(), insertRuntimeObservationSQL,
				runtimeObservationArguments(candidate)...)
			return err
		})
}

const adversarialRelationshipUpdateSQL = `
	UPDATE asset_relationships
	SET last_run_id=$1,last_page_sequence=$2,relation_page_sha256=repeat('c',64),
		accepted_checkpoint_version=$3,run_fence_epoch=(
			SELECT fence_epoch FROM asset_source_runs WHERE id=$1
		),freshness_order_sequence=$3,provider_version_sha256=repeat('d',64),
		relation_fact_sha256=repeat('e',64),version=version+1
	WHERE id=$4
`

func startAdversarialManualRun(
	t *testing.T,
	database *pgxpool.Pool,
	fixture assetCatalogFixture,
	leaseDuration string,
) runtimeContractRun {
	t.Helper()
	run := runtimeContractRun{id: "8c000000-0000-4000-8000-000000000001"}
	var gateRevision int64
	var checkpointSHA *string
	var sourceKind string
	if err := database.QueryRow(context.Background(), `
		SELECT source.published_revision,source.published_revision_digest,
			revision.source_definition_digest,source.gate_revision,
			source.checkpoint_version,source.checkpoint_sha256,source.provider_kind,source.source_kind
		FROM asset_sources AS source
		JOIN asset_source_revisions AS revision
		  ON revision.tenant_id=source.tenant_id
		 AND revision.workspace_id=source.workspace_id
		 AND revision.source_id=source.id
		 AND revision.revision=source.published_revision
		WHERE source.id=$1
	`, fixture.sourceID).Scan(&run.revision, &run.revisionDigest,
		&run.sourceDefinitionDigest, &gateRevision, &run.checkpointVersion,
		&checkpointSHA, &run.providerKind, &sourceKind); err != nil {
		t.Fatalf("read source admission: %v", err)
	}
	runKind, triggerType := "MANUAL_MUTATION", "HUMAN"
	if sourceKind != "MANUAL" {
		runKind, triggerType = "DISCOVERY", "SCHEDULED"
	}
	execAssetSQL(t, database, `
		INSERT INTO asset_source_runs (
			id,tenant_id,workspace_id,source_id,source_revision,source_revision_digest,
			run_kind,trigger_type,gate_revision,idempotency_key,request_hash,
			cursor_before_sha256,checkpoint_version
		) VALUES ($1,$2,$3,$4,$5,$6,$10,$11,$7,
			'adversarial-data-run',repeat('1',64),$8,$9)
	`, run.id, fixture.tenantID, fixture.workspaceID, fixture.sourceID,
		run.revision, run.revisionDigest, gateRevision, checkpointSHA, run.checkpointVersion,
		runKind, triggerType)
	execAssetSQL(t, database, `
		UPDATE asset_source_runs
		SET status='RUNNING',stage_code='READING',lease_owner='adversarial-worker',
			lease_expires_at=statement_timestamp()+$2::interval,fence_epoch=1,
			fence_token_hash=repeat('2',64),heartbeat_sequence=1,
			heartbeat_at=statement_timestamp(),version=version+1
		WHERE id=$1
	`, run.id, leaseDuration)
	execAssetSQL(t, database, `
		UPDATE asset_source_runs SET stage_code='NORMALIZING',version=version+1 WHERE id=$1
	`, run.id)
	if err := database.QueryRow(context.Background(), `
		SELECT checkpoint_version,fence_epoch,page_sequence
		FROM asset_source_runs WHERE id=$1
	`, run.id).Scan(&run.checkpointVersion, &run.fenceEpoch, &run.pageSequence); err != nil {
		t.Fatalf("read adversarial run coordinates: %v", err)
	}
	return run
}

func finalizeAdversarialFailureIntent(
	t *testing.T,
	database *pgxpool.Pool,
	fixture assetCatalogFixture,
	run runtimeContractRun,
) {
	t.Helper()
	tx, err := database.BeginTx(context.Background(), pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		t.Fatalf("begin adversarial failure finalization: %v", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := tx.Exec(context.Background(), `
		UPDATE asset_source_runs
		SET status='FINALIZING',stage_code='CLEANING_UP',
			work_result_kind='FAILURE_INTENT',work_result_status='FAILED',
			work_result_digest=repeat('e',64),work_result_recorded_at=statement_timestamp(),
			cleanup_status='PENDING',cleanup_attempt_id=gen_random_uuid(),
			cleanup_attempt_epoch=fence_epoch,
			version=version+1
		WHERE id=$1
	`, run.id); err != nil {
		t.Fatalf("persist adversarial failure intent: %v", err)
	}
	if err := tx.Commit(context.Background()); err != nil {
		t.Fatalf("commit adversarial failure finalization: %v", err)
	}
	revokeClosureAttempt(t, database, fixture, run.id, strings.Repeat("a", 64))
}

func finalizeAdversarialEmptySuccessPage(
	t *testing.T,
	database *pgxpool.Pool,
	fixture assetCatalogFixture,
	run runtimeContractRun,
) {
	t.Helper()
	tx, err := database.BeginTx(context.Background(), pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		t.Fatalf("begin adversarial empty success page: %v", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if err := stageAdversarialEmptySuccessPage(
		t, tx, fixture, run, "runtime-manual-executor", 0, true,
	); err != nil {
		t.Fatalf("stage empty successful final page: %v", err)
	}
	if err := tx.Commit(context.Background()); err != nil {
		t.Fatalf("commit adversarial empty success page: %v", err)
	}
	revokeClosureAttempt(t, database, fixture, run.id, strings.Repeat("b", 64))
}

func stageAdversarialEmptySuccessPage(
	t *testing.T,
	tx pgx.Tx,
	fixture assetCatalogFixture,
	run runtimeContractRun,
	pageActor string,
	observedCount int64,
	insertReceipts bool,
) error {
	t.Helper()
	pageDigest := strings.Repeat("d", 64)
	relationDigest := strings.Repeat("e", 64)
	if insertReceipts {
		if err := insertAdversarialPageReceipts(
			tx, fixture, run, pageActor, pageDigest, relationDigest,
		); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(context.Background(), `
		WITH envelope AS (
			SELECT decode('01'||repeat('05',12)||repeat('06',16),'hex') AS ciphertext
		)
		UPDATE asset_sources AS source
		SET checkpoint_ciphertext=envelope.ciphertext,checkpoint_key_id='opaque-runtime-key',
			checkpoint_sha256=encode(sha256(envelope.ciphertext),'hex'),
			checkpoint_version=source.checkpoint_version+1,version=source.version+1
		FROM envelope WHERE source.id=$1
	`, fixture.sourceID); err != nil {
		return err
	}
	if _, err := tx.Exec(context.Background(), `
		UPDATE asset_source_runs
		SET status='FINALIZING',stage_code='CLEANING_UP',page_sequence=page_sequence+1,
			page_digest=$2,relation_page_sequence=relation_page_sequence+1,
			relation_page_digest=$4,checkpoint_version=checkpoint_version+1,final_page=true,
			cursor_after_sha256=(SELECT checkpoint_sha256 FROM asset_sources WHERE id=$5),
			complete_snapshot=false,effective_complete_snapshot=false,
			observed_count=$3,
			heartbeat_sequence=heartbeat_sequence+1,heartbeat_at=statement_timestamp(),
			lease_expires_at=lease_expires_at+interval '1 minute',
			work_result_kind='DATA_PROJECTION',work_result_status='SUCCEEDED',
			work_result_digest=repeat('c',64),work_result_recorded_at=statement_timestamp(),
			cleanup_status='PENDING',cleanup_attempt_id=gen_random_uuid(),
			cleanup_attempt_epoch=fence_epoch,
			version=version+1
		WHERE id=$1
	`, run.id, pageDigest, observedCount, relationDigest, fixture.sourceID); err != nil {
		return err
	}
	return nil
}

func insertAdversarialPageReceipts(
	database assetSQLExecutor,
	fixture assetCatalogFixture,
	run runtimeContractRun,
	pageActor string,
	pageDigest string,
	relationDigest string,
) error {
	if _, err := database.Exec(context.Background(), `
		INSERT INTO audit_records (
			id,tenant_id,workspace_id,actor_type,actor_id,action,resource_type,
			resource_id,request_id,trace_id,payload_hash
		) VALUES (
			gen_random_uuid(),$1,$2,'SYSTEM',$5,'PAGE_APPLIED',
			'ASSET_SOURCE_RUN',$3,'source-page:'||$3||':1','empty-page-trace',$4
		)
	`, fixture.tenantID, fixture.workspaceID, run.id, pageDigest, pageActor); err != nil {
		return err
	}
	if _, err := database.Exec(context.Background(), `
		INSERT INTO audit_records (
			id,tenant_id,workspace_id,actor_type,actor_id,action,resource_type,
			resource_id,request_id,trace_id,payload_hash
		) VALUES (
			gen_random_uuid(),$1,$2,'SYSTEM',$5,'RELATION_PAGE_COMMITTED',
			'ASSET_SOURCE_RUN',$3,'source-relation-page:'||$3||':1',
			'empty-relation-page-trace',$4
		)
	`, fixture.tenantID, fixture.workspaceID, run.id, relationDigest, pageActor); err != nil {
		return err
	}
	return nil
}

func prepareAdversarialExternalDataRun(
	t *testing.T,
) (*assetCatalogHarness, assetCatalogFixture, runtimeContractRun) {
	t.Helper()
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedDraftAssetCatalog(t, harness.db)
	fixture = seedClosureExternalValidationOnFixture(t, harness.db, fixture)
	finishClosureExternalValidation(t, harness.db, fixture, 1, strings.Repeat("7", 64))
	run := startRuntimeContractManualRun(t, harness.db, fixture)
	return harness, fixture, run
}

func commitAdversarialRelationPage(
	database *pgxpool.Pool,
	fixture assetCatalogFixture,
	run runtimeContractRun,
	sequence int64,
	pageDigest string,
	relationDigest string,
	finalCompleteSnapshot bool,
) error {
	tx, err := database.BeginTx(context.Background(), pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if err := insertClosurePageReceipt(tx, fixture, run.id, sequence, pageDigest); err != nil {
		return err
	}
	if err := insertClosureRelationPageReceipt(tx, fixture, run.id, sequence, relationDigest); err != nil {
		return err
	}
	nonceByte, ciphertextByte := "05", "06"
	if sequence != 1 {
		nonceByte, ciphertextByte = "07", "08"
	}
	envelope := "01" + strings.Repeat(nonceByte, 12) + strings.Repeat(ciphertextByte, 16)
	if _, err := tx.Exec(context.Background(), `
		UPDATE asset_sources
		SET checkpoint_ciphertext=decode($2,'hex'),checkpoint_key_id='opaque-relation-page-key',
			checkpoint_sha256=encode(sha256(decode($2,'hex')),'hex'),
			checkpoint_version=checkpoint_version+1,version=version+1
		WHERE id=$1
	`, fixture.sourceID, envelope); err != nil {
		return err
	}
	if finalCompleteSnapshot {
		if _, err := tx.Exec(context.Background(), `
			UPDATE asset_source_runs
			SET status='FINALIZING',stage_code='CLEANING_UP',
				page_sequence=page_sequence+1,page_digest=$2,
				relation_page_sequence=relation_page_sequence+1,relation_page_digest=$3,
				checkpoint_version=checkpoint_version+1,
				cursor_after_sha256=(SELECT checkpoint_sha256 FROM asset_sources WHERE id=$4),
				final_page=true,complete_snapshot=true,effective_complete_snapshot=true,
				heartbeat_sequence=heartbeat_sequence+1,heartbeat_at=statement_timestamp(),
				lease_expires_at=lease_expires_at+interval '1 minute',
				work_result_kind='DATA_PROJECTION',work_result_status='SUCCEEDED',
				work_result_digest=repeat('c',64),work_result_recorded_at=statement_timestamp(),
				cleanup_status='PENDING',cleanup_attempt_id=gen_random_uuid(),
				cleanup_attempt_epoch=fence_epoch,version=version+1
			WHERE id=$1
		`, run.id, pageDigest, relationDigest, fixture.sourceID); err != nil {
			return err
		}
	} else if _, err := tx.Exec(context.Background(), `
		UPDATE asset_source_runs
		SET stage_code='APPLYING',page_sequence=page_sequence+1,page_digest=$2,
			relation_page_sequence=relation_page_sequence+1,relation_page_digest=$3,
			checkpoint_version=checkpoint_version+1,
			cursor_after_sha256=(SELECT checkpoint_sha256 FROM asset_sources WHERE id=$4),
			heartbeat_sequence=heartbeat_sequence+1,heartbeat_at=statement_timestamp(),
			lease_expires_at=lease_expires_at+interval '1 minute',version=version+1
		WHERE id=$1
	`, run.id, pageDigest, relationDigest, fixture.sourceID); err != nil {
		return err
	}
	return tx.Commit(context.Background())
}

func attemptAdversarialSuccessorRelationPage(
	database *pgxpool.Pool,
	fixture assetCatalogFixture,
	run runtimeContractRun,
	relationDigest any,
	relationReceiptMode string,
	relationReceiptDigest string,
	relationSequenceDelta int64,
	checkpointDelta int64,
	staleFence bool,
) error {
	tx, err := database.BeginTx(context.Background(), pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if err := insertClosurePageReceipt(tx, fixture, run.id, 2, strings.Repeat("2", 64)); err != nil {
		return err
	}
	if relationReceiptMode != "missing" {
		if err := insertClosureRelationPageReceipt(
			tx, fixture, run.id, 1+relationSequenceDelta, relationReceiptDigest,
		); err != nil {
			return err
		}
	}
	envelope := "01" + strings.Repeat("09", 12) + strings.Repeat("0a", 16)
	if _, err := tx.Exec(context.Background(), `
		UPDATE asset_sources
		SET checkpoint_ciphertext=decode($2,'hex'),checkpoint_key_id='opaque-relation-page-key',
			checkpoint_sha256=encode(sha256(decode($2,'hex')),'hex'),
			checkpoint_version=checkpoint_version+1,version=version+1
		WHERE id=$1
	`, fixture.sourceID, envelope); err != nil {
		return err
	}
	if _, err := tx.Exec(context.Background(), `
		UPDATE asset_source_runs
		SET page_sequence=page_sequence+1,page_digest=$2,
			relation_page_sequence=relation_page_sequence+$3,relation_page_digest=$4,
			checkpoint_version=checkpoint_version+$5,
			cursor_after_sha256=(SELECT checkpoint_sha256 FROM asset_sources WHERE id=$6),
			fence_epoch=CASE WHEN $7 THEN fence_epoch-1 ELSE fence_epoch END,
			heartbeat_sequence=heartbeat_sequence+1,heartbeat_at=statement_timestamp(),
			lease_expires_at=lease_expires_at+interval '1 minute',version=version+1
		WHERE id=$1
	`, run.id, strings.Repeat("2", 64), relationSequenceDelta, relationDigest,
		checkpointDelta, fixture.sourceID, staleFence); err != nil {
		return err
	}
	return tx.Commit(context.Background())
}

func assertAdversarialPostgreSQLError(t *testing.T, err error, state string, constraint string) {
	t.Helper()
	if err == nil {
		t.Fatalf("transaction committed; want SQLSTATE %s constraint %s", state, constraint)
	}
	var databaseError *pgconn.PgError
	if !errors.As(err, &databaseError) {
		t.Fatalf("transaction error=%v, want PostgreSQL %s/%s", err, state, constraint)
	}
	if databaseError.Code != state || databaseError.ConstraintName != constraint {
		t.Fatalf("transaction error=%s/%s (%v), want %s/%s",
			databaseError.Code, databaseError.ConstraintName, err, state, constraint)
	}
}

func assertAdversarialSuccessorPageRolledBack(
	t *testing.T,
	database *pgxpool.Pool,
	fixture assetCatalogFixture,
	run runtimeContractRun,
) {
	t.Helper()
	var pageSequence, relationSequence, runCheckpoint, sourceCheckpoint, pageReceipts, relationReceipts int64
	var fenceEpoch int64
	if err := database.QueryRow(context.Background(), `
		SELECT run.page_sequence,run.relation_page_sequence,run.checkpoint_version,
			run.fence_epoch,source.checkpoint_version,
			(SELECT count(*) FROM audit_records AS audit
			 WHERE audit.resource_type='ASSET_SOURCE_RUN' AND audit.resource_id=run.id::text
			   AND audit.action='PAGE_APPLIED'),
			(SELECT count(*) FROM audit_records AS audit
			 WHERE audit.resource_type='ASSET_SOURCE_RUN' AND audit.resource_id=run.id::text
			   AND audit.action='RELATION_PAGE_COMMITTED')
		FROM asset_source_runs AS run
		JOIN asset_sources AS source ON source.id=run.source_id
		WHERE run.id=$1 AND source.id=$2
	`, run.id, fixture.sourceID).Scan(&pageSequence, &relationSequence, &runCheckpoint,
		&fenceEpoch, &sourceCheckpoint, &pageReceipts, &relationReceipts); err != nil {
		t.Fatalf("read rejected successor page rollback: %v", err)
	}
	if pageSequence != 1 || relationSequence != 1 ||
		runCheckpoint != run.checkpointVersion+1 || sourceCheckpoint != run.checkpointVersion+1 ||
		fenceEpoch != run.fenceEpoch || pageReceipts != 1 || relationReceipts != 1 {
		t.Fatalf("rejected successor page residue = page:%d relation:%d run-checkpoint:%d source-checkpoint:%d fence:%d page-receipts:%d relation-receipts:%d",
			pageSequence, relationSequence, runCheckpoint, sourceCheckpoint, fenceEpoch,
			pageReceipts, relationReceipts)
	}
}

func assertAdversarialObservationAcceptedInPage(
	t *testing.T,
	database *pgxpool.Pool,
	fixture assetCatalogFixture,
	run runtimeContractRun,
	candidate runtimeObservation,
) {
	t.Helper()
	tx, err := database.BeginTx(context.Background(), pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		t.Fatalf("begin successor page: %v", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := tx.Exec(context.Background(), insertRuntimeObservationSQL,
		runtimeObservationArguments(candidate)...); err != nil {
		t.Fatalf("insert rollover successor observation: %v", err)
	}
	pageDigest := strings.Repeat("d", 64)
	relationDigest := strings.Repeat("e", 64)
	if _, err := tx.Exec(context.Background(), `
		INSERT INTO audit_records (
			id,tenant_id,workspace_id,actor_type,actor_id,action,resource_type,
			resource_id,request_id,trace_id,payload_hash
		) VALUES (gen_random_uuid(),$1,$2,'SYSTEM','runtime-manual-executor','PAGE_APPLIED',
			'ASSET_SOURCE_RUN',$3,'source-page:'||$3||':'||$4,'rollover-trace',$5)
	`, fixture.tenantID, fixture.workspaceID, run.id, run.pageSequence+1, pageDigest); err != nil {
		t.Fatalf("insert successor page receipt: %v", err)
	}
	if _, err := tx.Exec(context.Background(), `
		INSERT INTO audit_records (
			id,tenant_id,workspace_id,actor_type,actor_id,action,resource_type,
			resource_id,request_id,trace_id,payload_hash
		) VALUES (gen_random_uuid(),$1,$2,'SYSTEM','runtime-manual-executor',
			'RELATION_PAGE_COMMITTED','ASSET_SOURCE_RUN',$3,
			'source-relation-page:'||$3||':'||$4,'rollover-relation-trace',$5)
	`, fixture.tenantID, fixture.workspaceID, run.id, run.pageSequence+1, relationDigest); err != nil {
		t.Fatalf("insert successor relation page receipt: %v", err)
	}
	if _, err := tx.Exec(context.Background(), `
		UPDATE asset_sources SET checkpoint_version=checkpoint_version+1,version=version+1 WHERE id=$1
	`, fixture.sourceID); err != nil {
		t.Fatalf("advance successor checkpoint: %v", err)
	}
	if _, err := tx.Exec(context.Background(), `
		UPDATE asset_source_runs
		SET page_sequence=page_sequence+1,page_digest=$2,
			relation_page_sequence=relation_page_sequence+1,relation_page_digest=$3,
			checkpoint_version=checkpoint_version+1,observed_count=observed_count+1,
			heartbeat_sequence=heartbeat_sequence+1,heartbeat_at=statement_timestamp(),
			lease_expires_at=lease_expires_at+interval '1 minute',stage_code='READING',
			version=version+1
		WHERE id=$1
	`, run.id, pageDigest, relationDigest); err != nil {
		t.Fatalf("commit successor run page: %v", err)
	}
	if err := tx.Commit(context.Background()); err != nil {
		t.Fatalf("commit successor page: %v", err)
	}
}

func expectAdversarialCommitError(
	t *testing.T,
	database *pgxpool.Pool,
	state string,
	constraint string,
	mutate func(pgx.Tx) error,
) {
	t.Helper()
	tx, err := database.BeginTx(context.Background(), pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		t.Fatalf("begin adversarial transaction: %v", err)
	}
	mutationErr := mutate(tx)
	if mutationErr == nil {
		mutationErr = tx.Commit(context.Background())
	} else {
		_ = tx.Rollback(context.Background())
	}
	if mutationErr == nil {
		t.Fatalf("transaction committed; want SQLSTATE %s constraint %s", state, constraint)
	}
	var databaseError *pgconn.PgError
	if !errors.As(mutationErr, &databaseError) {
		t.Fatalf("transaction error=%v, want PostgreSQL %s/%s", mutationErr, state, constraint)
	}
	if databaseError.Code != state || databaseError.ConstraintName != constraint {
		t.Fatalf("transaction error=%s/%s (%v), want %s/%s",
			databaseError.Code, databaseError.ConstraintName, mutationErr, state, constraint)
	}
}
