package postgres

import (
	"context"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/seaworld008/aiops-system/internal/assetcatalog"
	"github.com/seaworld008/aiops-system/internal/discoveryqueue"
	"github.com/seaworld008/aiops-system/internal/discoverysource"
	"github.com/seaworld008/aiops-system/internal/leasefence"
)

const serializableAttempts = 3

type Repository struct {
	pool             *pgxpool.Pool
	cleanupVerifier  discoveryqueue.CleanupProofVerifier
	rolloverVerifier discoveryqueue.CheckpointLineageRolloverVerifier
	random           io.Reader
	newID            func() string
}

func New(
	pool *pgxpool.Pool,
	cleanupVerifier discoveryqueue.CleanupProofVerifier,
	rolloverVerifier discoveryqueue.CheckpointLineageRolloverVerifier,
) (*Repository, error) {
	return newRepository(pool, cleanupVerifier, rolloverVerifier, cryptorand.Reader, uuid.NewString)
}

func newRepository(
	pool *pgxpool.Pool,
	cleanupVerifier discoveryqueue.CleanupProofVerifier,
	rolloverVerifier discoveryqueue.CheckpointLineageRolloverVerifier,
	random io.Reader,
	newID func() string,
) (*Repository, error) {
	if pool == nil || cleanupVerifier == nil || rolloverVerifier == nil || random == nil || newID == nil {
		return nil, discoveryqueue.ErrInvalidRequest
	}
	return &Repository{
		pool: pool, cleanupVerifier: cleanupVerifier, rolloverVerifier: rolloverVerifier,
		random: random, newID: newID,
	}, nil
}

const eligibleRunPredicate = `
source.status = 'ACTIVE'
AND source.source_kind <> 'MANUAL'
AND (
    (
        run.run_kind = 'VALIDATION'
        AND revision.state = 'VALIDATING'
        AND revision.validation_run_id = run.id
        AND run.checkpoint_version = 0
        AND run.cursor_before_sha256 IS NULL
        AND run.cursor_after_sha256 IS NULL
        AND (
            (source.gate_status = 'UNAVAILABLE' AND source.gate_revision = run.gate_revision)
            OR (
                source.gate_status = 'VALIDATING'
                AND source.validated_run_id = run.id
                AND source.validation_digest IS NULL
                AND source.validated_binding_digest IS NULL
                AND source.gate_revision = run.gate_revision + 1
            )
        )
    )
    OR (
        run.run_kind <> 'VALIDATION'
        AND revision.state = 'PUBLISHED'
        AND source.published_revision = run.source_revision
        AND source.published_revision_digest = run.source_revision_digest
        AND source.checkpoint_revision = run.source_revision
        AND source.checkpoint_version = run.checkpoint_version
        AND source.checkpoint_sha256 IS NOT DISTINCT FROM COALESCE(run.cursor_after_sha256, run.cursor_before_sha256)
        AND (
            (run.lineage_rollover_reason IS NULL
             AND source.gate_status = 'AVAILABLE'
             AND source.gate_revision = run.gate_revision)
            OR
            (run.lineage_rollover_reason IS NOT NULL
             AND source.gate_status = 'DEGRADED'
             AND source.gate_reason_code = 'CHECKPOINT_LINEAGE_ROLLOVER'
             AND source.gate_revision = run.gate_revision + 1)
        )
        AND (
            (source.source_kind = 'CSV_IMPORT' AND run.run_kind = 'CSV_IMPORT')
            OR (source.source_kind = 'CONTROL_PLANE_API' AND run.run_kind = 'API_INGESTION')
            OR (source.source_kind IN (
                'EXTERNAL_CMDB','VSPHERE','PROXMOX','OPENSTACK','CLOUD_PROVIDER',
                'KUBERNETES_OPERATOR','AWX_INVENTORY'
            ) AND run.run_kind = 'DISCOVERY')
        )
    )
)
AND (source.next_allowed_at IS NULL OR source.next_allowed_at <= clock_timestamp())
`

const claimCandidateSQL = `
SELECT run.id::text
FROM asset_source_runs AS run
JOIN asset_sources AS source
  ON source.tenant_id=run.tenant_id
 AND source.workspace_id=run.workspace_id
 AND source.id=run.source_id
JOIN asset_source_revisions AS revision
  ON revision.tenant_id=run.tenant_id
 AND revision.workspace_id=run.workspace_id
 AND revision.source_id=run.source_id
 AND revision.revision=run.source_revision
 AND revision.canonical_revision_digest=run.source_revision_digest
WHERE run.status IN ('QUEUED','DELAYED')
  AND run.not_before <= clock_timestamp()
  AND source.provider_kind = ANY($1::text[])
  AND (` + eligibleRunPredicate + `)
  AND (
      (run.status='QUEUED' AND run.cleanup_status='NOT_OPENED')
      OR (
          run.status='DELAYED' AND run.cleanup_status='REVOKED'
          AND run.pending_transition IS NULL
          AND EXISTS (
              SELECT 1 FROM audit_records AS audit
              WHERE audit.tenant_id=run.tenant_id
                AND audit.workspace_id=run.workspace_id
                AND audit.action='ATTEMPT_CLEANED'
                AND audit.resource_type='ASSET_SOURCE_RUN'
                AND audit.resource_id=run.id::text
                AND audit.request_id='source-attempt:'||run.id::text||':'||run.cleanup_attempt_epoch::text
                AND audit.payload_hash=run.cleanup_digest
          )
      )
  )
ORDER BY run.not_before,run.created_at,run.id
FOR UPDATE OF run SKIP LOCKED
LIMIT 1
`

const claimRunSQL = `
UPDATE asset_source_runs
SET status='RUNNING',
    stage_code=CASE WHEN run_kind='VALIDATION' THEN 'VALIDATING' ELSE 'READING' END,
    lease_owner=$2,
    lease_expires_at=clock_timestamp()+($3::bigint*interval '1 microsecond'),
    fence_epoch=fence_epoch+1,
    fence_token_hash=$4,
    heartbeat_sequence=heartbeat_sequence+1,
    cleanup_attempt_id=NULL,
    cleanup_attempt_epoch=0,
    cleanup_status='NOT_OPENED',
    cleanup_digest=NULL,
    version=version+1
WHERE id=$1::uuid
`

func (repository *Repository) Claim(
	ctx context.Context,
	command discoveryqueue.ClaimCommand,
) (discoveryqueue.ClaimResult, error) {
	if err := command.Validate(); err != nil {
		return discoveryqueue.ClaimResult{}, err
	}
	if err := ctx.Err(); err != nil {
		return discoveryqueue.ClaimResult{}, err
	}
	var raw [32]byte
	if _, err := io.ReadFull(repository.random, raw[:]); err != nil {
		return discoveryqueue.ClaimResult{}, discoveryqueue.ErrUnavailable
	}
	tokenDigest := sha256.Sum256(raw[:])
	tokenHash := hex.EncodeToString(tokenDigest[:])

	state, err := withSerializable(ctx, repository.pool, func(tx pgx.Tx) (lockedState, error) {
		var runID string
		if err := tx.QueryRow(ctx, claimCandidateSQL, command.ProviderKinds).Scan(&runID); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return lockedState{}, discoveryqueue.ErrNoWork
			}
			return lockedState{}, err
		}
		if _, err := tx.Exec(
			ctx, claimRunSQL, runID, command.Owner, command.LeaseDuration.Microseconds(), tokenHash,
		); err != nil {
			return lockedState{}, err
		}
		return lockState(ctx, tx, discoveryqueue.RunCoordinates{RunID: runID}, true)
	})
	if err != nil {
		clear(raw[:])
		return discoveryqueue.ClaimResult{}, mapError(err)
	}
	result, err := makeClaimResult(state, &raw)
	clear(raw[:])
	if err != nil {
		return discoveryqueue.ClaimResult{}, err
	}
	return result, nil
}

type runRow struct {
	id, tenantID, workspaceID, sourceID, revisionDigest string
	sourceRevision                                      int64
	kind                                                assetcatalog.RunKind
	status                                              assetcatalog.RunStatus
	stage                                               assetcatalog.RunStage
	stageChangedAt                                      time.Time
	gateRevision, pageSequence                          int64
	pageDigest                                          *string
	relationPageSequence                                int64
	relationPageDigest                                  *string
	cursorBefore, cursorAfter                           *string
	checkpointVersion                                   int64
	notBefore                                           time.Time
	leaseOwner                                          *string
	leaseExpiresAt                                      *time.Time
	fenceEpoch                                          int64
	fenceTokenHash                                      *string
	heartbeatSequence                                   int64
	pendingReason, pendingDigest                        *string
	pendingNotBefore                                    *time.Time
	observed, created, changed, unchanged               int64
	conflicts, missing, stale, restored                 int64
	tombstoned, rejected                                int64
	finalPage, completeSnapshot, effectiveComplete      bool
	workKind                                            *assetcatalog.WorkResultKind
	workStatus                                          *assetcatalog.WorkResultStatus
	workDigest                                          *string
	workRecordedAt                                      *time.Time
	validationOutcome                                   *assetcatalog.ValidationOutcome
	validationDigest, validationProofDigest             *string
	lineageReason, lineageEvidence                      *string
	cleanupAttemptID                                    *string
	cleanupAttemptEpoch                                 int64
	cleanupStatus                                       assetcatalog.CredentialCleanupStatus
	cleanupDigest                                       *string
	terminalOverride, terminalOverrideDigest            *string
	terminalDigest, failureCode, traceID                *string
	startedAt, heartbeatAt, completedAt                 *time.Time
	version                                             int64
	createdAt                                           time.Time
	requestHash                                         string
}

type sourceRow struct {
	id, tenantID, workspaceID, providerKind string
	kind                                    assetcatalog.SourceKind
	status                                  assetcatalog.SourceStatus
	publishedRevision                       *int64
	publishedDigest                         *string
	gateStatus                              assetcatalog.SourceGateStatus
	gateReason                              *string
	gateRevision                            int64
	validatedRunID, validationDigest        *string
	validatedBindingDigest                  *string
	checkpointSHA                           *string
	checkpointVersion, checkpointRevision   int64
	nextAllowedAt                           *time.Time
	version                                 int64
}

type revisionRow struct {
	status                            assetcatalog.SourceRevisionStatus
	canonicalDigest, definitionDigest string
	profileCode                       assetcatalog.ProfileCode
	maxPageItems, maxPageRelations    int64
	maxPageBytes, maxDocumentBytes    int64
	backpressureBase, backpressureMax int64
	validationRunID, validationDigest *string
	version                           int64
}

type lockedState struct {
	run      runRow
	source   sourceRow
	revision revisionRow
}

const lockRunSQL = `
SELECT id::text,tenant_id::text,workspace_id::text,source_id::text,
       source_revision,source_revision_digest,run_kind,status,stage_code,stage_changed_at,
       gate_revision,page_sequence,page_digest,relation_page_sequence,relation_page_digest,
       cursor_before_sha256,cursor_after_sha256,checkpoint_version,not_before,
       lease_owner,lease_expires_at,fence_epoch,fence_token_hash,heartbeat_sequence,
       pending_transition_reason,pending_transition_digest,pending_transition_not_before,
       observed_count,created_count,changed_count,unchanged_count,conflict_count,
       missing_count,stale_count,restored_count,tombstoned_count,rejected_count,
       final_page,complete_snapshot,effective_complete_snapshot,
       work_result_kind,work_result_status,work_result_digest,work_result_recorded_at,
       validation_outcome,validation_digest,validation_proof_digest,
       lineage_rollover_reason,lineage_rollover_evidence_digest,
       cleanup_attempt_id::text,cleanup_attempt_epoch,cleanup_status,cleanup_digest,
       terminal_failure_override,terminal_failure_override_digest,
       terminal_command_sha256,failure_code,trace_id,started_at,heartbeat_at,completed_at,
       version,created_at,request_hash
FROM asset_source_runs
WHERE id=$1::uuid
  AND ($2::uuid IS NULL OR tenant_id=$2::uuid)
  AND ($3::uuid IS NULL OR workspace_id=$3::uuid)
FOR UPDATE
`

func lockRun(ctx context.Context, tx pgx.Tx, coordinates discoveryqueue.RunCoordinates) (runRow, error) {
	var row runRow
	var tenant, workspace any
	if coordinates.Scope.Valid() {
		tenant, workspace = coordinates.Scope.TenantID, coordinates.Scope.WorkspaceID
	}
	err := tx.QueryRow(ctx, lockRunSQL, coordinates.RunID, tenant, workspace).Scan(
		&row.id, &row.tenantID, &row.workspaceID, &row.sourceID,
		&row.sourceRevision, &row.revisionDigest, &row.kind, &row.status, &row.stage, &row.stageChangedAt,
		&row.gateRevision, &row.pageSequence, &row.pageDigest, &row.relationPageSequence, &row.relationPageDigest,
		&row.cursorBefore, &row.cursorAfter, &row.checkpointVersion, &row.notBefore,
		&row.leaseOwner, &row.leaseExpiresAt, &row.fenceEpoch, &row.fenceTokenHash, &row.heartbeatSequence,
		&row.pendingReason, &row.pendingDigest, &row.pendingNotBefore,
		&row.observed, &row.created, &row.changed, &row.unchanged, &row.conflicts,
		&row.missing, &row.stale, &row.restored, &row.tombstoned, &row.rejected,
		&row.finalPage, &row.completeSnapshot, &row.effectiveComplete,
		&row.workKind, &row.workStatus, &row.workDigest, &row.workRecordedAt,
		&row.validationOutcome, &row.validationDigest, &row.validationProofDigest,
		&row.lineageReason, &row.lineageEvidence,
		&row.cleanupAttemptID, &row.cleanupAttemptEpoch, &row.cleanupStatus, &row.cleanupDigest,
		&row.terminalOverride, &row.terminalOverrideDigest,
		&row.terminalDigest, &row.failureCode, &row.traceID, &row.startedAt, &row.heartbeatAt, &row.completedAt,
		&row.version, &row.createdAt, &row.requestHash,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return runRow{}, discoveryqueue.ErrNotFound
	}
	return row, err
}

const lockValidationSourceSQL = `
SELECT id::text,tenant_id::text,workspace_id::text,provider_kind,source_kind,status,
       published_revision,published_revision_digest,gate_status,gate_reason_code,gate_revision,
       validated_run_id::text,validation_digest,validated_binding_digest,
       next_allowed_at,version
FROM asset_sources
WHERE tenant_id=$1::uuid AND workspace_id=$2::uuid AND id=$3::uuid
FOR UPDATE
`

const lockDataSourceSQL = `
SELECT id::text,tenant_id::text,workspace_id::text,provider_kind,source_kind,status,
       published_revision,published_revision_digest,gate_status,gate_reason_code,gate_revision,
       validated_run_id::text,validation_digest,validated_binding_digest,
       checkpoint_sha256,checkpoint_version,checkpoint_revision,next_allowed_at,version
FROM asset_sources
WHERE tenant_id=$1::uuid AND workspace_id=$2::uuid AND id=$3::uuid
FOR UPDATE
`

func lockSource(ctx context.Context, tx pgx.Tx, run runRow) (sourceRow, error) {
	var source sourceRow
	if run.kind == assetcatalog.RunKindValidation {
		err := tx.QueryRow(ctx, lockValidationSourceSQL, run.tenantID, run.workspaceID, run.sourceID).Scan(
			&source.id, &source.tenantID, &source.workspaceID, &source.providerKind, &source.kind, &source.status,
			&source.publishedRevision, &source.publishedDigest, &source.gateStatus, &source.gateReason,
			&source.gateRevision, &source.validatedRunID, &source.validationDigest,
			&source.validatedBindingDigest, &source.nextAllowedAt, &source.version,
		)
		return source, err
	}
	err := tx.QueryRow(ctx, lockDataSourceSQL, run.tenantID, run.workspaceID, run.sourceID).Scan(
		&source.id, &source.tenantID, &source.workspaceID, &source.providerKind, &source.kind, &source.status,
		&source.publishedRevision, &source.publishedDigest, &source.gateStatus, &source.gateReason,
		&source.gateRevision, &source.validatedRunID, &source.validationDigest,
		&source.validatedBindingDigest, &source.checkpointSHA, &source.checkpointVersion,
		&source.checkpointRevision, &source.nextAllowedAt, &source.version,
	)
	return source, err
}

const lockRevisionSQL = `
SELECT state,canonical_revision_digest,source_definition_digest,profile_code,
       rate_limit_requests,rate_limit_window_seconds,
       backpressure_base_seconds,backpressure_max_seconds,
       validation_run_id::text,validation_digest,version,
	   (convert_from(canonical_profile_manifest,'UTF8')::jsonb->>'max_page_items')::bigint,
	   (convert_from(canonical_profile_manifest,'UTF8')::jsonb->>'max_page_relations')::bigint,
	   (convert_from(canonical_profile_manifest,'UTF8')::jsonb->>'max_page_bytes')::bigint,
	   (convert_from(canonical_profile_manifest,'UTF8')::jsonb->>'max_document_bytes')::bigint
FROM asset_source_revisions
WHERE tenant_id=$1::uuid AND workspace_id=$2::uuid AND source_id=$3::uuid
  AND revision=$4 AND canonical_revision_digest=$5
FOR UPDATE
`

func lockRevision(ctx context.Context, tx pgx.Tx, run runRow) (revisionRow, error) {
	var revision revisionRow
	var ignoredRateRequests, ignoredRateWindow int64
	err := tx.QueryRow(
		ctx, lockRevisionSQL, run.tenantID, run.workspaceID, run.sourceID,
		run.sourceRevision, run.revisionDigest,
	).Scan(
		&revision.status, &revision.canonicalDigest, &revision.definitionDigest, &revision.profileCode,
		&ignoredRateRequests, &ignoredRateWindow, &revision.backpressureBase, &revision.backpressureMax,
		&revision.validationRunID, &revision.validationDigest, &revision.version,
		&revision.maxPageItems, &revision.maxPageRelations, &revision.maxPageBytes, &revision.maxDocumentBytes,
	)
	return revision, err
}

func lockState(
	ctx context.Context,
	tx pgx.Tx,
	coordinates discoveryqueue.RunCoordinates,
	runAlreadyLocked bool,
) (lockedState, error) {
	_ = runAlreadyLocked
	run, err := lockRun(ctx, tx, coordinates)
	if err != nil {
		return lockedState{}, err
	}
	source, err := lockSource(ctx, tx, run)
	if err != nil {
		return lockedState{}, err
	}
	revision, err := lockRevision(ctx, tx, run)
	if err != nil {
		return lockedState{}, err
	}
	return lockedState{run: run, source: source, revision: revision}, nil
}

func makeClaimResult(state lockedState, raw *[32]byte) (discoveryqueue.ClaimResult, error) {
	if state.run.leaseOwner == nil || raw == nil {
		return discoveryqueue.ClaimResult{}, discoveryqueue.ErrStateConflict
	}
	fence, err := leasefence.FromQueueClaim(
		state.run.id, *state.run.leaseOwner, state.run.fenceEpoch, raw,
	)
	if err != nil {
		return discoveryqueue.ClaimResult{}, discoveryqueue.ErrStateConflict
	}
	result := discoveryqueue.ClaimResult{
		Run: safeRun(state.run), ProviderKind: state.source.providerKind,
		ProfileCode: state.revision.profileCode, Mode: claimMode(state.run), Fence: fence,
	}
	if state.run.cleanupAttemptID != nil {
		attempt := discoveryqueue.CleanupAttempt{
			RunID: state.run.id, AttemptID: *state.run.cleanupAttemptID,
			AttemptEpoch: state.run.cleanupAttemptEpoch,
		}
		result.CleanupAttempt = &attempt
	}
	if state.run.pendingReason != nil && state.run.pendingNotBefore != nil && state.run.pendingDigest != nil {
		delay := discoveryqueue.PersistedDelay{
			Reason:    discoveryqueue.DelayReason(*state.run.pendingReason),
			NotBefore: *state.run.pendingNotBefore, DigestSHA256: *state.run.pendingDigest,
		}
		result.PersistedDelay = &delay
	}
	return result, nil
}

func safeRun(row runRow) assetcatalog.SourceRun {
	run := assetcatalog.SourceRun{
		ID: row.id, SourceID: row.sourceID,
		Scope:          assetcatalog.SourceScope{TenantID: row.tenantID, WorkspaceID: row.workspaceID},
		SourceRevision: row.sourceRevision, SourceRevisionDigest: row.revisionDigest,
		Kind: row.kind, Status: row.status, Stage: row.stage, StageChangedAt: row.stageChangedAt,
		GateRevision: row.gateRevision, PageSequence: row.pageSequence,
		RelationPageSequence: row.relationPageSequence, CheckpointVersion: row.checkpointVersion,
		NotBefore: row.notBefore, FenceEpoch: row.fenceEpoch, HeartbeatSequence: row.heartbeatSequence,
		FinalPage: row.finalPage, CompleteSnapshot: row.completeSnapshot,
		EffectiveCompleteSnapshot: row.effectiveComplete,
		CredentialCleanupStatus:   row.cleanupStatus,
		Observed:                  row.observed, Created: row.created, Changed: row.changed, Unchanged: row.unchanged,
		Conflicts: row.conflicts, Missing: row.missing, Stale: row.stale, Restored: row.restored,
		Tombstoned: row.tombstoned, Rejected: row.rejected,
		Version: row.version, CreatedAt: row.createdAt,
	}
	run.PageDigest = stringValue(row.pageDigest)
	run.RelationPageDigest = stringValue(row.relationPageDigest)
	run.CursorBeforeSHA256 = stringValue(row.cursorBefore)
	run.CursorAfterSHA256 = stringValue(row.cursorAfter)
	run.LeaseExpiresAt = cloneTime(row.leaseExpiresAt)
	if row.workKind != nil {
		run.WorkResultKind = *row.workKind
	}
	if row.workStatus != nil {
		run.WorkResultStatus = *row.workStatus
	}
	run.WorkResultDigest = stringValue(row.workDigest)
	run.WorkResultRecordedAt = cloneTime(row.workRecordedAt)
	if row.validationOutcome != nil {
		run.ValidationOutcome = *row.validationOutcome
	}
	run.ValidationProofDigest = stringValue(row.validationProofDigest)
	run.FailureCode = stringValue(row.failureCode)
	run.TraceID = stringValue(row.traceID)
	run.StartedAt = cloneTime(row.startedAt)
	run.HeartbeatAt = cloneTime(row.heartbeatAt)
	run.CompletedAt = cloneTime(row.completedAt)
	return run
}

func claimMode(row runRow) discoveryqueue.ClaimMode {
	if row.status == assetcatalog.RunStatusSucceeded || row.status == assetcatalog.RunStatusPartial ||
		row.status == assetcatalog.RunStatusFailed || row.status == assetcatalog.RunStatusCancelled {
		return discoveryqueue.ClaimModeTerminal
	}
	if row.stage == assetcatalog.RunStageCleaningUp || row.cleanupStatus != assetcatalog.CredentialCleanupNotOpened {
		if row.status == assetcatalog.RunStatusFinalizing &&
			((row.cleanupStatus == assetcatalog.CredentialCleanupNotOpened &&
				row.workKind != nil && *row.workKind == assetcatalog.WorkResultFailureIntent) ||
				row.cleanupStatus == assetcatalog.CredentialCleanupRevoked ||
				row.cleanupStatus == assetcatalog.CredentialCleanupUncertain) {
			return discoveryqueue.ClaimModeTerminal
		}
		return discoveryqueue.ClaimModeCleanupOnly
	}
	return discoveryqueue.ClaimModeProvider
}

func stringValue(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func cloneTime(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func databaseNow(ctx context.Context, tx pgx.Tx) (time.Time, error) {
	var now time.Time
	if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return time.Time{}, err
	}
	return now, nil
}

func requireFence(
	run runRow,
	fence assetcatalog.LeaseFence,
	now time.Time,
	requireLive bool,
) error {
	if run.leaseOwner == nil || run.fenceTokenHash == nil || run.leaseExpiresAt == nil ||
		!fence.Matches(run.id, *run.leaseOwner, run.fenceEpoch, *run.fenceTokenHash) {
		return discoveryqueue.ErrStaleFence
	}
	if requireLive && !run.leaseExpiresAt.After(now) {
		return discoveryqueue.ErrStaleFence
	}
	return nil
}

func runAdmitted(state lockedState) bool {
	run, source, revision := state.run, state.source, state.revision
	if source.status != assetcatalog.SourceStatusActive || source.kind == assetcatalog.SourceKindManual {
		return false
	}
	if run.kind == assetcatalog.RunKindValidation {
		if revision.status != assetcatalog.SourceRevisionValidating || revision.validationRunID == nil ||
			*revision.validationRunID != run.id || run.checkpointVersion != 0 ||
			run.cursorBefore != nil || run.cursorAfter != nil {
			return false
		}
		return (source.gateStatus == assetcatalog.SourceGateUnavailable && source.gateRevision == run.gateRevision) ||
			(source.gateStatus == assetcatalog.SourceGateValidating && source.validatedRunID != nil &&
				*source.validatedRunID == run.id && source.validationDigest == nil &&
				source.validatedBindingDigest == nil && source.gateRevision == run.gateRevision+1)
	}
	if revision.status != assetcatalog.SourceRevisionPublished || source.publishedRevision == nil ||
		source.publishedDigest == nil || *source.publishedRevision != run.sourceRevision ||
		*source.publishedDigest != run.revisionDigest || source.checkpointRevision != run.sourceRevision ||
		source.checkpointVersion != run.checkpointVersion ||
		!nullableStringEqual(source.checkpointSHA, firstNonNil(run.cursorAfter, run.cursorBefore)) ||
		!runKindMatchesSource(run.kind, source.kind) {
		return false
	}
	if run.lineageReason == nil {
		return source.gateStatus == assetcatalog.SourceGateAvailable && source.gateRevision == run.gateRevision
	}
	return source.gateStatus == assetcatalog.SourceGateDegraded && source.gateReason != nil &&
		*source.gateReason == "CHECKPOINT_LINEAGE_ROLLOVER" && source.gateRevision == run.gateRevision+1
}

func runKindMatchesSource(kind assetcatalog.RunKind, source assetcatalog.SourceKind) bool {
	switch source {
	case assetcatalog.SourceKindCSVImport:
		return kind == assetcatalog.RunKindCSVImport
	case assetcatalog.SourceKindControlPlaneAPI:
		return kind == assetcatalog.RunKindAPIIngestion
	case assetcatalog.SourceKindExternalCMDB, assetcatalog.SourceKindVSphere,
		assetcatalog.SourceKindProxmox, assetcatalog.SourceKindOpenStack,
		assetcatalog.SourceKindCloudProvider, assetcatalog.SourceKindKubernetesOperator,
		assetcatalog.SourceKindAWXInventory:
		return kind == assetcatalog.RunKindDiscovery
	default:
		return false
	}
}

func firstNonNil(values ...*string) *string {
	for _, value := range values {
		if value != nil {
			return value
		}
	}
	return nil
}

func nullableStringEqual(left, right *string) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

func framedSHA256(values ...[]byte) string {
	hasher := sha256.New()
	for _, value := range values {
		if value == nil {
			_, _ = hasher.Write([]byte{0})
			continue
		}
		_, _ = hasher.Write([]byte{1})
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len(value)))
		_, _ = hasher.Write(length[:])
		_, _ = hasher.Write(value)
	}
	return hex.EncodeToString(hasher.Sum(nil))
}

func decodeDigest(value string) ([]byte, error) {
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != sha256.Size || hex.EncodeToString(decoded) != value {
		clear(decoded)
		return nil, discoveryqueue.ErrInvalidRequest
	}
	return decoded, nil
}

func delayIntentDigest(run runRow, intent discoveryqueue.DelayIntent) (string, error) {
	if intent.Validate() != nil || run.cleanupAttemptEpoch < 0 {
		return "", discoveryqueue.ErrInvalidRequest
	}
	var attemptID []byte
	if run.cleanupAttemptID != nil {
		attemptID = []byte(*run.cleanupAttemptID)
	}
	return framedSHA256(
		[]byte("asset-run-delay-intent.v1"),
		[]byte(run.id),
		attemptID,
		[]byte(strconv.FormatInt(run.cleanupAttemptEpoch, 10)),
		[]byte(intent.Reason),
		[]byte(intent.NotBefore.UTC().Format("2006-01-02T15:04:05.000000Z")),
	), nil
}

func withSerializable[T any](
	ctx context.Context,
	pool *pgxpool.Pool,
	operation func(pgx.Tx) (T, error),
) (T, error) {
	var zero T
	for attempt := 0; attempt < serializableAttempts; attempt++ {
		tx, err := pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
		if err != nil {
			return zero, err
		}
		result, operationErr := operation(tx)
		if operationErr != nil {
			_ = tx.Rollback(ctx)
			if retryable(operationErr) && attempt+1 < serializableAttempts {
				if err := waitRetry(ctx, attempt); err != nil {
					return zero, err
				}
				continue
			}
			return zero, operationErr
		}
		if err := tx.Commit(ctx); err != nil {
			if retryable(err) && attempt+1 < serializableAttempts {
				if err := waitRetry(ctx, attempt); err != nil {
					return zero, err
				}
				continue
			}
			return zero, err
		}
		return result, nil
	}
	return zero, discoveryqueue.ErrStateConflict
}

func waitRetry(ctx context.Context, attempt int) error {
	timer := time.NewTimer(time.Duration(attempt+1) * time.Millisecond)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func retryable(err error) bool {
	var databaseError *pgconn.PgError
	return errors.As(err, &databaseError) &&
		(databaseError.Code == "40001" || databaseError.Code == "40P01")
}

func mapError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	for _, stable := range []error{
		discoveryqueue.ErrInvalidRequest, discoveryqueue.ErrNoWork, discoveryqueue.ErrNotFound,
		discoveryqueue.ErrStaleFence, discoveryqueue.ErrIneligible,
		discoveryqueue.ErrStateConflict, discoveryqueue.ErrIdempotency,
		discoveryqueue.ErrUnavailable, discoveryqueue.ErrCleanupProof,
	} {
		if errors.Is(err, stable) {
			return stable
		}
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return discoveryqueue.ErrNotFound
	}
	var databaseError *pgconn.PgError
	if !errors.As(err, &databaseError) {
		return discoveryqueue.ErrUnavailable
	}
	switch databaseError.Code {
	case "23505":
		return discoveryqueue.ErrIdempotency
	case "23514", "22P02", "22001", "22023":
		return discoveryqueue.ErrInvalidRequest
	case "40001", "40P01", "55000":
		return discoveryqueue.ErrStateConflict
	default:
		return discoveryqueue.ErrUnavailable
	}
}

const reclaimCandidateSQL = `
SELECT run.id::text,
       clock_timestamp()+
           (revision.backpressure_base_seconds::bigint*interval '1 second') AS delay_at
FROM asset_source_runs AS run
JOIN asset_sources AS source
  ON source.tenant_id=run.tenant_id
 AND source.workspace_id=run.workspace_id
 AND source.id=run.source_id
JOIN asset_source_revisions AS revision
  ON revision.tenant_id=run.tenant_id
 AND revision.workspace_id=run.workspace_id
 AND revision.source_id=run.source_id
 AND revision.revision=run.source_revision
 AND revision.canonical_revision_digest=run.source_revision_digest
WHERE run.status='RUNNING'
  AND run.lease_expires_at <= clock_timestamp()
  AND source.provider_kind = ANY($1::text[])
  AND (` + eligibleRunPredicate + `)
  AND (
      run.cleanup_status IN ('NOT_OPENED','PENDING')
      OR (
          run.cleanup_status IN ('REVOKED','UNCERTAIN')
          AND EXISTS (
              SELECT 1 FROM audit_records AS audit
              WHERE audit.tenant_id=run.tenant_id
                AND audit.workspace_id=run.workspace_id
                AND audit.action='ATTEMPT_CLEANED'
                AND audit.resource_type='ASSET_SOURCE_RUN'
                AND audit.resource_id=run.id::text
                AND audit.request_id='source-attempt:'||run.id::text||':'||run.cleanup_attempt_epoch::text
                AND audit.payload_hash=run.cleanup_digest
          )
      )
  )
ORDER BY run.lease_expires_at,run.created_at,run.id
FOR UPDATE OF run SKIP LOCKED
LIMIT 1
`

const reclaimRunSQL = `
UPDATE asset_source_runs AS run
SET stage_code=CASE
        WHEN run.cleanup_status='NOT_OPENED' THEN run.stage_code
        ELSE 'CLEANING_UP'
    END,
    lease_owner=$2,
    lease_expires_at=clock_timestamp()+($3::bigint*interval '1 microsecond'),
    fence_epoch=run.fence_epoch+1,
    fence_token_hash=$4,
    heartbeat_sequence=run.heartbeat_sequence+1,
    pending_transition=CASE
        WHEN run.cleanup_status='PENDING' AND run.pending_transition IS NULL THEN 'DELAY'
        ELSE run.pending_transition
    END,
    pending_transition_reason=CASE
        WHEN run.cleanup_status='PENDING' AND run.pending_transition IS NULL THEN 'TRANSPORT_BACKOFF'
        ELSE run.pending_transition_reason
    END,
    pending_transition_not_before=CASE
        WHEN run.cleanup_status='PENDING' AND run.pending_transition IS NULL THEN $5::timestamptz
        ELSE run.pending_transition_not_before
    END,
    pending_transition_digest=CASE
        WHEN run.cleanup_status='PENDING' AND run.pending_transition IS NULL
        THEN asset_catalog_source_run_delay_intent_digest(run,'TRANSPORT_BACKOFF',$5::timestamptz)
        ELSE run.pending_transition_digest
    END,
    version=run.version+1
WHERE run.id=$1::uuid
`

// Remaining lifecycle methods are implemented below in state-machine order.
func (repository *Repository) Reclaim(
	ctx context.Context,
	command discoveryqueue.ReclaimCommand,
) (discoveryqueue.ClaimResult, error) {
	if err := command.Validate(); err != nil {
		return discoveryqueue.ClaimResult{}, err
	}
	if err := ctx.Err(); err != nil {
		return discoveryqueue.ClaimResult{}, err
	}
	var raw [32]byte
	if _, err := io.ReadFull(repository.random, raw[:]); err != nil {
		return discoveryqueue.ClaimResult{}, discoveryqueue.ErrUnavailable
	}
	tokenDigest := sha256.Sum256(raw[:])
	tokenHash := hex.EncodeToString(tokenDigest[:])
	state, err := withSerializable(ctx, repository.pool, func(tx pgx.Tx) (lockedState, error) {
		var runID string
		var delayAt time.Time
		if err := tx.QueryRow(ctx, reclaimCandidateSQL, command.ProviderKinds).Scan(&runID, &delayAt); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return lockedState{}, discoveryqueue.ErrNoWork
			}
			return lockedState{}, err
		}
		if _, err := tx.Exec(
			ctx, reclaimRunSQL, runID, command.Owner, command.LeaseDuration.Microseconds(), tokenHash, delayAt,
		); err != nil {
			return lockedState{}, err
		}
		return lockState(ctx, tx, discoveryqueue.RunCoordinates{RunID: runID}, true)
	})
	if err != nil {
		clear(raw[:])
		return discoveryqueue.ClaimResult{}, mapError(err)
	}
	result, err := makeClaimResult(state, &raw)
	clear(raw[:])
	if err != nil {
		return discoveryqueue.ClaimResult{}, err
	}
	return result, nil
}

const reclaimFinalizingCandidateSQL = `
SELECT run.id::text
FROM asset_source_runs AS run
JOIN asset_sources AS source
  ON source.tenant_id=run.tenant_id
 AND source.workspace_id=run.workspace_id
 AND source.id=run.source_id
WHERE run.status='FINALIZING' AND run.stage_code='CLEANING_UP'
  AND run.lease_expires_at <= clock_timestamp()
  AND source.source_kind <> 'MANUAL'
  AND source.provider_kind=ANY($1::text[])
  AND (
      run.cleanup_status IN ('NOT_OPENED','PENDING')
      OR (
          run.cleanup_status IN ('REVOKED','UNCERTAIN')
          AND EXISTS(
              SELECT 1 FROM audit_records AS audit
              WHERE audit.tenant_id=run.tenant_id AND audit.workspace_id=run.workspace_id
                AND audit.action='ATTEMPT_CLEANED' AND audit.resource_type='ASSET_SOURCE_RUN'
                AND audit.resource_id=run.id::text
                AND audit.request_id='source-attempt:'||run.id::text||':'||run.cleanup_attempt_epoch::text
                AND audit.payload_hash=run.cleanup_digest
          )
      )
  )
ORDER BY run.lease_expires_at,run.created_at,run.id
FOR UPDATE OF run SKIP LOCKED
LIMIT 1
`

func (repository *Repository) ReclaimFinalizing(
	ctx context.Context,
	command discoveryqueue.ReclaimCommand,
) (discoveryqueue.ClaimResult, error) {
	if err := command.Validate(); err != nil {
		return discoveryqueue.ClaimResult{}, err
	}
	var raw [32]byte
	if _, err := io.ReadFull(repository.random, raw[:]); err != nil {
		return discoveryqueue.ClaimResult{}, discoveryqueue.ErrUnavailable
	}
	tokenDigest := sha256.Sum256(raw[:])
	tokenHash := hex.EncodeToString(tokenDigest[:])
	state, err := withSerializable(ctx, repository.pool, func(tx pgx.Tx) (lockedState, error) {
		var runID string
		if err := tx.QueryRow(ctx, reclaimFinalizingCandidateSQL, command.ProviderKinds).Scan(&runID); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return lockedState{}, discoveryqueue.ErrNoWork
			}
			return lockedState{}, err
		}
		if _, err := tx.Exec(ctx, `
UPDATE asset_source_runs
SET lease_owner=$2,lease_expires_at=clock_timestamp()+($3::bigint*interval '1 microsecond'),
    fence_epoch=fence_epoch+1,fence_token_hash=$4,
    heartbeat_sequence=heartbeat_sequence+1,version=version+1
WHERE id=$1::uuid
`, runID, command.Owner, command.LeaseDuration.Microseconds(), tokenHash); err != nil {
			return lockedState{}, err
		}
		return lockState(ctx, tx, discoveryqueue.RunCoordinates{RunID: runID}, true)
	})
	if err != nil {
		clear(raw[:])
		return discoveryqueue.ClaimResult{}, mapError(err)
	}
	result, err := makeClaimResult(state, &raw)
	clear(raw[:])
	if err != nil {
		return discoveryqueue.ClaimResult{}, err
	}
	return result, nil
}

const reapDriftedCandidateSQL = `
SELECT run.id::text
FROM asset_source_runs AS run
JOIN asset_sources AS source
  ON source.tenant_id=run.tenant_id
 AND source.workspace_id=run.workspace_id
 AND source.id=run.source_id
JOIN asset_source_revisions AS revision
  ON revision.tenant_id=run.tenant_id
 AND revision.workspace_id=run.workspace_id
 AND revision.source_id=run.source_id
 AND revision.revision=run.source_revision
 AND revision.canonical_revision_digest=run.source_revision_digest
WHERE run.status='RUNNING'
  AND run.lease_expires_at <= clock_timestamp()
  AND source.source_kind <> 'MANUAL'
  AND source.provider_kind=ANY($1::text[])
  AND (` + eligibleRunPredicate + `) IS NOT TRUE
  AND run.work_result_kind IS NULL
  AND (
      (run.cleanup_status IN ('NOT_OPENED','PENDING') AND run.pending_transition IS NULL)
      OR (
          run.cleanup_status IN ('PENDING','REVOKED')
          AND run.pending_transition='DELAY'
          AND run.pending_transition_reason IS NOT NULL
          AND run.pending_transition_not_before IS NOT NULL
          AND run.pending_transition_digest=
              asset_catalog_source_run_delay_intent_digest(
                  run,run.pending_transition_reason,run.pending_transition_not_before
              )
          AND (
              run.cleanup_status='PENDING'
              OR EXISTS(
                  SELECT 1 FROM audit_records AS audit
                  WHERE audit.tenant_id=run.tenant_id
                    AND audit.workspace_id=run.workspace_id
                    AND audit.action='ATTEMPT_CLEANED'
                    AND audit.resource_type='ASSET_SOURCE_RUN'
                    AND audit.resource_id=run.id::text
                    AND audit.request_id='source-attempt:'||run.id::text||':'||run.cleanup_attempt_epoch::text
                    AND audit.payload_hash=run.cleanup_digest
              )
          )
      )
  )
ORDER BY run.lease_expires_at,run.created_at,run.id
FOR UPDATE OF run SKIP LOCKED
LIMIT 1
`

func driftEvidenceDigest(state lockedState) string {
	var gateReason, publishedDigest, validationDigest []byte
	if state.source.gateReason != nil {
		gateReason = []byte(*state.source.gateReason)
	}
	if state.source.publishedDigest != nil {
		publishedDigest = []byte(*state.source.publishedDigest)
	}
	if state.revision.validationDigest != nil {
		validationDigest = []byte(*state.revision.validationDigest)
	}
	return framedSHA256(
		[]byte("asset-run-admission-drift.v1"), []byte(state.run.id), []byte(state.run.requestHash),
		[]byte(state.source.status), []byte(state.source.gateStatus), gateReason,
		[]byte(strconv.FormatInt(state.source.gateRevision, 10)), publishedDigest,
		[]byte(state.revision.status), validationDigest,
		[]byte(strconv.FormatInt(state.revision.version, 10)),
	)
}

func (repository *Repository) ReapDrifted(
	ctx context.Context,
	command discoveryqueue.ReapCommand,
) (discoveryqueue.ClaimResult, error) {
	if err := command.Validate(); err != nil {
		return discoveryqueue.ClaimResult{}, err
	}
	if err := ctx.Err(); err != nil {
		return discoveryqueue.ClaimResult{}, err
	}
	var raw [32]byte
	if _, err := io.ReadFull(repository.random, raw[:]); err != nil {
		return discoveryqueue.ClaimResult{}, discoveryqueue.ErrUnavailable
	}
	tokenDigest := sha256.Sum256(raw[:])
	tokenHash := hex.EncodeToString(tokenDigest[:])
	state, err := withSerializable(ctx, repository.pool, func(tx pgx.Tx) (lockedState, error) {
		var runID string
		if err := tx.QueryRow(ctx, reapDriftedCandidateSQL, command.ProviderKinds).Scan(&runID); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return lockedState{}, discoveryqueue.ErrNoWork
			}
			return lockedState{}, err
		}
		if _, err := tx.Exec(ctx, `
UPDATE asset_source_runs
SET stage_code='CLEANING_UP',lease_owner=$2,
    lease_expires_at=clock_timestamp()+($3::bigint*interval '1 microsecond'),
    fence_epoch=fence_epoch+1,fence_token_hash=$4,
    heartbeat_sequence=heartbeat_sequence+1,version=version+1
WHERE id=$1::uuid
`, runID, command.Owner, command.LeaseDuration.Microseconds(), tokenHash); err != nil {
			return lockedState{}, err
		}
		current, err := lockState(ctx, tx, discoveryqueue.RunCoordinates{RunID: runID}, true)
		if err != nil {
			return lockedState{}, err
		}
		if runAdmitted(current) || current.run.status != assetcatalog.RunStatusRunning ||
			current.run.stage != assetcatalog.RunStageCleaningUp || current.run.workKind != nil ||
			(current.run.cleanupStatus != assetcatalog.CredentialCleanupNotOpened &&
				current.run.cleanupStatus != assetcatalog.CredentialCleanupPending &&
				current.run.cleanupStatus != assetcatalog.CredentialCleanupRevoked) {
			return lockedState{}, discoveryqueue.ErrStateConflict
		}
		if current.run.pendingDigest != nil {
			if current.run.pendingReason == nil || current.run.pendingNotBefore == nil ||
				(current.run.cleanupStatus != assetcatalog.CredentialCleanupPending &&
					current.run.cleanupStatus != assetcatalog.CredentialCleanupRevoked) {
				return lockedState{}, discoveryqueue.ErrStateConflict
			}
			intent := discoveryqueue.DelayIntent{
				Reason:    discoveryqueue.DelayReason(*current.run.pendingReason),
				NotBefore: *current.run.pendingNotBefore,
			}
			digest, err := delayIntentDigest(current.run, intent)
			if err != nil || digest != *current.run.pendingDigest {
				return lockedState{}, discoveryqueue.ErrStateConflict
			}
			return current, nil
		}
		if current.run.cleanupStatus != assetcatalog.CredentialCleanupNotOpened &&
			current.run.cleanupStatus != assetcatalog.CredentialCleanupPending {
			return lockedState{}, discoveryqueue.ErrStateConflict
		}
		evidenceDigest := driftEvidenceDigest(current)
		workDigest, err := failureIntentDigest(current.run.id, command.FailureCode, evidenceDigest)
		if err != nil {
			return lockedState{}, err
		}
		if _, err := tx.Exec(ctx, `
UPDATE asset_source_runs
SET status='FINALIZING',stage_code='CLEANING_UP',
    work_result_kind='FAILURE_INTENT',work_result_status='FAILED',
    work_result_digest=$4,failure_code=$5,version=version+1
WHERE tenant_id=$1::uuid AND workspace_id=$2::uuid AND id=$3::uuid
`, current.run.tenantID, current.run.workspaceID, current.run.id,
			workDigest, command.FailureCode); err != nil {
			return lockedState{}, err
		}
		return lockState(ctx, tx, discoveryqueue.RunCoordinates{RunID: runID}, true)
	})
	if err != nil {
		clear(raw[:])
		return discoveryqueue.ClaimResult{}, mapError(err)
	}
	result, err := makeClaimResult(state, &raw)
	clear(raw[:])
	if err != nil {
		return discoveryqueue.ClaimResult{}, err
	}
	return result, nil
}

const cancelIneligibleCandidateSQL = `
SELECT run.id::text
FROM asset_source_runs AS run
JOIN asset_sources AS source
  ON source.tenant_id=run.tenant_id
 AND source.workspace_id=run.workspace_id
 AND source.id=run.source_id
JOIN asset_source_revisions AS revision
  ON revision.tenant_id=run.tenant_id
 AND revision.workspace_id=run.workspace_id
 AND revision.source_id=run.source_id
 AND revision.revision=run.source_revision
 AND revision.canonical_revision_digest=run.source_revision_digest
WHERE run.status IN ('QUEUED','DELAYED')
  AND source.source_kind <> 'MANUAL'
  AND source.provider_kind=ANY($1::text[])
  AND (` + eligibleRunPredicate + `) IS NOT TRUE
  AND (
      run.status='QUEUED'
      OR (
          run.cleanup_status IN ('REVOKED','NO_CREDENTIAL')
          AND run.work_result_kind IS NULL
          AND run.pending_transition IS NULL
      )
  )
  AND (
      run.run_kind <> 'VALIDATION'
      OR (
          revision.state='VALIDATING'
          AND revision.validation_run_id=run.id
      )
  )
ORDER BY run.created_at,run.id
FOR UPDATE OF run SKIP LOCKED
LIMIT 1
`

func (repository *Repository) CancelIneligible(
	ctx context.Context,
	command discoveryqueue.CancelCommand,
) (discoveryqueue.CancelResult, error) {
	if err := command.Validate(); err != nil {
		return discoveryqueue.CancelResult{}, err
	}
	result, err := withSerializable(ctx, repository.pool, func(tx pgx.Tx) (discoveryqueue.CancelResult, error) {
		var runID string
		if err := tx.QueryRow(ctx, cancelIneligibleCandidateSQL, command.ProviderKinds).Scan(&runID); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return discoveryqueue.CancelResult{}, discoveryqueue.ErrNoWork
			}
			return discoveryqueue.CancelResult{}, err
		}
		state, err := lockState(ctx, tx, discoveryqueue.RunCoordinates{RunID: runID}, true)
		if err != nil {
			return discoveryqueue.CancelResult{}, err
		}
		if runAdmitted(state) || (state.run.status != assetcatalog.RunStatusQueued &&
			state.run.status != assetcatalog.RunStatusDelayed) {
			return discoveryqueue.CancelResult{}, discoveryqueue.ErrIneligible
		}
		if state.run.status == assetcatalog.RunStatusDelayed &&
			(state.run.cleanupStatus != assetcatalog.CredentialCleanupRevoked || state.run.workKind != nil ||
				state.run.pendingDigest != nil) {
			return discoveryqueue.CancelResult{}, discoveryqueue.ErrStateConflict
		}
		if _, err := tx.Exec(ctx, `
UPDATE asset_source_runs
SET status='CANCELLED',stage_code='COMPLETED',version=version+1
WHERE tenant_id=$1::uuid AND workspace_id=$2::uuid AND id=$3::uuid
`, state.run.tenantID, state.run.workspaceID, state.run.id); err != nil {
			return discoveryqueue.CancelResult{}, err
		}
		if state.run.kind == assetcatalog.RunKindValidation {
			commandTag, err := tx.Exec(ctx, `
UPDATE asset_source_revisions
SET state='REJECTED',validation_digest=$6,version=version+1
WHERE tenant_id=$1::uuid AND workspace_id=$2::uuid AND source_id=$3::uuid
  AND revision=$4 AND canonical_revision_digest=$5
  AND state='VALIDATING' AND validation_run_id=$7::uuid
`, state.run.tenantID, state.run.workspaceID, state.run.sourceID,
				state.run.sourceRevision, state.run.revisionDigest, state.run.requestHash, state.run.id)
			if err != nil {
				return discoveryqueue.CancelResult{}, err
			}
			if commandTag.RowsAffected() != 1 {
				return discoveryqueue.CancelResult{}, discoveryqueue.ErrStateConflict
			}
		}
		updated, err := lockRun(ctx, tx, discoveryqueue.RunCoordinates{RunID: state.run.id})
		if err != nil {
			return discoveryqueue.CancelResult{}, err
		}
		return discoveryqueue.CancelResult{Run: safeRun(updated)}, nil
	})
	if err != nil {
		return discoveryqueue.CancelResult{}, mapError(err)
	}
	return result, nil
}
func (repository *Repository) Heartbeat(
	ctx context.Context,
	fence assetcatalog.LeaseFence,
	command discoveryqueue.HeartbeatCommand,
) (discoveryqueue.HeartbeatResult, error) {
	if err := command.Validate(); err != nil {
		return discoveryqueue.HeartbeatResult{}, err
	}
	result, err := withSerializable(ctx, repository.pool, func(tx pgx.Tx) (discoveryqueue.HeartbeatResult, error) {
		state, err := lockState(ctx, tx, command.Coordinates, false)
		if err != nil {
			return discoveryqueue.HeartbeatResult{}, err
		}
		now, err := databaseNow(ctx, tx)
		if err != nil {
			return discoveryqueue.HeartbeatResult{}, err
		}
		if err := requireFence(state.run, fence, now, true); err != nil {
			return discoveryqueue.HeartbeatResult{}, err
		}
		if state.run.status != assetcatalog.RunStatusRunning && state.run.status != assetcatalog.RunStatusFinalizing {
			return discoveryqueue.HeartbeatResult{}, discoveryqueue.ErrStateConflict
		}
		if !runAdmitted(state) {
			return discoveryqueue.HeartbeatResult{}, discoveryqueue.ErrIneligible
		}
		if command.Sequence != state.run.heartbeatSequence+1 {
			return discoveryqueue.HeartbeatResult{}, discoveryqueue.ErrStateConflict
		}
		if _, err := tx.Exec(ctx, `
UPDATE asset_source_runs
SET heartbeat_sequence=$4,
    lease_expires_at=GREATEST(lease_expires_at,clock_timestamp()+($5::bigint*interval '1 microsecond')),
    version=version+1
WHERE tenant_id=$1::uuid AND workspace_id=$2::uuid AND id=$3::uuid
`, command.Coordinates.Scope.TenantID, command.Coordinates.Scope.WorkspaceID,
			command.Coordinates.RunID, command.Sequence, command.Extension.Microseconds()); err != nil {
			return discoveryqueue.HeartbeatResult{}, err
		}
		updated, err := lockRun(ctx, tx, command.Coordinates)
		if err != nil {
			return discoveryqueue.HeartbeatResult{}, err
		}
		if updated.leaseExpiresAt == nil {
			return discoveryqueue.HeartbeatResult{}, discoveryqueue.ErrStateConflict
		}
		return discoveryqueue.HeartbeatResult{Run: safeRun(updated), LeaseExpiresAt: *updated.leaseExpiresAt}, nil
	})
	if err != nil {
		return discoveryqueue.HeartbeatResult{}, mapError(err)
	}
	return result, nil
}
func (repository *Repository) AdvanceStage(
	ctx context.Context,
	fence assetcatalog.LeaseFence,
	command discoveryqueue.AdvanceStageCommand,
) (assetcatalog.SourceRun, error) {
	if err := command.Validate(); err != nil {
		return assetcatalog.SourceRun{}, err
	}
	ordinary := command.Delay == nil && ((command.From == assetcatalog.RunStageReading && command.To == assetcatalog.RunStageNormalizing) ||
		(command.From == assetcatalog.RunStageNormalizing && command.To == assetcatalog.RunStageApplying) ||
		(command.From == assetcatalog.RunStageApplying && command.To == assetcatalog.RunStageReading))
	cleanup := command.To == assetcatalog.RunStageCleaningUp && command.Delay != nil &&
		(command.From == assetcatalog.RunStageValidating || command.From == assetcatalog.RunStageReading ||
			command.From == assetcatalog.RunStageNormalizing || command.From == assetcatalog.RunStageApplying)
	if !ordinary && !cleanup {
		return assetcatalog.SourceRun{}, discoveryqueue.ErrInvalidRequest
	}
	result, err := withSerializable(ctx, repository.pool, func(tx pgx.Tx) (assetcatalog.SourceRun, error) {
		state, err := lockState(ctx, tx, command.Coordinates, false)
		if err != nil {
			return assetcatalog.SourceRun{}, err
		}
		now, err := databaseNow(ctx, tx)
		if err != nil {
			return assetcatalog.SourceRun{}, err
		}
		if err := requireFence(state.run, fence, now, true); err != nil {
			return assetcatalog.SourceRun{}, err
		}
		if state.run.status != assetcatalog.RunStatusRunning || state.run.stage != command.From {
			return assetcatalog.SourceRun{}, discoveryqueue.ErrStateConflict
		}
		if !runAdmitted(state) {
			return assetcatalog.SourceRun{}, discoveryqueue.ErrIneligible
		}
		if ordinary {
			if _, err := tx.Exec(ctx, `
UPDATE asset_source_runs SET stage_code=$4,version=version+1
WHERE tenant_id=$1::uuid AND workspace_id=$2::uuid AND id=$3::uuid
`, command.Coordinates.Scope.TenantID, command.Coordinates.Scope.WorkspaceID,
				command.Coordinates.RunID, command.To); err != nil {
				return assetcatalog.SourceRun{}, err
			}
		} else {
			if state.run.cleanupStatus != assetcatalog.CredentialCleanupPending ||
				state.run.pendingDigest != nil || state.run.cleanupAttemptID == nil {
				return assetcatalog.SourceRun{}, discoveryqueue.ErrStateConflict
			}
			intent := *command.Delay
			maximum := now.Add(time.Duration(state.revision.backpressureMax) * time.Second)
			if !intent.NotBefore.After(now) || intent.NotBefore.After(maximum) ||
				(intent.Reason == discoveryqueue.DelayReasonProviderRetryAfter &&
					intent.NotBefore.After(now.Add(60*time.Second))) ||
				(intent.Reason == discoveryqueue.DelayReasonTransportBackoff &&
					intent.NotBefore.After(now.Add(15*time.Minute))) {
				return assetcatalog.SourceRun{}, discoveryqueue.ErrInvalidRequest
			}
			digest, err := delayIntentDigest(state.run, intent)
			if err != nil {
				return assetcatalog.SourceRun{}, err
			}
			if _, err := tx.Exec(ctx, `
UPDATE asset_source_runs
SET stage_code='CLEANING_UP',pending_transition='DELAY',
    pending_transition_reason=$4,pending_transition_not_before=$5,
    pending_transition_digest=$6,version=version+1
WHERE tenant_id=$1::uuid AND workspace_id=$2::uuid AND id=$3::uuid
`, command.Coordinates.Scope.TenantID, command.Coordinates.Scope.WorkspaceID,
				command.Coordinates.RunID, intent.Reason, intent.NotBefore, digest); err != nil {
				return assetcatalog.SourceRun{}, err
			}
		}
		updated, err := lockRun(ctx, tx, command.Coordinates)
		if err != nil {
			return assetcatalog.SourceRun{}, err
		}
		return safeRun(updated), nil
	})
	if err != nil {
		return assetcatalog.SourceRun{}, mapError(err)
	}
	return result, nil
}

func (repository *Repository) ReserveCleanupAttempt(
	ctx context.Context,
	fence assetcatalog.LeaseFence,
	command discoveryqueue.RunCommand,
) (discoveryqueue.CleanupAttempt, error) {
	if err := command.Validate(); err != nil {
		return discoveryqueue.CleanupAttempt{}, err
	}
	attemptID := repository.newID()
	parsed, err := uuid.Parse(attemptID)
	if err != nil || parsed.String() != attemptID {
		return discoveryqueue.CleanupAttempt{}, discoveryqueue.ErrUnavailable
	}
	result, err := withSerializable(ctx, repository.pool, func(tx pgx.Tx) (discoveryqueue.CleanupAttempt, error) {
		state, err := lockState(ctx, tx, command.Coordinates, false)
		if err != nil {
			return discoveryqueue.CleanupAttempt{}, err
		}
		now, err := databaseNow(ctx, tx)
		if err != nil {
			return discoveryqueue.CleanupAttempt{}, err
		}
		if err := requireFence(state.run, fence, now, true); err != nil {
			return discoveryqueue.CleanupAttempt{}, err
		}
		if state.run.status != assetcatalog.RunStatusRunning || state.source.kind == assetcatalog.SourceKindManual {
			return discoveryqueue.CleanupAttempt{}, discoveryqueue.ErrStateConflict
		}
		if !runAdmitted(state) {
			return discoveryqueue.CleanupAttempt{}, discoveryqueue.ErrIneligible
		}
		if state.run.cleanupStatus == assetcatalog.CredentialCleanupPending {
			if state.run.cleanupAttemptID == nil || state.run.cleanupAttemptEpoch != state.run.fenceEpoch {
				return discoveryqueue.CleanupAttempt{}, discoveryqueue.ErrStateConflict
			}
			return discoveryqueue.CleanupAttempt{
				RunID: state.run.id, AttemptID: *state.run.cleanupAttemptID,
				AttemptEpoch: state.run.cleanupAttemptEpoch,
			}, nil
		}
		if state.run.cleanupStatus != assetcatalog.CredentialCleanupNotOpened {
			return discoveryqueue.CleanupAttempt{}, discoveryqueue.ErrStateConflict
		}
		if _, err := tx.Exec(ctx, `
UPDATE asset_source_runs
SET cleanup_attempt_id=$4::uuid,cleanup_attempt_epoch=fence_epoch,
    cleanup_status='PENDING',version=version+1
WHERE tenant_id=$1::uuid AND workspace_id=$2::uuid AND id=$3::uuid
`, command.Coordinates.Scope.TenantID, command.Coordinates.Scope.WorkspaceID,
			command.Coordinates.RunID, attemptID); err != nil {
			return discoveryqueue.CleanupAttempt{}, err
		}
		return discoveryqueue.CleanupAttempt{
			RunID: state.run.id, AttemptID: attemptID, AttemptEpoch: state.run.fenceEpoch,
		}, nil
	})
	if err != nil {
		return discoveryqueue.CleanupAttempt{}, mapError(err)
	}
	return result, nil
}

type cleanupReceipt struct {
	digest, attemptID, status string
	epoch                     int64
}

func (repository *Repository) readCleanupReceipt(
	ctx context.Context,
	proof discoveryqueue.CleanupProof,
) (cleanupReceipt, bool, error) {
	coordinates, attempt := proof.Coordinates(), proof.Attempt()
	var receipt cleanupReceipt
	err := repository.pool.QueryRow(ctx, `
SELECT payload_hash,details->>'attempt_id',(details->>'attempt_epoch')::bigint,details->>'status'
FROM audit_records
WHERE tenant_id=$1::uuid AND workspace_id=$2::uuid
  AND action='ATTEMPT_CLEANED' AND resource_type='ASSET_SOURCE_RUN'
  AND resource_id=$3 AND request_id='source-attempt:'||$3||':'||$4::text
`, coordinates.Scope.TenantID, coordinates.Scope.WorkspaceID,
		coordinates.RunID, attempt.AttemptEpoch).Scan(
		&receipt.digest, &receipt.attemptID, &receipt.epoch, &receipt.status,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return cleanupReceipt{}, false, nil
	}
	return receipt, err == nil, err
}

func exactCleanupReceipt(receipt cleanupReceipt, proof discoveryqueue.CleanupProof) bool {
	attempt := proof.Attempt()
	return receipt.digest == proof.DigestSHA256() && receipt.attemptID == attempt.AttemptID &&
		receipt.epoch == attempt.AttemptEpoch && receipt.status == string(proof.Status())
}

func (repository *Repository) RecordCleanup(
	ctx context.Context,
	fence assetcatalog.LeaseFence,
	proof discoveryqueue.CleanupProof,
) (discoveryqueue.CleanupResult, error) {
	if err := proof.Validate(); err != nil {
		return discoveryqueue.CleanupResult{}, err
	}
	verificationProof := proof.Clone()
	verificationErr := repository.cleanupVerifier.VerifyCleanupProof(ctx, verificationProof)
	verificationProof.Destroy()
	if verificationErr != nil {
		if contextErr := ctx.Err(); contextErr != nil {
			return discoveryqueue.CleanupResult{}, contextErr
		}
		return discoveryqueue.CleanupResult{}, discoveryqueue.ErrCleanupProof
	}
	if receipt, exists, err := repository.readCleanupReceipt(ctx, proof); err != nil {
		return discoveryqueue.CleanupResult{}, mapError(err)
	} else if exists {
		if !exactCleanupReceipt(receipt, proof) {
			return discoveryqueue.CleanupResult{}, discoveryqueue.ErrIdempotency
		}
		return discoveryqueue.CleanupResult{
			Attempt: proof.Attempt(), Status: proof.Status(), DigestSHA256: proof.DigestSHA256(), Replayed: true,
		}, nil
	}
	auditID := repository.newID()
	if parsed, err := uuid.Parse(auditID); err != nil || parsed.String() != auditID {
		return discoveryqueue.CleanupResult{}, discoveryqueue.ErrUnavailable
	}
	terminalAuditID := ""
	if proof.Status() == assetcatalog.CredentialCleanupUncertain {
		terminalAuditID = repository.newID()
		if parsed, err := uuid.Parse(terminalAuditID); err != nil || parsed.String() != terminalAuditID {
			return discoveryqueue.CleanupResult{}, discoveryqueue.ErrUnavailable
		}
	}
	result, err := withSerializable(ctx, repository.pool, func(tx pgx.Tx) (discoveryqueue.CleanupResult, error) {
		coordinates, attempt := proof.Coordinates(), proof.Attempt()
		state, err := lockState(ctx, tx, coordinates, false)
		if err != nil {
			return discoveryqueue.CleanupResult{}, err
		}
		now, err := databaseNow(ctx, tx)
		if err != nil {
			return discoveryqueue.CleanupResult{}, err
		}
		if err := requireFence(state.run, fence, now, true); err != nil {
			return discoveryqueue.CleanupResult{}, err
		}
		if state.run.cleanupStatus != assetcatalog.CredentialCleanupPending ||
			state.run.cleanupAttemptID == nil || *state.run.cleanupAttemptID != attempt.AttemptID ||
			state.run.cleanupAttemptEpoch != attempt.AttemptEpoch || state.run.id != attempt.RunID ||
			state.run.stage != assetcatalog.RunStageCleaningUp ||
			!((state.run.pendingDigest != nil && state.run.workKind == nil) ||
				(state.run.pendingDigest == nil && state.run.workKind != nil)) {
			return discoveryqueue.CleanupResult{}, discoveryqueue.ErrStateConflict
		}
		if _, err := tx.Exec(ctx, `
INSERT INTO audit_records(
 id,tenant_id,workspace_id,actor_type,actor_id,action,resource_type,resource_id,
 request_id,trace_id,payload_hash,details
) VALUES(
 $1::uuid,$2::uuid,$3::uuid,'SYSTEM',$4,'ATTEMPT_CLEANED','ASSET_SOURCE_RUN',$5,
 'source-attempt:'||$5||':'||$6::text,$7,$8,
 jsonb_build_object(
   'attempt_id',$9,'attempt_epoch',$6,'status',$10,'digest',$8,
   'delay_reason',$11,'delay_not_before',$12,'delay_digest',$13
 )
)
`, auditID, state.run.tenantID, state.run.workspaceID, *state.run.leaseOwner,
			state.run.id, attempt.AttemptEpoch, state.run.traceID, proof.DigestSHA256(),
			attempt.AttemptID, proof.Status(), state.run.pendingReason,
			state.run.pendingNotBefore, state.run.pendingDigest); err != nil {
			return discoveryqueue.CleanupResult{}, err
		}
		if proof.Status() == assetcatalog.CredentialCleanupUncertain {
			return recordUncertainCleanup(ctx, tx, state, proof, terminalAuditID)
		}
		if _, err := tx.Exec(ctx, `
UPDATE asset_source_runs SET cleanup_status=$4,cleanup_digest=$5,version=version+1
WHERE tenant_id=$1::uuid AND workspace_id=$2::uuid AND id=$3::uuid
`, state.run.tenantID, state.run.workspaceID, state.run.id, proof.Status(), proof.DigestSHA256()); err != nil {
			return discoveryqueue.CleanupResult{}, err
		}
		return discoveryqueue.CleanupResult{
			Attempt: attempt, Status: proof.Status(), DigestSHA256: proof.DigestSHA256(),
		}, nil
	})
	if err != nil {
		mapped := mapError(err)
		if errors.Is(mapped, discoveryqueue.ErrIdempotency) {
			if receipt, exists, lookupErr := repository.readCleanupReceipt(ctx, proof); lookupErr == nil && exists {
				if exactCleanupReceipt(receipt, proof) {
					return discoveryqueue.CleanupResult{
						Attempt: proof.Attempt(), Status: proof.Status(),
						DigestSHA256: proof.DigestSHA256(), Replayed: true,
					}, nil
				}
			}
		}
		return discoveryqueue.CleanupResult{}, mapped
	}
	if proof.Status() == assetcatalog.CredentialCleanupUncertain {
		fence.Destroy()
	}
	return result, nil
}

func recordUncertainCleanup(
	ctx context.Context,
	tx pgx.Tx,
	state lockedState,
	proof discoveryqueue.CleanupProof,
	terminalAuditID string,
) (discoveryqueue.CleanupResult, error) {
	const failureCode = "CLEANUP_UNCERTAIN"
	digest := proof.DigestSHA256()
	effective := state.run
	effective.cleanupStatus = assetcatalog.CredentialCleanupUncertain
	effective.cleanupDigest = &digest
	failure := failureCode
	effective.failureCode = &failure

	if state.run.status == assetcatalog.RunStatusRunning {
		if state.run.workKind != nil {
			return discoveryqueue.CleanupResult{}, discoveryqueue.ErrStateConflict
		}
		workDigest, err := failureIntentDigest(state.run.id, failureCode, digest)
		if err != nil {
			return discoveryqueue.CleanupResult{}, err
		}
		kind := assetcatalog.WorkResultFailureIntent
		status := assetcatalog.WorkResultStatusFailed
		effective.workKind = &kind
		effective.workStatus = &status
		effective.workDigest = &workDigest
	} else if state.run.status != assetcatalog.RunStatusFinalizing || state.run.workKind == nil ||
		state.run.workStatus == nil || state.run.workDigest == nil {
		return discoveryqueue.CleanupResult{}, discoveryqueue.ErrStateConflict
	}
	override := "CLEANUP_UNCERTAIN"
	effective.terminalOverride = &override
	overrideDigest, err := failureOverrideDigest(effective, failureCode)
	if err != nil {
		return discoveryqueue.CleanupResult{}, err
	}
	effective.terminalOverrideDigest = &overrideDigest
	command := discoveryqueue.TerminalCommand{
		Coordinates: discoveryqueue.RunCoordinates{
			Scope: assetcatalog.SourceScope{
				TenantID: state.run.tenantID, WorkspaceID: state.run.workspaceID,
			},
			RunID: state.run.id,
		},
		DesiredStatus:    assetcatalog.RunStatusFailed,
		WorkResultDigest: *effective.workDigest,
		CleanupStatus:    assetcatalog.CredentialCleanupUncertain,
		CleanupDigest:    digest,
		FailureCode:      failureCode,
	}
	if err := command.Validate(); err != nil {
		return discoveryqueue.CleanupResult{}, discoveryqueue.ErrStateConflict
	}
	if state.run.status == assetcatalog.RunStatusRunning {
		if _, err := tx.Exec(ctx, `
UPDATE asset_source_runs
SET status='FINALIZING',stage_code='CLEANING_UP',
    pending_transition=NULL,pending_transition_reason=NULL,
    pending_transition_not_before=NULL,pending_transition_digest=NULL,
    work_result_kind='FAILURE_INTENT',work_result_status='FAILED',
    work_result_digest=$4,cleanup_status='UNCERTAIN',cleanup_digest=$5,
    failure_code=$6,terminal_failure_override='CLEANUP_UNCERTAIN',
    terminal_failure_override_digest=$7,version=version+1
WHERE tenant_id=$1::uuid AND workspace_id=$2::uuid AND id=$3::uuid
`, state.run.tenantID, state.run.workspaceID, state.run.id,
			*effective.workDigest, digest, failureCode, overrideDigest); err != nil {
			return discoveryqueue.CleanupResult{}, err
		}
	} else if _, err := tx.Exec(ctx, `
UPDATE asset_source_runs
SET cleanup_status='UNCERTAIN',cleanup_digest=$4,failure_code=$5,
    terminal_failure_override='CLEANUP_UNCERTAIN',
    terminal_failure_override_digest=$6,version=version+1
WHERE tenant_id=$1::uuid AND workspace_id=$2::uuid AND id=$3::uuid
`, state.run.tenantID, state.run.workspaceID, state.run.id,
		digest, failureCode, overrideDigest); err != nil {
		return discoveryqueue.CleanupResult{}, err
	}
	commandDigest, err := terminalCommandDigest(effective, assetcatalog.RunStatusFailed, failureCode)
	if err != nil {
		return discoveryqueue.CleanupResult{}, err
	}
	if _, err := tx.Exec(ctx, `
INSERT INTO audit_records(
 id,tenant_id,workspace_id,actor_type,actor_id,action,resource_type,resource_id,
 request_id,trace_id,payload_hash,details
) VALUES(
 $1::uuid,$2::uuid,$3::uuid,'SYSTEM',$4,'TERMINAL_COMMITTED','ASSET_SOURCE_RUN',$5,
 'source-terminal:'||$5,$6,$7,
 jsonb_build_object(
   'status','FAILED','work_result_digest',$8,'cleanup_status','UNCERTAIN',
   'cleanup_digest',$9,'failure_code',$10
 )
)
`, terminalAuditID, state.run.tenantID, state.run.workspaceID, *state.run.leaseOwner,
		state.run.id, state.run.traceID, commandDigest, *effective.workDigest, digest, failureCode); err != nil {
		return discoveryqueue.CleanupResult{}, err
	}
	if _, err := tx.Exec(ctx, `
UPDATE asset_source_runs
SET status='FAILED',stage_code='COMPLETED',terminal_command_sha256=$4,
    failure_code=$5,terminal_failure_override='CLEANUP_UNCERTAIN',
    terminal_failure_override_digest=$6,version=version+1
WHERE tenant_id=$1::uuid AND workspace_id=$2::uuid AND id=$3::uuid
`, state.run.tenantID, state.run.workspaceID, state.run.id,
		commandDigest, failureCode, overrideDigest); err != nil {
		return discoveryqueue.CleanupResult{}, err
	}
	var completedAt time.Time
	if err := tx.QueryRow(ctx, `
SELECT completed_at FROM asset_source_runs
WHERE tenant_id=$1::uuid AND workspace_id=$2::uuid AND id=$3::uuid
`, state.run.tenantID, state.run.workspaceID, state.run.id).Scan(&completedAt); err != nil {
		return discoveryqueue.CleanupResult{}, err
	}
	if err := closeTerminalBindings(ctx, tx, state, effective, command, completedAt); err != nil {
		return discoveryqueue.CleanupResult{}, err
	}
	return discoveryqueue.CleanupResult{
		Attempt: proof.Attempt(), Status: proof.Status(), DigestSHA256: proof.DigestSHA256(),
	}, nil
}

func (repository *Repository) Delay(
	ctx context.Context,
	fence assetcatalog.LeaseFence,
	command discoveryqueue.DelayCommand,
) (assetcatalog.SourceRun, error) {
	if err := command.Validate(); err != nil {
		return assetcatalog.SourceRun{}, err
	}
	result, err := withSerializable(ctx, repository.pool, func(tx pgx.Tx) (assetcatalog.SourceRun, error) {
		state, err := lockState(ctx, tx, command.Coordinates, false)
		if err != nil {
			return assetcatalog.SourceRun{}, err
		}
		now, err := databaseNow(ctx, tx)
		if err != nil {
			return assetcatalog.SourceRun{}, err
		}
		if err := requireFence(state.run, fence, now, true); err != nil {
			return assetcatalog.SourceRun{}, err
		}
		digest, err := delayIntentDigest(state.run, command.Intent)
		if err != nil {
			return assetcatalog.SourceRun{}, err
		}
		if state.run.status != assetcatalog.RunStatusRunning || state.run.stage != assetcatalog.RunStageCleaningUp ||
			state.run.cleanupStatus != assetcatalog.CredentialCleanupRevoked ||
			state.run.pendingReason == nil || *state.run.pendingReason != string(command.Intent.Reason) ||
			state.run.pendingNotBefore == nil || !state.run.pendingNotBefore.Equal(command.Intent.NotBefore) ||
			state.run.pendingDigest == nil || *state.run.pendingDigest != digest || state.run.cleanupDigest == nil {
			return assetcatalog.SourceRun{}, discoveryqueue.ErrStateConflict
		}
		var receiptExists bool
		if err := tx.QueryRow(ctx, `
SELECT EXISTS(
 SELECT 1 FROM audit_records
 WHERE tenant_id=$1::uuid AND workspace_id=$2::uuid
   AND action='ATTEMPT_CLEANED' AND resource_type='ASSET_SOURCE_RUN'
   AND resource_id=$3 AND request_id='source-attempt:'||$3||':'||$4::text
   AND payload_hash=$5
)
`, state.run.tenantID, state.run.workspaceID, state.run.id,
			state.run.cleanupAttemptEpoch, *state.run.cleanupDigest).Scan(&receiptExists); err != nil {
			return assetcatalog.SourceRun{}, err
		}
		if !receiptExists {
			return assetcatalog.SourceRun{}, discoveryqueue.ErrStateConflict
		}
		if _, err := tx.Exec(ctx, `
UPDATE asset_source_runs
SET status='DELAYED',stage_code='DELAYED',lease_owner=NULL,lease_expires_at=NULL,
    fence_token_hash=NULL,pending_transition=NULL,pending_transition_reason=NULL,
    pending_transition_not_before=NULL,pending_transition_digest=NULL,version=version+1
WHERE tenant_id=$1::uuid AND workspace_id=$2::uuid AND id=$3::uuid
`, state.run.tenantID, state.run.workspaceID, state.run.id); err != nil {
			return assetcatalog.SourceRun{}, err
		}
		updated, err := lockRun(ctx, tx, command.Coordinates)
		if err != nil {
			return assetcatalog.SourceRun{}, err
		}
		return safeRun(updated), nil
	})
	if err != nil {
		return assetcatalog.SourceRun{}, mapError(err)
	}
	fence.Destroy()
	return result, nil
}
func (repository *Repository) ProposeValidationResult(
	ctx context.Context,
	fence assetcatalog.LeaseFence,
	command discoveryqueue.ValidationResultCommand,
) (discoveryqueue.WorkResult, error) {
	if err := command.Validate(); err != nil {
		return discoveryqueue.WorkResult{}, err
	}
	result, err := withSerializable(ctx, repository.pool, func(tx pgx.Tx) (discoveryqueue.WorkResult, error) {
		state, err := lockState(ctx, tx, command.Coordinates, false)
		if err != nil {
			return discoveryqueue.WorkResult{}, err
		}
		request := discoverysource.ValidationRequest{
			Locator: assetcatalog.SourceLocator{
				Scope:    assetcatalog.SourceScope{TenantID: state.run.tenantID, WorkspaceID: state.run.workspaceID},
				SourceID: state.run.sourceID,
			},
			SourceRevision: state.run.sourceRevision, SourceRevisionDigest: state.run.revisionDigest,
			Limits: discoverysource.Limits{
				MaxPageItems: state.revision.maxPageItems, MaxPageRelations: state.revision.maxPageRelations,
				MaxPageBytes: state.revision.maxPageBytes, MaxDocumentBytes: state.revision.maxDocumentBytes,
			},
		}
		digest, digestErr := command.Proof.Digest(request)
		if digestErr != nil {
			return discoveryqueue.WorkResult{}, discoveryqueue.ErrInvalidRequest
		}
		status := assetcatalog.WorkResultStatus(command.Proof.Outcome)
		if state.run.status == assetcatalog.RunStatusFinalizing {
			if state.run.workKind != nil && *state.run.workKind == assetcatalog.WorkResultValidationProof &&
				state.run.workStatus != nil && *state.run.workStatus == status &&
				state.run.workDigest != nil && *state.run.workDigest == digest &&
				state.run.validationOutcome != nil && *state.run.validationOutcome == command.Proof.Outcome {
				return discoveryqueue.WorkResult{
					Kind: assetcatalog.WorkResultValidationProof, Status: status,
					DigestSHA256: digest, Replayed: true,
				}, nil
			}
			return discoveryqueue.WorkResult{}, discoveryqueue.ErrIdempotency
		}
		now, err := databaseNow(ctx, tx)
		if err != nil {
			return discoveryqueue.WorkResult{}, err
		}
		if err := requireFence(state.run, fence, now, true); err != nil {
			return discoveryqueue.WorkResult{}, err
		}
		if state.run.kind != assetcatalog.RunKindValidation || state.run.status != assetcatalog.RunStatusRunning ||
			state.run.cleanupStatus != assetcatalog.CredentialCleanupPending || state.run.pendingDigest != nil ||
			state.run.workKind != nil || !runAdmitted(state) {
			return discoveryqueue.WorkResult{}, discoveryqueue.ErrStateConflict
		}
		if _, err := tx.Exec(ctx, `
UPDATE asset_source_runs
SET status='FINALIZING',stage_code='CLEANING_UP',
    work_result_kind='VALIDATION_PROOF',work_result_status=$4,
    work_result_digest=$5,validation_outcome=$6,
    validation_digest=$5,validation_proof_digest=$5,version=version+1
WHERE tenant_id=$1::uuid AND workspace_id=$2::uuid AND id=$3::uuid
`, state.run.tenantID, state.run.workspaceID, state.run.id, status, digest, command.Proof.Outcome); err != nil {
			return discoveryqueue.WorkResult{}, err
		}
		return discoveryqueue.WorkResult{
			Kind: assetcatalog.WorkResultValidationProof, Status: status, DigestSHA256: digest,
		}, nil
	})
	if err != nil {
		return discoveryqueue.WorkResult{}, mapError(err)
	}
	return result, nil
}

func failureIntentDigest(runID, failureCode, evidenceDigest string) (string, error) {
	evidence, err := decodeDigest(evidenceDigest)
	if err != nil {
		return "", err
	}
	defer clear(evidence)
	return framedSHA256(
		[]byte("asset-run-failure-intent.v1"), []byte(runID), []byte(failureCode), evidence,
	), nil
}

func failureOverrideDigest(run runRow, failureCode string) (string, error) {
	if run.cleanupStatus != assetcatalog.CredentialCleanupUncertain || run.cleanupDigest == nil {
		return "", discoveryqueue.ErrInvalidRequest
	}
	cleanup, err := decodeDigest(*run.cleanupDigest)
	if err != nil {
		return "", err
	}
	defer clear(cleanup)
	var kind, work []byte
	if run.workKind != nil {
		kind = []byte(*run.workKind)
		if run.workDigest == nil {
			return "", discoveryqueue.ErrInvalidRequest
		}
		work, err = decodeDigest(*run.workDigest)
		if err != nil {
			return "", err
		}
		defer clear(work)
	}
	return framedSHA256(
		[]byte("asset-run-terminal-failure-override.v1"), []byte(run.id), kind, work,
		[]byte(run.cleanupStatus), cleanup, []byte(failureCode),
	), nil
}

func terminalCommandDigest(run runRow, status assetcatalog.RunStatus, failureCode string) (string, error) {
	if run.workKind == nil || run.workDigest == nil {
		return "", discoveryqueue.ErrInvalidRequest
	}
	work, err := decodeDigest(*run.workDigest)
	if err != nil {
		return "", err
	}
	defer clear(work)
	var cleanup, overrideDigest []byte
	if run.cleanupDigest != nil {
		cleanup, err = decodeDigest(*run.cleanupDigest)
		if err != nil {
			return "", err
		}
		defer clear(cleanup)
	}
	if run.terminalOverrideDigest != nil {
		overrideDigest, err = decodeDigest(*run.terminalOverrideDigest)
		if err != nil {
			return "", err
		}
		defer clear(overrideDigest)
	}
	var override, failure []byte
	if run.terminalOverride != nil {
		override = []byte(*run.terminalOverride)
	}
	if failureCode != "" {
		failure = []byte(failureCode)
	}
	return framedSHA256(
		[]byte("asset-run-terminal.v1"), []byte(run.id), []byte(status), []byte(*run.workKind), work,
		[]byte(run.cleanupStatus), cleanup, override, overrideDigest, failure,
	), nil
}

func (repository *Repository) PrepareFailureIntent(
	ctx context.Context,
	fence assetcatalog.LeaseFence,
	command discoveryqueue.FailureIntentCommand,
) (discoveryqueue.WorkResult, error) {
	if err := command.Validate(); err != nil {
		return discoveryqueue.WorkResult{}, err
	}
	result, err := withSerializable(ctx, repository.pool, func(tx pgx.Tx) (discoveryqueue.WorkResult, error) {
		state, err := lockState(ctx, tx, command.Coordinates, false)
		if err != nil {
			return discoveryqueue.WorkResult{}, err
		}
		digest, err := failureIntentDigest(state.run.id, command.FailureCode, command.EvidenceDigest)
		if err != nil {
			return discoveryqueue.WorkResult{}, err
		}
		if state.run.status == assetcatalog.RunStatusFinalizing {
			if state.run.workKind != nil && *state.run.workKind == assetcatalog.WorkResultFailureIntent &&
				state.run.workStatus != nil && *state.run.workStatus == assetcatalog.WorkResultStatusFailed &&
				state.run.workDigest != nil && *state.run.workDigest == digest &&
				state.run.failureCode != nil && *state.run.failureCode == command.FailureCode {
				return discoveryqueue.WorkResult{
					Kind: assetcatalog.WorkResultFailureIntent, Status: assetcatalog.WorkResultStatusFailed,
					DigestSHA256: digest, FailureCode: command.FailureCode, Replayed: true,
				}, nil
			}
			return discoveryqueue.WorkResult{}, discoveryqueue.ErrIdempotency
		}
		now, err := databaseNow(ctx, tx)
		if err != nil {
			return discoveryqueue.WorkResult{}, err
		}
		if err := requireFence(state.run, fence, now, true); err != nil {
			return discoveryqueue.WorkResult{}, err
		}
		admitted := runAdmitted(state)
		if state.run.status != assetcatalog.RunStatusRunning || state.run.workKind != nil ||
			state.run.pendingDigest != nil ||
			(state.run.cleanupStatus != assetcatalog.CredentialCleanupPending &&
				!(state.run.cleanupStatus == assetcatalog.CredentialCleanupNotOpened && !admitted)) {
			return discoveryqueue.WorkResult{}, discoveryqueue.ErrStateConflict
		}
		if _, err := tx.Exec(ctx, `
UPDATE asset_source_runs
SET status='FINALIZING',stage_code='CLEANING_UP',
    work_result_kind='FAILURE_INTENT',work_result_status='FAILED',
    work_result_digest=$4,failure_code=$5,version=version+1
WHERE tenant_id=$1::uuid AND workspace_id=$2::uuid AND id=$3::uuid
`, state.run.tenantID, state.run.workspaceID, state.run.id, digest, command.FailureCode); err != nil {
			return discoveryqueue.WorkResult{}, err
		}
		return discoveryqueue.WorkResult{
			Kind: assetcatalog.WorkResultFailureIntent, Status: assetcatalog.WorkResultStatusFailed,
			DigestSHA256: digest, FailureCode: command.FailureCode,
		}, nil
	})
	if err != nil {
		return discoveryqueue.WorkResult{}, mapError(err)
	}
	return result, nil
}
func (repository *Repository) BeginCheckpointLineageRollover(
	ctx context.Context,
	fence assetcatalog.LeaseFence,
	command discoveryqueue.RolloverCommand,
) (discoveryqueue.RolloverResult, error) {
	if err := command.Validate(); err != nil {
		return discoveryqueue.RolloverResult{}, err
	}
	auditID := repository.newID()
	if parsed, err := uuid.Parse(auditID); err != nil || parsed.String() != auditID {
		return discoveryqueue.RolloverResult{}, discoveryqueue.ErrUnavailable
	}
	result, err := withSerializable(ctx, repository.pool, func(tx pgx.Tx) (discoveryqueue.RolloverResult, error) {
		state, err := lockState(ctx, tx, command.Coordinates, false)
		if err != nil {
			return discoveryqueue.RolloverResult{}, err
		}
		if replay, found, err := rolloverReplay(ctx, tx, state, command); err != nil {
			return discoveryqueue.RolloverResult{}, err
		} else if found {
			return replay, nil
		}
		now, err := databaseNow(ctx, tx)
		if err != nil {
			return discoveryqueue.RolloverResult{}, err
		}
		if err := requireFence(state.run, fence, now, true); err != nil {
			return discoveryqueue.RolloverResult{}, err
		}
		if state.run.kind == assetcatalog.RunKindValidation ||
			state.run.status != assetcatalog.RunStatusRunning ||
			(state.run.stage != assetcatalog.RunStageReading &&
				state.run.stage != assetcatalog.RunStageNormalizing &&
				state.run.stage != assetcatalog.RunStageApplying) ||
			state.source.kind == assetcatalog.SourceKindManual ||
			state.run.lineageReason != nil || state.run.workKind != nil || state.run.pendingDigest != nil ||
			state.run.cleanupStatus != assetcatalog.CredentialCleanupPending ||
			state.run.cleanupAttemptID == nil || state.run.cleanupAttemptEpoch != state.run.fenceEpoch ||
			!runAdmitted(state) {
			return discoveryqueue.RolloverResult{}, discoveryqueue.ErrStateConflict
		}
		request := discoveryqueue.CheckpointLineageRolloverRequest{
			Coordinates: discoveryqueue.RunCoordinates{
				Scope: assetcatalog.SourceScope{
					TenantID: state.run.tenantID, WorkspaceID: state.run.workspaceID,
				},
				RunID: state.run.id,
			},
			SourceID: state.run.sourceID, ProviderKind: state.source.providerKind,
			SourceRevision: state.run.sourceRevision, SourceRevisionDigest: state.run.revisionDigest,
			SourceDefinitionDigest: state.revision.definitionDigest,
			ProfileCode:            state.revision.profileCode,
			CheckpointVersion:      state.run.checkpointVersion,
			CheckpointSHA256:       stringValue(state.source.checkpointSHA),
			ReasonCode:             command.ReasonCode,
			EvidenceDigest:         command.EvidenceDigest,
		}
		if err := repository.rolloverVerifier.VerifyCheckpointLineageRollover(ctx, request); err != nil {
			if contextErr := ctx.Err(); contextErr != nil {
				return discoveryqueue.RolloverResult{}, contextErr
			}
			return discoveryqueue.RolloverResult{}, discoveryqueue.ErrIneligible
		}
		gateRevision := state.source.gateRevision + 1
		if _, err := tx.Exec(ctx, `
INSERT INTO audit_records(
 id,tenant_id,workspace_id,actor_type,actor_id,action,resource_type,resource_id,
 request_id,trace_id,payload_hash,details
) VALUES(
 $1::uuid,$2::uuid,$3::uuid,'SYSTEM',$4,
 'CHECKPOINT_LINEAGE_ROLLOVER_BOUND','ASSET_SOURCE_RUN',$5,
 'source-rollover:'||$5,$6,$7,
 jsonb_build_object(
   'reason_code',$8,'evidence_digest',$7,'gate_revision',$9,
   'source_revision',$10,'source_revision_digest',$11,
   'source_definition_digest',$12,'profile_code',$13,
   'checkpoint_version',$14,'checkpoint_sha256',$15,'fence_epoch',$16
 )
)
`, auditID, state.run.tenantID, state.run.workspaceID, *state.run.leaseOwner,
			state.run.id, state.run.traceID, command.EvidenceDigest, command.ReasonCode,
			gateRevision, state.run.sourceRevision, state.run.revisionDigest,
			state.revision.definitionDigest, state.revision.profileCode,
			state.run.checkpointVersion, state.source.checkpointSHA, state.run.fenceEpoch); err != nil {
			return discoveryqueue.RolloverResult{}, err
		}
		sourceTag, err := tx.Exec(ctx, `
UPDATE asset_sources
SET gate_status='DEGRADED',gate_reason_code='CHECKPOINT_LINEAGE_ROLLOVER',
    gate_revision=gate_revision+1,version=version+1
WHERE tenant_id=$1::uuid AND workspace_id=$2::uuid AND id=$3::uuid
  AND status='ACTIVE' AND source_kind <> 'MANUAL'
  AND published_revision=$4 AND published_revision_digest=$5
  AND gate_status='AVAILABLE' AND gate_revision=$6
  AND checkpoint_revision=$4 AND checkpoint_version=$7
  AND checkpoint_sha256 IS NOT DISTINCT FROM $8
`, state.run.tenantID, state.run.workspaceID, state.run.sourceID,
			state.run.sourceRevision, state.run.revisionDigest, state.run.gateRevision,
			state.run.checkpointVersion, state.source.checkpointSHA)
		if err != nil {
			return discoveryqueue.RolloverResult{}, err
		}
		if sourceTag.RowsAffected() != 1 {
			return discoveryqueue.RolloverResult{}, discoveryqueue.ErrStateConflict
		}
		runTag, err := tx.Exec(ctx, `
UPDATE asset_source_runs
SET lineage_rollover_reason=$4,lineage_rollover_evidence_digest=$5,version=version+1
WHERE tenant_id=$1::uuid AND workspace_id=$2::uuid AND id=$3::uuid
  AND lineage_rollover_reason IS NULL AND lineage_rollover_evidence_digest IS NULL
`, state.run.tenantID, state.run.workspaceID, state.run.id,
			command.ReasonCode, command.EvidenceDigest)
		if err != nil {
			return discoveryqueue.RolloverResult{}, err
		}
		if runTag.RowsAffected() != 1 {
			return discoveryqueue.RolloverResult{}, discoveryqueue.ErrStateConflict
		}
		return discoveryqueue.RolloverResult{
			ReasonCode: command.ReasonCode, EvidenceDigest: command.EvidenceDigest,
			GateRevision: gateRevision,
		}, nil
	})
	if err != nil {
		return discoveryqueue.RolloverResult{}, mapError(err)
	}
	return result, nil
}

func rolloverReplay(
	ctx context.Context,
	tx pgx.Tx,
	state lockedState,
	command discoveryqueue.RolloverCommand,
) (discoveryqueue.RolloverResult, bool, error) {
	var (
		receiptDigest, reasonCode, revisionDigest, definitionDigest, profileCode string
		gateRevision, sourceRevision, checkpointVersion, fenceEpoch              int64
		checkpointSHA                                                            *string
	)
	err := tx.QueryRow(ctx, `
SELECT payload_hash,details->>'reason_code',(details->>'gate_revision')::bigint,
       (details->>'source_revision')::bigint,details->>'source_revision_digest',
       details->>'source_definition_digest',details->>'profile_code',
       (details->>'checkpoint_version')::bigint,details->>'checkpoint_sha256',
       (details->>'fence_epoch')::bigint
FROM audit_records
WHERE tenant_id=$1::uuid AND workspace_id=$2::uuid
  AND action='CHECKPOINT_LINEAGE_ROLLOVER_BOUND'
  AND resource_type='ASSET_SOURCE_RUN' AND resource_id=$3
  AND request_id='source-rollover:'||$3
`, state.run.tenantID, state.run.workspaceID, state.run.id).Scan(
		&receiptDigest, &reasonCode, &gateRevision, &sourceRevision, &revisionDigest,
		&definitionDigest, &profileCode, &checkpointVersion, &checkpointSHA, &fenceEpoch,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		if state.run.lineageReason != nil || state.run.lineageEvidence != nil {
			return discoveryqueue.RolloverResult{}, false, discoveryqueue.ErrStateConflict
		}
		return discoveryqueue.RolloverResult{}, false, nil
	}
	if err != nil {
		return discoveryqueue.RolloverResult{}, false, err
	}
	if receiptDigest != command.EvidenceDigest || reasonCode != command.ReasonCode {
		return discoveryqueue.RolloverResult{}, false, discoveryqueue.ErrIdempotency
	}
	if checkpointVersion < 0 || checkpointVersion > state.run.checkpointVersion ||
		fenceEpoch <= 0 || fenceEpoch > state.run.fenceEpoch {
		return discoveryqueue.RolloverResult{}, false, discoveryqueue.ErrStateConflict
	}
	if checkpointSHA != nil {
		decoded, err := decodeDigest(*checkpointSHA)
		if err != nil {
			return discoveryqueue.RolloverResult{}, false, discoveryqueue.ErrStateConflict
		}
		clear(decoded)
	}
	if state.run.lineageReason == nil || state.run.lineageEvidence == nil ||
		*state.run.lineageReason != reasonCode || *state.run.lineageEvidence != receiptDigest ||
		sourceRevision != state.run.sourceRevision || revisionDigest != state.run.revisionDigest ||
		definitionDigest != state.revision.definitionDigest || profileCode != string(state.revision.profileCode) ||
		gateRevision != state.run.gateRevision+1 {
		return discoveryqueue.RolloverResult{}, false, discoveryqueue.ErrStateConflict
	}
	return discoveryqueue.RolloverResult{
		ReasonCode: reasonCode, EvidenceDigest: receiptDigest,
		GateRevision: gateRevision, Replayed: true,
	}, true, nil
}
func (repository *Repository) Complete(
	ctx context.Context,
	fence assetcatalog.LeaseFence,
	command discoveryqueue.TerminalCommand,
) (discoveryqueue.TerminalResult, error) {
	if command.DesiredStatus != assetcatalog.RunStatusSucceeded &&
		command.DesiredStatus != assetcatalog.RunStatusPartial {
		return discoveryqueue.TerminalResult{}, discoveryqueue.ErrInvalidRequest
	}
	return repository.terminal(ctx, fence, command, false)
}
func (repository *Repository) Fail(
	ctx context.Context,
	fence assetcatalog.LeaseFence,
	command discoveryqueue.TerminalCommand,
) (discoveryqueue.TerminalResult, error) {
	if command.DesiredStatus != assetcatalog.RunStatusFailed {
		return discoveryqueue.TerminalResult{}, discoveryqueue.ErrInvalidRequest
	}
	return repository.terminal(ctx, fence, command, true)
}

func (repository *Repository) terminal(
	ctx context.Context,
	fence assetcatalog.LeaseFence,
	command discoveryqueue.TerminalCommand,
	failing bool,
) (discoveryqueue.TerminalResult, error) {
	if err := command.Validate(); err != nil {
		return discoveryqueue.TerminalResult{}, err
	}
	auditID := repository.newID()
	if parsed, err := uuid.Parse(auditID); err != nil || parsed.String() != auditID {
		return discoveryqueue.TerminalResult{}, discoveryqueue.ErrUnavailable
	}
	result, err := withSerializable(ctx, repository.pool, func(tx pgx.Tx) (discoveryqueue.TerminalResult, error) {
		state, err := lockState(ctx, tx, command.Coordinates, false)
		if err != nil {
			return discoveryqueue.TerminalResult{}, err
		}
		if replay, found, err := terminalReplay(ctx, tx, state.run, command); err != nil {
			return discoveryqueue.TerminalResult{}, err
		} else if found {
			return replay, nil
		}
		now, err := databaseNow(ctx, tx)
		if err != nil {
			return discoveryqueue.TerminalResult{}, err
		}
		if err := requireFence(state.run, fence, now, true); err != nil {
			return discoveryqueue.TerminalResult{}, err
		}
		if state.run.status != assetcatalog.RunStatusFinalizing ||
			state.run.stage != assetcatalog.RunStageCleaningUp || state.run.workKind == nil ||
			state.run.workStatus == nil || state.run.workDigest == nil ||
			*state.run.workDigest != command.WorkResultDigest ||
			state.run.cleanupStatus != command.CleanupStatus ||
			stringValue(state.run.cleanupDigest) != command.CleanupDigest {
			return discoveryqueue.TerminalResult{}, discoveryqueue.ErrStateConflict
		}
		if failing {
			if command.CleanupStatus == assetcatalog.CredentialCleanupUncertain {
				if command.FailureCode != "CLEANUP_UNCERTAIN" {
					return discoveryqueue.TerminalResult{}, discoveryqueue.ErrInvalidRequest
				}
			} else if *state.run.workStatus != assetcatalog.WorkResultStatusFailed ||
				(*state.run.workKind != assetcatalog.WorkResultValidationProof &&
					*state.run.workKind != assetcatalog.WorkResultFailureIntent) {
				return discoveryqueue.TerminalResult{}, discoveryqueue.ErrStateConflict
			}
		} else {
			if command.CleanupStatus != assetcatalog.CredentialCleanupRevoked ||
				assetcatalog.RunStatus(*state.run.workStatus) != command.DesiredStatus ||
				(*state.run.workKind != assetcatalog.WorkResultValidationProof &&
					*state.run.workKind != assetcatalog.WorkResultDataProjection) ||
				(state.run.kind == assetcatalog.RunKindValidation && command.DesiredStatus != assetcatalog.RunStatusSucceeded) {
				return discoveryqueue.TerminalResult{}, discoveryqueue.ErrStateConflict
			}
		}

		effective := state.run
		if failing {
			failure := command.FailureCode
			effective.failureCode = &failure
		}
		if command.CleanupStatus == assetcatalog.CredentialCleanupUncertain {
			override := "CLEANUP_UNCERTAIN"
			effective.terminalOverride = &override
			digest, err := failureOverrideDigest(effective, command.FailureCode)
			if err != nil {
				return discoveryqueue.TerminalResult{}, err
			}
			effective.terminalOverrideDigest = &digest
		}
		commandDigest, err := terminalCommandDigest(effective, command.DesiredStatus, command.FailureCode)
		if err != nil {
			return discoveryqueue.TerminalResult{}, err
		}
		if _, err := tx.Exec(ctx, `
INSERT INTO audit_records(
 id,tenant_id,workspace_id,actor_type,actor_id,action,resource_type,resource_id,
 request_id,trace_id,payload_hash,details
) VALUES(
 $1::uuid,$2::uuid,$3::uuid,'SYSTEM',$4,'TERMINAL_COMMITTED','ASSET_SOURCE_RUN',$5,
 'source-terminal:'||$5,$6,$7,
 jsonb_build_object(
   'status',$8,'work_result_digest',$9,'cleanup_status',$10,
   'cleanup_digest',$11,'failure_code',$12
 )
)
`, auditID, state.run.tenantID, state.run.workspaceID, *state.run.leaseOwner,
			state.run.id, state.run.traceID, commandDigest, command.DesiredStatus,
			command.WorkResultDigest, command.CleanupStatus, nullableText(command.CleanupDigest),
			nullableText(command.FailureCode)); err != nil {
			return discoveryqueue.TerminalResult{}, err
		}
		var completedAt time.Time
		var terminalVersion int64
		if _, err := tx.Exec(ctx, `
UPDATE asset_source_runs
SET status=$4,stage_code='COMPLETED',terminal_command_sha256=$5,
    failure_code=$6,terminal_failure_override=$7,
    terminal_failure_override_digest=$8,version=version+1
WHERE tenant_id=$1::uuid AND workspace_id=$2::uuid AND id=$3::uuid
`, state.run.tenantID, state.run.workspaceID, state.run.id, command.DesiredStatus,
			commandDigest, nullableText(command.FailureCode), effective.terminalOverride,
			effective.terminalOverrideDigest); err != nil {
			return discoveryqueue.TerminalResult{}, err
		}
		if err := tx.QueryRow(ctx, `
SELECT completed_at,version FROM asset_source_runs
WHERE tenant_id=$1::uuid AND workspace_id=$2::uuid AND id=$3::uuid
`, state.run.tenantID, state.run.workspaceID, state.run.id).Scan(&completedAt, &terminalVersion); err != nil {
			return discoveryqueue.TerminalResult{}, err
		}
		_ = terminalVersion
		if err := closeTerminalBindings(ctx, tx, state, effective, command, completedAt); err != nil {
			return discoveryqueue.TerminalResult{}, err
		}
		return discoveryqueue.TerminalResult{
			RunID: state.run.id, Status: command.DesiredStatus,
			CommandDigest: commandDigest, CompletedAt: completedAt,
		}, nil
	})
	if err != nil {
		return discoveryqueue.TerminalResult{}, mapError(err)
	}
	fence.Destroy()
	return result, nil
}

func terminalReplay(
	ctx context.Context,
	tx pgx.Tx,
	run runRow,
	command discoveryqueue.TerminalCommand,
) (discoveryqueue.TerminalResult, bool, error) {
	var receiptDigest string
	err := tx.QueryRow(ctx, `
SELECT payload_hash FROM audit_records
WHERE tenant_id=$1::uuid AND workspace_id=$2::uuid
  AND action='TERMINAL_COMMITTED' AND resource_type='ASSET_SOURCE_RUN'
  AND resource_id=$3 AND request_id='source-terminal:'||$3
`, run.tenantID, run.workspaceID, run.id).Scan(&receiptDigest)
	if errors.Is(err, pgx.ErrNoRows) {
		if run.status == assetcatalog.RunStatusSucceeded || run.status == assetcatalog.RunStatusPartial ||
			run.status == assetcatalog.RunStatusFailed {
			return discoveryqueue.TerminalResult{}, false, discoveryqueue.ErrStateConflict
		}
		return discoveryqueue.TerminalResult{}, false, nil
	}
	if err != nil {
		return discoveryqueue.TerminalResult{}, false, err
	}
	if run.completedAt == nil || run.terminalDigest == nil || run.workDigest == nil ||
		run.status != command.DesiredStatus || *run.workDigest != command.WorkResultDigest ||
		run.cleanupStatus != command.CleanupStatus || stringValue(run.cleanupDigest) != command.CleanupDigest ||
		stringValue(run.failureCode) != command.FailureCode {
		return discoveryqueue.TerminalResult{}, false, discoveryqueue.ErrIdempotency
	}
	expected, err := terminalCommandDigest(run, command.DesiredStatus, command.FailureCode)
	if err != nil {
		return discoveryqueue.TerminalResult{}, false, discoveryqueue.ErrStateConflict
	}
	if expected != receiptDigest || expected != *run.terminalDigest {
		return discoveryqueue.TerminalResult{}, false, discoveryqueue.ErrStateConflict
	}
	return discoveryqueue.TerminalResult{
		RunID: run.id, Status: run.status, CommandDigest: expected,
		CompletedAt: *run.completedAt, Replayed: true,
	}, true, nil
}

func closeTerminalBindings(
	ctx context.Context,
	tx pgx.Tx,
	state lockedState,
	effective runRow,
	command discoveryqueue.TerminalCommand,
	completedAt time.Time,
) error {
	if state.run.kind == assetcatalog.RunKindValidation {
		status := assetcatalog.SourceRevisionValidated
		digest := stringValue(state.run.validationDigest)
		if command.DesiredStatus == assetcatalog.RunStatusFailed {
			status = assetcatalog.SourceRevisionRejected
			digest = firstString(
				stringValue(effective.terminalOverrideDigest), stringValue(state.run.validationProofDigest),
				stringValue(state.run.workDigest), state.run.requestHash,
			)
		}
		if digest == "" {
			return discoveryqueue.ErrStateConflict
		}
		if _, err := tx.Exec(ctx, `
UPDATE asset_source_revisions
SET state=$6,validation_digest=$7,version=version+1
WHERE tenant_id=$1::uuid AND workspace_id=$2::uuid AND source_id=$3::uuid
  AND revision=$4 AND canonical_revision_digest=$5
`, state.run.tenantID, state.run.workspaceID, state.run.sourceID,
			state.run.sourceRevision, state.run.revisionDigest, status, digest); err != nil {
			return err
		}
	}

	cleanupUncertain := command.CleanupStatus == assetcatalog.CredentialCleanupUncertain
	rollover := state.run.lineageReason != nil
	if cleanupUncertain || (rollover && command.DesiredStatus != assetcatalog.RunStatusSucceeded) {
		reason := command.FailureCode
		if cleanupUncertain {
			reason = "CLEANUP_UNCERTAIN"
		}
		if _, err := tx.Exec(ctx, `
UPDATE asset_sources
SET gate_status='SUSPENDED',gate_reason_code=$4,
    gate_revision=gate_revision+1,version=version+1
WHERE tenant_id=$1::uuid AND workspace_id=$2::uuid AND id=$3::uuid
`, state.run.tenantID, state.run.workspaceID, state.run.sourceID, reason); err != nil {
			return err
		}
		return nil
	}
	if state.run.kind == assetcatalog.RunKindValidation || command.DesiredStatus != assetcatalog.RunStatusSucceeded {
		return nil
	}
	if rollover {
		if !state.run.effectiveComplete {
			return discoveryqueue.ErrStateConflict
		}
		_, err := tx.Exec(ctx, `
UPDATE asset_sources
SET gate_status='AVAILABLE',gate_reason_code=NULL,gate_revision=gate_revision+1,
    last_success_run_id=$4::uuid,last_success_at=$5,
    last_complete_snapshot_run_id=$4::uuid,last_complete_snapshot_at=$5,
    version=version+1
WHERE tenant_id=$1::uuid AND workspace_id=$2::uuid AND id=$3::uuid
`, state.run.tenantID, state.run.workspaceID, state.run.sourceID, state.run.id, completedAt)
		return err
	}
	if state.run.effectiveComplete {
		_, err := tx.Exec(ctx, `
UPDATE asset_sources
SET last_success_run_id=$4::uuid,last_success_at=$5,
    last_complete_snapshot_run_id=$4::uuid,last_complete_snapshot_at=$5,
    version=version+1
WHERE tenant_id=$1::uuid AND workspace_id=$2::uuid AND id=$3::uuid
`, state.run.tenantID, state.run.workspaceID, state.run.sourceID, state.run.id, completedAt)
		return err
	}
	_, err := tx.Exec(ctx, `
UPDATE asset_sources
SET last_success_run_id=$4::uuid,last_success_at=$5,version=version+1
WHERE tenant_id=$1::uuid AND workspace_id=$2::uuid AND id=$3::uuid
`, state.run.tenantID, state.run.workspaceID, state.run.sourceID, state.run.id, completedAt)
	return err
}

func nullableText(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func firstString(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

var _ discoveryqueue.Queue = (*Repository)(nil)
