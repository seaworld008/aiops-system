package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/seaworld008/aiops-system/internal/assetcatalog"
	"github.com/seaworld008/aiops-system/internal/assetdiscovery"
	"github.com/seaworld008/aiops-system/internal/discoverycheckpoint"
	"github.com/seaworld008/aiops-system/internal/discoverysource"
)

const pageReceiptAction = "PAGE_APPLIED"
const relationPageReceiptAction = "RELATION_PAGE_COMMITTED"

const selectPageRunSQL = `
SELECT run.id::text,run.tenant_id::text,run.workspace_id::text,run.source_id::text,
       run.source_revision,run.source_revision_digest,run.run_kind,run.status,run.stage_code,
       run.gate_revision,run.cursor_before_sha256,run.cursor_after_sha256,
       run.page_sequence,run.page_digest,run.relation_page_sequence,run.relation_page_digest,
       run.final_page,run.complete_snapshot,run.effective_complete_snapshot,
       run.checkpoint_version,run.lease_owner,run.lease_expires_at,
       run.lease_expires_at>clock_timestamp(),run.fence_epoch,
       run.fence_token_hash,run.heartbeat_sequence,
       run.observed_count,run.created_count,run.changed_count,run.unchanged_count,
       run.conflict_count,run.missing_count,run.stale_count,run.restored_count,
       run.tombstoned_count,run.rejected_count,run.lineage_rollover_reason,
       run.lineage_rollover_evidence_digest,run.version
FROM asset_source_runs AS run
WHERE run.tenant_id=$1::uuid AND run.workspace_id=$2::uuid
  AND run.source_id=$3::uuid AND run.id=$4::uuid
`

const selectPageRunForUpdateSQL = selectPageRunSQL + ` FOR UPDATE`

const selectPageSourceSQL = `
SELECT source.id::text,source.tenant_id::text,source.workspace_id::text,
       source.source_kind,source.provider_kind,source.status,
       source.published_revision,source.published_revision_digest,
       source.gate_status,source.gate_reason_code,source.gate_revision,
       source.checkpoint_ciphertext,source.checkpoint_key_id,source.checkpoint_sha256,
       source.checkpoint_revision,source.checkpoint_version,source.version
FROM asset_sources AS source
WHERE source.tenant_id=$1::uuid AND source.workspace_id=$2::uuid AND source.id=$3::uuid
`

const selectPageSourceForUpdateSQL = selectPageSourceSQL + ` FOR UPDATE`

const selectPageReceiptSQL = `
SELECT audit.action,audit.resource_type,audit.resource_id,audit.payload_hash,audit.details
FROM audit_records AS audit
WHERE audit.tenant_id=$1::uuid AND audit.workspace_id=$2::uuid AND audit.request_id=$3
`

const advancePageRunStageSQL = `
UPDATE asset_source_runs
SET stage_code='APPLYING',version=version+1
WHERE tenant_id=$1::uuid AND workspace_id=$2::uuid AND source_id=$3::uuid AND id=$4::uuid
  AND status='RUNNING' AND stage_code='NORMALIZING' AND version=$5
  AND lease_owner=$6 AND fence_epoch=$7 AND fence_token_hash=$8
  AND lease_expires_at>clock_timestamp()
RETURNING version
`

const advancePageSourceCheckpointSQL = `
UPDATE asset_sources
SET checkpoint_ciphertext=$5,checkpoint_key_id=$6,checkpoint_sha256=$7,
    checkpoint_revision=$8,checkpoint_version=$9,version=version+1
WHERE tenant_id=$1::uuid AND workspace_id=$2::uuid AND id=$3::uuid AND version=$4
  AND status='ACTIVE' AND published_revision=$8 AND published_revision_digest=$10
  AND checkpoint_revision=$8 AND checkpoint_version=$11
  AND checkpoint_sha256 IS NOT DISTINCT FROM $12
  AND gate_status=$13 AND gate_revision=$14
RETURNING version
`

const advancePageRunSQL = `
UPDATE asset_source_runs
SET status=$5,stage_code=$6,
    page_sequence=$7,page_digest=$8,
    relation_page_sequence=$7,relation_page_digest=$9,
    checkpoint_version=$10,cursor_after_sha256=$11,
    observed_count=observed_count+$12,created_count=created_count+$13,
    changed_count=changed_count+$14,unchanged_count=unchanged_count+$15,
    conflict_count=conflict_count+$16,missing_count=missing_count+$17,
    stale_count=stale_count+$18,restored_count=restored_count+$19,
    tombstoned_count=tombstoned_count+$20,rejected_count=rejected_count+$21,
    final_page=$22,complete_snapshot=$23,effective_complete_snapshot=$24,
    work_result_kind=$25,work_result_status=$26,work_result_digest=$27,
    heartbeat_sequence=heartbeat_sequence+1,version=version+1
WHERE tenant_id=$1::uuid AND workspace_id=$2::uuid AND source_id=$3::uuid AND id=$4::uuid
  AND status='RUNNING' AND stage_code='APPLYING'
  AND page_sequence=$28 AND relation_page_sequence=$29 AND checkpoint_version=$30
  AND final_page=false AND version=$31
  AND lease_owner=$32 AND fence_epoch=$33 AND fence_token_hash=$34
  AND lease_expires_at>clock_timestamp()
RETURNING version,rejected_count
`

const recheckPageFenceSQL = `
SELECT run.id::text,run.lease_owner,run.fence_epoch,run.fence_token_hash
FROM asset_source_runs AS run
JOIN asset_sources AS source
  ON source.tenant_id=run.tenant_id AND source.workspace_id=run.workspace_id
 AND source.id=run.source_id
WHERE run.tenant_id=$1::uuid AND run.workspace_id=$2::uuid
  AND run.source_id=$3::uuid AND run.id=$4::uuid
  AND run.checkpoint_version=$5 AND run.page_sequence=$6
  AND source.checkpoint_version=$5 AND source.checkpoint_sha256=$7
  AND run.lease_expires_at>clock_timestamp()
FOR UPDATE OF run,source
`

type PageCommitter struct {
	repository     *Repository
	keyring        *discoverycheckpoint.InMemoryKeyring
	codec          *discoverycheckpoint.CheckpointCodec
	policyResolver discoverysource.PageFactPolicyResolver
}

type pageRunState struct {
	ID, TenantID, WorkspaceID, SourceID                  string
	SourceRevision                                       int64
	SourceRevisionDigest                                 string
	RunKind, Status, StageCode                           string
	GateRevision                                         int64
	CursorBeforeSHA256, CursorAfterSHA256                string
	PageSequence                                         int64
	PageDigest                                           string
	RelationPageSequence                                 int64
	RelationPageDigest                                   string
	FinalPage, CompleteSnapshot, EffectiveComplete       bool
	CheckpointVersion                                    int64
	LeaseOwner                                           string
	LeaseExpiresAt                                       time.Time
	LeaseCurrent                                         bool
	FenceEpoch                                           int64
	FenceTokenSHA256                                     string
	HeartbeatSequence                                    int64
	Observed, Created, Changed, Unchanged                int64
	Conflict, Missing, Stale, Restored, Tombstoned       int64
	Rejected                                             int64
	LineageRolloverReason, LineageRolloverEvidenceSHA256 string
	Version                                              int64
}

type pageSourceState struct {
	ID, TenantID, WorkspaceID, SourceKind, ProviderKind string
	Status                                              string
	PublishedRevision                                   int64
	PublishedRevisionDigest                             string
	GateStatus, GateReason                              string
	GateRevision                                        int64
	CheckpointCiphertext                                []byte
	CheckpointKeyID, CheckpointSHA256                   string
	CheckpointRevision, CheckpointVersion, Version      int64
}

type pageAdmission struct {
	Run      pageRunState
	Source   pageSourceState
	Revision assetcatalog.SourceRevision
}

type pageReceiptDetails struct {
	ProfileCode             assetcatalog.ProfileCode `json:"profile_code"`
	SemanticIdentitySHA256  string                   `json:"semantic_identity_sha256"`
	ProviderKind            string                   `json:"provider_kind"`
	CheckpointRevision      int64                    `json:"checkpoint_revision"`
	CanonicalRevisionDigest string                   `json:"canonical_revision_digest"`
	SourceDefinitionDigest  string                   `json:"source_definition_digest"`
	CheckpointKeyID         string                   `json:"checkpoint_key_id"`
	Result                  pageReceiptResult        `json:"result"`
}

type pageReceiptResult struct {
	CheckpointVersion        int64  `json:"checkpoint_version"`
	CheckpointSHA256         string `json:"checkpoint_sha256"`
	PageDigestSHA256         string `json:"page_digest_sha256"`
	RelationPageDigestSHA256 string `json:"relation_page_digest_sha256"`
	FinalPage                bool   `json:"final_page"`
	CompleteSnapshot         bool   `json:"complete_snapshot"`
}

type pageReceipt struct {
	PayloadHash string
	Details     pageReceiptDetails
}

type pageDB interface {
	QueryRow(context.Context, string, ...any) pgx.Row
	Query(context.Context, string, ...any) (pgx.Rows, error)
}

func NewPageCommitter(
	repository *Repository,
	keyring *discoverycheckpoint.InMemoryKeyring,
	policyResolver discoverysource.PageFactPolicyResolver,
) (*PageCommitter, error) {
	if repository == nil || repository.pool == nil || repository.newID == nil || keyring == nil ||
		policyResolver == nil || interfaceIsNil(policyResolver) {
		return nil, discoverysource.ErrPageCommitUnavailable
	}
	if _, err := keyring.ActiveKeyID(); err != nil {
		return nil, discoverysource.ErrPageCommitUnavailable
	}
	codec, err := discoverycheckpoint.NewCheckpointCodec(keyring)
	if err != nil {
		return nil, discoverysource.ErrPageCommitUnavailable
	}
	return &PageCommitter{
		repository: repository, keyring: keyring, codec: codec, policyResolver: policyResolver,
	}, nil
}

func (committer *PageCommitter) ApplyPage(
	ctx context.Context,
	fence assetcatalog.LeaseFence,
	coordinates discoverysource.PageCommitCoordinates,
	page discoverysource.Page,
) (discoverysource.PageCommitResult, error) {
	if ctx == nil {
		return discoverysource.PageCommitResult{}, discoverysource.ErrPageCommitInvalid
	}
	if err := ctx.Err(); err != nil {
		return discoverysource.PageCommitResult{}, err
	}
	if committer == nil || committer.repository == nil || committer.repository.pool == nil ||
		committer.codec == nil || committer.keyring == nil || committer.policyResolver == nil {
		return discoverysource.PageCommitResult{}, discoverysource.ErrPageCommitUnavailable
	}
	page = cloneDiscoveryPage(page)
	if !validPageCommitShape(coordinates, page) {
		return discoverysource.PageCommitResult{}, discoverysource.ErrPageCommitInvalid
	}

	receipt, found, err := readPageReceipt(ctx, committer.repository.pool, coordinates)
	if err != nil {
		return discoverysource.PageCommitResult{}, err
	}
	if found {
		return committer.replayReceipt(ctx, coordinates, page, receipt)
	}

	snapshot, err := loadPageAdmission(ctx, committer.repository.pool, coordinates, false)
	if err != nil {
		return discoverysource.PageCommitResult{}, collapsePageAdmissionError(err)
	}
	if page.NextCheckpoint.ProfileCode() != snapshot.Revision.ProfileCode {
		return discoverysource.PageCommitResult{}, discoverysource.ErrPageCommitInvalid
	}
	if err := validatePageAdmission(snapshot, coordinates, fence); err != nil {
		return discoverysource.PageCommitResult{}, err
	}
	activeKeyID, err := committer.keyring.ActiveKeyID()
	if err != nil {
		return discoverysource.PageCommitResult{}, discoverysource.ErrPageCommitUnavailable
	}
	aad := checkpointAAD(snapshot, activeKeyID)
	sealed, err := committer.codec.Seal(ctx, aad, page.NextCheckpoint)
	if err != nil {
		return discoverysource.PageCommitResult{}, collapsePageCodecError(err)
	}
	defer clear(sealed.Envelope)
	replayIdentity, err := committer.codec.ReplayIdentity(ctx, aad, page.NextCheckpoint)
	if err != nil {
		return discoverysource.PageCommitResult{}, collapsePageCodecError(err)
	}
	semanticIdentity, err := pageSemanticIdentity(coordinates, page, replayIdentity)
	if err != nil {
		return discoverysource.PageCommitResult{}, discoverysource.ErrPageCommitInvalid
	}
	ids, err := allocatePageProjectionIDs(committer.repository, len(page.Items), len(page.Relations))
	if err != nil {
		return discoverysource.PageCommitResult{}, discoverysource.ErrPageCommitUnavailable
	}

	for attempt := 0; attempt < serializableAttempts; attempt++ {
		tx, beginErr := committer.repository.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
		if beginErr != nil {
			return discoverysource.PageCommitResult{}, discoverysource.ErrPageCommitUnavailable
		}
		result, replayed, applyErr := committer.applyPageAttempt(
			ctx, tx, fence, coordinates, page, snapshot, aad, sealed, semanticIdentity, ids,
		)
		if applyErr != nil {
			_ = tx.Rollback(ctx)
			if retryablePageCommitAttempt(applyErr) && attempt+1 < serializableAttempts {
				if waitErr := waitForRetry(ctx, attempt); waitErr != nil {
					return discoverysource.PageCommitResult{}, waitErr
				}
				continue
			}
			return discoverysource.PageCommitResult{}, collapsePageAttemptError(applyErr)
		}
		if replayed {
			_ = tx.Rollback(ctx)
			return result, nil
		}
		commitErr := tx.Commit(ctx)
		if commitErr == nil {
			return result, nil
		}
		if isRetryablePGError(commitErr) && attempt+1 < serializableAttempts {
			if waitErr := waitForRetry(ctx, attempt); waitErr != nil {
				return discoverysource.PageCommitResult{}, waitErr
			}
			continue
		}
		if isRetryablePGError(commitErr) {
			return discoverysource.PageCommitResult{}, discoverysource.ErrPageCommitConflict
		}
		// Any non-retryable commit response is resolved only through the immutable
		// receipt. This is safe for both definite rollback (no receipt) and a lost
		// success response, and never attempts to submit the page a second time.
		recoveryContext := context.WithoutCancel(ctx)
		receipt, found, receiptErr := readPageReceipt(recoveryContext, committer.repository.pool, coordinates)
		if receiptErr != nil || !found {
			return discoverysource.PageCommitResult{}, discoverysource.ErrPageCommitUnavailable
		}
		return committer.replayReceipt(recoveryContext, coordinates, page, receipt)
	}
	return discoverysource.PageCommitResult{}, discoverysource.ErrPageCommitConflict
}

func (committer *PageCommitter) applyPageAttempt(
	ctx context.Context,
	tx pgx.Tx,
	fence assetcatalog.LeaseFence,
	coordinates discoverysource.PageCommitCoordinates,
	page discoverysource.Page,
	snapshot pageAdmission,
	aad discoverycheckpoint.CheckpointAAD,
	sealed discoverycheckpoint.SealedCheckpoint,
	semanticIdentity string,
	ids pageProjectionIDs,
) (discoverysource.PageCommitResult, bool, error) {
	locked, err := loadPageAdmission(ctx, tx, coordinates, true)
	if err != nil {
		return discoverysource.PageCommitResult{}, false, err
	}
	receipt, found, err := readPageReceipt(ctx, tx, coordinates)
	if err != nil {
		return discoverysource.PageCommitResult{}, false, err
	}
	if found {
		result, replayErr := committer.replayReceipt(ctx, coordinates, page, receipt)
		return result, replayErr == nil, replayErr
	}
	if !reflect.DeepEqual(snapshot, locked) || checkpointAAD(locked, aad.CheckpointKeyID) != aad {
		return discoverysource.PageCommitResult{}, false, discoverysource.ErrPageCommitConflict
	}
	if page.NextCheckpoint.ProfileCode() != locked.Revision.ProfileCode {
		return discoverysource.PageCommitResult{}, false, discoverysource.ErrPageCommitConflict
	}
	if err := validatePageAdmission(locked, coordinates, fence); err != nil {
		return discoverysource.PageCommitResult{}, false, err
	}
	policy, err := committer.policyResolver.ResolvePageFactPolicy(ctx, locked.Revision.Clone())
	if err != nil || !exactPageFactPolicy(locked, policy) ||
		assetdiscovery.ValidateFacts(nil, nil, policy) != nil {
		return discoverysource.PageCommitResult{}, false, discoverysource.ErrPageCommitUnavailable
	}
	if err := assetdiscovery.ValidateFacts(page.Items, page.Relations, policy); err != nil {
		return discoverysource.PageCommitResult{}, false, discoverysource.ErrPageCommitInvalid
	}
	if err := committer.authorizeCrossEnvironmentRelations(ctx, locked.Revision, page.Relations); err != nil {
		return discoverysource.PageCommitResult{}, false, err
	}
	if locked.Run.StageCode == "NORMALIZING" {
		var nextVersion int64
		if err := tx.QueryRow(ctx, advancePageRunStageSQL,
			locked.Run.TenantID, locked.Run.WorkspaceID, locked.Run.SourceID, locked.Run.ID,
			locked.Run.Version, locked.Run.LeaseOwner, locked.Run.FenceEpoch, locked.Run.FenceTokenSHA256,
		).Scan(&nextVersion); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return discoverysource.PageCommitResult{}, false, discoverysource.ErrPageCommitConflict
			}
			return discoverysource.PageCommitResult{}, false, err
		} else if nextVersion != locked.Run.Version+1 {
			return discoverysource.PageCommitResult{}, false, discoverysource.ErrPageCommitConflict
		}
		locked.Run.Version = nextVersion
		locked.Run.StageCode = "APPLYING"
	}
	var acceptedAt time.Time
	if err := tx.QueryRow(ctx, `SELECT transaction_timestamp()`).Scan(&acceptedAt); err != nil {
		return discoverysource.PageCommitResult{}, false, err
	}
	acceptedAt = canonicalDatabaseTime(acceptedAt)
	projection, err := projectDiscoveryPage(
		ctx, tx, locked, coordinates, page, acceptedAt, ids, committer.repository.newID,
	)
	if err != nil {
		return discoverysource.PageCommitResult{}, false, err
	}
	pageDigest := committedPageDigest(
		locked, coordinates, page, acceptedAt, sealed, projection, semanticIdentity,
	)
	result := discoverysource.PageCommitResult{
		RunID: coordinates.RunID, PageSequence: coordinates.PageSequence,
		CheckpointVersion: sealed.CheckpointVersion, CheckpointSHA256: sealed.CheckpointSHA256,
		PageDigestSHA256: pageDigest, RelationPageDigestSHA256: projection.RelationPageDigest,
		FinalPage: page.FinalPage, CompleteSnapshot: page.CompleteSnapshot,
	}
	if err := insertPageReceipts(
		ctx, tx, ids, locked, coordinates, result, semanticIdentity, aad,
	); err != nil {
		return discoverysource.PageCommitResult{}, false, err
	}
	var sourceVersion int64
	if err := tx.QueryRow(ctx, advancePageSourceCheckpointSQL,
		locked.Source.TenantID, locked.Source.WorkspaceID, locked.Source.ID, locked.Source.Version,
		sealed.Envelope, sealed.CheckpointKeyID, sealed.CheckpointSHA256,
		locked.Revision.Revision, sealed.CheckpointVersion, locked.Revision.CanonicalRevisionDigest,
		locked.Source.CheckpointVersion, nullablePageString(locked.Source.CheckpointSHA256),
		locked.Source.GateStatus, locked.Source.GateRevision,
	).Scan(&sourceVersion); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return discoverysource.PageCommitResult{}, false, discoverysource.ErrPageCommitConflict
		}
		return discoverysource.PageCommitResult{}, false, err
	} else if sourceVersion != locked.Source.Version+1 {
		return discoverysource.PageCommitResult{}, false, discoverysource.ErrPageCommitConflict
	}
	status, stage := "RUNNING", "READING"
	var workKind, workStatus, workDigest any
	effectiveComplete := false
	if page.FinalPage {
		status, stage = "FINALIZING", "CLEANING_UP"
		workKind, workDigest = "DATA_PROJECTION", pageDigest
		if locked.Run.Rejected+projection.Counts.Rejected == 0 {
			workStatus = "SUCCEEDED"
		} else {
			workStatus = "PARTIAL"
		}
		effectiveComplete = page.CompleteSnapshot && locked.Run.Rejected+projection.Counts.Rejected == 0
	}
	var runVersion, cumulativeRejected int64
	if err := tx.QueryRow(ctx, advancePageRunSQL,
		locked.Run.TenantID, locked.Run.WorkspaceID, locked.Run.SourceID, locked.Run.ID,
		status, stage, coordinates.PageSequence, pageDigest, projection.RelationPageDigest,
		sealed.CheckpointVersion, sealed.CheckpointSHA256,
		projection.Counts.Observed, projection.Counts.Created, projection.Counts.Changed,
		projection.Counts.Unchanged, projection.Counts.Conflict, projection.Counts.Missing,
		projection.Counts.Stale, projection.Counts.Restored, projection.Counts.Tombstoned,
		projection.Counts.Rejected, page.FinalPage, page.CompleteSnapshot, effectiveComplete,
		workKind, workStatus, workDigest,
		locked.Run.PageSequence, locked.Run.RelationPageSequence, locked.Run.CheckpointVersion,
		locked.Run.Version, locked.Run.LeaseOwner, locked.Run.FenceEpoch, locked.Run.FenceTokenSHA256,
	).Scan(&runVersion, &cumulativeRejected); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return discoverysource.PageCommitResult{}, false, discoverysource.ErrPageCommitConflict
		}
		return discoverysource.PageCommitResult{}, false, err
	} else if runVersion != locked.Run.Version+1 ||
		cumulativeRejected != locked.Run.Rejected+projection.Counts.Rejected {
		return discoverysource.PageCommitResult{}, false, discoverysource.ErrPageCommitConflict
	}
	var persistedRunID, persistedOwner, persistedFenceHash string
	var persistedEpoch int64
	if err := tx.QueryRow(ctx, recheckPageFenceSQL,
		locked.Run.TenantID, locked.Run.WorkspaceID, locked.Run.SourceID, locked.Run.ID,
		sealed.CheckpointVersion, coordinates.PageSequence, sealed.CheckpointSHA256,
	).Scan(&persistedRunID, &persistedOwner, &persistedEpoch, &persistedFenceHash); err != nil ||
		!fence.Matches(persistedRunID, persistedOwner, persistedEpoch, persistedFenceHash) {
		return discoverysource.PageCommitResult{}, false, discoverysource.ErrPageCommitConflict
	}
	return result, false, nil
}

func (committer *PageCommitter) replayReceipt(
	ctx context.Context,
	coordinates discoverysource.PageCommitCoordinates,
	page discoverysource.Page,
	receipt pageReceipt,
) (discoverysource.PageCommitResult, error) {
	if page.NextCheckpoint.ProfileCode() != receipt.Details.ProfileCode {
		return discoverysource.PageCommitResult{}, discoverysource.ErrPageCommitInvalid
	}
	aad := discoverycheckpoint.CheckpointAAD{
		TenantID: coordinates.Locator.Scope.TenantID, WorkspaceID: coordinates.Locator.Scope.WorkspaceID,
		SourceID: coordinates.Locator.SourceID, ProviderKind: receipt.Details.ProviderKind,
		CheckpointRevision:      receipt.Details.CheckpointRevision,
		CanonicalRevisionDigest: receipt.Details.CanonicalRevisionDigest,
		SourceDefinitionDigest:  receipt.Details.SourceDefinitionDigest,
		CheckpointKeyID:         receipt.Details.CheckpointKeyID,
		CheckpointVersion:       receipt.Details.Result.CheckpointVersion,
	}
	replayIdentity, err := committer.codec.ReplayIdentity(ctx, aad, page.NextCheckpoint)
	if err != nil {
		return discoverysource.PageCommitResult{}, collapsePageCodecError(err)
	}
	identity, err := pageSemanticIdentity(coordinates, page, replayIdentity)
	if err != nil {
		return discoverysource.PageCommitResult{}, discoverysource.ErrPageCommitInvalid
	}
	if identity != receipt.Details.SemanticIdentitySHA256 ||
		receipt.PayloadHash != receipt.Details.Result.PageDigestSHA256 {
		return discoverysource.PageCommitResult{}, discoverysource.ErrPageCommitConflict
	}
	return discoverysource.PageCommitResult{
		RunID: coordinates.RunID, PageSequence: coordinates.PageSequence,
		CheckpointVersion:        receipt.Details.Result.CheckpointVersion,
		CheckpointSHA256:         receipt.Details.Result.CheckpointSHA256,
		PageDigestSHA256:         receipt.Details.Result.PageDigestSHA256,
		RelationPageDigestSHA256: receipt.Details.Result.RelationPageDigestSHA256,
		FinalPage:                receipt.Details.Result.FinalPage,
		CompleteSnapshot:         receipt.Details.Result.CompleteSnapshot,
		Replayed:                 true,
	}, nil
}

func (committer *PageCommitter) authorizeCrossEnvironmentRelations(
	ctx context.Context,
	revision assetcatalog.SourceRevision,
	relations []assetdiscovery.ObservedRelation,
) error {
	for _, relation := range relations {
		if relation.SourceEnvironmentID == relation.TargetEnvironmentID {
			continue
		}
		expected, err := committer.policyResolver.ResolveCrossEnvironmentRelationPolicy(
			ctx,
			revision.Clone(),
			discoverysource.CrossEnvironmentRelationPolicyCoordinates{
				SourceEnvironmentID: relation.SourceEnvironmentID,
				TargetEnvironmentID: relation.TargetEnvironmentID,
				RelationshipType:    relation.Type,
				ProviderPathCode:    relation.ProviderPathCode,
			},
		)
		if err != nil || expected == "" || !expected.Valid() {
			return discoverysource.ErrPageCommitUnavailable
		}
		if expected != relation.CrossEnvironmentPolicyReferenceID {
			return discoverysource.ErrPageCommitInvalid
		}
	}
	return nil
}

func loadPageAdmission(
	ctx context.Context,
	database pageDB,
	coordinates discoverysource.PageCommitCoordinates,
	locked bool,
) (pageAdmission, error) {
	if database == nil {
		return pageAdmission{}, pgx.ErrNoRows
	}
	runSQL, sourceSQL, revisionSQL, authoritySQL := selectPageRunSQL, selectPageSourceSQL,
		pageRevisionSQL(false), pageAuthoritySQL(false)
	if locked {
		runSQL, sourceSQL, revisionSQL, authoritySQL = selectPageRunForUpdateSQL,
			selectPageSourceForUpdateSQL, pageRevisionSQL(true), pageAuthoritySQL(true)
	}
	var admission pageAdmission
	if err := scanPageRun(database.QueryRow(
		ctx, runSQL, coordinates.Locator.Scope.TenantID, coordinates.Locator.Scope.WorkspaceID,
		coordinates.Locator.SourceID, coordinates.RunID,
	), &admission.Run); err != nil {
		return pageAdmission{}, err
	}
	if err := scanPageSource(database.QueryRow(
		ctx, sourceSQL, coordinates.Locator.Scope.TenantID, coordinates.Locator.Scope.WorkspaceID,
		coordinates.Locator.SourceID,
	), &admission.Source); err != nil {
		return pageAdmission{}, err
	}
	if err := scanPageRevision(database.QueryRow(
		ctx, revisionSQL, coordinates.Locator.Scope.TenantID, coordinates.Locator.Scope.WorkspaceID,
		coordinates.Locator.SourceID, admission.Run.SourceRevision,
	), &admission.Revision); err != nil {
		return pageAdmission{}, err
	}
	rows, err := database.Query(
		ctx, authoritySQL, coordinates.Locator.Scope.TenantID, coordinates.Locator.Scope.WorkspaceID,
		coordinates.Locator.SourceID, admission.Run.SourceRevision,
	)
	if err != nil {
		return pageAdmission{}, err
	}
	defer rows.Close()
	ordinal := 0
	for rows.Next() {
		var environmentID string
		var candidateOrdinal int
		if err := rows.Scan(&environmentID, &candidateOrdinal); err != nil {
			return pageAdmission{}, err
		}
		ordinal++
		if candidateOrdinal != ordinal {
			return pageAdmission{}, discoverysource.ErrPageCommitConflict
		}
		admission.Revision.AuthorityEnvironmentIDs = append(
			admission.Revision.AuthorityEnvironmentIDs, environmentID,
		)
	}
	if err := rows.Err(); err != nil {
		return pageAdmission{}, err
	}
	return admission, nil
}

func scanPageRun(row pgx.Row, run *pageRunState) error {
	var cursorBefore, cursorAfter, pageDigest, relationDigest *string
	var leaseOwner, fenceHash, rolloverReason, rolloverEvidence *string
	if err := row.Scan(
		&run.ID, &run.TenantID, &run.WorkspaceID, &run.SourceID,
		&run.SourceRevision, &run.SourceRevisionDigest, &run.RunKind, &run.Status, &run.StageCode,
		&run.GateRevision, &cursorBefore, &cursorAfter, &run.PageSequence, &pageDigest,
		&run.RelationPageSequence, &relationDigest, &run.FinalPage, &run.CompleteSnapshot,
		&run.EffectiveComplete, &run.CheckpointVersion, &leaseOwner, &run.LeaseExpiresAt,
		&run.LeaseCurrent,
		&run.FenceEpoch, &fenceHash, &run.HeartbeatSequence,
		&run.Observed, &run.Created, &run.Changed, &run.Unchanged, &run.Conflict,
		&run.Missing, &run.Stale, &run.Restored, &run.Tombstoned, &run.Rejected,
		&rolloverReason, &rolloverEvidence, &run.Version,
	); err != nil {
		return err
	}
	run.CursorBeforeSHA256 = optionalString(cursorBefore)
	run.CursorAfterSHA256 = optionalString(cursorAfter)
	run.PageDigest = optionalString(pageDigest)
	run.RelationPageDigest = optionalString(relationDigest)
	run.LeaseOwner = optionalString(leaseOwner)
	run.FenceTokenSHA256 = optionalString(fenceHash)
	run.LineageRolloverReason = optionalString(rolloverReason)
	run.LineageRolloverEvidenceSHA256 = optionalString(rolloverEvidence)
	run.LeaseExpiresAt = canonicalDatabaseTime(run.LeaseExpiresAt)
	return nil
}

func scanPageSource(row pgx.Row, source *pageSourceState) error {
	var publishedRevision *int64
	var publishedDigest, gateReason, checkpointKey, checkpointSHA *string
	if err := row.Scan(
		&source.ID, &source.TenantID, &source.WorkspaceID, &source.SourceKind,
		&source.ProviderKind, &source.Status, &publishedRevision, &publishedDigest,
		&source.GateStatus, &gateReason, &source.GateRevision,
		&source.CheckpointCiphertext, &checkpointKey, &checkpointSHA,
		&source.CheckpointRevision, &source.CheckpointVersion, &source.Version,
	); err != nil {
		return err
	}
	if publishedRevision == nil || publishedDigest == nil {
		return pgx.ErrNoRows
	}
	source.PublishedRevision = *publishedRevision
	source.PublishedRevisionDigest = *publishedDigest
	source.GateReason = optionalString(gateReason)
	source.CheckpointKeyID = optionalString(checkpointKey)
	source.CheckpointSHA256 = optionalString(checkpointSHA)
	source.CheckpointCiphertext = bytes.Clone(source.CheckpointCiphertext)
	return nil
}

func scanPageRevision(row pgx.Row, revision *assetcatalog.SourceRevision) error {
	var integrationID, credentialID, trustID, networkID *string
	var schedule, extensionCode, extensionDigest *string
	var validationRunID, validationDigest *string
	if err := row.Scan(
		&revision.ID, &revision.SourceID, &revision.TenantID, &revision.WorkspaceID,
		&revision.Revision, &revision.Status, &revision.CanonicalProfileManifest,
		&revision.ProfileManifestSHA256, &revision.CanonicalProviderSchema,
		&revision.CanonicalProviderSchemaSHA256, &revision.SourceDefinitionDigest,
		&revision.CanonicalRevisionDigest, &integrationID, &revision.SyncMode,
		&credentialID, &trustID, &networkID, &revision.AuthorityScopeDigest,
		&revision.RateLimitRequests, &revision.RateLimitWindowSeconds,
		&revision.BackpressureBaseSeconds, &revision.BackpressureMaxSeconds,
		&revision.ProfileCode, &schedule, &extensionCode, &extensionDigest,
		&validationRunID, &validationDigest, &revision.CreatedBy,
		&revision.ChangeReasonCode, &revision.ExpectedSourceVersion, &revision.Version,
		&revision.CreatedAt, &revision.UpdatedAt,
	); err != nil {
		return err
	}
	revision.IntegrationID = optionalString(integrationID)
	revision.CredentialReferenceID = assetcatalog.CredentialReferenceID(optionalString(credentialID))
	revision.TrustReferenceID = assetcatalog.TrustReferenceID(optionalString(trustID))
	revision.NetworkPolicyReferenceID = assetcatalog.NetworkPolicyReferenceID(optionalString(networkID))
	revision.ScheduleExpression = optionalString(schedule)
	revision.TypedExtensionCode = assetcatalog.ExtensionCode(optionalString(extensionCode))
	revision.PreparedExtensionDigest = optionalString(extensionDigest)
	revision.ValidationRunID = optionalString(validationRunID)
	revision.ValidationDigest = optionalString(validationDigest)
	revision.CanonicalProfileManifest = bytes.Clone(revision.CanonicalProfileManifest)
	revision.CanonicalProviderSchema = bytes.Clone(revision.CanonicalProviderSchema)
	revision.CreatedAt = canonicalDatabaseTime(revision.CreatedAt)
	revision.UpdatedAt = canonicalDatabaseTime(revision.UpdatedAt)
	return nil
}

func pageRevisionSQL(locked bool) string {
	query := `
SELECT revision.id::text,revision.source_id::text,revision.tenant_id::text,
       revision.workspace_id::text,revision.revision,revision.state,
       revision.canonical_profile_manifest,revision.profile_manifest_sha256,
       revision.canonical_provider_schema,revision.canonical_provider_schema_sha256,
       revision.source_definition_digest,revision.canonical_revision_digest,
       revision.integration_id::text,revision.sync_mode,revision.credential_reference_id,
       revision.trust_reference_id,revision.network_policy_reference_id,
       revision.authority_scope_digest,revision.rate_limit_requests,
       revision.rate_limit_window_seconds,revision.backpressure_base_seconds,
       revision.backpressure_max_seconds,revision.profile_code,revision.schedule_expression,
       revision.typed_extension_code,revision.prepared_extension_digest,
       revision.validation_run_id::text,revision.validation_digest,
       revision.created_by,revision.change_reason_code,revision.expected_source_version,
       revision.version,revision.created_at,revision.updated_at
FROM asset_source_revisions AS revision
WHERE revision.tenant_id=$1::uuid AND revision.workspace_id=$2::uuid
  AND revision.source_id=$3::uuid AND revision.revision=$4`
	if locked {
		query += ` FOR SHARE`
	}
	return query
}

func pageAuthoritySQL(_ bool) string {
	// The exact published parent Revision is locked above. Authority children
	// are then read in canonical order from the same SERIALIZABLE snapshot; the
	// schema permits their insertion only with a same-transaction DRAFT/version=1
	// parent and rejects every later UPDATE, DELETE, or TRUNCATE.
	return `
SELECT authority.environment_id::text,authority.canonical_ordinal
FROM asset_source_revision_authorities AS authority
WHERE authority.tenant_id=$1::uuid AND authority.workspace_id=$2::uuid
  AND authority.source_id=$3::uuid AND authority.source_revision=$4
ORDER BY authority.canonical_ordinal,authority.environment_id`
}

func validatePageAdmission(
	admission pageAdmission,
	coordinates discoverysource.PageCommitCoordinates,
	fence assetcatalog.LeaseFence,
) error {
	run, source, revision := admission.Run, admission.Source, admission.Revision
	if run.ID != coordinates.RunID || run.TenantID != coordinates.Locator.Scope.TenantID ||
		run.WorkspaceID != coordinates.Locator.Scope.WorkspaceID || run.SourceID != coordinates.Locator.SourceID ||
		run.RunKind == string(assetcatalog.RunKindValidation) || run.Status != string(assetcatalog.RunStatusRunning) ||
		(run.StageCode != string(assetcatalog.RunStageNormalizing) && run.StageCode != string(assetcatalog.RunStageApplying)) ||
		run.FinalPage || run.PageSequence+1 != coordinates.PageSequence ||
		run.RelationPageSequence != run.PageSequence || run.CheckpointVersion != source.CheckpointVersion {
		return discoverysource.ErrPageCommitConflict
	}
	if run.SourceRevision != source.PublishedRevision || run.SourceRevisionDigest != source.PublishedRevisionDigest ||
		run.SourceRevision != revision.Revision || run.SourceRevisionDigest != revision.CanonicalRevisionDigest ||
		source.Status != string(assetcatalog.SourceStatusActive) ||
		!validPageLineageState(source, run) || revision.Status != assetcatalog.SourceRevisionPublished ||
		source.CheckpointRevision != revision.Revision || source.ProviderKind == "" ||
		source.ProviderKind != manifestProviderKind(revision.CanonicalProfileManifest) ||
		revision.Validate() != nil || !validCheckpointBefore(source, run) {
		return discoverysource.ErrPageCommitConflict
	}
	if run.LeaseOwner == "" || run.FenceEpoch <= 0 || !validSHA256(run.FenceTokenSHA256) ||
		!run.LeaseCurrent ||
		!fence.Matches(run.ID, run.LeaseOwner, run.FenceEpoch, run.FenceTokenSHA256) {
		return discoverysource.ErrPageCommitConflict
	}
	return nil
}

func validPageLineageState(source pageSourceState, run pageRunState) bool {
	normal := source.GateStatus == string(assetcatalog.SourceGateAvailable) &&
		source.GateReason == "" && source.GateRevision == run.GateRevision &&
		run.LineageRolloverReason == "" && run.LineageRolloverEvidenceSHA256 == ""
	rollover := source.GateStatus == string(assetcatalog.SourceGateDegraded) &&
		source.GateReason == "CHECKPOINT_LINEAGE_ROLLOVER" &&
		source.GateRevision == run.GateRevision+1 &&
		run.LineageRolloverReason != "" && validSHA256(run.LineageRolloverEvidenceSHA256)
	return normal || rollover
}

func validCheckpointBefore(source pageSourceState, run pageRunState) bool {
	expected := run.CursorAfterSHA256
	if expected == "" {
		expected = run.CursorBeforeSHA256
	}
	if source.CheckpointSHA256 != expected {
		return false
	}
	if source.CheckpointVersion == 0 {
		return len(source.CheckpointCiphertext) == 0 && source.CheckpointKeyID == "" && source.CheckpointSHA256 == ""
	}
	return len(source.CheckpointCiphertext) > 0 && source.CheckpointKeyID != "" && validSHA256(source.CheckpointSHA256)
}

func exactPageFactPolicy(admission pageAdmission, policy assetdiscovery.FactPolicy) bool {
	var manifest struct {
		ProviderKind       string                              `json:"provider_kind"`
		ProfileCode        assetcatalog.ProfileCode            `json:"profile_code"`
		FreshnessKind      assetcatalog.FreshnessKind          `json:"freshness_kind"`
		EnvironmentMapping assetcatalog.EnvironmentMappingMode `json:"environment_mapping_mode"`
		TrustedPathCodes   []string                            `json:"trusted_path_codes"`
		RelationshipTypes  []assetcatalog.RelationshipType     `json:"relationship_types"`
	}
	if json.Unmarshal(admission.Revision.CanonicalProfileManifest, &manifest) != nil {
		return false
	}
	return manifest.ProviderKind == admission.Source.ProviderKind &&
		manifest.ProfileCode == admission.Revision.ProfileCode &&
		policy.ProviderKind == manifest.ProviderKind && policy.FreshnessKind == manifest.FreshnessKind &&
		policy.EnvironmentMapping == manifest.EnvironmentMapping &&
		slices.Equal(policy.AuthorityEnvironmentIDs, admission.Revision.AuthorityEnvironmentIDs) &&
		slices.Equal(policy.TrustedPathCodes, manifest.TrustedPathCodes) &&
		slices.Equal(policy.RelationshipTypes, manifest.RelationshipTypes)
}

func manifestProviderKind(manifest []byte) string {
	var value struct {
		ProviderKind string `json:"provider_kind"`
	}
	if json.Unmarshal(manifest, &value) != nil {
		return ""
	}
	return value.ProviderKind
}

func checkpointAAD(admission pageAdmission, keyID string) discoverycheckpoint.CheckpointAAD {
	return discoverycheckpoint.CheckpointAAD{
		TenantID: admission.Run.TenantID, WorkspaceID: admission.Run.WorkspaceID,
		SourceID: admission.Run.SourceID, ProviderKind: admission.Source.ProviderKind,
		CheckpointRevision:      admission.Revision.Revision,
		CanonicalRevisionDigest: admission.Revision.CanonicalRevisionDigest,
		SourceDefinitionDigest:  admission.Revision.SourceDefinitionDigest,
		CheckpointKeyID:         keyID, CheckpointVersion: admission.Run.CheckpointVersion + 1,
	}
}

func readPageReceipt(
	ctx context.Context,
	database interface {
		QueryRow(context.Context, string, ...any) pgx.Row
	},
	coordinates discoverysource.PageCommitCoordinates,
) (pageReceipt, bool, error) {
	requestID := "source-page:" + coordinates.RunID + ":" + strconv.FormatInt(coordinates.PageSequence, 10)
	var action, resourceType, resourceID, payloadHash string
	var detailsJSON []byte
	err := database.QueryRow(
		ctx, selectPageReceiptSQL, coordinates.Locator.Scope.TenantID,
		coordinates.Locator.Scope.WorkspaceID, requestID,
	).Scan(&action, &resourceType, &resourceID, &payloadHash, &detailsJSON)
	if errors.Is(err, pgx.ErrNoRows) {
		return pageReceipt{}, false, nil
	}
	if err != nil {
		return pageReceipt{}, false, discoverysource.ErrPageCommitUnavailable
	}
	if action != pageReceiptAction || resourceType != "ASSET_SOURCE_RUN" ||
		resourceID != coordinates.RunID || !validSHA256(payloadHash) {
		return pageReceipt{}, false, discoverysource.ErrPageCommitUnavailable
	}
	decoder := json.NewDecoder(bytes.NewReader(detailsJSON))
	decoder.DisallowUnknownFields()
	var details pageReceiptDetails
	if decoder.Decode(&details) != nil || !details.ProfileCode.Valid() ||
		!validSHA256(details.SemanticIdentitySHA256) || details.ProviderKind == "" ||
		details.CheckpointRevision <= 0 || !validSHA256(details.CanonicalRevisionDigest) ||
		!validSHA256(details.SourceDefinitionDigest) || details.CheckpointKeyID == "" ||
		details.Result.CheckpointVersion <= 0 || !validSHA256(details.Result.CheckpointSHA256) ||
		!validSHA256(details.Result.PageDigestSHA256) ||
		!validSHA256(details.Result.RelationPageDigestSHA256) ||
		details.Result.CompleteSnapshot && !details.Result.FinalPage {
		return pageReceipt{}, false, discoverysource.ErrPageCommitUnavailable
	}
	return pageReceipt{PayloadHash: payloadHash, Details: details}, true, nil
}

func insertPageReceipts(
	ctx context.Context,
	tx pgx.Tx,
	ids pageProjectionIDs,
	admission pageAdmission,
	coordinates discoverysource.PageCommitCoordinates,
	result discoverysource.PageCommitResult,
	semanticIdentity string,
	aad discoverycheckpoint.CheckpointAAD,
) error {
	details := pageReceiptDetails{
		ProfileCode: admission.Revision.ProfileCode, SemanticIdentitySHA256: semanticIdentity,
		ProviderKind: admission.Source.ProviderKind, CheckpointRevision: aad.CheckpointRevision,
		CanonicalRevisionDigest: aad.CanonicalRevisionDigest,
		SourceDefinitionDigest:  aad.SourceDefinitionDigest, CheckpointKeyID: aad.CheckpointKeyID,
		Result: pageReceiptResult{
			CheckpointVersion: result.CheckpointVersion, CheckpointSHA256: result.CheckpointSHA256,
			PageDigestSHA256:         result.PageDigestSHA256,
			RelationPageDigestSHA256: result.RelationPageDigestSHA256,
			FinalPage:                result.FinalPage, CompleteSnapshot: result.CompleteSnapshot,
		},
	}
	detailsJSON, err := canonicalJSON(details)
	if err != nil {
		return discoverysource.ErrPageCommitUnavailable
	}
	requestID := "source-page:" + coordinates.RunID + ":" + strconv.FormatInt(coordinates.PageSequence, 10)
	relationRequestID := "source-relation-page:" + coordinates.RunID + ":" + strconv.FormatInt(coordinates.PageSequence, 10)
	if _, err := tx.Exec(ctx, `
INSERT INTO audit_records (
 id,tenant_id,workspace_id,actor_type,actor_id,action,resource_type,
 resource_id,request_id,trace_id,payload_hash,details
) VALUES ($1::uuid,$2::uuid,$3::uuid,'SYSTEM',$4,$5,'ASSET_SOURCE_RUN',$6,$7,NULL,$8,$9::jsonb)
`, ids.PageAuditID, admission.Run.TenantID, admission.Run.WorkspaceID,
		admission.Run.LeaseOwner, pageReceiptAction, admission.Run.ID, requestID,
		result.PageDigestSHA256, string(detailsJSON)); err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `
INSERT INTO audit_records (
 id,tenant_id,workspace_id,actor_type,actor_id,action,resource_type,
 resource_id,request_id,trace_id,payload_hash,details
) VALUES ($1::uuid,$2::uuid,$3::uuid,'SYSTEM',$4,$5,'ASSET_SOURCE_RUN',$6,$7,NULL,$8,'{}'::jsonb)
`, ids.RelationAuditID, admission.Run.TenantID, admission.Run.WorkspaceID,
		admission.Run.LeaseOwner, relationPageReceiptAction, admission.Run.ID,
		relationRequestID, result.RelationPageDigestSHA256)
	return err
}

func validPageCommitShape(
	coordinates discoverysource.PageCommitCoordinates,
	page discoverysource.Page,
) bool {
	return coordinates.Locator.Scope.Valid() && validUUID(coordinates.Locator.SourceID) &&
		validUUID(coordinates.RunID) && coordinates.PageSequence > 0 &&
		page.NextCheckpoint.ProfileCode().Valid() &&
		(!page.CompleteSnapshot || page.FinalPage) &&
		(len(page.Items) != 0 || len(page.Relations) != 0 || page.FinalPage && page.CompleteSnapshot)
}

func cloneDiscoveryPage(page discoverysource.Page) discoverysource.Page {
	page.NextCheckpoint = page.NextCheckpoint.Clone()
	page.Items = slices.Clone(page.Items)
	for index := range page.Items {
		page.Items[index].Document = bytes.Clone(page.Items[index].Document)
		page.Items[index].FieldProvenance = slices.Clone(page.Items[index].FieldProvenance)
		if page.Items[index].Fingerprints != nil {
			fingerprints := page.Items[index].Fingerprints
			page.Items[index].Fingerprints = make(map[string]string, len(fingerprints))
			for key, value := range fingerprints {
				page.Items[index].Fingerprints[key] = value
			}
		}
		if page.Items[index].Freshness.OrderTime != nil {
			value := *page.Items[index].Freshness.OrderTime
			page.Items[index].Freshness.OrderTime = &value
		}
	}
	page.Relations = slices.Clone(page.Relations)
	for index := range page.Relations {
		if page.Relations[index].Freshness.OrderTime != nil {
			value := *page.Relations[index].Freshness.OrderTime
			page.Relations[index].Freshness.OrderTime = &value
		}
	}
	return page
}

func interfaceIsNil(value any) bool {
	candidate := reflect.ValueOf(value)
	switch candidate.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return candidate.IsNil()
	default:
		return false
	}
}

func nullablePageString(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func collapsePageCodecError(err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	if errors.Is(err, discoverycheckpoint.ErrInvalidInput) {
		return discoverysource.ErrPageCommitInvalid
	}
	return discoverysource.ErrPageCommitUnavailable
}

func collapsePageAdmissionError(err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	for _, stable := range []error{
		discoverysource.ErrPageCommitInvalid,
		discoverysource.ErrPageCommitConflict,
		discoverysource.ErrPageCommitUnavailable,
	} {
		if errors.Is(err, stable) {
			return stable
		}
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return discoverysource.ErrPageCommitConflict
	}
	return discoverysource.ErrPageCommitUnavailable
}

func collapsePageAttemptError(err error) error {
	if errors.Is(err, errPageAcceptanceTimeRetry) {
		return discoverysource.ErrPageCommitConflict
	}
	for _, stable := range []error{
		discoverysource.ErrPageCommitInvalid,
		discoverysource.ErrPageCommitConflict,
		discoverysource.ErrPageCommitUnavailable,
		context.Canceled,
		context.DeadlineExceeded,
	} {
		if errors.Is(err, stable) {
			return stable
		}
	}
	if isRetryablePGError(err) {
		return discoverysource.ErrPageCommitConflict
	}
	return discoverysource.ErrPageCommitUnavailable
}

func retryablePageCommitAttempt(err error) bool {
	return errors.Is(err, errPageAcceptanceTimeRetry) || isRetryablePGError(err)
}
