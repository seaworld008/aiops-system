package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"reflect"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/seaworld008/aiops-system/internal/assetcatalog"
	"github.com/seaworld008/aiops-system/internal/discoverylimit"
	"github.com/seaworld008/aiops-system/internal/domain"
)

const serializableAttempts = 3

type Limiter struct {
	pool            *pgxpool.Pool
	profileResolver assetcatalog.SourceProfileAdmissionResolver
	newID           func() string
}

func New(
	pool *pgxpool.Pool,
	profileResolver assetcatalog.SourceProfileAdmissionResolver,
) (*Limiter, error) {
	return newLimiter(pool, profileResolver, uuid.NewString)
}

func newLimiter(
	pool *pgxpool.Pool,
	profileResolver assetcatalog.SourceProfileAdmissionResolver,
	newID func() string,
) (*Limiter, error) {
	if pool == nil || profileResolver == nil || interfaceIsNil(profileResolver) || newID == nil {
		return nil, discoverylimit.ErrInvalidRequest
	}
	return &Limiter{pool: pool, profileResolver: profileResolver, newID: newID}, nil
}

func (limiter *Limiter) Acquire(
	ctx context.Context,
	command discoverylimit.AcquireCommand,
) (discoverylimit.Permit, error) {
	if err := command.Validate(); err != nil {
		return discoverylimit.Permit{}, err
	}
	commandSHA256 := acquireCommandDigest(command)
	outcome, err := withSerializable(ctx, limiter.pool,
		func(tx pgx.Tx) (committedOutcome[discoverylimit.Permit], error) {
			if err := pinTransaction(ctx, tx); err != nil {
				return committedOutcome[discoverylimit.Permit]{}, err
			}
			replay, found, err := loadRecordByRequest(
				ctx, tx, command.Coordinates.Scope, command.RequestID,
			)
			if err != nil {
				return committedOutcome[discoverylimit.Permit]{}, err
			}
			if found {
				if replay.kind != recordAcquire || replay.commandSHA256 != commandSHA256 ||
					replay.coordinates != command.Coordinates {
					return committedOutcome[discoverylimit.Permit]{}, discoverylimit.ErrIdempotency
				}
				return committedOutcome[discoverylimit.Permit]{value: replay.permit()}, nil
			}

			admission, err := lockAdmission(ctx, tx, command.Coordinates)
			if err != nil {
				return committedOutcome[discoverylimit.Permit]{}, err
			}
			buckets, err := limiter.ensureAndLockBuckets(ctx, tx, command.Coordinates, admission.now)
			if err != nil {
				return committedOutcome[discoverylimit.Permit]{}, err
			}
			if err := limiter.validateInstalledProfile(ctx, admission); err != nil {
				return committedOutcome[discoverylimit.Permit]{}, err
			}
			admission.now, err = revalidateAdmission(ctx, tx, command.Coordinates)
			if err != nil {
				return committedOutcome[discoverylimit.Permit]{}, err
			}
			admission.rateRequests = min(
				admission.rateRequests, discoverylimit.MaxRateLimitRequests,
			)
			admission.rateWindowSeconds = min(
				admission.rateWindowSeconds, discoverylimit.MaxRateLimitWindowSeconds,
			)
			if err := limiter.expireStalePermits(
				ctx, tx, command.Coordinates.Scope, command.Coordinates.SourceID,
				command.Coordinates.ProviderKind, admission.now, &buckets,
			); err != nil {
				return committedOutcome[discoverylimit.Permit]{}, err
			}
			limited, err := limiterLimited(ctx, tx, command.Coordinates.Scope, admission, buckets)
			if err != nil {
				return committedOutcome[discoverylimit.Permit]{}, err
			}
			if limited {
				return committedOutcome[discoverylimit.Permit]{
					postCommitErr: discoverylimit.ErrLimited,
				}, nil
			}

			permitID := limiter.newID()
			if !validUUID(permitID) {
				return committedOutcome[discoverylimit.Permit]{}, discoverylimit.ErrUnavailable
			}
			record := permitRecord{
				id: permitID, permitID: permitID, kind: recordAcquire,
				coordinates:    command.Coordinates,
				sourceBucketID: buckets[0].id, workspaceBucketID: buckets[1].id,
				providerBucketID: buckets[2].id,
				requestID:        command.RequestID, commandSHA256: commandSHA256,
				acquiredAt: admission.now, expiresAt: admission.now.Add(command.TTL),
				createdAt: admission.now,
			}
			record.receiptSHA256 = record.digest()
			if err := insertRecord(ctx, tx, record); err != nil {
				return committedOutcome[discoverylimit.Permit]{}, err
			}
			quantum := tokenQuantum(admission.rateRequests, admission.rateWindowSeconds)
			for index := range buckets {
				nextTokenAt := admission.now.Add(quantum)
				if err := updateBucket(ctx, tx, &buckets[index], nextTokenAt, record.id); err != nil {
					return committedOutcome[discoverylimit.Permit]{}, err
				}
			}
			return committedOutcome[discoverylimit.Permit]{value: record.permit()}, nil
		})
	if err != nil {
		return discoverylimit.Permit{}, mapError(err)
	}
	if outcome.postCommitErr != nil {
		return discoverylimit.Permit{}, outcome.postCommitErr
	}
	return outcome.value, nil
}

func (limiter *Limiter) Release(
	ctx context.Context,
	command discoverylimit.ReleaseCommand,
) (discoverylimit.Receipt, error) {
	if err := command.Validate(); err != nil {
		return discoverylimit.Receipt{}, err
	}
	return limiter.terminal(ctx, terminalCommand{
		coordinates: command.Coordinates, permitID: command.PermitID,
		requestID: command.RequestID, reasonCode: command.ReasonCode,
		kind: recordRelease, commandSHA256: releaseCommandDigest(command),
	})
}

func (limiter *Limiter) Delay(
	ctx context.Context,
	command discoverylimit.DelayCommand,
) (discoverylimit.Receipt, error) {
	if err := command.Validate(); err != nil {
		return discoverylimit.Receipt{}, err
	}
	notBefore := command.NotBefore
	return limiter.terminal(ctx, terminalCommand{
		coordinates: command.Coordinates, permitID: command.PermitID,
		requestID: command.RequestID, reasonCode: command.ReasonCode,
		kind: recordDelay, commandSHA256: delayCommandDigest(command),
		notBefore: &notBefore,
	})
}

type terminalCommand struct {
	coordinates   discoverylimit.Coordinates
	permitID      string
	requestID     string
	reasonCode    string
	kind          recordKind
	commandSHA256 string
	notBefore     *time.Time
}

func (limiter *Limiter) terminal(
	ctx context.Context,
	command terminalCommand,
) (discoverylimit.Receipt, error) {
	outcome, err := withSerializable(ctx, limiter.pool,
		func(tx pgx.Tx) (committedOutcome[discoverylimit.Receipt], error) {
			if err := pinTransaction(ctx, tx); err != nil {
				return committedOutcome[discoverylimit.Receipt]{}, err
			}
			replay, found, err := loadRecordByRequest(
				ctx, tx, command.coordinates.Scope, command.requestID,
			)
			if err != nil {
				return committedOutcome[discoverylimit.Receipt]{}, err
			}
			if found {
				if replay.kind != command.kind || replay.commandSHA256 != command.commandSHA256 ||
					replay.coordinates != command.coordinates || replay.permitID != command.permitID {
					return committedOutcome[discoverylimit.Receipt]{}, discoverylimit.ErrIdempotency
				}
				return committedOutcome[discoverylimit.Receipt]{value: replay.receipt()}, nil
			}

			acquire, err := loadAcquire(ctx, tx, command.coordinates, command.permitID)
			if err != nil {
				return committedOutcome[discoverylimit.Receipt]{}, err
			}
			buckets, err := lockPermitBuckets(ctx, tx, acquire)
			if err != nil {
				return committedOutcome[discoverylimit.Receipt]{}, err
			}
			existing, err := loadTerminal(ctx, tx, acquire)
			if err != nil {
				return committedOutcome[discoverylimit.Receipt]{}, err
			}
			if existing {
				return committedOutcome[discoverylimit.Receipt]{}, discoverylimit.ErrStateConflict
			}
			now, err := databaseClock(ctx, tx)
			if err != nil {
				return committedOutcome[discoverylimit.Receipt]{}, err
			}
			if !acquire.expiresAt.After(now) {
				if err := limiter.appendExpiry(ctx, tx, acquire, now, &buckets); err != nil {
					return committedOutcome[discoverylimit.Receipt]{}, err
				}
				return committedOutcome[discoverylimit.Receipt]{
					postCommitErr: discoverylimit.ErrStalePermit,
				}, nil
			}
			if command.notBefore != nil {
				if !command.notBefore.After(now) {
					return committedOutcome[discoverylimit.Receipt]{}, discoverylimit.ErrInvalidRequest
				}
			}
			receiptID := limiter.newID()
			if !validUUID(receiptID) {
				return committedOutcome[discoverylimit.Receipt]{}, discoverylimit.ErrUnavailable
			}
			record := acquire.terminal(
				receiptID, command.kind, command.requestID, command.commandSHA256,
				command.reasonCode, command.notBefore, now,
			)
			if err := insertRecord(ctx, tx, record); err != nil {
				return committedOutcome[discoverylimit.Receipt]{}, err
			}
			for index := range buckets {
				if err := updateBucket(
					ctx, tx, &buckets[index], buckets[index].nextTokenAt, record.id,
				); err != nil {
					return committedOutcome[discoverylimit.Receipt]{}, err
				}
			}
			return committedOutcome[discoverylimit.Receipt]{value: record.receipt()}, nil
		})
	if err != nil {
		return discoverylimit.Receipt{}, mapError(err)
	}
	if outcome.postCommitErr != nil {
		return discoverylimit.Receipt{}, outcome.postCommitErr
	}
	return outcome.value.Clone(), nil
}

type admissionState struct {
	now                                         time.Time
	sourceKind                                  assetcatalog.SourceKind
	providerKind                                string
	profileCode                                 assetcatalog.ProfileCode
	syncMode                                    assetcatalog.SyncMode
	profileManifest, providerSchema             []byte
	profileManifestSHA256, providerSchemaSHA256 string
	rateRequests, rateWindowSeconds             int64
}

const limiterEligibleRunPredicate = `
source.status='ACTIVE'
AND source.source_kind<>'MANUAL'
AND (
  (
    run.run_kind='VALIDATION'
    AND run.stage_code='VALIDATING'
    AND revision.state='VALIDATING'
    AND revision.validation_run_id=run.id
    AND run.checkpoint_version=0
    AND run.cursor_before_sha256 IS NULL
    AND run.cursor_after_sha256 IS NULL
    AND (
      (source.gate_status='UNAVAILABLE' AND source.gate_revision=run.gate_revision)
      OR (
        source.gate_status='VALIDATING'
        AND source.validated_run_id=run.id
        AND source.validation_digest IS NULL
        AND source.validated_binding_digest IS NULL
        AND source.gate_revision=run.gate_revision+1
      )
    )
  )
  OR (
    run.run_kind<>'VALIDATION'
    AND run.stage_code='READING'
    AND revision.state='PUBLISHED'
    AND source.published_revision=run.source_revision
    AND source.published_revision_digest=run.source_revision_digest
    AND source.checkpoint_revision=run.source_revision
    AND source.checkpoint_version=run.checkpoint_version
    AND source.checkpoint_sha256 IS NOT DISTINCT FROM
        COALESCE(run.cursor_after_sha256,run.cursor_before_sha256)
    AND (
      (
        run.lineage_rollover_reason IS NULL
        AND source.gate_status='AVAILABLE'
        AND source.gate_revision=run.gate_revision
      )
      OR (
        run.lineage_rollover_reason IS NOT NULL
        AND source.gate_status='DEGRADED'
        AND source.gate_reason_code='CHECKPOINT_LINEAGE_ROLLOVER'
        AND source.gate_revision=run.gate_revision+1
      )
    )
    AND (
      (source.source_kind='CSV_IMPORT' AND run.run_kind='CSV_IMPORT')
      OR (source.source_kind='CONTROL_PLANE_API' AND run.run_kind='API_INGESTION')
      OR (
        source.source_kind IN (
          'EXTERNAL_CMDB','VSPHERE','PROXMOX','OPENSTACK','CLOUD_PROVIDER',
          'KUBERNETES_OPERATOR','AWX_INVENTORY'
        )
        AND run.run_kind='DISCOVERY'
      )
    )
  )
)
AND (source.next_allowed_at IS NULL OR source.next_allowed_at<=clock_timestamp())
`

const limiterAdmissionFromWhere = `
FROM public.asset_source_runs AS run
JOIN public.asset_sources AS source
  ON source.tenant_id=run.tenant_id
 AND source.workspace_id=run.workspace_id
 AND source.id=run.source_id
JOIN public.asset_source_revisions AS revision
  ON revision.tenant_id=run.tenant_id
 AND revision.workspace_id=run.workspace_id
 AND revision.source_id=run.source_id
 AND revision.revision=run.source_revision
 AND revision.canonical_revision_digest=run.source_revision_digest
WHERE run.tenant_id=$1::uuid AND run.workspace_id=$2::uuid
  AND run.source_id=$3::uuid AND run.id=$4::uuid
  AND source.provider_kind=$5
  AND run.status='RUNNING'
  AND run.lease_owner IS NOT NULL
  AND run.fence_token_hash IS NOT NULL
  AND run.fence_epoch>0
  AND run.lease_expires_at>clock_timestamp()
  AND (` + limiterEligibleRunPredicate + `)
`

const lockAdmissionSQL = `
SELECT clock_timestamp(),source.source_kind,source.provider_kind,
       revision.profile_code,revision.sync_mode,
       revision.canonical_profile_manifest,revision.profile_manifest_sha256,
       revision.canonical_provider_schema,revision.canonical_provider_schema_sha256,
       revision.rate_limit_requests,revision.rate_limit_window_seconds
` + limiterAdmissionFromWhere + `
FOR UPDATE OF run,source,revision
`

func lockAdmission(
	ctx context.Context,
	tx pgx.Tx,
	coordinates discoverylimit.Coordinates,
) (admissionState, error) {
	var state admissionState
	err := tx.QueryRow(ctx, lockAdmissionSQL,
		coordinates.Scope.TenantID, coordinates.Scope.WorkspaceID,
		coordinates.SourceID, coordinates.RunID, coordinates.ProviderKind,
	).Scan(
		&state.now, &state.sourceKind, &state.providerKind,
		&state.profileCode, &state.syncMode,
		&state.profileManifest, &state.profileManifestSHA256,
		&state.providerSchema, &state.providerSchemaSHA256,
		&state.rateRequests, &state.rateWindowSeconds,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return admissionState{}, discoverylimit.ErrIneligible
	}
	if err != nil {
		return admissionState{}, err
	}
	state.now = state.now.UTC()
	if state.rateRequests < 1 || state.rateWindowSeconds < 1 {
		return admissionState{}, discoverylimit.ErrIneligible
	}
	return state, nil
}

func (limiter *Limiter) validateInstalledProfile(
	ctx context.Context,
	state admissionState,
) error {
	profile, err := limiter.profileResolver.ResolveProfileAdmission(ctx, state.profileCode)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return err
		}
		if errors.Is(err, assetcatalog.ErrNotFound) ||
			errors.Is(err, assetcatalog.ErrInvalidRequest) {
			return discoverylimit.ErrIneligible
		}
		return discoverylimit.ErrUnavailable
	}
	manifestSHA256, err := assetcatalog.ProfileManifestDigest(
		profile.CanonicalProfileManifest,
	)
	if err != nil {
		return discoverylimit.ErrIneligible
	}
	schemaDigest := sha256.Sum256(profile.CanonicalProviderSchema)
	schemaSHA256 := hex.EncodeToString(schemaDigest[:])
	if profile.SourceKind != state.sourceKind ||
		profile.ProviderKind != state.providerKind ||
		profile.ProfileCode != state.profileCode ||
		profile.SyncMode != state.syncMode ||
		profile.RateLimitRequests != state.rateRequests ||
		profile.RateLimitWindowSeconds != state.rateWindowSeconds ||
		manifestSHA256 != profile.ProfileManifestSHA256 ||
		manifestSHA256 != state.profileManifestSHA256 ||
		schemaSHA256 != profile.CanonicalProviderSchemaSHA256 ||
		schemaSHA256 != state.providerSchemaSHA256 ||
		!bytes.Equal(profile.CanonicalProfileManifest, state.profileManifest) ||
		!bytes.Equal(profile.CanonicalProviderSchema, state.providerSchema) {
		return discoverylimit.ErrIneligible
	}
	return nil
}

func revalidateAdmission(
	ctx context.Context,
	tx pgx.Tx,
	coordinates discoverylimit.Coordinates,
) (time.Time, error) {
	var now, leaseExpiresAt time.Time
	err := tx.QueryRow(ctx, `
		SELECT clock_timestamp(),run.lease_expires_at
		`+limiterAdmissionFromWhere+`
		FOR UPDATE OF run,source,revision
	`, coordinates.Scope.TenantID, coordinates.Scope.WorkspaceID,
		coordinates.SourceID, coordinates.RunID, coordinates.ProviderKind,
	).Scan(&now, &leaseExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return time.Time{}, discoverylimit.ErrIneligible
	}
	if err != nil {
		return time.Time{}, err
	}
	now = now.UTC()
	leaseExpiresAt = leaseExpiresAt.UTC()
	if !leaseExpiresAt.After(now) {
		return time.Time{}, discoverylimit.ErrIneligible
	}
	return now, nil
}

type bucketState struct {
	id            string
	kind          string
	key           string
	nextTokenAt   time.Time
	lastReceiptID string
	version       int64
}

func (limiter *Limiter) ensureAndLockBuckets(
	ctx context.Context,
	tx pgx.Tx,
	coordinates discoverylimit.Coordinates,
	now time.Time,
) ([3]bucketState, error) {
	specifications := [3]struct {
		kind         string
		key          string
		sourceID     any
		providerKind any
	}{
		{kind: "SOURCE", key: coordinates.SourceID, sourceID: coordinates.SourceID},
		{kind: "WORKSPACE", key: coordinates.Scope.WorkspaceID},
		{kind: "PROVIDER", key: coordinates.ProviderKind, providerKind: coordinates.ProviderKind},
	}
	var buckets [3]bucketState
	for index, specification := range specifications {
		candidateID := limiter.newID()
		if !validUUID(candidateID) {
			return [3]bucketState{}, discoverylimit.ErrUnavailable
		}
		_, err := tx.Exec(ctx, `
			INSERT INTO public.asset_source_limit_buckets(
			  id,tenant_id,workspace_id,bucket_kind,bucket_key,source_id,provider_kind,next_token_at
			) VALUES($1::uuid,$2::uuid,$3::uuid,$4,$5,$6::uuid,$7,$8)
			ON CONFLICT (tenant_id,workspace_id,bucket_kind,bucket_key) DO NOTHING
		`, candidateID, coordinates.Scope.TenantID, coordinates.Scope.WorkspaceID,
			specification.kind, specification.key, specification.sourceID,
			specification.providerKind, now)
		if err != nil {
			return [3]bucketState{}, err
		}
		bucket, err := lockBucket(
			ctx, tx, coordinates.Scope, specification.kind, specification.key,
			specification.sourceID, specification.providerKind,
		)
		if err != nil {
			return [3]bucketState{}, err
		}
		buckets[index] = bucket
	}
	return buckets, nil
}

func lockBucket(
	ctx context.Context,
	tx pgx.Tx,
	scope assetcatalog.SourceScope,
	kind, key string,
	sourceID, providerKind any,
) (bucketState, error) {
	var bucket bucketState
	err := tx.QueryRow(ctx, `
		SELECT id::text,bucket_kind,bucket_key,next_token_at,
		       COALESCE(last_receipt_id::text,''),version
		FROM public.asset_source_limit_buckets
		WHERE tenant_id=$1::uuid AND workspace_id=$2::uuid
		  AND bucket_kind=$3 AND bucket_key=$4
		  AND source_id IS NOT DISTINCT FROM $5::uuid
		  AND provider_kind IS NOT DISTINCT FROM $6
		FOR UPDATE
	`, scope.TenantID, scope.WorkspaceID, kind, key, sourceID, providerKind).Scan(
		&bucket.id, &bucket.kind, &bucket.key, &bucket.nextTokenAt,
		&bucket.lastReceiptID, &bucket.version,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return bucketState{}, discoverylimit.ErrStateConflict
	}
	if err != nil {
		return bucketState{}, err
	}
	bucket.nextTokenAt = bucket.nextTokenAt.UTC()
	if !validUUID(bucket.id) || bucket.kind != kind || bucket.key != key ||
		bucket.version < 1 {
		return bucketState{}, discoverylimit.ErrStateConflict
	}
	return bucket, nil
}

func lockPermitBuckets(
	ctx context.Context,
	tx pgx.Tx,
	acquire permitRecord,
) ([3]bucketState, error) {
	specifications := [3]struct {
		id           string
		kind         string
		key          string
		sourceID     any
		providerKind any
	}{
		{
			id: acquire.sourceBucketID, kind: "SOURCE", key: acquire.coordinates.SourceID,
			sourceID: acquire.coordinates.SourceID,
		},
		{
			id: acquire.workspaceBucketID, kind: "WORKSPACE",
			key: acquire.coordinates.Scope.WorkspaceID,
		},
		{
			id: acquire.providerBucketID, kind: "PROVIDER",
			key: acquire.coordinates.ProviderKind, providerKind: acquire.coordinates.ProviderKind,
		},
	}
	var buckets [3]bucketState
	for index, specification := range specifications {
		bucket, err := lockBucket(
			ctx, tx, acquire.coordinates.Scope, specification.kind, specification.key,
			specification.sourceID, specification.providerKind,
		)
		if err != nil {
			return [3]bucketState{}, err
		}
		if bucket.id != specification.id {
			return [3]bucketState{}, discoverylimit.ErrStalePermit
		}
		buckets[index] = bucket
	}
	return buckets, nil
}

func limiterLimited(
	ctx context.Context,
	tx pgx.Tx,
	scope assetcatalog.SourceScope,
	admission admissionState,
	buckets [3]bucketState,
) (bool, error) {
	for _, bucket := range buckets {
		if bucket.nextTokenAt.After(admission.now) {
			return true, nil
		}
		active, err := countActive(ctx, tx, scope, bucket, admission.now)
		if err != nil {
			return false, err
		}
		if active >= admission.rateRequests {
			return true, nil
		}
	}
	return false, nil
}

func countActive(
	ctx context.Context,
	tx pgx.Tx,
	scope assetcatalog.SourceScope,
	bucket bucketState,
	now time.Time,
) (int64, error) {
	column := ""
	switch bucket.kind {
	case "SOURCE":
		column = "source_bucket_id"
	case "WORKSPACE":
		column = "workspace_bucket_id"
	case "PROVIDER":
		column = "provider_bucket_id"
	default:
		return 0, discoverylimit.ErrStateConflict
	}
	query := `
		SELECT count(*)
		FROM public.asset_source_limit_permits AS acquire
		WHERE acquire.tenant_id=$1::uuid
		  AND acquire.workspace_id=$2::uuid
		  AND acquire.record_kind='ACQUIRE'
		  AND acquire.expires_at>$3
		  AND acquire.` + column + `=$4::uuid
		  AND NOT EXISTS (
		    SELECT 1
		    FROM public.asset_source_limit_permits AS terminal
		    WHERE terminal.tenant_id=acquire.tenant_id
		      AND terminal.workspace_id=acquire.workspace_id
		      AND terminal.permit_id=acquire.id
		      AND terminal.record_kind IN ('RELEASE','DELAY','EXPIRE')
		  )
	`
	var active int64
	if err := tx.QueryRow(ctx, query, scope.TenantID, scope.WorkspaceID, now, bucket.id).Scan(
		&active,
	); err != nil {
		return 0, err
	}
	return active, nil
}

func (limiter *Limiter) expireStalePermits(
	ctx context.Context,
	tx pgx.Tx,
	scope assetcatalog.SourceScope,
	sourceID, providerKind string,
	now time.Time,
	buckets *[3]bucketState,
) error {
	rows, err := tx.Query(ctx, `
		SELECT id::text,tenant_id::text,workspace_id::text,permit_id::text,record_kind,
		       source_id::text,run_id::text,provider_kind,
		       source_bucket_id::text,workspace_bucket_id::text,provider_bucket_id::text,
		       request_id,command_sha256,receipt_sha256,
		       acquired_at,expires_at,not_before,terminal_reason_code,created_at
		FROM public.asset_source_limit_permits AS acquire
		WHERE acquire.tenant_id=$1::uuid AND acquire.workspace_id=$2::uuid
		  AND acquire.source_id=$3::uuid AND acquire.provider_kind=$4
		  AND acquire.source_bucket_id=$5::uuid
		  AND acquire.workspace_bucket_id=$6::uuid
		  AND acquire.provider_bucket_id=$7::uuid
		  AND acquire.record_kind='ACQUIRE'
		  AND acquire.expires_at<=$8
		  AND NOT EXISTS (
		    SELECT 1
		    FROM public.asset_source_limit_permits AS terminal
		    WHERE terminal.tenant_id=acquire.tenant_id
		      AND terminal.workspace_id=acquire.workspace_id
		      AND terminal.permit_id=acquire.id
		      AND terminal.record_kind IN ('RELEASE','DELAY','EXPIRE')
		  )
		ORDER BY acquire.acquired_at,acquire.id
	`, scope.TenantID, scope.WorkspaceID, sourceID, providerKind,
		buckets[0].id, buckets[1].id, buckets[2].id, now)
	if err != nil {
		return err
	}
	defer rows.Close()
	var expired []permitRecord
	for rows.Next() {
		record, err := scanRecord(rows)
		if err != nil {
			return err
		}
		if !record.valid() || record.kind != recordAcquire {
			return discoverylimit.ErrStateConflict
		}
		expired = append(expired, record)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for _, acquire := range expired {
		if err := limiter.appendExpiry(ctx, tx, acquire, now, buckets); err != nil {
			return err
		}
	}
	return nil
}

func (limiter *Limiter) appendExpiry(
	ctx context.Context,
	tx pgx.Tx,
	acquire permitRecord,
	now time.Time,
	buckets *[3]bucketState,
) error {
	receiptID := limiter.newID()
	if !validUUID(receiptID) {
		return discoverylimit.ErrUnavailable
	}
	requestID := "limiter-expire:" + acquire.permitID
	commandSHA256 := expiryCommandDigest(acquire)
	record := acquire.terminal(
		receiptID, recordExpire, requestID, commandSHA256,
		"PERMIT_EXPIRED", nil, now,
	)
	if err := insertRecord(ctx, tx, record); err != nil {
		return err
	}
	for index := range buckets {
		if err := updateBucket(
			ctx, tx, &buckets[index], buckets[index].nextTokenAt, record.id,
		); err != nil {
			return err
		}
	}
	return nil
}

func updateBucket(
	ctx context.Context,
	tx pgx.Tx,
	bucket *bucketState,
	nextTokenAt time.Time,
	receiptID string,
) error {
	tag, err := tx.Exec(ctx, `
		UPDATE public.asset_source_limit_buckets
		SET next_token_at=$1,last_receipt_id=$2::uuid,version=version+1
		WHERE id=$3::uuid AND version=$4 AND next_token_at=$5
		  AND last_receipt_id IS NOT DISTINCT FROM NULLIF($6,'')::uuid
	`, nextTokenAt, receiptID, bucket.id, bucket.version,
		bucket.nextTokenAt, bucket.lastReceiptID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return discoverylimit.ErrStateConflict
	}
	bucket.nextTokenAt = nextTokenAt
	bucket.lastReceiptID = receiptID
	bucket.version++
	return nil
}

type recordKind string

const (
	recordAcquire recordKind = "ACQUIRE"
	recordRelease recordKind = "RELEASE"
	recordDelay   recordKind = "DELAY"
	recordExpire  recordKind = "EXPIRE"
)

type permitRecord struct {
	id, permitID string
	kind         recordKind
	coordinates  discoverylimit.Coordinates

	sourceBucketID, workspaceBucketID, providerBucketID string
	requestID, commandSHA256, receiptSHA256             string
	acquiredAt, expiresAt, createdAt                    time.Time
	notBefore                                           *time.Time
	reasonCode                                          *string
}

func (record permitRecord) valid() bool {
	if !validUUID(record.id) || !validUUID(record.permitID) ||
		!record.coordinates.Valid() ||
		!validUUID(record.sourceBucketID) || !validUUID(record.workspaceBucketID) ||
		!validUUID(record.providerBucketID) ||
		!domain.ValidIdempotencyKey(record.requestID) ||
		!domain.ValidSHA256Hex(record.commandSHA256) ||
		!domain.ValidSHA256Hex(record.receiptSHA256) ||
		!validTime(record.acquiredAt) || !validTime(record.expiresAt) ||
		!validTime(record.createdAt) || !record.expiresAt.After(record.acquiredAt) ||
		record.expiresAt.Sub(record.acquiredAt) > discoverylimit.MaxPermitTTL ||
		record.receiptSHA256 != record.digest() {
		return false
	}
	switch record.kind {
	case recordAcquire:
		return record.id == record.permitID && record.notBefore == nil &&
			record.reasonCode == nil && record.createdAt.Equal(record.acquiredAt)
	case recordRelease:
		return record.id != record.permitID && record.notBefore == nil &&
			record.reasonCode != nil && validReason(*record.reasonCode)
	case recordDelay:
		return record.id != record.permitID && record.notBefore != nil &&
			validTime(*record.notBefore) && record.notBefore.After(record.createdAt) &&
			record.reasonCode != nil && validReason(*record.reasonCode)
	case recordExpire:
		return record.id != record.permitID && record.notBefore == nil &&
			!record.createdAt.Before(record.expiresAt) &&
			record.reasonCode != nil && validReason(*record.reasonCode)
	default:
		return false
	}
}

func (record permitRecord) permit() discoverylimit.Permit {
	return discoverylimit.Permit{
		PermitID: record.permitID, Coordinates: record.coordinates,
		RequestID: record.requestID, CommandSHA256: record.commandSHA256,
		ReceiptSHA256: record.receiptSHA256,
		AcquiredAt:    record.acquiredAt.UTC(), ExpiresAt: record.expiresAt.UTC(),
	}
}

func (record permitRecord) receipt() discoverylimit.Receipt {
	var notBefore *time.Time
	if record.notBefore != nil {
		value := record.notBefore.UTC()
		notBefore = &value
	}
	reason := ""
	if record.reasonCode != nil {
		reason = *record.reasonCode
	}
	return discoverylimit.Receipt{
		ReceiptID: record.id, PermitID: record.permitID,
		Kind: discoverylimit.ReceiptKind(record.kind), Coordinates: record.coordinates,
		RequestID: record.requestID, CommandSHA256: record.commandSHA256,
		ReceiptSHA256: record.receiptSHA256,
		AcquiredAt:    record.acquiredAt.UTC(), ExpiresAt: record.expiresAt.UTC(),
		NotBefore: notBefore, ReasonCode: reason,
	}
}

func (record permitRecord) terminal(
	id string,
	kind recordKind,
	requestID, commandSHA256, reasonCode string,
	notBefore *time.Time,
	createdAt time.Time,
) permitRecord {
	record.id = id
	record.kind = kind
	record.requestID = requestID
	record.commandSHA256 = commandSHA256
	record.createdAt = createdAt.UTC()
	record.notBefore = nil
	if notBefore != nil {
		value := notBefore.UTC()
		record.notBefore = &value
	}
	record.reasonCode = &reasonCode
	record.receiptSHA256 = record.digest()
	return record
}

func (record permitRecord) digest() string {
	var notBefore, reason []byte
	if record.notBefore != nil {
		notBefore = []byte(formatTime(*record.notBefore))
	}
	if record.reasonCode != nil {
		reason = []byte(*record.reasonCode)
	}
	return framedDigest(
		[]byte("asset-source-limit-receipt.v1"), []byte(record.id), []byte(record.permitID),
		[]byte(record.kind), []byte(record.coordinates.Scope.TenantID),
		[]byte(record.coordinates.Scope.WorkspaceID), []byte(record.coordinates.SourceID),
		[]byte(record.coordinates.RunID), []byte(record.coordinates.ProviderKind),
		[]byte(record.sourceBucketID), []byte("SOURCE"), []byte(record.coordinates.SourceID),
		[]byte(record.workspaceBucketID), []byte("WORKSPACE"),
		[]byte(record.coordinates.Scope.WorkspaceID),
		[]byte(record.providerBucketID), []byte("PROVIDER"),
		[]byte(record.coordinates.ProviderKind), []byte(record.requestID),
		decodeDigest(record.commandSHA256), []byte(formatTime(record.acquiredAt)),
		[]byte(formatTime(record.expiresAt)), optionalFrame(notBefore),
		optionalFrame(reason), []byte(formatTime(record.createdAt)),
	)
}

func insertRecord(ctx context.Context, tx pgx.Tx, record permitRecord) error {
	if !record.valid() {
		return discoverylimit.ErrStateConflict
	}
	_, err := tx.Exec(ctx, `
		INSERT INTO public.asset_source_limit_permits(
		  id,tenant_id,workspace_id,permit_id,record_kind,source_id,run_id,provider_kind,
		  source_bucket_id,source_bucket_kind,source_bucket_key,
		  workspace_bucket_id,workspace_bucket_kind,workspace_bucket_key,
		  provider_bucket_id,provider_bucket_kind,provider_bucket_key,
		  request_id,command_sha256,receipt_sha256,acquired_at,expires_at,
		  not_before,terminal_reason_code,created_at
		) VALUES(
		  $1::uuid,$2::uuid,$3::uuid,$4::uuid,$5,$6::uuid,$7::uuid,$8,
		  $9::uuid,'SOURCE',$6,$10::uuid,'WORKSPACE',$3,
		  $11::uuid,'PROVIDER',$8,$12,$13,$14,$15,$16,$17,$18,$19
		)
	`, record.id, record.coordinates.Scope.TenantID, record.coordinates.Scope.WorkspaceID,
		record.permitID, record.kind, record.coordinates.SourceID, record.coordinates.RunID,
		record.coordinates.ProviderKind, record.sourceBucketID, record.workspaceBucketID,
		record.providerBucketID, record.requestID, record.commandSHA256,
		record.receiptSHA256, record.acquiredAt, record.expiresAt,
		record.notBefore, record.reasonCode, record.createdAt)
	return err
}

func loadRecordByRequest(
	ctx context.Context,
	tx pgx.Tx,
	scope assetcatalog.SourceScope,
	requestID string,
) (permitRecord, bool, error) {
	row := tx.QueryRow(ctx, `
		SELECT id::text,tenant_id::text,workspace_id::text,permit_id::text,record_kind,
		       source_id::text,run_id::text,provider_kind,
		       source_bucket_id::text,workspace_bucket_id::text,provider_bucket_id::text,
		       request_id,command_sha256,receipt_sha256,
		       acquired_at,expires_at,not_before,terminal_reason_code,created_at
		FROM public.asset_source_limit_permits
		WHERE tenant_id=$1::uuid AND workspace_id=$2::uuid AND request_id=$3
	`, scope.TenantID, scope.WorkspaceID, requestID)
	record, err := scanRecord(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return permitRecord{}, false, nil
	}
	if err != nil {
		return permitRecord{}, false, err
	}
	if !record.valid() {
		return permitRecord{}, false, discoverylimit.ErrStateConflict
	}
	return record, true, nil
}

func loadAcquire(
	ctx context.Context,
	tx pgx.Tx,
	coordinates discoverylimit.Coordinates,
	permitID string,
) (permitRecord, error) {
	row := tx.QueryRow(ctx, `
		SELECT id::text,tenant_id::text,workspace_id::text,permit_id::text,record_kind,
		       source_id::text,run_id::text,provider_kind,
		       source_bucket_id::text,workspace_bucket_id::text,provider_bucket_id::text,
		       request_id,command_sha256,receipt_sha256,
		       acquired_at,expires_at,not_before,terminal_reason_code,created_at
		FROM public.asset_source_limit_permits
		WHERE tenant_id=$1::uuid AND workspace_id=$2::uuid
		  AND id=$3::uuid AND permit_id=$3::uuid AND record_kind='ACQUIRE'
		  AND source_id=$4::uuid AND run_id=$5::uuid AND provider_kind=$6
	`, coordinates.Scope.TenantID, coordinates.Scope.WorkspaceID, permitID,
		coordinates.SourceID, coordinates.RunID, coordinates.ProviderKind)
	record, err := scanRecord(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return permitRecord{}, discoverylimit.ErrStalePermit
	}
	if err != nil {
		return permitRecord{}, err
	}
	if !record.valid() || record.kind != recordAcquire ||
		record.coordinates != coordinates || record.permitID != permitID {
		return permitRecord{}, discoverylimit.ErrStalePermit
	}
	return record, nil
}

func loadTerminal(ctx context.Context, tx pgx.Tx, acquire permitRecord) (bool, error) {
	var exists bool
	err := tx.QueryRow(ctx, `
		SELECT EXISTS(
		  SELECT 1
		  FROM public.asset_source_limit_permits
		  WHERE tenant_id=$1::uuid AND workspace_id=$2::uuid
		    AND permit_id=$3::uuid
		    AND record_kind IN ('RELEASE','DELAY','EXPIRE')
		)
	`, acquire.coordinates.Scope.TenantID, acquire.coordinates.Scope.WorkspaceID,
		acquire.permitID).Scan(&exists)
	return exists, err
}

type rowScanner interface {
	Scan(...any) error
}

func scanRecord(row rowScanner) (permitRecord, error) {
	var record permitRecord
	var tenantID, workspaceID, sourceID, runID, providerKind string
	if err := row.Scan(
		&record.id, &tenantID, &workspaceID, &record.permitID, &record.kind,
		&sourceID, &runID, &providerKind,
		&record.sourceBucketID, &record.workspaceBucketID, &record.providerBucketID,
		&record.requestID, &record.commandSHA256, &record.receiptSHA256,
		&record.acquiredAt, &record.expiresAt, &record.notBefore, &record.reasonCode,
		&record.createdAt,
	); err != nil {
		return permitRecord{}, err
	}
	record.coordinates = discoverylimit.Coordinates{
		Scope:    assetcatalog.SourceScope{TenantID: tenantID, WorkspaceID: workspaceID},
		SourceID: sourceID, RunID: runID, ProviderKind: providerKind,
	}
	record.acquiredAt = record.acquiredAt.UTC()
	record.expiresAt = record.expiresAt.UTC()
	record.createdAt = record.createdAt.UTC()
	if record.notBefore != nil {
		value := record.notBefore.UTC()
		record.notBefore = &value
	}
	return record, nil
}

func acquireCommandDigest(command discoverylimit.AcquireCommand) string {
	frames := append(
		[][]byte{[]byte("asset-source-limit-acquire-command.v1")},
		coordinateFrames(command.Coordinates)...,
	)
	frames = append(
		frames,
		[]byte(command.RequestID),
		[]byte(strconv.FormatInt(command.TTL.Microseconds(), 10)),
	)
	return framedDigest(frames...)
}

func releaseCommandDigest(command discoverylimit.ReleaseCommand) string {
	return framedDigest(append(
		append(
			[][]byte{[]byte("asset-source-limit-release-command.v1")},
			coordinateFrames(command.Coordinates)...,
		),
		[]byte(command.PermitID), []byte(command.RequestID), []byte(command.ReasonCode),
	)...)
}

func delayCommandDigest(command discoverylimit.DelayCommand) string {
	return framedDigest(append(
		append(
			[][]byte{[]byte("asset-source-limit-delay-command.v1")},
			coordinateFrames(command.Coordinates)...,
		),
		[]byte(command.PermitID), []byte(command.RequestID), []byte(command.ReasonCode),
		[]byte(formatTime(command.NotBefore)),
	)...)
}

func expiryCommandDigest(acquire permitRecord) string {
	return framedDigest(
		[]byte("asset-source-limit-expire-command.v1"),
		[]byte(acquire.permitID), []byte(acquire.coordinates.Scope.TenantID),
		[]byte(acquire.coordinates.Scope.WorkspaceID), []byte(acquire.coordinates.SourceID),
		[]byte(acquire.coordinates.RunID), []byte(acquire.coordinates.ProviderKind),
		[]byte(formatTime(acquire.acquiredAt)), []byte(formatTime(acquire.expiresAt)),
	)
}

func coordinateFrames(coordinates discoverylimit.Coordinates) [][]byte {
	return [][]byte{
		[]byte(coordinates.Scope.TenantID), []byte(coordinates.Scope.WorkspaceID),
		[]byte(coordinates.SourceID), []byte(coordinates.RunID),
		[]byte(coordinates.ProviderKind),
	}
}

func framedDigest(values ...[]byte) string {
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

func optionalFrame(value []byte) []byte {
	if value == nil {
		return nil
	}
	return value
}

func decodeDigest(value string) []byte {
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != sha256.Size {
		return nil
	}
	return decoded
}

func tokenQuantum(requests, windowSeconds int64) time.Duration {
	windowMicroseconds := windowSeconds * int64(time.Second/time.Microsecond)
	microseconds := (windowMicroseconds + requests - 1) / requests
	return time.Duration(max(microseconds, 1)) * time.Microsecond
}

func formatTime(value time.Time) string {
	return value.UTC().Format("2006-01-02T15:04:05.000000Z")
}

func validTime(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC &&
		value.Year() >= 2000 && value.Year() <= 9999 &&
		value.Nanosecond()%1000 == 0 && value == value.Round(0)
}

func validUUID(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil && parsed.String() == value &&
		parsed.Version() >= 1 && parsed.Version() <= 5 && parsed.Variant() == uuid.RFC4122
}

func validReason(value string) bool {
	if len(value) < 1 || len(value) > 128 || value[0] < 'A' || value[0] > 'Z' {
		return false
	}
	for _, character := range value {
		if character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' || character == '_' {
			continue
		}
		return false
	}
	return true
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

func pinTransaction(ctx context.Context, tx pgx.Tx) error {
	_, err := tx.Exec(ctx, `SET LOCAL search_path=pg_catalog,public,pg_temp`)
	return err
}

func databaseClock(ctx context.Context, tx pgx.Tx) (time.Time, error) {
	var now time.Time
	if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return time.Time{}, err
	}
	return now.UTC().Truncate(time.Microsecond), nil
}

type committedOutcome[T any] struct {
	value         T
	postCommitErr error
}

func withSerializable[T any](
	ctx context.Context,
	pool *pgxpool.Pool,
	operation func(pgx.Tx) (committedOutcome[T], error),
) (committedOutcome[T], error) {
	var zero committedOutcome[T]
	for attempt := 0; attempt < serializableAttempts; attempt++ {
		tx, err := pool.BeginTx(ctx, pgx.TxOptions{
			IsoLevel: pgx.Serializable, AccessMode: pgx.ReadWrite,
		})
		if err != nil {
			return zero, err
		}
		outcome, operationErr := operation(tx)
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
		return outcome, nil
	}
	return zero, discoverylimit.ErrStateConflict
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
	if !errors.As(err, &databaseError) {
		return false
	}
	if databaseError.Code == "40001" || databaseError.Code == "40P01" {
		return true
	}
	if databaseError.Code != "23505" {
		return false
	}
	return databaseError.ConstraintName == "asset_source_limit_permits_workspace_request_uk" ||
		databaseError.ConstraintName == "asset_source_limit_permits_one_terminal_uk"
}

func mapError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	for _, stable := range []error{
		discoverylimit.ErrInvalidRequest, discoverylimit.ErrIneligible,
		discoverylimit.ErrLimited, discoverylimit.ErrStalePermit,
		discoverylimit.ErrIdempotency, discoverylimit.ErrStateConflict,
		discoverylimit.ErrUnavailable,
	} {
		if errors.Is(err, stable) {
			return stable
		}
	}
	var databaseError *pgconn.PgError
	if !errors.As(err, &databaseError) {
		return discoverylimit.ErrUnavailable
	}
	switch databaseError.Code {
	case "23505":
		return discoverylimit.ErrStateConflict
	case "23503", "23514", "40001", "40P01", "55000":
		return discoverylimit.ErrStateConflict
	case "22P02", "22001", "22007", "22008", "22023":
		return discoverylimit.ErrInvalidRequest
	default:
		return discoverylimit.ErrUnavailable
	}
}

var _ discoverylimit.Limiter = (*Limiter)(nil)
