package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"regexp"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/seaworld008/aiops-system/internal/assetcatalog"
	"github.com/seaworld008/aiops-system/internal/overview"
)

const statementTimeoutSQL = "SET LOCAL statement_timeout = '500ms'"

const resolveScopeSQL = `
SELECT w.tenant_id::text, w.id::text, e.id::text
FROM workspaces AS w
JOIN environments AS e
  ON e.tenant_id = w.tenant_id
 AND e.workspace_id = w.id
WHERE w.id = $1::uuid
  AND e.id = $2::uuid
`

const readinessSQL = `
SELECT relation_name, to_regclass('public.' || relation_name) IS NOT NULL AS present
FROM unnest($1::text[]) WITH ORDINALITY AS required(relation_name, ordinal)
ORDER BY ordinal
`

const assetFactsSQL = `
SELECT
  COALESCE(max(asset.updated_at), transaction_timestamp()) AS observed_at,
  count(*)::bigint AS total,
  count(*) FILTER (WHERE asset.lifecycle = 'DISCOVERED')::bigint AS discovered,
  count(*) FILTER (WHERE asset.lifecycle = 'ACTIVE')::bigint AS active,
  count(*) FILTER (WHERE asset.lifecycle = 'STALE')::bigint AS stale,
  count(*) FILTER (WHERE asset.lifecycle = 'QUARANTINED')::bigint AS quarantined,
  count(*) FILTER (WHERE asset.lifecycle = 'RETIRED')::bigint AS retired,
  count(*) FILTER (WHERE asset.mapping_status = 'EXACT')::bigint AS exact,
  count(*) FILTER (WHERE asset.mapping_status = 'AMBIGUOUS')::bigint AS ambiguous,
  count(*) FILTER (WHERE asset.mapping_status = 'UNRESOLVED')::bigint AS unresolved,
  min(asset.last_observed_at) FILTER (WHERE asset.lifecycle = 'STALE') AS oldest_stale_at,
  (
    SELECT count(*)::bigint
    FROM asset_conflicts AS conflict
    WHERE conflict.tenant_id = $1::uuid
      AND conflict.workspace_id = $2::uuid
      AND conflict.environment_id = $3::uuid
      AND conflict.status = 'OPEN'
  ) AS open_conflicts
FROM assets AS asset
WHERE asset.tenant_id = $1::uuid
  AND asset.workspace_id = $2::uuid
  AND asset.environment_id = $3::uuid
`

const sourceFactsSQL = `
WITH scoped_sources AS (
  SELECT source.*
  FROM asset_sources AS source
  WHERE source.tenant_id = $1::uuid
    AND source.workspace_id = $2::uuid
    AND EXISTS (
      SELECT 1
      FROM asset_source_revision_authorities AS authority
      WHERE authority.tenant_id = source.tenant_id
        AND authority.workspace_id = source.workspace_id
        AND authority.source_id = source.id
        AND authority.source_revision = COALESCE(
          source.published_revision,
          (
            SELECT max(latest.revision)
            FROM asset_source_revisions AS latest
            WHERE latest.tenant_id = source.tenant_id
              AND latest.workspace_id = source.workspace_id
              AND latest.source_id = source.id
          )
        )
        AND authority.environment_id = $3::uuid
    )
),
source_counts AS (
  SELECT
    max(source.updated_at) AS observed_at,
    count(*)::bigint AS total,
    count(*) FILTER (WHERE source.status = 'ACTIVE')::bigint AS active,
    count(*) FILTER (WHERE source.status = 'PAUSED')::bigint AS paused,
    count(*) FILTER (WHERE source.status = 'DEGRADED')::bigint AS degraded,
    count(*) FILTER (WHERE source.status = 'DISABLED')::bigint AS disabled,
    count(*) FILTER (WHERE source.gate_status = 'UNAVAILABLE')::bigint AS gate_unavailable,
    count(*) FILTER (WHERE source.gate_status = 'VALIDATING')::bigint AS gate_validating,
    count(*) FILTER (WHERE source.gate_status = 'AVAILABLE')::bigint AS gate_available,
    count(*) FILTER (WHERE source.gate_status = 'DEGRADED')::bigint AS gate_degraded,
    count(*) FILTER (WHERE source.gate_status = 'SUSPENDED')::bigint AS gate_suspended,
    count(*) FILTER (WHERE EXISTS (
      SELECT 1
      FROM asset_source_limit_buckets AS bucket
      WHERE bucket.tenant_id = source.tenant_id
        AND bucket.workspace_id = source.workspace_id
        AND bucket.next_token_at > transaction_timestamp()
        AND (
          bucket.bucket_kind = 'WORKSPACE'
          OR (bucket.bucket_kind = 'SOURCE' AND bucket.source_id = source.id)
          OR (bucket.bucket_kind = 'PROVIDER' AND bucket.provider_kind = source.provider_kind)
        )
    ))::bigint AS backpressured
  FROM scoped_sources AS source
),
revision_counts AS (
  SELECT
    max(revision.updated_at) AS observed_at,
    count(*) FILTER (WHERE revision.state = 'DRAFT')::bigint AS draft,
    count(*) FILTER (WHERE revision.state = 'VALIDATING')::bigint AS validating,
    count(*) FILTER (WHERE revision.state = 'VALIDATED')::bigint AS validated,
    count(*) FILTER (WHERE revision.state = 'REJECTED')::bigint AS rejected,
    count(*) FILTER (WHERE revision.state = 'PUBLISHED')::bigint AS published,
    count(*) FILTER (WHERE revision.state = 'SUPERSEDED')::bigint AS superseded
  FROM asset_source_revisions AS revision
  JOIN scoped_sources AS source
    ON source.tenant_id = revision.tenant_id
   AND source.workspace_id = revision.workspace_id
   AND source.id = revision.source_id
  WHERE EXISTS (
    SELECT 1
    FROM asset_source_revision_authorities AS authority
    WHERE authority.tenant_id = revision.tenant_id
      AND authority.workspace_id = revision.workspace_id
      AND authority.source_id = revision.source_id
      AND authority.source_revision = revision.revision
      AND authority.environment_id = $3::uuid
  )
),
run_counts AS (
  SELECT
    max(GREATEST(run.created_at, run.stage_changed_at)) AS observed_at,
    count(*) FILTER (WHERE run.status = 'QUEUED')::bigint AS queued,
    count(*) FILTER (WHERE run.status = 'DELAYED')::bigint AS delayed,
    count(*) FILTER (WHERE run.status = 'RUNNING')::bigint AS running,
    count(*) FILTER (WHERE run.status = 'FINALIZING')::bigint AS finalizing,
    count(*) FILTER (WHERE run.status = 'SUCCEEDED')::bigint AS succeeded,
    count(*) FILTER (WHERE run.status = 'PARTIAL')::bigint AS partial,
    count(*) FILTER (WHERE run.status = 'FAILED')::bigint AS failed,
    count(*) FILTER (WHERE run.status = 'CANCELLED')::bigint AS cancelled
  FROM asset_source_runs AS run
  JOIN scoped_sources AS source
    ON source.tenant_id = run.tenant_id
   AND source.workspace_id = run.workspace_id
   AND source.id = run.source_id
  WHERE EXISTS (
    SELECT 1
    FROM asset_source_revision_authorities AS authority
    WHERE authority.tenant_id = run.tenant_id
      AND authority.workspace_id = run.workspace_id
      AND authority.source_id = run.source_id
      AND authority.source_revision = run.source_revision
      AND authority.environment_id = $3::uuid
  )
),
provider_gate_rows AS (
  SELECT
    source.provider_kind,
    source.gate_status,
    count(*)::bigint AS source_count,
    max(COALESCE(source.last_success_at, source.updated_at)) AS evidence_at
  FROM scoped_sources AS source
  GROUP BY source.provider_kind, source.gate_status
),
provider_gates AS (
  SELECT COALESCE(
    jsonb_agg(
      jsonb_build_object(
        'provider_kind', provider_kind,
        'gate_status', gate_status,
        'source_count', source_count,
        'evidence_at', evidence_at
      )
      ORDER BY provider_kind, gate_status
    ),
    '[]'::jsonb
  ) AS summaries
  FROM provider_gate_rows
)
SELECT
  COALESCE(
    NULLIF(
      GREATEST(
        COALESCE(source_counts.observed_at, '-infinity'::timestamptz),
        COALESCE(revision_counts.observed_at, '-infinity'::timestamptz),
        COALESCE(run_counts.observed_at, '-infinity'::timestamptz)
      ),
      '-infinity'::timestamptz
    ),
    transaction_timestamp()
  ) AS observed_at,
  source_counts.total,
  source_counts.active,
  source_counts.paused,
  source_counts.degraded,
  source_counts.disabled,
  revision_counts.draft,
  revision_counts.validating,
  revision_counts.validated,
  revision_counts.rejected,
  revision_counts.published,
  revision_counts.superseded,
  source_counts.gate_unavailable,
  source_counts.gate_validating,
  source_counts.gate_available,
  source_counts.gate_degraded,
  source_counts.gate_suspended,
  run_counts.queued,
  run_counts.delayed,
  run_counts.running,
  run_counts.finalizing,
  run_counts.succeeded,
  run_counts.partial,
  run_counts.failed,
  run_counts.cancelled,
  source_counts.backpressured,
  provider_gates.summaries
FROM source_counts
CROSS JOIN revision_counts
CROSS JOIN run_counts
CROSS JOIN provider_gates
`

var canonicalUUIDPattern = regexp.MustCompile(
	`^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`,
)

var assetRelations = []string{"assets", "asset_conflicts"}

var sourceRelations = []string{
	"asset_sources",
	"asset_source_revisions",
	"asset_source_revision_authorities",
	"asset_source_runs",
	"asset_source_limit_buckets",
}

type readPool interface {
	BeginTx(context.Context, pgx.TxOptions) (pgx.Tx, error)
}

type Repository struct {
	pool readPool
}

func New(pool *pgxpool.Pool) (*Repository, error) {
	if pool == nil {
		return nil, errors.New("overview PostgreSQL pool is required")
	}
	return newRepository(pool), nil
}

func newRepository(pool readPool) *Repository {
	return &Repository{pool: pool}
}

func (repository *Repository) ResolveScope(
	ctx context.Context,
	workspaceID string,
	environmentID string,
) (assetcatalog.Scope, error) {
	if !canonicalUUIDPattern.MatchString(workspaceID) ||
		!canonicalUUIDPattern.MatchString(environmentID) {
		return assetcatalog.Scope{}, assetcatalog.ErrInvalidRequest
	}
	var scope assetcatalog.Scope
	err := repository.withReadOnly(ctx, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, resolveScopeSQL, workspaceID, environmentID).Scan(
			&scope.TenantID,
			&scope.WorkspaceID,
			&scope.EnvironmentID,
		)
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return assetcatalog.Scope{}, assetcatalog.ErrNotFound
		}
		return assetcatalog.Scope{}, err
	}
	if !scope.Valid() || scope.WorkspaceID != workspaceID || scope.EnvironmentID != environmentID {
		return assetcatalog.Scope{}, assetcatalog.ErrNotFound
	}
	return scope, nil
}

func (repository *Repository) State(
	ctx context.Context,
	scope assetcatalog.Scope,
	feature overview.Feature,
) (overview.ImplementationState, error) {
	if !scope.Valid() || !feature.Valid() {
		return "", overview.ErrInvalidRequest
	}
	var relations []string
	switch feature {
	case overview.FeatureAssets:
		relations = assetRelations
	case overview.FeatureSources:
		relations = sourceRelations
	default:
		return overview.StateNotStarted, nil
	}
	present := 0
	seen := 0
	err := repository.withReadOnly(ctx, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, readinessSQL, relations)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var relation string
			var exists bool
			if err := rows.Scan(&relation, &exists); err != nil {
				return err
			}
			if seen >= len(relations) || relation != relations[seen] {
				return overview.ErrUnavailable
			}
			seen++
			if exists {
				present++
			}
		}
		return rows.Err()
	})
	if err != nil {
		return "", err
	}
	if seen != len(relations) {
		return "", overview.ErrUnavailable
	}
	switch {
	case present == 0:
		return overview.StateNotStarted, nil
	case present == len(relations):
		return overview.StateAvailable, nil
	default:
		return overview.StateUnavailable, nil
	}
}

func (repository *Repository) ReadAssetFacts(
	ctx context.Context,
	scope assetcatalog.Scope,
) (overview.AssetFacts, error) {
	if !scope.Valid() {
		return overview.AssetFacts{}, overview.ErrInvalidRequest
	}
	var facts overview.AssetFacts
	var discovered, active, stale, quarantined, retired int64
	var exact, ambiguous, unresolved int64
	var oldestStaleAt pgtype.Timestamptz
	err := repository.withReadOnly(ctx, func(tx pgx.Tx) error {
		return tx.QueryRow(
			ctx,
			assetFactsSQL,
			scope.TenantID,
			scope.WorkspaceID,
			scope.EnvironmentID,
		).Scan(
			&facts.ObservedAt,
			&facts.Total,
			&discovered,
			&active,
			&stale,
			&quarantined,
			&retired,
			&exact,
			&ambiguous,
			&unresolved,
			&oldestStaleAt,
			&facts.OpenConflictCount,
		)
	})
	if err != nil {
		return overview.AssetFacts{}, err
	}
	facts.StaleCount = stale
	if oldestStaleAt.Valid {
		value := oldestStaleAt.Time
		facts.OldestStaleAt = &value
	}
	facts.Lifecycles = []overview.StateCount{
		{State: string(assetcatalog.LifecycleDiscovered), Count: discovered},
		{State: string(assetcatalog.LifecycleActive), Count: active},
		{State: string(assetcatalog.LifecycleStale), Count: stale},
		{State: string(assetcatalog.LifecycleQuarantined), Count: quarantined},
		{State: string(assetcatalog.LifecycleRetired), Count: retired},
	}
	facts.MappingStatuses = []overview.StateCount{
		{State: "EXACT", Count: exact},
		{State: "AMBIGUOUS", Count: ambiguous},
		{State: "UNRESOLVED", Count: unresolved},
	}
	return facts, nil
}

func (repository *Repository) ReadSourceFacts(
	ctx context.Context,
	scope assetcatalog.Scope,
) (overview.SourceFacts, error) {
	if !scope.Valid() {
		return overview.SourceFacts{}, overview.ErrInvalidRequest
	}
	var facts overview.SourceFacts
	var active, paused, degraded, disabled int64
	var revisionDraft, revisionValidating, revisionValidated int64
	var revisionRejected, revisionPublished, revisionSuperseded int64
	var gateUnavailable, gateValidating, gateAvailable, gateDegraded, gateSuspended int64
	var runQueued, runDelayed, runRunning, runFinalizing int64
	var runSucceeded, runPartial, runFailed, runCancelled int64
	var providerGates []byte
	err := repository.withReadOnly(ctx, func(tx pgx.Tx) error {
		return tx.QueryRow(
			ctx,
			sourceFactsSQL,
			scope.TenantID,
			scope.WorkspaceID,
			scope.EnvironmentID,
		).Scan(
			&facts.ObservedAt,
			&facts.Total,
			&active,
			&paused,
			&degraded,
			&disabled,
			&revisionDraft,
			&revisionValidating,
			&revisionValidated,
			&revisionRejected,
			&revisionPublished,
			&revisionSuperseded,
			&gateUnavailable,
			&gateValidating,
			&gateAvailable,
			&gateDegraded,
			&gateSuspended,
			&runQueued,
			&runDelayed,
			&runRunning,
			&runFinalizing,
			&runSucceeded,
			&runPartial,
			&runFailed,
			&runCancelled,
			&facts.BackpressuredCount,
			&providerGates,
		)
	})
	if err != nil {
		return overview.SourceFacts{}, err
	}
	if err := json.Unmarshal(providerGates, &facts.ProviderGates); err != nil {
		return overview.SourceFacts{}, overview.ErrUnavailable
	}
	facts.Statuses = []overview.StateCount{
		{State: string(assetcatalog.SourceStatusActive), Count: active},
		{State: string(assetcatalog.SourceStatusPaused), Count: paused},
		{State: string(assetcatalog.SourceStatusDegraded), Count: degraded},
		{State: string(assetcatalog.SourceStatusDisabled), Count: disabled},
	}
	facts.RevisionStatuses = []overview.StateCount{
		{State: string(assetcatalog.SourceRevisionDraft), Count: revisionDraft},
		{State: string(assetcatalog.SourceRevisionValidating), Count: revisionValidating},
		{State: string(assetcatalog.SourceRevisionValidated), Count: revisionValidated},
		{State: string(assetcatalog.SourceRevisionRejected), Count: revisionRejected},
		{State: string(assetcatalog.SourceRevisionPublished), Count: revisionPublished},
		{State: string(assetcatalog.SourceRevisionSuperseded), Count: revisionSuperseded},
	}
	facts.GateStatuses = []overview.StateCount{
		{State: string(assetcatalog.SourceGateUnavailable), Count: gateUnavailable},
		{State: string(assetcatalog.SourceGateValidating), Count: gateValidating},
		{State: string(assetcatalog.SourceGateAvailable), Count: gateAvailable},
		{State: string(assetcatalog.SourceGateDegraded), Count: gateDegraded},
		{State: string(assetcatalog.SourceGateSuspended), Count: gateSuspended},
	}
	facts.RunStatuses = []overview.StateCount{
		{State: string(assetcatalog.RunStatusQueued), Count: runQueued},
		{State: string(assetcatalog.RunStatusDelayed), Count: runDelayed},
		{State: string(assetcatalog.RunStatusRunning), Count: runRunning},
		{State: string(assetcatalog.RunStatusFinalizing), Count: runFinalizing},
		{State: string(assetcatalog.RunStatusSucceeded), Count: runSucceeded},
		{State: string(assetcatalog.RunStatusPartial), Count: runPartial},
		{State: string(assetcatalog.RunStatusFailed), Count: runFailed},
		{State: string(assetcatalog.RunStatusCancelled), Count: runCancelled},
	}
	return facts, nil
}

func (repository *Repository) withReadOnly(
	ctx context.Context,
	operation func(pgx.Tx) error,
) error {
	if repository == nil || nilReadPool(repository.pool) || operation == nil {
		return overview.ErrUnavailable
	}
	tx, err := repository.pool.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return mapReadError(err)
	}
	if _, err := tx.Exec(ctx, statementTimeoutSQL); err != nil {
		_ = tx.Rollback(ctx)
		return mapReadError(err)
	}
	if err := operation(tx); err != nil {
		_ = tx.Rollback(ctx)
		return mapReadError(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return mapReadError(err)
	}
	return nil
}

func mapReadError(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return pgx.ErrNoRows
	}
	if errors.Is(err, overview.ErrInvalidRequest) ||
		errors.Is(err, overview.ErrUnavailable) {
		return err
	}
	return overview.ErrUnavailable
}

func nilReadPool(pool readPool) bool {
	if pool == nil {
		return true
	}
	value := reflect.ValueOf(pool)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}
