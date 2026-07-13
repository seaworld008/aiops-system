# Asset Repository and Discovery Reconciliation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 在已落库的资产目录模型上实现复合作用域 Repository、append-only 发现事实、确定性合并、失联/恢复和跨来源冲突，且控制平面不接触目标网络。

**Architecture:** PostgreSQL `SERIALIZABLE` 事务承载资产投影、Observation、Type Detail、审计、Outbox 和幂等原子性；`internal/assetdiscovery` 只验证并规范化批次，`internal/assetcatalog/postgres` 按固定去重键投影。来源同步由异步事件触发，Control Plane 不加载 Provider 凭据或网络客户端。

**Tech Stack:** Go 1.26.5、PostgreSQL 18.4、pgx v5、现有 `audit_records`/`outbox_events`。

## Global Constraints

- 前置任务：先完成 [01-schema-domain.md](./01-schema-domain.md)，并以已确认规范 `docs/superpowers/specs/2026-07-13-operational-assets-controlled-access-design.md` 为产品事实源。
- 必须在仓库目录树之外的隔离 worktree 实施；不得删除用户已有 `.worktrees/*`。
- 迁移归属固定为 `000015_assets_catalog`；本包不得新建或修改 000016 及以后迁移。
- 复合 Scope 固定为 Tenant + Workspace + Environment；所有读写都必须带复合作用域。
- 去重键固定为 `(tenant_id, workspace_id, source_id, provider_kind, external_id)`；跨来源不得按名称或优先级静默合并。
- `AssetObservation` 与 `AssetTypeDetail` revision append-only；同步不得覆盖 Owner、Service、关键度、数据等级或人工标签。
- 同步只能标记 `STALE` 或记录来源已恢复；恢复资产仍保持 `STALE`，直到后续 Connection Publication 复验显式转为 `ACTIVE`；Capability availability 不参与资产生命周期转换。
- 资产、审计、Outbox、幂等结果必须同事务提交；错误不得把数据库或 Provider 文本透传。
- 浏览器、模型、Task、Control Plane 均不得提交或持久化 endpoint、DSN、Secret、Token、私钥、命令、SQL、任意 Header、任意请求体。
- 生产只使用 PostgreSQL Repository；memory store/fake 仅允许在测试。锁、租约、幂等与恢复状态必须落数据库，支持多副本和故障转移。
- Repository/Source Run 必须通过低基数 Metrics 接口记录 operation/result/duration；禁止租户、资产、外部 ID、Subject 或 Trace ID 标签。实际 Prometheus 适配器由 `11-e2e-docs.md` 落地。
- 必须验证新 Repository 对 000015 schema readiness fail closed、应用回滚保留数据、逻辑备份恢复后 Observation/Type Detail/版本/Outbox 一致。
- 本包完成不等于阶段生产验收；真实 OIDC/OpenAPI/前端由 03–04 实现，真实 PostgreSQL/OIDC E2E、指标、备份和 HA 由 05 收口，任何测试 fake 不得进入这些生产路径。
- 最终路线是受治理生产写闭环；当前 Repository 只管理资产事实，不得把发现成功解释成目标写授权。
- 每个任务严格按 Red → Green → Refactor 执行；任务末尾只提交本任务列出的文件。
- 本包完成后按 [README.md](./README.md) 顺序进入 `03-mapping-auth-api.md`。

---


### Task 3: Scoped PostgreSQL asset repository and atomic governance writes

**Files:**
- Create: **internal/assetcatalog/postgres/repository.go**
- Create: **internal/assetcatalog/postgres/scope.go**
- Create: **internal/assetcatalog/postgres/assets.go**
- Create: **internal/assetcatalog/postgres/scan.go**
- Create: **internal/assetcatalog/postgres/assets_test.go**
- Create: **internal/assetcatalog/postgres/assets_integration_test.go**

**Interfaces:**
- Consumes: `assetcatalog.Repository`、`pgxpool.Pool`、现有 `audit_records` 和 `outbox_events`。
- Produces: `postgres.New(*pgxpool.Pool, func() time.Time, func() string) (*Repository, error)`；该对象同时实现 `assetcatalog.Reader`、`ScopeResolver` 和资产写仓储。
- Transaction rule: 资产、Observation、Type Detail、Audit、Outbox 和幂等结果必须在同一 `SERIALIZABLE` 事务提交；任何一步失败全部回滚。

- [ ] **Step 1: Write failing SQL-shape and repository contract tests**

~~~go
package postgres

import (
	"strings"
	"testing"
)

func TestAssetQueriesAlwaysCarryCompositeScope(t *testing.T) {
	t.Parallel()
	for name, query := range map[string]string{
		"resolve": resolveScopeSQL,
		"get":     getAssetSQL,
		"list":    listAssetsSQL,
		"update":  updateGovernanceSQL,
		"state":   transitionAssetSQL,
	} {
		normalized := strings.ToLower(query)
		for _, predicate := range []string{"tenant_id", "workspace_id", "environment_id"} {
			if !strings.Contains(normalized, predicate) {
				t.Errorf("%s query is missing %s", name, predicate)
			}
		}
	}
}

func TestAssetListUsesStableKeysetOrder(t *testing.T) {
	t.Parallel()
	query := strings.ToLower(listAssetsSQL)
	for _, fragment := range []string{
		"lower(a.display_name)", "a.id", "order by",
		"limit $", "a.environment_id =", "a.workspace_id =", "a.tenant_id =",
	} {
		if !strings.Contains(query, fragment) {
			t.Errorf("list query missing %q", fragment)
		}
	}
	if strings.Contains(query, " offset ") {
		t.Fatal("asset list must not use offset pagination")
	}
}
~~~

Run: `go test ./internal/assetcatalog/postgres -run 'TestAsset(Queries|List)' -count=1`

Expected: FAIL because the query constants and repository do not exist.

- [ ] **Step 2: Add fail-closed construction and database scope resolution**

~~~go
package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/seaworld008/aiops-system/internal/assetcatalog"
)

type Repository struct {
	pool  *pgxpool.Pool
	clock func() time.Time
	newID func() string
}

func New(pool *pgxpool.Pool, clock func() time.Time, newID func() string) (*Repository, error) {
	if pool == nil || newID == nil {
		return nil, errors.New("asset catalog pool and id generator are required")
	}
	if clock == nil {
		clock = time.Now
	}
	return &Repository{pool: pool, clock: clock, newID: newID}, nil
}

const resolveScopeSQL = `
SELECT w.tenant_id::text, w.id::text, e.id::text
FROM workspaces w
JOIN environments e
  ON e.tenant_id = w.tenant_id AND e.workspace_id = w.id
WHERE w.id = $1::uuid AND e.id = $2::uuid
`

func (repository *Repository) ResolveScope(
	ctx context.Context,
	workspaceID string,
	environmentID string,
) (assetcatalog.Scope, error) {
	var scope assetcatalog.Scope
	err := repository.pool.QueryRow(ctx, resolveScopeSQL, workspaceID, environmentID).
		Scan(&scope.TenantID, &scope.WorkspaceID, &scope.EnvironmentID)
	if err != nil {
		return assetcatalog.Scope{}, mapPGError(err)
	}
	return scope, nil
}
~~~

`mapPGError` must map `pgx.ErrNoRows` to `assetcatalog.ErrNotFound`, SQLSTATE `23503` to `ErrScopeViolation`, SQLSTATE `23505` to `ErrIdempotency`, SQLSTATE `23514/22P02` to `ErrInvalidRequest`, and serialization/deadlock SQLSTATE `40001/40P01` to a bounded retry followed by `ErrStateConflict`. It must never return database text to HTTP callers.

- [ ] **Step 3: Implement safe Get and keyset List**

Use one explicit column list shared by `scanAsset`; never use `SELECT *`. The filter builder may select only these allow-listed columns: `kind`、`source_id`、`lifecycle`、`mapping_status`、`service_id` and an escaped display-name search. `limit` must be 1–100.

~~~go
const assetColumns = `
a.id::text, a.tenant_id::text, a.workspace_id::text, a.environment_id::text,
a.source_id::text, a.kind, a.provider_kind, a.external_id, a.display_name,
a.lifecycle, a.mapping_status, a.owner_group, a.criticality,
a.data_classification, a.labels, a.last_observation_id::text,
a.last_observed_at, a.last_source_revision, a.version, a.created_at, a.updated_at`

const getAssetSQL = `SELECT ` + assetColumns + `
FROM assets a
WHERE a.tenant_id = $1::uuid AND a.workspace_id = $2::uuid
  AND a.environment_id = $3::uuid AND a.id = $4::uuid`

const listAssetsSQL = `SELECT ` + assetColumns + `
FROM assets a
WHERE a.tenant_id = $1::uuid AND a.workspace_id = $2::uuid
  AND a.environment_id = $3::uuid
  AND ($4::text = '' OR lower(a.display_name) LIKE $4 ESCAPE '\')
  AND ($5::text[] IS NULL OR a.kind = ANY($5))
  AND ($6::uuid[] IS NULL OR a.source_id = ANY($6))
  AND ($7::text[] IS NULL OR a.lifecycle = ANY($7))
  AND ($8::text[] IS NULL OR a.mapping_status = ANY($8))
  AND ($9::uuid IS NULL OR EXISTS (
      SELECT 1 FROM service_asset_bindings b
      WHERE b.tenant_id = a.tenant_id AND b.workspace_id = a.workspace_id
        AND b.environment_id = a.environment_id AND b.asset_id = a.id
        AND b.service_id = $9 AND b.status = 'ACTIVE'
  ))
  AND ($10::text IS NULL OR (lower(a.display_name), a.id) > ($10, $11::uuid))
ORDER BY lower(a.display_name), a.id
LIMIT $12`
~~~

Add a second constant `listAssetsLastObservedSQL` with the same selected columns, filters, and scope, but keyset predicate `($10::timestamptz IS NULL OR (a.last_observed_at,a.id) < ($10,$11::uuid))` and `ORDER BY a.last_observed_at DESC,a.id DESC`. Select between the two constants with an exhaustive `switch` on `AssetSort`; never interpolate a client sort/direction into SQL.

`List` requests `limit+1`, removes the sentinel row, and derives `Next` from either `(strings.ToLower(DisplayName),ID)` or `(LastObservedAt.UTC().Format(time.RFC3339Nano),ID)`. It rejects a cursor whose embedded sort differs from the request, copies every labels map before returning, and supports no offset. Add table tests for both sorts, empty/exact/next pages, equal sort-value UUID tie-breaks, wildcard escaping, maximum limit, and all filter combinations.

- [ ] **Step 4: Write failing real-PostgreSQL transaction tests**

~~~go
func TestCreateAssetIsReplaySafeAndAtomic(t *testing.T) {
	database := openAssetCatalogDatabase(t)
	fixture := seedAssetScope(t, database)
	repository := newAssetRepository(t, database)
	command := fixture.createAssetCommand()

	first, err := repository.Create(context.Background(), command)
	if err != nil {
		t.Fatal(err)
	}
	if first.Receipt.AuditID == "" || first.Receipt.TraceID != command.TraceID || first.Receipt.IdempotentReplay {
		t.Fatalf("first receipt = %#v", first.Receipt)
	}
	replay, err := repository.Create(context.Background(), command)
	if err != nil || replay.Asset.ID != first.Asset.ID ||
		replay.Asset.Version != first.Asset.Version || !replay.Receipt.IdempotentReplay {
		t.Fatalf("replay = (%#v, %v), want %#v", replay, err, first)
	}

	conflict := command
	conflict.DisplayName = "different-name"
	if _, err := repository.Create(context.Background(), conflict); !errors.Is(err, assetcatalog.ErrIdempotency) {
		t.Fatalf("conflicting replay error = %v", err)
	}

	assertCounts(t, database, first.Asset.ID, map[string]int{
		"assets": 1, "asset_observations": 1, "asset_type_details": 1,
		"audit_records": 1, "outbox_events": 1,
	})
}

func TestUpdateAssetRejectsStaleVersionAndRollsBackAudit(t *testing.T) {
	database := openAssetCatalogDatabase(t)
	fixture := seedPersistedAsset(t, database)
	repository := newAssetRepository(t, database)
	command := fixture.updateCommand()
	command.ExpectedVersion = fixture.Asset.Version - 1

	if _, err := repository.UpdateGovernance(context.Background(), command); !errors.Is(err, assetcatalog.ErrVersionConflict) {
		t.Fatalf("UpdateGovernance error = %v", err)
	}
	assertAssetVersionAndSideEffects(t, database, fixture.Asset.ID, fixture.Asset.Version, 0, 0)
}
~~~

Run: `TEST_DATABASE_URL='postgres://postgres:postgres@127.0.0.1:5432/aiops_test?sslmode=disable' go test ./internal/assetcatalog/postgres -run 'Test(CreateAsset|UpdateAsset)' -count=1`

Expected: FAIL because `Create` and `UpdateGovernance` are not implemented.

- [ ] **Step 5: Implement atomic create, governance update, and restricted transitions**

For every write:

1. Validate command, canonical UUIDs, SHA-256 lowercase request hash, bounded reason, and UTC microsecond times before opening the transaction.
2. Begin `pgx.Serializable`; resolve workspace/environment to a tenant within the transaction.
3. Acquire the Workspace+Idempotency-Key transaction advisory lock, query the partial-unique asset audit ledger, and either return an identical scoped replay or reject a key/hash/operation conflict; then lock the governed asset using `FOR UPDATE`.
4. On create, insert the supplied normalized Observation, append revision `1` Type Detail, then insert `DISCOVERED` Asset.
5. On replay, return the scoped resource only when operation and request hashes match; otherwise return `ErrIdempotency`. This rule covers create, governance update, transition, source create/sync, binding and conflict decisions.
6. On governance update, update only `display_name`、`owner_group`、`criticality`、`data_classification` and `labels`, using `WHERE version = $expected`, then increment version.
7. `Transition` accepts only `QUARANTINED` or `RETIRED` in this plan. It must call `CanTransition`, use the expected version, persist a bounded reason in audit metadata, and increment version.
8. Insert one low-sensitivity audit row and one outbox row with exact types `asset.created.v1`、`asset.governance.updated.v1`、`asset.quarantined.v1` or `asset.retired.v1`.
9. Outbox payload contains only IDs, lifecycle, version, and trace ID. It must not contain labels, normalized documents, provider payload, owner, external ID, endpoint, credential, token, DSN, or source error text.
10. Commit once; retry SQLSTATE `40001` at most twice with context-aware bounded jitter.

Use an explicit compare-and-swap statement:

~~~sql
UPDATE assets
SET display_name = $5,
    owner_group = $6,
    criticality = $7,
    data_classification = $8,
    labels = $9::jsonb,
    version = version + 1,
    updated_at = $10
WHERE tenant_id = $1::uuid AND workspace_id = $2::uuid
  AND environment_id = $3::uuid AND id = $4::uuid
  AND version = $11
RETURNING version, updated_at;
~~~

The implementation must differentiate not-found from stale-version using a second scope-bound existence query inside the same transaction.

- [ ] **Step 6: Verify repository behavior and race safety**

Run:

~~~bash
gofmt -w internal/assetcatalog/postgres/*.go
go test -race ./internal/assetcatalog/postgres -count=1
TEST_DATABASE_URL='postgres://postgres:postgres@127.0.0.1:5432/aiops_test?sslmode=disable' \
  go test -race ./internal/assetcatalog/postgres -run Integration -count=1
~~~

Expected: both commands PASS; the integration suite proves cross-tenant/workspace/environment reads return not found, two concurrent updates yield exactly one success and one version conflict, and rollback leaves zero partial audit/outbox rows.

- [ ] **Step 7: Commit**

~~~bash
git add internal/assetcatalog/postgres/repository.go \
  internal/assetcatalog/postgres/scope.go internal/assetcatalog/postgres/assets.go \
  internal/assetcatalog/postgres/scan.go internal/assetcatalog/postgres/assets_test.go \
  internal/assetcatalog/postgres/assets_integration_test.go
git commit -m "feat(assetcatalog): persist scoped governed assets"
~~~

### Task 4: Append-only discovery sources, runs, observations, and deterministic reconciliation

**Files:**
- Modify: **internal/assetcatalog/types.go**
- Modify: **internal/assetcatalog/repository.go**
- Create: **internal/assetdiscovery/reconciler.go**
- Create: **internal/assetdiscovery/reconciler_test.go**
- Create: **internal/assetcatalog/postgres/discovery.go**
- Create: **internal/assetcatalog/postgres/discovery_test.go**
- Create: **internal/assetcatalog/postgres/discovery_integration_test.go**

**Interfaces:**
- Consumes: normalized source batches produced outside the Control Plane process; this plan does not open target sockets and does not put provider credentials in a job payload.
- Produces: read-only `assetcatalog.SourceReadRepository` and `assetdiscovery.Reconciler.Reconcile(context.Context, Batch) (Result, error)`; Source create/sync remains exclusively owned by Tasks 13–14.
- Event contract: sync requests write `asset.source.sync.requested.v1`; completed reconciliation writes `asset.source.run.completed.v1` or `asset.source.run.failed.v1` with only IDs/counts/status.

- [ ] **Step 1: Add failing reconciliation scenario tests**

~~~go
package assetdiscovery

import (
	"context"
	"testing"
	"time"

	"github.com/seaworld008/aiops-system/internal/assetcatalog"
)

func TestReconcileIsDeterministicAndNeverOverwritesGovernance(t *testing.T) {
	store := newMemoryDiscoveryStore()
	fixture := discoveryFixture()
	store.assets[fixture.existing.ID] = fixture.existing
	reconciler := mustReconciler(store, fixture.clock)

	result, err := reconciler.Reconcile(context.Background(), Batch{
		Scope: fixture.scope, SourceID: fixture.source.ID, RunID: fixture.runID,
		ObservedAt: fixture.now, Complete: true,
		CursorBeforeHash: "0000000000000000000000000000000000000000000000000000000000000000",
		CursorAfterHash: "1111111111111111111111111111111111111111111111111111111111111111",
		PageSequence: 1, PageDigest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Items: []NormalizedItem{fixture.renamedItem, fixture.newItem},
	})
	if err != nil {
		t.Fatal(err)
	}
	updated := store.assets[fixture.existing.ID]
	if updated.OwnerGroup != fixture.existing.OwnerGroup ||
		updated.Criticality != fixture.existing.Criticality ||
		updated.DataClassification != fixture.existing.DataClassification ||
		updated.Labels["manual"] != "preserved" {
		t.Fatalf("governance was overwritten: %#v", updated)
	}
	if result.Created != 1 || result.Updated != 1 || result.Conflicts != 0 {
		t.Fatalf("result = %#v", result)
	}
}

func TestCompleteRunMarksMissingAssetsStaleAndRecoveryDoesNotActivate(t *testing.T) {
	store := newMemoryDiscoveryStore()
	fixture := discoveryFixture()
	store.assets[fixture.existing.ID] = fixture.existingActive
	reconciler := mustReconciler(store, fixture.clock)

	_, err := reconciler.Reconcile(context.Background(), Batch{
		Scope: fixture.scope, SourceID: fixture.source.ID, RunID: fixture.runID,
		ObservedAt: fixture.now, Complete: true,
		CursorBeforeHash: "0000000000000000000000000000000000000000000000000000000000000000",
		CursorAfterHash: "1111111111111111111111111111111111111111111111111111111111111111",
		PageSequence: 1, PageDigest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Items: []NormalizedItem{},
	})
	if err != nil || store.assets[fixture.existing.ID].Lifecycle != assetcatalog.LifecycleStale {
		t.Fatalf("stale reconcile = (%#v, %v)", store.assets[fixture.existing.ID], err)
	}

	_, err = reconciler.Reconcile(context.Background(), Batch{
		Scope: fixture.scope, SourceID: fixture.source.ID, RunID: fixture.nextRunID,
		ObservedAt: fixture.now.Add(time.Minute), Complete: true,
		CursorBeforeHash: "1111111111111111111111111111111111111111111111111111111111111111",
		CursorAfterHash: "2222222222222222222222222222222222222222222222222222222222222222",
		PageSequence: 1, PageDigest: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		Items: []NormalizedItem{fixture.recoveredItem},
	})
	if err != nil || store.assets[fixture.existing.ID].Lifecycle != assetcatalog.LifecycleStale {
		t.Fatalf("recovery must require review: (%#v, %v)", store.assets[fixture.existing.ID], err)
	}
}

func TestCrossSourceCandidateCreatesConflictWithoutImplicitMerge(t *testing.T) {
	store := newMemoryDiscoveryStore()
	fixture := discoveryFixture()
	store.assets[fixture.existing.ID] = fixture.existing
	reconciler := mustReconciler(store, fixture.clock)
	candidate := fixture.newItem
	candidate.Fingerprints = map[string]string{"provider_instance_id": fixture.existing.ExternalID}

	result, err := reconciler.Reconcile(context.Background(), Batch{
		Scope: fixture.scope, SourceID: fixture.secondSourceID, RunID: fixture.runID,
		ObservedAt: fixture.now, Complete: true,
		CursorBeforeHash: "0000000000000000000000000000000000000000000000000000000000000000",
		CursorAfterHash: "1111111111111111111111111111111111111111111111111111111111111111",
		PageSequence: 1, PageDigest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Items: []NormalizedItem{candidate},
	})
	if err != nil || result.Conflicts != 1 || len(store.conflicts) != 1 {
		t.Fatalf("conflict reconcile = (%#v, %v)", result, err)
	}
	if len(store.assets) != 1 {
		t.Fatal("cross-source candidate was merged or created before a decision")
	}
}
~~~

Run: `go test ./internal/assetdiscovery -count=1`

Expected: FAIL because the reconciler types do not exist.

- [ ] **Step 2: Define normalized batch and discovery repository contracts**

~~~go
package assetdiscovery

import (
	"context"
	"encoding/json"
	"time"

	"github.com/seaworld008/aiops-system/internal/assetcatalog"
)

type NormalizedItem struct {
	ProviderKind      string
	ExternalID        string
	Kind              assetcatalog.Kind
	DisplayName       string
	SourceRevision    int64
	SchemaVersion     string
	Document          json.RawMessage
	DocumentSHA256    string
	FieldProvenance   []FieldProvenance
	ProvenanceSHA256  string
	Tombstone         bool
	TombstoneReason   string
	Fingerprints      map[string]string
	ObservedRelations []ObservedRelation
}

type FieldProvenance struct {
	FieldCode       string
	ProviderPathCode string
	Ownership       string
	SourceRevision  int64
	ObservedAt      time.Time
	Confidence      int
}

type ObservedRelation struct {
	FromExternalID string
	ToExternalID   string
	Type           assetcatalog.RelationshipType
	Confidence     int
}

type Batch struct {
	Scope      assetcatalog.Scope
	SourceID   string
	RunID      string
	ObservedAt time.Time
	Complete   bool
	CursorBeforeHash string
	CursorAfterHash  string
	PageSequence     int64
	PageDigest       string
	Items      []NormalizedItem
}

type Result struct {
	RunID      string
	Created    int
	Updated    int
	Unchanged  int
	Stale      int
	Restored   int
	Tombstoned int
	Conflicts  int
	Rejected   int
}

type Store interface {
	ReconcileBatch(context.Context, Batch) (Result, error)
}

type Reconciler struct {
	store Store
}

func New(store Store) (*Reconciler, error) {
	if store == nil {
		return nil, assetcatalog.ErrInvalidRequest
	}
	return &Reconciler{store: store}, nil
}

func (reconciler *Reconciler) Reconcile(ctx context.Context, batch Batch) (Result, error) {
	if err := validateBatch(batch); err != nil {
		return Result{}, err
	}
	return reconciler.store.ReconcileBatch(ctx, canonicalizeBatch(batch))
}
~~~

Add to `assetcatalog/repository.go`:

~~~go
type SourceRun struct {
	ID                   string
	TenantID             string
	WorkspaceID          string
	SourceID             string
	SourceRevision       int64
	SourceRevisionDigest string
	RunKind              string
	Status               string
	PageSequence         int64
	PageDigest           string
	CursorBeforeHash     string
	CursorAfterHash      string
	FenceEpoch           int64
	HeartbeatSequence    int64
	ObservedFrom         time.Time
	ObservedTo           time.Time
	Created              int
	Updated              int
	Unchanged            int
	Stale                int
	Restored             int
	Tombstoned           int
	Conflicts            int
	Rejected             int
	Version              int64
	CreatedAt            time.Time
	FinishedAt           time.Time
}

type SourceReadRepository interface {
	GetSource(context.Context, string, string, string) (Source, error)
	ListSources(context.Context, ListSourcesRequest) (SourcePage, error)
	GetSourceRun(context.Context, string, string, string) (SourceRun, error)
}
~~~

`assetdiscovery.Store` owns `ReconcileBatch(context.Context, Batch) (Result, error)` and is implemented by `internal/assetcatalog/postgres.Repository`. Safe Source/run reads remain in `assetcatalog.SourceReadRepository`. This keeps the final dependency direction `assetdiscovery -> assetcatalog`; `assetcatalog` never imports `assetdiscovery`. This pack must not create a stable Source without revision 1 or enqueue a run before the complete Source revision gate exists.

- [ ] **Step 3: Implement canonical validation before persistence**

`canonicalizeBatch` must:

- sort Items by `(provider_kind, external_id)` and relations by their full tuple;
- reject more than 10,000 items or 50,000 relations per batch;
- require canonical provider/external IDs, exact lowercase 64-character document SHA-256, UTC microsecond `ObservedAt`, and unique item keys;
- reject unknown JSON fields, arrays at document root, documents over 64 KiB, label-like credential/endpoint keys, and any raw document containing secret-bearing field names;
- recompute the canonical JSON SHA-256 rather than trusting the caller;
- reject a partial batch that attempts stale detection (`Complete=false` means no missing-asset transition).
- require provenance for every source-owned normalized field; provenance field/path codes come from the Provider adapter allow-list and cannot contain raw values, JSONPath, endpoint, credential or source error text;
- accept a tombstone only with no document/relations, a stable reason code and a source revision newer than the stored observation; a tombstone is never a hard delete or automatic retirement;
- require `PageSequence > 0`, a lowercase SHA-256 `PageDigest`, and exact cursor-before equality with the current sealed checkpoint projection before persistence.

Use this exact invariant in the test:

~~~go
func TestCanonicalizeRejectsCredentialShapedDocument(t *testing.T) {
	fixture := discoveryFixture()
	fixture.newItem.Document = json.RawMessage(`{"name":"vm-1","access_token":"forbidden"}`)
	_, err := canonicalizeBatch(Batch{
		Scope: fixture.scope, SourceID: fixture.source.ID, RunID: fixture.runID,
		ObservedAt: fixture.now, Complete: true,
		CursorBeforeHash: "0000000000000000000000000000000000000000000000000000000000000000",
		CursorAfterHash: "1111111111111111111111111111111111111111111111111111111111111111",
		PageSequence: 1, PageDigest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Items: []NormalizedItem{fixture.newItem},
	})
	if !errors.Is(err, assetcatalog.ErrInvalidRequest) {
		t.Fatalf("canonicalizeBatch error = %v", err)
	}
}
~~~

- [ ] **Step 4: Implement one serializable reconciliation transaction**

For each canonical batch, `internal/assetcatalog/postgres/discovery.go` must execute this exact order:

1. Lock `asset_source_runs` by `(tenant_id, workspace_id, run_id)`. Matching `request_hash` replay returns persisted counts; a different hash returns `ErrIdempotency`.
2. Lock the `asset_sources` row in the same tenant/workspace and reject paused, disabled, or wrong-source runs.
3. Insert every Observation with `ON CONFLICT (tenant_id, workspace_id, source_id, provider_kind, external_id, source_revision) DO NOTHING`; matching replays verify `document_sha256`.
4. Match only the fixed dedupe key `(tenant_id, workspace_id, source_id, provider_kind, external_id)`.
5. New exact-source items create `DISCOVERED` assets with defaults `UNRESOLVED/INTERNAL/MEDIUM`, `owner_group="unassigned"` and empty governance labels, then append Type Detail revision 1. The sentinel renders as “未分配” and is not an inferred owner or Service.
6. Existing exact-source items update only source-owned projection fields: `display_name`、`last_observation_id`、`last_observed_at`、`last_source_revision`; append Type Detail only when document hash changes. Persist the allow-listed field-provenance digest with the Observation and preserve governance fields.
7. Cross-source fingerprint candidates create or refresh `OPEN` AssetConflict with `AMBIGUOUS`; do not create, merge, bind, or overwrite an Asset.
8. Only a complete successful run identifies source-owned assets not observed in this run. `ACTIVE` becomes `STALE`; `DISCOVERED` remains `DISCOVERED`; `QUARANTINED/RETIRED` remain unchanged.
9. A provider tombstone or complete-run absence changes `ACTIVE` to `STALE`, retires only source-owned active relation projections, and preserves Asset/Observation/Type Detail history. A recovered `STALE` asset receives the new Observation and `asset.source.asset.restored.v1` event but remains `STALE`; only the later publication/capability revalidation path may move it to `ACTIVE`.
10. Resolve relations only when both endpoint assets have exact same-source keys; otherwise record a conflict. Upsert relation version by content hash.
11. Within the same transaction and under the current run fence, advance the encrypted source checkpoint by compare-and-swap from `CursorBeforeHash` to `CursorAfterHash`, increment `checkpoint_version` and `page_sequence` once, and store only cursor/page digests in audit/outbox. A stale fence, page replay with a different digest, or checkpoint mismatch rolls back every Observation and projection mutation.
12. Mark run `SUCCEEDED` when all items were accepted or `PARTIAL` when bounded item validation produced rejections; persist counts/cursor hashes, update source `last_success_at` only for a complete applied projection, insert one safe audit row and one completion outbox event, then commit.
13. On any error, roll back batch mutations and use a separate bounded transaction to mark an already-created run `FAILED` with stable `error_code`; never persist provider error text.

Use row-level advisory locking keyed by the source UUID before processing so two different run IDs for the same source cannot reorder observations.

- [ ] **Step 5: Test append-only enforcement, stale/recovery, replay, and concurrent runs**

Run:

~~~bash
gofmt -w internal/assetcatalog internal/assetdiscovery internal/assetcatalog/postgres
go test -race ./internal/assetdiscovery ./internal/assetcatalog/postgres -count=1
TEST_DATABASE_URL='postgres://postgres:postgres@127.0.0.1:5432/aiops_test?sslmode=disable' \
  go test -race ./internal/assetcatalog/postgres -run 'TestDiscoveryIntegration' -count=1
~~~

Expected: PASS. Integration assertions include SQLSTATE `55000` for Observation/Type Detail update or delete, identical counts on replay, no governance overwrite, no stale transition on partial runs, no implicit cross-source merge, field-level provenance integrity, tombstone/recovery soft lifecycle, stale-fence rejection, atomic checkpoint advancement, and deterministic winner/order under concurrent source runs.

- [ ] **Step 6: Commit**

~~~bash
git add internal/assetcatalog/types.go internal/assetcatalog/repository.go \
  internal/assetdiscovery/reconciler.go internal/assetdiscovery/reconciler_test.go \
  internal/assetcatalog/postgres/discovery.go internal/assetcatalog/postgres/discovery_test.go \
  internal/assetcatalog/postgres/discovery_integration_test.go
git commit -m "feat(assetcatalog): reconcile append-only discovery facts"
~~~
