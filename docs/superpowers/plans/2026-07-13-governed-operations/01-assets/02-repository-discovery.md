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
- `SourceRevision` 在领域、provenance 和 PostgreSQL 中只表示 immutable Source definition revision；Provider object/version/sequence 使用各 Adapter 的闭合类型并在进入 Reconciler 前按其 checkpoint contract 验证，不能复用该字段。
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
- Create: **internal/assetcatalog/postgres/read_models.go**
- Create: **internal/assetcatalog/postgres/manual_run.go**
- Create: **internal/assetcatalog/postgres/scan.go**
- Create: **internal/assetcatalog/postgres/assets_test.go**
- Create: **internal/assetcatalog/postgres/read_models_test.go**
- Create: **internal/assetcatalog/postgres/manual_run_test.go**
- Create: **internal/assetcatalog/postgres/assets_integration_test.go**

**Interfaces:**
- Consumes: `assetcatalog.Repository`、Task 2 immutable `ManualProfileV1()`、`pgxpool.Pool`、现有 `audit_records` 和 `outbox_events`。
- Produces: `postgres.New(*pgxpool.Pool, func() time.Time, func() string) (*Repository, error)`；该对象同时实现 `assetcatalog.Reader`、`AssetReadRepository`、`ScopeResolver` 和资产写仓储，并由私有 `ManualRunExecutor` 构造唯一的同步 MANUAL validation/mutation fence；它不导出任意 token/fence factory。
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

The Red suite also asserts `GetReadModel/List` use one scoped query with Source、ACTIVE Service bindings、safe provenance/relation counts and explicit neutral operational summaries；the List statement returns server-owned `ManualCreateEligible` from the exact Task 2 built-in profile + sole authority child + current binding closure in the requested Environment。A zero `AssetReadConstraint` is rejected before SQL，restricted-empty returns zero rows，and two allowed Service IDs return their union without leaking an unbound Asset。Mutating any filter/access/sort/Scope field must change the cursor QueryDigest.

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

Use one explicit core column list shared by `scanAsset`; never use `SELECT *`. `owner_group` scans into `*string` and NULL remains a persisted unknown, not a scan error or fabricated owner。The filter builder may select only `kind`、`source_id`、`lifecycle`、`mapping_status`、`service_id`、`criticality`、`data_classification` and escaped display-name search；`limit` is 1–100.

~~~go
const assetColumns = `
a.id::text, a.tenant_id::text, a.workspace_id::text, a.environment_id::text,
a.source_id::text, a.kind, a.provider_kind, a.external_id, a.display_name,
a.lifecycle, a.mapping_status, a.owner_group, a.criticality,
a.data_classification, a.labels, a.last_observation_id::text,
a.last_observation_chain_sha256, a.last_observed_at, a.last_source_revision,
a.version, a.created_at, a.updated_at`

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
  AND ($10::text[] IS NULL OR a.criticality = ANY($10))
  AND ($11::text[] IS NULL OR a.data_classification = ANY($11))
  AND ($12::boolean OR EXISTS (
      SELECT 1 FROM service_asset_bindings access_binding
      WHERE access_binding.tenant_id = a.tenant_id
        AND access_binding.workspace_id = a.workspace_id
        AND access_binding.environment_id = a.environment_id
        AND access_binding.asset_id = a.id
        AND access_binding.service_id = ANY($13::uuid[])
        AND access_binding.status = 'ACTIVE'
  ))
  AND ($14::text IS NULL OR (lower(a.display_name), a.id) > ($14, $15::uuid))
ORDER BY lower(a.display_name), a.id
LIMIT $16`
~~~

Add `listAssetsLastObservedSQL` with identical projection/filters/scope/access but keyset predicate `($14::timestamptz IS NULL OR (a.last_observed_at,a.id) < ($14,$15::uuid))` and order `a.last_observed_at DESC,a.id DESC`. Select by exhaustive `AssetSort` switch；never interpolate client sort/direction。Validate `AssetReadConstraint` before SQL；`$12=true` is only its initialized unrestricted form，while restricted-empty uses `$12=false,$13='{}'` and therefore returns no rows。Client `Filter.ServiceID=$9` never replaces this authorization predicate.

`List` executes one `listAssetReadModelsSQL` statement built on that exact core query and joins same-Scope `asset_sources` plus a `LEFT JOIN LATERAL` aggregate of ACTIVE `service_asset_bindings→services` sorted/deduplicated by `(lower(service.name),service.id,binding_role)`。The same statement computes one collection `manual_create_eligible` bit with `EXISTS` over an exact `MANUAL/MANUAL_V1/MANUAL_V1` Source/Revision, its sole ordered authority child equal to the requested Environment, and `PublishedBindingEligible`-equivalent stored/SQL-recomputed closure；zero matching Sources returns false，one or more independently eligible Sources returns true，because no product/database contract makes MANUAL Source unique per Environment。No browser input participates。The write path still locks and revalidates the caller-selected exact `source_id`; the collection bit never chooses a Source or grants permission。It projects fixed `connection=NOT_CONFIGURED` and `capability=NOT_CONFIGURED,count=0` until their owned migrations extend the query。`GetReadModel` uses the same access predicate and one scoped statement that additionally loads the last Observation's allow-listed canonical field provenance and ACTIVE incoming/outgoing relation counts；Go decodes only the Task 2 safe summary fields and never returns document bytes。Core `Reader.Get` remains the narrow Phase 2 projection。Create/update/transition return `AssetDetailReadModel` from the same serializable transaction, so management needs no second Repository call.

`List` canonicalizes exact Tenant/Workspace/Environment、normalized filters、the server access constraint and sort to Task 2 `QueryDigest`, requests `limit+1`, removes the sentinel row, and derives `Next` from either `(strings.ToLower(DisplayName),ID)` or `(LastObservedAt.UTC().Format(time.RFC3339Nano),ID)` plus that digest. It rejects sort/value-shape or digest mismatch before SQL, deep-copies every nested model, and supports no offset. Tests cover both sorts、equal tie-breaks、wildcard escaping、all filters、two-Service union、restricted-empty and cursor replay across Scope/filter/access/sort.

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
	if first.Receipt.AuditID == "" || first.Receipt.TraceID != command.Context.TraceID() || first.Receipt.IdempotentReplay {
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
4. On create, lock the existing same-Workspace `MANUAL/MANUAL_V1` Source、its exact revision and sole authority child，then compare every immutable profile semantic to Task 2 `ManualProfileV1()` and revalidate `ACTIVE + PUBLISHED + AVAILABLE` with all revision/gate/binding digests equal；Task 13 is not a dependency. Because the built-in profile is `SINGLE_ENVIRONMENT`, require the child Environment to equal the command/path Environment exactly；same Workspace alone is insufficient. In this same serializable transaction, create and privately claim one `MANUAL_MUTATION` Run, allocate `CATALOG_SEQUENCE = source.checkpoint_version + 1`, build the allow-listed MANUAL document/provenance/fingerprint/fact/chain using database-owned Catalog time and the exact `manual-catalog-version.v1` Provider-version digest, insert its Observation, append revision `1` Type Detail, insert the `DISCOVERED` Asset, CAS the server-owned MANUAL logical checkpoint version (no ciphertext/key), and complete the Run under a private process-local fence. The command never supplies Observation、ProviderKind、Source revision、freshness、Catalog time、run/fence/checkpoint fields or canonical digests. Matching idempotent replay is returned only after current Principal/Scope/state authorization is rechecked and never allocates another sequence or Run. Add cross-Environment、missing/multiple authority child and same-code profile-semantic-drift negatives proving no Run/sequence/audit row is allocated.
5. On replay, return the scoped resource only when operation and request hashes match; otherwise return `ErrIdempotency`. This rule covers create, governance update, transition, source create/sync, binding and conflict decisions.
6. On governance update, update only `display_name`、`owner_group`、`criticality`、`data_classification` and `labels`, using `WHERE version = $expected`, then increment version.
7. `Transition` accepts only `QUARANTINED` or `RETIRED` in this plan. It must call structural `IsLifecycleEdge`, separately enforce this operation allow-list/current authorization, reject self-edges, use the expected version, persist a bounded reason in audit metadata, and increment version.
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
gofmt -w $(rg --files internal/assetcatalog/postgres -g '*.go')
go test -race ./internal/assetcatalog/postgres -count=1
TEST_DATABASE_URL='postgres://postgres:postgres@127.0.0.1:5432/aiops_test?sslmode=disable' \
  go test -race ./internal/assetcatalog/postgres -run Integration -count=1
~~~

Expected: both commands PASS; the integration suite proves cross-tenant/workspace/environment reads return not found、zero/restricted/multi-Service access semantics、one-query read-model joins and deep clones，two concurrent updates yield exactly one success and one version conflict，and rollback leaves zero partial audit/outbox rows.

- [ ] **Step 7: Commit**

~~~bash
git add internal/assetcatalog/postgres/repository.go \
  internal/assetcatalog/postgres/scope.go internal/assetcatalog/postgres/assets.go \
  internal/assetcatalog/postgres/read_models.go internal/assetcatalog/postgres/read_models_test.go \
  internal/assetcatalog/postgres/manual_run.go internal/assetcatalog/postgres/manual_run_test.go \
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
- Create: **internal/assetcatalog/postgres/source_reads.go**
- Create: **internal/assetcatalog/postgres/source_reads_test.go**
- Create: **internal/assetcatalog/postgres/source_reads_integration_test.go**

**Interfaces:**
- Consumes: normalized source batches produced outside the Control Plane process; this plan does not open target sockets and does not put provider credentials in a job payload.
- Produces: read-only `assetcatalog.SourceReadRepository` and `assetdiscovery.Reconciler.Reconcile(context.Context, assetcatalog.LeaseFence, Batch) (Result, error)`; Source create/sync remains exclusively owned by Tasks 13–14.
- Event contract: sync requests write `asset.source.sync.requested.v1`; completed reconciliation writes `asset.source.run.completed.v1` or `asset.source.run.failed.v1` with only IDs/counts/status.

- [ ] **Step 1: Add failing reconciliation scenario tests**

~~~go
package assetdiscovery

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/seaworld008/aiops-system/internal/assetcatalog"
)

func TestReconcileIsDeterministicAndNeverOverwritesGovernance(t *testing.T) {
	store := newMemoryDiscoveryStore()
	fixture := discoveryFixture()
	store.assets[fixture.existing.ID] = fixture.existing
	reconciler := mustReconciler(store, fixture.clock)

	result, err := reconciler.Reconcile(context.Background(), fixture.fenceFor(fixture.runID), Batch{
		Scope: fixture.sourceScope, SourceID: fixture.source.ID, RunID: fixture.runID,
		FinalPage: true, CompleteSnapshot: true,
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
	if result.Created != 1 || result.Changed != 1 || result.Conflicts != 0 {
		t.Fatalf("result = %#v", result)
	}
}

func TestCompleteRunMarksMissingAssetsStaleAndRecoveryDoesNotActivate(t *testing.T) {
	store := newMemoryDiscoveryStore()
	fixture := discoveryFixture()
	store.assets[fixture.existing.ID] = fixture.existingActive
	reconciler := mustReconciler(store, fixture.clock)

	_, err := reconciler.Reconcile(context.Background(), fixture.fenceFor(fixture.runID), Batch{
		Scope: fixture.sourceScope, SourceID: fixture.source.ID, RunID: fixture.runID,
		FinalPage: true, CompleteSnapshot: true,
		CursorBeforeHash: "0000000000000000000000000000000000000000000000000000000000000000",
		CursorAfterHash: "1111111111111111111111111111111111111111111111111111111111111111",
		PageSequence: 1, PageDigest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Items: []NormalizedItem{},
	})
	if err != nil || store.assets[fixture.existing.ID].Lifecycle != assetcatalog.LifecycleStale {
		t.Fatalf("stale reconcile = (%#v, %v)", store.assets[fixture.existing.ID], err)
	}

	_, err = reconciler.Reconcile(context.Background(), fixture.fenceFor(fixture.nextRunID), Batch{
		Scope: fixture.sourceScope, SourceID: fixture.source.ID, RunID: fixture.nextRunID,
		FinalPage: true, CompleteSnapshot: true,
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

	result, err := reconciler.Reconcile(context.Background(), fixture.fenceFor(fixture.runID), Batch{
		Scope: fixture.sourceScope, SourceID: fixture.secondSourceID, RunID: fixture.runID,
		FinalPage: true, CompleteSnapshot: true,
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

func TestHigherFreshnessKindDriftRollsBackWholePage(t *testing.T) {
	fixture := persistedDiscoveryFixture()
	drifted := fixture.nextItem
	drifted.Kind = assetcatalog.KindDatabase
	before := fixture.snapshotCountsAndCheckpoint(t)
	_, err := fixture.reconcile(drifted)
	if !errors.Is(err, assetcatalog.ErrSourceAssetKindDrift) {
		t.Fatalf("kind drift error = %v", err)
	}
	fixture.assertCountsAndCheckpointEqual(t, before) // no Observation/receipt/checkpoint
}

func TestProviderFactGoldenBindsEveryProjectionInputButNotCatalogTime(t *testing.T) {
	base := semanticFactFixture()
	want := goldenProviderFactDigest()
	if got := providerFactSHA256(base); got != want {
		t.Fatalf("provider fact = %s, want %s", got, want)
	}
	for _, mutate := range []func(*SemanticFact){changeKind, changeDisplayName, changeFingerprintSet} {
		candidate := base.Clone(); mutate(&candidate)
		if providerFactSHA256(candidate) == want { t.Fatal("projection input was not bound") }
	}
	base.CatalogObservedAt = base.CatalogObservedAt.Add(time.Hour)
	if providerFactSHA256(base) != want { t.Fatal("Catalog time changed semantic fact") }
	assertLaterRunAppendsUnchangedObservation(t, base)
}

func TestCompleteClosureSeesRelationsFromFinalAndIntermediatePages(t *testing.T) {
	assertRelationRemainsActiveWhenSeenOnlyOnFinalPage(t)
	assertRelationRemainsActiveWhenSeenOnlyOnIntermediatePage(t)
}
~~~

The same Red commit adds SQL-shape/scan/integration tests for `ResolveSourceScope`、`GetSource`、`ListSources` and `GetSourceRun`. They require explicit safe columns, ordered authority-child aggregation, one scoped query per read, keyset `(source.id ASC)` with QueryDigest, exact latest/published/current/last-success joins, and no checkpoint ciphertext/key、lease/token、canonical schema bytes or provider payload. A zero SourceReadConstraint rejects before SQL；restricted-empty returns none；a multi-Environment Source is visible only when its complete authority set is a subset of the allowed IDs；manual-create usage requires exactly one authority Environment equal to the requested Environment. `PARTIAL` and aggregate max-completed logic can never become last-success.

Run: `go test ./internal/assetdiscovery ./internal/assetcatalog/postgres -run 'Test(Reconcile|SourceRead)' -count=1`

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
	EnvironmentID     string
	ProviderKind      string
	ExternalID        string
	Kind              assetcatalog.Kind
	DisplayName       string
	SchemaVersion     string
	Document          json.RawMessage
	DocumentSHA256    string
	Freshness         FreshnessCandidate
	FieldProvenance   []FieldProvenance
	Tombstone         bool
	TombstoneReason   string
	Fingerprints      map[string]string
}

type FreshnessCandidate struct {
	Kind                  assetcatalog.FreshnessKind
	OrderTime             *time.Time
	OrderSequence         int64
	ProviderVersionSHA256 string
}

type FieldProvenance struct {
	FieldCode        string
	ProviderPathCode string
	Ownership        string
	Confidence       int
}

type ObservedRelation struct {
	SourceEnvironmentID string
	TargetEnvironmentID string
	FromExternalID      string
	ToExternalID        string
	Type                assetcatalog.RelationshipType
	ProviderPathCode    string
	Confidence          int
	Freshness           FreshnessCandidate
}

type Batch struct {
	Scope            assetcatalog.SourceScope
	SourceID         string
	RunID            string
	FinalPage        bool
	CompleteSnapshot bool
	CursorBeforeHash string
	CursorAfterHash  string
	PageSequence     int64
	PageDigest       string
	Items            []NormalizedItem
	Relations        []ObservedRelation
}

type Result struct {
	RunID      string
	Observed   int
	Created    int
	Changed    int
	Unchanged  int
	Conflicts  int
	Missing    int
	Stale      int
	Restored   int
	Tombstoned int
	Rejected   int
}

type Store interface {
	ReconcileBatch(context.Context, assetcatalog.LeaseFence, Batch) (Result, error)
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

func (reconciler *Reconciler) Reconcile(
	ctx context.Context,
	fence assetcatalog.LeaseFence,
	batch Batch,
) (Result, error) {
	if err := validateBatch(batch); err != nil {
		return Result{}, err
	}
	canonical, err := canonicalizeBatch(batch)
	if err != nil {
		return Result{}, err
	}
	return reconciler.store.ReconcileBatch(ctx, fence, canonical)
}
~~~

`PageDigest` is never trusted caller text. After canonical sorting, Repository computes `item_page_sha256 = SHA256(FramedTupleV1("asset-item-page.v1",item_count,repeated environment_id,provider_kind,external_id,freshness_kind,freshness_order_time-or-NULL,freshness_order_sequence,provider_version_sha256,provider_fact_sha256))` and the Pack 01 `relation_page_sha256` over independently sorted top-level relations. It then recomputes `PageDigest = SHA256(FramedTupleV1("asset-source-page.v2",tenant_id,workspace_id,source_id,run_id,page_sequence,cursor_before_sha256,cursor_after_sha256,final_page,complete_snapshot,item_count,item_page_sha256,relation_count,relation_page_sha256))` and requires exact equality. Asset and relation semantic digests exclude Catalog time/Observation ID, so relation-only pages and exact replay are identifiable without duplicating an Item. The immutable page receipt uses `audit_records.resource_type='ASSET_SOURCE_RUN'`, operation `PAGE_APPLIED`, request ID `source-page:<run_uuid>:<page_sequence>`, `payload_hash=PageDigest`, and a closed safe metadata object containing only cursor hashes、final flags、item/relation page digests and exact per-page/cumulative counts；Workspace request-key uniqueness prevents a second receipt.

`LeaseFence` is the sealed process-local value defined in Pack 01 and returned by Queue claim: exact Run ID、owner、epoch and a private 32-byte raw token. It rejects JSON/text/log serialization and exposes only constant-time comparison against the already locked PostgreSQL Run coordinates/token hash; raw token never enters `Batch`、Task payload、audit、outbox or errors. Provider items cannot submit Source definition revision or Catalog time. The Repository injects both from the locked Run and database clock, and the Profile Registry fixes the only legal `FreshnessKind` for that canonical revision.

Consume the exact `assetcatalog.SourceScope`、typed safe `SourceRun` and `SourceReadRepository` definitions from Task 2；this task must not redeclare or widen them. The internal PostgreSQL Run row additionally retains the opaque cleanup attempt ID/epoch and cleanup/terminal receipt digests required by Pack 09, while the public `SourceRun` structurally omits them. `SourceScope` is exactly Tenant+Workspace because Source/Run rows stop at Workspace；every normalized Fact carries its explicit Environment and Repository resolves that Environment inside the Source's immutable authority mapping. `assetdiscovery.Store` owns `ReconcileBatch(context.Context, assetcatalog.LeaseFence, Batch) (Result, error)` and is implemented by `internal/assetcatalog/postgres.Repository`. This keeps the final dependency direction `assetdiscovery -> assetcatalog`; `assetcatalog` never imports `assetdiscovery`. This pack must not create a stable Source without revision 1 or enqueue a run before the complete Source revision gate exists.

`source_reads.go` implements—rather than redefines—the Task 2 interfaces. `ResolveSourceScope(workspaceID)` reads the canonical Tenant/Workspace pair. `GetSource/ListSources` select exact `asset_sources` safe fields and use LATERAL subqueries for max Revision, exact published pointer, unique current nonterminal Run, and the Source's persisted exact last-success pointer；each Revision aggregates `asset_source_revision_authorities` as a lowercase UUID array ordered by ordinal and rejects zero/noncontiguous/digest-inconsistent results in scan validation. `GetSourceRun` joins its parent Source and that Run's exact Revision/authority rows before applying the same full-subset access rule. Filters are closed enums, limit is 1–100, order is `source.id ASC`, cursor holds `(QueryDigest,SourceID)`, and QueryDigest covers resolved SourceScope、normalized filters、usage、EnvironmentID and sorted server allow-list. No read uses aggregate counts, `MAX(completed_at)` or a caller-supplied visibility flag.

- [ ] **Step 3: Implement canonical validation before persistence**

`canonicalizeBatch` must:

- sort Items by `(provider_kind, external_id)` and relations by their full tuple;
- reject more than 10,000 items or 50,000 relations per batch;
- require canonical Environment/provider/external IDs, exact lowercase 64-character document SHA-256 for non-tombstones, a Profile-allowed `FreshnessCandidate`, and unique `(provider_kind,external_id)` keys within the page；Repository plus the same-Run unique constraint rejects Item duplicates across different pages of the Run, because a page-local canonicalizer cannot prove prior-page membership;
- require each top-level Relation to carry both explicit Environment IDs、both external IDs、a Profile-allowed independent freshness candidate and an allowed path/confidence；its stable same-Run identity `(source_environment_id,target_environment_id,from_external_id,to_external_id,type,provider_path_code)` must be unique within the page, and the persisted Relationship last-Run/page coordinates reject a duplicate on any other page as `SOURCE_RUN_RELATION_DUPLICATE`;
- reject unknown JSON fields, arrays at document root, documents over 64 KiB, label-like credential/endpoint keys, and any raw document containing secret-bearing field names;
- recompute the canonical JSON SHA-256 rather than trusting the caller;
- require `CompleteSnapshot` to imply `FinalPage`; an intermediate page (`FinalPage=false`) keeps the Run `RUNNING`, while a final incremental page may use `FinalPage=true, CompleteSnapshot=false` and never performs missing-asset transitions;
- require provenance for every source-owned normalized field and observed relation; provenance field/path codes come from the Provider adapter allow-list, confidence is an integer 0–100, and neither can contain raw values, JSONPath, endpoint, credential or source error text; Repository injects Source ID/provider/revision and Catalog acceptance time;
- accept an Item tombstone only with no document, empty Kind/DisplayName/fingerprints, a stable reason code and a Profile-allowed freshness candidate；relations remain separate facts and cannot use tombstone shape. Repository derives the exact Source definition revision from the locked Run, and a tombstone is never a hard delete or automatic retirement;
- permit a relation-only page but reject a page with neither Items nor Relations unless it is the final empty authoritative snapshot. Each relation's endpoints must already exist as exact same-Source Assets from a prior committed page/Run or be created by Items in this same page；Adapters must buffer/reorder an edge until both endpoints are ready, and exceeding the bounded buffer fails closed as `SOURCE_RELATION_ENDPOINT_NOT_READY` without checkpoint advance;
- require `PageSequence > 0`, recompute the exact domain-separated `PageDigest` above, and require exact cursor-before equality with the current sealed checkpoint projection before persistence.

Use this exact invariant in the test:

~~~go
func TestCanonicalizeRejectsCredentialShapedDocument(t *testing.T) {
	fixture := discoveryFixture()
	fixture.newItem.Document = json.RawMessage(`{"name":"vm-1","access_token":"forbidden"}`)
	_, err := canonicalizeBatch(Batch{
		Scope: fixture.sourceScope, SourceID: fixture.source.ID, RunID: fixture.runID,
		FinalPage: true, CompleteSnapshot: true,
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

1. Canonicalize the page and compute its stable request/page digest before allocating an Observation ID or Catalog time. Immediately after beginning the serializable transaction, read its fixed server `transaction_timestamp()` once；this value is not yet an allocated Observation fact and must be reused unchanged if the transaction reaches insertion. Lock `asset_source_runs` by `(tenant_id,workspace_id,run_id)`. First check the immutable safe `ASSET_SOURCE_RUN/PAGE_APPLIED` audit receipt keyed by `(run_id,page_sequence,page_digest)`: an exact replay validates scope、cursor/final markers、incoming freshness/semantic digests and all stored Observation coordinates, then returns the persisted per-page/cumulative result without requiring a now-destroyed terminal fence and without any mutation. This covers a committed final-page response loss even after the Run is terminal; a stale Worker gains no write authority. A same/lower page sequence with a different receipt/digest is `ErrIdempotency`. Only a genuinely new page proceeds to exact live owner/raw-token hash/epoch/unexpired-lease admission.
2. Lock the `asset_sources` row in the same tenant/workspace and reject paused, disabled, wrong-source, gate/revision/digest/checkpoint drift. Lock each exact Asset and its last Observation, then every addressed Relationship in deterministic identity order；resolve and authorize every item/relation Environment against the immutable revision authority. Before allocating any Observation, reject an existing exact-source Asset whose immutable `kind` differs from the incoming non-tombstone Kind as `SOURCE_ASSET_KIND_DRIFT`; the whole page rolls back and checkpoint does not advance.
3. Registry validates each asset and relation `FreshnessCandidate`, then Repository uses Pack 01's sole `FramedTupleV1` encoder to compute full persisted provenance, time-free Provider provenance, fingerprints, asset semantic `provider_fact_sha256`, independent `relation_fact_sha256` and Observation-chain digests. For an asset, compare the locked prior Source definition revision and `(freshness order,provider_version_sha256,provider_fact_sha256)`：a smaller order rolls back the whole page as `SOURCE_FRESHNESS_REGRESSION`; an equal order with a different Provider-version or semantic-fact digest rolls back as `SOURCE_FRESHNESS_COLLISION`; an equal fully identical tuple in the same Run is replay, while in a later Run it appends an unchanged Observation; a greater order appends an Observation and is `Unchanged` when semantic fact is equal or `Changed` when it differs. Relations use the same comparisons against their independently persisted last freshness/fact tuple. A new canonical Source revision starts a new freshness domain only after exact publication initializes its checkpoint；checkpoint-lineage rollover does not reset object freshness. Tombstone follows the same rule. Regression/collision is never item-level PARTIAL and never advances checkpoint.
4. Use only the transaction-fixed `transaction_timestamp()` read in step 1 as every new `observed_at` and inject that exact canonical UTC microsecond value into provenance/chain bytes. After locking the prior Asset/Observation, if this transaction timestamp is not strictly later than the prior `observed_at`, roll back the whole page and retry from a new serializable transaction with a fresh timestamp；never derive a replacement with `clock_timestamp()`、`statement_timestamp()` or `max(prior+1 microsecond)`. Provider update/event time exists only in freshness/checkpoint proof.
5. Before allocating any new Observation ID/time/chain or advancing an Asset pointer, query the exact same-Run identity `(tenant_id,workspace_id,source_id,run_id,provider_kind,external_id)`. Existing rows are replay only when **all** belong to the same `page_sequence + page_digest + immutable page receipt`; verify Environment、Source definition revision、accepted checkpoint/fence/page coordinates、freshness、tombstone shape and semantic/document/fingerprint/full-provenance/chain digests and return that receipt. If the key exists on another page of the same Run—even with identical content—fail the whole page as `SOURCE_RUN_OBJECT_DUPLICATE`; mixed present/absent state under a purported receipt is corruption. For a nonterminal immediate replay the Asset must still point to that Observation；for a historical terminal replay, the current pointer must be that Observation or a later immutable chain descendant. Only the absent path allocates database Catalog time/ID/chain and inserts；`ON CONFLICT ... DO NOTHING` remains a final race defense, never the primary replay algorithm. A later Run under the same published revision always appends. The new row's `previous_observation_id/previous_chain_sha256` must match the locked Asset pointer；pointer CAS prevents ABA.
6. Match only the fixed dedupe key `(tenant_id, workspace_id, source_id, provider_kind, external_id)`.
7. New exact-source items create `DISCOVERED` assets with defaults `UNRESOLVED/INTERNAL/MEDIUM`, SQL `owner_group=NULL` and empty governance labels, then append exact-identity Type Detail revision 1. API/UI renders NULL as “未分配”；no sentinel is persisted or inferred as an owner/Service.
8. Existing exact-source items update only source-owned projection fields: `display_name`、exact last Observation/chain、`last_observed_at`、`last_source_revision`; append Type Detail only when normalized detail hash changes. Preserve governance fields.
9. Cross-source fingerprint candidates create or refresh `OPEN` AssetConflict with the exact candidate Source+Observation and `AMBIGUOUS`; do not create, merge, bind, or overwrite an Asset.
10. Process top-level relations after same-page Items **before any final membership closure**. Resolve both explicit Environment+external keys only to exact same-Source Assets and require both Environments in the immutable authority scope；an endpoint not yet committed/created is `SOURCE_RELATION_ENDPOINT_NOT_READY`, while an unauthorized/cross-source endpoint is a relation conflict. Before mutation, check the Relationship's last Run/page identity：the same relation identity on another page of this Run is `SOURCE_RUN_RELATION_DUPLICATE`；an exact replay is served only by its immutable page receipt. Compare independent relation freshness/version/fact as in step 3, upsert the current projection and its last exact Run/page/fact coordinates, and include every accepted relation in the immutable page receipt. A later Run with an unchanged relation still advances its last-seen coordinates and appends receipt evidence but does not change semantic relationship fields.
11. After step 10 has written every final-page relation coordinate, only a `FinalPage=true, CompleteSnapshot=true` Run with zero projection/schema/DLP/identity/relation rejections proves authoritative asset-and-relation membership closure and identifies source-owned Assets/Relationships not observed anywhere in this Run. Any rejection makes effective `CompleteSnapshot=false`, yields no missing/stale/inactive transition, and cannot update `last_complete_snapshot_at`；the system does not guess membership from a partially parsed record. Missing `ACTIVE` Assets become `STALE`；`DISCOVERED` remains `DISCOVERED`；`QUARANTINED/RETIRED` remain unchanged. Missing source-owned active Relationships become `INACTIVE` by their last-seen Run coordinate. Intermediate pages, final incremental Runs and all `PARTIAL` Runs never perform either missing detection. Tests cover a relation present only on the final page and one present only on an intermediate page so neither is falsely inactivated.
12. A fresh Provider tombstone or complete-run absence changes `ACTIVE` to `STALE`, retires only source-owned active relation projections, and preserves Asset/Observation/Type Detail history. A recovered `STALE` Asset receives the new Observation and `asset.source.asset.restored.v1` event but remains `STALE`；only later publication/capability revalidation may move it to `ACTIVE`.
13. Within the same transaction and under the current Run fence, advance the Source checkpoint by CAS from `CursorBeforeHash` to `CursorAfterHash`, increment checkpoint/page sequence once, revalidate the live fence using `clock_timestamp()` immediately before commit, and insert an immutable safe page receipt with exact page/cumulative counts. Non-MANUAL checkpoints use the exact `CheckpointAAD`; MANUAL uses only its logical Catalog-sequence CAS. Any stale fence/page/checkpoint mismatch rolls back Observation, projection, receipt, audit and outbox together.
14. Intermediate pages persist page/checkpoint/count progress and leave the Run `RUNNING` with no completion event. A final page persists `DATA_PROJECTION` with proposed `SUCCEEDED|PARTIAL`, final/effective-complete-snapshot flags, exact work-result digest and `work_result_recorded_at`, then transitions only to `FINALIZING/CLEANING_UP`；it does not set `completed_at`、Source success pointers or emit a completion event. After Broker-backed Provider/runtime cleanup, `Queue.Complete` verifies the terminal command's Run ID、work-result digest and `REVOKED|NO_CREDENTIAL` cleanup digest, atomically writes its receipt and terminal status/`completed_at`, advances `last_success_run_id/at` only for `SUCCEEDED` non-Validation data Runs, advances `last_complete_snapshot_run_id/at` only for `SUCCEEDED + effective complete_snapshot=true`, and emits completion audit/outbox. `PARTIAL` advances neither pointer. `MANUAL_MUTATION` supplies `NO_CREDENTIAL` and performs both transitions inside its one transaction.
15. On any reconciliation error, roll back every batch mutation and return only a typed stable error code to the Worker；Reconciler never writes `FAILED` itself. The Worker first calls fenced `Queue.PrepareFailureIntent` to persist that exact stable code/digest and enter `FINALIZING/CLEANING_UP`, then revokes any cleanup attempt and persists its receipt, and finally calls `Queue.Fail` to consume the already-persisted intent. The synchronous MANUAL transaction rolls back in full and returns its stable error without leaving a Run. Provider error text is never persisted.

Do not create a second discovery-ownership mechanism with advisory locks. The durable Queue's partial unique nonterminal-Run constraint and lease/fence establish ownership；inside each page transaction, the Repository locks the exact Run then Source row and prior projections in deterministic order. Any impossible second nonterminal Run is rejected as corruption rather than serialized by a parallel lock. Transactional advisory locking remains limited to the separate Idempotency-Key ledger described in Task 2.

- [ ] **Step 5: Test append-only enforcement, stale/recovery, replay, and concurrent runs**

Run:

~~~bash
gofmt -w $(rg --files internal/assetcatalog internal/assetdiscovery -g '*.go')
go test -race ./internal/assetdiscovery ./internal/assetcatalog/postgres -count=1
TEST_DATABASE_URL='postgres://postgres:postgres@127.0.0.1:5432/aiops_test?sslmode=disable' \
  go test -race ./internal/assetcatalog/postgres -run 'TestDiscoveryIntegration' -count=1
~~~

Expected: PASS. Integration assertions include SQLSTATE `55000` for Observation/Type Detail update or delete, identical counts on replay, no governance overwrite, no stale transition on partial runs, no implicit cross-source merge, field-level provenance integrity, tombstone/recovery soft lifecycle, stale-fence rejection, atomic checkpoint advancement, and deterministic winner/order under concurrent source runs；Source reads prove cross-Scope rejection、zero/restricted/full-subset/multi-Environment access、manual sole-authority usage、deep clones、cursor drift rejection、exact pointer joins and structurally safe Run projection.

- [ ] **Step 6: Commit**

~~~bash
git add internal/assetcatalog/types.go internal/assetcatalog/repository.go \
  internal/assetdiscovery/reconciler.go internal/assetdiscovery/reconciler_test.go \
  internal/assetcatalog/postgres/discovery.go internal/assetcatalog/postgres/discovery_test.go \
  internal/assetcatalog/postgres/discovery_integration_test.go \
  internal/assetcatalog/postgres/source_reads.go internal/assetcatalog/postgres/source_reads_test.go \
  internal/assetcatalog/postgres/source_reads_integration_test.go
git commit -m "feat(assetcatalog): reconcile append-only discovery facts"
~~~
