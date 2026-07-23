# Asset Catalog Schema and Domain Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans. 本包的 Files/Interfaces/安全契约/最终证据继续有效；当前 `M0-asset-domain-contract` 的实施顺序与验证频率以[快速开发与真实验收计划](../../2026-07-15-fast-development-validation-program.md)为准。

**Goal:** 用 `000015_assets_catalog` 建立十二张生产级资产目录表、不可变 Source Revision/authority membership、独立 Limiter bucket/permit receipt、强作用域/生命周期与最窄 parent-lock 约束，并定义后续 Connection、Grant 和前端共同消费的稳定 Go 领域接口。

**Architecture:** PostgreSQL 保存 append-only 外部观测与带版本治理投影；Go 领域层把来源事实、治理事实、生命周期、映射和 Service Binding 分开。数据库约束是最后防线，Repository/HTTP 的校验不能替代复合外键、CAS、不可变触发器和受保护回滚。

**Tech Stack:** Go 1.26.5、PostgreSQL 18.4、pgx v5、PostgreSQL 18 core `sha256(bytea)`、现有 `audit_records`/`outbox_events`。

## Global Constraints

- 规范事实源：`docs/superpowers/specs/2026-07-13-operational-assets-controlled-access-design.md`。
- 实施前用 superpowers:using-git-worktrees 创建仓库目录树之外的独立 worktree；不得删除或修改用户已有 `.worktrees/*`。
- Go 固定 `go 1.26`、`toolchain go1.26.5`；集成数据库只接受 PostgreSQL 18.4 或更新 18.x。
- 本包只拥有 `migrations/000015_assets_catalog.{up,down}.sql`；000016 Connection、000017 VictoriaMetrics、000018 Grant、000019 主机/PostgreSQL、000020 治理能力均不得提前实现。
- 000015 只创建 `asset_sources`、`asset_source_revisions`、`asset_source_revision_authorities`、`asset_source_runs`、`asset_source_limit_buckets`、`asset_source_limit_permits`、`asset_observations`、`assets`、`asset_type_details`、`asset_conflicts`、`asset_relationships`、`service_asset_bindings`。
- 保留 `services`、`service_bindings`、`integrations` 及未知 JSONB；未知 JSONB 不能解释为运行能力。
- 所有跨作用域引用使用 Tenant + Workspace + Environment（来源级对象止于 Workspace）；不能只信全局 UUID。
- 去重键固定 `(tenant_id, workspace_id, source_id, provider_kind, external_id)`；跨来源合并必须走 Conflict/Decision。
- Observation 与 Type Detail revision append-only；Asset 是带 `version` 的管理态投影。
- 发现同步不得覆盖 Service、Owner、关键度、数据等级和人工标签。
- 生命周期严格为已确认状态图；`RETIRED` 终态。本阶段不公开 `ACTIVE`，但数据库为后续“来源有效 + 映射 EXACT + Connection 已发布/复验”门禁保留合法边；Capability availability 保持独立状态。
- 文本/JSON/bytea/数组有明确字节与数量上限；Hash 为 lowercase SHA-256；时间统一 UTC microsecond。
- 生产实现不得使用内存 fake；fake 仅可在测试文件。持久化必须适配多副本、事务重试、滚动升级和数据库故障转移。
- 迁移必须提供备份/恢复演练：恢复到迁移 000015 后约束、行数、Hash 和审计关联一致；禁止有数据时 down。
- 指标仅用低基数标签：migration/version/result、repository operation/result；不得使用租户/资产/Subject/外部 ID。
- Schema/领域完成不代表生产验收；03–04 必须接入真实 OIDC、闭合 OpenAPI 和生成类型前端，05 必须以真实 PostgreSQL/Keycloak E2E、指标、备份恢复和 HA 演练收口，fake 只能存在于测试。
- 这是完整生产闭环的基础，不是 demo/read-only pilot；最终路线会进入受治理生产写，本包不提前开放目标写能力。
- C0 枚举/摘要/身份/fence 契约保留定向 Red → Green；其余 Task 2 实现与关键行为测试在同一 Batch 完成，不要求 test-only commit 或逐 checkbox 重跑完整 Task 1 恢复矩阵。
- `M0` 通过 G2 后可进入 [02-repository-discovery.md](./02-repository-discovery.md)；本包完整真库/恢复/安全矩阵作为 G3/G4 最终验收证据保留。

---

### Task 1: PostgreSQL 18.4 schema, invariants, rollback guard, and recovery proof

**Files:**
- Modify: **migrations/000015_assets_catalog.up.sql**
- Modify: **migrations/000015_assets_catalog.down.sql**
- Modify: **internal/assetcatalog/postgres/migration_test.go**; Create: **internal/assetcatalog/postgres/migration_corrective_test.go**
- Modify: **internal/assetcatalog/postgres/migration_integration_test.go**
- Modify: **internal/assetcatalog/postgres/migration_shape_integration_test.go**
- Modify: **internal/assetcatalog/postgres/migration_contract_integration_test.go**
- Modify: **internal/assetcatalog/postgres/migration_adversarial_contract_integration_test.go**
- Modify: **internal/assetcatalog/postgres/migration_closure_adversarial_integration_test.go**
- Modify: **internal/assetcatalog/postgres/migration_final_contract_integration_test.go**
- Modify: **internal/assetcatalog/postgres/migration_run_replay_acceptance_integration_test.go**
- Modify: **internal/assetcatalog/postgres/migration_reclaim_acceptance_integration_test.go**
- Modify: **internal/assetcatalog/postgres/migration_scope_shape_acceptance_integration_test.go**
- Modify: **internal/assetcatalog/postgres/migration_scope_remaining_acceptance_integration_test.go**
- Modify: **internal/assetcatalog/postgres/migration_freshness_domain_acceptance_integration_test.go**
- Modify: **internal/assetcatalog/postgres/migration_online_compatibility_integration_test.go**
- Modify: **internal/assetcatalog/postgres/migration_recovery_integration_test.go**
- Modify: **internal/assetcatalog/postgres/recovery_container_test.go**
- Modify: **internal/assetcatalog/postgres/schema_admission.go**
- Modify: **internal/assetcatalog/postgres/schema_admission_test.go**
- Modify: **internal/assetcatalog/postgres/schema_admission_integration_test.go**
- Create: **internal/store/postgres/database_role_admission.go**, **internal/store/postgres/database_role_admission_test.go**
- Create: **docs/operations/database-role-bootstrap.md**; Modify: **docs/operations/local-postgresql-development.md**, **scripts/with-local-postgres.sh**, **.env.example**, **.github/workflows/ci.yml**
- Modify: **internal/store/postgres/migrations_integration_test.go**
- Modify: **internal/investigation/postgres/testpostgres_test.go**
- Modify: **internal/investigation/postgres/correlation_create_integration_test.go**
- Modify: **internal/investigation/postgres/latest_runtime_fixture_integration_test.go**
- Modify: **Makefile**

**Interfaces:**
- Consumes candidates from 000002: `workspaces(tenant_id,id)`、`environments(tenant_id,workspace_id,id)`、`integrations(tenant_id,workspace_id,id)`、`services(tenant_id,workspace_id,id)`。
- Produces `assets UNIQUE (tenant_id,workspace_id,environment_id,id)` for 000016 Connection.
- Produces Workspace/Environment-scoped candidate keys for the other eleven tables, including the exact Revision/Environment authority key、Source/Run/Provider permit identity and three canonical Limiter bucket identities.
- Produces the deployment-preprovisioned base database-role ABI and its production startup/CI admission; later migrations extend only its reviewed extension-owner manifest.
- Does not change any 000001–000014 table definition.

The original nine-table/32-function implementation remains historical evidence。The 2026-07-14 preflight first reopened Steps 1–7 for the corrective ten-table/profile/authority/definition/binding/future-hook/opaque/NOWAIT/manifest contract；Steps 2–4 were then completed and independently approved in `d557237`。The first 2026-07-15 Step 8 review returned `REJECT/P1` only because the corrective Profile/authority/digest/opaque/typed/future-hook behavior lacked a persistent PostgreSQL 18.4 regression matrix，so Steps 1/5/6/7 were reopened while Steps 2–4 remained checked。Regression commit `ba99233` closed that evidence gap without exposing a production defect，and the follow-up Step 8 review returned `APPROVE` with no P0–P3 or reopened step。Task 2 has since entered `BUILDING_CLOSED` under Batch `M0-asset-domain-contract`.
- [x] **Step 1: Write failing ownership and invariant shape tests**

~~~go
package postgres_test

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestAssetCatalogMigrationOwnsExactTablesAndGuardsData(t *testing.T) {
	up := strings.ToLower(readMigration(t, "000015_assets_catalog.up.sql"))
	down := strings.ToLower(readMigration(t, "000015_assets_catalog.down.sql"))
	owned := []string{
		"asset_sources", "asset_source_revisions", "asset_source_revision_authorities", "asset_source_runs", "asset_observations", "assets",
		"asset_source_limit_buckets", "asset_source_limit_permits",
		"asset_type_details", "asset_conflicts", "asset_relationships",
		"service_asset_bindings",
	}
	for _, table := range owned {
		if !strings.Contains(up, "create table "+table) {
			t.Errorf("up does not create %s", table)
		}
		if !strings.Contains(down, "drop table "+table) {
			t.Errorf("down does not drop %s", table)
		}
	}
	for _, forbidden := range []string{
		"connection_profiles", "published_targets", "asset_snapshots",
		"investigation_grants", "runner_realms", "credential_references",
	} {
		if strings.Contains(up, "create table "+forbidden) {
			t.Errorf("000015 illegally owns %s", forbidden)
		}
	}
	for _, required := range []string{
		"unique (tenant_id, workspace_id, source_id, provider_kind, external_id)",
		"unique (tenant_id, workspace_id, environment_id, id)",
		"before update on asset_observations", "before delete on asset_observations",
		"before update on asset_type_details", "before delete on asset_type_details",
		"retired asset is terminal",
		"unsafe asset catalog rollback: catalog state remains",
	} {
		if !strings.Contains(up+"\n"+down, required) {
			t.Errorf("missing invariant %q", required)
		}
	}
}

func TestAssetCatalogCorrectiveOwnsExact36RoutineSignaturesAndRuntimeLock(t *testing.T) { assertCorrectiveExact36RoutineSignaturesAndRuntimeLock(t) }
func TestAssetCatalogCorrectiveRejectsNoncanonicalProfileManifestAndDefinitionV2Drift(t *testing.T) { assertCorrectiveProfileManifestAndDefinitionV2(t) }
func TestAssetCatalogCorrectiveRecomputesAuthorityDefinitionAndBindingDigestsInSQL(t *testing.T) { assertCorrectiveSQLDigestClosure(t) }
func TestAssetCatalogCorrectiveRejectsOpaqueReferenceAndTypedPairDrift(t *testing.T) { assertCorrectiveOpaqueReferenceAndTypedPair(t) }
func TestAssetCatalogCorrectiveFutureSourceInsertAndLiveStagesFailClosed(t *testing.T) { assertCorrectiveFutureSourceStages(t) }
func TestAssetCatalogCorrectiveDownUsesOneShotNowaitAndDropsEveryDependency(t *testing.T) { assertCorrectiveDownLockAndDependencyOrder(t) }
func TestAssetCatalogCorrectiveManualProfileLiteralAndSQLParity(t *testing.T) { assertCorrectiveManualProfileLiteralAndParity(t) }
func TestAssetCatalogCorrectiveEnforcesDatabaseRoleSeparation(t *testing.T) { assertCorrectiveDatabaseRoleSeparation(t) }

func readMigration(t *testing.T, name string) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate migration test")
	}
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(file), "..", "..", "..", "migrations", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}
~~~

Run the historical static gate with `go test ./internal/assetcatalog/postgres -run 'TestAssetCatalog(MigrationOwnsExactTablesAndGuardsData|Corrective)' -count=1`，then add and target exactly `TestAssetCatalogMigrationCorrectivePersistentContractMatrix` and `TestAssetCatalogFutureSourceHookPersistentContractMatrix` through the required PostgreSQL wrapper/DSNs.

Expected: the original eight static RED causes remain historical evidence；this reopen's RED is the independently reported absence of durable real-database cases，not a claim that `d557237` production SQL is known broken。Each new top-level matrix uses sequential isolated transactions/fixtures，exact SQLSTATE plus constraint names，rollback/cleanup assertions and no Skip；it recomputes every dependent digest so a stale outer digest cannot mask the intended guard。Before accepting test quality，temporarily and locally mutate one exact expected constraint or a controlled fixture/hook per contract family，prove the targeted new test fails for that mutation，restore the baseline completely，then record baseline PASS as `regression-coverage GREEN`。Never weaken an assertion or alter production SQL merely to manufacture RED；a real behavior failure reopens its owning Step 2–4 before further work。

- [x] **Step 2: Implement the transactional up migration with this exact schema**

Start with `BEGIN; SET LOCAL lock_timeout='5s';`，then acquire every prerequisite relation in one fully qualified statement：`LOCK TABLE public.tenants, public.workspaces, public.environments, public.integrations, public.services, public.service_bindings, public.audit_records, public.outbox_events IN ACCESS EXCLUSIVE MODE NOWAIT`。Any conflicting DDL/DML returns SQLSTATE `55P03` and aborts the whole migration transaction；the migrator retries from `BEGIN` and never waits while holding a partial prerequisite lock set. Only after that single statement succeeds may prerequisite checks or owned DDL run，and all locks remain held through `COMMIT`，so concurrent schema change、binding mutation and implicit referenced-table FK locks cannot interleave.

| Table | Required columns and exact purpose |
|---|---|
| `asset_sources` | 稳定 UUID 身份/Workspace Scope；`source_kind/provider_kind/name/status` 与 `published_revision/published_revision_digest`；正交 `gate_status/gate_reason_code/gate_revision/validated_run_id/validation_digest/validated_binding_digest`；当前 checkpoint (`checkpoint_ciphertext/checkpoint_key_id/checkpoint_sha256/checkpoint_version/checkpoint_revision`)；HA backpressure (`next_allowed_at/consecutive_failures`)；创建幂等/hash、version、exact `last_success_run_id/at` 与 `last_complete_snapshot_run_id/at`、timestamps |
| `asset_source_revisions` | 复合 Scope + stable source + monotonically increasing revision；`DRAFT/VALIDATING/VALIDATED/REJECTED/PUBLISHED/SUPERSEDED`；safe content-addressed canonical Profile manifest and Provider schema；`integration_id/sync_mode/authority_scope_digest/source_definition_digest`；opaque Credential/Trust/Network references；nullable-pair typed extension code/digest；固定 rate/backpressure/profile/schedule；完整 availability binding digest；validation run/digest；actor/reason/CAS/time；创建后 canonical content 不可变 |
| `asset_source_revision_authorities` | exact Source Revision + same-Scope Environment composite FKs；1–100 contiguous canonical ordinals；deferred ordered-set digest closure；immutable insert-only authority membership |
| `asset_source_runs` | source scope + exact source definition revision/canonical digest; `run_kind/status/stage_code/stage_changed_at/trigger_type`; immutable gate revision; idempotency/hash; cursor before/after SHA; page sequence/digest and final/complete-snapshot proof; lease owner/expiry, monotonically increasing `fence_epoch`, token hash and heartbeat sequence; pending `DELAY` transition with reason/`not_before`/attempt-bound intent digest; observed/created/changed/unchanged/conflict/missing/stale/restored/tombstoned/rejected counts; typed work result/digest/recorded time; validation proof; checkpoint-lineage-rollover proof; broker-owned opaque cleanup attempt ID/epoch plus cleanup status/digest; optional immutable terminal-failure override/digest; exact `terminal_command_sha256`; stable failure code/trace; start/heartbeat/complete |
| `asset_source_limit_buckets` | stable UUID + Tenant/Workspace；exact `SOURCE|WORKSPACE|PROVIDER` kind/key closed shape；SOURCE exact Source FK、WORKSPACE exact workspace key、PROVIDER exact provider token；finite monotonic `next_token_at`、nullable `last_receipt_id` 通过命名 `DEFERRABLE INITIALLY IMMEDIATE` same-Scope FK 指向 permit/receipt、CAS version/timestamps；无 active counter、Queue fence 或 Source backpressure |
| `asset_source_limit_permits` | append-only `ACQUIRE|RELEASE|DELAY|EXPIRE` ledger；ACQUIRE 的 `id=permit_id`，terminal row exact-FK 回同 permit tuple；exact Source/Run/Provider、三 bucket kind/key、request/command/receipt SHA、positive TTL、optional delay `not_before`；每 request 唯一且每 permit 最多一个 terminal receipt |
| `asset_observations` | full scope/source/run; provider/external/exact Source definition revision; server-owned Catalog acceptance `observed_at`; page/checkpoint/fence coordinates; profile-locked freshness order, Provider version/fact/fingerprint digest and previous Observation/chain; schema version; nullable tombstone document + SHA; bounded field-provenance bytea + SHA; explicit tombstone flag/reason code; created time |
| `assets` | full scope/source; provider/external/kind/display; governance fields; lifecycle/mapping; exact last Observation/chain/time/Source definition revision; create idempotency/hash; version/timestamps |
| `asset_type_details` | full scope/asset plus redundant exact source/provider/external/revision/time identity; append-only revision/schema; exact source Observation; bytea details + SHA; actor/time |
| `asset_conflicts` | scope/existing asset/nullable candidate asset/nullable candidate service/source/observation; type/field; existing/candidate value SHA only; status/resolution/reason/actor/time; resolution idempotency/hash; version/timestamps |
| `asset_relationships` | workspace plus exact Source definition revision and last Run/page receipt；持久 `accepted_checkpoint_version/run_fence_epoch`；source/target environments/assets/external IDs；type/path/confidence and independent freshness/provider-version/relation-fact proof；provenance source；explicit cross-environment policy ref；status；idempotency/hash/version/timestamps |
| `service_asset_bindings` | full scope/service/asset; role/mapping/provenance/status; idempotency/hash/version/timestamps |

Exact state vocabularies:

~~~text
source_kind: MANUAL CSV_IMPORT CONTROL_PLANE_API EXTERNAL_CMDB VSPHERE
             PROXMOX OPENSTACK CLOUD_PROVIDER KUBERNETES_OPERATOR AWX_INVENTORY
sync_mode: MANUAL ON_DEMAND SCHEDULED
source status: ACTIVE PAUSED DEGRADED DISABLED
source gate: UNAVAILABLE VALIDATING AVAILABLE DEGRADED SUSPENDED
source revision: DRAFT VALIDATING VALIDATED REJECTED PUBLISHED SUPERSEDED
run kind: VALIDATION DISCOVERY CSV_IMPORT API_INGESTION MANUAL_MUTATION
run status: QUEUED DELAYED RUNNING FINALIZING SUCCEEDED PARTIAL FAILED CANCELLED
run stage: WAITING DELAYED VALIDATING READING NORMALIZING APPLYING CLEANING_UP COMPLETED
trigger_type: HUMAN API SCHEDULED
credential cleanup: NOT_OPENED PENDING REVOKED NO_CREDENTIAL UNCERTAIN
work result: DATA_PROJECTION VALIDATION_PROOF FAILURE_INTENT
terminal failure override: CLEANUP_UNCERTAIN
delay reason: PROVIDER_RETRY_AFTER TRANSPORT_BACKOFF
pending transition: DELAY
asset lifecycle: DISCOVERED ACTIVE STALE QUARANTINED RETIRED
mapping: EXACT AMBIGUOUS UNRESOLVED
criticality: LOW MEDIUM HIGH CRITICAL
data classification: PUBLIC INTERNAL CONFIDENTIAL RESTRICTED
conflict status: OPEN RESOLVED REJECTED
resolution: CONFIRM_EXACT REJECT_CANDIDATE KEEP_UNRESOLVED QUARANTINE_ASSET
relationship: RUNS_ON CONTAINS DEPENDS_ON MONITORED_BY LOGS_TO TRACES_TO
              DELIVERED_BY MANAGED_BY PRIMARY_RUNTIME_FOR
relationship status: ACTIVE INACTIVE
binding role: PRIMARY_RUNTIME DEPENDENCY OBSERVABILITY_SOURCE DELIVERY_TARGET MANAGED_TARGET
binding status: ACTIVE INACTIVE
provenance: MANUAL DISCOVERED MERGE_DECISION
freshness: CATALOG_SEQUENCE OBJECT_SEQUENCE OBJECT_TIME_SEQUENCE CHECKPOINT_SEQUENCE
~~~

> **Future-only boundary:** `QUALIFICATION`、`QUALIFICATION_PROOF`、qualification evidence `TWO_WORKER_HA|PROVIDER_CANARY`、safe evidence/HA digest columns 和 gate-evidence pointer 都不属于上述当前 `000015` exact vocabulary；它们是后继 Pack 06 Task 19A2a 的 future schema/domain C0 extension。本文件后续 Task 1/Task 2 中保留的任何 qualification Run/work-result、GateEvidence/HA 字段与 qualification/evidence-specific gate arithmetic 也都只是 Task 19A2a/19A2b/19A2c 的 future cross-reference，不是已勾选 Task 1、当前 `000015` 或当前 Go types 的实现要求；现有 validation 与 checkpoint-lineage-rollover gate arithmetic 继续属于当前 Task 1 合同。Task 19A2b 才实现 persistence/runtime rechecks，Task 19A2c 才装配唯一 lane/verifier registry/sink/signer。本次合同纠偏不把它们描述为当前已实现，也不重开或勾改上述 Task 1 checkbox，合并前数据库/运行能力继续关闭。

The Phase 1 Relationship check constraint is named `asset_relationships_type_check` and contains exactly the nine values above. A later owned migration may expand it only together with the shared Go `RelationshipType` enum/tests and a down guard；Phase 1 adapters cannot submit future values early.

Use composite foreign keys for every parent. `service_asset_bindings` must additionally use `(service_id,environment_id) -> service_bindings(service_id,environment_id)` and Repository validation to prove the Service is bound to the selected Environment; separate Service/Environment Workspace FKs do not replace this eligibility edge. M1F mutation first locks Conflict and Assets in the established order, then in the same `SERIALIZABLE READ WRITE` transaction invokes the sole exact `public.asset_catalog_lock_exact_service_binding(uuid,uuid,uuid,uuid) RETURNS boolean` entry point。It is strict、non-overloaded、`LANGUAGE plpgsql VOLATILE PARALLEL UNSAFE SECURITY DEFINER`、owned by `aiops_schema_owner` with `search_path=pg_catalog, public, pg_temp`，locks exact Service `FOR KEY SHARE` then exact legacy binding `FOR SHARE` and requires `mapping_status='EXACT'`。PUBLIC has no EXECUTE；only runtime does。Runtime/workload keeps SELECT but has no direct parent UPDATE/grant option and direct row lock returns `42501`。`asset_observations.source_revision`、provenance `source_revision` and `assets.last_source_revision` always mean the immutable Source **definition** revision (`asset_source_revisions.revision`); `asset_source_runs` therefore has no second `definition_revision` alias. Provider-specific object versions are hashed into the closed freshness proof and never reuse this integer. `assets.last_source_revision` references the exact Source Revision, and its current Observation FK includes Environment, Source, Provider, Source Revision and Observation chain so a projection cannot bind cross-Environment or drifted facts. Observation replay identity is exactly `(tenant_id,workspace_id,source_id,run_id,provider_kind,external_id)`: this admits at most one item per Run across all pages while allowing the same asset to append a new Observation in every later Run under the same published Source definition revision. Every Adapter must reject/coalesce duplicate object keys before page commit; a changed duplicate in the same Run is `SOURCE_RUN_OBJECT_DUPLICATE`, not a second Observation.

Freshness is a separate persisted contract. Registry locks one `FreshnessKind` per Provider profile/revision. `CATALOG_SEQUENCE` is server-only for governed `MANUAL_MUTATION`; `OBJECT_SEQUENCE` uses a positive Provider integer; `OBJECT_TIME_SEQUENCE` uses finite UTC microsecond Provider time plus a positive integer tie-break; `CHECKPOINT_SEQUENCE` must equal the accepted next source checkpoint version. Each Observation stores the order, lowercase SHA-256 of any opaque Provider version, a domain-separated `provider_fact_sha256`, `previous_observation_id/previous_chain_sha256`, a unique `observation_chain_sha256`, accepted checkpoint version, run fence epoch and run page sequence. Insert admission requires the exact live lease/fence、published Source definition/gate/checkpoint and next Run page/checkpoint coordinates；a `DEFERRABLE INITIALLY DEFERRED` closure additionally requires the same transaction to advance Run/Source to those coordinates and append exact `ASSET_SOURCE_RUN/PAGE_APPLIED` receipt `request_id="source-page:<run_uuid>:<page_sequence>"`、`payload_hash=page_digest`. The page transaction first reads its fixed server `transaction_timestamp()`；Go uses that value to construct canonical provenance and Observation chain bytes，then PostgreSQL requires `observed_at` and provenance acceptance time to equal the same transaction timestamp. Production INSERT SQL must not construct JSON/canonical bytes or depend on the unknowable next-statement `statement_timestamp()`. Repository locks and CASes the exact prior Asset `last_observation_id/chain`; the repeatable provider fact digest is never the sole ABA guard.

All Catalog fact hashes use one byte-exact `FramedTupleV1`: concatenate fields in the listed order; encode `NULL` as one byte `0x00`, and a present field as `0x01 || uint32-big-endian byte_length || raw_bytes`. Empty and `NULL` are distinct. UUID/token/enum/schema values are canonical UTF-8; integers are minimal base-10 ASCII without sign or leading zero (`0` is the sole zero encoding); booleans are `0` or `1`; times are finite UTC microsecond text `YYYY-MM-DDTHH:MM:SS.ffffffZ`; every named SHA-256 field is the decoded 32 raw bytes, never its 64-byte hex text. RFC 8785 canonical document/provenance bytes must have unique JSON keys. `field_provenance_sha256 = SHA256(canonical_persisted_provenance_bytes)` and therefore binds the injected Catalog time. Separately, sort Provider provenance skeleton entries by `field_code` and compute `provider_provenance_sha256 = SHA256(FramedTupleV1("asset-provider-provenance.v1",entry_count,repeated field_code,provider_path_code,ownership,confidence))`; this semantic digest excludes server-injected Source ID/provider/revision/observed time and is carried only inside `provider_fact_sha256`. Fingerprint values are normalized only in Adapter memory, then each value becomes `SHA256(FramedTupleV1("asset-fingerprint-value.v1",fingerprint_code,canonical_value))`; sort by `fingerprint_code` and compute `fingerprint_sha256 = SHA256(FramedTupleV1("asset-fingerprints.v1",entry_count,repeated fingerprint_code,fingerprint_value_sha256))`. The empty fingerprint set is the digest of that domain plus count `0`; raw fingerprint values are never persisted or returned.

`provider_fact_sha256` is the persisted asset semantic fact digest, exactly `SHA256(FramedTupleV1("asset-provider-fact.v1",tenant_id,workspace_id,source_id,provider_kind,source_revision,canonical_revision_digest,source_definition_digest,environment_id,external_id,kind-or-NULL,display_name-or-NULL,schema_version,tombstone,tombstone_reason-or-NULL,document_sha256-or-NULL,fingerprint_sha256,provider_provenance_sha256))`. A non-tombstone has canonical non-empty Kind/DisplayName；a tombstone encodes both as `NULL` and requires the empty fingerprint digest. It deliberately excludes freshness/order/version proof, Observation/Run identity, fence, checkpoint coordinate, full persisted provenance and Catalog acceptance time, so unchanged Provider content remains comparable across Runs while every asset projection/conflict input remains bound. `observation_chain_sha256` is exactly `SHA256(FramedTupleV1("asset-observation-chain.v1",tenant_id,workspace_id,environment_id,source_id,run_id,observation_id,provider_kind,external_id,source_revision,canonical_revision_digest,observed_at,freshness_kind,freshness_order_time-or-NULL,freshness_order_sequence,provider_version_sha256,accepted_checkpoint_version,run_fence_epoch,run_page_sequence,provider_fact_sha256,field_provenance_sha256,previous_observation_id-or-NULL,previous_chain_sha256-or-NULL))`. The two previous fields are either both `NULL` or both present.

Relations are independent top-level facts rather than fields nested in an asset Observation. For each relation, `relation_fact_sha256 = SHA256(FramedTupleV1("asset-relation-fact.v1",tenant_id,workspace_id,source_id,source_revision,canonical_revision_digest,source_environment_id,target_environment_id,from_external_id,to_external_id,relationship_type,provider_path_code,confidence))`；its replay/freshness tuple is `(freshness order,provider_version_sha256,relation_fact_sha256)`. A page sorts relations by `(source_environment_id,target_environment_id,from_external_id,to_external_id,relationship_type,provider_path_code)` and computes `relation_page_sha256 = SHA256(FramedTupleV1("asset-relation-page.v1",relation_count,repeated source_environment_id,target_environment_id,from_external_id,to_external_id,relationship_type,provider_path_code,freshness_kind,freshness_order_time-or-NULL,freshness_order_sequence,provider_version_sha256,relation_fact_sha256))`. The empty page is the digest of that domain plus count `0`；consecutive empty pages therefore intentionally have the same content digest and are distinguished by monotonic relation-page sequence plus the exact unique receipt request ID, never by adding a nonce or page sequence to the digest. This permits Providers to emit bounded asset pages first and relation-only pages later without duplicating an asset Observation while still binding exact freshness/replay coordinates. The mutable Relationship projection stores `accepted_checkpoint_version`、`run_fence_epoch` and its last exact Run/page/freshness/fact coordinates；insert/update admission revalidates the live exact lease/fence、published Source definition/gate/checkpoint and next relation-page coordinates. A distinct immutable `ASSET_SOURCE_RUN/RELATION_PAGE_COMMITTED` receipt preserves every accepted relation page with `request_id="source-relation-page:<run_uuid>:<page_sequence>"`、`payload_hash=relation_page_sha256`；a `DEFERRABLE INITIALLY DEFERRED` closure requires Relationship、Run relation-page summary、Source checkpoint 和该 receipt 在同一事务原子一致，不能用资产页 `PAGE_APPLIED` receipt 代替。任何声明 `complete_snapshot=true`（以及由它推导的 `effective_complete_snapshot=true`）的 final asset page，必须在同一事务把 relation-page sequence 精确推进一次、封存该页 canonical relation-page digest，并写入上述 exact receipt；即使关系集合为空，也必须封存 canonical empty relation page，不能以“没有关系”为由省略闭合证明。Go is the sole constructor of canonical document/provenance/fingerprint/provider-fact/relation-fact/chain bytes；PostgreSQL recomputes SHA-256 for stored canonical document/provenance bytes, validates all digest shapes and exact coordinates, and admission compares the supplied domain digests—it must not implement a second JSON canonicalizer or a different tuple encoder.

`asset_type_details` uses redundant source/provider/external/revision/time columns and two exact composite FKs so the referenced Asset identity and Observation fact must be the same; same-Environment cross-source or cross-external detail attachment is rejected. `asset_conflicts.asset_id` and `candidate_asset_id` reference `(tenant_id,workspace_id,environment_id,id)`; `candidate_service_id` references `(tenant_id,workspace_id,id)`; conflict `(source_id,observation_id)` is one composite FK to the exact Observation source, not two independent parents. A shape check requires at least one candidate target or a field-level conflict hash, and an open-partial unique index prevents duplicate `(source_id,observation_id,conflict_type,field_name,candidate_asset_id,candidate_service_id)` queue items. `DISCOVERED` Relationship/Binding requires non-null `provenance_source_id` equal to its Asset source (both endpoints for a Relationship); `MANUAL|MERGE_DECISION` requires it null.

Source success pointers are exact pairs, not free timestamps. `last_success_run_id/last_success_at` are both NULL or use one composite FK to the same Source's terminal `SUCCEEDED` non-VALIDATION Run and equal its `completed_at`; `PARTIAL` never advances this pointer. `last_complete_snapshot_run_id/last_complete_snapshot_at` are both NULL or reference a terminal `SUCCEEDED` Run whose persisted effective `complete_snapshot=true` and equal that `completed_at`. `MANUAL_MUTATION` 永远不是 authoritative complete snapshot：其 `complete_snapshot/effective_complete_snapshot` 必须均为 `false`，成功只推进 `last_success_run_id/at`，绝不推进 `last_complete_snapshot_run_id/at`。A trigger rejects caller-selected timestamps, cross-Source Runs, `PARTIAL` targets and regression to an older completion.

Use exact uniqueness:

~~~sql
UNIQUE (tenant_id, workspace_id, source_id, provider_kind, external_id);
UNIQUE (tenant_id, workspace_id, environment_id, id);
UNIQUE (tenant_id, workspace_id, source_id, run_id, provider_kind, external_id);
CREATE UNIQUE INDEX asset_relationships_active_edge_uk
ON asset_relationships (
  tenant_id, workspace_id, source_asset_id, target_asset_id, relationship_type
) WHERE status = 'ACTIVE';
CREATE UNIQUE INDEX service_asset_bindings_active_uk
ON service_asset_bindings (
  tenant_id, workspace_id, environment_id, service_id, asset_id, binding_role
) WHERE status = 'ACTIVE';
CREATE UNIQUE INDEX asset_management_idempotency_audit_uk
ON audit_records (workspace_id, request_id)
WHERE resource_type IN (
  'ASSET', 'ASSET_SOURCE', 'ASSET_SOURCE_RUN',
  'ASSET_CONFLICT', 'SERVICE_ASSET_BINDING'
);
~~~

For asset-management audit rows only, `audit_records.request_id` is the validated Idempotency-Key and `payload_hash` is the canonical request SHA-256. The Repository takes `pg_advisory_xact_lock` on a stable Workspace+key digest, checks this partial-unique ledger before mutation, returns the scoped resource on matching replay, and rejects a reused key/hash or operation. This preserves every historical write key without a ninth table and remains safe across replicas. Transport request ID remains in structured logs; Trace ID remains in `trace_id`.

All idempotency uniqueness is `(workspace_id,idempotency_key)`; Idempotency-Key uses `^[a-z0-9][a-z0-9._:/-]{0,127}$`; request hashes are exactly 64 lowercase hex. JSON labels must be an object ≤16 KiB and ≤64 pairs (application validation enforces pair count); normalized/details bytea are RFC 8785 canonical JSON bytes 2–64 KiB with database-enforced UTF-8 object shape and unique keys:

~~~sql
CHECK (
  (NOT tombstone
   AND normalized_document IS NOT NULL
   AND octet_length(document_sha256) = 64
   AND document_sha256 COLLATE "C" !~ '[^a-f0-9]'
   AND encode(sha256(normalized_document), 'hex') = document_sha256
   AND tombstone_reason IS NULL)
  OR
  (tombstone
   AND normalized_document IS NULL
   AND document_sha256 IS NULL
   AND tombstone_reason IS NOT NULL)
);
~~~

`field_provenance` is canonical JSON ≤32 KiB with unique keys and contains only allow-listed persisted field codes (including `data_classification`, never the obsolete alias `classification`). Every entry has exactly server-injected `source_id`、`provider_kind`、Source definition `source_revision`、Catalog acceptance `observed_at` formatted `YYYY-MM-DDTHH:MM:SS.ffffffZ`, required closed `provider_path_code`, JSON integer `confidence` 0–100 and ownership (`SOURCE|GOVERNANCE|MERGE_DECISION`); raw provider paths or values are forbidden. Non-tombstone Observation requires document+hash and null reason; tombstone requires document+hash both NULL, a stable reason, provenance and the full freshness/chain proof.

For non-MANUAL Sources, `checkpoint_ciphertext` is the versioned AES-256-GCM envelope `0x01 || 12-byte non-zero nonce || ciphertext || 16-byte tag`. The only AAD constructor accepts a typed `CheckpointAAD{TenantID,WorkspaceID,SourceID,ProviderKind,CheckpointRevision,CanonicalRevisionDigest,SourceDefinitionDigest,CheckpointKeyID,CheckpointVersion}` and encodes exactly `FramedTupleV1("asset-source-checkpoint.v1",the nine fields in that order)`; `checkpoint_key_id` is an opaque key reference. Golden-byte/hash tests and one-field-at-a-time tamper tests cover all nine fields, empty/NULL rejection and key rotation. Fence/gate/Run fields are deliberately absent so ciphertext survives reclaim and later Runs without false version advances. A stale Worker may already hold a key or plaintext under the global keyring design; it must zero it and cannot pass open/use/Provider-call/heartbeat/reconcile/checkpoint/complete admission or commit under an old fence. Publication of every new canonical Source revision always clears ciphertext/key/hash, sets `checkpoint_version=0` and sets `checkpoint_revision` to the newly published revision because the AAD domain changed; before the first publication both numeric fields are zero. No Control Plane re-encryption fallback exists. The database validates envelope shape/hash while the Repository performs authenticated encryption/decryption and exact AAD verification.

A Provider token/resource-version/collector expiry never authorizes an arbitrary same-revision checkpoint clear or rewind. A Profile may instead register closed rollover reasons and call fenced `BeginCheckpointLineageRollover` after its real Adapter verifies expiry. `MANUAL/MANUAL_V1` has no Provider cursor or Adapter and is categorically ineligible for this rollover path. The Run's originally admitted `gate_revision` is immutable. In one serializable transaction this method binds a safe Adapter evidence digest to the exact Run、published revision、old checkpoint hash/version and fence, marks only that Run as `CHECKPOINT_LINEAGE_ROLLOVER`, and changes the Source to `DEGRADED` at exactly `source.gate_revision=run.gate_revision+1`；it does not change checkpoint bytes/hash/version. The same exact Run is the sole gate exception and must perform a new authoritative full snapshot. Its first accepted page CASes from the still-current old hash to the new Provider lineage and every page keeps checkpoint version strictly increasing. Recoverable Provider/transport failures clean the attempt and `DELAY` this same nonterminal Run；they never terminalize it merely to create a side Run. A terminal `SUCCEEDED` effective complete snapshot seals an immutable rollover receipt and restores `AVAILABLE` at exactly `run.gate_revision+2`；any terminal failure or uncertainty sets `SUSPENDED` at exactly `run.gate_revision+2` and requires a newly validated/published canonical revision before work can resume. `SUSPENDED` 不能通过 `UNAVAILABLE→AVAILABLE` 两跳复用旧 `validated_*` 证明；只有发布新的 canonical revision（或将 Source 置为非 ACTIVE并保持关闭）可离开该 gate，且没有受控事实变化时不得单独推进 `gate_revision`。Therefore a crash before the first new page retains the old checkpoint, a crash after a committed page resumes the new lineage, and only publication of a new canonical revision resets version to zero.

`MANUAL` is the sole checkpoint exception: the Source row itself requires `provider_kind=MANUAL_V1`，its only installed Revision profile is `MANUAL_V1`，and every such Revision requires `credential_reference_id/trust_reference_id/network_policy_reference_id` all `NULL`; non-MANUAL Sources and Revisions cannot claim `MANUAL_V1`. It has no Provider cursor and keeps `checkpoint_ciphertext/checkpoint_key_id/checkpoint_sha256` NULL forever. Its positive `checkpoint_version` is only the server-owned monotonic Catalog sequence, CASed by the synchronous `MANUAL_MUTATION`, and `checkpoint_revision` is the exact published Source definition revision. Before first publication both numeric fields are zero；every publication sets `checkpoint_version=0, checkpoint_revision=<new published revision>`，and each mutation increments only the version. Thus Pack 02 has no forward dependency on the Pack 09 checkpoint codec. `ProviderVersionSHA256` for sequence `n` is exactly `SHA256(FramedTupleV1("manual-catalog-version.v1",tenant_id,workspace_id,source_id,checkpoint_revision,n))`. Its cleanup is exact `NO_CREDENTIAL` with `cleanup_attempt_id=NULL`、`cleanup_attempt_epoch=0` and deterministic `cleanup_digest=SHA256(FramedTupleV1("asset-run-no-credential.v1",run_id,source_revision,source_revision_digest,fence_epoch))`；the same transaction must append `ASSET_SOURCE_RUN/ATTEMPT_CLEANED` receipt `request_id="source-attempt:<run_uuid>:0"`、`payload_hash=cleanup_digest`. MANUAL Run 不得进入 `PENDING|REVOKED|UNCERTAIN` cleanup、pending `DELAY` 或 `DELAYED` 状态，也不得把 `NO_CREDENTIAL` 重置为 `NOT_OPENED`；deferred closure 在提交点拒绝任何仍为 `QUEUED|RUNNING|FINALIZING` 的 MANUAL Run，因此 Validation/MANUAL_MUTATION 必须在创建它的同一 serializable API transaction 内完成 claim、work、exact cleanup receipt、terminal receipt 与 Revision/Source closure，失败则整笔回滚且不留下共享队列条目。A `MANUAL_MUTATION` may close its final page but must persist `complete_snapshot=false/effective_complete_snapshot=false` because manual input cannot prove authoritative membership absence；on success it advances only `last_success_run_id/at`. The database never stores a plaintext provider cursor, raw lease token, credential material, endpoint, CA PEM or source error body.

`asset_source_revisions` 的 canonical content 在创建后不可修改。Authority child rows must number 1..N in canonical-text `C` order and the parent digest is exactly `SHA256(FramedTupleV1("asset-source-authority-scope.v1",N,repeated ordered Environment IDs))`；the deferred parent/child closure rejects missing、extra、cross-Scope or reordered facts。`typed_extension_code/prepared_extension_digest` are both NULL or both present and are immutable。状态只能 `DRAFT|REJECTED→VALIDATING→VALIDATED|REJECTED`、`VALIDATED→PUBLISHED`、`PUBLISHED→SUPERSEDED`。进入 `VALIDATING` 必须将 `validation_run_id` 替换为新的 exact append-only `QUEUED` Validation Run 并清空 digest；返回 `VALIDATED|REJECTED` 只能消费该同一 Run 的 terminal proof，不得依赖时间比较或复用旧成功 Run。Validation `SUCCEEDED` 原子写 `VALIDATED` 与 exact proof；Validation `FAILED|CANCELLED`（包括漂移、reaper、cleanup uncertainty）必须在终态事务中把仍绑定该 `validation_run_id` 的 `VALIDATING` revision 写为 `REJECTED`，保存稳定 failure code/proof digest，使其可重新进入 Validation，而不是遗留永久 `VALIDATING`。`REJECTED` 不能直接发布。Revision insert 必须在锁定 stable Source 后满足 `revision=max+1` 与 `expected_source_version=current source.version`，并原子推进 Source version。每个 source 最多一个 `PUBLISHED`，发布任何新 canonical 修订必须在同一事务更新 stable source pointer、supersede 旧修订、按前述 Profile 规则初始化新 revision checkpoint 并关闭 gate。

`asset_sources.gate_status='AVAILABLE'` is legal only when `status='ACTIVE'`, the exact published revision has traversed `QUEUED→RUNNING→FINALIZING→SUCCEEDED` (the synchronous MANUAL path may do all transitions in one transaction), `validation_digest` is lowercase SHA-256, and `validated_binding_digest = canonical_revision_digest = published_revision_digest`. The canonical digest covers the definition plus every immutable Integration/sync/Credential/Trust/Network/authority/rate/backpressure/profile/schedule binding and the typed-extension code/digest as two independent frames; `source_definition_digest` cannot satisfy this comparison. Every non-MANUAL publication ends at `PUBLISHED + UNAVAILABLE`；only `MANUAL_V1` may open in the publication transaction. A separately claimed `QUALIFICATION` Run may consume current `PUBLISHED + UNAVAILABLE` solely through the fixed workload-only qualification lane, must finish with zero Catalog projection/checkpoint/success-pointer change, and seals an unexpired signed `QUALIFICATION_PROOF` bound to exact Scope/Source/Revision/binding/runtime/lab-binding facts. Ordinary non-Validation claim and `RequestSync` continue to require `AVAILABLE`；profiles requiring qualification additionally recheck the current unexpired evidence tuple at every ordinary admission/data-write boundary. Gate epoch arithmetic is closed and exact. With starting epoch `G`, the first-publication path keeps the Source `UNAVAILABLE/G` while its exact Validation Run carries `gate_revision=G`, publication closes to `UNAVAILABLE/G+1`, qualification keeps that epoch, and the sole serializable `AdmitGate` reaches `AVAILABLE/G+2`. If the product exposes validation progress, only `UNAVAILABLE/G→VALIDATING/G+1` may bind that exact newly queued Run；the binding is immutable, publication closes to `UNAVAILABLE/G+2`, qualification keeps that epoch, and `AdmitGate` reaches `AVAILABLE/G+3`. An already `AVAILABLE` Source may retain the gate only when status, reason, epoch and all validation/evidence bindings are unchanged. Checkpoint-lineage rollover is the sole runtime exception：the admitted data Run keeps epoch `G`, begin-rollover closes to `DEGRADED/G+1`, and the same Run's serializable terminal closure reaches exactly `AVAILABLE/G+2` for an effective complete success or `SUSPENDED/G+2` for failure/uncertainty. Any publication/reference/evidence drift atomically sets the gate back to `UNAVAILABLE`; ordinary discovery success、final matrix、direct SQL 或测试 fake cannot open it, an unexplained epoch-only increment is rejected, and no path may compress or skip these epochs. `MANUAL` is served by the governed Asset API；`KUBERNETES_OPERATOR` remains `UNAVAILABLE` until Phase 3 publishes its provider contract，`AWX_INVENTORY` remains `UNAVAILABLE` until Phase 5 publishes its fixed AWX contract.

Every textual identity has non-empty, trimmed canonical-character and octet-length constraints: ProviderKind matches `^[A-Z][A-Z0-9_]{0,63}$`, external ID ≤512, display/name ≤256, owner/actor/reason/revision/schema/idempotency/trace within their domain maxima. Reject NUL/CR/LF. `assets_kind_check` is a named closed constraint containing exactly the 17 Phase 1 Kind values. Count checks are non-negative. Run shape is exact:

- `QUEUED/WAITING` has no start/heartbeat/lease/progress/work result/completion and cleanup `NOT_OPENED`；`DELAYED/DELAYED` may preserve committed page/checkpoint/count progress and the latest released-attempt cleanup proof, but has bounded `not_before`、no active lease and no final work result/completion.
- `RUNNING` has start/heartbeat/current owner+token-hash+epoch+expiry and stage `VALIDATING|READING|NORMALIZING|APPLYING|CLEANING_UP`. Before credential use it is `NOT_OPENED`；after `ReserveCleanupAttempt` it stores a broker-owned opaque UUID plus the originating fence epoch and becomes `PENDING`. Before entering `CLEANING_UP`, a nonterminal retry must persist the closed next intent `DELAY` plus exact delay reason/bounded `not_before`；`CLEANING_UP` is cleanup-only and cannot open Provider runtime/checkpoint or apply a page.
- `FINALIZING/CLEANING_UP` has a live/expired cleanup-only lease and exactly one immutable persisted work result：a data `DATA_PROJECTION` proposed `SUCCEEDED|PARTIAL`, a `VALIDATION_PROOF` proposed `SUCCEEDED|FAILED`, a zero-projection signed `QUALIFICATION_PROOF` proposed `SUCCEEDED|FAILED`, or a no-projection `FAILURE_INTENT` proposed `FAILED`. It has `work_result_digest/work_result_recorded_at` but no completion. Validation and qualification proofs bind exact Source revision、canonical/binding digests、closed outcome/code and proof digest；qualification additionally binds evidence kind、runtime/lab-binding/prior receipts/signature/expiry and requires every projection/count/checkpoint/success-pointer field to remain zero/unchanged. Cleanup cannot replace this result.
- `CANCELLED/COMPLETED` has no active/open credential and no **final** work result. A Run cancelled directly from `QUEUED` or from a pre-claim zero-progress `DELAYED` state has zero progress plus `NOT_OPENED`；one cancelled from `DELAYED` after a released attempt may retain only its previously committed intermediate page/checkpoint/count progress and `REVOKED|NO_CREDENTIAL` attempt receipt. Neither form performs membership closure or advances a success pointer. `DATA_PROJECTION` may close as `SUCCEEDED|PARTIAL/COMPLETED`；successful `VALIDATION_PROOF` or `QUALIFICATION_PROOF` may close only as `SUCCEEDED/COMPLETED`，all with `REVOKED|NO_CREDENTIAL` and no failure override. Ordinary `FAILED/COMPLETED` requires a rejected Validation/qualification proof or failure intent plus terminal cleanup. If cleanup becomes `UNCERTAIN` after any work result was already persisted, `Fail` preserves that result and atomically adds the sole override `CLEANUP_UNCERTAIN` with `terminal_failure_override_digest = SHA256(FramedTupleV1("asset-run-terminal-failure-override.v1",run_id,work_result_kind-or-NULL,work_result_digest-or-NULL,cleanup_status,cleanup_digest,failure_code))`；this is the only legal result/status override, forces `FAILED + SUSPENDED`, rejects a bound Validation revision or qualification evidence and advances no success pointer. Validation/qualification never becomes `PARTIAL`. Every non-cancelled terminal row persists exact `terminal_command_sha256` and has exact `completed_at`；the terminal Run mutation、exact `TERMINAL_COMMITTED` receipt and every required Source/Revision/evidence closure must be one serializable transaction，cleanup `UNCERTAIN` additionally requires Source `SUSPENDED` in that transaction.

`stage_code/stage_changed_at` is server-owned. Allowed transitions are `WAITING→VALIDATING|READING`, `WAITING→DELAYED`, `DELAYED→VALIDATING|READING`, data-page cycles `READING→NORMALIZING→APPLYING→READING`, any active stage to `CLEANING_UP`, retry cleanup `CLEANING_UP→DELAYED`, and terminal `CLEANING_UP→COMPLETED`；only `CancelIneligible` may additionally perform no-lease `WAITING|DELAYED→COMPLETED`. Only fenced Queue/Worker methods may advance every other transition. Terminal owner/token-hash/epoch/heartbeat evidence remains immutable after capacity/raw-token release. Conflict shape requires OPEN=no decision and closed=complete decision.

- [x] **Step 3: Add immutable and lifecycle database guards**

~~~sql
CREATE OR REPLACE FUNCTION reject_asset_catalog_immutable() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION USING ERRCODE='55000',
    MESSAGE=TG_TABLE_NAME || ' rows are immutable';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER asset_observations_immutable
BEFORE UPDATE OR DELETE ON asset_observations
FOR EACH ROW EXECUTE FUNCTION reject_asset_catalog_immutable();
CREATE TRIGGER asset_type_details_immutable
BEFORE UPDATE OR DELETE ON asset_type_details
FOR EACH ROW EXECUTE FUNCTION reject_asset_catalog_immutable();
~~~

`assets_transition_guard` must reject physical DELETE, make tenant/workspace/environment/source/provider/external/kind immutable, require `NEW.version=OLD.version+1`, set `updated_at=statement_timestamp()`, reject leaving RETIRED with message `retired asset is terminal`, and allow only:

~~~text
DISCOVERED -> ACTIVE | QUARANTINED | RETIRED
ACTIVE -> STALE | QUARANTINED | RETIRED
STALE -> ACTIVE | QUARANTINED | RETIRED
QUARANTINED -> ACTIVE | RETIRED
~~~

Create indexes for default catalog `(tenant,workspace,environment,lower(display_name),id) WHERE lifecycle<>'RETIRED'`, filters `(kind,lifecycle,mapping_status,id)`, open conflicts `(created_at,id)`, and source runs `(source_id,created_at DESC,id DESC)`. End with `COMMIT`.

Create the claim index `(not_before,created_at,id) WHERE status IN ('QUEUED','DELAYED')`, the expired execution reclaim index `(lease_expires_at,id) WHERE status='RUNNING'`, the cleanup-only reclaim index `(lease_expires_at,id) WHERE status='FINALIZING'`, and a partial unique index allowing at most one nonterminal Run per Source. A Validation Run is bound to its draft/validating revision but carries checkpoint version/hash zero and never compares、opens or advances the current published Source checkpoint. A qualification Run uses a distinct claim predicate requiring current published-but-closed binding and the fixed production qualification admission；it cannot satisfy or reuse the ordinary data predicate and its private cursor/evidence cannot become Source checkpoint or Catalog projection. A Discovery/Import/Ingestion Run starts from the Source's exact current checkpoint version/hash and still requires `AVAILABLE`；a synchronous `MANUAL_MUTATION` is privately fenced and completed inside the governed Asset API transaction and never enters the Discovery Worker. Claim/normal reclaim requires exact current Source/gate/revision/checkpoint/backpressure eligibility, except for the explicitly bound Validation、qualification and checkpoint-lineage-rollover cases above, changes owner/token, advances `fence_epoch` exactly once and establishes a new heartbeat. Every heartbeat repeats the same run-kind-specific check.

`DELAYED` is the only nonterminal no-lease recovery state：it preserves prior page/checkpoint/count progress and the immutable cleanup receipt for the released attempt, requires bounded `not_before`, has no owner/expiry/raw-token access, and may return to `RUNNING` only through a fresh eligible claim/fence. A successful final data page changes `RUNNING→FINALIZING` atomically, persists `DATA_PROJECTION` with proposed `SUCCEEDED|PARTIAL`, final/effective-complete-snapshot flags, digest and `work_result_recorded_at`. A fenced `Queue.ProposeValidationResult` performs the corresponding transition for a Validation Run and persists exact `VALIDATION_PROOF` with proposed `SUCCEEDED|FAILED`. Every other fatal execution path must call fenced `Queue.PrepareFailureIntent` before cleanup；it persists one stable `FAILURE_INTENT` and changes `RUNNING→FINALIZING`, while a drift reaper uses that same internal transition. It cannot replace an existing data/validation result. Every form is cleanup-only and cannot call Provider, decrypt checkpoint or apply another page. `Queue.Complete` consumes an exact cleanup proof (`REVOKED|NO_CREDENTIAL`) and matching successful work-result digest；`Fail` consumes a rejected Validation proof or failure intent, or applies the sole `CLEANUP_UNCERTAIN` override without replacing an existing result. For Validation，terminal Run and exact bound Revision `VALIDATED|REJECTED` close in one serializable transaction；for a data Run，terminal Run and exact Source success/complete pointer、rollover gate or `SUSPENDED` gate close in one serializable transaction. An expired `FINALIZING` Run can only be reclaimed as cleanup-only work；cleanup uncertainty reaches stable `FAILED + SUSPENDED`, never a second work result. `MANUAL` Validation and `MANUAL_MUTATION` supply the deterministic `NO_CREDENTIAL` proof and perform their receipt/work-result/finalization/terminal/Source-or-Revision closure in one serializable API transaction.

Before any credential/session can open, the Worker calls fenced `ReserveCleanupAttempt`, which persists a random broker-owned opaque `cleanup_attempt_id` and its originating fence epoch. Reserve is exact-idempotent for `(run_id,fence_epoch)`：response-loss retry returns the same UUID and can never allocate/overwrite a second attempt. The external Cleanup Broker owns every revoke/session handle；`OpenAttempt(attempt_id)` is idempotent and may create at most one logical session for that ID，while `RevokeAttempt(attempt_id)` is idempotent and returns the same signed safe proof. The database never stores the handle or any credential. If an Open response is lost/ambiguous, the Worker must not retry Provider work or reserve another attempt；it immediately persists `TRANSPORT_BACKOFF`, calls `RevokeAttempt` for the known ID, records cleanup and delays. Before retry cleanup, Queue persists `pending_transition='DELAY'` plus reason/`not_before` and exact `pending_transition_digest = SHA256(FramedTupleV1("asset-run-delay-intent.v1",run_id,cleanup_attempt_id-or-NULL,cleanup_attempt_epoch,delay_reason,not_before))`. `RecordCleanup` verifies the proof and appends immutable `ASSET_SOURCE_RUN/ATTEMPT_CLEANED` audit receipt `request_id="source-attempt:<run_uuid>:<attempt_epoch>"` with `payload_hash` equal to the signed proof digest before updating the current summary. The `NO_CREDENTIAL` specialization is accepted only for exact `MANUAL/MANUAL_V1` Revision with all three external references `NULL`，uses attempt epoch `0` and the deterministic digest defined above, and must have that same exact receipt；an arbitrary caller SHA is never cleanup proof. If an expired `RUNNING` attempt had `PENDING` cleanup, reclaim moves its stage to cleanup-only `CLEANING_UP`, persists/uses a bounded `TRANSPORT_BACKOFF` delay intent, revokes that attempt and may only execute that `Delay` for a fresh claim or fail；it cannot continue Provider work under a replacement fence. If cleanup is already `REVOKED|NO_CREDENTIAL`, reclaim must verify the exact attempt receipt and the intent digest bound to that attempt epoch, then execute it；missing/mismatched intent is corruption and suspends the gate. `ReclaimFinalizing` likewise uses only the opaque attempt ID and Broker proof—never Provider runtime or checkpoint；when cleanup already has a valid receipt, it consumes the persisted work result/failure intent through `Complete|Fail`. A fresh claim atomically clears the consumed pending intent and may reset the current cleanup summary to `NOT_OPENED` only after verifying the prior append-only receipt, so history is never overwritten. A missing/invalid/uncertain Broker proof deterministically fails the Run and suspends the Source gate.

`CancelIneligible` locks the Source and atomically transitions its `QUEUED|DELAYED` Runs to `CANCELLED` when disable/publication/gate/revision/checkpoint drift makes them unclaimable; because those states have no open credential, no cleanup is skipped and the unique nonterminal slot is released. If the Run is the exact Validation bound by a `VALIDATING` Revision, that same transaction writes the Revision `REJECTED` with stable cancellation proof/code. If an expired `RUNNING` Run drifted, a bounded reaper takes the next fence without Provider/checkpoint access: it may fail directly only when cleanup is `NOT_OPENED|NO_CREDENTIAL`; otherwise it enters cleanup-only work and must revoke/close before `Fail` (or persist `UNCERTAIN` and suspend the gate). Before expiry, the current fence may perform cleanup/fail but cannot extend after drift. Terminal rows preserve owner/token-hash/epoch/heartbeat evidence while raw token is destroyed and capacity released. `last_success_at` equals `completed_at` only for the latest terminal `SUCCEEDED` non-VALIDATION data Run, including final delta/API/MANUAL runs；`PARTIAL` does not advance it. `last_complete_snapshot_at` equals `completed_at` only when that `SUCCEEDED` Run persisted effective `complete_snapshot=true`，and `MANUAL_MUTATION` is categorically ineligible. Neither accepts caller time. No terminal Run may commit alone：its `TERMINAL_COMMITTED` receipt and required Source/Revision updates are deferred-validated as one serializable closure；cleanup `UNCERTAIN` without exact Source `SUSPENDED` rolls back the whole transaction. QUEUED rows cannot receive counts/proof/pages, DELAYED rows preserve only committed progress, FINALIZING rows accept only cleanup/terminal facts, terminal rows are immutable, and every successful page/checkpoint advance increases both Run page/checkpoint and Source checkpoint version exactly once. Add row-level `BEFORE DELETE` and statement-level `BEFORE TRUNCATE` rejection to all twelve tables; lifecycle/status transitions are the only removal path. `asset_source_revision_authorities` and `asset_source_limit_permits` additionally reject every `UPDATE` because ordered authority membership and permit/receipt history are immutable content.

- [x] **Step 4: Implement guarded down and online-compatibility checks**

Down begins one transaction and takes **one** fully qualified non-waiting lock statement over every prerequisite/FK target、the four predecessor relations whose ACL `000015` extends、both Audit/Outbox shared surfaces and all owned relations：`LOCK TABLE public.tenants, public.workspaces, public.environments, public.integrations, public.services, public.service_bindings, public.audit_records, public.outbox_events, public.asset_sources, public.asset_source_revisions, public.asset_source_revision_authorities, public.asset_source_runs, public.asset_source_limit_buckets, public.asset_source_limit_permits, public.asset_observations, public.assets, public.asset_type_details, public.asset_conflicts, public.asset_relationships, public.service_asset_bindings IN ACCESS EXCLUSIVE MODE NOWAIT`。The six prerequisite targets are mandatory because PostgreSQL 18 FK removal otherwise acquires their `AccessExclusiveLock` after child locks；`workspaces/environments/services/service_bindings` and Audit/Outbox are mandatory because Down restores the exact predecessor ACL of those four relations plus the reviewed Audit/Outbox indexes/triggers/ACL/comment surface。Any member conflict returns `55P03` and rolls back before guard；there is no later implicit relation lock that may wait while a partial set is held。After the full set is held，Down raises `55000` with exact message `unsafe asset catalog rollback: catalog state remains` if any owned row exists。Only empty locked state may restore the four predecessor ACLs and Audit/Outbox shared surfaces、drop dependent triggers/functions/FKs and then twelve tables child-first；this manifest order is not a production row-lock order。

Add production `schema_admission.go` and `database_role_admission.go` probes consumed later by Control Plane assembly. Their constructors require the explicit trusted schema name (`public` in production); they never use `current_schema`, `search_path` object resolution or a caller-selected schema. Task 1 owns four exact base roles；all four are `NOSUPERUSER/NOCREATEDB/NOCREATEROLE/NOREPLICATION/NOBYPASSRLS`：`aiops_migrator` is `LOGIN/NOINHERIT`，`aiops_schema_owner` and `aiops_control_plane_runtime` are `NOLOGIN/NOINHERIT`，and `aiops_control_plane_workload` is `LOGIN/INHERIT`。The only base membership edges are migrator→schema owner with `inherit=false,set=true,admin=false` and workload→runtime with `inherit=true,set=false,admin=false`；neither runtime identity has any edge to migrator/schema owner。Source Gate A2a separately consumes two preprovisioned capability LOGIN identities—`aiops_source_gate_sealer` and `aiops_source_gate_admitter`—both `NOINHERIT` with all five dangerous flags disabled、no membership and mutually distinct credentials/DSNs；they are neither base ACL carriers nor extension owners。Environment IaC/bootstrap precreates the two roles and credentials before A2a，but exact-36 application database/schema ACL explicitly excludes both capability identities。Only after owned exact-38 plus global exact-110 postflight may the helper grant their direct `CONNECT|USAGE` as owner and require full admission；exact-36/down/unknown/partial revokes and proves absence。Migration、application、seal and admit DSNs remain distinct。Migration admission requires exact migrator identity and the SET-only schema-owner edge；ordinary application and both post-A2a capability probes require their exact session identities and reject role switching。Runtime keeps the reviewed parent and twelve-Asset relation/column ACL；after A2a Sources/Runs use the exact protected column grants and direct forbidden writes remain `42501`。After A2a all global 110 routines have no PUBLIC EXECUTE；A2a explicitly adds the fixed runtime→predecessor exact72 owner-grantor/non-grantable direct manifest，so runtime direct/effective function count is predecessor72 + existing Asset18 = exact90，workload direct0/effective90 only through INHERIT。Sealer only seal、admitter only admit，both have predecessor edge0 and no relation/sequence privileges。The initially empty extension-owner ABI remains unchanged。
The exact-36 direct schema ACL is `OWNER=CREATE+USAGE` and `RUNTIME=USAGE`；only owned exact-38/global exact-110 postflight adds `SEALER=USAGE` and `ADMITTER=USAGE`。Likewise direct database ACL adds sealer/admitter `CONNECT` only in that hardened state；all semantic grantors are OWNER and no LOGIN receives `CREATE|TEMP`。Admission accepts only predecessor72+owned36 normalized ACL or global110+owned38 hardened ACL；default PUBLIC `USAGE`、wrong-version capability ACL、unknown/extra routine or grantee、wrong grantor/grantability、duplicate/overload all close admission。`DatabaseRoleAdmission.Check` remains the exact workload application probe；migration and capability probes are separate fixed paths。
Every owned runtime function fixes explicit `search_path=pg_catalog, public, pg_temp` in `proconfig`；putting `pg_temp` last prevents PostgreSQL's implicit temporary-schema precedence。Every trusted relation/type is nevertheless `public.`-qualified and security-relevant builtin/operator is `pg_catalog`-qualified；no function inherits the session path or resolves a caller schema，so hostile temporary/public names cannot change admission。The schema code contains one reviewed hard-coded PostgreSQL-18.4 manifest SHA-256 generated from the migration at build/review time, never derived from the live database or migration file at runtime. The structured manifest covers all twelve relations, including authority child、Limiter bucket/permit ledger, every column/constraint/index/trigger and every owned function's exact signature/body/language/volatility/strict/security/search path, plus the affected Audit/Outbox surface。Relation/function owner and semantic ACL normalization remain role-name/OID-portable，reject unknown/duplicate/extra/grantable/wrong-grantor rows，and include the runtime-only SECURITY DEFINER definition/ACL plus bucket column-only UPDATE。Catalog rows are length-prefixed and `C`-sorted before SHA-256；schema and role admission require exact equality.

Real negative tests create a hostile ordinary schema first in `search_path` and，in an isolated non-admission fixture，a dedicated hostile test LOGIN with TEMP plus only the minimum test-call privileges to create same-named temporary relations/types/functions/operators；the production workload itself remains unable to create TEMP。They also replace one guard function with a no-op, weaken one CHECK/FK, alter an index/trigger/column/default/comment；each returns stable `asset_catalog_unavailable` or is rejected before DDL，and neither hostile schema can change a deferred digest/gate result。Test that a binary aware only of 000014 continues health/session reads while 000015 exists, while the new production probe remains closed until the full exact manifest is present; Pack 03 maps that sentinel to HTTP 503. The up migration must not rewrite existing large tables or add a defaulted column to them.

- [x] **Step 5: Add real PostgreSQL scope, immutability, concurrency, and recovery tests**

The integration harness connects through a separately named safe test control database, asserts PostgreSQL 18.4, creates a randomized physical database named `aiops_assets_test_<hex>` (never merely a schema), reconnects and applies 000001–000015 to `public`, then force-drops that database in cleanup. It rejects non-test control database names and missing CREATE DATABASE authority rather than mutating the supplied database. The two persistent corrective matrix tests additionally cover both K8S/AWX kinds and assert exact failure identities：future false/NULL initial/live `23514/asset_sources_future_phase_gate_guard`，read-committed initial `55000/asset_sources_initial_revision_closure_guard`；authority absent/unsorted `23514/asset_source_revision_authorities_order_guard`，duplicate `23505/asset_source_revision_authorities_pkey`，digest mismatch `23514/asset_source_revisions_digest_closure_guard`，late append `55000/asset_source_revision_authorities_parent_guard`；Profile whitespace/key-order `23514/asset_source_revisions_canonical_content_guard`，duplicate key `23514/asset_source_revisions_schema_ck`，unknown key `23514/asset_source_revisions_profile_manifest_guard`，oversize `23514/asset_source_revisions_schema_ck`；typed one-sided `23514/asset_source_revisions_typed_extension_ck` and semantic mismatch `23514/asset_source_revisions_typed_extension_guard`；URL/DSN/Vault/PEM/Header opaque values `23514/asset_source_revisions_reference_ck`。The row-level unique-key JSON/schema check intentionally rejects a duplicate before the deferred closed-key guard，while an otherwise valid unknown-key document reaches the latter；tests must not weaken or reorder either fail-closed layer merely to share an error identity。Positive successor-hook stages and K8S/AWX typed-pair candidates must commit only at their exact legal boundary；SUSPENDED/UNAVAILABLE cleanup must bypass a bomb hook，and every rejected transaction must leave no row or hook drift。The harness then seeds two tenants/workspaces/environments and proves:

- cross-scope FK insert returns `23503`;
- unknown Asset Kind, non-canonical Idempotency-Key, untrimmed identity and duplicate-key JSON return `23514`;
- Observation/Asset Provider, Source Revision and Environment drift plus an unbound Service/Environment return `23503`;
- Observation/Type Detail update/delete returns `55000`;
- physical DELETE of every remaining catalog table and TRUNCATE of every catalog table return `55000`;
- DISCOVERED→STALE returns `23514`; valid transitions increment exactly once;
- retired recovery and identity reparenting return `55000`;
- duplicate dedupe/idempotency/active edge/binding are rejected;
- bad hash/oversized JSON/bad terminal shapes are rejected;
- plaintext checkpoint, raw fence token, invalid/duplicate-key provenance, stale owner/fence and checkpoint regression are rejected;
- tombstone document/hash XOR, finite canonical Catalog/provenance time, required path code, integer confidence, semantic fact/Observation-chain coordinates and same-Run exact unique identity are enforced;
- two consecutive discovery runs advance the same Source checkpoint without resetting the second Run to zero;
- same-page replay returns its immutable receipt; a same-Run cross-page object duplicate, freshness regression/collision and changed replay all roll back; a later-Run unchanged fact appends one Observation/chain without Type Detail change;
- non-monotonic Source Revision, stale Source CAS, direct terminal Run insert and revision/history DELETE are rejected;
- exact `QUEUED/DELAYED/RUNNING/FINALIZING/terminal` shapes, exact cleanup/terminal receipts, final-page transition, ineligible cancellation, drift cleanup reaper, heartbeat/reclaim source revalidation, rollover `run/+1/+2` gate arithmetic and atomic Source/Revision terminal closure are enforced;
- Observation `PAGE_APPLIED` and Relationship `RELATION_PAGE_COMMITTED` receipts cannot be forged, swapped or committed apart from their exact live fence/checkpoint/page coordinates;
- synchronous MANUAL validation/mutation uses reference-free deterministic `NO_CREDENTIAL` plus logical Catalog sequence, never stores checkpoint ciphertext/key/hash, and a mutation advances last-success but never complete-snapshot state;
- a source gate cannot become `AVAILABLE` without a matching successful validation run and becomes `UNAVAILABLE` on any Credential/Trust/Network/authority/rate/backpressure/profile/schedule drift；Limiter concurrent Acquire/response-loss/changed replay/one-terminal/expiry cases preserve exact three-bucket capacity，and M1F proves SECURITY DEFINER lock blocking plus direct runtime parent-lock `42501`;
- two concurrent lifecycle writes cannot both commit.
- both up and down locking use one schema-qualified `ACCESS EXCLUSIVE ... NOWAIT` statement；down fixtures independently hold each of six prerequisites、Audit、Outbox and twelve owned relations and require `55P03` with zero schema/data change before guard，then prove full retry after release succeeds。A transaction started after successful locking cannot cross preflight/emptiness guard，and catalog observation proves no relation lock is first acquired later by FK/trigger/shared-surface cleanup.

TRUNCATE negative assertions check SQLSTATE `55000` **and** the exact target table guard constraint/trigger name, so `CASCADE` cannot accidentally pass because a child table blocked first. The full migration runner applies 000015 up before including 000015 down in reverse-order tests; it never excludes this migration merely to make legacy integration green.

Core assertion:

~~~go
expectSQLState(t, database, "55000",
	`UPDATE asset_observations SET source_revision=source_revision+1`)
expectSQLState(t, database, "23514", `
	UPDATE assets SET lifecycle='STALE', version=version+1
	WHERE id=$1 AND lifecycle='DISCOVERED'`, assetID)
~~~

Recovery test uses `recovery_container_test.go` to start two distinct digest-pinned PostgreSQL 18.4 instances with different `system_identifier` values、checksums and role OIDs。Both begin at predecessor72+owned36 with capability ACL absent；migration through `000015` must prove owned38/global110 before capability grant and dump。`pg_dump --format=custom --role=aiops_schema_owner` and non-superuser `pg_restore --single-transaction --role=aiops_schema_owner` preserve owner/ACL records；the clean target starts at the predecessor state and after restore must pass global110/owned38 postflight plus full admission。Down on either instance must restore exact predecessor72 catalog/ACL；partial/unknown revokes capability ACL and closes。`--no-owner`、`--no-acl`、`--disable-triggers`、`--use-set-session-authorization`、superuser restore and ownership rewriting are forbidden。Representative data and all schema/role/ACL/digest assertions must pass with no Skip。This dual-instance recovery is required A2a G2 because the ACL/archive contract changed。

Run:

~~~bash
AIOPS_LOCAL_POSTGRES_ROOT=/path/to/workstation/postgresql \
  scripts/with-local-postgres.sh go test -race ./internal/assetcatalog/postgres \
  -run '^(TestAssetCatalogMigrationCorrectivePersistentContractMatrix|TestAssetCatalogFutureSourceHookPersistentContractMatrix|TestAssetCatalog(Migration|Recovery).*)$' \
  -count=1
~~~

Expected: the exact two persistent matrices plus all migration/recovery assertions PASS under PostgreSQL 18.4 TLS with zero required-test skips。Historical exact-36 evidence is not Source Gate successor evidence。A2a G2 requires all five DSNs：the predecessor72/owned36 state rejects both capability connections；global110/owned38 passes both full capability probes；down restores predecessor72 exactly；unexpected111、wrong predecessor ACL、partial/unknown and dump/restore fail closed or pass only at their exact expected boundary。Missing root/DSN、unreachable identity、unexecuted dual-instance recovery or Skip is not completion evidence。

- [x] **Step 6: Wire and verify the integration target**

Append `./internal/assetcatalog/postgres` to `make test-integration`. Legacy package fixtures must stop at their explicit owned migration cutoff；the full migration runner and Asset Catalog harness execute `000015` only inside a 128-bit randomized physical database created from the project-specific `aiops_test` control-database naming family, and may destructively clean up only a database whose creation they confirmed. Package serialization、`IF NOT EXISTS` and a shared destructive `public` schema are not substitutes for isolation.

Run:

~~~bash
gofmt -w $(rg --files internal/assetcatalog/postgres -g '*.go')
go test ./internal/assetcatalog/postgres -count=1
test -n "$AIOPS_TEST_POSTGRES_DSN"
make test-integration
~~~

Expected: PASS with zero required-test skips；the integration target keeps cross-package parallelism so schema/physical-database isolation remains exercised.

- [x] **Step 7: Commit**

~~~bash
git add internal/assetcatalog/postgres/migration_integration_test.go \
  internal/assetcatalog/postgres/migration_closure_adversarial_integration_test.go
git commit -m "test(assetcatalog): persist corrective PostgreSQL regression matrix"
~~~

- [x] **Step 8: Independently review and accept the corrective Asset Catalog contract**

Task 2 preflight found that the original `enforce_asset_sources_mutation` body permanently hard-coded `KUBERNETES_OPERATOR/AWX_INVENTORY` as unavailable. The contract below is the corrective acceptance specification。Step 8 owns no implementation/Red cycle，but every finding reopens its owning earlier checkbox and the reject/reopen state must be committed as a dedicated documentation checkpoint before implementation resumes。The first 2026-07-15 review returned `REJECT/P1` and reopened only Steps 1/5/6/7 for the missing persistent PostgreSQL 18.4 matrix；Steps 2–4 remained accepted because the new matrix exposed no production defect。Regression commit `ba99233` and the required Green evidence closed all reopened steps；the follow-up independent review returned `APPROVE` with no P0–P3 and no step to reopen。Task 2 has now started in `BUILDING_CLOSED`; the new environment-mapping enum parity finding reopens only its owning Task 1 slice.

Independently inspect the implementation and Green static/PostgreSQL evidence proving:

- `000015` defines exactly `public.asset_catalog_future_source_gate_admitted(candidate public.asset_sources) RETURNS boolean` as `LANGUAGE plpgsql STABLE SECURITY INVOKER`, defaults to `false` and fixes `search_path=pg_catalog, public, pg_temp`。`enforce_asset_sources_mutation` first applies every generic auto-fail-close normalization to the final `NEW` row，then delegates only future-source `VALIDATING|AVAILABLE|DEGRADED` admission with `asset_catalog_future_source_gate_admitted(NEW) IS NOT TRUE` instead of `NOT fn()`；an old live state must never make the hook reject an update whose normalized final destination is `UNAVAILABLE|SUSPENDED`。The existing deferred Source constraint trigger handles `TG_OP='INSERT'` separately：it reloads the exact current Source after revision/authority/typed facts exist, but before calling the hook requires that final row still be the exact initial `UNAVAILABLE` shape（version 2 after revision-1 CAS、one `DRAFT` revision 1、gate/checkpoint revision and version zero、all published/validated/run/checkpoint pointers and checkpoint material NULL）。It invokes the hook with that current composite，never the stale INSERT-time value。Thus Source+revision creation may commit by itself under an owned successor, but Source creation plus `VALIDATING`、publication or live admission in the same transaction always rolls back；a later new serializable transaction owns each next stage。A false/NULL result fails closed；initial future creation and all live/validation paths require `transaction_isolation='serializable'`。Updates that drive an existing Source to `UNAVAILABLE|SUSPENDED` remain legal fail-close destinations and never require a positive hook or serializable precondition;
- the default implementation rejects initial creation as well as every attempt to validate or open either future Source, including profile substitution, revision/digest drift and direct SQL；therefore a pre-successor K8S/AWX draft cannot become undeletable legacy state。After an owned successor has admitted creation, an ineligible/live future Source can still always be driven to `SUSPENDED`/`UNAVAILABLE` without the hook blocking cleanup;
- `000017` and `000019` may only `CREATE OR REPLACE` that exact signature, never copy or take ownership of the base Source/deferred trigger。Each successor adds an exact initial `UNAVAILABLE` creation branch for only its owned SourceKind, requiring same-transaction revision/authority and provider facts without pretending validation already succeeded；the Phase 1 INSERT closure—not a hook branch alone—enforces that the transaction ends at this creation boundary。Any later `AVAILABLE|DEGRADED` branch must additionally consume Task 19A2b's current unexpired gate-evidence pointer/digest（shape 由 Task 19A2a 冻结）and the Provider-owned qualification/HA/canary closure；validation/cleanup alone is insufficient。Their down migrations refuse while any owned Provider Source exists and then restore the predecessor body;
- the schema-admission manifest and dump/restore proof include all twelve relations and every function definition digest plus role-name/OID-portable owner/ACL semantics；all owned relations/functions resolve to `aiops_schema_owner`，unknown/duplicate/extra/grantable/wrong-grantor ACL、body/owner/overload/search-path drift close startup admission;
- `asset_source_revision_authorities` is the immutable child truth for 1–100 Environment IDs，with composite Revision and Environment FKs、canonical ordinal and unique Environment/ordinal keys。A deferred closure trigger requires contiguous ordinals in canonical-text `C` order and an authority digest of exactly `N+2` frames：domain `asset-source-authority-scope.v1`、minimal-decimal `N`、then one present frame per lowercase canonical Environment UUID UTF-8 in `environment_id::text COLLATE "C"` order；`MANUAL/MANUAL_V1` requires exactly one row。Parent/child insert in one transaction succeeds；absent/cross-Scope/unsorted/duplicate/mismatched direct SQL fails at commit，and update/delete/truncate always fails。The exact four new trigger instances reuse existing callers and add no 36th routine：`asset_source_revision_authorities_immutable BEFORE UPDATE ROW→public.reject_asset_catalog_immutable()`、`asset_source_revision_authorities_delete_guard BEFORE DELETE ROW→public.reject_asset_catalog_delete()`、`asset_source_revision_authorities_truncate_guard BEFORE TRUNCATE STATEMENT→public.reject_asset_catalog_truncate()`、`asset_source_revision_authorities_deferred_state_guard CONSTRAINT AFTER INSERT ROW DEFERRABLE INITIALLY DEFERRED→public.validate_asset_source_revision_deferred_state()`；the last caller branches on `TG_TABLE_NAME` and reloads the parent Revision so a later transaction cannot append membership;
- base `asset_source_revisions` adds nullable-pair `typed_extension_code/prepared_extension_digest` with exact code/SHA checks；the pair is immutable canonical content and BindingDigest frames 19/20 reload directly from it。Under the locked SourceKind set, `KUBERNETES_OPERATOR` requires both non-NULL and `typed_extension_code=profile_code`；every other kind, including all Phase 1 profiles、`MANUAL` and `AWX_INVENTORY`, requires both NULL。A later `000017` typed extension row must bind that exact non-NULL pair and cannot invent a second digest owner；changing this matrix requires an owned migration plus digest/admission updates;
- `asset_catalog_framed_value_v1(candidate bytea) RETURNS bytea` remains the only SQL frame encoder：`NULL → 0x00`，present → `0x01 || int4send(octet_length(candidate)) || candidate`；it is `LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE SECURITY INVOKER` with fixed `search_path=pg_catalog, public, pg_temp`。The pure `asset_catalog_source_revision_binding_digest(candidate public.asset_source_revisions) RETURNS text` remains the exact 20-frame BindingDigest helper and 35th historical function；the non-overloaded parent lock remains the 36th，and A2a may add only the exact 37th receipt-seal and 38th gate-admit primitives—not another predicate/hash/trigger helper;
- `asset_source_limit_buckets` and `asset_source_limit_permits` are the sole Limiter truths。Bucket INSERT starts version 1；only `next_token_at/last_receipt_id/version/updated_at` may change，version advances exactly once。Named `asset_source_limit_buckets_last_receipt_fk` is a `DEFERRABLE INITIALLY IMMEDIATE` same-Scope FK that preserves receipt existence across restore，while the bucket mutation trigger independently requires that receipt to reference the exact bucket and be inserted in the same transaction；neither layer substitutes for the other。Permit rows are UPDATE/DELETE/TRUNCATE-immutable；ACQUIRE self-identifies，terminal rows exact-FK to the acquire tuple，a partial unique index allows at most one terminal receipt，and request replay uniqueness plus command/receipt SHA supports response-loss recovery。Acquire/Release/Delay/Expiry lock buckets `SOURCE→WORKSPACE→PROVIDER` in one serializable read-write transaction；no advisory/Source/Queue state substitutes;
- `asset_source_revisions` persists 1–16,384 UTF-8 RFC 8785 bytes in `canonical_profile_manifest` plus its exact lowercase SHA in `profile_manifest_sha256` and the exact Provider-schema bytes/SHA。The deferred SQL closure parses the raw manifest as `json`（not duplicate-collapsing `jsonb`），requires exactly 26 rows/26 distinct closed keys and exact types，then inlines an explicit ASCII-key-order constructor using typed extraction、minimal-decimal integers、JSON-escaped token strings and C-sorted unique arrays；`convert_to(reconstructed,'UTF8')` must byte-equal the stored input。Thus whitespace、key-order、duplicate-key、NULL/type/unknown/oversize drift fails even when caller hashes are self-consistent。It recomputes both content hashes、authority digest、`source_definition_digest=SHA256(FramedTupleV1("asset-source-definition.v2",source_kind,provider_kind,profile_code,raw profile_manifest_sha256,raw provider_schema_sha256))` with six present frames/two decoded raw 32-byte hashes，and BindingDigest；SQL/Go/MANUAL/Victoria/AWX share that formula。Manifest/revision duplicate semantics must also match field-for-field：Source/Provider/Profile/sync、four rate/backpressure integers、typed-extension code and Integration/Credential/Trust/Network/schedule presence modes；mode `NONE` requires SQL NULL and required modes require a present valid reference/expression。For `MANUAL/MANUAL_V1` SQL additionally compares the exact 794-byte literal/SHA and all corresponding Revision fields，not code alone。Go performs the same strict decode/re-encode/parity and deep-clones both byte slices。Validation/publication、Source gate and every successor hook require installed Profile bytes/hash plus duplicate-field parity；late children or any byte/semantic/digest drift rolls back;
- Credential/Trust/Network/Cross-Environment Policy references use exact `public.asset_catalog_opaque_reference_valid(candidate text) RETURNS boolean` rather than the general code grammar。It is `LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE SECURITY INVOKER` with fixed `search_path=pg_catalog, public, pg_temp` and accepts only `^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`；this enforces a bounded single-line no-scheme/no-path lookup token and rejects URL、DSN、Vault path、PEM/Header syntax, but does not claim to recognize every secret-looking alphanumeric value。Authorization requires exact scoped registry resolution and purpose matching；raw Secret prevention remains an independent API/log/payload/scan invariant.

After A2a the corrected migration will own the previous unordered35 routine identities plus exact non-overloaded parent-lock、receipt-seal与gate-admit signatures；the `000015` owned manifest is exact38 with no overload or39th routine。Separately，application-schema global exact110=fixed predecessor72+Asset38。Static authority has78 definitions、6 replacements、72 final identities（68 trigger+4 helper）；pre-up has no predecessor direct grant and normalized ACL is owner+PUBLIC on all72。唯一完整identity list与production digest由 [Pack06 canonical predecessor exact72 runtime EXECUTE manifest](./06-source-external-cmdb.md#canonical-predecessor-exact72-runtime-execute-manifest) 固定；Task1不复制列表。Migration的显式PUBLIC revoke、runtime grant、down revoke/restore、schema/application admission与test必须逐项等于该列表并使用该production常量，不得运行时生成后接受。Missing、unknown73rd、overload或owner/grantor/grantability/ACL drift在DDL前整笔回滚；禁止`ON ALL FUNCTIONS IN SCHEMA`与schema-wide grant/revoke。After up owner exact110、runtime direct/effective90（72+Asset18）、workload direct0/effective90、sealer/admitter各1，migrator0 without SET ROLE；capability edges仍仅seal/admit。Down先显式revoke新增runtime72 edges，再移除owned38并恢复PUBLIC72，最终catalog/owner/ACL等于pre-up。三条typed entry point与trigger exact46、20-relation NOWAIT down order均不变。

The merged pre-A2a global routine helper remains an unmodified safety truth。Fresh A2a creates only `internal/assetcatalog/postgres/migration_qualification_contract_integration_test.go` within its exact-12 ownership and proves pre-up72、runtime-edge exact72 count/digest、up110 direct/effective/PUBLIC/owner/grantor/grantability、unexpected111、wrong predecessor ACL、down72 restored、up/down/up、five identities and dump/restore RED→GREEN。The application identity must exercise predecessor key DML across the action-queue、credential-revocation and investigation/runtime/evidence surfaces after up、down and re-up，thereby firing the predecessor trigger graph and all four helper paths；after up and re-up it also exercises Asset/Audit/Outbox ordinary behavior。Permission success alone cannot replace behavior assertions。Because this changes archive ACL and restoration semantics，dual-instance recovery is required A2a G2，not deferred。Recovery/admission freeze the global110↔predecessor72 relationship and A2a-added runtime exact72 edge revoke/restore relation；every future `000016..000022` public routine addition/replacement must update the content-addressed global manifest、explicit PUBLIC revoke and rollback contract，otherwise admission fails closed。Across `000015/000017/000019`, “function definition digest” has one byte contract：`SHA256(pg_catalog.convert_to(pg_catalog.pg_get_functiondef(oid),'UTF8'))` on PostgreSQL 18.4，with no normalization。Before every fingerprint/catalog-definition preflight or postflight、schema-admission、dump/restore or predecessor-restoration fingerprint query, the transaction executes `SET LOCAL quote_all_identifiers=off` and `SET LOCAL search_path=pg_catalog,pg_temp`；the read-only minimum-existence check may precede these GUCs。Inspected objects use explicit schema/OID；DDL uses explicit `public.` identities and `SET LOCAL search_path=pg_catalog,public,pg_temp`。Definition、owner、semantic ACL、overload count and `proconfig` are compared separately.

Review only the owned `000015` hook/stage boundary、Profile/schema content hashes、authority/definition/binding closure、typed pair、opaque validator、down cleanup and reviewed manifest；future migration bodies remain in their own packages。Verify the reopened Steps 1–7 recorded the expected Red causes and that all Task 1 unit、PostgreSQL 18.4 TLS/race、online compatibility、dual-instance recovery、schema admission、integration、`go test ./...`、vet、build、diff and secret gates are Green with no required Skip。Only then update `docs/status/current.md` to accepted and check Step 8；any finding reopens its owning earlier step.

~~~bash
git add docs/status/current.md docs/superpowers/plans/2026-07-13-governed-operations/01-assets/01-schema-domain.md
git commit -m "docs: accept corrected asset catalog contract"
~~~

### Task 2: Stable domain, validation, lifecycle, and downstream contracts

**Files:**
- Modify: **internal/authn/authenticator.go**
- Modify: **internal/authn/authenticator_test.go**
- Modify: **internal/authn/keycloak.go**
- Modify: **internal/authn/keycloak_test.go**
- Create: **internal/assetcatalog/types.go**
- Create: **internal/assetcatalog/validation.go**
- Create: **internal/assetcatalog/lifecycle.go**
- Create: **internal/assetcatalog/repository.go**
- Create: **internal/assetcatalog/lease_fence.go**
- Create: **internal/leasefence/fence.go**
- Create: **internal/leasefence/fence_test.go**
- Create: **internal/assetcatalog/types_test.go**
- Create: **internal/assetcatalog/mutation_context_architecture_test.go**
- Create: **internal/assetcatalog/lifecycle_test.go**
- Create: **internal/assetcatalog/lease_fence_test.go**
- Create: **internal/assetcatalog/lease_fence_architecture_test.go**
- Create: **internal/assetcatalog/postgres/binding_digest_parity_integration_test.go**

**Interfaces:**
- Produces the locked downstream contract:

~~~go
type Scope struct { TenantID, WorkspaceID, EnvironmentID string }
type SourceScope struct { TenantID, WorkspaceID string }
type AssetLocator struct { Scope Scope; AssetID string }
type ScopeResolver interface { ResolveScope(context.Context, string, string) (Scope, error) }
type SourceScopeResolver interface { ResolveSourceScope(context.Context, string) (SourceScope, error) }
type ConflictScopeResolver interface { ResolveConflictScope(context.Context, string, string) (Scope, error) }
type Reader interface { Get(context.Context, AssetLocator) (Asset, error) }
~~~

- `assets` keeps `UNIQUE (tenant_id,workspace_id,environment_id,id)` so 000016 may create a composite FK.
- Domain consumes existing `domain.MappingStatus`; it does not duplicate that enum.
- Domain consumes `authn.Principal.TenantID`; Task 2 therefore first adds the required fixed Keycloak claim `aiops_tenant_id` as one canonical lowercase UUID to `VerifiedClaims` and `Principal`. Missing/noncanonical Tenant is unauthenticated；Workspace/Environment claims cannot override it.

- [ ] **Step 1: Write failing lifecycle, validation, and operability tests**

Write executable table tests named `TestLifecycleAllowsOnlyReviewedTransitions`、`TestCatalogEligibilityIsOnlyTheLocalAssetProjection`、`TestSourceAvailabilityRequiresCurrentValidatedBinding` and `TestAuthenticatedPrincipalRequiresCanonicalTenantID`. They cover every lifecycle pair with no self-edge/terminal RETIRED；local eligibility only for `ACTIVE+EXACT`；one-field Source binding drift；and missing/uppercase/non-RFC4122 `aiops_tenant_id` rejection. Add exact Source-definition/authority/BindingDigest SQL-parity tests, `ManualProfileV1` immutable-clone/semantic tests, Source Revision authority-slice deep-clone tests, FieldOwnership unknown rejection, mutation-context zero/forgery/call-site、every cursor query-digest、read-constraint constructor/call-site、collection manual-admission、conflict-scope resolver shape and fence serialization/redaction/consume/race tables in the same Red commit.

Run: `go test ./internal/assetcatalog -count=1`

Expected: FAIL because domain types/functions do not exist.

- [ ] **Step 2: Define exact enum/value model**

`Kind` constants are exactly: SERVICE、LINUX_VM、WINDOWS_VM、BARE_METAL_HOST、KUBERNETES_CLUSTER、KUBERNETES_NAMESPACE、KUBERNETES_WORKLOAD、DATABASE_INSTANCE、DATABASE、METRICS_SOURCE、LOG_SOURCE、TRACE_SOURCE、AWX_INVENTORY、ARGO_APPLICATION、CI_PIPELINE、GIT_REPOSITORY、CLOUD_RESOURCE.

`SourceKind`、`SourceStatus`、`SourceGateStatus`、`SourceRevisionStatus`、`SyncMode`、`RunKind`、`RunStatus`、`RunStage`、`TriggerType`、`WorkResultKind`、`WorkResultStatus`、`ValidationOutcome`、`QualificationEvidenceKind`、`CredentialCleanupStatus`、`FreshnessKind`、`Lifecycle`、`Criticality`、`DataClassification`、`RelationshipType`、`RelationshipStatus`、`BindingRole`、`BindingStatus`、`Provenance`、`ConflictStatus` and `ConflictResolution` exactly match Task 1 vocabularies.

~~~go
type Asset struct {
	ID, SourceID, ProviderKind, ExternalID, DisplayName string
	Scope Scope
	Kind Kind
	Lifecycle Lifecycle
	MappingStatus domain.MappingStatus
	OwnerGroup *string
	Criticality Criticality
	DataClassification DataClassification
	Labels map[string]string
	LastObservationID, LastObservationChainSHA256 string
	LastObservedAt time.Time
	LastSourceRevision, Version int64
	CreatedAt, UpdatedAt time.Time
}

type Relationship struct {
	ID, SourceID, CanonicalRevisionDigest, LastRunID string
	SourceScope SourceScope
	SourceRevision, LastPageSequence, AcceptedCheckpointVersion, RunFenceEpoch int64
	RelationPageSHA256 string
	SourceEnvironmentID, TargetEnvironmentID string
	SourceAssetID, TargetAssetID, FromExternalID, ToExternalID string
	Type RelationshipType
	ProviderPathCode string
	Confidence int
	FreshnessKind FreshnessKind
	FreshnessOrderTime *time.Time
	FreshnessOrderSequence int64
	ProviderVersionSHA256, RelationFactSHA256 string
	Provenance Provenance
	ProvenanceSourceID string
	CrossEnvironmentPolicyReferenceID PolicyReferenceID
	Status RelationshipStatus
	Version int64
	CreatedAt, UpdatedAt time.Time
}

type Conflict struct {
	ID string
	Scope Scope
	AssetID, CandidateAssetID, CandidateServiceID string
	SourceID, ObservationID, Type, FieldName string
	ExistingValueSHA256, CandidateValueSHA256 string
	Status ConflictStatus
	Resolution ConflictResolution
	ResolutionReasonCode, ResolvedBy string
	ResolvedAt *time.Time
	Version int64
	CreatedAt, UpdatedAt time.Time
}

type ServiceAssetBinding struct {
	ID, ServiceID, AssetID string
	Scope Scope
	Role BindingRole
	MappingStatus domain.MappingStatus
	Provenance Provenance
	ProvenanceSourceID string
	Status BindingStatus
	Version int64
	CreatedAt, UpdatedAt time.Time
}

func (asset Asset) Clone() Asset {
	asset.Labels = maps.Clone(asset.Labels)
	if asset.OwnerGroup != nil { value := *asset.OwnerGroup; asset.OwnerGroup = &value }
	return asset
}

func (asset Asset) CatalogEligible() bool {
	return asset.Validate() == nil && asset.Lifecycle == LifecycleActive &&
		asset.MappingStatus == domain.MappingExact
}
~~~

Also define `SourceScope{TenantID,WorkspaceID}`、Source、the structurally safe SourceRun projection、Observation、the complete persisted Relationship above、Conflict、ServiceAssetBinding; page/cursor/filter types; and only the asset/mapping/binding commands owned by Tasks 2–5. Source mutation commands and `SourceRevisionRepository` are owned solely by Task 13；Task 2 must not create a reduced Source lifecycle or transaction callback.

Domain commands are internal service/repository values, never JSON DTOs. They embed an opaque `MutationContext` whose fields are unexported. Its checked constructor requires an authenticated `authn.Principal`、a database-resolved Scope and server request metadata, verifies Tenant/actor/auth time consistency and canonical request hash shape, and is restricted by an AST call-site test to Task 6 management plus `_test.go` fixtures；production handlers can pass only strict request DTOs to management. Tenant comes only from the verified Principal；Workspace/Environment/Service come from the complete trusted route plus composite database resolution；actor/subject/authentication time and Trace ID are server-injected；Idempotency-Key comes only from the validated header；request hash is server-computed over canonical typed input plus route Scope. Repository rejects a zero context, re-resolves Scope and rechecks current state before returning an idempotent replay, and CAS versions come from validated `If-Match`. Tests must reject a transport DTO that can set any of those trusted fields and must prove Repository replay cannot bypass the authorization/state check.

The source-facing model is exact and secret-free:

~~~go
type SourceGateStatus string

const (
	SourceGateUnavailable SourceGateStatus = "UNAVAILABLE"
	SourceGateValidating  SourceGateStatus = "VALIDATING"
	SourceGateAvailable   SourceGateStatus = "AVAILABLE"
	SourceGateDegraded    SourceGateStatus = "DEGRADED"
	SourceGateSuspended   SourceGateStatus = "SUSPENDED"
)

type Source struct {
	ID, TenantID, WorkspaceID, ProviderKind, Name string
	Kind SourceKind
	Status SourceStatus
	PublishedRevision int64
	PublishedRevisionDigest string
	GateStatus SourceGateStatus
	GateReasonCode, GateEvidenceRunID, GateEvidenceDigest string
	GateRevision int64; GateEvidenceExpiresAt *time.Time
	ValidatedRunID, ValidationDigest, ValidatedBindingDigest string
	CheckpointSHA256 string
	CheckpointVersion, CheckpointSourceRevision int64
	NextAllowedAt *time.Time
	ConsecutiveFailures int
	LastSuccessRunID string
	LastSuccessAt *time.Time
	LastCompleteSnapshotRunID string
	LastCompleteSnapshotAt *time.Time
	Version int64
	CreatedAt, UpdatedAt time.Time
}

type SourceRevision struct {
	ID, SourceID, TenantID, WorkspaceID string
	Revision int64
	Status SourceRevisionStatus
	CanonicalProfileManifest []byte
	CanonicalProviderSchema []byte
	ProfileManifestSHA256, CanonicalProviderSchemaSHA256 string
	SourceDefinitionDigest, CanonicalRevisionDigest, IntegrationID string
	SyncMode SyncMode
	CredentialReferenceID CredentialReferenceID
	TrustReferenceID TrustReferenceID
	NetworkPolicyReferenceID NetworkPolicyReferenceID
	AuthorityEnvironmentIDs []string
	AuthorityScopeDigest string
	RateLimitRequests, RateLimitWindowSeconds int64
	BackpressureBaseSeconds, BackpressureMaxSeconds int64
	ProfileCode ProfileCode
	ScheduleExpression string
	TypedExtensionCode ExtensionCode
	PreparedExtensionDigest, ValidationRunID, ValidationDigest string
	CreatedBy, ChangeReasonCode string
	ExpectedSourceVersion, Version int64
	CreatedAt, UpdatedAt time.Time
}

type EnvironmentMappingMode string
const (
	EnvironmentMappingSingle EnvironmentMappingMode = "SINGLE_ENVIRONMENT"
	EnvironmentMappingExplicitItem EnvironmentMappingMode = "EXPLICIT_ITEM_ENVIRONMENT"
)
type BuiltinSourceProfile struct {
	SourceKind SourceKind; ProviderKind string; ProfileCode ProfileCode
	SyncMode SyncMode; FreshnessKind FreshnessKind; EnvironmentMapping EnvironmentMappingMode
	IntegrationMode, CredentialPurpose, TrustMode, NetworkMode, ScheduleMode string
	ParserCode, CompatibilityClass, DLPPolicyCode string
	MaxPageItems, MaxPageRelations, MaxPageBytes, MaxDocumentBytes int64
	TrustedPathCodes []string; RelationshipTypes []RelationshipType
	CanonicalProfileManifest, CanonicalProviderSchema []byte
	ProfileManifestSHA256, CanonicalProviderSchemaSHA256 string
	IntegrationID string; CredentialReferenceID CredentialReferenceID; TrustReferenceID TrustReferenceID; NetworkPolicyReferenceID NetworkPolicyReferenceID
	RateLimitRequests, RateLimitWindowSeconds, BackpressureBaseSeconds, BackpressureMaxSeconds int64
	ScheduleExpression string; TypedExtensionCode ExtensionCode; PreparedExtensionDigest string
}
func ManualProfileV1() BuiltinSourceProfile
type SourceProfileAdmissionResolver interface { ResolveProfileAdmission(context.Context, ProfileCode) (BuiltinSourceProfile, error) }
func NewBuiltinSourceProfileAdmissionResolver() SourceProfileAdmissionResolver

type Observation struct {
	ID, SourceID, RunID, ProviderKind, ExternalID string
	Scope Scope
	SourceRevision int64
	CanonicalRevisionDigest, SourceDefinitionDigest string
	ObservedAt time.Time
	FreshnessKind FreshnessKind
	FreshnessOrderTime *time.Time
	FreshnessOrderSequence int64
	ProviderVersionSHA256, ProviderFactSHA256, FingerprintSHA256 string
	ProviderProvenanceSHA256 string
	PreviousObservationID, PreviousChainSHA256, ObservationChainSHA256 string
	AcceptedCheckpointVersion int64
	RunFenceEpoch, RunPageSequence int64
	SchemaVersion string
	NormalizedDocument, FieldProvenance []byte
	DocumentSHA256, FieldProvenanceSHA256 string
	Tombstone bool
	TombstoneReasonCode string
	CreatedAt time.Time
}

type SourceRun struct {
	ID, SourceID string
	Scope SourceScope
	SourceRevision int64
	SourceRevisionDigest string
	Kind RunKind
	Status RunStatus
	Stage RunStage
	StageChangedAt time.Time
	TriggerType TriggerType
	GateRevision, PageSequence int64
	PageDigest string
	RelationPageSequence int64
	RelationPageDigest, CursorBeforeSHA256, CursorAfterSHA256 string
	CheckpointVersion int64
	NotBefore time.Time
	LeaseExpiresAt *time.Time
	FenceEpoch, HeartbeatSequence int64
	FinalPage, CompleteSnapshot bool
	EffectiveCompleteSnapshot bool
	WorkResultKind WorkResultKind
	WorkResultStatus WorkResultStatus
	WorkResultDigest string
	WorkResultRecordedAt, QualificationReceiptExpiresAt *time.Time
	ValidationOutcome ValidationOutcome; QualificationEvidenceKind QualificationEvidenceKind
	ValidationProofDigest, QualificationScopeDigest, QualificationBindingDigest, QualificationDescriptorDigest, QualificationRuntimeManifestDigest, QualificationLabBindingDigest, QualificationPriorReceiptDigestsSHA256, QualificationResultDigest, QualificationReceiptDigest, QualificationSigningKeyID, QualificationSignature, HAOwnerWorkerIdentityDigest, HATakeoverWorkerIdentityDigest, HAOwnerProcessInstanceDigest, HATakeoverProcessInstanceDigest, HATakeoverReceiptDigest, HARestartReceiptDigest, HASessionRecoveryReceiptDigest, HACleanupReceiptDigest, HAResponseLossReceiptDigest, HAFactChainDigest string
	CredentialCleanupStatus CredentialCleanupStatus
	Observed, Created, Changed, Unchanged, Conflicts int64
	Missing, Stale, Restored, Tombstoned, Rejected int64
	FailureCode, TraceID string
	Version int64
	CreatedAt time.Time
	StartedAt, HeartbeatAt, CompletedAt *time.Time
}

func AuthorityScopeDigest(environmentIDs []string) (string, error)
func ProfileManifestDigest(canonicalManifest []byte) (string, error)
func SourceDefinitionDigest(source Source, revision SourceRevision) (string, error)
func (revision SourceRevision) BindingDigest() string
func (source Source) PublishedBindingEligible(revision SourceRevision) bool
~~~

`ManualProfileV1()` is the Task 2-owned immutable read-only bootstrap contract required before Task 13 exists：`MANUAL/MANUAL_V1/MANUAL_V1`、`MANUAL` sync、`CATALOG_SEQUENCE` freshness、`SINGLE_ENVIRONMENT`、rate/window/backpressure values `1/1/1/1`、page item/relation/bytes/document limits `1/0/65536/65536`，and NULL Integration/Credential/Trust/Network/schedule/typed-extension fields。Its 62-byte Provider schema is `{"additionalProperties":false,"properties":{},"type":"object"}` with SHA `99334726611ccf58a148b0814696bfa6fe08c1b2d027e946beccf5a74331c9aa`。The definition is exactly `FramedTupleV1("asset-source-definition.v2",source_kind,provider_kind,profile_code,raw_profile_manifest_sha256,raw_provider_schema_sha256)` in that six-frame order；SQL and Go decode both named hashes to raw 32-byte frames and byte-match the MANUAL/Victoria/AWX fixtures。For MANUAL its framed length is 144 and SHA is `7a0c248c3ebd32dae4e94b516d6f56608d4f1a25cd33d0fe467b54200824984c`。The constructor returns deep clones；digest helpers recompute from bytes and no helper accepts precomputed caller truth。

Profile manifest v1 has exactly these RFC 8785 keys and no others：`version/source_kind/provider_kind/profile_code/sync_mode/freshness_kind/environment_mapping_mode/integration_mode/credential_purpose/trust_mode/network_mode/rate_limit_requests/rate_limit_window_seconds/backpressure_base_seconds/backpressure_max_seconds/schedule_mode/max_page_items/max_page_relations/max_page_bytes/max_document_bytes/parser_code/compatibility_class/dlp_policy_code/trusted_path_codes/relationship_types/typed_extension_code`。Codes are bounded canonical enums/tokens，integers are bounded nonnegative/positive as appropriate，arrays are unique `C`-sorted，extension is string-or-NULL；no reference value、endpoint、secret or runtime locator is legal。The exact `MANUAL_V1` bytes are `{"backpressure_base_seconds":1,"backpressure_max_seconds":1,"compatibility_class":"MANUAL_V1","credential_purpose":"NONE","dlp_policy_code":"ASSET_SAFE_V1","environment_mapping_mode":"SINGLE_ENVIRONMENT","freshness_kind":"CATALOG_SEQUENCE","integration_mode":"NONE","max_document_bytes":65536,"max_page_bytes":65536,"max_page_items":1,"max_page_relations":0,"network_mode":"NONE","parser_code":"MANUAL_ASSET_V1","profile_code":"MANUAL_V1","provider_kind":"MANUAL_V1","rate_limit_requests":1,"rate_limit_window_seconds":1,"relationship_types":[],"schedule_mode":"NONE","source_kind":"MANUAL","sync_mode":"MANUAL","trust_mode":"NONE","trusted_path_codes":["MANUAL_V1_DISPLAY_NAME","MANUAL_V1_EXTERNAL_ID","MANUAL_V1_KIND"],"typed_extension_code":null,"version":"asset-source-profile-manifest.v1"}`（794 bytes，SHA-256 `57d171caef88e859700dde32fda6b9a982b25b50deca47c6246945c8dfb60b96`）。The built-in resolver serves only this profile；Task 13 extends the same interface。Every repository/admission path compares resolver bytes/hash to the persisted Revision before using freshness、mapping、path、purpose or limits；same-code drift is fatal.

`BindingDigest` is the lowercase SHA-256 of exactly 20 `FramedTupleV1` frames in this immutable order: domain `asset-source-revision-binding.v1`, Tenant ID, Workspace ID, Source ID, minimal-decimal revision, 32 raw bytes of `source_definition_digest`, Integration ID-or-NULL, sync mode, Credential Reference-or-NULL, Trust Reference-or-NULL, Network Policy Reference-or-NULL, 32 raw bytes of `authority_scope_digest`, minimal-decimal rate requests/window seconds/backpressure base seconds/backpressure max seconds, Profile Code, schedule-or-NULL, typed-extension-code-or-NULL, and 32 raw bytes prepared-extension-digest-or-NULL. The final two frames are present as `NULL` even for no-extension/MANUAL revisions and may never be appended later under `.v1`; code/digest must be both NULL or both present. In Go, each optional Integration/reference/schedule/extension named-string zero value is the sole SQL-NULL representation；present-empty is invalid and cannot be constructed as a second semantic value. UUID/enum/opaque tokens use canonical UTF-8, integers have no sign/leading zero, and named digests are decoded raw bytes rather than 64-byte hex text. `source_definition_digest` remains the Provider/Profile definition only；it includes exact persisted Profile-manifest/schema hashes but never source-specific binding or typed extension. Status、validation、version、actor and timestamps are deliberately excluded.

The golden present fixture uses Tenant `11111111-1111-4111-8111-111111111111`、Workspace `22222222-2222-4222-8222-222222222222`、Source `33333333-3333-4333-8333-333333333333`、revision `7`、definition bytes `0x11×32`、Integration `44444444-4444-4444-8444-444444444444`、`SCHEDULED`、references `cred-ref-v1/trust-ref-v1/network-ref-v1`、authority bytes `0x22×32`、limits `100/60/5/300`、Profile and extension code `VICTORIAMETRICS_OPERATOR_V1`、schedule `0 */5 * * * *` and extension bytes `0x33×32`; framed length is `495` and SHA-256 is `49f8013b8e3cccdcbeb1d125915b2bf424815306494318ee2d3b7e298f3f6b74`. The all-NULL-optional MANUAL fixture reuses those three IDs, sets revision `1`、definition bytes `0xaa×32`、Integration/three references/schedule/extension code/extension digest all NULL、sync `MANUAL`、authority bytes `0xbb×32`、limits `1/1/1/1` and Profile `MANUAL_V1`; its 20-frame length is `296` and SHA-256 is `88965ba68eb1d6450b1252a0a261bfaa282556e0ec569b6db2c0153d235912b5`. Unit tests distinguish NULL from present-empty, mutate every included field, prove excluded lifecycle fields do not change the digest and fuzz boundary collisions；`internal/assetcatalog/postgres/binding_digest_parity_integration_test.go` sends the exact 20 frames to real PostgreSQL 18.4 `asset_catalog_framed_value_v1` and byte-compares both Go fixtures.

Opaque Credential/Trust/Network/Policy references are distinct named value types with the same dedicated no-scheme/no-path grammar enforced by Task 1；they are only registry lookup IDs. String validity never proves the referenced object exists：the owning service must resolve the exact scoped registry fact and purpose before use.

Validation requires `revision.BindingDigest() == revision.CanonicalRevisionDigest`. `PublishedBindingEligible` is deliberately non-authoritative and proves only the already-loaded Source/Revision row closure: `ACTIVE + AVAILABLE`, positive gate revision, exact `PUBLISHED` revision/digest, successful validated run, non-empty validation digest and exact binding digest；for profiles that require real qualification it additionally requires a current non-expired gate-evidence pointer/digest，while exact `MANUAL_V1` retains its no-evidence synchronous publication special case. A Source enum is never evidence that a Provider/Profile is installed. Every production admission must reload the exact scoped Source/Revision plus installed Profile/Adapter and all required Connection/Runtime/Capability/qualification facts；future K8S/AWX stay unavailable until their owned successor hook and evidence pass. No domain method accepts caller-supplied `published`/`available` booleans or claims full live-capability authorization.

`SourceRun` uses typed `RunKind/RunStatus/RunStage/TriggerType/FreshnessKind` enums and carries exact Source definition revision/canonical digest, gate revision, page/checkpoint hashes, page sequence, safe timing/fence epoch/heartbeat coordinates, typed work-result summary, validation/qualification proof digests, safe HA worker/process/event-chain digests, cleanup status, stable failure code/trace and the exact persisted counts. HA fields are Repository-derived and all-null outside `TWO_WORKER_HA`；persistence/terminal command interfaces reject caller-populated HA facts，and only the Repository read model populates them from durable receipts. Its structure—not a serializer omit-tag—excludes lease owner/token hash, checkpoint ciphertext/key ID, cleanup attempt ID/epoch/private digests, terminal private digests and Provider runtime material. Observation and every page/cursor/filter clone likewise deep-copy all byte slices、maps、slices、pointers and nested results.

Task 13 solely owns the typed Source extension transaction contract. It must expose no SQL string、variadic arguments、`pgx.Tx/Rows/Row/Conn`、Begin/Commit/Rollback/Copy or raw connection. A repository-created shared-state session offers only closed scoped trusted-fact lookup, read-own-extension and create-own-extension operations；its `VALIDATING → CREATING → VERIFIED → CLOSED` state prevents writes during validation, new reads after base sealing, more than one extension write or use after the outer serializable transaction. Exact fixed stored-procedure manifests bind signature、owner、ACL、search path and definition digest；extension roles have only their own 1:1 table rights. Failure/digest mismatch rolls back base、extension、audit and outbox together. Task 2 defines none of these mutation interfaces.

`LeaseFence` is a non-serializable process-local value whose root `assetcatalog` type is an alias of `internal/leasefence.Fence`. Its unexported shared state binds exact Run ID、owner、epoch and one 32-byte raw token. The internal package exposes only the two purpose-named constructors `FromManualRun` and `FromQueueClaim`; there is no `New/FromRaw/Token/Bytes/Hash` factory or accessor. An AST/import architecture test allows production constructor calls only in `internal/assetcatalog/postgres/manual_run.go` and `internal/discoveryqueue/postgres/repository.go`, with the latter introduced by Task 27. Both constructors consume a `*[32]byte` and clear the caller buffer on success and every error. Copies share one mutex-protected state, so `Destroy` zeroes coordinates/token and invalidates every copy under race. JSON/Text/Binary marshal/unmarshal fail；`String`/`GoString`/`Format`/`LogValue` return only `[REDACTED_LEASE_FENCE]`. `Matches` locks state, decodes the persisted lowercase SHA-256 and uses constant-time comparison after the Repository locked the Run；zero/destroyed/forged coordinates never match. The type is only a misuse barrier：every transaction still reloads persisted authorization/gate/checkpoint facts. Task 27 owns terminal-command construction plus Go↔SQL digest parity and receipt-first response-loss replay; Task 2 must not create an incomplete public terminal constructor.

Asset list sorting is a closed enum, not arbitrary SQL:

~~~go
type AssetSort string

const (
	AssetSortDisplayNameAsc    AssetSort = "display_name_asc"
	AssetSortLastObservedDesc AssetSort = "last_observed_at_desc"
)

type AssetCursor struct {
	Sort        AssetSort
	QueryDigest string
	Value       string
	AssetID     string
}
~~~

`ListAssetsRequest` carries one of those sorts, limit 1–100, filters and optional matching cursor. It computes a canonical query digest over exact Scope、normalized filter set and sort；a cursor whose sort or query digest differs is invalid. Task 7 signs the full cursor payload. Cursor values cannot change filters/Scope during traversal.

- [ ] **Step 3: Implement exhaustive bounded validation**

~~~go
type CredentialReferenceID string
type TrustReferenceID string
type NetworkPolicyReferenceID string
type PolicyReferenceID string
type ProfileCode string
type ExtensionCode string

var opaqueReference = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
var providerToken = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)
var labelKey = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)
var lowercaseRFC4122UUID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

func (scope Scope) Valid() bool {
	return validUUID(scope.TenantID) &&
		validUUID(scope.WorkspaceID) &&
		validUUID(scope.EnvironmentID)
}

func validUUID(value string) bool {
	return lowercaseRFC4122UUID.MatchString(value)
}
~~~

Validation must use exhaustive switches (no default acceptance), including the exact `SOURCE|GOVERNANCE|MERGE_DECISION` FieldOwnership set, and enforce non-zero finite UTC times with no monotonic component、microsecond precision and a bounded year, versions >0, at most 64 labels/max 16 KiB UTF-8 serialization, trimmed strings, no NUL/CR/LF, and reject label keys containing normalized secret/token/password/credential/dsn/endpoint. The Keycloak verifier maps only the fixed `aiops_tenant_id` string claim, and the Authenticator requires it to pass the same canonical UUID validator before constructing Principal；there is no query/body/configurable alternate tenant claim. New IDs use `internal/ids.NewUUID`; Clone all maps/slices/bytes/pointers/pages/cursors and nested mutation results at boundaries. `IsLifecycleEdge` rejects self-edges and is only the structural graph；receipt-first replay handles idempotency, and management/policy decides which edge is currently authorized. `RETIRED` has no outgoing edge；Task 3 exposes only quarantine/retire while ACTIVE waits for later trusted closure.

Stable errors: `ErrInvalidRequest`、`ErrNotFound`、`ErrScopeViolation`、`ErrVersionConflict`、`ErrStateConflict`、`ErrIdempotency`. They contain no database/provider text.

- [ ] **Step 4: Define repository groups without import cycles**

~~~go
type MutationMetadata struct { TraceID, IdempotencyKey, RequestHash string }
type MutationContext struct { scopeKind uint8; sourceScope SourceScope; environmentID, actorID, subjectID string; authenticatedAt time.Time; traceID, idempotencyKey, requestHash string }
func NewMutationContext(authn.Principal, Scope, MutationMetadata) (MutationContext, error)
func NewSourceMutationContext(authn.Principal, SourceScope, MutationMetadata) (MutationContext, error)
func (MutationContext) Validate() error
func (MutationContext) SourceScope() SourceScope
func (MutationContext) EnvironmentScope() (Scope, bool)
func (MutationContext) ActorID() string; func (MutationContext) SubjectID() string
func (MutationContext) AuthenticatedAt() time.Time; func (MutationContext) TraceID() string
func (MutationContext) IdempotencyKey() string; func (MutationContext) RequestHash() string

type AssetReadConstraint struct { initialized, unrestricted bool; serviceIDs []string }
type SourceReadConstraint struct { initialized bool; environmentIDs []string }
func NewAssetReadConstraint(bool, []string) (AssetReadConstraint, error)
func NewSourceReadConstraint([]string) (SourceReadConstraint, error)
func (AssetReadConstraint) Validate() error; func (AssetReadConstraint) Unrestricted() bool; func (AssetReadConstraint) ServiceIDs() []string
func (SourceReadConstraint) Validate() error; func (SourceReadConstraint) EnvironmentIDs() []string

type AssetFilter struct { Search, ServiceID string; Kinds []Kind; SourceIDs []string; Lifecycles []Lifecycle; MappingStatuses []domain.MappingStatus; Criticalities []Criticality; DataClassifications []DataClassification }
type ListAssetsRequest struct { Scope Scope; Filter AssetFilter; Access AssetReadConstraint; Sort AssetSort; Limit int; Cursor *AssetCursor }
type CreateAssetCommand struct { Context MutationContext; SourceID string; Kind Kind; ExternalID, DisplayName string; OwnerGroup *string; Criticality Criticality; DataClassification DataClassification; Labels map[string]string }
type UpdateGovernanceCommand struct { Context MutationContext; AssetID, DisplayName string; OwnerGroup *string; Criticality Criticality; DataClassification DataClassification; Labels map[string]string; ExpectedVersion int64 }
type TransitionCommand struct { Context MutationContext; AssetID string; To Lifecycle; ReasonCode string; ExpectedVersion int64 }

type AssetSourceReference struct { ID, Name string; Kind SourceKind }
type AssetServiceReference struct { ID, Name string; Role BindingRole }
type OperationalSummaryStatus string
const OperationalSummaryNotConfigured OperationalSummaryStatus = "NOT_CONFIGURED"
type ConnectionSummary struct { Status OperationalSummaryStatus }
type CapabilitySummary struct { Status OperationalSummaryStatus; Count int64 }
type FieldOwnership string
const (
	FieldOwnershipSource FieldOwnership = "SOURCE"
	FieldOwnershipGovernance FieldOwnership = "GOVERNANCE"
	FieldOwnershipMergeDecision FieldOwnership = "MERGE_DECISION"
)
type FieldProvenanceSummary struct { FieldCode, SourceID, ProviderKind string; SourceRevision int64; ObservedAt time.Time; ProviderPathCode string; Confidence int; Ownership FieldOwnership }
type AssetRelationCounts struct { Incoming, Outgoing int64 }
type AssetReadModel struct { Asset; Source AssetSourceReference; Services []AssetServiceReference; Connection ConnectionSummary; Capability CapabilitySummary }
type AssetDetailReadModel struct { AssetReadModel; FieldProvenance []FieldProvenanceSummary; Relations AssetRelationCounts }
type AssetPage struct { Items []AssetReadModel; Next *AssetCursor; ManualCreateEligible bool }

type RelationshipCursor struct { QueryDigest string; Type RelationshipType; SourceAssetID, TargetAssetID, RelationshipID string }
type ListRelationshipsRequest struct { Scope Scope; Access AssetReadConstraint; AssetID, SourceID string; Types []RelationshipType; Statuses []RelationshipStatus; Limit int; Cursor *RelationshipCursor }
type RelationshipPage struct { Items []Relationship; Next *RelationshipCursor }
type BindingCursor struct { QueryDigest, ServiceID, AssetID, BindingID string; Role BindingRole }
type ListBindingsRequest struct { Scope Scope; Access AssetReadConstraint; ServiceID, AssetID string; Roles []BindingRole; Statuses []BindingStatus; Limit int; Cursor *BindingCursor }
type BindingPage struct { Items []ServiceAssetBinding; Next *BindingCursor }
type CreateBindingCommand struct { Context MutationContext; ServiceID, AssetID string; Role BindingRole; ReasonCode string }
type DeleteBindingCommand struct { Context MutationContext; BindingID, ReasonCode string; ExpectedVersion int64 }

type ConflictObservationReference struct { ID, SourceID string; SourceRevision int64; ObservedAt time.Time }
type ConflictAssetReference struct { ID, DisplayName string; Kind Kind; Lifecycle Lifecycle }
type ConflictServiceReference struct { ID, Name string }
type ConflictImpactCounts struct { AssetActiveBindings, AssetActiveRelationships, CandidateAssetActiveBindings, CandidateAssetActiveRelationships, CandidateServiceActiveBindings int64 }
type ConflictReadModel struct { Conflict; Observation ConflictObservationReference; Asset ConflictAssetReference; CandidateAsset *ConflictAssetReference; CandidateService *ConflictServiceReference; Impact ConflictImpactCounts }
type ConflictCursor struct { QueryDigest string; CreatedAt time.Time; ConflictID string }
type ListConflictsRequest struct { Scope Scope; Access AssetReadConstraint; AssetID, SourceID string; Statuses []ConflictStatus; Limit int; Cursor *ConflictCursor }
type ConflictPage struct { Items []ConflictReadModel; Next *ConflictCursor }
type MappingDecision struct { Context MutationContext; ConflictID, ServiceID string; Resolution ConflictResolution; BindingRole BindingRole; ReasonCode string; ExpectedVersion int64 }

type SourceUsage string
const SourceUsageManualAssetCreate SourceUsage = "manual_asset_create"
type SourceCursor struct { QueryDigest, SourceID string }
type ListSourcesRequest struct { Scope SourceScope; Access SourceReadConstraint; Kinds []SourceKind; Statuses []SourceStatus; GateStatuses []SourceGateStatus; Usage SourceUsage; EnvironmentID string; Limit int; Cursor *SourceCursor }
type SourceReadModel struct { Source Source; LatestRevision SourceRevision; PublishedRevision *SourceRevision; CurrentRun, LastSuccessfulRun *SourceRun }
type SourcePage struct { Items []SourceReadModel; Next *SourceCursor }
type SourceLocator struct { Scope SourceScope; SourceID string }
type SourceRunLocator struct { Scope SourceScope; RunID string }

type MutationReceipt struct { AuditID, TraceID string; IdempotentReplay bool }
type AssetMutationResult struct { Asset AssetDetailReadModel; Receipt MutationReceipt }
type BindingMutationResult struct { Binding ServiceAssetBinding; Receipt MutationReceipt }
type MappingDecisionResult struct { Conflict ConflictReadModel; Binding *ServiceAssetBinding; Receipt MutationReceipt }

type AssetReadRepository interface { GetReadModel(context.Context, AssetLocator, AssetReadConstraint) (AssetDetailReadModel, error); List(context.Context, ListAssetsRequest) (AssetPage, error) }
type Repository interface { Reader; AssetReadRepository; ScopeResolver; Create(context.Context, CreateAssetCommand) (AssetMutationResult, error); UpdateGovernance(context.Context, UpdateGovernanceCommand) (AssetMutationResult, error); Transition(context.Context, TransitionCommand) (AssetMutationResult, error) }
type MappingRepository interface { ConflictScopeResolver; ListRelationships(context.Context, ListRelationshipsRequest) (RelationshipPage, error); ListBindings(context.Context, ListBindingsRequest) (BindingPage, error); CreateBinding(context.Context, CreateBindingCommand) (BindingMutationResult, error); DeleteBinding(context.Context, DeleteBindingCommand) (MutationReceipt, error); ListConflicts(context.Context, ListConflictsRequest) (ConflictPage, error); ResolveConflict(context.Context, MappingDecision) (MappingDecisionResult, error) }
type SourceReadRepository interface { SourceScopeResolver; GetSource(context.Context, SourceLocator, SourceReadConstraint) (SourceReadModel, error); ListSources(context.Context, ListSourcesRequest) (SourcePage, error); GetSourceRun(context.Context, SourceRunLocator, SourceReadConstraint) (SourceRun, error) }
~~~

`NewMutationContext` is Environment-scoped；`NewSourceMutationContext` is Workspace-scoped and never fabricates an Environment。Both derive `actorID="oidc:"+principal.Subject`、subject/auth time/Tenant solely from the verified Principal, require the database-resolved scope Tenant to match, and accept only server-built metadata。Their constructors plus the two purpose-named exported-but-opaque read-constraint constructors have AST-allowed production call sites only in `internal/assetcatalog/management.go`（later Task 14 extends that same owner）and `_test.go`；Pack 02 PostgreSQL tests can therefore construct normal values without exposing fields, getters clone slices and zero values fail closed。`AssetFilter.ServiceID` is a client filter, while `AssetReadConstraint.ServiceIDs` is the independent server authorization set；the latter is included in QueryDigest and an initialized restricted-empty set returns no rows, never “all”。`NewSourceReadConstraint` accepts 0–100 unique canonical Environment IDs and always returns an initialized value：an explicit empty input is the legal deny-all constraint，whereas the unconstructed zero value has `initialized=false` and fails validation before SQL。A Source is visible only when its nonempty full authority set is a subset of the initialized allow-list, so a multi-Environment Source is never partially disclosed。`SourceUsageManualAssetCreate` additionally requires the exact sole authority Environment to equal the requested Environment。Tests distinguish zero value、constructed empty、one ID、100 IDs、101 IDs、duplicates and non-canonical UUIDs.

Every cursor QueryDigest covers exact resolved Scope、normalized filters、server read constraint and fixed sort；relation order is `(relationship_type,source_asset_id,target_asset_id,id)`，binding `(service_id,binding_role,asset_id,id)`，conflict `(created_at DESC,id DESC)` and Source `(id ASC)`。`AssetCursor.Value` must match its sort as normalized UTF-8 or canonical UTC time before SQL。Latest Source revision is the exact max revision；published/current/last-success pointers are scope/source-consistent, current is the unique nonterminal Run and last-success is only the exact `SUCCEEDED` pointer（never aggregate or PARTIAL）。Core Conflict exposes hashes only；the read model adds safe candidate references、Observation revision/time and ACTIVE impact counts in one scoped query/decision transaction, never raw values。`AssetReadModel` joins same-Scope Source and sorted/deduplicated ACTIVE Service bindings；before 000016/000017 it returns only explicit `NOT_CONFIGURED`/count `0`, never inferred health。`AssetPage.ManualCreateEligible` is a server-owned collection fact, not a permission：Pack 02 computes it from the exact built-in `ManualProfileV1` Source, its one authority child equal to the requested Environment, and current `ACTIVE + PUBLISHED + AVAILABLE` binding closure；Pack 03 combines it with authorization and never accepts a browser boolean or performs an unscoped second lookup。A nullable persisted OwnerGroup remains `*string`; API projection renders nil as the fixed “未分配” display without changing the database fact.

Safe Source/Run read interfaces remain in `assetcatalog`; Source create/revision/sync mutation interfaces are deferred to Task 13. Reconciliation batch/store lives in `assetdiscovery` with dependency direction `assetdiscovery -> assetcatalog`. Pack 02/03 consume these exact types and never redeclare reduced copies.

- [ ] **Step 5: Run domain tests**

Run:

~~~bash
gofmt -w $(rg --files internal/authn internal/assetcatalog internal/leasefence -g '*.go')
go test -race ./internal/authn ./internal/assetcatalog ./internal/leasefence -count=1
AIOPS_TEST_POSTGRES_DSN="$AIOPS_TEST_POSTGRES_DSN" go test ./internal/assetcatalog/postgres -run TestBindingDigestParity -count=1
~~~

The PostgreSQL command must execute against the Task 1 PostgreSQL 18.4 TLS harness；an unset/unreachable DSN is a failure, not a skip.

Expected: PASS for every enum member and unknown rejection；canonical Scope/IDs/opaque references/UTC time；every model field mutation；the exact BindingDigest golden/parity/NULL boundary and every included/excluded field；clone isolation；query-bound cursors；structurally safe SourceRun；stable safe errors；lifecycle matrix with no self-edge and terminal RETIRED；local Catalog/binding eligibility without provider-support inference；and non-serializable/redacted/consuming/destroy-all-copies/race-safe fence behavior plus exact constructor-call architecture gates.

- [ ] **Step 6: Commit**

~~~bash
git add internal/assetcatalog/types.go internal/assetcatalog/validation.go \
  internal/assetcatalog/lifecycle.go internal/assetcatalog/repository.go \
  internal/assetcatalog/lease_fence.go internal/assetcatalog/types_test.go \
  internal/assetcatalog/mutation_context_architecture_test.go \
  internal/assetcatalog/lifecycle_test.go internal/assetcatalog/lease_fence_test.go \
  internal/assetcatalog/lease_fence_architecture_test.go internal/leasefence \
  internal/assetcatalog/postgres/binding_digest_parity_integration_test.go \
  internal/authn/authenticator.go internal/authn/authenticator_test.go \
  internal/authn/keycloak.go internal/authn/keycloak_test.go
git commit -m "feat(assetcatalog): define governed asset domain"
~~~
