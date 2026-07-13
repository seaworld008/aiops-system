# Asset Catalog Schema and Domain Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 用 `000015_assets_catalog` 建立九张生产级资产目录表、不可变 Source Revision、强作用域/生命周期约束，并定义后续 Connection、Grant 和前端共同消费的稳定 Go 领域接口。

**Architecture:** PostgreSQL 保存 append-only 外部观测与带版本治理投影；Go 领域层把来源事实、治理事实、生命周期、映射和 Service Binding 分开。数据库约束是最后防线，Repository/HTTP 的校验不能替代复合外键、CAS、不可变触发器和受保护回滚。

**Tech Stack:** Go 1.26.5、PostgreSQL 18.4、pgx v5、`pgcrypto` SHA-256、现有 `audit_records`/`outbox_events`。

## Global Constraints

- 规范事实源：`docs/superpowers/specs/2026-07-13-operational-assets-controlled-access-design.md`。
- 实施前用 superpowers:using-git-worktrees 创建仓库目录树之外的独立 worktree；不得删除或修改用户已有 `.worktrees/*`。
- Go 固定 `go 1.26`、`toolchain go1.26.5`；集成数据库只接受 PostgreSQL 18.4 或更新 18.x。
- 本包只拥有 `migrations/000015_assets_catalog.{up,down}.sql`；000016 Connection、000017 VictoriaMetrics、000018 Grant、000019 主机/PostgreSQL、000020 治理能力均不得提前实现。
- 000015 只创建 `asset_sources`、`asset_source_revisions`、`asset_source_runs`、`asset_observations`、`assets`、`asset_type_details`、`asset_conflicts`、`asset_relationships`、`service_asset_bindings`。
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
- 每个任务按 Red → Green → Refactor；每个任务末尾提交步骤只包含本任务文件。
- 完成本包后进入 [02-repository-discovery.md](./02-repository-discovery.md)。

---

### Task 1: PostgreSQL 18.4 schema, invariants, rollback guard, and recovery proof

**Files:**
- Create: **migrations/000015_assets_catalog.up.sql**
- Create: **migrations/000015_assets_catalog.down.sql**
- Create: **internal/assetcatalog/postgres/migration_test.go**
- Create: **internal/assetcatalog/postgres/migration_integration_test.go**
- Create: **internal/assetcatalog/postgres/migration_shape_integration_test.go**
- Create: **internal/assetcatalog/postgres/migration_contract_integration_test.go**
- Create: **internal/assetcatalog/postgres/migration_adversarial_contract_integration_test.go**
- Create: **internal/assetcatalog/postgres/migration_closure_adversarial_integration_test.go**
- Create: **internal/assetcatalog/postgres/migration_final_contract_integration_test.go**
- Create: **internal/assetcatalog/postgres/migration_run_replay_acceptance_integration_test.go**
- Create: **internal/assetcatalog/postgres/migration_reclaim_acceptance_integration_test.go**
- Create: **internal/assetcatalog/postgres/migration_scope_shape_acceptance_integration_test.go**
- Create: **internal/assetcatalog/postgres/migration_scope_remaining_acceptance_integration_test.go**
- Create: **internal/assetcatalog/postgres/migration_freshness_domain_acceptance_integration_test.go**
- Create: **internal/assetcatalog/postgres/migration_online_compatibility_integration_test.go**
- Create: **internal/assetcatalog/postgres/migration_recovery_integration_test.go**
- Create: **internal/assetcatalog/postgres/recovery_container_test.go**
- Create: **internal/assetcatalog/postgres/schema_admission.go**
- Create: **internal/assetcatalog/postgres/schema_admission_test.go**
- Create: **internal/assetcatalog/postgres/schema_admission_integration_test.go**
- Modify: **internal/store/postgres/migrations_integration_test.go**
- Modify: **internal/investigation/postgres/testpostgres_test.go**
- Modify: **internal/investigation/postgres/correlation_create_integration_test.go**
- Modify: **internal/investigation/postgres/latest_runtime_fixture_integration_test.go**
- Modify: **Makefile**

**Interfaces:**
- Consumes candidates from 000002: `workspaces(tenant_id,id)`、`environments(tenant_id,workspace_id,id)`、`integrations(tenant_id,workspace_id,id)`、`services(tenant_id,workspace_id,id)`。
- Produces `assets UNIQUE (tenant_id,workspace_id,environment_id,id)` for 000016 Connection.
- Produces Workspace/Environment-scoped candidate keys for the other eight tables.
- Does not change any 000001–000014 table definition.

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
		"asset_sources", "asset_source_revisions", "asset_source_runs", "asset_observations", "assets",
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
		"before update or delete on asset_observations",
		"before update or delete on asset_type_details",
		"retired asset is terminal",
		"unsafe asset catalog rollback: catalog state remains",
	} {
		if !strings.Contains(up+"\n"+down, required) {
			t.Errorf("missing invariant %q", required)
		}
	}
}

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

Run: `go test ./internal/assetcatalog/postgres -run TestAssetCatalogMigrationOwnsExactTablesAndGuardsData -count=1`

Expected: FAIL because both 000015 files are missing.

- [x] **Step 2: Implement the transactional up migration with this exact schema**

Start with `BEGIN; SET LOCAL lock_timeout='5s';` and lock `tenants, workspaces, environments, integrations, services, service_bindings, audit_records, outbox_events` in access-exclusive order so concurrent schema changes cannot interleave and the new binding-eligibility FK never relies on an implicit referenced-table DDL lock.

| Table | Required columns and exact purpose |
|---|---|
| `asset_sources` | 稳定 UUID 身份/Workspace Scope；`source_kind/provider_kind/name/status` 与 `published_revision/published_revision_digest`；正交 `gate_status/gate_reason_code/gate_revision/validated_run_id/validation_digest/validated_binding_digest`；当前 checkpoint (`checkpoint_ciphertext/checkpoint_key_id/checkpoint_sha256/checkpoint_version/checkpoint_revision`)；HA backpressure (`next_allowed_at/consecutive_failures`)；创建幂等/hash、version、exact `last_success_run_id/at` 与 `last_complete_snapshot_run_id/at`、timestamps |
| `asset_source_revisions` | 复合 Scope + stable source + monotonically increasing revision；`DRAFT/VALIDATING/VALIDATED/REJECTED/PUBLISHED/SUPERSEDED`；content-addressed canonical provider schema；`integration_id/sync_mode/authority_scope_digest/source_definition_digest`；opaque `credential_reference_id/trust_reference_id/network_policy_reference_id`（`MANUAL/MANUAL_V1` 三者必须全为 `NULL`）；固定 rate/backpressure/profile/schedule；完整 availability binding 的 `canonical_revision_digest`；validation run/digest；actor/reason/CAS/time；创建后 canonical content 不可变 |
| `asset_source_runs` | source scope + exact source definition revision/canonical digest; `run_kind/status/stage_code/stage_changed_at/trigger_type`; immutable gate revision; idempotency/hash; cursor before/after SHA; page sequence/digest and final/complete-snapshot proof; lease owner/expiry, monotonically increasing `fence_epoch`, token hash and heartbeat sequence; pending `DELAY` transition with reason/`not_before`/attempt-bound intent digest; observed/created/changed/unchanged/conflict/missing/stale/restored/tombstoned/rejected counts; typed work result/digest/recorded time; validation proof; checkpoint-lineage-rollover proof; broker-owned opaque cleanup attempt ID/epoch plus cleanup status/digest; optional immutable terminal-failure override/digest; exact `terminal_command_sha256`; stable failure code/trace; start/heartbeat/complete |
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

The Phase 1 Relationship check constraint is named `asset_relationships_type_check` and contains exactly the nine values above. A later owned migration may expand it only together with the shared Go `RelationshipType` enum/tests and a down guard；Phase 1 adapters cannot submit future values early.

Use composite foreign keys for every parent. `service_asset_bindings` must additionally use `(service_id,environment_id) -> service_bindings(service_id,environment_id)` and Repository validation to prove the Service is bound to the selected Environment; separate Service/Environment Workspace FKs do not replace this eligibility edge. `asset_observations.source_revision`、provenance `source_revision` and `assets.last_source_revision` always mean the immutable Source **definition** revision (`asset_source_revisions.revision`); `asset_source_runs` therefore has no second `definition_revision` alias. Provider-specific object versions are hashed into the closed freshness proof and never reuse this integer. `assets.last_source_revision` references the exact Source Revision, and its current Observation FK includes Environment, Source, Provider, Source Revision and Observation chain so a projection cannot bind cross-Environment or drifted facts. Observation replay identity is exactly `(tenant_id,workspace_id,source_id,run_id,provider_kind,external_id)`: this admits at most one item per Run across all pages while allowing the same asset to append a new Observation in every later Run under the same published Source definition revision. Every Adapter must reject/coalesce duplicate object keys before page commit; a changed duplicate in the same Run is `SOURCE_RUN_OBJECT_DUPLICATE`, not a second Observation.

Freshness is a separate persisted contract. Registry locks one `FreshnessKind` per Provider profile/revision. `CATALOG_SEQUENCE` is server-only for governed `MANUAL_MUTATION`; `OBJECT_SEQUENCE` uses a positive Provider integer; `OBJECT_TIME_SEQUENCE` uses finite UTC microsecond Provider time plus a positive integer tie-break; `CHECKPOINT_SEQUENCE` must equal the accepted next source checkpoint version. Each Observation stores the order, lowercase SHA-256 of any opaque Provider version, a domain-separated `provider_fact_sha256`, `previous_observation_id/previous_chain_sha256`, a unique `observation_chain_sha256`, accepted checkpoint version, run fence epoch and run page sequence. Insert admission requires the exact live lease/fence、published Source definition/gate/checkpoint and next Run page/checkpoint coordinates；a `DEFERRABLE INITIALLY DEFERRED` closure additionally requires the same transaction to advance Run/Source to those coordinates and append exact `ASSET_SOURCE_RUN/PAGE_APPLIED` receipt `request_id="source-page:<run_uuid>:<page_sequence>"`、`payload_hash=page_digest`. The page transaction first reads its fixed server `transaction_timestamp()`；Go uses that value to construct canonical provenance and Observation chain bytes，then PostgreSQL requires `observed_at` and provenance acceptance time to equal the same transaction timestamp. Production INSERT SQL must not construct JSON/canonical bytes or depend on the unknowable next-statement `statement_timestamp()`. Repository locks and CASes the exact prior Asset `last_observation_id/chain`; the repeatable provider fact digest is never the sole ABA guard.

All Catalog fact hashes use one byte-exact `FramedTupleV1`: concatenate fields in the listed order; encode `NULL` as one byte `0x00`, and a present field as `0x01 || uint32-big-endian byte_length || raw_bytes`. Empty and `NULL` are distinct. UUID/token/enum/schema values are canonical UTF-8; integers are minimal base-10 ASCII without sign or leading zero (`0` is the sole zero encoding); booleans are `0` or `1`; times are finite UTC microsecond text `YYYY-MM-DDTHH:MM:SS.ffffffZ`; every named SHA-256 field is the decoded 32 raw bytes, never its 64-byte hex text. RFC 8785 canonical document/provenance bytes must have unique JSON keys. `field_provenance_sha256 = SHA256(canonical_persisted_provenance_bytes)` and therefore binds the injected Catalog time. Separately, sort Provider provenance skeleton entries by `field_code` and compute `provider_provenance_sha256 = SHA256(FramedTupleV1("asset-provider-provenance.v1",entry_count,repeated field_code,provider_path_code,ownership,confidence))`; this semantic digest excludes server-injected Source ID/provider/revision/observed time and is carried only inside `provider_fact_sha256`. Fingerprint values are normalized only in Adapter memory, then each value becomes `SHA256(FramedTupleV1("asset-fingerprint-value.v1",fingerprint_code,canonical_value))`; sort by `fingerprint_code` and compute `fingerprint_sha256 = SHA256(FramedTupleV1("asset-fingerprints.v1",entry_count,repeated fingerprint_code,fingerprint_value_sha256))`. The empty fingerprint set is the digest of that domain plus count `0`; raw fingerprint values are never persisted or returned.

`provider_fact_sha256` is the persisted asset semantic fact digest, exactly `SHA256(FramedTupleV1("asset-provider-fact.v1",tenant_id,workspace_id,source_id,provider_kind,source_revision,canonical_revision_digest,source_definition_digest,environment_id,external_id,kind-or-NULL,display_name-or-NULL,schema_version,tombstone,tombstone_reason-or-NULL,document_sha256-or-NULL,fingerprint_sha256,provider_provenance_sha256))`. A non-tombstone has canonical non-empty Kind/DisplayName；a tombstone encodes both as `NULL` and requires the empty fingerprint digest. It deliberately excludes freshness/order/version proof, Observation/Run identity, fence, checkpoint coordinate, full persisted provenance and Catalog acceptance time, so unchanged Provider content remains comparable across Runs while every asset projection/conflict input remains bound. `observation_chain_sha256` is exactly `SHA256(FramedTupleV1("asset-observation-chain.v1",tenant_id,workspace_id,environment_id,source_id,run_id,observation_id,provider_kind,external_id,source_revision,canonical_revision_digest,observed_at,freshness_kind,freshness_order_time-or-NULL,freshness_order_sequence,provider_version_sha256,accepted_checkpoint_version,run_fence_epoch,run_page_sequence,provider_fact_sha256,field_provenance_sha256,previous_observation_id-or-NULL,previous_chain_sha256-or-NULL))`. The two previous fields are either both `NULL` or both present.

Relations are independent top-level facts rather than fields nested in an asset Observation. For each relation, `relation_fact_sha256 = SHA256(FramedTupleV1("asset-relation-fact.v1",tenant_id,workspace_id,source_id,source_revision,canonical_revision_digest,source_environment_id,target_environment_id,from_external_id,to_external_id,relationship_type,provider_path_code,confidence))`；its replay/freshness tuple is `(freshness order,provider_version_sha256,relation_fact_sha256)`. A page sorts relations by `(source_environment_id,target_environment_id,from_external_id,to_external_id,relationship_type,provider_path_code)` and computes `relation_page_sha256 = SHA256(FramedTupleV1("asset-relation-page.v1",relation_count,repeated source_environment_id,target_environment_id,from_external_id,to_external_id,relationship_type,provider_path_code,freshness_kind,freshness_order_time-or-NULL,freshness_order_sequence,provider_version_sha256,relation_fact_sha256))`. The empty page is the digest of that domain plus count `0`. This permits Providers to emit bounded asset pages first and relation-only pages later without duplicating an asset Observation while still binding exact freshness/replay coordinates. The mutable Relationship projection stores `accepted_checkpoint_version`、`run_fence_epoch` and its last exact Run/page/freshness/fact coordinates；insert/update admission revalidates the live exact lease/fence、published Source definition/gate/checkpoint and next relation-page coordinates. A distinct immutable `ASSET_SOURCE_RUN/RELATION_PAGE_COMMITTED` receipt preserves every accepted relation page with `request_id="source-relation-page:<run_uuid>:<page_sequence>"`、`payload_hash=relation_page_sha256`；a `DEFERRABLE INITIALLY DEFERRED` closure requires Relationship、Run relation-page summary、Source checkpoint 和该 receipt 在同一事务原子一致，不能用资产页 `PAGE_APPLIED` receipt 代替。任何声明 `complete_snapshot=true`（以及由它推导的 `effective_complete_snapshot=true`）的 final asset page，必须在同一事务把 relation-page sequence 精确推进一次、封存一个新的 relation-page digest，并写入上述 exact receipt；即使关系集合为空，也必须封存 canonical empty relation page，不能以“没有关系”为由省略闭合证明。Go is the sole constructor of canonical document/provenance/fingerprint/provider-fact/relation-fact/chain bytes；PostgreSQL recomputes SHA-256 for stored canonical document/provenance bytes, validates all digest shapes and exact coordinates, and admission compares the supplied domain digests—it must not implement a second JSON canonicalizer or a different tuple encoder.

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

`asset_source_revisions` 的 canonical content 在创建后不可修改；状态只能 `DRAFT|REJECTED→VALIDATING→VALIDATED|REJECTED`、`VALIDATED→PUBLISHED`、`PUBLISHED→SUPERSEDED`。进入 `VALIDATING` 必须将 `validation_run_id` 替换为新的 exact append-only `QUEUED` Validation Run 并清空 digest；返回 `VALIDATED|REJECTED` 只能消费该同一 Run 的 terminal proof，不得依赖时间比较或复用旧成功 Run。Validation `SUCCEEDED` 原子写 `VALIDATED` 与 exact proof；Validation `FAILED|CANCELLED`（包括漂移、reaper、cleanup uncertainty）必须在终态事务中把仍绑定该 `validation_run_id` 的 `VALIDATING` revision 写为 `REJECTED`，保存稳定 failure code/proof digest，使其可重新进入 Validation，而不是遗留永久 `VALIDATING`。`REJECTED` 不能直接发布。Revision insert 必须在锁定 stable Source 后满足 `revision=max+1` 与 `expected_source_version=current source.version`，并原子推进 Source version。每个 source 最多一个 `PUBLISHED`，发布任何新 canonical 修订必须在同一事务更新 stable source pointer、supersede 旧修订、按前述 Profile 规则初始化新 revision checkpoint 并关闭 gate。

`asset_sources.gate_status='AVAILABLE'` is legal only when `status='ACTIVE'`, the exact published revision has traversed `QUEUED→RUNNING→FINALIZING→SUCCEEDED` (the synchronous MANUAL path may do all transitions in one transaction), `validation_digest` is lowercase SHA-256, and `validated_binding_digest = canonical_revision_digest = published_revision_digest`. The canonical digest covers the definition plus every immutable Integration/sync/Credential/Trust/Network/authority/rate/backpressure/profile/schedule binding; `source_definition_digest` cannot satisfy this comparison. Gate epoch arithmetic is closed and exact. With starting epoch `G`, the first-publication path keeps the Source `UNAVAILABLE/G` while its exact Validation Run carries `gate_revision=G`, publication closes to `UNAVAILABLE/G+1`, and the separately admitted open reaches `AVAILABLE/G+2`. If the product exposes validation progress, only `UNAVAILABLE/G→VALIDATING/G+1` may bind that exact newly queued Run；the binding is immutable, publication closes to `UNAVAILABLE/G+2`, and the separately admitted open reaches `AVAILABLE/G+3`. An already `AVAILABLE` Source may retain the gate only when status, reason, epoch and all validation bindings are unchanged. Checkpoint-lineage rollover is the sole runtime exception：the admitted data Run keeps epoch `G`, begin-rollover closes to `DEGRADED/G+1`, and the same Run's serializable terminal closure reaches exactly `AVAILABLE/G+2` for an effective complete success or `SUSPENDED/G+2` for failure/uncertainty. Any publication/reference drift atomically sets the gate back to `UNAVAILABLE`; ordinary discovery success cannot open it, an unexplained epoch-only increment is rejected, and no path may compress or skip these epochs. `MANUAL` is served by the governed Asset API；`KUBERNETES_OPERATOR` remains `UNAVAILABLE` until Phase 3 publishes its provider contract，`AWX_INVENTORY` remains `UNAVAILABLE` until Phase 5 publishes its fixed AWX contract.

Every textual identity has non-empty, trimmed canonical-character and octet-length constraints: ProviderKind matches `^[A-Z][A-Z0-9_]{0,63}$`, external ID ≤512, display/name ≤256, owner/actor/reason/revision/schema/idempotency/trace within their domain maxima. Reject NUL/CR/LF. `assets_kind_check` is a named closed constraint containing exactly the 17 Phase 1 Kind values. Count checks are non-negative. Run shape is exact:

- `QUEUED/WAITING` has no start/heartbeat/lease/progress/work result/completion and cleanup `NOT_OPENED`；`DELAYED/DELAYED` may preserve committed page/checkpoint/count progress and the latest released-attempt cleanup proof, but has bounded `not_before`、no active lease and no final work result/completion.
- `RUNNING` has start/heartbeat/current owner+token-hash+epoch+expiry and stage `VALIDATING|READING|NORMALIZING|APPLYING|CLEANING_UP`. Before credential use it is `NOT_OPENED`；after `ReserveCleanupAttempt` it stores a broker-owned opaque UUID plus the originating fence epoch and becomes `PENDING`. Before entering `CLEANING_UP`, a nonterminal retry must persist the closed next intent `DELAY` plus exact delay reason/bounded `not_before`；`CLEANING_UP` is cleanup-only and cannot open Provider runtime/checkpoint or apply a page.
- `FINALIZING/CLEANING_UP` has a live/expired cleanup-only lease and exactly one immutable persisted work result：a data `DATA_PROJECTION` proposed `SUCCEEDED|PARTIAL`, a `VALIDATION_PROOF` proposed `SUCCEEDED|FAILED`, or a no-projection `FAILURE_INTENT` proposed `FAILED`. It has `work_result_digest/work_result_recorded_at` but no completion. A Validation proof binds exact Source revision、canonical/binding digests、closed outcome/code and proof digest；it never pretends to have an asset projection. Cleanup cannot replace this result.
- `CANCELLED/COMPLETED` has no active/open credential and no **final** work result. A Run cancelled directly from `QUEUED` or from a pre-claim zero-progress `DELAYED` state has zero progress plus `NOT_OPENED`；one cancelled from `DELAYED` after a released attempt may retain only its previously committed intermediate page/checkpoint/count progress and `REVOKED|NO_CREDENTIAL` attempt receipt. Neither form performs membership closure or advances a success pointer. `SUCCEEDED|PARTIAL/COMPLETED` requires matching `DATA_PROJECTION` or successful `VALIDATION_PROOF` plus `REVOKED|NO_CREDENTIAL` and no failure override. Ordinary `FAILED/COMPLETED` requires a rejected Validation proof or failure intent plus terminal cleanup. If cleanup becomes `UNCERTAIN` after any work result was already persisted, `Fail` preserves that result and atomically adds the sole override `CLEANUP_UNCERTAIN` with `terminal_failure_override_digest = SHA256(FramedTupleV1("asset-run-terminal-failure-override.v1",run_id,work_result_kind-or-NULL,work_result_digest-or-NULL,cleanup_status,cleanup_digest,failure_code))`；this is the only legal result/status override, forces `FAILED + SUSPENDED`, rejects a bound Validation revision and advances no success pointer. Validation never becomes `PARTIAL`. Every non-cancelled terminal row persists exact `terminal_command_sha256` and has exact `completed_at`；the terminal Run mutation、exact `TERMINAL_COMMITTED` receipt and every required Source/Revision closure must be one serializable transaction，cleanup `UNCERTAIN` additionally requires Source `SUSPENDED` in that transaction.

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

Create the claim index `(not_before,created_at,id) WHERE status IN ('QUEUED','DELAYED')`, the expired execution reclaim index `(lease_expires_at,id) WHERE status='RUNNING'`, the cleanup-only reclaim index `(lease_expires_at,id) WHERE status='FINALIZING'`, and a partial unique index allowing at most one nonterminal Run per Source. A Validation Run is bound to its draft/validating revision but carries checkpoint version/hash zero and never compares、opens or advances the current published Source checkpoint. A Discovery/Import/Ingestion Run starts from the Source's exact current checkpoint version/hash；a synchronous `MANUAL_MUTATION` is privately fenced and completed inside the governed Asset API transaction and never enters the Discovery Worker. Claim/normal reclaim requires exact current Source/gate/revision/checkpoint/backpressure eligibility, except for the explicitly bound Validation and checkpoint-lineage-rollover cases above, changes owner/token, advances `fence_epoch` exactly once and establishes a new heartbeat. Every ordinary heartbeat repeats the same run-kind-specific check.

`DELAYED` is the only nonterminal no-lease recovery state：it preserves prior page/checkpoint/count progress and the immutable cleanup receipt for the released attempt, requires bounded `not_before`, has no owner/expiry/raw-token access, and may return to `RUNNING` only through a fresh eligible claim/fence. A successful final data page changes `RUNNING→FINALIZING` atomically, persists `DATA_PROJECTION` with proposed `SUCCEEDED|PARTIAL`, final/effective-complete-snapshot flags, digest and `work_result_recorded_at`. A fenced `Queue.ProposeValidationResult` performs the corresponding transition for a Validation Run and persists exact `VALIDATION_PROOF` with proposed `SUCCEEDED|FAILED`. Every other fatal execution path must call fenced `Queue.PrepareFailureIntent` before cleanup；it persists one stable `FAILURE_INTENT` and changes `RUNNING→FINALIZING`, while a drift reaper uses that same internal transition. It cannot replace an existing data/validation result. Every form is cleanup-only and cannot call Provider, decrypt checkpoint or apply another page. `Queue.Complete` consumes an exact cleanup proof (`REVOKED|NO_CREDENTIAL`) and matching successful work-result digest；`Fail` consumes a rejected Validation proof or failure intent, or applies the sole `CLEANUP_UNCERTAIN` override without replacing an existing result. For Validation，terminal Run and exact bound Revision `VALIDATED|REJECTED` close in one serializable transaction；for a data Run，terminal Run and exact Source success/complete pointer、rollover gate or `SUSPENDED` gate close in one serializable transaction. An expired `FINALIZING` Run can only be reclaimed as cleanup-only work；cleanup uncertainty reaches stable `FAILED + SUSPENDED`, never a second work result. `MANUAL` Validation and `MANUAL_MUTATION` supply the deterministic `NO_CREDENTIAL` proof and perform their receipt/work-result/finalization/terminal/Source-or-Revision closure in one serializable API transaction.

Before any credential/session can open, the Worker calls fenced `ReserveCleanupAttempt`, which persists a random broker-owned opaque `cleanup_attempt_id` and its originating fence epoch. Reserve is exact-idempotent for `(run_id,fence_epoch)`：response-loss retry returns the same UUID and can never allocate/overwrite a second attempt. The external Cleanup Broker owns every revoke/session handle；`OpenAttempt(attempt_id)` is idempotent and may create at most one logical session for that ID，while `RevokeAttempt(attempt_id)` is idempotent and returns the same signed safe proof. The database never stores the handle or any credential. If an Open response is lost/ambiguous, the Worker must not retry Provider work or reserve another attempt；it immediately persists `TRANSPORT_BACKOFF`, calls `RevokeAttempt` for the known ID, records cleanup and delays. Before retry cleanup, Queue persists `pending_transition='DELAY'` plus reason/`not_before` and exact `pending_transition_digest = SHA256(FramedTupleV1("asset-run-delay-intent.v1",run_id,cleanup_attempt_id-or-NULL,cleanup_attempt_epoch,delay_reason,not_before))`. `RecordCleanup` verifies the proof and appends immutable `ASSET_SOURCE_RUN/ATTEMPT_CLEANED` audit receipt `request_id="source-attempt:<run_uuid>:<attempt_epoch>"` with `payload_hash` equal to the signed proof digest before updating the current summary. The `NO_CREDENTIAL` specialization is accepted only for exact `MANUAL/MANUAL_V1` Revision with all three external references `NULL`，uses attempt epoch `0` and the deterministic digest defined above, and must have that same exact receipt；an arbitrary caller SHA is never cleanup proof. If an expired `RUNNING` attempt had `PENDING` cleanup, reclaim moves its stage to cleanup-only `CLEANING_UP`, persists/uses a bounded `TRANSPORT_BACKOFF` delay intent, revokes that attempt and may only execute that `Delay` for a fresh claim or fail；it cannot continue Provider work under a replacement fence. If cleanup is already `REVOKED|NO_CREDENTIAL`, reclaim must verify the exact attempt receipt and the intent digest bound to that attempt epoch, then execute it；missing/mismatched intent is corruption and suspends the gate. `ReclaimFinalizing` likewise uses only the opaque attempt ID and Broker proof—never Provider runtime or checkpoint；when cleanup already has a valid receipt, it consumes the persisted work result/failure intent through `Complete|Fail`. A fresh claim atomically clears the consumed pending intent and may reset the current cleanup summary to `NOT_OPENED` only after verifying the prior append-only receipt, so history is never overwritten. A missing/invalid/uncertain Broker proof deterministically fails the Run and suspends the Source gate.

`CancelIneligible` locks the Source and atomically transitions its `QUEUED|DELAYED` Runs to `CANCELLED` when disable/publication/gate/revision/checkpoint drift makes them unclaimable; because those states have no open credential, no cleanup is skipped and the unique nonterminal slot is released. If the Run is the exact Validation bound by a `VALIDATING` Revision, that same transaction writes the Revision `REJECTED` with stable cancellation proof/code. If an expired `RUNNING` Run drifted, a bounded reaper takes the next fence without Provider/checkpoint access: it may fail directly only when cleanup is `NOT_OPENED|NO_CREDENTIAL`; otherwise it enters cleanup-only work and must revoke/close before `Fail` (or persist `UNCERTAIN` and suspend the gate). Before expiry, the current fence may perform cleanup/fail but cannot extend after drift. Terminal rows preserve owner/token-hash/epoch/heartbeat evidence while raw token is destroyed and capacity released. `last_success_at` equals `completed_at` only for the latest terminal `SUCCEEDED` non-VALIDATION data Run, including final delta/API/MANUAL runs；`PARTIAL` does not advance it. `last_complete_snapshot_at` equals `completed_at` only when that `SUCCEEDED` Run persisted effective `complete_snapshot=true`，and `MANUAL_MUTATION` is categorically ineligible. Neither accepts caller time. No terminal Run may commit alone：its `TERMINAL_COMMITTED` receipt and required Source/Revision updates are deferred-validated as one serializable closure；cleanup `UNCERTAIN` without exact Source `SUSPENDED` rolls back the whole transaction. QUEUED rows cannot receive counts/proof/pages, DELAYED rows preserve only committed progress, FINALIZING rows accept only cleanup/terminal facts, terminal rows are immutable, and every successful page/checkpoint advance increases both Run page/checkpoint and Source checkpoint version exactly once. Add row-level `BEFORE DELETE` and statement-level `BEFORE TRUNCATE` rejection to all nine tables; lifecycle/status transitions are the only removal path.

- [x] **Step 4: Implement guarded down and online-compatibility checks**

Down begins a transaction, locks all nine tables child-first, and raises SQLSTATE `55000` with exact message `unsafe asset catalog rollback: catalog state remains` if any row exists. Only empty tables may drop `asset_management_idempotency_audit_uk`, then the nine tables child-first and their triggers/functions.

Add a production `schema_admission.go` probe consumed later by Control Plane assembly. Its constructor requires the explicit trusted schema name (`public` in production); it never uses `current_schema`, `search_path` object resolution or a caller-selected schema. Every owned runtime function fixes `search_path=pg_catalog, public` in `proconfig`，不得继承迁移会话、把 `public` 放在 `pg_catalog` 前或包含 `pg_temp`；hostile 同名 function/operator 不能改变门禁求值。The code contains one reviewed hard-coded PostgreSQL-18.4 manifest SHA-256 generated from the migration at build/review time, never derived from the live database or migration file at runtime. The structured manifest covers all nine relations (column order/name/type/typmod/null/default/identity/generated、persistence、RLS), every named/unnamed constraint and exact normalized definition, every required explicit/implicit index and predicate, every trigger event/level/function/deferrability with `tgenabled='O'`, every owned function's exact signature/body/language/volatility/strict/security/search_path, plus the exact affected `audit_records/outbox_events` index/trigger/comment surface. Catalog rows are length-prefixed and sorted before SHA-256; admission succeeds only on exact equality.

Real negative tests create a shadow schema first in `search_path`, replace one guard function with a no-op, weaken one CHECK/FK, drop/alter one index, set a trigger replica-only/disabled, alter a column/default and change the checkpoint comment; each must return stable `asset_catalog_unavailable`. Test that a binary aware only of 000014 continues health/session reads while 000015 exists, while the new production probe remains closed until the full exact manifest is present; Pack 03 maps that sentinel to HTTP 503. The up migration must not rewrite existing large tables or add a defaulted column to them.

- [x] **Step 5: Add real PostgreSQL scope, immutability, concurrency, and recovery tests**

The integration harness connects through a separately named safe test control database, asserts PostgreSQL 18.4, creates a randomized physical database named `aiops_assets_test_<hex>` (never merely a schema), reconnects and applies 000001–000015 to `public`, then force-drops that database in cleanup. It rejects non-test control database names and missing CREATE DATABASE authority rather than mutating the supplied database. It seeds two tenants/workspaces/environments, then proves:

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
- a source gate cannot become `AVAILABLE` without a matching successful validation run and becomes `UNAVAILABLE` on any Credential/Trust/Network/authority/rate/backpressure/profile/schedule drift;
- two concurrent lifecycle writes cannot both commit.

TRUNCATE negative assertions check SQLSTATE `55000` **and** the exact target table guard constraint/trigger name, so `CASCADE` cannot accidentally pass because a child table blocked first. The full migration runner applies 000015 up before including 000015 down in reverse-order tests; it never excludes this migration merely to make legacy integration green.

Core assertion:

~~~go
expectSQLState(t, database, "55000",
	`UPDATE asset_observations SET source_revision=source_revision+1`)
expectSQLState(t, database, "23514", `
	UPDATE assets SET lifecycle='STALE', version=version+1
	WHERE id=$1 AND lifecycle='DISCOVERED'`, assetID)
~~~

Recovery test uses `recovery_container_test.go` to start two distinct PostgreSQL 18.4 instances from the same approved digest-pinned image as CI, verifies different `system_identifier` values and enabled data checksums, then streams a sanitized custom-format `pg_dump` archive into `pg_restore --single-transaction` on the clean target. It inserts representative rows in all nine tables plus their scoped Audit/Outbox links, reapplies checksum verification, and asserts counts, every exact FK closure (including conflict Source、Type Detail identity、relationship/binding provenance、Service eligibility), last-success/complete-snapshot exact Run links, freshness/chain SHA equality, source-revision publication pointers, lifecycle/version, Audit/Outbox linkage, immutable/delete triggers and the production schema-admission fingerprint. Docker context is explicitly configurable or deterministically discovers one safe local Unix context; it rejects ambiguous/remote contexts and must not hard-code a developer-specific context, container, DSN host, user or database. During the required zero-Skip invocation, any missing Docker/image/context prerequisite fails rather than skips. It must use sanitized fixtures, never production data.

Run:

~~~bash
go test ./internal/assetcatalog/postgres -count=1
test -n "$AIOPS_TEST_POSTGRES_DSN"
AIOPS_TEST_POSTGRES_DSN="$AIOPS_TEST_POSTGRES_DSN" \
  go test -race ./internal/assetcatalog/postgres -run 'TestAssetCatalog(Migration|Recovery)' -count=1
~~~

Expected: unit and PostgreSQL 18.4+ migration/recovery assertions all PASS with zero required-test skips. A missing `AIOPS_TEST_POSTGRES_DSN` is an unmet task prerequisite: the `test -n` command fails, this checkbox remains incomplete, and the task may not be committed. A diagnostic local invocation may report Skip, but Skip is never completion evidence.

- [x] **Step 6: Wire and verify the integration target**

Append `./internal/assetcatalog/postgres` to `make test-integration`. Legacy package fixtures must stop at their explicit owned migration cutoff；the full migration runner and Asset Catalog harness execute `000015` only inside a 128-bit randomized physical database created from the project-specific `aiops_test` control-database naming family, and may destructively clean up only a database whose creation they confirmed. Package serialization、`IF NOT EXISTS` and a shared destructive `public` schema are not substitutes for isolation.

Run:

~~~bash
gofmt -w internal/assetcatalog/postgres/*.go
go test ./internal/assetcatalog/postgres -count=1
test -n "$AIOPS_TEST_POSTGRES_DSN"
make test-integration
~~~

Expected: PASS with zero required-test skips；the integration target keeps cross-package parallelism so schema/physical-database isolation remains exercised.

- [x] **Step 7: Commit**

~~~bash
git add migrations/000015_assets_catalog.up.sql migrations/000015_assets_catalog.down.sql \
  internal/assetcatalog/postgres internal/store/postgres/migrations_integration_test.go \
  internal/investigation/postgres/testpostgres_test.go \
  internal/investigation/postgres/correlation_create_integration_test.go \
  internal/investigation/postgres/latest_runtime_fixture_integration_test.go \
  Makefile docs/superpowers docs/status/current.md
git commit -m "fix(assetcatalog): close production asset schema invariants"
~~~

### Task 2: Stable domain, validation, lifecycle, and downstream contracts

**Files:**
- Create: **internal/assetcatalog/types.go**
- Create: **internal/assetcatalog/validation.go**
- Create: **internal/assetcatalog/lifecycle.go**
- Create: **internal/assetcatalog/repository.go**
- Create: **internal/assetcatalog/lease_fence.go**
- Create: **internal/assetcatalog/types_test.go**
- Create: **internal/assetcatalog/lifecycle_test.go**
- Create: **internal/assetcatalog/lease_fence_test.go**

**Interfaces:**
- Produces the locked downstream contract:

~~~go
type Scope struct {
	TenantID      string
	WorkspaceID   string
	EnvironmentID string
}
type AssetLocator struct {
	Scope   Scope
	AssetID string
}
type Reader interface {
	Get(context.Context, AssetLocator) (Asset, error)
}
~~~

- `assets` keeps `UNIQUE (tenant_id,workspace_id,environment_id,id)` so 000016 may create a composite FK.
- Domain consumes existing `domain.MappingStatus`; it does not duplicate that enum.

- [ ] **Step 1: Write failing lifecycle, validation, and operability tests**

~~~go
func TestLifecycleAllowsOnlyReviewedTransitions(t *testing.T) {
	allowed := map[Lifecycle][]Lifecycle{
		LifecycleDiscovered:  {LifecycleActive, LifecycleQuarantined, LifecycleRetired},
		LifecycleActive:      {LifecycleStale, LifecycleQuarantined, LifecycleRetired},
		LifecycleStale:       {LifecycleActive, LifecycleQuarantined, LifecycleRetired},
		LifecycleQuarantined: {LifecycleActive, LifecycleRetired},
		LifecycleRetired:     {},
	}
	for from, destinations := range allowed {
		for _, to := range allLifecycles() {
			want := from == to || slices.Contains(destinations, to)
			if CanTransition(from, to) != want {
				t.Errorf("CanTransition(%s,%s) mismatch", from, to)
			}
		}
	}
}

func TestLiveCapabilityRequiresEveryOrthogonalGate(t *testing.T) {
	asset := validAsset()
	asset.Lifecycle = LifecycleActive
	asset.MappingStatus = domain.MappingExact
	if !asset.LiveCapabilityEligible(true, true) {
		t.Fatal("fully gated asset is ineligible")
	}
	if asset.LiveCapabilityEligible(false, true) || asset.LiveCapabilityEligible(true, false) {
		t.Fatal("publication/capability gate was bypassed")
	}
}

func TestSourceAvailabilityRequiresCurrentValidatedBinding(t *testing.T) {
	source := validSource()
	revision := validSourceRevision()
	source.Status = SourceStatusActive
	source.GateStatus = SourceGateAvailable
	source.GateRevision = 7
	source.PublishedRevision = revision.Revision
	source.PublishedRevisionDigest = revision.CanonicalRevisionDigest
	source.ValidatedBindingDigest = revision.BindingDigest()
	if !source.Available(revision) {
		t.Fatal("current validated source must be available")
	}
	revision.CredentialReferenceID = "cred-ref-rotated"
	if source.Available(revision) {
		t.Fatal("credential-reference drift bypassed source gate")
	}
}
~~~

Run: `go test ./internal/assetcatalog -count=1`

Expected: FAIL because domain types/functions do not exist.

- [ ] **Step 2: Define exact enum/value model**

`Kind` constants are exactly: SERVICE、LINUX_VM、WINDOWS_VM、BARE_METAL_HOST、KUBERNETES_CLUSTER、KUBERNETES_NAMESPACE、KUBERNETES_WORKLOAD、DATABASE_INSTANCE、DATABASE、METRICS_SOURCE、LOG_SOURCE、TRACE_SOURCE、AWX_INVENTORY、ARGO_APPLICATION、CI_PIPELINE、GIT_REPOSITORY、CLOUD_RESOURCE.

`SourceKind`、`Lifecycle`、`Criticality`、`DataClassification`、`RelationshipType`、`RelationshipStatus`、`BindingRole`、`BindingStatus`、`Provenance` and `ConflictResolution` exactly match Task 1 vocabularies.

~~~go
type Asset struct {
	ID                 string
	Scope              Scope
	SourceID           string
	Kind               Kind
	ProviderKind       string
	ExternalID         string
	DisplayName        string
	Lifecycle          Lifecycle
	MappingStatus      domain.MappingStatus
	OwnerGroup         string
	Criticality        Criticality
	DataClassification DataClassification
	Labels             map[string]string
	LastObservationID  string
	LastObservationChainSHA256 string
	LastObservedAt     time.Time
	LastSourceRevision int64
	Version            int64
	CreatedAt          time.Time
	UpdatedAt          time.Time
}

type Relationship struct {
	ID                              string
	TenantID                        string
	WorkspaceID                     string
	SourceEnvironmentID             string
	TargetEnvironmentID             string
	SourceAssetID                    string
	TargetAssetID                    string
	Type                            RelationshipType
	Provenance                      Provenance
	ProvenanceSourceID              string
	CrossEnvironmentPolicyReferenceID string
	Status                          RelationshipStatus
	Version                         int64
	CreatedAt                       time.Time
	UpdatedAt                       time.Time
}

func (asset Asset) Clone() Asset {
	asset.Labels = maps.Clone(asset.Labels)
	return asset
}

func (asset Asset) LiveCapabilityEligible(published, available bool) bool {
	return asset.Validate() == nil && asset.Lifecycle == LifecycleActive &&
		asset.MappingStatus == domain.MappingExact && published && available
}
~~~

Also define Source、SourceRun、Observation、Relationship、Conflict、ServiceAssetBinding; page/cursor/filter types; create/update/transition/source/sync/mapping/binding commands. Every write command carries Scope, actor, trace, Idempotency-Key and canonical request hash; updates/transitions/delete/decisions also carry expected version for CAS.

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
	ID                        string
	TenantID                  string
	WorkspaceID               string
	Kind                      SourceKind
	ProviderKind              string
	Status                    SourceStatus
	PublishedRevision         int64
	PublishedRevisionDigest   string
	GateStatus                SourceGateStatus
	GateReasonCode            string
	GateRevision              int64
	ValidatedRunID            string
	ValidationDigest          string
	ValidatedBindingDigest    string
	CheckpointSHA256          string
	CheckpointVersion         int64
	CheckpointSourceRevision  int64
	LastSuccessRunID          string
	LastSuccessAt             *time.Time
	LastCompleteSnapshotRunID string
	LastCompleteSnapshotAt    *time.Time
	Version                   int64
}

type SourceRevision struct {
	SourceID                 string
	TenantID                 string
	WorkspaceID              string
	Revision                 int64
	Status                   SourceRevisionStatus
	SourceDefinitionDigest   string
	CanonicalRevisionDigest  string
	IntegrationID            string
	SyncMode                 SyncMode
	CredentialReferenceID    string
	TrustReferenceID         string
	NetworkPolicyReferenceID string
	AuthorityScopeDigest     string
	RateLimitRequests        int64
	RateLimitWindowSeconds   int64
	BackpressureBaseSeconds  int64
	BackpressureMaxSeconds   int64
	ProfileCode              string
	ScheduleExpression       string
	ValidationRunID          string
	ValidationDigest         string
}

func (revision SourceRevision) BindingDigest() string
func (source Source) Available(revision SourceRevision) bool
~~~

`BindingDigest` hashes canonical Tenant/Workspace, stable source identity, revision, definition digest, Integration/sync mode, opaque Credential/Trust/Network references, authority scope, all rate/backpressure/profile fields and schedule; it never hashes secret values or runtime endpoint text. Validation requires `revision.BindingDigest() == revision.CanonicalRevisionDigest`. `Available` requires `ACTIVE + AVAILABLE`, a positive gate revision, the exact `PUBLISHED` revision/digest, a successful validated run, non-empty validation digest and `source.ValidatedBindingDigest == revision.CanonicalRevisionDigest`. `SourceRun` adds exact Source definition revision/canonical digest, `RunKind`, stable `Stage`, gate revision, `PageSequence`, `PageDigest`, `NotBefore`, `LeaseExpiresAt`, `FenceEpoch`, `HeartbeatSequence`, checkpoint hashes, typed work-result summary and the exact persisted count set; public clones omit lease token hash, checkpoint ciphertext, cleanup attempt ID/digest and provider runtime material.

Later phases may add a typed Source profile only through the Phase 1 `TypedSourceExtensionRegistry`. The Source Revision Repository calls the registered extension's `ValidateAndDigestInTx(ctx,restrictedTx,draft)` inside its own serializable transaction；`restrictedTx` is a sealed repository-owned capability exposing only scoped `Exec/Query/QueryRow`, never commit/rollback/begin/copy/raw connection. The returned immutable `PreparedExtension` supplies `Digest()` before the base digest/row is sealed, then `CreateInTx(ctx,restrictedTx,baseRevision)` persists the exact 1:1 extension after the base insert and before the outer Repository alone commits. Failure or digest mismatch rolls back both rows. There is no later phase-owned Publish/status lifecycle、post-commit extension write or second transaction, and an adversarial architecture/integration test proves Phase 3/5 extensions cannot escape transaction ownership or mutate base/audit tables.

`LeaseFence` is a non-serializable process-local value with unexported shared state containing exact Run ID、owner、epoch and a 32-byte raw token. Its only two named production construction paths are PostgreSQL Queue claim/reclaim and PostgreSQL `ManualRunExecutor` (restricted to `MANUAL_V1` synchronous VALIDATION/MANUAL_MUTATION); there is no generic exported raw-token factory, and an architecture test rejects any other call site. Copies share the same state so terminal `Destroy` zeroes the token for every copy; `MarshalJSON`/`MarshalText` fail, `String`/`GoString` return only `[REDACTED_LEASE_FENCE]`, and no accessor returns the token or token hash. It exposes only a constant-time `Matches(runID,owner,epoch,persistedTokenSHA256)` predicate used after the PostgreSQL Repository has locked the Run. A zero/destroyed fence never matches. `Complete/Fail` commands separately carry safe Run ID、terminal status/intent/work-result digest、cleanup status/digest and optional terminal-failure-override digest. Repository computes `terminal_command_sha256 = SHA256(FramedTupleV1("asset-run-terminal.v1",run_id,terminal_status,work_result_kind,work_result_digest,cleanup_status,cleanup_digest,terminal_failure_override-or-NULL,terminal_failure_override_digest-or-NULL,failure_code-or-NULL))`. Their transaction first checks immutable `ASSET_SOURCE_RUN/TERMINAL_COMMITTED` audit receipt `request_id="source-terminal:<run_uuid>"` and exact `payload_hash=terminal_command_sha256`；a matching replay is read-only and returns before fence admission, while any changed tuple hits the same request ID with a different hash and is rejected. Only the first terminal mutation requires `Matches` and writes the receipt before commit/`Destroy`, so response-loss replay remains implementable without reviving a destroyed fence. This type is a misuse barrier, not an authorization source：every new open/use/Provider-call/heartbeat/page/terminal transaction revalidates persisted facts according to Run kind. Validation checks its exact revision/gate/lease plus its own empty checkpoint shape and never reads/compares the published Source checkpoint；data Runs additionally revalidate the exact Source checkpoint.

Asset list sorting is a closed enum, not arbitrary SQL:

~~~go
type AssetSort string

const (
	AssetSortDisplayNameAsc    AssetSort = "display_name_asc"
	AssetSortLastObservedDesc AssetSort = "last_observed_at_desc"
)

type AssetCursor struct {
	Sort    AssetSort
	Value   string
	AssetID string
}
~~~

`ListAssetsRequest` carries one of those sorts, limit 1–100, filters and optional matching cursor. A cursor whose sort differs from the request is invalid.

- [ ] **Step 3: Implement exhaustive bounded validation**

~~~go
var safeToken = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,255}$`)
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

Validation must use exhaustive switches (no default acceptance), enforce non-zero UTC microsecond time, versions >0, at most 64 labels/max 16 KiB UTF-8 serialization, trimmed strings, no NUL/CR/LF, and reject label keys containing normalized secret/token/password/credential/dsn/endpoint. New IDs use `internal/ids.NewUUID`; Clone all maps/slices at boundaries.

Stable errors: `ErrInvalidRequest`、`ErrNotFound`、`ErrScopeViolation`、`ErrVersionConflict`、`ErrStateConflict`、`ErrIdempotency`. They contain no database/provider text.

- [ ] **Step 4: Define repository groups without import cycles**

~~~go
type Repository interface {
	Reader
	ScopeResolver
	List(context.Context, ListAssetsRequest) (AssetPage, error)
	Create(context.Context, CreateAssetCommand) (AssetMutationResult, error)
	UpdateGovernance(context.Context, UpdateGovernanceCommand) (AssetMutationResult, error)
	Transition(context.Context, TransitionCommand) (AssetMutationResult, error)
}

type MutationReceipt struct {
	AuditID         string
	TraceID         string
	IdempotentReplay bool
}

type AssetMutationResult struct {
	Asset   Asset
	Receipt MutationReceipt
}

type BindingMutationResult struct {
	Binding ServiceAssetBinding
	Receipt MutationReceipt
}

type MappingRepository interface {
	ListRelationships(context.Context, ListRelationshipsRequest) (RelationshipPage, error)
	ListBindings(context.Context, ListBindingsRequest) (BindingPage, error)
	CreateBinding(context.Context, CreateBindingCommand) (BindingMutationResult, error)
	DeleteBinding(context.Context, DeleteBindingCommand) (MutationReceipt, error)
	ListConflicts(context.Context, ListConflictsRequest) (ConflictPage, error)
	ResolveConflict(context.Context, MappingDecision) (MappingDecisionResult, error)
}

type MappingDecisionResult struct {
	Conflict Conflict
	Binding  *ServiceAssetBinding
	Receipt  MutationReceipt
}
~~~

Source CRUD/sync/run interfaces remain in `assetcatalog`; reconciliation batch/store interface lives in `assetdiscovery`, whose dependency direction is `assetdiscovery -> assetcatalog`. `assetcatalog` must never import `assetdiscovery`.

- [ ] **Step 5: Run domain tests**

Run: `gofmt -w internal/assetcatalog/*.go && go test -race ./internal/assetcatalog -count=1`

Expected: PASS for every enum member, invalid unknowns, canonical IDs, label safety, clone isolation, lifecycle matrix, retired terminal state, all live-capability gates, non-serializable/redacted/destroy-all-copies fence behavior and rejection of zero/forged coordinate matches.

- [ ] **Step 6: Commit**

~~~bash
git add internal/assetcatalog/types.go internal/assetcatalog/validation.go \
  internal/assetcatalog/lifecycle.go internal/assetcatalog/repository.go \
  internal/assetcatalog/types_test.go internal/assetcatalog/lifecycle_test.go
git commit -m "feat(assetcatalog): define governed asset domain"
~~~
