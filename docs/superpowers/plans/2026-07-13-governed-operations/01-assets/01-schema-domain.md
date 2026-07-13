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
- Create: **internal/assetcatalog/postgres/migration_recovery_integration_test.go**
- Create: **internal/assetcatalog/postgres/recovery_container_test.go**
- Create: **internal/assetcatalog/postgres/schema_admission.go**
- Create: **internal/assetcatalog/postgres/schema_admission_test.go**
- Modify: **Makefile**

**Interfaces:**
- Consumes candidates from 000002: `workspaces(tenant_id,id)`、`environments(tenant_id,workspace_id,id)`、`integrations(tenant_id,workspace_id,id)`、`services(tenant_id,workspace_id,id)`。
- Produces `assets UNIQUE (tenant_id,workspace_id,environment_id,id)` for 000016 Connection.
- Produces Workspace/Environment-scoped candidate keys for the other eight tables.
- Does not change any 000001–000014 table definition.

- [ ] **Step 1: Write failing ownership and invariant shape tests**

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

- [ ] **Step 2: Implement the transactional up migration with this exact schema**

Start with `BEGIN; SET LOCAL lock_timeout='5s';` and lock `tenants, workspaces, environments, integrations, services, service_bindings, audit_records, outbox_events` in access-exclusive order so concurrent schema changes cannot interleave and the new binding-eligibility FK never relies on an implicit referenced-table DDL lock.

| Table | Required columns and exact purpose |
|---|---|
| `asset_sources` | 稳定 UUID 身份/Workspace Scope；`source_kind/provider_kind/name/status` 与 `published_revision/published_revision_digest`；正交 `gate_status/gate_reason_code/gate_revision/validated_run_id/validation_digest/validated_binding_digest`；加密当前 checkpoint (`checkpoint_ciphertext/checkpoint_key_id/checkpoint_sha256/checkpoint_version/checkpoint_revision`)；HA backpressure (`next_allowed_at/consecutive_failures`)；创建幂等/hash、version、last success、timestamps |
| `asset_source_revisions` | 复合 Scope + stable source + monotonically increasing revision；`DRAFT/VALIDATING/VALIDATED/REJECTED/PUBLISHED/SUPERSEDED`；content-addressed canonical provider schema；`integration_id/sync_mode/authority_scope_digest/source_definition_digest`；opaque `credential_reference_id/trust_reference_id/network_policy_reference_id`；固定 rate/backpressure/profile/schedule；完整 availability binding 的 `canonical_revision_digest`；validation run/digest；actor/reason/CAS/time；创建后 canonical content 不可变 |
| `asset_source_runs` | source scope + exact source revision/digest; `run_kind/status/trigger_type`; definition/gate revision; idempotency/hash; cursor before/after SHA; page sequence/digest; lease owner/expiry, monotonically increasing `fence_epoch`, token hash, heartbeat sequence and `not_before`; observed/created/changed/unchanged/conflict/missing/rejected counts; stable failure code/trace; start/heartbeat/complete |
| `asset_observations` | full scope/source/run; provider/external/source revision; observed/schema version; normalized document bytea + SHA; bounded field-provenance bytea + SHA; explicit tombstone flag/reason code; created time |
| `assets` | full scope/source; provider/external/kind/display; governance fields; lifecycle/mapping; last observation/time/source revision; create idempotency/hash; version/timestamps |
| `asset_type_details` | full scope/asset; append-only revision/schema; source observation; bytea details + SHA; actor/time |
| `asset_conflicts` | scope/existing asset/nullable candidate asset/nullable candidate service/source/observation; type/field; existing/candidate value SHA only; status/resolution/reason/actor/time; resolution idempotency/hash; version/timestamps |
| `asset_relationships` | workspace plus source/target environments/assets; type/provenance source; explicit cross-environment policy ref; status; idempotency/hash/version/timestamps |
| `service_asset_bindings` | full scope/service/asset; role/mapping/provenance/status; idempotency/hash/version/timestamps |

Exact state vocabularies:

~~~text
source_kind: MANUAL CSV_IMPORT CONTROL_PLANE_API EXTERNAL_CMDB VSPHERE
             PROXMOX OPENSTACK CLOUD_PROVIDER KUBERNETES_OPERATOR AWX_INVENTORY
sync_mode: MANUAL ON_DEMAND SCHEDULED
source status: ACTIVE PAUSED DEGRADED DISABLED
source gate: UNAVAILABLE VALIDATING AVAILABLE DEGRADED SUSPENDED
source revision: DRAFT VALIDATING VALIDATED REJECTED PUBLISHED SUPERSEDED
run kind: VALIDATION DISCOVERY CSV_IMPORT API_INGESTION
run status: QUEUED RUNNING SUCCEEDED PARTIAL FAILED CANCELLED
trigger_type: HUMAN API SCHEDULED
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
~~~

Use composite foreign keys for every parent. `service_asset_bindings` must additionally use `(service_id,environment_id) -> service_bindings(service_id,environment_id)` and Repository validation to prove the Service is bound to the selected Environment; separate Service/Environment Workspace FKs do not replace this eligibility edge. `assets.last_source_revision` references the exact Source Revision, and its current Observation FK includes Environment, Source, Provider and Source Revision so a projection cannot bind cross-Environment or drifted facts.

`asset_conflicts.asset_id` and `candidate_asset_id` reference `(tenant_id,workspace_id,environment_id,id)`; `candidate_service_id` references `(tenant_id,workspace_id,id)`. A shape check requires at least one candidate target or a field-level conflict hash, and an open-partial unique index prevents duplicate `(source_id,observation_id,conflict_type,field_name,candidate_asset_id,candidate_service_id)` queue items.

Use exact uniqueness:

~~~sql
UNIQUE (tenant_id, workspace_id, source_id, provider_kind, external_id);
UNIQUE (tenant_id, workspace_id, environment_id, id);
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
  octet_length(document_sha256) = 64
  AND document_sha256 COLLATE "C" !~ '[^a-f0-9]'
  AND encode(sha256(normalized_document), 'hex') = document_sha256
);
~~~

`field_provenance` is canonical JSON ≤32 KiB with unique keys and contains only allow-listed field codes, `source_id`, `provider_kind`, `source_revision`, observation time, confidence and ownership (`SOURCE|GOVERNANCE|MERGE_DECISION`); it cannot carry raw provider paths or values. `checkpoint_ciphertext` is the versioned AES-256-GCM envelope `0x01 || 12-byte non-zero nonce || ciphertext || 16-byte tag`; its AAD is `(tenant_id,workspace_id,source_id,provider_kind,source_definition_digest,checkpoint_version)` and `checkpoint_key_id` is an opaque key reference. The database validates envelope shape/hash while the Repository performs authenticated encryption/decryption and AAD verification. The database never stores a plaintext provider cursor, raw lease token, credential material, endpoint, CA PEM or source error body.

`asset_source_revisions` 的 canonical content 在创建后不可修改；状态只能 `DRAFT|REJECTED→VALIDATING→VALIDATED|REJECTED`、`VALIDATED→PUBLISHED`、`PUBLISHED→SUPERSEDED`。每次重试创建新的 append-only Validation Run；`REJECTED` 不能直接发布。Revision insert 必须在锁定 stable Source 后满足 `revision=max+1` 与 `expected_source_version=current source.version`，并原子推进 Source version。每个 source 最多一个 `PUBLISHED`，发布新修订必须在同一事务更新 stable source pointer、supersede 旧修订、清空不兼容 checkpoint 并关闭 gate。

`asset_sources.gate_status='AVAILABLE'` is legal only when `status='ACTIVE'`, the exact published revision has traversed `QUEUED→RUNNING→SUCCEEDED`, `validation_digest` is lowercase SHA-256, and `validated_binding_digest = canonical_revision_digest = published_revision_digest`. The canonical digest covers the definition plus every immutable Integration/sync/Credential/Trust/Network/authority/rate/backpressure/profile/schedule binding; `source_definition_digest` cannot satisfy this comparison. Any publication/reference drift atomically sets the gate back to `UNAVAILABLE`; ordinary discovery success cannot open it. `MANUAL` is served by the governed Asset API；`KUBERNETES_OPERATOR` remains `UNAVAILABLE` until Phase 3 publishes its provider contract，`AWX_INVENTORY` remains `UNAVAILABLE` until Phase 5 publishes its fixed AWX contract.

Every textual identity has non-empty, trimmed canonical-character and octet-length constraints: ProviderKind matches `^[A-Z][A-Z0-9_]{0,63}$`, external ID ≤512, display/name ≤256, owner/actor/reason/revision/schema/idempotency/trace within their domain maxima. Reject NUL/CR/LF. `assets_kind_check` is a named closed constraint containing exactly the 17 Phase 1 Kind values. Count checks are non-negative. Run shape requires queued=no times/results/lease, running=start+heartbeat/no complete, terminal=complete. Conflict shape requires OPEN=no decision and closed=complete decision.

- [ ] **Step 3: Add immutable and lifecycle database guards**

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

Create the HA claim index on queued runs `(not_before,created_at,id) WHERE status='QUEUED'`, the expired-lease reclaim index `(lease_expires_at,id) WHERE status='RUNNING'`, and a partial unique index allowing at most one live run per source. A Validation Run starts with checkpoint version zero; a Discovery/Import/Ingestion Run starts from the Source's exact current checkpoint version/hash. Claim or reclaim that changes lease owner/token must advance `fence_epoch` exactly once and establish a new heartbeat; ordinary heartbeat/lease extension must advance heartbeat sequence/time. QUEUED rows cannot receive counters, proof, pages or completion facts without Claim, terminal rows are immutable, and every successful page/checkpoint advance increases both Run page/checkpoint and Source checkpoint version exactly once. Add row-level `BEFORE DELETE` and statement-level `BEFORE TRUNCATE` rejection to all nine tables; lifecycle/status transitions are the only removal path.

- [ ] **Step 4: Implement guarded down and online-compatibility checks**

Down begins a transaction, locks all nine tables child-first, and raises SQLSTATE `55000` with exact message `unsafe asset catalog rollback: catalog state remains` if any row exists. Only empty tables may drop `asset_management_idempotency_audit_uk`, then the nine tables child-first and their triggers/functions.

Add a production `schema_admission.go` probe consumed later by Control Plane assembly. Test that a binary aware only of 000014 continues health/session reads while 000015 exists, while the new production probe returns stable `asset_catalog_unavailable` until all 000015 relations/constraints are visible; Pack 03 maps that sentinel to HTTP 503. The up migration must not rewrite existing large tables or add a defaulted column to them.

- [ ] **Step 5: Add real PostgreSQL scope, immutability, concurrency, and recovery tests**

The integration harness applies 000001–000015 in a temporary database, asserts server major 18, seeds two tenants/workspaces/environments, then proves:

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
- two consecutive discovery runs advance the same Source checkpoint without resetting the second Run to zero;
- non-monotonic Source Revision, stale Source CAS, direct terminal Run insert and revision/history DELETE are rejected;
- a source gate cannot become `AVAILABLE` without a matching successful validation run and becomes `UNAVAILABLE` on any Credential/Trust/Network/authority/rate/backpressure/profile/schedule drift;
- two concurrent lifecycle writes cannot both commit.

Core assertion:

~~~go
expectSQLState(t, database, "55000",
	`UPDATE asset_observations SET source_revision='tampered'`)
expectSQLState(t, database, "23514", `
	UPDATE assets SET lifecycle='STALE', version=version+1
	WHERE id=$1 AND lifecycle='DISCOVERED'`, assetID)
~~~

Recovery test uses `recovery_container_test.go` to start two distinct PostgreSQL 18.4 instances from the same approved digest-pinned image as CI, verifies different `system_identifier` values and enabled data checksums, then streams a sanitized custom-format `pg_dump` archive into `pg_restore --single-transaction` on the clean target. It inserts representative rows in all nine tables plus their scoped Audit/Outbox links, reapplies checksum verification, and asserts counts, complete FK closure, source-revision publication pointers, SHA equality, lifecycle/version, Audit/Outbox linkage and immutable/delete triggers. Docker context is explicitly configurable or deterministically discovers one safe local Unix context; it rejects ambiguous/remote contexts and must not hard-code a developer-specific context, container, DSN host, user or database. During the required zero-Skip invocation, any missing Docker/image/context prerequisite fails rather than skips. It must use sanitized fixtures, never production data.

Run:

~~~bash
go test ./internal/assetcatalog/postgres -count=1
test -n "$AIOPS_TEST_POSTGRES_DSN"
AIOPS_TEST_POSTGRES_DSN="$AIOPS_TEST_POSTGRES_DSN" \
  go test -race ./internal/assetcatalog/postgres -run 'TestAssetCatalog(Migration|Recovery)' -count=1
~~~

Expected: unit and PostgreSQL 18.4+ migration/recovery assertions all PASS with zero required-test skips. A missing `AIOPS_TEST_POSTGRES_DSN` is an unmet task prerequisite: the `test -n` command fails, this checkbox remains incomplete, and the task may not be committed. A diagnostic local invocation may report Skip, but Skip is never completion evidence.

- [ ] **Step 6: Wire and verify the integration target**

Append `./internal/assetcatalog/postgres` to `make test-integration`, then:

Run: `gofmt -w internal/assetcatalog/postgres/*.go && go test ./internal/assetcatalog/postgres -count=1`

Expected: PASS.

- [ ] **Step 7: Commit**

~~~bash
git add migrations/000015_assets_catalog.up.sql migrations/000015_assets_catalog.down.sql \
  internal/assetcatalog/postgres/migration_test.go \
  internal/assetcatalog/postgres/migration_integration_test.go \
  internal/assetcatalog/postgres/migration_recovery_integration_test.go \
  internal/assetcatalog/postgres/recovery_container_test.go \
  internal/assetcatalog/postgres/schema_admission.go \
  internal/assetcatalog/postgres/schema_admission_test.go Makefile
git commit -m "feat(assetcatalog): add production asset schema"
~~~

### Task 2: Stable domain, validation, lifecycle, and downstream contracts

**Files:**
- Create: **internal/assetcatalog/types.go**
- Create: **internal/assetcatalog/validation.go**
- Create: **internal/assetcatalog/lifecycle.go**
- Create: **internal/assetcatalog/repository.go**
- Create: **internal/assetcatalog/types_test.go**
- Create: **internal/assetcatalog/lifecycle_test.go**

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

`BindingDigest` hashes canonical Tenant/Workspace, stable source identity, revision, definition digest, Integration/sync mode, opaque Credential/Trust/Network references, authority scope, all rate/backpressure/profile fields and schedule; it never hashes secret values or runtime endpoint text. Validation requires `revision.BindingDigest() == revision.CanonicalRevisionDigest`. `Available` requires `ACTIVE + AVAILABLE`, a positive gate revision, the exact `PUBLISHED` revision/digest, a successful validated run, non-empty validation digest and `source.ValidatedBindingDigest == revision.CanonicalRevisionDigest`. `SourceRun` adds exact source revision/digest, `RunKind`, definition/gate revision, `PageSequence`, `PageDigest`, `NotBefore`, `LeaseExpiresAt`, `FenceEpoch`, `HeartbeatSequence`, checkpoint hashes and counts; public clones omit lease token hash, checkpoint ciphertext and provider runtime material.

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

Expected: PASS for every enum member, invalid unknowns, canonical IDs, label safety, clone isolation, lifecycle matrix, retired terminal state, and all live-capability gates.

- [ ] **Step 6: Commit**

~~~bash
git add internal/assetcatalog/types.go internal/assetcatalog/validation.go \
  internal/assetcatalog/lifecycle.go internal/assetcatalog/repository.go \
  internal/assetcatalog/types_test.go internal/assetcatalog/lifecycle_test.go
git commit -m "feat(assetcatalog): define governed asset domain"
~~~
