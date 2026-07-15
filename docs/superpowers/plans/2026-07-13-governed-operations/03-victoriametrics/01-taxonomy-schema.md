# VictoriaMetrics Taxonomy and Schema Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 建立 VictoriaMetrics 生态的完整资产分类、`000017` 持久契约、版本兼容 profile 和服务端租户路由，使后续发现与只读能力只能在精确闭包内工作。

**Architecture:** 扩展统一 Asset Kind 与 Connection Provider，不建立第二套资产或 Source lifecycle；新增 Phase 1 Operator Source Revision 的不可变 typed extension、Compatibility profile 和 Connection contract revision。查询租户值只存在于私有 contract，公共 projection 只返回 mode/digest；兼容矩阵以精确测试版本起步，未知版本 fail closed。

**Tech Stack:** Go 1.26.5、PostgreSQL 18.4+、pgx v5、RFC 8785 JCS、SHA-256、标准库 `testing`。

## Global Constraints

- 每个 Task 严格采用 Red → Green → Refactor：先运行并保存预期失败，再做最小生产实现，复跑指定测试后才允许重构和提交。
- migration 固定为 `000017_victoriametrics_ecosystem`，并显式要求 `000015` 与 `000016` 已存在。
- `000017` 是 `public.asset_catalog_future_source_gate_admitted(candidate public.asset_sources) RETURNS boolean` 的 Phase 3 successor owner；只能 `CREATE OR REPLACE` 该已验收签名，不得 overload、改名或绕过 `000015` 的 `enforce_asset_sources_mutation`。
- 复用 `assets`、`asset_relationships`、`connection_profiles`、`connection_revisions`、`capability_definitions` 与 runtime publication 表；禁止复制 observation、target 或 capability 状态。
- 所有新表的主外键都包含 Tenant/Workspace/Environment Scope；Operator source 也必须绑定 Environment。
- 长期组件、配置 CRD、工具制品是互斥 taxonomy class；配置与工具不得成为 Query Target。
- `AccountID`、`ProjectID` 是私有、服务端拥有的 contract 字段；不得出现在公共 DTO、日志、metric label、审计 payload 或 evidence。
- Profile 发布后、Connection contract 发布后不可原地更新或删除；变更只能创建新 revision。
- 初始支持矩阵只认 Operator `0.73.1`、VictoriaMetrics `1.147.0`、VictoriaLogs `1.51.0`、VictoriaTraces `0.9.4`。
- unknown/custom image version 可以成为资产，但不得获得已发布能力。
- 新增行为严格 TDD；每个 Task 都先看到预期失败，再做最小实现并独立提交。

---

## Prerequisite Interfaces

Consumes from Phase 1:

```go
type Scope struct {
    TenantID      string
    WorkspaceID   string
    EnvironmentID string
}

type Kind string

type Asset struct {
    ID            string
    Scope         Scope
    Kind          Kind
    Lifecycle     string
    MappingStatus string
    Version       int64
}
```

Consumes from Phase 2:

```go
type ProviderKind string

type CompileInput struct {
    Scope                  assetcatalog.Scope
    Asset                  assetcatalog.Asset
    Revision               connectionprofile.Revision
    ValidationResultDigest string
    CredentialCleanup      connectionprofile.CredentialCleanup
    ConnectorManifest      readconnector.Manifest
    EgressManifest         readexecutor.EgressManifest
    ExecutorProfile        readexecutor.Profile
}
```

### Task 1: Add the `000017` scoped database contract

**Files:**
- Create: `migrations/000017_victoriametrics_ecosystem.up.sql`
- Create: `migrations/000017_victoriametrics_ecosystem.down.sql`
- Modify: `internal/store/postgres/migrations_integration_test.go`
- Modify: `internal/assetcatalog/postgres/schema_admission.go`
- Modify: `internal/assetcatalog/postgres/schema_admission_test.go`
- Modify: `internal/assetcatalog/postgres/schema_admission_integration_test.go`
- Modify: `internal/assetcatalog/postgres/migration_recovery_integration_test.go`
- Modify: `internal/assetcatalog/postgres/recovery_container_test.go`
- Modify: `internal/store/postgres/database_role_admission.go`
- Modify: `internal/store/postgres/database_role_admission_test.go`
- Modify: `docs/operations/database-role-bootstrap.md`
- Modify: `.github/workflows/ci.yml`
- Modify: `internal/assetcatalog/types.go`
- Modify: `internal/assetcatalog/types_test.go`
- Create: `internal/victoriametrics/source_profile.go`
- Create: `internal/victoriametrics/source_profile_test.go`

**Interfaces:**
- Consumes: `assets` and `asset_sources` from `000015`; `credential_reference_revisions`, `connection_revisions`, `capability_definitions` and `runtime_publications` from `000016`.
- Produces: expanded Asset/Provider/Relationship constraints and matching shared Go enums, four immutable Scope-bound Victoria-specific contract relations, plus the `000017` successor body of `public.asset_catalog_future_source_gate_admitted(public.asset_sources)`.
- Safety: successor admission is state-specific：`VALIDATING` requires the exact `KUBERNETES_OPERATOR / VICTORIAMETRICS_OPERATOR_V1 / typed extension / newly queued validation` closure，while `AVAILABLE|DEGRADED` additionally requires the exact successful terminal validation/cleanup proof；it remains false for `AWX_INVENTORY`。Down refuses while any Victoria asset/provider/source/contract/profile or any Kubernetes Operator Source（including `UNAVAILABLE|SUSPENDED`）remains, then restores the exact `000015` default-false body；no secret-bearing column is permitted.

The migration owns exactly these new relations:

| Relation | Identity | Purpose |
|---|---|---|
| `victoria_operator_source_revisions` | exact Phase 1 Source Revision + Environment | 1:1 typed cluster/namespace/API-discovery/opaque credential/network/realm closure; sealed only by Phase 1 `TypedSourceExtensionRegistry`, with no independent status/publish owner |
| `victoria_compatibility_profiles` | Scope + profile + revision | exact Operator/product/schema/executor compatibility |
| `victoria_compatibility_capabilities` | Scope + profile revision + capability definition revision | closed allowlist of compiled read capabilities |
| `victoria_connection_contracts` | Scope + connection revision | target role/topology/private tenant route/profile closure |

- [ ] **Step 1: Write failing real-PostgreSQL migration tests**

Add these exact test cases:

```go
func TestVictoriaMetricsEcosystemMigrationRequiresPhaseOneAndTwo(t *testing.T)
func TestVictoriaMetricsEcosystemMigrationAcceptsEveryVictoriaAssetKind(t *testing.T)
func TestVictoriaMetricsEcosystemMigrationAcceptsOnlyVictoriaRelationshipExtensions(t *testing.T)
func TestVictoriaMetricsEcosystemMigrationEnforcesScopedForeignKeys(t *testing.T)
func TestVictoriaMetricsEcosystemMigrationRejectsTenantRangeAndModeMismatch(t *testing.T)
func TestVictoriaMetricsEcosystemMigrationMakesPublishedContractsImmutable(t *testing.T)
func TestVictoriaMetricsEcosystemMigrationOwnsExactFutureSourceGateDefinition(t *testing.T)
func TestVictoriaMetricsEcosystemMigrationAdmitsOnlyExactOperatorSourceClosure(t *testing.T)
func TestVictoriaMetricsEcosystemMigrationRejectsOperatorProfileManifestSchemaAndDigestDrift(t *testing.T)
func TestVictoriaMetricsEcosystemMigrationPreflightMatchesReviewedManifest(t *testing.T)
func TestVictoriaMetricsEcosystemMigrationRecoversOnlyAfterExactRepublishAndRevalidation(t *testing.T)
func TestVictoriaMetricsEcosystemMigrationDownRefusesPersistedState(t *testing.T)
func TestVictoriaMetricsEcosystemMigrationDownRefusesAnyOperatorSource(t *testing.T)
func TestVictoriaMetricsEcosystemMigrationDownRestoresDefaultFalseFutureSourceGate(t *testing.T)
func TestVictoriaMetricsEcosystemMigrationRoundTripsEmptyDatabase(t *testing.T)
func TestVictoriaMetricsEcosystemMigrationNowaitLockFailureIsAtomicAndRetryable(t *testing.T)
func TestVictoriaMetricsEcosystemMigrationOwnsExactRoutineManifest(t *testing.T)
func TestVictoriaSchemaAdmissionIncludesFutureSourceGateDefinitionDigest(t *testing.T)
func TestVictoriaSchemaAdmissionRejectsFutureSourceGateBodyDrift(t *testing.T)
func TestVictoriaDatabaseRoleAdmissionExtendsExactOwnerGraph(t *testing.T)
func TestVictoriaSchemaAdmissionSurvivesMultiOwnerDumpRestore(t *testing.T)
func TestOperatorProfileManifestV1Golden(t *testing.T)
func TestOperatorProviderSchemaV1Golden(t *testing.T)
func TestOperatorSourceDefinitionV2Golden(t *testing.T)
func Test000017EmbedsExactOperatorProfileGolden(t *testing.T)
```

Assert all 37 new kinds insert successfully；an unlisted kind fails `assets_kind_check`；`CONFIGURES|SELECTS|OWNED_BY` Relationship values insert successfully while arbitrary text fails `asset_relationships_type_check`；`VICTORIAMETRICS` and `VICTORIATRACES` providers are accepted while arbitrary provider text is rejected；cross-Scope FKs fail；tenant values outside `0..4294967295` fail；typed extension UPDATE/DELETE/TRUNCATE always rejects with SQLSTATE `55000`，and every one-field extension mutation changes the recomputed prepared digest。Direct SQL initial parent `PUBLISHED|SUPERSEDED|REVOKED`、child under non-DRAFT parent、child code/provider/family mismatch、random/stale child/profile/connection digest and transition bypass all fail before trusted publication。An existing 000015-era K8S Source makes 000017 up fail atomically；after clean up, base Revision without same-transaction typed row、typed row without new base、or late typed insert all fail deferred closure。Future Source gate tests query `pg_proc`/`pg_get_functiondef` and compare the exact PostgreSQL 18.4 UTF-8 definition SHA-256 golden，证明 schema-qualified identity 恰为 `public.asset_catalog_future_source_gate_admitted(public.asset_sources)` 且没有 overload；仅 enum/provider row、错误 versioned `profile_code`、错误 canonical Profile manifest bytes/SHA-256、错误 canonical Provider schema bytes/SHA-256、缺失或多余 typed extension、extension/base prepared digest 或 20-frame BindingDigest 不闭合、错误/旧 Validation Run、cleanup 不确定、revision 或 validation digest 漂移都必须保持 `UNAVAILABLE`。正向 pre-validation fixture 先证明 base Revision、authority child 与 exact typed row 在同一 serializable transaction 创建后，exact queued Run 才能进入 `VALIDATING`，而没有 terminal proof 绝不能进入 `AVAILABLE`；随后完整经历 exact revision publication 与成功 `VALIDATION_PROOF` 才能开门。任一漂移都能无条件收敛到 `SUSPENDED/UNAVAILABLE`，恢复只有新 immutable revision 重新验证、发布并重新 admission，直接改 gate 被拒绝。`TestVictoriaMetricsEcosystemMigrationPreflightMatchesReviewedManifest` additionally byte-compares every inlined assertion in both migration directions with the reviewed `000015/000017` entries exported by `internal/assetcatalog/postgres/schema_admission.go`；removing an assertion fails before DDL。Non-empty down names constraint `victoria_ecosystem_down_guard`；empty up/down/up succeeds；任一相关表被并发 DML 持锁时 up/down 必须以 `55P03` 整笔失败且零 schema/data 变化，释放后从新事务完整重试才成功；拿齐全表锁后启动的 Source/typed-row/gate 事务不能越过 guard。Shared `assetcatalog.RelationshipType` must expose exactly Phase 1 values plus these three after Phase 3, so Adapter and database cannot drift.

- [ ] **Step 2: Run the focused test and verify the expected failure**

```bash
AIOPS_TEST_POSTGRES_DSN="$AIOPS_TEST_POSTGRES_DSN" go test ./internal/store/postgres -run 'TestVictoriaMetricsEcosystemMigration' -count=1
AIOPS_TEST_POSTGRES_DSN="$AIOPS_TEST_POSTGRES_DSN" go test ./internal/store/postgres -run 'TestVictoriaDatabaseRoleAdmission' -count=1
AIOPS_TEST_POSTGRES_DSN="$AIOPS_TEST_POSTGRES_DSN" go test ./internal/assetcatalog/postgres -run 'TestVictoriaSchemaAdmission' -count=1
go test ./internal/victoriametrics -run 'Test(Operator|000017Embeds).*Golden' -count=1
```

Expected: FAIL because migration `000017_victoriametrics_ecosystem` and its reviewed successor schema-admission manifest are absent.

- [ ] **Step 3: Implement the up migration in one transaction**

Use the complete constraint shape below. Preserve every Phase 1 kind and the legacy `PROMETHEUS` provider. The fenced block is an **ordered DDL excerpt, not a copyable migration**：the final migration must inline the complete generated predecessor assertions from the reviewed manifest owned by `internal/assetcatalog/postgres/schema_admission.go` at the marked GUC boundary, and must inline every routine/trigger/index body required by this Task before postflight. `TestVictoriaMetricsEcosystemMigrationPreflightMatchesReviewedManifest` parses the final up/down SQL and byte-compares that assertion set；there is no runtime skip、comment-only substitute or optional include.

```sql
BEGIN;
SET LOCAL lock_timeout = '5s';

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM pg_catalog.unnest(ARRAY[
            'public.environments',
            'public.asset_sources',
            'public.asset_source_revisions',
            'public.asset_source_revision_authorities',
            'public.asset_source_runs',
            'public.asset_observations',
            'public.assets',
            'public.asset_type_details',
            'public.asset_conflicts',
            'public.asset_relationships',
            'public.service_asset_bindings',
            'public.audit_records',
            'public.outbox_events',
            'public.credential_references',
            'public.credential_reference_revisions',
            'public.connection_profiles',
            'public.connection_revisions',
            'public.connection_revision_capabilities',
            'public.capability_definitions',
            'public.connection_validation_runs',
            'public.connection_validation_checks',
            'public.validation_credential_revocations',
            'public.runner_realms',
            'public.runner_capability_bindings',
            'public.published_targets',
            'public.published_capability_sets',
            'public.published_capability_set_items',
            'public.runtime_publications',
            'public.runtime_publication_artifacts'
        ]) AS prerequisite(name)
        WHERE pg_catalog.to_regclass(prerequisite.name) IS NULL
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = '000015 and 000016 are required',
            CONSTRAINT = 'victoria_ecosystem_prerequisite';
    END IF;
END;
$$;

SELECT pg_catalog.pg_advisory_xact_lock(712017001900001);
LOCK TABLE
    public.environments,
    public.asset_sources, public.asset_source_revisions,
    public.asset_source_revision_authorities, public.asset_source_runs,
    public.asset_observations, public.assets, public.asset_type_details,
    public.asset_conflicts, public.asset_relationships, public.service_asset_bindings,
    public.audit_records, public.outbox_events,
    public.credential_references, public.credential_reference_revisions,
    public.connection_profiles, public.connection_revisions,
    public.connection_revision_capabilities, public.capability_definitions,
    public.connection_validation_runs, public.connection_validation_checks,
    public.validation_credential_revocations,
    public.runner_realms, public.runner_capability_bindings,
    public.published_targets, public.published_capability_sets,
    public.published_capability_set_items,
    public.runtime_publications, public.runtime_publication_artifacts
IN ACCESS EXCLUSIVE MODE NOWAIT;

SET LOCAL quote_all_identifiers = off;
SET LOCAL search_path = pg_catalog, pg_temp;
-- Ordered excerpt resumes only after the final migration has executed every
-- reviewed 000015 definition/owner/ACL/signature/no-overload assertion.
SET LOCAL search_path = public, pg_catalog, pg_temp;

ALTER TABLE assets DROP CONSTRAINT assets_kind_check;
ALTER TABLE assets ADD CONSTRAINT assets_kind_check CHECK (kind IN (
    'SERVICE','LINUX_VM','WINDOWS_VM','BARE_METAL_HOST',
    'KUBERNETES_CLUSTER','KUBERNETES_NAMESPACE','KUBERNETES_WORKLOAD',
    'DATABASE_INSTANCE','DATABASE','METRICS_SOURCE','LOG_SOURCE','TRACE_SOURCE',
    'AWX_INVENTORY','ARGO_APPLICATION','CI_PIPELINE','GIT_REPOSITORY','CLOUD_RESOURCE',
    'VICTORIAMETRICS_SINGLE','VICTORIAMETRICS_CLUSTER','VICTORIAMETRICS_VMSELECT',
    'VICTORIAMETRICS_VMINSERT','VICTORIAMETRICS_VMSTORAGE',
    'VICTORIALOGS_SINGLE','VICTORIALOGS_CLUSTER','VICTORIALOGS_VLSELECT',
    'VICTORIALOGS_VLINSERT','VICTORIALOGS_VLSTORAGE',
    'VICTORIATRACES_SINGLE','VICTORIATRACES_CLUSTER','VICTORIATRACES_VTSELECT',
    'VICTORIATRACES_VTINSERT','VICTORIATRACES_VTSTORAGE',
    'VMAGENT','VLAGENT','VMALERT','VMAUTH','VMGATEWAY','VMALERTMANAGER',
    'VMANOMALY','VMOPERATOR','VMBACKUPMANAGER',
    'VMRULE','VMUSER','VMALERTMANAGER_CONFIG','VMNODE_SCRAPE','VMPOD_SCRAPE',
    'VMPROBE','VMSERVICE_SCRAPE','VMSTATIC_SCRAPE','VMSCRAPE_CONFIG',
    'VMCTL','VMBACKUP','VMRESTORE','VMALERT_TOOL'
));

ALTER TABLE asset_relationships
    DROP CONSTRAINT asset_relationships_type_check;
ALTER TABLE asset_relationships
    ADD CONSTRAINT asset_relationships_type_check CHECK (relationship_type IN (
        'RUNS_ON','CONTAINS','DEPENDS_ON','MONITORED_BY','LOGS_TO','TRACES_TO',
        'DELIVERED_BY','MANAGED_BY','PRIMARY_RUNTIME_FOR',
        'CONFIGURES','SELECTS','OWNED_BY'
    ));

ALTER TABLE connection_profiles
    DROP CONSTRAINT connection_profiles_provider_kind_check;
ALTER TABLE connection_profiles
    ADD CONSTRAINT connection_profiles_provider_kind_check
    CHECK (provider_kind IN (
        'PROMETHEUS','VICTORIAMETRICS','VICTORIALOGS','VICTORIATRACES'
    ));

ALTER TABLE runner_capability_bindings
    DROP CONSTRAINT runner_capability_bindings_provider_kind_check;
ALTER TABLE runner_capability_bindings
    ADD CONSTRAINT runner_capability_bindings_provider_kind_check
    CHECK (provider_kind IN (
        'PROMETHEUS','VICTORIAMETRICS','VICTORIALOGS','VICTORIATRACES'
    ));

ALTER TABLE capability_definitions
    DROP CONSTRAINT capability_definitions_provider_kind_check;
ALTER TABLE capability_definitions
    ADD CONSTRAINT capability_definitions_provider_kind_check
    CHECK (provider_kind IN (
        'PROMETHEUS','VICTORIAMETRICS','VICTORIALOGS','VICTORIATRACES'
    ));

CREATE TABLE victoria_operator_source_revisions (
    tenant_id uuid NOT NULL,
    workspace_id uuid NOT NULL,
    environment_id uuid NOT NULL,
    source_id uuid NOT NULL,
    revision bigint NOT NULL CHECK (revision > 0),
    kubernetes_cluster_asset_id uuid NOT NULL,
    credential_reference_id uuid NOT NULL,
    credential_reference_revision bigint NOT NULL CHECK (credential_reference_revision > 0),
    network_policy_ref text NOT NULL
        CHECK (public.asset_catalog_opaque_reference_valid(network_policy_ref)),
    discovery_realm_ref text NOT NULL
        CHECK (discovery_realm_ref ~ '^[a-z0-9][a-z0-9_.-]{0,59}-v1-[a-f0-9]{64}$'),
    namespace_allowlist text[] NOT NULL
        CHECK (public.victoria_namespace_allowlist_valid(namespace_allowlist)),
    api_discovery_profile_digest text NOT NULL CHECK (api_discovery_profile_digest ~ '^[a-f0-9]{64}$'),
    artifact_inventory_digest text NOT NULL CHECK (artifact_inventory_digest ~ '^[a-f0-9]{64}$'),
    manifest_digest text NOT NULL CHECK (manifest_digest ~ '^[a-f0-9]{64}$'),
    prepared_extension_digest text NOT NULL CHECK (prepared_extension_digest ~ '^[a-f0-9]{64}$'),
    created_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id,workspace_id,source_id,revision),
    UNIQUE (tenant_id,workspace_id,environment_id,source_id,revision),
    FOREIGN KEY (tenant_id,workspace_id,source_id,revision)
        REFERENCES asset_source_revisions (tenant_id,workspace_id,source_id,revision)
        DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (tenant_id,workspace_id,environment_id,kubernetes_cluster_asset_id)
        REFERENCES assets (tenant_id,workspace_id,environment_id,id),
    FOREIGN KEY (tenant_id,workspace_id,environment_id,credential_reference_id,credential_reference_revision)
        REFERENCES credential_reference_revisions
        (tenant_id,workspace_id,environment_id,credential_reference_id,revision)
);

CREATE TABLE victoria_compatibility_profiles (
    tenant_id uuid NOT NULL,
    workspace_id uuid NOT NULL,
    environment_id uuid NOT NULL,
    id uuid NOT NULL,
    revision bigint NOT NULL CHECK (revision > 0),
    operator_version text NOT NULL,
    product_family text NOT NULL CHECK (product_family IN ('METRICS','LOGS','TRACES')),
    product_version text NOT NULL,
    topology text NOT NULL CHECK (topology IN ('SINGLE','CLUSTER','GOVERNED_PROXY')),
    target_role text NOT NULL CHECK (target_role IN ('SINGLE','SELECT','PROXY')),
    target_schema_version text NOT NULL,
    connector_schema_version text NOT NULL,
    evidence_schema_version text NOT NULL,
    executor_profile_digest text NOT NULL CHECK (executor_profile_digest ~ '^[a-f0-9]{64}$'),
    status text NOT NULL CHECK (status IN ('DRAFT','PUBLISHED','SUPERSEDED','REVOKED')),
    manifest_digest text NOT NULL CHECK (manifest_digest ~ '^[a-f0-9]{64}$'),
    created_by text NOT NULL,
    created_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id,workspace_id,environment_id,id,revision),
    UNIQUE (tenant_id,workspace_id,environment_id,product_family,product_version,topology,target_role,revision)
);

CREATE TABLE victoria_compatibility_capabilities (
    tenant_id uuid NOT NULL,
    workspace_id uuid NOT NULL,
    environment_id uuid NOT NULL,
    profile_id uuid NOT NULL,
    profile_revision bigint NOT NULL,
    capability_definition_id uuid NOT NULL,
    capability_definition_revision bigint NOT NULL,
    capability_code text NOT NULL,
    manifest_digest text NOT NULL CHECK (manifest_digest ~ '^[a-f0-9]{64}$'),
    PRIMARY KEY (tenant_id,workspace_id,environment_id,profile_id,profile_revision,capability_code),
    FOREIGN KEY (tenant_id,workspace_id,environment_id,profile_id,profile_revision)
        REFERENCES victoria_compatibility_profiles
        (tenant_id,workspace_id,environment_id,id,revision),
    FOREIGN KEY (tenant_id,workspace_id,environment_id,capability_definition_id,capability_definition_revision)
        REFERENCES capability_definitions
        (tenant_id,workspace_id,environment_id,id,revision)
);

CREATE TABLE victoria_connection_contracts (
    tenant_id uuid NOT NULL,
    workspace_id uuid NOT NULL,
    environment_id uuid NOT NULL,
    connection_id uuid NOT NULL,
    connection_revision bigint NOT NULL,
    product_family text NOT NULL CHECK (product_family IN ('METRICS','LOGS','TRACES')),
    topology text NOT NULL CHECK (topology IN ('SINGLE','CLUSTER','GOVERNED_PROXY')),
    target_role text NOT NULL CHECK (target_role IN ('SINGLE','SELECT','PROXY')),
    tenant_route_mode text NOT NULL CHECK (tenant_route_mode IN (
        'SINGLE_DEFAULT','METRICS_CLUSTER_PATH','METRICS_CLUSTER_HEADERS',
        'LOGS_HEADERS','TRACES_HEADERS','GOVERNED_PROXY'
    )),
    account_id bigint,
    project_id bigint,
    route_profile_digest text,
    product_version text NOT NULL,
    operator_version text NOT NULL,
    compatibility_profile_id uuid NOT NULL,
    compatibility_profile_revision bigint NOT NULL,
    compatibility_profile_digest text NOT NULL CHECK (compatibility_profile_digest ~ '^[a-f0-9]{64}$'),
    hidden_fields_profile_digest text CHECK (hidden_fields_profile_digest ~ '^[a-f0-9]{64}$'),
    status text NOT NULL CHECK (status IN ('DRAFT','PUBLISHED','SUPERSEDED','REVOKED')),
    manifest_digest text NOT NULL CHECK (manifest_digest ~ '^[a-f0-9]{64}$'),
    created_by text NOT NULL,
    created_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id,workspace_id,environment_id,connection_id,connection_revision),
    FOREIGN KEY (tenant_id,workspace_id,environment_id,connection_id,connection_revision)
        REFERENCES connection_revisions
        (tenant_id,workspace_id,environment_id,connection_id,revision),
    FOREIGN KEY (tenant_id,workspace_id,environment_id,compatibility_profile_id,compatibility_profile_revision)
        REFERENCES victoria_compatibility_profiles
        (tenant_id,workspace_id,environment_id,id,revision),
    CHECK (account_id IS NULL OR account_id BETWEEN 0 AND 4294967295),
    CHECK (project_id IS NULL OR project_id BETWEEN 0 AND 4294967295),
    CHECK (
        (tenant_route_mode = 'SINGLE_DEFAULT' AND account_id = 0 AND project_id = 0 AND route_profile_digest IS NULL)
        OR (tenant_route_mode IN ('METRICS_CLUSTER_PATH','METRICS_CLUSTER_HEADERS','LOGS_HEADERS','TRACES_HEADERS')
            AND account_id IS NOT NULL AND project_id IS NOT NULL AND route_profile_digest IS NULL)
        OR (tenant_route_mode = 'GOVERNED_PROXY' AND account_id IS NULL AND project_id IS NULL
            AND route_profile_digest ~ '^[a-f0-9]{64}$')
    )
);

-- Ordered excerpt ends here; the final migration next installs the complete
-- successor hook/routine/trigger/index manifest and runs reviewed postflight.
```

Task 1 owns the Profile golden before any later registry exists. `OperatorProfileManifestV1()` returns deep copies of the exact 1,573-byte RFC 8785 value `{"backpressure_base_seconds":5,"backpressure_max_seconds":300,"compatibility_class":"VICTORIAMETRICS_OPERATOR_V1","credential_purpose":"KUBERNETES_DISCOVERY_READ","dlp_policy_code":"ASSET_SAFE_V1","environment_mapping_mode":"SINGLE_ENVIRONMENT","freshness_kind":"CHECKPOINT_SEQUENCE","integration_mode":"NONE","max_document_bytes":65536,"max_page_bytes":8388608,"max_page_items":500,"max_page_relations":2000,"network_mode":"REQUIRED","parser_code":"VICTORIAMETRICS_OPERATOR_ASSET_V1","profile_code":"VICTORIAMETRICS_OPERATOR_V1","provider_kind":"VICTORIAMETRICS_OPERATOR_V1","rate_limit_requests":100,"rate_limit_window_seconds":60,"relationship_types":["CONFIGURES","CONTAINS","MANAGED_BY","PRIMARY_RUNTIME_FOR"],"schedule_mode":"REQUIRED","source_kind":"KUBERNETES_OPERATOR","sync_mode":"SCHEDULED","trust_mode":"REQUIRED","trusted_path_codes":["VICTORIAMETRICS_OPERATOR_V1_API_VERSION","VICTORIAMETRICS_OPERATOR_V1_COMPATIBILITY_STATUS","VICTORIAMETRICS_OPERATOR_V1_CONDITIONS","VICTORIAMETRICS_OPERATOR_V1_CREDENTIAL_REFERENCE","VICTORIAMETRICS_OPERATOR_V1_DESIRED_REPLICAS","VICTORIAMETRICS_OPERATOR_V1_DISPLAY_NAME","VICTORIAMETRICS_OPERATOR_V1_EXTERNAL_ID","VICTORIAMETRICS_OPERATOR_V1_GENERATION","VICTORIAMETRICS_OPERATOR_V1_NAMESPACE_DIGEST","VICTORIAMETRICS_OPERATOR_V1_OBJECT_UID","VICTORIAMETRICS_OPERATOR_V1_PRODUCT_VERSION","VICTORIAMETRICS_OPERATOR_V1_READY_REPLICAS","VICTORIAMETRICS_OPERATOR_V1_RESOURCE_KIND","VICTORIAMETRICS_OPERATOR_V1_TAXONOMY_CLASS"],"typed_extension_code":"VICTORIAMETRICS_OPERATOR_V1","version":"asset-source-profile-manifest.v1"}` with SHA-256 `fcfbd34fa6678a7eb98694327949e49cc0809111c5273c9b130c4fa230c49132`.

Its exact 1,026-byte canonical Provider schema is `{"additionalProperties":false,"properties":{"api_version":{"maxLength":64,"minLength":1,"type":"string"},"conditions":{"items":{"additionalProperties":false,"properties":{"status":{"enum":["False","True","Unknown"]},"type":{"enum":["Available","Degraded","Progressing","Ready"]}},"required":["status","type"],"type":"object"},"maxItems":4,"type":"array"},"credential_reference":{"pattern":"^vmuser-credential-v1-[a-f0-9]{64}$","type":"string"},"desired_replicas":{"minimum":0,"type":"integer"},"generation":{"minimum":0,"type":"integer"},"namespace_digest":{"pattern":"^[a-f0-9]{64}$","type":"string"},"object_uid":{"maxLength":128,"minLength":1,"type":"string"},"product_version":{"maxLength":128,"minLength":1,"type":"string"},"ready_replicas":{"minimum":0,"type":"integer"},"resource_kind":{"maxLength":64,"minLength":1,"type":"string"},"taxonomy_class":{"maxLength":64,"minLength":1,"type":"string"}},"required":["api_version","generation","namespace_digest","object_uid","resource_kind","taxonomy_class"],"type":"object"}` with SHA-256 `c9e7d80a6ee64ef4f1d999894d3df5aba312a0a38cc539afd1d4c5f86273d8a1`. The six-frame `asset-source-definition.v2` for `KUBERNETES_OPERATOR/VICTORIAMETRICS_OPERATOR_V1/VICTORIAMETRICS_OPERATOR_V1` is 193 bytes with SHA-256 `fe6a235ff65e962bc3520cd62165da630416b0fd90a85e3c8bec00c80c192b7f`. Migration SQL embeds independent raw UTF-8 literals and recomputes all three hashes; tests byte-compare SQL, typed reconstruction and the Go fixture. Task 4 only consumes this Task 1-owned function and may not regenerate or redefine it.

`000017` owns exactly nine new routines plus the one in-place hook (post-up net `+9`), with no overload: `public.victoria_namespace_allowlist_valid(text[]) RETURNS boolean`; `public.victoria_operator_source_extension_digest(uuid,uuid,uuid,uuid,bigint,uuid,uuid,bigint,text,text,text[],text,text,text) RETURNS text`; procedure `public.asset_catalog_create_victoria_operator_source_revision(uuid,uuid,uuid,uuid,bigint,uuid,uuid,bigint,text,text,text[],text,text,text,text)`; `public.validate_victoria_operator_source_revision_closure()`; `public.reject_victoria_operator_source_revision_mutation()`; `public.reject_victoria_published_mutation()`; `public.transition_victoria_compatibility_profile(uuid,uuid,uuid,uuid,bigint,text,text)`; `public.transition_victoria_connection_contract(uuid,uuid,uuid,uuid,bigint,text,text)`; `public.reject_victoria_truncate()`。The tenth manifest entry is the replace-only future hook. All identities/trusted relations/types are `public`-qualified，builtins/operators `pg_catalog`-qualified，and every routine fixes `search_path=pg_catalog, public, pg_temp` with definition hash、semantic ACL and zero overload。Pure validators/digests are INVOKER；triggers/transitions are DEFINER owned by schema owner，runtime executes only transitions and the extension procedure。Contract tables grant runtime `SELECT/INSERT` for DRAFT and no direct UPDATE/DELETE/TRUNCATE；typed Source has no runtime DML，but hook gets exact read-only trusted-table ACL。Real workload tests cover inherited paths、TEMP shadow and unauthorized denial。The sole exception owner is preprovisioned `aiops_victoria_operator_extension_owner` (`NOLOGIN/NOINHERIT`)；it has schema `USAGE`、typed-table `INSERT/SELECT` and exactly four helper EXECUTEs：`public.asset_catalog_opaque_reference_valid(text)`、`public.asset_catalog_framed_value_v1(bytea)`、`public.victoria_namespace_allowlist_valid(text[])`、the exact scalar `public.victoria_operator_source_extension_digest(...)`，with no base/trigger/transition right。Only migrator has its SET-only edge。Migration temporarily grants uncommitted schema CREATE to migrator/extension owner for create/transfer，then revokes before postflight；failure rolls back all，and real extension-owner procedure tests prove missing/extra helper ACL fails admission。

`victoria_namespace_allowlist_valid` accepts only a one-dimensional array with lower bound 1 and 1–128 non-NULL values; each value is 1–63 UTF-8 octets, matches Kubernetes DNS label `^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`, and is strictly increasing against its predecessor under `COLLATE "C"`. Direct SQL tests reject NULL elements, two dimensions, a non-1 lower bound, duplicate/out-of-order values, uppercase, dots and 64-byte labels. The scalar-only digest routine computes the exact extension frames；the procedure recomputes that digest solely from its scalar arguments plus the row it is about to insert，compares the caller's expected digest and inserts only the 1:1 typed row；it never reads the base revision or treats that optimistic comparison as authoritative base equality。The deferred closure attached to both base K8S revisions and typed rows is the authoritative base↔typed comparison，and the Phase 1 Controller rereads the inserted row before Audit/Outbox。The two transition routines are the sole contract status writers: target `PUBLISHED` locks the stable key, validates `DRAFT` plus children and all content digests below, moves the old published row to `SUPERSEDED` first, then publishes the new row; target `SUPERSEDED|REVOKED` accepts only the exact current published row and first closes dependent Sources in the same transaction.

The two transition routines also own SQL content-addressing without adding routines。Each `victoria_compatibility_capabilities.manifest_digest` must equal lowercase `SHA256(FramedTupleV1("victoria-compatibility-capability.v1",tenant_id,workspace_id,environment_id,profile_id,minimal-decimal profile_revision,capability_code,capability_definition_id,minimal-decimal capability_definition_revision))`。Children are locked and sorted by `(capability_code COLLATE "C",capability_definition_id::text COLLATE "C",capability_definition_revision)`；the profile digest is lowercase `SHA256(FramedTupleV1("victoria-compatibility-profile.v1",tenant_id,workspace_id,environment_id,id,minimal-decimal revision,operator_version,product_family,product_version,topology,target_role,target_schema_version,connector_schema_version,evidence_schema_version,raw executor_profile_digest,minimal-decimal child count,repeated raw child manifest_digest))`。The connection digest is lowercase `SHA256(FramedTupleV1("victoria-connection-contract.v1",tenant_id,workspace_id,environment_id,connection_id,minimal-decimal connection_revision,product_family,topology,target_role,tenant_route_mode,nullable minimal-decimal account_id,nullable minimal-decimal project_id,nullable raw route_profile_digest,product_version,operator_version,compatibility_profile_id,minimal-decimal compatibility_profile_revision,raw recomputed compatibility profile digest,nullable raw hidden_fields_profile_digest))`。`status/created_by/created_at` are excluded；UUIDs are lowercase canonical text，hashes are raw 32-byte frames，NULL uses the shared NULL frame，all other values are present UTF-8 frames。Before either publication, SQL locks every referenced row，recomputes every child/profile/connection value，requires persisted and function-argument expected digests to match，and rejects a random or self-consistently stale digest with `23514` before any status mutation。Tests cover every frame、child reorder/count/reference drift and direct-SQL DRAFT→PUBLISHED attempts；Go uses the same framed routines rather than treating JCS or caller SHA as publication truth。

上方 `BEGIN` block 的顺序是规范而非示意：最低存在性检查之后、任何 fingerprint/guard/`ALTER`/`CREATE` 之前，`000017` 先取 `pg_catalog.pg_advisory_xact_lock(712017001900001)`，再以**一条** fully qualified `ACCESS EXCLUSIVE ... NOWAIT` statement 锁住上方列出的全部 Phase 1/2 FK target、hook/reverse-close trusted fact、mutable credential/runtime/realm surface 和待 ALTER relation，并持有完整锁集到 `COMMIT`。任一关系被并发 DML/DDL 持有时返回 `55P03`，整个 transaction 立即回滚并从 `BEGIN` 重试；迁移绝不一边等待一边持有部分表锁，因此不会与 Source→Revision 或 Run→Source 路径形成等待环。Only after the lock succeeds does it set the deparse GUCs to `quote_all_identifiers=off` and `search_path=pg_catalog,pg_temp`，then prove the existing hook has exactly one signature、the exact PostgreSQL 18.4 UTF-8 definition digest of the `000015` predecessor、precise `plpgsql/STABLE/SECURITY INVOKER/search_path`、owner equal to the single Asset Catalog relation owner、normalized ACL and zero overload。It also consumes the Task 1 role ABI and requires preprovisioned `aiops_victoria_operator_extension_owner` to be NOLOGIN/NOINHERIT、outside schema/runtime membership edges、without schema CREATE or base-table privilege before DDL；`pg_auth_members` must contain exactly the migrator SET-only/non-inheriting/non-admin edge described above，and no other membership to the owner。The reviewed extension-owner manifest is added by this Task and CI/runbook create the role plus only that deployment edge，not data/schema privileges。Fingerprint queries resolve every object by explicit schema/OID；before unqualified SQL snippets run, the migration explicitly restores `SET LOCAL search_path=public,pg_catalog,pg_temp`，and before postflight switches back to the deparse pair。任一前置条件不满足整笔拒绝，不能让 `CREATE OR REPLACE` 继承被篡改的 owner/ACL。Preflight 还必须拒绝任何已存在的 `KUBERNETES_OPERATOR` Source/Revision，即使 gate 是 `UNAVAILABLE|SUSPENDED`；000015-era typed digest 没有 1:1 row，不能在安装 successor 后补写并复用。随后在四表创建完成且仍处于同一 migration transaction 内，`000017` 才执行：

```sql
CREATE OR REPLACE FUNCTION public.asset_catalog_future_source_gate_admitted(
    candidate public.asset_sources
) RETURNS boolean
```

函数保持 `LANGUAGE plpgsql STABLE SECURITY INVOKER` 与 `SET search_path = pg_catalog, public, pg_temp`，且 body 只用 `public.`-qualified trusted relations/types and `pg_catalog` builtins/operators，是按 candidate gate 状态分支的默认拒绝闭包。三个分支都先要求 candidate `ACTIVE`、`source_kind='KUBERNETES_OPERATOR'`、`provider_kind='VICTORIAMETRICS_OPERATOR_V1'`，并要求 Revision 的 persisted canonical Profile manifest bytes/SHA-256 与本 Task 1 固定的 `VICTORIAMETRICS_OPERATOR_V1` bytes/hash 完全相等；Profile code alone never admits。它把 exact base revision 连接到唯一 `victoria_operator_source_revisions` typed extension；base 必须有 `typed_extension_code='VICTORIAMETRICS_OPERATOR_V1'` 且 `prepared_extension_digest=extension.prepared_extension_digest`，再由 Phase 1 SQL functions 重算 Profile-manifest hash、`asset-source-definition.v2` 与固定 20-frame BindingDigest。Duplicated bindings have one exact meaning：base `credential_reference_id` must equal lowercase canonical `extension.credential_reference_id::text`，base `network_policy_reference_id` must equal `extension.network_policy_ref`，and the extension revision must be the immutable revision of that same scoped Credential Reference with purpose `KUBERNETES_DISCOVERY_READ`。Base `trust_reference_id` independently binds the immutable API-server trust bundle；`discovery_realm_ref` binds the validated Runner Realm and is never treated as a second Trust Reference。`source_definition_digest` remains the Provider/Profile definition and excludes source-specific bindings/typed extension.

- initial `UNAVAILABLE` creation branch 仅由 Phase 1 deferred INSERT closure 调用：要求 Source 无 published/validated/checkpoint/run pointer，`gate_revision=0`、`checkpoint_version=0`、`checkpoint_revision=0`、checkpoint material NULL，且只有 one same-transaction `DRAFT` revision 1 with `expected_source_version=1`；Revision insert 已按 Phase 1 CAS 将 stable Source version 从 1 精确推进到 2。Authority child/typed row/Scope/Environment/prepared digest 必须全闭合；它只允许 stable Source+revision creation，不允许 validation 或开门。
- `VALIDATING` branch 绑定 candidate 的 exact newly queued Validation Run，要求其 revision 当前为 `VALIDATING`、versioned `profile_code='VICTORIAMETRICS_OPERATOR_V1'`、migration-fixed canonical Profile manifest bytes/SHA-256、canonical Provider schema bytes/SHA-256、typed extension、Scope/Environment 与 `asset-source-definition.v2`/BindingDigest 全闭合；此时不要求尚不存在的 terminal validation proof。
- `AVAILABLE|DEGRADED` branch 绑定 candidate exact `PUBLISHED` revision/digest 与同一 typed extension，并要求 `validated_run_id/validation_digest/validated_binding_digest` 连接该 revision 的 exact terminal `SUCCEEDED/COMPLETED/VALIDATION/VALIDATION_PROOF` Run；because the extension requires a Credential Reference，actual cleanup must be exactly `REVOKED` and `NO_CREDENTIAL` is a negative fixture。Validation proof、published revision 与 validated binding digest 全相等；`DEGRADED` 还必须保留 Phase 1 generic rollover closure。

任一零行、多行、Scope/Environment/profile/schema/revision/extension/validation/cleanup/digest 漂移均返回 false；所有其他 gate 状态或 Source kind（尤其 `AWX_INVENTORY`）返回 false。Phase 1 UPDATE/live path only calls the hook for `VALIDATING|AVAILABLE|DEGRADED`；the separate deferred INSERT closure is the sole exception and calls its exact initial `UNAVAILABLE` creation branch。Existing rows may always converge to `UNAVAILABLE|SUSPENDED` without hook admission。函数不得读取可变注册表推断支持、调用动态 SQL或把 enum 存在当成 admission。

所有进入/保持 `VALIDATING|AVAILABLE|DEGRADED` 的 Repository 路径必须在同一 `SERIALIZABLE` transaction 内按固定顺序锁定 Source、base revision、typed extension、Validation Run 及其 provider-specific trusted facts，再执行 Source UPDATE；Phase 1 trigger 对非-serializable future live transition 直接拒绝。Hook 在该 transaction/snapshot 内重查相同闭包。Typed extension、terminal proof 与 published revision 继续由 immutable trigger 拒绝 UPDATE/DELETE；任何其余可变 profile/pointer/revocation 事务必须使用同一全局锁序反向查找并锁定全部依赖 Source，在改变可信事实的同一事务先把它们推进到 `SUSPENDED/UNAVAILABLE`。并发测试允许两个事务顺序提交，但若漂移事务提交则 Source 必须已原子关门；否则必须有一方 serialization failure，绝不允许最终 live Source 引用旧闭包。

迁移测试固定 schema-qualified signature 与 `SHA256(convert_to(pg_get_functiondef(oid),'UTF8'))`；the generated predecessor-manifest relation set must equal the one-shot NOWAIT lock set exactly，and a per-relation fixture holds each member to require `55P03` before any mutation。Pre/postflight 重查 definition、owner、semantic ACL、language/security/path/no-overload and full reviewed surface。Multi-owner recovery extends Phase1：source archive owners are exactly `{aiops_schema_owner,aiops_victoria_operator_extension_owner}`，only the fixed procedure uses the latter；source catalog plus rendered archive ACL commands must prove every ACL grantor equals that object's owner，because any third grantor would make PostgreSQL 18 emit forbidden `SET SESSION AUTHORIZATION`。Target preprovisions exact persistent flags/SET-only edges at different OIDs and stays quarantined。An authorized coordinator control connection takes **session-level** `pg_catalog.pg_advisory_lock(712017001900001)` before any committed temporary authority and holds it through restore plus cleanup；because PostgreSQL releases that lock when the coordinator crashes，every newly elected coordinator must first reacquire the same lock，idempotently revoke any residual schema `CREATE` and recovery-only membership edge，verify the persistent baseline/quarantine and only then install fresh temporary authority or invoke restore。A role-admin action adds recovery-only `schema_owner→extension_owner` membership `inherit=true,set=true,admin=false`，while a separately authenticated migrator does `SET ROLE aiops_schema_owner` to grant extension owner temporary `CREATE ON SCHEMA public`。The schema-owner role attribute remains NOINHERIT。Authenticated non-superuser migrator then runs `pg_restore --single-transaction --role=aiops_schema_owner`：table data runs with owner privilege，recorded ownership can transfer only the fixed procedure，and ACL pass inherits its owner authority。No `--role`、non-owner ACL grantor、missing temporary edge/CREATE are mandatory negatives。On success/failure，migrator-as-schema-owner first revokes CREATE，role admin revokes the edge，then admission passes before CONNECT and the control session unlocks；a hard crash may leave only those committed residues, but workload CONNECT/admission remains closed and the next coordinator must clean them before restore。Kill-after-each-committed-authority-step fixtures prove lock release never opens traffic，a replacement cleans residue before any restore call，and repeated cleanup is safe；either residue fails admission。`--no-owner/--no-acl/--disable-triggers/--use-set-session-authorization`、third owner and unquarantined restore are forbidden；the superuser prohibition applies to dump/restore data connections，not to an externally controlled role-administration authority if platform policy requires one。Only exact schema+role admission opens traffic。Up remains atomic；Task completes only with migration/admission/recovery Green。

`victoria_operator_source_revisions` is unconditionally append-only：dedicated row/statement guards reject every UPDATE、DELETE and TRUNCATE with SQLSTATE `55000`，independent of base lifecycle。A `DEFERRABLE INITIALLY DEFERRED` 000017-owned closure trigger fires from both the base `asset_source_revisions` K8S row and typed row；at commit it requires exactly one extension with matching Scope/revision、sole authority Environment、code and recomputed prepared digest. Thus base revision、authority child and typed row must be inserted in the same outer transaction，and neither an old base row nor a later extension insert can commit. `reject_victoria_published_mutation()` is installed as `BEFORE INSERT OR UPDATE OR DELETE` on both parent tables and as the child insert/mutation guard：every parent INSERT must be `DRAFT`；a capability child INSERT requires its locked parent still `DRAFT` plus exact referenced Capability `code` and Provider mapping `METRICS→VICTORIAMETRICS|LOGS→VICTORIALOGS|TRACES→VICTORIATRACES`；arbitrary UPDATE/DELETE of a trusted parent/child raises `55000`，and only the exact task-owned transition routines may perform their closed status changes。All four tables reject DELETE/TRUNCATE. Add partial unique indexes allowing one `PUBLISHED` profile tuple and connection contract per stable identity.

- [ ] **Step 4: Implement the guarded down migration**

The down migration begins one transaction, executes `SET LOCAL lock_timeout='5s'`, runs the same full minimum-existence check and takes `pg_catalog.pg_advisory_xact_lock(712017001900001)`—the successor-hook migration key shared by 000017/000019 up/down. Before any fingerprint or guard it uses one fully qualified `LOCK TABLE ... IN ACCESS EXCLUSIVE MODE NOWAIT` statement over the exact up set plus `public.victoria_operator_source_revisions`、`public.victoria_compatibility_profiles`、`public.victoria_compatibility_capabilities` and `public.victoria_connection_contracts`，holding the complete set through `COMMIT`. A `55P03` conflict aborts the whole transaction without guard/hook/schema change and may only be retried from a new `BEGIN`；after success, later DML waits behind the complete set. It then sets `quote_all_identifiers=off/search_path=pg_catalog,pg_temp` for exact successor fingerprint preflight，restores `search_path=public,pg_catalog,pg_temp` before guard/restore/drop SQL，switches back to the deparse pair for predecessor postflight，rejects any Victoria row or provider/asset, restores the hook, drops triggers/tables in child-first FK order, restores provider and asset constraints to the exact Phase 1/2 values, post-verifies catalog identity, and commits. The listed relation sequence is a migration manifest, not a production row-lock order；every up/down path that can install/replace this hook follows advisory→one-shot NOWAIT lock→preflight before any catalog mutation.

```sql
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM victoria_connection_contracts)
       OR EXISTS (SELECT 1 FROM victoria_compatibility_capabilities)
       OR EXISTS (SELECT 1 FROM victoria_compatibility_profiles)
       OR EXISTS (SELECT 1 FROM victoria_operator_source_revisions)
       OR EXISTS (
            SELECT 1 FROM asset_sources
            WHERE source_kind = 'KUBERNETES_OPERATOR'
       )
       OR EXISTS (SELECT 1 FROM connection_profiles WHERE provider_kind IN ('VICTORIAMETRICS','VICTORIATRACES'))
       OR EXISTS (SELECT 1 FROM runner_capability_bindings WHERE provider_kind IN ('VICTORIAMETRICS','VICTORIATRACES'))
       OR EXISTS (SELECT 1 FROM capability_definitions WHERE provider_kind IN ('VICTORIAMETRICS','VICTORIATRACES'))
       OR EXISTS (SELECT 1 FROM asset_relationships WHERE relationship_type IN ('CONFIGURES','SELECTS','OWNED_BY'))
       OR EXISTS (SELECT 1 FROM assets WHERE kind LIKE 'VICTORIA%' OR kind IN (
            'VMAGENT','VLAGENT','VMALERT','VMAUTH','VMGATEWAY','VMALERTMANAGER','VMANOMALY',
            'VMOPERATOR','VMBACKUPMANAGER','VMRULE','VMUSER','VMALERTMANAGER_CONFIG',
            'VMNODE_SCRAPE','VMPOD_SCRAPE','VMPROBE','VMSERVICE_SCRAPE','VMSTATIC_SCRAPE',
            'VMSCRAPE_CONFIG','VMCTL','VMBACKUP','VMRESTORE','VMALERT_TOOL'
       )) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'unsafe VictoriaMetrics ecosystem rollback: state remains',
            CONSTRAINT = 'victoria_ecosystem_down_guard';
    END IF;
END;
$$;
```

空状态回滚必须把 `connection_profiles_provider_kind_check`、`runner_capability_bindings_provider_kind_check`、`capability_definitions_provider_kind_check` 三者都恢复到 Phase 2 的 `PROMETHEUS|VICTORIALOGS`；不能只恢复 Connection 而留下 Capability/Realm 接受新 Provider。它还必须把 `asset_relationships_type_check` 精确恢复为 Phase 1 九值并同步还原 shared Go enum；任何扩展关系仍存在时 down guard 先拒绝，不能靠 constraint drop 丢失事实。

down 必须先执行上述 guard，随后在任何 extension 表被删除前，以 `CREATE OR REPLACE FUNCTION public.asset_catalog_future_source_gate_admitted(candidate public.asset_sources) RETURNS boolean` 恢复 exact `000015` reviewed predecessor definition：body 仅返回 false，language/volatility/security/ACL 与 `SET search_path = pg_catalog, public, pg_temp` 都必须使 exact UTF-8 definition digest 等于 `000015` golden。验证 predecessor digest 后逐名 drop 四表 triggers/owned constraints；再无 `CASCADE` 地依次 drop `public.transition_victoria_connection_contract(uuid,uuid,uuid,uuid,bigint,text,text)`、`public.transition_victoria_compatibility_profile(uuid,uuid,uuid,uuid,bigint,text,text)`、procedure `public.asset_catalog_create_victoria_operator_source_revision(uuid,uuid,uuid,uuid,bigint,uuid,uuid,bigint,text,text,text[],text,text,text,text)`、`public.validate_victoria_operator_source_revision_closure()`、`public.reject_victoria_operator_source_revision_mutation()`、`public.reject_victoria_published_mutation()`、`public.reject_victoria_truncate()`；then child-first drop capability child、connection contract、profile and typed-source tables。Only after namespace CHECK and every digest dependency disappear may it drop `public.victoria_namespace_allowlist_valid(text[])` and `public.victoria_operator_source_extension_digest(uuid,uuid,uuid,uuid,bigint,uuid,uuid,bigint,text,text,text[],text,text,text)`。这里的“不得 drop/recreate”只指 predecessor hook；postflight 必须证明上述九个 `000017`-owned signatures 零残留、hook 仍只有 predecessor 一签名、extension owner 不再拥有对象且仍无 schema CREATE。

down 验收必须同时证明：存在任一 Kubernetes Operator Source（包括 `UNAVAILABLE|SUSPENDED`）时整笔回滚；并发插入 typed row、创建 Source 或 gate 转换不能越过“锁定→guard→restore/drop”，只能在 down 提交后看到 predecessor 并失败关闭，或使一方锁超时/serialization failure。安全清空后 down 成功、predecessor `000015` reviewed schema-admission manifest 重新通过，且 `KUBERNETES_OPERATOR`、`AWX_INVENTORY` 都重新默认关闭；再次 up 后只有重新构造 exact typed-extension/validation closure 的 Kubernetes Operator fixture 可以恢复，旧 definition digest 或旧 validation proof 不得复用。

- [ ] **Step 5: Run migration tests**

```bash
AIOPS_TEST_POSTGRES_DSN="$AIOPS_TEST_POSTGRES_DSN" go test ./internal/store/postgres -run 'TestVictoriaMetricsEcosystemMigration' -count=1
AIOPS_TEST_POSTGRES_DSN="$AIOPS_TEST_POSTGRES_DSN" go test ./internal/store/postgres -run 'TestVictoriaDatabaseRoleAdmission' -count=1
AIOPS_TEST_POSTGRES_DSN="$AIOPS_TEST_POSTGRES_DSN" go test ./internal/assetcatalog/postgres -run 'TestVictoriaSchemaAdmission' -count=1
```

Expected: PASS, including guarded down and empty up/down/up.

- [ ] **Step 6: Commit the migration**

```bash
git add migrations/000017_victoriametrics_ecosystem.up.sql migrations/000017_victoriametrics_ecosystem.down.sql internal/store/postgres/migrations_integration_test.go internal/store/postgres/database_role_admission.go internal/store/postgres/database_role_admission_test.go internal/assetcatalog/postgres/schema_admission.go internal/assetcatalog/postgres/schema_admission_test.go internal/assetcatalog/postgres/schema_admission_integration_test.go internal/assetcatalog/postgres/migration_recovery_integration_test.go internal/assetcatalog/postgres/recovery_container_test.go internal/victoriametrics/source_profile.go internal/victoriametrics/source_profile_test.go docs/operations/database-role-bootstrap.md .github/workflows/ci.yml
git commit -m "feat(victoria): add ecosystem schema"
```

### Task 2: Add exhaustive taxonomy and eligibility rules

**Files:**
- Modify: `internal/assetcatalog/types.go`
- Modify: `internal/assetcatalog/types_test.go`
- Create: `internal/victoriametrics/taxonomy.go`
- Create: `internal/victoriametrics/taxonomy_test.go`
- Modify: `internal/connectionprofile/types.go`
- Create: `internal/connectionprofile/types_test.go`

**Interfaces:**
- Consumes: Phase 1 `assetcatalog.Kind` and Phase 2 `connectionprofile.Provider`.
- Produces: exhaustive Kind constants, taxonomy class/family/role and the only legal Target eligibility decision.
- Safety: the default branch is asset-visible but not targetable; no string-prefix inference grants a capability.

- [ ] **Step 1: Write failing table-driven taxonomy tests**

```go
func TestVictoriaTaxonomyCoversEveryKindExactlyOnce(t *testing.T)
func TestVictoriaConfigurationAndToolsNeverBecomeTargets(t *testing.T)
func TestVictoriaInsertAndStorageRolesNeverBecomeQueryTargets(t *testing.T)
func TestVMAnomalyHasNoCapability(t *testing.T)
func TestVictoriaProviderValidation(t *testing.T)
```

The first test contains the exact 37-kind list from the migration and compares it against `victoriametrics.AllKinds()`. It asserts unique membership and exact class totals: 24 long-lived, 9 configuration, 4 tool. It also asserts only Single, Select and explicitly governed Proxy roles can return `QueryEligible=true`.

- [ ] **Step 2: Run tests and verify missing constants fail**

```bash
go test ./internal/assetcatalog ./internal/connectionprofile ./internal/victoriametrics -run 'TestVictoria' -count=1
```

Expected: FAIL because the package and constants do not exist.

- [ ] **Step 3: Implement explicit enums and catalog**

Add all 37 asset constants to `assetcatalog/types.go`. Extend the existing Phase 2 `Provider` type without renaming it or creating a parallel enum:

```go
const (
    ProviderPrometheus      Provider = "PROMETHEUS"
    ProviderVictoriaMetrics Provider = "VICTORIAMETRICS"
    ProviderVictoriaLogs    Provider = "VICTORIALOGS"
    ProviderVictoriaTraces  Provider = "VICTORIATRACES"
)
```

Create these types and one literal catalog entry per Kind:

```go
package victoriametrics

type Class string
type Family string
type Role string

const (
    ClassRuntime       Class = "LONG_LIVED_RUNTIME"
    ClassConfiguration Class = "CONFIGURATION_CRD"
    ClassTool          Class = "TOOL_ARTIFACT"

    FamilyMetrics Family = "METRICS"
    FamilyLogs    Family = "LOGS"
    FamilyTraces  Family = "TRACES"
    FamilyControl Family = "CONTROL"

    RoleSingle  Role = "SINGLE"
    RoleCluster Role = "CLUSTER"
    RoleSelect  Role = "SELECT"
    RoleInsert  Role = "INSERT"
    RoleStorage Role = "STORAGE"
    RoleProxy   Role = "PROXY"
    RoleAgent   Role = "AGENT"
    RoleConfig  Role = "CONFIG"
    RoleTool    Role = "TOOL"
)

type Descriptor struct {
    Kind          assetcatalog.Kind
    Class         Class
    Family        Family
    Role          Role
    QueryEligible bool
    HealthOnly    bool
}

func Lookup(kind assetcatalog.Kind) (Descriptor, bool)
func AllKinds() []assetcatalog.Kind
func ValidateTarget(kind assetcatalog.Kind, governedProxy bool) error
```

`Lookup` reads a literal `map[assetcatalog.Kind]Descriptor`; `AllKinds` returns a sorted copy. `ValidateTarget` succeeds only for Single/Select, or Proxy with `governedProxy=true`. Cluster roots, insert, storage, agent/control, config, tools and unknown kinds return stable typed errors.

- [ ] **Step 4: Run taxonomy tests**

```bash
go test ./internal/assetcatalog ./internal/connectionprofile ./internal/victoriametrics -run 'TestVictoria|TestVMAnomaly' -count=1
```

Expected: PASS with exact coverage and no inferred eligibility.

- [ ] **Step 5: Commit taxonomy changes**

```bash
git add internal/assetcatalog/types.go internal/assetcatalog/types_test.go internal/connectionprofile/types.go internal/connectionprofile/types_test.go internal/victoriametrics/taxonomy.go internal/victoriametrics/taxonomy_test.go
git commit -m "feat(victoria): define ecosystem taxonomy"
```

### Task 3: Implement immutable compatibility profiles

**Files:**
- Create: `internal/victoriametrics/compatibility.go`
- Create: `internal/victoriametrics/compatibility_test.go`
- Create: `internal/victoriametrics/postgres/compatibility_repository.go`
- Create: `internal/victoriametrics/postgres/compatibility_repository_test.go`

**Interfaces:**
- Consumes: Scope, taxonomy descriptors, Phase 2 capability definition revisions and executor profile digests.
- Produces: exact compatibility lookup and immutable published profile persistence.
- Safety: no semver widening; unknown version, stale profile, missing capability revision or digest mismatch returns `CAPABILITY_PROFILE_INCOMPATIBLE`.

- [ ] **Step 1: Write failing domain and repository tests**

```go
func TestCompatibilityProfileRequiresExactVersionClosure(t *testing.T)
func TestCompatibilityProfileRejectsUnknownOrRevokedVersion(t *testing.T)
func TestCompatibilityProfileDigestIsOrderIndependent(t *testing.T)
func TestCompatibilityRepositoryIsScopedAndImmutable(t *testing.T)
func TestCompatibilityRepositoryRejectsMissingCapabilityRevision(t *testing.T)
```

Use real PostgreSQL for repository tests. Include one cross-Scope lookup and prove it returns `ErrNotFound`, not another tenant's profile.

- [ ] **Step 2: Run tests and verify failure**

```bash
go test ./internal/victoriametrics/... -run 'TestCompatibility' -count=1
```

Expected: FAIL because compatibility types and repository are absent.

- [ ] **Step 3: Implement the exact domain contract**

```go
type CompatibilityKey struct {
    OperatorVersion string
    ProductFamily   Family
    ProductVersion  string
    Topology        Topology
    TargetRole      Role
}

type CompatibilityProfile struct {
    ID                      string
    Revision                int64
    Scope                   assetcatalog.Scope
    Key                     CompatibilityKey
    TargetSchemaVersion     string
    ConnectorSchemaVersion  string
    EvidenceSchemaVersion   string
    ExecutorProfileDigest   string
    CapabilityDefinitions   []CapabilityDefinitionRef
    Status                  string
    ManifestDigest          string
}

type CompatibilityRepository interface {
    Publish(context.Context, CompatibilityProfile) error
    FindPublished(context.Context, assetcatalog.Scope, CompatibilityKey) (CompatibilityProfile, error)
    Get(context.Context, assetcatalog.Scope, string, int64) (CompatibilityProfile, error)
}

func (p CompatibilityProfile) Validate() error
func (p CompatibilityProfile) CanonicalManifest() ([]byte, error)
func (p CompatibilityProfile) ManifestDigest() (string, error)
```

Validation requires exact nonempty versions, known family/topology/role pairing, lowercase 64-hex digests, nonempty unique capability codes and `Status=PUBLISHED` for compile use. `CanonicalManifest` emits only the safe audit projection；`ManifestDigest` sorts capability refs by `(code,id,revision)` and implements the Task 1 exact framed child/aggregate contract。Repository reads recompute both layers and never equate JCS bytes with the persisted framed digest。

- [ ] **Step 4: Implement scoped pgx repository and concurrency behavior**

`Publish` uses `SERIALIZABLE`, locks the stable key with `pg_advisory_xact_lock`, verifies all referenced capability definitions in the same Scope, inserts the profile and items as `DRAFT`, then calls the exact `transition_victoria_compatibility_profile` function；that function supersedes the old published row before publishing the new row, so the partial unique index is never transiently violated. A concurrent duplicate with identical manifest returns the existing row; a different manifest and same revision returns `ErrConflict`.

- [ ] **Step 5: Run compatibility tests**

```bash
go test -race ./internal/victoriametrics/... -run 'TestCompatibility' -count=1
```

Expected: PASS, including concurrent publish and cross-Scope isolation.

- [ ] **Step 6: Commit compatibility implementation**

```bash
git add internal/victoriametrics/compatibility.go internal/victoriametrics/compatibility_test.go internal/victoriametrics/postgres/compatibility_repository.go internal/victoriametrics/postgres/compatibility_repository_test.go
git commit -m "feat(victoria): add exact compatibility profiles"
```

### Task 4: Implement private connection contracts and bootstrap profiles

**Files:**
- Create: `internal/victoriametrics/connection_contract.go`
- Create: `internal/victoriametrics/connection_contract_test.go`
- Create: `internal/victoriametrics/operator_source.go`
- Create: `internal/victoriametrics/operator_source_test.go`
- Create: `internal/victoriametrics/postgres/connection_contract_repository.go`
- Create: `internal/victoriametrics/postgres/connection_contract_repository_test.go`
- Create: `internal/victoriametrics/postgres/operator_source_reader.go`
- Create: `internal/victoriametrics/postgres/operator_source_reader_test.go`
- Create: `internal/victoriametrics/bootstrap.go`
- Create: `internal/victoriametrics/bootstrap_test.go`
- Modify: `internal/capability/compiler.go`
- Modify: `internal/capability/compiler_test.go`

**Interfaces:**
- Consumes: a Phase 1 Asset Source Revision transaction, eligible Asset, published Connection Revision/Compatibility Profile and 18 Phase 3 capability definitions.
- Produces: immutable 1:1 typed extension of the exact Phase 1 Source Revision, private tenant route contract, safe public summary and compiler compatibility gate.
- Safety: compiler never accepts tenant/path/header from `CompileInput`; profile bootstrap is idempotent per Scope and only seeds exact tested versions.

- [ ] **Step 1: Write failing route, redaction and compiler tests**

```go
func TestConnectionContractValidatesEveryTenantRouteMode(t *testing.T)
func TestConnectionContractPublicSummaryNeverContainsTenantValues(t *testing.T)
func TestConnectionContractManifestBindsProfileAndTenantRoute(t *testing.T)
func TestConnectionContractRepositoryIsScopedAndImmutable(t *testing.T)
func TestOperatorSourceRevisionRequiresScopedOpaqueReferencesAndSortedNamespaces(t *testing.T)
func TestOperatorSourcePreparedExtensionCreateInTxIsScopedImmutableAndIdempotent(t *testing.T)
func TestOperatorSourceExtensionUsesPhase1RegistryAndSameSerializableTransaction(t *testing.T)
func TestOperatorSourceRevisionCannotCommitWithoutPreparedExtension(t *testing.T)
func TestBootstrapPublishesOnlyExactTestedVersions(t *testing.T)
func TestCompilerRejectsIncompatibleVictoriaClosure(t *testing.T)
func TestCompilerRejectsConfigurationToolInsertAndStorageAssets(t *testing.T)
```

Scan serialized public summary and errors for the fixture values `4294967001`, `4294967002`, `/select/4294967001:4294967002/` and fail if any appears.

- [ ] **Step 2: Run tests and verify failure**

```bash
go test ./internal/victoriametrics/... ./internal/connectionprofile -run 'TestConnectionContract|TestOperatorSource|TestBootstrap|TestCompilerRejects' -count=1
```

Expected: FAIL because contracts and compile gate do not exist.

- [ ] **Step 3: Implement the immutable Operator source contract**

```go
type OperatorSourceRevision struct {
    Scope                       assetcatalog.Scope
    SourceID                    string
    Revision                    int64
    KubernetesClusterAssetID    string
    CredentialReferenceID       string
    CredentialReferenceRevision int64
    NetworkPolicyRef            string
    DiscoveryRealmRef           string
    NamespaceAllowlist          []string
    APIDiscoveryProfileDigest   string
    ArtifactInventoryDigest     string
    ManifestDigest              string
}

type OperatorSourceExtension struct{}

func (e *OperatorSourceExtension) ValidateAndDigestInTx(
    context.Context,
    assetcatalog.SourceRevisionTx,
    assetcatalog.SourceRevisionDraft,
) (assetcatalog.PreparedExtension, error)

type OperatorSourceReader interface {
    GetPublished(context.Context, assetcatalog.Scope, string) (OperatorSourceRevision, error)
}
```

`VICTORIAMETRICS_OPERATOR_V1` Source Profile 必须在 bootstrap 时把无 Repository/DB 字段的纯领域 `OperatorSourceExtension` 注册到 Phase 1 `TypedSourceExtensionRegistry`，并只消费 Task 1-owned immutable `OperatorProfileManifestV1()` fixture；其 RFC 8785 bytes/hash 同时由 `000017` migration literal、Phase 1 `SourceProfileAdmissionResolver` 与 registry parity test 固定，任一 byte drift fail closed，不得重新生成 fixture 或直接调用 writable typed repository。Phase 1 `SourceRevisionRepository` 是唯一事务 owner：它启动同一个 `SERIALIZABLE` transaction，锁定 stable Source 后只把 repository-created `assetcatalog.SourceRevisionTx` narrow Session facade 传给 `ValidateAndDigestInTx`；separate `revisioncap.Controller` 仅由 Phase 1 PostgreSQL owner 持有。Extension 只能用 closed `LookupFact` 读取 same-Scope Cluster Asset、Credential Reference、Network/Realm/Runtime digest 并规范化 Namespace/canonical document；它看不到 controller、SQL、pgx row/connection 或 transaction control。返回的 immutable Prepared object 封存 canonical bytes 与 prepared-extension digest；该 digest 与 extension code 只进入 Task 2 BindingDigest 的独立第 19/20 帧，`source_definition_digest` remains the Provider/Profile definition and never absorbs source-specific binding or typed extension。base revision insert 后，owner 用 Controller `ArmCreate`，Prepared `CreateInTx` 只调用一次 facade `CreateOwnExtension`；固定 procedure 写入 1:1 row 后由 Controller `VerifyCreated` 重读/恒时比对，再写 Audit/Outbox 并由外层 commit。Controller `Close` 使所有 retained Session copies 失效，任何 validation-time write、create-time read、second write、use-after-close、digest/insert/hook 漂移整笔回滚。typed package 不得拥有 begin/commit/retry 或独立 create lifecycle；测试证明恶意 extension 无法取得 controller/SQL/pgx、提前 commit/rollback 或修改 base/audit 表。

`victoria_operator_source_revisions` has no independent status、actor、publish/supersede/revoke path. It is an append-only 1:1 typed extension keyed by the exact Phase 1 `(Tenant,Workspace,Source,Revision)` and is written only by the frozen Phase 1 extension procedure in the same outer `SERIALIZABLE` transaction that inserts the base Revision and authority child；the Victoria PostgreSQL package exposes read-only `GetPublished` and no create/update/publish method. Validation sorts and deduplicates `NamespaceAllowlist`, requires a same-Scope Kubernetes cluster Asset and exact Credential Reference revision with purpose `KUBERNETES_DISCOVERY_READ`, and validates network/realm/discovery/inventory content-addressed refs. Base/typed equality is mandatory：`base.credential_reference_id=typed.credential_reference_id::text` and `base.network_policy_reference_id=typed.network_policy_ref`；the independently resolved base Trust Reference is the API-server trust bundle，while `typed.discovery_realm_ref` is the Runner Realm. Its stored `prepared_extension_digest` is exactly lowercase `SHA256(FramedTupleV1("victoria-operator-source-extension.v1",tenant_id,workspace_id,environment_id,source_id,minimal-decimal revision,kubernetes_cluster_asset_id,credential_reference_id,minimal-decimal credential_reference_revision,network_policy_ref,discovery_realm_ref,minimal-decimal namespace count,repeated sorted namespace,raw api_discovery_profile_digest,raw artifact_inventory_digest,raw manifest_digest))`；`created_at` is excluded. The fixed procedure recomputes this value only from its scalar arguments/inserted row and compares the caller's expected digest；it never reads the base revision。The deferred base/typed closure and Phase 1 Controller reread are authoritative：they compare the persisted base `prepared_extension_digest` to the exact inserted row before Audit/Outbox，so an optimistic caller SHA cannot establish equality. The Source Profile is `SINGLE_ENVIRONMENT`, so the sole base authority Environment must equal this extension/cluster Environment. The artifact inventory is a signed private manifest of explicitly managed workload UID + OCI digest + taxonomy kind；it contains no environment/argument/config/credential data. Only the Phase 1 revision lifecycle may validate/publish/supersede the joined revision. Publishing a new canonical revision is the only path that clears its checkpoint and closes the old gate; runtime token/resourceVersion expiry must instead use Phase 1 `CHECKPOINT_LINEAGE_ROLLOVER` and must never invoke the extension hook as a same-revision reset. `GetPublished` joins exact base+extension rows, recomputes this extension digest and the Task 2 20-frame BindingDigest, and fails closed unless base status/pointer/digests are current.

- [ ] **Step 4: Implement the private/public connection split**

```go
type TenantRouteMode string

const (
    TenantRouteSingleDefault         TenantRouteMode = "SINGLE_DEFAULT"
    TenantRouteMetricsClusterPath    TenantRouteMode = "METRICS_CLUSTER_PATH"
    TenantRouteMetricsClusterHeaders TenantRouteMode = "METRICS_CLUSTER_HEADERS"
    TenantRouteLogsHeaders           TenantRouteMode = "LOGS_HEADERS"
    TenantRouteTracesHeaders         TenantRouteMode = "TRACES_HEADERS"
    TenantRouteGovernedProxy         TenantRouteMode = "GOVERNED_PROXY"
)

type TenantRoute struct {
    Mode               TenantRouteMode
    AccountID          *uint32
    ProjectID          *uint32
    RouteProfileDigest string
}

type ConnectionContract struct {
    Scope                      assetcatalog.Scope
    ConnectionID               string
    ConnectionRevision         int64
    Family                     Family
    Topology                   Topology
    TargetRole                 Role
    TenantRoute                TenantRoute
    ProductVersion             string
    OperatorVersion            string
    CompatibilityProfileID     string
    CompatibilityRevision      int64
    CompatibilityProfileDigest string
    HiddenFieldsProfileDigest  string
    Status                     string
    ManifestDigest             string
}

type PublicContractSummary struct {
    Family                     Family          `json:"family"`
    Topology                   Topology        `json:"topology"`
    TargetRole                 Role            `json:"target_role"`
    TenantRouteMode            TenantRouteMode `json:"tenant_route_mode"`
    ProductVersion             string          `json:"product_version"`
    OperatorVersion            string          `json:"operator_version"`
    CompatibilityProfileDigest string          `json:"compatibility_profile_digest"`
    Status                     string          `json:"status"`
}

func (c ConnectionContract) Validate() error
func (c ConnectionContract) PublicSummary() PublicContractSummary
func (c ConnectionContract) CanonicalManifest() ([]byte, error)
func (c ConnectionContract) ManifestDigest() (string, error)
```

Only the private Target compiler receives `TenantRoute`. Logs/Traces/header-mode Metrics require both uint32 values; Single requires `0/0`; Proxy requires only a route profile digest. No `json` tag is added to private route fields. The repository publishes by starting `SERIALIZABLE`、locking the stable Connection key and referenced published compatibility profile/children、inserting the contract as `DRAFT` with the Go-computed Task 1 framed digest，then calling exact `transition_victoria_connection_contract(..., expected_digest, 'PUBLISHED')`；the SQL transition independently recomputes profile and contract digests，supersedes the prior published row first and rejects any stale/random digest before state change。Reads recompute again；no fixture or manual SQL may create a production `PUBLISHED` contract。

- [ ] **Step 5: Bootstrap the exact initial profile set**

`BootstrapCatalog.EnsureScope` publishes capability definitions first, then profiles for legal target roles:

```go
var InitialVersions = struct {
    Operator string
    Metrics  string
    Logs     string
    Traces   string
}{
    Operator: "0.73.1",
    Metrics:  "1.147.0",
    Logs:     "1.51.0",
    Traces:   "0.9.4",
}
```

Create profiles for Metrics Single/Select/Governed Proxy, Logs Single/Select/Governed Proxy and Traces Single/Select/Governed Proxy. Each profile includes only its family's six capability definition revisions and exact schema/profile digests supplied by the runtime packages; a second identical bootstrap performs zero inserts.

- [ ] **Step 6: Gate compilation on the full closure**

Before Phase 2 compiler emits any Victoria artifact, it must verify asset is ACTIVE/EXACT, taxonomy target eligibility, contract is PUBLISHED, compatibility profile is PUBLISHED, every schema version/digest equals the connector/target/evidence/executor inputs, and the referenced runtime publication is APPLIED. Return `CAPABILITY_PROFILE_INCOMPATIBLE` without leaking which private tenant field differed.

- [ ] **Step 7: Run contract and compiler tests**

```bash
go test -race ./internal/victoriametrics/... ./internal/connectionprofile -run 'TestConnectionContract|TestOperatorSource|TestBootstrap|TestCompilerRejects' -count=1
```

Expected: PASS; public JSON contains neither account/project values nor routes.

- [ ] **Step 8: Commit contracts and bootstrap**

```bash
git add internal/victoriametrics/connection_contract.go internal/victoriametrics/connection_contract_test.go internal/victoriametrics/operator_source.go internal/victoriametrics/operator_source_test.go internal/victoriametrics/postgres/connection_contract_repository.go internal/victoriametrics/postgres/connection_contract_repository_test.go internal/victoriametrics/postgres/operator_source_reader.go internal/victoriametrics/postgres/operator_source_reader_test.go internal/victoriametrics/bootstrap.go internal/victoriametrics/bootstrap_test.go internal/capability/compiler.go internal/capability/compiler_test.go
git commit -m "feat(victoria): bind tenant and version contracts"
```

## Pack Completion Gate

Run from repository root:

```bash
AIOPS_TEST_POSTGRES_DSN="$AIOPS_TEST_POSTGRES_DSN" go test ./internal/store/postgres -run 'TestVictoriaMetricsEcosystemMigration' -count=1
go test -race ./internal/assetcatalog ./internal/connectionprofile ./internal/victoriametrics/... -count=1
go vet ./internal/assetcatalog ./internal/connectionprofile ./internal/victoriametrics/...
git diff --check
```

Expected: all commands exit 0; 37 kinds are exhaustive, four schema tables are scoped/immutable, public contract projections contain no tenant value, and unknown versions cannot compile.
