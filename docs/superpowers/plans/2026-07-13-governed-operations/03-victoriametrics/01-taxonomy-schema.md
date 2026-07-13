# VictoriaMetrics Taxonomy and Schema Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 建立 VictoriaMetrics 生态的完整资产分类、`000017` 持久契约、版本兼容 profile 和服务端租户路由，使后续发现与只读能力只能在精确闭包内工作。

**Architecture:** 扩展统一 Asset Kind 与 Connection Provider，不建立第二套资产表；新增不可变 Operator source revision、Compatibility profile 和 Connection contract revision。查询租户值只存在于私有 contract，公共 projection 只返回 mode/digest；兼容矩阵以精确测试版本起步，未知版本 fail closed。

**Tech Stack:** Go 1.26.5、PostgreSQL 18.4+、pgx v5、RFC 8785 JCS、SHA-256、标准库 `testing`。

## Global Constraints

- 每个 Task 严格采用 Red → Green → Refactor：先运行并保存预期失败，再做最小生产实现，复跑指定测试后才允许重构和提交。
- migration 固定为 `000017_victoriametrics_ecosystem`，并显式要求 `000015` 与 `000016` 已存在。
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

**Interfaces:**
- Consumes: `assets` and `asset_sources` from `000015`; `credential_reference_revisions`, `connection_revisions`, `capability_definitions` and `runtime_publications` from `000016`.
- Produces: expanded Asset/Provider constraints and four immutable, Scope-bound Victoria-specific contract relations.
- Safety: down migration refuses while any Victoria asset/provider/source/contract/profile remains; no secret-bearing column is permitted.

The migration owns exactly these new relations:

| Relation | Identity | Purpose |
|---|---|---|
| `victoria_operator_source_revisions` | Scope + source + revision | cluster/namespace/API-discovery/opaque credential/network/realm closure |
| `victoria_compatibility_profiles` | Scope + profile + revision | exact Operator/product/schema/executor compatibility |
| `victoria_compatibility_capabilities` | Scope + profile revision + capability definition revision | closed allowlist of compiled read capabilities |
| `victoria_connection_contracts` | Scope + connection revision | target role/topology/private tenant route/profile closure |

- [ ] **Step 1: Write failing real-PostgreSQL migration tests**

Add these exact test cases:

```go
func TestVictoriaMetricsEcosystemMigrationRequiresPhaseOneAndTwo(t *testing.T)
func TestVictoriaMetricsEcosystemMigrationAcceptsEveryVictoriaAssetKind(t *testing.T)
func TestVictoriaMetricsEcosystemMigrationEnforcesScopedForeignKeys(t *testing.T)
func TestVictoriaMetricsEcosystemMigrationRejectsTenantRangeAndModeMismatch(t *testing.T)
func TestVictoriaMetricsEcosystemMigrationMakesPublishedContractsImmutable(t *testing.T)
func TestVictoriaMetricsEcosystemMigrationDownRefusesPersistedState(t *testing.T)
func TestVictoriaMetricsEcosystemMigrationRoundTripsEmptyDatabase(t *testing.T)
```

Assert all 37 new kinds insert successfully; an unlisted kind fails `assets_kind_check`; `VICTORIAMETRICS` and `VICTORIATRACES` providers are accepted while arbitrary provider text is rejected; cross-Scope FKs fail; tenant values outside `0..4294967295` fail; published rows reject UPDATE/DELETE with SQLSTATE `55000`; non-empty down names constraint `victoria_ecosystem_down_guard`; empty up/down/up succeeds.

- [ ] **Step 2: Run the focused test and verify the expected failure**

```bash
AIOPS_TEST_POSTGRES_DSN="$AIOPS_TEST_POSTGRES_DSN" go test ./internal/store/postgres -run 'TestVictoriaMetricsEcosystemMigration' -count=1
```

Expected: FAIL because migration `000017_victoriametrics_ecosystem` is absent.

- [ ] **Step 3: Implement the up migration in one transaction**

Use the complete constraint shape below. Preserve every Phase 1 kind and the legacy `PROMETHEUS` provider.

```sql
BEGIN;

DO $$
BEGIN
    IF to_regclass('public.assets') IS NULL
       OR to_regclass('public.connection_revisions') IS NULL
       OR to_regclass('public.runtime_publications') IS NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = '000015 and 000016 are required',
            CONSTRAINT = 'victoria_ecosystem_prerequisite';
    END IF;
END;
$$;

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
    network_policy_ref text NOT NULL,
    discovery_realm_ref text NOT NULL
        CHECK (discovery_realm_ref ~ '^[a-z0-9][a-z0-9_.-]{0,59}-v1-[a-f0-9]{64}$'),
    namespace_allowlist text[] NOT NULL CHECK (cardinality(namespace_allowlist) BETWEEN 1 AND 128),
    api_discovery_profile_digest text NOT NULL CHECK (api_discovery_profile_digest ~ '^[a-f0-9]{64}$'),
    artifact_inventory_digest text NOT NULL CHECK (artifact_inventory_digest ~ '^[a-f0-9]{64}$'),
    status text NOT NULL CHECK (status IN ('DRAFT','PUBLISHED','SUPERSEDED','REVOKED')),
    manifest_digest text NOT NULL CHECK (manifest_digest ~ '^[a-f0-9]{64}$'),
    created_by text NOT NULL,
    created_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id,workspace_id,environment_id,source_id,revision),
    FOREIGN KEY (tenant_id,workspace_id,source_id)
        REFERENCES asset_sources (tenant_id,workspace_id,id),
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

COMMIT;
```

Add one trigger function `reject_victoria_published_mutation()` and attach it to all four tables so any UPDATE/DELETE of a row whose status is `PUBLISHED|SUPERSEDED|REVOKED`, or whose parent profile is published, raises SQLSTATE `55000`. Add partial unique indexes allowing one `PUBLISHED` source revision, profile tuple and connection contract per stable identity.

- [ ] **Step 4: Implement the guarded down migration**

The down migration first rejects any Victoria row or provider/asset. It then drops triggers and tables in reverse FK order, restores provider and asset constraints to the exact Phase 1/2 values, and commits.

```sql
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM victoria_connection_contracts)
       OR EXISTS (SELECT 1 FROM victoria_compatibility_capabilities)
       OR EXISTS (SELECT 1 FROM victoria_compatibility_profiles)
       OR EXISTS (SELECT 1 FROM victoria_operator_source_revisions)
       OR EXISTS (SELECT 1 FROM connection_profiles WHERE provider_kind IN ('VICTORIAMETRICS','VICTORIATRACES'))
       OR EXISTS (SELECT 1 FROM runner_capability_bindings WHERE provider_kind IN ('VICTORIAMETRICS','VICTORIATRACES'))
       OR EXISTS (SELECT 1 FROM capability_definitions WHERE provider_kind IN ('VICTORIAMETRICS','VICTORIATRACES'))
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

空状态回滚必须把 `connection_profiles_provider_kind_check`、`runner_capability_bindings_provider_kind_check`、`capability_definitions_provider_kind_check` 三者都恢复到 Phase 2 的 `PROMETHEUS|VICTORIALOGS`；不能只恢复 Connection 而留下 Capability/Realm 接受新 Provider。

- [ ] **Step 5: Run migration tests**

```bash
AIOPS_TEST_POSTGRES_DSN="$AIOPS_TEST_POSTGRES_DSN" go test ./internal/store/postgres -run 'TestVictoriaMetricsEcosystemMigration' -count=1
```

Expected: PASS, including guarded down and empty up/down/up.

- [ ] **Step 6: Commit the migration**

```bash
git add migrations/000017_victoriametrics_ecosystem.up.sql migrations/000017_victoriametrics_ecosystem.down.sql internal/store/postgres/migrations_integration_test.go
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
func (p CompatibilityProfile) CanonicalManifest() ([]byte, string, error)
```

Validation requires exact nonempty versions, known family/topology/role pairing, lowercase 64-hex digests, nonempty unique capability codes and `Status=PUBLISHED` for compile use. Canonicalization sorts capability refs by `(code,id,revision)`, emits JCS bytes and compares SHA-256 to persisted digest.

- [ ] **Step 4: Implement scoped pgx repository and concurrency behavior**

`Publish` uses `SERIALIZABLE`, locks the stable key with `pg_advisory_xact_lock`, verifies all referenced capability definitions in the same Scope, inserts profile and items, then marks the prior published row `SUPERSEDED` only through a dedicated transition function. A concurrent duplicate with identical manifest returns the existing row; a different manifest and same revision returns `ErrConflict`.

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
- Create: `internal/victoriametrics/postgres/operator_source_repository.go`
- Create: `internal/victoriametrics/postgres/operator_source_repository_test.go`
- Create: `internal/victoriametrics/bootstrap.go`
- Create: `internal/victoriametrics/bootstrap_test.go`
- Modify: `internal/capability/compiler.go`
- Modify: `internal/capability/compiler_test.go`

**Interfaces:**
- Consumes: a published Asset Source/Connection Revision, eligible Asset, published Compatibility Profile and 18 Phase 3 capability definitions.
- Produces: immutable Operator Source Revision, private tenant route contract, safe public summary and compiler compatibility gate.
- Safety: compiler never accepts tenant/path/header from `CompileInput`; profile bootstrap is idempotent per Scope and only seeds exact tested versions.

- [ ] **Step 1: Write failing route, redaction and compiler tests**

```go
func TestConnectionContractValidatesEveryTenantRouteMode(t *testing.T)
func TestConnectionContractPublicSummaryNeverContainsTenantValues(t *testing.T)
func TestConnectionContractManifestBindsProfileAndTenantRoute(t *testing.T)
func TestConnectionContractRepositoryIsScopedAndImmutable(t *testing.T)
func TestOperatorSourceRevisionRequiresScopedOpaqueReferencesAndSortedNamespaces(t *testing.T)
func TestOperatorSourceRepositoryIsScopedImmutableAndIdempotent(t *testing.T)
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
    Status                      string
    ManifestDigest              string
}

type OperatorSourceRepository interface {
    Publish(context.Context, OperatorSourceRevision) error
    GetPublished(context.Context, assetcatalog.Scope, string) (OperatorSourceRevision, error)
}
```

Validation sorts and deduplicates `NamespaceAllowlist`, requires a same-Scope Kubernetes cluster Asset and Credential Reference revision, and validates network/realm/discovery/inventory content-addressed refs. The artifact inventory is a signed private manifest of explicitly managed workload UID + OCI digest + taxonomy kind；it contains no environment/argument/config/credential data. Publish uses a Scope-bound transaction and immutable revision/idempotency rules identical to compatibility profiles.

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
func (c ConnectionContract) CanonicalManifest() ([]byte, string, error)
```

Only the private Target compiler receives `TenantRoute`. Logs/Traces/header-mode Metrics require both uint32 values; Single requires `0/0`; Proxy requires only a route profile digest. No `json` tag is added to private route fields.

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
git add internal/victoriametrics/connection_contract.go internal/victoriametrics/connection_contract_test.go internal/victoriametrics/operator_source.go internal/victoriametrics/operator_source_test.go internal/victoriametrics/postgres/connection_contract_repository.go internal/victoriametrics/postgres/connection_contract_repository_test.go internal/victoriametrics/postgres/operator_source_repository.go internal/victoriametrics/postgres/operator_source_repository_test.go internal/victoriametrics/bootstrap.go internal/victoriametrics/bootstrap_test.go internal/capability/compiler.go internal/capability/compiler_test.go
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
