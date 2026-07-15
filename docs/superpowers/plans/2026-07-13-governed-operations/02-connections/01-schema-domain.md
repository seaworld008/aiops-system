# Connection Schema and Domain Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 建立 ConnectionProfile/Revision、Credential Reference、Validation、Operation、Published Target/Capability 和 Runtime Publication 的 000016 数据契约与纯领域状态机。

**Architecture:** PostgreSQL 以 Tenant/Workspace/Environment 复合 Scope、不可变修订、显式状态约束和有保护的 down migration 保证持久真相；Go 领域层只接受安全引用并拒绝隐式状态跳转。

**Tech Stack:** Go 1.26.5、PostgreSQL 18.4+、pgx v5、标准库 testing、JCS/SHA-256。

## Global Constraints

- 每个 Task 严格采用 Red → Green → Refactor：先运行并保存预期失败，再做最小生产实现，复跑指定测试后才允许重构和提交。
- 这是生产级连接发布闭环的第一包，不是 demo；测试 fake 不得进入生产装配。
- migration 编号固定为 `000016`，必须在 `000015` Operational Asset Catalog 之后。
- 所有表的业务主键和外键都绑定 `tenant_id/workspace_id/environment_id`；禁止只凭 UUID 跨 Scope 关联。
- Profile 是稳定身份；Revision、Credential Reference Revision、Capability Definition、Published Target/Set、Runtime Artifact 一经发布不可原地修改。
- Endpoint 只接受 HTTPS 身份；Trust、Network Policy、Credential、Realm 都是 opaque/content-addressed reference，不保存 secret、token、DSN、PEM、Vault path。
- Validation 与 Investigation 使用独立 Pool/Realm；本阶段只建立只读连接发布基础，不提前开放受治理写执行。
- 异步正确性来自持久 Operation、lease、fencing 和 cleanup receipt，不依赖进程内状态。
- 新增行为严格 TDD：先确认测试因缺失能力失败，再写最小实现；每个任务末有独立 commit。

## Prerequisite Interfaces

Consumes from `000015`:

```go
type Scope struct {
    TenantID string
    WorkspaceID string
    EnvironmentID string
}

type Asset struct {
    ID string
    Scope Scope
    Type string
    ServiceID string
    Lifecycle string
    MappingStatus string
    Version int64
}

type Reader interface {
    Get(context.Context, Scope, string) (Asset, error)
}
```

Connection bootstrap admits a source-valid, same-Scope Asset only when `MappingStatus == EXACT` and `Lifecycle` is `DISCOVERED`, `STALE`, or `ACTIVE`. `QUARANTINED`, `RETIRED`, `MISSING`, `AMBIGUOUS`, source-invalid, and cross-Scope assets are rejected before validation. Validation/publication does not itself authorize investigation; only an exactly applied Runtime plus terminal credential cleanup may activate `DISCOVERED|STALE` through the Phase 1 lifecycle repository, and live admission still requires `ACTIVE+EXACT+PUBLISHED+AVAILABLE`.

### Task 1: Add the 000016 database contract

**Files:**
- Create: `migrations/000016_connection_runtime_publication.up.sql`
- Create: `migrations/000016_connection_runtime_publication.down.sql`
- Modify: `internal/store/postgres/migrations_integration_test.go`

**Interfaces:**
- Consumes: `assets(tenant_id, workspace_id, environment_id, id)`；existing `runner_registrations` and Runner pool constraint；PostgreSQL UUID/JSONB/timestamptz/check/trigger support。
- Produces: scoped schemas for Realm、Credential Reference、Connection Revision、Capability Definition、Validation、Operation、Published Target/Capability、Runtime Publication。

The migration owns these relations:

| Relation | Identity | Required invariants |
|---|---|---|
| `runner_realms` | Scope + `id` | stable `mode × adapter_family × network_zone` identity；mode `VALIDATION|READ`、immutable revision、enabled flag |
| `runner_capability_bindings` | Scope + Realm + provider + capability + revision | fixed allowlist；at most one AVAILABLE revision per tuple |
| `credential_references` | Scope + `id` | stable identity and latest revision only |
| `credential_reference_revisions` | Scope + id + revision | issuer metadata only, immutable |
| `connection_profiles` | Scope + `id` | Asset FK, provider, owner, ACTIVE/REVOKED, version |
| `connection_revisions` | Scope + connection + revision | endpoint/trust/credential/network/realm refs |
| `connection_revision_capabilities` | Scope + connection + revision + capability | bounded budgets |
| `capability_definitions` | Scope + id + revision | typed template/result policy, immutable |
| `control_plane_operations` | Scope + `id` | durable idempotent asynchronous state |
| `connection_validation_runs` | Scope + `id` | lease owner/attempt/fencing/deadline/cleanup |
| `connection_validation_checks` | Scope + run + check | fixed low-sensitivity status/digest |
| `validation_credential_revocations` | Scope + run + attempt | durable cleanup receipt |
| `published_targets` | Scope + `id` | captured connection closure and digest |
| `published_capability_sets` | Scope + `id` | closed-by-gate immutable set |
| `published_capability_set_items` | Scope + set + capability | compiled limits/digest |
| `runtime_publications` | Scope + `id` | bundle/deployment digest and rollout status |
| `runtime_publication_artifacts` | Scope + publication + closed kind | canonical bytes/schema/SHA-256；named `runtime_publication_artifacts_kind_check` initially permits exactly `CONNECTOR_MANIFEST|TARGET_MANIFEST|EGRESS_MANIFEST|TRUST_CLOSURE` |

- [ ] **Step 1: Write failing real-PostgreSQL migration tests**

Add these exact test cases:

```go
func TestConnectionMigrationEnforcesScopeAndImmutableRevisions(t *testing.T)
func TestConnectionMigrationRejectsInvalidStateTransitions(t *testing.T)
func TestValidationLeaseUsesMonotonicAttemptAndFencing(t *testing.T)
func TestRuntimePublicationAllowsOneActiveRevisionPerConnection(t *testing.T)
func TestConnectionMigrationDownRefusesPersistedState(t *testing.T)
func TestConnectionMigrationRoundTripsEmptyDatabase(t *testing.T)
```

Assertions:

- cross-Scope Asset/Credential/Realm/Capability FK inserts fail;
- Realm rejects unsupported mode/adapter/network-zone, and a VALIDATION worker cannot bind a READ Realm (or the reverse);
- Revision input fields and published rows reject UPDATE/DELETE;
- only `DRAFT→VALIDATING→VALIDATED|REJECTED`, `VALIDATED→PUBLISHED`, `PUBLISHED→SUPERSEDED|REVOKED` are accepted;
- `VALIDATED` requires result digest and revoked/no-credential cleanup;
- stale fencing token cannot heartbeat or complete;
- one Connection has at most one current PUBLISHED Revision;
- non-empty down returns SQLSTATE `55000` and constraint `connection_runtime_publication_down_guard`;
- empty up/down/up succeeds.

- [ ] **Step 2: Run the focused test and verify failure**

Run:

```bash
AIOPS_TEST_POSTGRES_DSN="$AIOPS_TEST_POSTGRES_DSN" go test ./internal/store/postgres -run 'TestConnectionMigration|TestValidationLease|TestRuntimePublication' -count=1
```

Expected: FAIL because `000016` does not exist.

- [ ] **Step 3: Implement the up migration in dependency order**

Start a transaction, reject missing prerequisites, then create the relations in the ownership table.

```sql
BEGIN;

DO $$
BEGIN
    IF to_regclass('public.assets') IS NULL
       OR to_regclass('public.runner_registrations') IS NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = '000015 asset catalog and runner registrations are required',
            CONSTRAINT = 'connection_runtime_publication_prerequisite';
    END IF;
END;
$$;

ALTER TABLE runner_registrations
    DROP CONSTRAINT runner_registrations_pool_ck,
    ADD CONSTRAINT runner_registrations_pool_ck
        CHECK (runner_pool IN ('READ', 'WRITE', 'VALIDATION')),
    ADD COLUMN runner_realm_id uuid;

CREATE TABLE runner_realms (
    tenant_id uuid NOT NULL,
    workspace_id uuid NOT NULL,
    environment_id uuid NOT NULL,
    id uuid NOT NULL,
    mode text NOT NULL CHECK (mode IN ('VALIDATION', 'READ')),
    adapter_family text NOT NULL CHECK (adapter_family IN (
        'PROMETHEUS', 'VICTORIALOGS', 'VICTORIATRACES',
        'HOST_PROBE_MTLS', 'AWX_API', 'POSTGRESQL'
    )),
    network_zone text NOT NULL
        CHECK (network_zone ~ '^[a-z0-9][a-z0-9_.-]{0,63}$'),
    reference text NOT NULL,
    revision bigint NOT NULL CHECK (revision > 0),
    trust_domain text NOT NULL,
    enabled boolean NOT NULL DEFAULT false,
    version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, workspace_id, environment_id, id),
    UNIQUE (tenant_id, workspace_id, environment_id, reference, revision),
    UNIQUE (tenant_id, workspace_id, environment_id,
            mode, adapter_family, network_zone, revision)
);

CREATE TABLE connection_profiles (
    tenant_id uuid NOT NULL,
    workspace_id uuid NOT NULL,
    environment_id uuid NOT NULL,
    id uuid NOT NULL,
    asset_id uuid NOT NULL,
    provider_kind text NOT NULL
        CONSTRAINT connection_profiles_provider_kind_check
        CHECK (provider_kind IN ('PROMETHEUS', 'VICTORIALOGS')),
    display_name text NOT NULL
        CHECK (char_length(display_name) BETWEEN 1 AND 128),
    status text NOT NULL CHECK (status IN ('ACTIVE', 'REVOKED')),
    version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
    created_by text NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, workspace_id, environment_id, id),
    FOREIGN KEY (tenant_id, workspace_id, environment_id, asset_id)
        REFERENCES assets (tenant_id, workspace_id, environment_id, id)
);
```

Apply these exact cross-cutting constraints to all remaining tables:

- endpoint scheme `https`, port `1..65535`, host equals verified server name;
- references match `^[a-z0-9][a-z0-9_.-]{0,59}-v1-[a-f0-9]{64}$`;
- capability duration `1..20` seconds, items `1..1000`, bytes `1024..1048576`;
- Operation progress `0..100` and terminal rows require `completed_at`;
- `runner_capability_bindings` contains Scope、realm_id、provider_kind、capability_kind、revision、status、binding_digest；its FK references `runner_realms(Scope,id)`，unique key is `(Scope,realm_id,provider_kind,capability_kind,revision)`，and a partial unique index permits at most one `status='AVAILABLE'` row for the tuple；a trigger rejects provider/adapter mismatch and bindings whose capability mode differs from Realm mode;
- `runner_registrations` receives the full `(tenant_id,workspace_id,environment_id,runner_realm_id)` FK；registration pool must equal Realm mode (`VALIDATION` or `READ`) at registration/heartbeat admission, never only in UI configuration;
- `published_targets` has candidate key `UNIQUE (tenant_id,workspace_id,environment_id,target_ref)` in addition to its scoped primary key；`target_ref` is content-addressed and immutable so 000018 can reference the exact published Target without an unscoped FK;
- Provider checks use stable names `connection_profiles_provider_kind_check`、`runner_capability_bindings_provider_kind_check` and `capability_definitions_provider_kind_check`；000016 permits only `PROMETHEUS|VICTORIALOGS`，so later migrations can transactionally extend and safely restore the exact predecessor allowlist;
- lease deadline is after claim/start; fencing token and attempt are positive;
- cleanup is `PENDING|REVOKED|NO_CREDENTIAL|FAILED` and only REVOKED/NO_CREDENTIAL permits successful validation;
- all SHA-256 columns are 64 lowercase hex;
- partial unique indexes permit one nonterminal validate/publish Operation per Revision and one active Runtime Publication per Connection;
- immutable triggers reject published/revision input UPDATE or DELETE with SQLSTATE `55000`.

- [ ] **Step 4: Implement the guarded down migration**

The guard checks every `000016` state table and VALIDATION registration before any drop. If empty, drop triggers while their tables exist, then tables in reverse FK order, restore Runner pool to `READ|WRITE`, drop Realm, and commit.

```sql
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM runtime_publications)
       OR EXISTS (SELECT 1 FROM published_targets)
       OR EXISTS (SELECT 1 FROM connection_validation_runs)
       OR EXISTS (SELECT 1 FROM control_plane_operations)
       OR EXISTS (SELECT 1 FROM connection_revisions)
       OR EXISTS (SELECT 1 FROM connection_profiles)
       OR EXISTS (SELECT 1 FROM credential_reference_revisions)
       OR EXISTS (
           SELECT 1 FROM runner_registrations
           WHERE runner_pool = 'VALIDATION' OR runner_realm_id IS NOT NULL
       ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'unsafe connection runtime publication rollback: state remains',
            CONSTRAINT = 'connection_runtime_publication_down_guard';
    END IF;
END;
$$;
```

- [ ] **Step 5: Run migration tests**

Run:

```bash
AIOPS_TEST_POSTGRES_DSN="$AIOPS_TEST_POSTGRES_DSN" go test ./internal/store/postgres -run 'TestConnectionMigration|TestValidationLease|TestRuntimePublication' -count=1
```

Expected: PASS；Scope、immutable、transition、lease、single-publication 和 guarded rollback assertions all pass.

- [ ] **Step 6: Commit**

```bash
git add migrations/000016_connection_runtime_publication.up.sql migrations/000016_connection_runtime_publication.down.sql internal/store/postgres/migrations_integration_test.go
git commit -m "feat: add connection runtime publication schema"
```

### Task 2: Implement Connection, Credential Reference and Operation domains

**Files:**
- Create: `internal/connectionprofile/types.go`
- Create: `internal/connectionprofile/revision.go`
- Create: `internal/connectionprofile/revision_test.go`
- Create: `internal/credentialreference/reference.go`
- Create: `internal/credentialreference/reference_test.go`
- Create: `internal/operation/operation.go`
- Create: `internal/operation/operation_test.go`

**Interfaces:**
- Consumes: `assetcatalog.Asset` and `assetcatalog.Scope`。
- Produces: pure constructors/transitions, opaque Credential Reference public projection, durable Operation state model。

- [ ] **Step 1: Write failing domain and redaction tests**

```go
func TestNewProfileRequiresSourceValidExactScopedBootstrapAsset(t *testing.T)
func TestRevisionStateMachineRejectsSkippedTransitions(t *testing.T)
func TestValidatedRevisionRequiresResultDigestAndCredentialCleanup(t *testing.T)
func TestCredentialReferencePublicProjectionCannotLeakMaterial(t *testing.T)
func TestOperationRequiresTerminalFailureCodeConsistency(t *testing.T)
```

The projection test marshals JSON and rejects case-insensitive keys `token`, `secret`, `password`, `private_key`, `vault_path`, `vault_url`, `dsn`, `pem`, `accessor` and `ciphertext`; it requires `"redacted":true`.

- [ ] **Step 2: Run tests and verify failure**

Run:

```bash
go test ./internal/connectionprofile ./internal/credentialreference ./internal/operation -count=1
```

Expected: FAIL because packages/types are absent.

- [ ] **Step 3: Implement exact domain contracts**

```go
type Provider string
type ProfileStatus string
type RevisionStatus string
type CredentialCleanup string

const (
    ProviderPrometheus Provider = "PROMETHEUS"
    ProviderVictoriaLogs Provider = "VICTORIALOGS"
    ProfileActive ProfileStatus = "ACTIVE"
    ProfileRevoked ProfileStatus = "REVOKED"
    RevisionDraft RevisionStatus = "DRAFT"
    RevisionValidating RevisionStatus = "VALIDATING"
    RevisionValidated RevisionStatus = "VALIDATED"
    RevisionRejected RevisionStatus = "REJECTED"
    RevisionPublished RevisionStatus = "PUBLISHED"
    RevisionRevoked RevisionStatus = "REVOKED"
    RevisionSuperseded RevisionStatus = "SUPERSEDED"
    CredentialCleanupRevoked CredentialCleanup = "REVOKED"
    CredentialCleanupNoCredential CredentialCleanup = "NO_CREDENTIAL"
)

type EndpointIdentity struct {
    Scheme string
    Host string
    Port uint16
    ServerName string
}

type CapabilitySelection struct {
    DefinitionID string
    DefinitionRevision int64
    MaxDurationSeconds int
    MaxResultItems int
    MaxResultBytes int
}
```

`Revision` contains Profile/Revision/Scope/Asset/Provider、Endpoint、Trust Reference、Credential Reference ID+Revision、Network Policy、Realm、Capability selections、Status、failure/result/operation/runtime IDs、Version and timestamps. Constructor copies slices, validates unique `definitionID/revision` using `fmt.Sprintf("%s/%d", ...)`, requires HTTPS and a source-valid same-Scope `EXACT` Asset whose lifecycle is `DISCOVERED|STALE|ACTIVE`；it rejects all unsafe states. Runtime APPLIED plus terminal cleanup activates the first two states later；live investigation remains `ACTIVE+EXACT+PUBLISHED+AVAILABLE` only.

State methods:

```go
func NewProfile(
    CreateProfileCommand,
    assetcatalog.Asset,
    time.Time,
) (Profile, Revision, error)

func (Revision) StartValidation(
    operationID string,
    now time.Time,
) (Revision, error)

func (Revision) CompleteValidation(
    ValidationOutcome,
    time.Time,
) (Revision, error)

func (Revision) Publish(
    runtimePublicationID string,
    now time.Time,
) (Revision, error)
```

`credentialreference.Reference` contains only ID、Scope、display/owner/provider、Revision、issuer kind/id/revision、usage role、max TTL、status and last-used/validated timestamps. `PublicProjection` omits Scope and always sets `Redacted=true`.

`operation.Operation` supports `QUEUED→RUNNING→SUCCEEDED|FAILED` plus `CANCELLED|EXPIRED` terminal recovery. Constructor validates Scope、kind、resource revision、idempotency key、64-hex request hash and actor. Update methods copy values and increment optimistic Version exactly once.

- [ ] **Step 4: Run focused and race tests**

Run:

```bash
go test ./internal/connectionprofile ./internal/credentialreference ./internal/operation -count=1
go test -race ./internal/connectionprofile ./internal/credentialreference ./internal/operation -count=1
```

Expected: both PASS；invalid Asset, endpoint, bounds, duplicate capabilities, skipped transitions and unsafe projections are rejected.

- [ ] **Step 5: Commit**

```bash
git add internal/connectionprofile internal/credentialreference internal/operation
git commit -m "feat: add connection publication domain contracts"
```
