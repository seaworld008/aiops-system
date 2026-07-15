# Production Platform Assembly Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 建立 `000020` 生产平台事实、严格 production dependency graph、八类核心进程装配及已由 Phase 5 交付的外部 Enrollment control services，并生成首个完整只读 Helm chart，使任何缺失/测试/loopback 依赖都在 readiness 前 fail closed。

**Architecture:** `productionplatform` 领域只保存 revision/digest/gate/decision；PostgreSQL repository 保证 Scope、不可变与阶段前驱。`productionassembly` 从只读配置和 workload identity 构造真实 PostgreSQL/Temporal/Keycloak/Vault/audit/evidence/telemetry adapters，再把窄接口注入各 command。Control Plane image 由 Node 24/pnpm 10 的 build stage 生成 `web/dist`、Go stage 生成 binary，最终 non-root/read-only image 只携带 binary 与 `/opt/aiops/web`；同一 Control Plane process/Service/Origin 提供 SPA 和 `/api/*`。Helm chart 使用独立 ServiceAccount、Deployment、Service、PDB/HPA 与 default-deny NetworkPolicy，不包含 WRITE 资源或独立 Web workload。

**Tech Stack:** Go 1.26.5、PostgreSQL 18.4+、pgx/v5、Temporal SDK 1.46.0、Keycloak Server 26.6.3、Vault API/Kubernetes Auth/PKI、Kubernetes 1.36.2、Helm 3、OpenTelemetry、RFC 8785 JCS/SHA-256。

## Global Constraints

- 每个 Task 严格采用 Red → Green → Refactor：先运行并保存预期失败，再做最小生产实现，复跑指定测试后才允许重构和提交。
- migration 固定 `000020_production_platform`，创建且只创建 README 所列七表。
- `000020` 只校验 Phase 1–5 已定义的完整 schema prerequisites；Phase 1–5 acceptance digests 由 production constructor 与 rollout admission 通过各阶段权威 repository/API 复验。缺 schema 时 migration 拒绝，缺/过期 acceptance 时进程不 Ready 且 rollout 拒绝；不得假设一个未定义的通用 accepted marker 表。
- Platform/Component/Rollout/Gate Evidence/Decision/Backup/Recovery 一经发布或完成不可 UPDATE/DELETE。
- 业务主外键全部包含 Tenant/Workspace/Environment Scope；平台全局配置不能成为跨 Scope 访问旁路。
- production config 只包含公开地址、内容引用和文件描述符编号；Secret、Token、DSN、PEM、Vault path 不在 env/flag/JSON。
- Production constructors 拒绝 typed nil、memory/fake adapter、loopback/unspecified/plaintext endpoint、缺 TLS/identity/timeout/health probe。
- 每个 command 只装配其职责所需 adapter；Control Plane 不持有目标 READ credential，Runner 不持有 Keycloak admin 或数据库 migration 权限。
- readiness 必须在 migration、依赖身份、task queue/namespace、audit/evidence、Realm binding 验证后开启；liveness 不因外部依赖短故障杀死进程。
- graceful shutdown 先关闭 admission/claim，再 drain，最后释放 lease；不得中断后继续以旧 fence 完成。
- Helm 基础 chart 属于 Phase 6；无 WRITE Runner、Action worker、WRITE ServiceAccount/Realm/NetworkPolicy/credential values。
- chart 与 production command 不含 `latest`、mutable tag、development mode、hostNetwork、privileged、service account token 自动挂载或 broad RBAC。
- Production Control Plane artifact 是 Web/API 单镜像、单 Deployment、单 Service、单身份；Vite 不是 production server，最终镜像不得包含 Node、pnpm、MSW、source map、Service Worker、前端源码或开发依赖。
- fake、memory、MSW 只能位于测试文件/目录，不能被 production import graph 引用。
- AWX capability 启用时，production graph 还必须验证 Phase 5 的 AWX 24.6.1 governed image、两个 EnrollmentCleanupBroker、Vault 2.0.3 TLS Raft/KV/三把 Transit key、purpose-specific mTLS L7 gateway、authority-keyring Runtime 与 host-local attestor；它们是受治理外部依赖，缺失时只关闭对应 AWX enrollment/diagnostic admission，不能回退 stock launch 或软件导出身份。
- 新增行为严格 TDD，每个 Task 独立 commit。

---

### Task 1: Define immutable platform, rollout, evidence and decision domains

**Files:**
- Create: `internal/productionplatform/model.go`
- Create: `internal/productionplatform/model_test.go`
- Create: `internal/productionplatform/canonical.go`
- Create: `internal/productionplatform/canonical_test.go`
- Create: `internal/productionplatform/transition.go`
- Create: `internal/productionplatform/transition_test.go`

**Interfaces:**
- Consumes: `assetcatalog.Scope`、Phase 2 Runtime digest、Phase 4 Policy/Snapshot/Grant/Kill Switch digest、Phase 5 cleanup/Receipt digest。
- Produces: exhaustive component/stage/gate/decision enums, validation, predecessor transition and domain-separated canonical digests.
- Safety: unknown enum/default is invalid; decision has no arbitrary reason text; private dependency details are references only.

- [ ] **Step 1: Write failing exhaustive domain tests**

```go
func TestComponentKindsContainOnlyProductionReadPath(t *testing.T)
func TestRolloutStagesHaveOneLegalPredecessor(t *testing.T)
func TestGateCodesAndResultsAreClosedEnums(t *testing.T)
func TestDecisionAllowsOnlyThreeTerminalValues(t *testing.T)
func TestPlatformRevisionRejectsMissingOrSecretBearingReferences(t *testing.T)
func TestCanonicalDigestsAreOrderIndependentAndDomainSeparated(t *testing.T)
func TestApprovalRequiresSupervisedStageAndCompletePassingEvidence(t *testing.T)
```

Assert no enum/string contains `WRITE`, `ACTION`, `MUTATION` or `BYPASS`; mutation-test every digest-bound field and prove each changes the digest.

- [ ] **Step 2: Run focused tests and verify failure**

```bash
go test ./internal/productionplatform -run 'Test(ComponentKinds|RolloutStages|GateCodes|Decision|PlatformRevision|Canonical|Approval)' -count=1
```

Expected: FAIL because package does not exist.

- [ ] **Step 3: Implement exact enums and immutable values**

```go
type ComponentKind string
type RolloutStage string
type GateCode string
type GateResult string
type Decision string

const (
    ComponentControlPlane     ComponentKind = "CONTROL_PLANE"
    ComponentControlWorker    ComponentKind = "CONTROL_WORKER"
    ComponentOutboxDispatcher ComponentKind = "OUTBOX_DISPATCHER"
    ComponentScheduler        ComponentKind = "SCHEDULER"
    ComponentDiscoveryWorker  ComponentKind = "DISCOVERY_WORKER"
    ComponentRunnerGateway    ComponentKind = "RUNNER_GATEWAY"
    ComponentValidationRunner ComponentKind = "VALIDATION_RUNNER"
    ComponentReadRunner       ComponentKind = "READ_RUNNER"

    StagePreview                       RolloutStage = "PREVIEW"
    StageNonproductionReadOnly         RolloutStage = "NONPRODUCTION_READ_ONLY"
    StageProductionShadow              RolloutStage = "PRODUCTION_SHADOW"
    StageSupervisedProductionReadOnly  RolloutStage = "SUPERVISED_PRODUCTION_READ_ONLY"

    DecisionNoGo                      Decision = "NO_GO"
    DecisionContinueShadow             Decision = "CONTINUE_SHADOW"
    DecisionApproveProductionReadOnly  Decision = "APPROVE_PRODUCTION_READ_ONLY"
)
```

Gate codes are exactly the README registry: `PLATFORM_REVISION_ACCEPTED`, `DEPENDENCY_CLOSURE_HEALTHY`, `PHASE_INPUTS_ACCEPTED`, `SCOPE_REALM_EXACT`, `NETWORK_DEFAULT_DENY`, `OIDC_RECENT_AUTH`, `WORKLOAD_IDENTITY_VALID`, `GRANT_RUNTIME_CURRENT`, `KILL_SWITCH_OPEN_FOR_READ`, `UNAUTHORIZED_WRITE_SURFACE_ABSENT`, `SHADOW_ZERO_SIDE_EFFECT`, `READ_CREDENTIAL_CLEAN`, `HA_FENCE_PROVEN`, `SLO_BUDGET_HEALTHY`, `AUDIT_CHAIN_COMPLETE`, `DLP_SCAN_CLEAN`, `BACKUP_RECENT_VALID`, `CLEAN_ROOM_RECOVERY_PROVEN`, `DEPENDENCY_DRILLS_PASS`, `RUNNER_CRASH_RECOVERED`, `STAGE_SOAK_COMPLETE`, `HUMAN_SUPERVISION_COMPLETE`. Result is `PASS|FAIL|INCONCLUSIVE`; only all required current observations PASS is approvable. The accepted Action manifest is empty in Phase 6, so the unauthorized-surface gate is equivalent to complete WRITE absence until a separately accepted Phase 7 successor exists.

```go
type PlatformRevision struct {
    Scope                 assetcatalog.Scope
    ID                    string
    Revision              int64
    ChartVersion          string
    ChartDigest           string
    ImagesLockDigest      string
    ConfigurationDigest   string
    DependenciesDigest    string
    Components            []Component
    Status                string
    ManifestDigest        string
}

type RolloutRevision struct {
    Scope                  assetcatalog.Scope
    ID                     string
    Revision               int64
    Stage                  RolloutStage
    PredecessorID          string
    PredecessorRevision    int64
    PlatformID             string
    PlatformRevision       int64
    PolicyDigest           string
    SnapshotDigest         string
    RuntimeDigest          string
    KillSwitchDigest       string
    Status                 string
    ManifestDigest         string
}

type GateEvidence struct {
    Code            GateCode
    Result          GateResult
    SampleCount     int64
    FailureCount    int64
    ObservedSeconds int64
    RPOSeconds      int64
    RTOSeconds      int64
    EvidenceDigest  string
}
```

- [ ] **Step 4: Implement canonicalization and transition checks**

Sort Components by kind/Realm/digest and Evidence by code; encode JCS; hash domain prefixes `aiops.production-platform.v1`, `aiops.production-rollout.v1`, `aiops.production-evidence-set.v1`, `aiops.production-decision.v1`. `ValidateTransition` requires accepted predecessor and exact stage order. Approval additionally requires recent-auth subject digest and evidence set containing every gate exactly once/PASS.

- [ ] **Step 5: Run domain tests**

```bash
go test -race ./internal/productionplatform -count=1
```

Expected: PASS; enums exhaustive, transitions cannot skip and canonical digests are deterministic.

- [ ] **Step 6: Commit domain contracts**

```bash
git add internal/productionplatform
git commit -m "feat(platform): define production read gates"
```

### Task 2: Add `000020` and scoped PostgreSQL repositories

**Files:**
- Create: `migrations/000020_production_platform.up.sql`
- Create: `migrations/000020_production_platform.down.sql`
- Modify: `internal/store/postgres/migrations_integration_test.go`
- Create: `internal/productionplatform/postgres/repository.go`
- Create: `internal/productionplatform/postgres/repository_test.go`
- Create: `internal/productionplatform/postgres/repository_integration_test.go`

**Interfaces:**
- Consumes: Phase 1 Scope/Asset, Phase 2 Runtime/Realm, Phase 4 Policy/Grant/Kill Switch and Phase 5 cleanup/Receipt tables.
- Produces: seven scoped tables and transactional Repository for platform publish, rollout transition, gate evidence, decision, backup and exercise.
- Safety: append-only completed facts, serializable transition locks and guarded rollback.

- [ ] **Step 1: Write failing migration/repository tests**

```go
func TestProductionPlatformMigrationRequires000015Through000019(t *testing.T)
func TestProductionPlatformMigrationOwnsExactlySevenTables(t *testing.T)
func TestProductionPlatformMigrationRejectsCrossScopeAndInvalidEnums(t *testing.T)
func TestProductionPlatformPublishedFactsAreImmutable(t *testing.T)
func TestProductionPlatformTransitionSerializesConcurrentRevisions(t *testing.T)
func TestProductionDecisionRequiresCompleteEvidenceSet(t *testing.T)
func TestProductionApprovalPersistsImmutableHandoff(t *testing.T)
func TestNonApprovalDecisionRejectsHandoff(t *testing.T)
func TestProductionPlatformDownRefusesStateOrOpenReadAdmission(t *testing.T)
func TestProductionPlatformMigrationRoundTripsEmptyDatabase(t *testing.T)
```

- [ ] **Step 2: Run migration tests and verify failure**

```bash
AIOPS_TEST_POSTGRES_DSN="$AIOPS_TEST_POSTGRES_DSN" go test ./internal/store/postgres ./internal/productionplatform/postgres -run 'TestProductionPlatform' -count=1
```

Expected: FAIL because migration/repository are absent.

- [ ] **Step 3: Implement the exact schema in one transaction**

```sql
BEGIN;

DO $$
BEGIN
  IF to_regclass('public.environments') IS NULL
     OR to_regclass('public.assets') IS NULL
     OR to_regclass('public.runtime_publications') IS NULL
     OR to_regclass('public.investigation_grants') IS NULL
     OR to_regclass('public.diagnostic_execution_receipts') IS NULL THEN
    RAISE EXCEPTION USING ERRCODE='55000',
      CONSTRAINT='production_platform_prerequisite',
      MESSAGE='required Phase 1 through Phase 5 schema prerequisites are missing';
  END IF;
END $$;

CREATE TABLE production_platform_revisions (
  tenant_id uuid NOT NULL, workspace_id uuid NOT NULL, environment_id uuid NOT NULL,
  id uuid NOT NULL, revision bigint NOT NULL CHECK (revision > 0),
  chart_version text NOT NULL CHECK (char_length(chart_version) BETWEEN 1 AND 64),
  chart_digest text NOT NULL CHECK (chart_digest ~ '^[a-f0-9]{64}$'),
  images_lock_digest text NOT NULL CHECK (images_lock_digest ~ '^[a-f0-9]{64}$'),
  configuration_digest text NOT NULL CHECK (configuration_digest ~ '^[a-f0-9]{64}$'),
  dependencies_digest text NOT NULL CHECK (dependencies_digest ~ '^[a-f0-9]{64}$'),
  status text NOT NULL CHECK (status IN ('DRAFT','VALIDATED','APPLIED','SUPERSEDED','REVOKED')),
  manifest_digest text NOT NULL CHECK (manifest_digest ~ '^[a-f0-9]{64}$'),
  created_by_digest text NOT NULL CHECK (created_by_digest ~ '^[a-f0-9]{64}$'),
  created_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id,workspace_id,environment_id,id,revision),
  FOREIGN KEY (tenant_id,workspace_id,environment_id)
    REFERENCES environments (tenant_id,workspace_id,id) ON DELETE RESTRICT
);

CREATE TABLE production_platform_components (
  tenant_id uuid NOT NULL, workspace_id uuid NOT NULL, environment_id uuid NOT NULL,
  platform_id uuid NOT NULL, platform_revision bigint NOT NULL,
  component_kind text NOT NULL CHECK (component_kind IN (
    'CONTROL_PLANE','CONTROL_WORKER','OUTBOX_DISPATCHER','SCHEDULER','DISCOVERY_WORKER',
    'RUNNER_GATEWAY','VALIDATION_RUNNER','READ_RUNNER')),
  realm_reference text NOT NULL,
  image_digest text NOT NULL CHECK (image_digest ~ '^sha256:[a-f0-9]{64}$'),
  configuration_digest text NOT NULL CHECK (configuration_digest ~ '^[a-f0-9]{64}$'),
  workload_identity_digest text NOT NULL CHECK (workload_identity_digest ~ '^[a-f0-9]{64}$'),
  network_policy_digest text NOT NULL CHECK (network_policy_digest ~ '^[a-f0-9]{64}$'),
  replica_min integer NOT NULL CHECK (replica_min BETWEEN 2 AND 100),
  replica_max integer NOT NULL CHECK (replica_max BETWEEN replica_min AND 200),
  pdb_min_available integer NOT NULL CHECK (pdb_min_available BETWEEN 1 AND replica_min-1),
  rollout_digest text NOT NULL CHECK (rollout_digest ~ '^[a-f0-9]{64}$'),
  PRIMARY KEY (tenant_id,workspace_id,environment_id,platform_id,platform_revision,component_kind,realm_reference),
  FOREIGN KEY (tenant_id,workspace_id,environment_id,platform_id,platform_revision)
    REFERENCES production_platform_revisions (tenant_id,workspace_id,environment_id,id,revision),
  FOREIGN KEY (tenant_id,workspace_id,environment_id)
    REFERENCES environments (tenant_id,workspace_id,id) ON DELETE RESTRICT
);

CREATE TABLE production_read_rollout_revisions (
  tenant_id uuid NOT NULL, workspace_id uuid NOT NULL, environment_id uuid NOT NULL,
  id uuid NOT NULL, revision bigint NOT NULL CHECK (revision > 0),
  stage text NOT NULL CHECK (stage IN ('PREVIEW','NONPRODUCTION_READ_ONLY','PRODUCTION_SHADOW','SUPERVISED_PRODUCTION_READ_ONLY')),
  predecessor_id uuid, predecessor_revision bigint,
  platform_id uuid NOT NULL, platform_revision bigint NOT NULL,
  policy_digest text NOT NULL CHECK (policy_digest ~ '^[a-f0-9]{64}$'),
  snapshot_digest text NOT NULL CHECK (snapshot_digest ~ '^[a-f0-9]{64}$'),
  runtime_digest text NOT NULL CHECK (runtime_digest ~ '^[a-f0-9]{64}$'),
  kill_switch_digest text NOT NULL CHECK (kill_switch_digest ~ '^[a-f0-9]{64}$'),
  status text NOT NULL CHECK (status IN ('DRAFT','RUNNING','ACCEPTED','REJECTED','SUPERSEDED')),
  manifest_digest text NOT NULL CHECK (manifest_digest ~ '^[a-f0-9]{64}$'),
  started_at timestamptz, completed_at timestamptz, created_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id,workspace_id,environment_id,id,revision),
  FOREIGN KEY (tenant_id,workspace_id,environment_id,platform_id,platform_revision)
    REFERENCES production_platform_revisions (tenant_id,workspace_id,environment_id,id,revision),
  FOREIGN KEY (tenant_id,workspace_id,environment_id,predecessor_id,predecessor_revision)
    REFERENCES production_read_rollout_revisions (tenant_id,workspace_id,environment_id,id,revision),
  FOREIGN KEY (tenant_id,workspace_id,environment_id)
    REFERENCES environments (tenant_id,workspace_id,id) ON DELETE RESTRICT,
  CHECK ((predecessor_id IS NULL) = (predecessor_revision IS NULL)),
  CHECK ((predecessor_id IS NULL) = (stage='PREVIEW')),
  CHECK ((status IN ('ACCEPTED','REJECTED','SUPERSEDED')) = (completed_at IS NOT NULL))
);
```

Complete the transaction with the remaining four relations；do not leave their columns to implementation-time interpretation:

```sql
CREATE TABLE production_rollout_gate_evidence (
  tenant_id uuid NOT NULL, workspace_id uuid NOT NULL, environment_id uuid NOT NULL,
  rollout_id uuid NOT NULL, rollout_revision bigint NOT NULL,
  gate_code text NOT NULL CHECK (gate_code IN (
    'PLATFORM_REVISION_ACCEPTED','DEPENDENCY_CLOSURE_HEALTHY','PHASE_INPUTS_ACCEPTED',
    'SCOPE_REALM_EXACT','NETWORK_DEFAULT_DENY','OIDC_RECENT_AUTH','WORKLOAD_IDENTITY_VALID',
    'GRANT_RUNTIME_CURRENT','KILL_SWITCH_OPEN_FOR_READ','UNAUTHORIZED_WRITE_SURFACE_ABSENT',
    'SHADOW_ZERO_SIDE_EFFECT','READ_CREDENTIAL_CLEAN','HA_FENCE_PROVEN','SLO_BUDGET_HEALTHY',
    'AUDIT_CHAIN_COMPLETE','DLP_SCAN_CLEAN','BACKUP_RECENT_VALID','CLEAN_ROOM_RECOVERY_PROVEN',
    'DEPENDENCY_DRILLS_PASS','RUNNER_CRASH_RECOVERED','STAGE_SOAK_COMPLETE','HUMAN_SUPERVISION_COMPLETE')),
  observation_revision bigint NOT NULL CHECK (observation_revision > 0),
  result text NOT NULL CHECK (result IN ('PASS','FAIL','INCONCLUSIVE')),
  sample_count bigint NOT NULL CHECK (sample_count >= 0),
  failure_count bigint NOT NULL CHECK (failure_count BETWEEN 0 AND sample_count),
  observed_seconds bigint NOT NULL CHECK (observed_seconds >= 0),
  rpo_seconds bigint CHECK (rpo_seconds >= 0),
  rto_seconds bigint CHECK (rto_seconds >= 0),
  observed_from timestamptz NOT NULL, observed_until timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  producer_digest char(64) NOT NULL CHECK (producer_digest ~ '^[a-f0-9]{64}$'),
  evidence_digest char(64) NOT NULL CHECK (evidence_digest ~ '^[a-f0-9]{64}$'),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id,workspace_id,environment_id,rollout_id,rollout_revision,gate_code,observation_revision),
  FOREIGN KEY (tenant_id,workspace_id,environment_id,rollout_id,rollout_revision)
    REFERENCES production_read_rollout_revisions (tenant_id,workspace_id,environment_id,id,revision),
  FOREIGN KEY (tenant_id,workspace_id,environment_id)
    REFERENCES environments (tenant_id,workspace_id,id) ON DELETE RESTRICT,
  CHECK (observed_from <= observed_until AND observed_until <= expires_at)
);

CREATE TABLE production_readiness_decisions (
  tenant_id uuid NOT NULL, workspace_id uuid NOT NULL, environment_id uuid NOT NULL,
  rollout_id uuid NOT NULL, rollout_revision bigint NOT NULL,
  decision_revision bigint NOT NULL CHECK (decision_revision > 0),
  decision text NOT NULL CHECK (decision IN ('NO_GO','CONTINUE_SHADOW','APPROVE_PRODUCTION_READ_ONLY')),
  evidence_set_digest char(64) NOT NULL CHECK (evidence_set_digest ~ '^[a-f0-9]{64}$'),
  actor_digest char(64) NOT NULL CHECK (actor_digest ~ '^[a-f0-9]{64}$'),
  reauthenticated_at timestamptz NOT NULL, decided_at timestamptz NOT NULL,
  handoff_id uuid,
  handoff_digest char(64) CHECK (handoff_digest ~ '^[a-f0-9]{64}$'),
  PRIMARY KEY (tenant_id,workspace_id,environment_id,rollout_id,rollout_revision,decision_revision),
  UNIQUE (tenant_id,workspace_id,environment_id,rollout_id,rollout_revision,decision_revision,handoff_id,handoff_digest),
  FOREIGN KEY (tenant_id,workspace_id,environment_id,rollout_id,rollout_revision)
    REFERENCES production_read_rollout_revisions (tenant_id,workspace_id,environment_id,id,revision),
  FOREIGN KEY (tenant_id,workspace_id,environment_id)
    REFERENCES environments (tenant_id,workspace_id,id) ON DELETE RESTRICT,
  CHECK (reauthenticated_at <= decided_at),
  CHECK (
    (decision = 'APPROVE_PRODUCTION_READ_ONLY' AND handoff_id IS NOT NULL AND handoff_digest IS NOT NULL)
    OR (decision <> 'APPROVE_PRODUCTION_READ_ONLY' AND handoff_id IS NULL AND handoff_digest IS NULL)
  )
);

CREATE TABLE production_backup_manifests (
  tenant_id uuid NOT NULL, workspace_id uuid NOT NULL, environment_id uuid NOT NULL,
  id uuid NOT NULL,
  platform_id uuid NOT NULL, platform_revision bigint NOT NULL,
  recovery_cut timestamptz NOT NULL,
  objects jsonb NOT NULL CHECK (jsonb_typeof(objects) = 'array' AND jsonb_array_length(objects) BETWEEN 1 AND 7),
  kms_attestation_digest char(64) NOT NULL CHECK (kms_attestation_digest ~ '^[a-f0-9]{64}$'),
  manifest_digest char(64) NOT NULL CHECK (manifest_digest ~ '^[a-f0-9]{64}$'),
  status text NOT NULL CHECK (status IN ('CREATING','VERIFIED','FAILED','EXPIRED')),
  created_by_digest char(64) NOT NULL CHECK (created_by_digest ~ '^[a-f0-9]{64}$'),
  created_at timestamptz NOT NULL DEFAULT now(),
  completed_at timestamptz,
  PRIMARY KEY (tenant_id,workspace_id,environment_id,id),
  UNIQUE (tenant_id,workspace_id,environment_id,manifest_digest),
  UNIQUE (tenant_id,workspace_id,environment_id,id,platform_id,platform_revision),
  FOREIGN KEY (tenant_id,workspace_id,environment_id,platform_id,platform_revision)
    REFERENCES production_platform_revisions (tenant_id,workspace_id,environment_id,id,revision),
  FOREIGN KEY (tenant_id,workspace_id,environment_id)
    REFERENCES environments (tenant_id,workspace_id,id) ON DELETE RESTRICT,
  CHECK ((status = 'CREATING') = (completed_at IS NULL)),
  CHECK (completed_at IS NULL OR (recovery_cut <= completed_at AND created_at <= completed_at))
);

CREATE TABLE production_recovery_exercises (
  tenant_id uuid NOT NULL, workspace_id uuid NOT NULL, environment_id uuid NOT NULL,
  id uuid NOT NULL, backup_id uuid,
  platform_id uuid NOT NULL, platform_revision bigint NOT NULL,
  rollout_id uuid, rollout_revision bigint,
  exercise_kind text NOT NULL CHECK (exercise_kind IN (
    'CLEAN_ROOM_RESTORE','REGIONAL_FAILOVER','CORRUPT_BACKUP','LOST_WAL','KMS_VAULT_OUTAGE','SPLIT_BRAIN')),
  result text NOT NULL CHECK (result IN ('PASS','FAIL','INCONCLUSIVE')),
  measured_rpo_seconds bigint NOT NULL CHECK (measured_rpo_seconds >= 0),
  measured_rto_seconds bigint NOT NULL CHECK (measured_rto_seconds >= 0),
  evidence_digest char(64) NOT NULL CHECK (evidence_digest ~ '^[a-f0-9]{64}$'),
  started_at timestamptz NOT NULL, completed_at timestamptz NOT NULL,
  conducted_by_digest char(64) NOT NULL CHECK (conducted_by_digest ~ '^[a-f0-9]{64}$'),
  PRIMARY KEY (tenant_id,workspace_id,environment_id,id),
  FOREIGN KEY (tenant_id,workspace_id,environment_id,backup_id,platform_id,platform_revision)
    REFERENCES production_backup_manifests (tenant_id,workspace_id,environment_id,id,platform_id,platform_revision),
  FOREIGN KEY (tenant_id,workspace_id,environment_id,platform_id,platform_revision)
    REFERENCES production_platform_revisions (tenant_id,workspace_id,environment_id,id,revision),
  FOREIGN KEY (tenant_id,workspace_id,environment_id,rollout_id,rollout_revision)
    REFERENCES production_read_rollout_revisions (tenant_id,workspace_id,environment_id,id,revision),
  FOREIGN KEY (tenant_id,workspace_id,environment_id)
    REFERENCES environments (tenant_id,workspace_id,id) ON DELETE RESTRICT,
  CHECK ((rollout_id IS NULL) = (rollout_revision IS NULL)),
  CHECK (started_at <= completed_at)
);

COMMIT;
```

`production_backup_manifests.objects` uses a closed JSON schema enforced by a constraint trigger: every element has exactly `kind/immutable_ref/ciphertext_digest/plaintext_digest/recovery_point/verified_at`; `kind` is one of `PLATFORM_POSTGRES|TEMPORAL_POSTGRES|KEYCLOAK_POSTGRES|VAULT_RAFT|EVIDENCE_STORE|AUDIT_STORE|RELEASE_ARTIFACTS`, appears at most once, both digests are lowercase 64-hex, references match the opaque immutable-reference grammar, and times are ordered and no later than `recovery_cut`/`completed_at`. Canonical JCS sorts by kind and immutable ref before recomputing `manifest_digest`. A partial driver result persists `FAILED` with no current recovery-cut advancement.

The approval transaction computes the canonical handoff envelope after loading the exact ordered PASS evidence set, writes its server-generated UUID and SHA-256 digest into the same immutable `production_readiness_decisions` row, then emits the outbox record. `NO_GO` and `CONTINUE_SHADOW` must persist both handoff columns as SQL `NULL`. Phase 7 references the full Scope+rollout+decision+handoff unique tuple；an independently supplied or recomputed-mismatch handoff cannot satisfy that FK/validation boundary.

- [ ] **Step 4: Add transition/immutability triggers and guarded down**

Use one SECURITY INVOKER trigger function to reject UPDATE/DELETE of applied/completed rows with SQLSTATE `55000`; a separate transition function under row lock validates exact predecessor stage and complete gate set, and a backup-object trigger enforces the closed aggregate schema above. Down checks every seven table plus resolved production READ admission and raises constraint `production_platform_down_guard` before dropping in reverse FK order.

- [ ] **Step 5: Implement pgx repository transactions**

```go
type Repository interface {
    PublishPlatform(context.Context, productionplatform.PlatformRevision) error
    BeginRollout(context.Context, productionplatform.RolloutRevision) error
    RecordGate(context.Context, assetcatalog.Scope, string, int64, productionplatform.GateEvidence) error
    AcceptOrReject(context.Context, assetcatalog.Scope, string, int64, string) error
    Decide(context.Context, productionplatform.DecisionRecord) error
    RecordBackup(context.Context, productionplatform.BackupManifest) error
    RecordExercise(context.Context, productionplatform.RecoveryExercise) error
}
```

Use SERIALIZABLE plus `pg_advisory_xact_lock` on Scope+rollout ID. Identical idempotent replay returns original；different bytes/revision conflict. Decision loads and hashes ordered evidence inside the same transaction. Only `APPROVE_PRODUCTION_READ_ONLY` builds a non-empty `HandoffID`/`HandoffDigest`; the repository rejects caller-provided values, persists the server result once and protects the row with the completed-fact immutability trigger.

- [ ] **Step 6: Run migration/repository tests**

```bash
AIOPS_TEST_POSTGRES_DSN="$AIOPS_TEST_POSTGRES_DSN" go test -race ./internal/store/postgres ./internal/productionplatform/postgres -run 'TestProductionPlatform' -count=1
```

Expected: PASS including concurrent transition, down guard and empty up/down/up.

- [ ] **Step 7: Commit schema/repository**

```bash
git add migrations/000020_production_platform.up.sql migrations/000020_production_platform.down.sql internal/store/postgres/migrations_integration_test.go internal/productionplatform/postgres
git commit -m "feat(platform): persist production read readiness"
```

### Task 3: Build strict production configuration and dependency constructors

**Files:**
- Create: `internal/productionassembly/config.go`
- Create: `internal/productionassembly/config_test.go`
- Create: `internal/productionassembly/dependencies.go`
- Create: `internal/productionassembly/dependencies_test.go`
- Create: `internal/productionassembly/readiness.go`
- Create: `internal/productionassembly/readiness_test.go`
- Create: `internal/productionassembly/architecture_boundary_test.go`
- Modify: `internal/config/config.go`
- Modify: `internal/config/config_test.go`

**Interfaces:**
- Consumes: mounted `/etc/aiops/platform/config.json`, image/chart lock, Kubernetes workload identity token FD and trust bundle FD.
- Produces: verified real adapters and a dependency/readiness graph for each component role.
- Safety: public config cannot carry secrets; architecture test rejects production imports/calls to memory/fake/test constructors.

- [ ] **Step 1: Write failing configuration/dependency tests**

```go
func TestProductionConfigRejectsSecretFieldsEnvironmentAndFlags(t *testing.T)
func TestProductionConfigRejectsLoopbackPlaintextAndUnboundedTimeouts(t *testing.T)
func TestProductionDependenciesRejectEveryMissingOrTypedNilAdapter(t *testing.T)
func TestProductionDependenciesRequireTLSIdentityHealthAndClose(t *testing.T)
func TestReadinessRequiresMigrationsIdentityQueuesAuditEvidenceAndTelemetry(t *testing.T)
func TestProductionImportGraphContainsNoMemoryFakeOrTestAdapter(t *testing.T)
```

- [ ] **Step 2: Run tests and verify failure**

```bash
go test ./internal/productionassembly ./internal/config -run 'TestProduction' -count=1
```

Expected: FAIL because production assembly is absent.

- [ ] **Step 3: Implement safe configuration**

```go
type Config struct {
    Role                  ComponentKind `json:"role"`
    ScopeReference        string        `json:"scope_reference"`
    PostgreSQLReference   string        `json:"postgresql_reference"`
    TemporalAddress       string        `json:"temporal_address"`
    TemporalNamespace     string        `json:"temporal_namespace"`
    KeycloakIssuer        string        `json:"keycloak_issuer"`
    KeycloakAPIAudience   string        `json:"keycloak_api_audience"`
    KeycloakAuthorizedParty string      `json:"keycloak_authorized_party"`
    BrowserOIDCURL        string        `json:"browser_oidc_url"`
    BrowserOIDCRealm      string        `json:"browser_oidc_realm"`
    BrowserOIDCClientID   string        `json:"browser_oidc_client_id"`
    VaultAddress          string        `json:"vault_address"`
    VaultRoleReference    string        `json:"vault_role_reference"`
    AuditSinkReference    string        `json:"audit_sink_reference"`
    EvidenceStoreReference string       `json:"evidence_store_reference"`
    TelemetryReference    string        `json:"telemetry_reference"`
    WorkloadTokenFD       int           `json:"workload_token_fd"`
    TrustBundleFD         int           `json:"trust_bundle_fd"`
}
```

Strict JSON decoder rejects unknown fields. Human identity values map without ambiguity to Phase 1 `AIOPS_OIDC_ISSUER`、`AIOPS_OIDC_API_AUDIENCE`、`AIOPS_OIDC_AUTHORIZED_PARTY`、`AIOPS_WEB_OIDC_URL`、`AIOPS_WEB_OIDC_REALM` and `AIOPS_WEB_OIDC_CLIENT_ID`；production requires API audience `aiops-control-plane` and browser public authorized party/client `control-plane-web`. Only the three safe browser values may be projected through `/api/v1/browser-config`. All addresses are HTTPS/mTLS DNS identities, never loopback/IP literal/credentials-in-URL. FDs must be inherited, non-stdio, close-on-exec managed；config has no password/token/DSN/PEM/path fields.

- [ ] **Step 4: Implement role-specific dependency graph**

```go
type Dependencies struct {
    Database       Database
    Temporal       Temporal
    HumanIdentity HumanIdentity
    WorkloadPKI    WorkloadPKI
    Audit          AuditSink
    Evidence       EvidenceStore
    Telemetry      Telemetry
    Clock          Clock
}

func Build(ctx context.Context, cfg Config, source WorkloadIdentitySource) (Dependencies, error)
func RequiredFor(role ComponentKind) RequirementSet
```

`RequiredFor` is a literal matrix. Build authenticates with Vault via projected workload JWT, obtains only role-bound client certificate/database handle, verifies Keycloak issuer/JWKS/audience, Temporal namespace/task queues, schema version, audit append and evidence put/delete-canary, then returns adapters. Never log probe responses.

- [ ] **Step 5: Implement separate live/ready/drain states**

`/livez` reports process loop only. `/readyz` returns generic 503 until all required checks and platform revision match. `BeginDrain` atomically closes admission/claim, stops new Temporal/outbox work, waits bounded in-flight work, persists unresolved attempts and exits nonzero if fence/cleanup uncertain.

- [ ] **Step 6: Run assembly tests**

```bash
go test -race ./internal/productionassembly ./internal/config -count=1
```

Expected: PASS; each single dependency removal prevents readiness and no secret field is accepted.

- [ ] **Step 7: Commit dependency assembly**

```bash
git add internal/productionassembly internal/config
git commit -m "feat(platform): fail closed production dependencies"
```

### Task 4: Assemble production commands and the Phase 6 Helm foundation

**Files:**
- Modify: `cmd/control-plane/main.go`
- Modify: `cmd/control-plane/main_test.go`
- Modify: `cmd/worker/main.go`
- Modify: `cmd/worker/main_test.go`
- Create: `cmd/outbox-dispatcher/main.go`
- Create: `cmd/outbox-dispatcher/main_test.go`
- Create: `cmd/scheduler/main.go`
- Create: `cmd/scheduler/main_test.go`
- Modify: `cmd/discovery-worker/main.go`
- Modify: `cmd/discovery-worker/main_test.go`
- Create: `cmd/runner-gateway/main.go`
- Create: `cmd/runner-gateway/main_test.go`
- Modify: `cmd/validation-runner/main.go`
- Modify: `cmd/validation-runner/main_test.go`
- Modify: `cmd/read-runner/main.go`
- Modify: `cmd/read-runner/main_test.go`
- Create: `build/package/control-plane/Dockerfile`
- Create: `test/production/control_plane_image_contract_test.go`
- Create: `deploy/images.lock`
- Create: `deploy/helm/aiops/Chart.yaml`
- Create: `deploy/helm/aiops/values.yaml`
- Create: `deploy/helm/aiops/values.schema.json`
- Create: `deploy/helm/aiops/templates/_helpers.tpl`
- Create: `deploy/helm/aiops/templates/serviceaccounts.yaml`
- Create: `deploy/helm/aiops/templates/config.yaml`
- Create: `deploy/helm/aiops/templates/control-plane.yaml`
- Create: `deploy/helm/aiops/templates/control-worker.yaml`
- Create: `deploy/helm/aiops/templates/outbox-dispatcher.yaml`
- Create: `deploy/helm/aiops/templates/scheduler.yaml`
- Create: `deploy/helm/aiops/templates/discovery-worker.yaml`
- Create: `deploy/helm/aiops/templates/runner-gateway.yaml`
- Create: `deploy/helm/aiops/templates/validation-runner.yaml`
- Create: `deploy/helm/aiops/templates/read-runner.yaml`
- Create: `deploy/helm/aiops/templates/services.yaml`
- Create: `deploy/helm/aiops/templates/pdb.yaml`
- Create: `deploy/helm/aiops/templates/hpa.yaml`
- Create: `deploy/helm/aiops/templates/networkpolicy.yaml`
- Create: `deploy/helm/aiops/chart_contract_test.go`
- Create: `test/production/kind-ha.yaml`
- Create: `test/production/images.lock`
- Create: `test/production/up.sh`
- Create: `test/production/down.sh`
- Create: `test/production/wait-ready.sh`
- Create: `test/production/verify-all.sh`
- Create: `test/production/manifests/namespaces.yaml`
- Create: `test/production/manifests/postgresql-ha.yaml`
- Create: `test/production/manifests/temporal.yaml`
- Create: `test/production/manifests/keycloak.yaml`
- Create: `test/production/manifests/vault-ha.yaml`
- Create: `test/production/manifests/object-store.yaml`
- Create: `test/production/manifests/observability.yaml`
- Create: `test/production/manifests/test-targets.yaml`
- Create: `test/production/manifests/networking.yaml`
- Create: `test/production/bootstrap-keycloak.sh`
- Create: `test/production/bootstrap-vault.sh`
- Create: `test/production/stack_contract_test.go`

**Interfaces:**
- Consumes: production dependencies, Phase 1–5 real repositories/services/workflows/Gateway/runners and image lock.
- Produces: eight runnable roles, one content-addressed Control Plane Web/API image, complete read-only Helm foundation and the reusable real-dependency reference stack required by Packs 02–06.
- Safety: chart rendering and Go architecture tests prove the observed WRITE set exactly equals the accepted Action manifest and that no READ-owned boundary is weakened；the Phase 6 manifest is empty。Image contract tests prove `/opt/aiops/web` and the Go binary are present while Node、pnpm、MSW、Service Worker、source map、frontend source and development dependencies are absent。

- [ ] **Step 1: Write failing command/chart boundary tests**

```go
func TestEveryProductionCommandRejectsMissingDependencyBeforeReady(t *testing.T)
func TestProductionCommandsExposeOnlyTheirFixedRole(t *testing.T)
func TestRenderedChartHasEveryReadComponentWithPDBHPAAndServiceAccount(t *testing.T)
func TestRenderedChartUsesLockedDigestsAndNoMutableImages(t *testing.T)
func TestRenderedChartMatchesAcceptedActionManifestAndReadBaseline(t *testing.T)
func TestRenderedChartUsesNoPrivilegedHostNetworkOrBroadRBAC(t *testing.T)
func TestPhaseOwnershipAllowsPhaseSevenOnlyAdditiveWriteTemplates(t *testing.T)
func TestProductionFoundationPinsKubernetes136AndEveryDependencyImage(t *testing.T)
func TestProductionFoundationScriptsHaveTimeoutCleanupAndSecretGuards(t *testing.T)
func TestProductionAWXEnrollmentDependenciesAreExactHAAndFailClosed(t *testing.T)
func TestControlPlaneImagePackagesGoAndWebWithoutNodeRuntime(t *testing.T)
func TestRenderedChartHasNoIndependentWebImageWorkloadServiceOrIdentity(t *testing.T)
```

- [ ] **Step 2: Run tests and verify failure**

```bash
go test ./cmd/... ./deploy/helm/aiops ./test/production -run 'Test(EveryProduction|ProductionCommands|RenderedChart|PhaseOwnership|ProductionFoundation|ControlPlaneImage)' -count=1
```

Expected: FAIL because role binaries/chart foundation and the packaged Control Plane Web/API image are incomplete.

- [ ] **Step 3: Wire each command through one production builder**

Each `main` parses only `--config-fd`, loads/validates role, calls `productionassembly.Build`, constructs the real role service, starts live/ready endpoints, handles SIGTERM via drain and returns nonzero on uncertain cleanup. Outbox uses Phase 1/4 dispatchers with PostgreSQL claim；Scheduler uses Phase 4 `SchedulerPublisher`；Discovery Worker uses only accepted Phase 1/5 source-adapter registrations、durable cursors and lease/fence repositories；Gateway embeds all Phase 2–5 authorizers；runners register exact Realm/capabilities. AWX-enabled assembly additionally validates the exact governed AWX image/admission route、two-replica Broker live-quorum receipt、Vault/KV/Transit and L7 policy digests、authority-keyring Runtime plus host-attestor compatibility artifact before admitting enrollment or diagnostics；这些外部服务不增加浏览器入口，也不能被 stock AWX launch 替代。No command selects role or Provider by arbitrary flag.

`productionassembly.Build` reads the accepted Phase 1–5 revision/digest tuple from each phase's authoritative repository/service, recomputes the closure and binds it into the Platform revision. Missing、rejected、superseded、expired or mismatched input returns a typed startup error before readiness；this runtime check is deliberately separate from the schema-only migration prerequisite.

The Control Plane Dockerfile has three fixed stages: Node 24 with Corepack/pnpm 10.34.0 performs a frozen-lockfile install, generated-API drift check, typecheck/test/build；Go 1.26.5 builds the Control Plane binary；the final distroless-equivalent non-root image copies only the binary and verified `web/dist` to `/opt/aiops/web`. Build labels and `deploy/images.lock` bind source commit、OpenAPI contract digest、Web bundle digest and Go binary digest into the single Control Plane image digest. No independent Web image is produced.

- [ ] **Step 4: Implement locked Helm values/schema and workload templates**

Values schema requires digest image refs、replica min/max、resource requests/limits、topology keys、Realm refs、public dependency refs and FD mounts. It rejects secret values, raw env arrays, arbitrary command/args, extra containers/volumes, host aliases and every undeclared key. `images.controlPlane` is the sole Web/API artifact；schema and render tests reject `images.web`、Web Deployment/Service/ServiceAccount、Node sidecar and a second ingress origin. The Phase 6 schema exposes READ fields only；Phase 7 may modify it solely by adding closed WRITE/Action branches tied to accepted Action types, while Phase 6 values continue to render no WRITE resource. Templates use non-root UID, read-only root FS, seccomp RuntimeDefault, drop ALL capabilities, no privilege escalation, automount token false plus audience-bound projected token where Vault auth is required.

- [ ] **Step 5: Add PDB/HPA/spread and services**

Control Plane/Gateway minimum 3 and PDB 2；Worker minimum 3/PDB 2；Outbox/Scheduler/Discovery/Validation/READ minimum 2/PDB 1. Every Deployment spreads over zone and hostname with maxSkew 1, RollingUpdate maxUnavailable 0/maxSurge 1, readiness gate and preStop drain. Only Control Plane and Gateway have Services；the Control Plane Service exposes same-origin SPA and `/api/*`, while Gateway service is cluster-internal mTLS. Control Plane readiness verifies the binary plus `/opt/aiops/web/index.html`/asset manifest before admitting traffic；missing or mismatched static artifacts fail closed.

- [ ] **Step 6: Create the reusable real-dependency reference foundation**

Pin Kubernetes `1.36.2` Kind node images and immutable PostgreSQL、Temporal、Keycloak Server 26.6.3、Vault 2.0.3 TLS Raft、AWX 24.6.1 governed image、two-replica EnrollmentCleanupBroker/L7 gateway、object-store and observability images. `up.sh` creates one control-plane plus three zone-labelled workers, applies TLS-only dependencies and the Phase 6 chart, waits with bounded deadlines and writes only safe IDs/digests to `.state/reference.json`. `down.sh` is idempotent and removes cluster、volumes、temporary trust/credential files. Packs 02–05 extend fixtures through their own declared files but reuse these exact lifecycle scripts；Pack 06 modifies this foundation for final full-path E2E rather than creating a second stack.

- [ ] **Step 7: Render/lint/build and run tests**

```bash
helm lint deploy/helm/aiops
helm template aiops deploy/helm/aiops -f deploy/helm/aiops/values.yaml > /tmp/aiops-rendered.yaml
go test -race ./cmd/... ./deploy/helm/aiops ./test/production -run 'Test(EveryProduction|ProductionCommands|RenderedChart|PhaseOwnership|ProductionFoundation)' -count=1
go build ./cmd/control-plane ./cmd/worker ./cmd/outbox-dispatcher ./cmd/scheduler ./cmd/discovery-worker ./cmd/runner-gateway ./cmd/validation-runner ./cmd/read-runner
docker build --file build/package/control-plane/Dockerfile --tag aiops/control-plane:phase6 .
go test ./test/production -run 'TestControlPlaneImage|TestRenderedChartHasNoIndependentWeb' -count=1
```

Expected: all commands exit 0；the Phase 6 render contains eight non-WRITE roles and an empty WRITE manifest, with all images matching the lock. The Control Plane image contains the Go binary and `/opt/aiops/web`, contains no Node runtime/test-only frontend artifact, and is the only Web/API workload. The test remains valid after Phase 7 by comparing successor resources with its accepted manifest rather than banning registered WRITE names globally.

- [ ] **Step 8: Commit production commands/chart and reference foundation**

```bash
git add cmd/control-plane cmd/worker cmd/outbox-dispatcher cmd/scheduler cmd/discovery-worker cmd/runner-gateway cmd/validation-runner cmd/read-runner build/package/control-plane/Dockerfile deploy/images.lock deploy/helm/aiops test/production
git commit -m "feat(platform): assemble production read platform"
```

## Pack Completion Gate

```bash
AIOPS_TEST_POSTGRES_DSN="$AIOPS_TEST_POSTGRES_DSN" go test -race ./internal/productionplatform/... ./internal/store/postgres -run 'TestProductionPlatform' -count=1
go test -race ./internal/productionassembly ./internal/config ./cmd/... ./deploy/helm/aiops -count=1
go vet ./internal/productionplatform/... ./internal/productionassembly ./cmd/...
helm lint deploy/helm/aiops
git diff --check
```

Expected: all commands exit 0；`000020` facts scoped/immutable, production dependencies fail closed, eight non-WRITE roles and complete Phase 6 chart exist, the single Control Plane image serves same-origin Web/API without a production Node runtime, and WRITE remains absent.
