# Governed Action Catalog and Immutable Plan Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 建立 `000021_governed_actions`、逐类型 Action Catalog/Gate 和绑定 Phase 1–6 事实的不可变 ActionPlan V2。

**Architecture:** 现有 core `action_plans`、`action_queue`、`executions` 和 credential revocation 表保持兼容；`000021` 增加不可变治理绑定、normalized decision/attempt/verification/recovery/receipt records，并以 FK/trigger 替换旧的全局 production-WRITE 数据库关闭约束。Go 领域层继续使用 typed Action union，V2 hash 把 exact Asset/Snapshot/Runtime/Policy/Kill Switch 全部纳入 JCS；ActionPlan Service 在一个 serializable PostgreSQL transaction 内调用 Phase 4 `HandoffLoader` 重载可信 Proposal 闭包、解析其余可信事实并 `CreateInTx` 封存，任何漂移使整笔事务回滚。

**Tech Stack:** Go 1.26.5、PostgreSQL 18.4+、pgx v5/pgxmock、RFC 8785 JCS、SHA-256、Ed25519、标准库 `embed`。

## Global Constraints

- 每个 Task 严格采用 Red → Green → Refactor：先运行并保存预期失败，再做最小生产实现，复跑指定测试后才允许重构和提交。
- Migration 固定 `000021_governed_actions`；`000015..000020` 必须已经验收，`000022` 不得提前使用。
- `000021` 创建独立 `production_action_platform_revisions` successor；它引用 Phase 6 immutable READ baseline/handoff，但绝不修改或把 READ approval 解释为 WRITE approval。
- 只允许 `K8S_ROLLOUT_RESTART`、`K8S_SCALE`、`GITOPS_REVERT`、`AWX_SERVICE_RESTART` 四种 typed union；Catalog 不能存 executable command/template/endpoint/payload。
- ActionPlan V1 和没有 `action_plan_bindings` 的 legacy row 永远 `NON_EXECUTABLE`；production 只接受 `action-envelope.v2`。
- 所有 FK 使用 Tenant/Workspace/Environment 复合 Scope；Plan binding、Definition、Gate、Decision、mutation step、Receipt append-only。Attempt identity/bindings immutable，lifecycle projection 只能用当前 fence/version 单调推进并同步写 audit event。
- Action type gate 默认 `CLOSED`，迁移或应用启动不能自动提升。
- 旧 production-WRITE check constraint 只有在新 FK、immutable trigger、gate revision 和 production binding check 已安装后才移除。
- 本文件不开放 claim；Package 3 才实现 gated claim/admission，旧二进制仍会拒绝 production WRITE。
- Proposals、Evidence、READ Grants 和 READ Credentials 不能被转换或复用于 WRITE。
- Phase 4 契约固定为 `actionproposal.HandoffLoader.LoadTrustedForActionPlanDerivation(context.Context, pgx.Tx, actionproposal.HandoffRequest) (actionproposal.TrustedDerivationSource, error)`；必须与 ActionPlan 封存共用同一个 serializable `pgx.Tx`，不得在事务外预读 Proposal/Catalog/Evidence/Snapshot 后拼接 Plan。
- ActionPlan 创建入口固定为 `POST /api/v1/workspaces/{workspace_id}/environments/{environment_id}/services/{service_id}/action-plans`；认证 Principal 提供 Tenant，三个 path 参数提供 Workspace/Environment/Service，服务端据此构造完整 `investigationgrant.Scope`。body、Proposal projection 或事务外查询不得补充/覆盖任何 Scope 字段。
- `SealIntent` 只含 Proposal ID、expected Proposal/Intent digest、Action type、typed parameters 和 change reason；Principal、Scope、Target、window、verification、compensation、Idempotency-Key 和 request hash 均不是可提交字段。
- 生产 repository 必须 PostgreSQL；memory implementation 仅允许 `*_test.go`。

---

### Task 1: Add the 000021 governed-action persistence contract

**Files:**
- Create: `migrations/000021_governed_actions.up.sql`
- Create: `migrations/000021_governed_actions.down.sql`
- Modify: `internal/store/postgres/migrations_integration_test.go`
- Create: `internal/actioncatalog/postgres/migration_test.go`

**Interfaces:**
- Consumes: scoped `assets`、`asset_snapshots`、`runtime_publications`、`kill_switch_revisions`、core `action_plans/policy_decisions/approvals/executions`、`action_queue`、`credential_revocations`、`runner_registrations`。
- Produces: 16 governed-action relations plus production-only bindings on existing write queue/credential/Runner records。

Owned relations:

| Relation | Primary identity | Safety purpose |
|---|---|---|
| `production_action_platform_revisions` | Scope + successor id/revision | Phase 6 handoff + READ baseline + exact accepted Action/WRITE deployment manifest |
| `action_definition_revisions` | Scope + action type + revision | immutable typed adapter/schema/verification/credential contract |
| `action_type_gate_revisions` | Scope + action type + revision | CLOSED→drill→canary→AVAILABLE append-only gate |
| `write_runner_realms` | Scope + realm id/revision | WRITE-only trust/issuer/network/adapters |
| `action_plan_bindings` | Scope + action_plan_id | V2 exact Asset/Snapshot/Target/Runtime/Policy/Kill/Evidence closure |
| `action_policy_snapshots` | Scope + id | per-stage immutable evaluation input/output digest |
| `action_reauthentication_proofs` | Scope + id | one-time plan/subject/auth_time/acr/amr binding hash |
| `action_approval_decisions` | Scope + id | one human decision per subject/plan/approval round |
| `action_attempts` | Scope + id | Action/lease epoch/fencing/admission/credential identity |
| `action_mutation_steps` | Scope + attempt + ordinal | fixed per-step send intent/outcome; no repeated provider write |
| `action_verification_runs` | Scope + id | independent post-action verification lifecycle |
| `action_verification_checks` | Scope + run + code | bounded low-sensitivity post-state facts |
| `action_reconciliation_cases` | Scope + id | uncertain outcome facts and escalation |
| `action_rollback_attempts` | Scope + id | separately fenced safe compensation |
| `action_receipts` | Scope + id | immutable terminal chain hash |
| `action_drill_results` | Scope + id | non-production/canary acceptance evidence |

- [ ] **Step 1: Write failing real-PostgreSQL migration tests**

Add:

```go
func TestGovernedActionsMigrationRequiresPhasesOneThroughSix(t *testing.T)
func TestGovernedActionsSuccessorRequiresAcceptedReadHandoffAndExactBaseline(t *testing.T)
func TestGovernedActionsMigrationRejectsCrossScopeBindings(t *testing.T)
func TestGovernedActionsMigrationMakesPlansAndReceiptsImmutable(t *testing.T)
func TestGovernedActionsProductionQueueRequiresV2BindingAndRejectsClosedGate(t *testing.T)
func TestGovernedActionsAttemptCredentialAndFenceAreUnique(t *testing.T)
func TestGovernedActionsMutationStepOrdinalsAreUniqueAndImmutable(t *testing.T)
func TestGovernedActionsDownRefusesProductionOrAuditState(t *testing.T)
func TestGovernedActionsMigrationRoundTripsEmptyDatabase(t *testing.T)
```

The tests prove:

- every Plan FK carries Tenant/Workspace/Environment and exact prior-phase row;
- one sealed Plan has one binding and its PlanHash/canonical digest cannot update/delete;
- one Action + attempt number, one Action + lease epoch and one credential per Attempt are unique;
- duplicate Receipt/verification/rollback completion cannot overwrite prior proof;
- a production queue row without V2 plan, definition revision, current gate revision and WRITE Realm is rejected;
- gate defaults CLOSED and no SQL path promotes it implicitly;
- down migration returns SQLSTATE `55000` with `governed_actions_down_guard` while any Phase 7 state remains.

- [ ] **Step 2: Run tests to verify failure**

Run:

```bash
AIOPS_TEST_POSTGRES_DSN="$AIOPS_TEST_POSTGRES_DSN" go test ./internal/store/postgres ./internal/actioncatalog/postgres -run 'TestGovernedActions' -count=1
```

Expected: FAIL because `000021` and governed-action tables do not exist.

- [ ] **Step 3: Implement prerequisites and immutable catalog/plan tables**

The migration begins:

```sql
BEGIN;

DO $$
BEGIN
    IF to_regclass('public.assets') IS NULL
       OR to_regclass('public.asset_snapshots') IS NULL
       OR to_regclass('public.runtime_publications') IS NULL
       OR to_regclass('public.kill_switch_revisions') IS NULL
       OR to_regclass('public.action_queue') IS NULL
       OR to_regclass('public.production_platform_revisions') IS NULL
       OR to_regclass('public.production_read_rollout_revisions') IS NULL
       OR to_regclass('public.production_readiness_decisions') IS NULL
       OR to_regclass('public.production_rollout_gate_evidence') IS NULL
       OR to_regclass('public.credential_revocations') IS NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'governed actions require accepted migrations 000015 through 000020',
            CONSTRAINT = 'governed_actions_prerequisite';
    END IF;
END;
$$;

CREATE TABLE production_action_platform_revisions (
    tenant_id uuid NOT NULL,
    workspace_id uuid NOT NULL,
    environment_id uuid NOT NULL,
    id uuid NOT NULL,
    revision bigint NOT NULL CHECK (revision > 0),
    read_platform_id uuid NOT NULL,
    read_platform_revision bigint NOT NULL,
    read_rollout_id uuid NOT NULL,
    read_rollout_revision bigint NOT NULL,
    readiness_decision_revision bigint NOT NULL,
    phase6_handoff_id uuid NOT NULL,
    phase6_handoff_digest char(64) NOT NULL CHECK (phase6_handoff_digest ~ '^[a-f0-9]{64}$'),
    read_baseline_digest text NOT NULL CHECK (read_baseline_digest ~ '^[a-f0-9]{64}$'),
    action_manifest_digest text NOT NULL CHECK (action_manifest_digest ~ '^[a-f0-9]{64}$'),
    chart_digest text NOT NULL CHECK (chart_digest ~ '^[a-f0-9]{64}$'),
    values_schema_digest text NOT NULL CHECK (values_schema_digest ~ '^[a-f0-9]{64}$'),
    images_lock_digest text NOT NULL CHECK (images_lock_digest ~ '^[a-f0-9]{64}$'),
    workload_identity_digest text NOT NULL CHECK (workload_identity_digest ~ '^[a-f0-9]{64}$'),
    network_policy_digest text NOT NULL CHECK (network_policy_digest ~ '^[a-f0-9]{64}$'),
    status text NOT NULL CHECK (status IN ('DRAFT','VALIDATED','ACCEPTED','SUPERSEDED','REVOKED')),
    manifest_digest text NOT NULL CHECK (manifest_digest ~ '^[a-f0-9]{64}$'),
    created_at timestamptz NOT NULL,
    accepted_at timestamptz,
    PRIMARY KEY (tenant_id,workspace_id,environment_id,id,revision),
    FOREIGN KEY (tenant_id,workspace_id,environment_id,read_platform_id,read_platform_revision)
      REFERENCES production_platform_revisions (tenant_id,workspace_id,environment_id,id,revision),
    FOREIGN KEY (tenant_id,workspace_id,environment_id,read_rollout_id,read_rollout_revision)
      REFERENCES production_read_rollout_revisions (tenant_id,workspace_id,environment_id,id,revision),
    FOREIGN KEY (tenant_id,workspace_id,environment_id,read_rollout_id,read_rollout_revision,readiness_decision_revision,phase6_handoff_id,phase6_handoff_digest)
      REFERENCES production_readiness_decisions (tenant_id,workspace_id,environment_id,rollout_id,rollout_revision,decision_revision,handoff_id,handoff_digest),
    CHECK ((status = 'ACCEPTED') = (accepted_at IS NOT NULL))
);

CREATE TABLE action_definition_revisions (
    tenant_id uuid NOT NULL,
    workspace_id uuid NOT NULL,
    environment_id uuid NOT NULL,
    action_type text NOT NULL CHECK (action_type IN (
        'K8S_ROLLOUT_RESTART',
        'K8S_SCALE',
        'GITOPS_REVERT',
        'AWX_SERVICE_RESTART'
    )),
    revision bigint NOT NULL CHECK (revision > 0),
    adapter_family text NOT NULL CHECK (
        adapter_family IN ('KUBERNETES', 'GITOPS', 'AWX')
    ),
    parameter_schema_digest text NOT NULL,
    verification_mode text NOT NULL CHECK (verification_mode IN (
        'KUBERNETES_ROLLOUT',
        'ARGO_CD_HEALTH',
        'AWX_SERVICE_HEALTH'
    )),
    compensation_mode text NOT NULL CHECK (
        compensation_mode IN ('EXACT_SCALE_RESTORE', 'MANUAL_ONLY', 'NEW_PLAN_ONLY')
    ),
    credential_permission text NOT NULL,
    max_credential_ttl_seconds integer NOT NULL
        CHECK (max_credential_ttl_seconds BETWEEN 1 AND 300),
    definition_digest text NOT NULL,
    created_by text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    PRIMARY KEY (
        tenant_id, workspace_id, environment_id, action_type, revision
    ),
    UNIQUE (
        tenant_id, workspace_id, environment_id, action_type, definition_digest
    ),
    CHECK (
        parameter_schema_digest ~ '^[a-f0-9]{64}$'
        AND definition_digest ~ '^[a-f0-9]{64}$'
    )
);
```

`action_plan_bindings` requires exact columns: `tenant_id/workspace_id/environment_id/action_plan_id/service_id/incident_id/investigation_id/action_type/action_definition_revision/action_definition_digest/asset_id/asset_revision/asset_snapshot_id/asset_snapshot_digest/target_digest/runtime_publication_id/runtime_bundle_digest/policy_version/policy_digest/kill_switch_revision/kill_switch_digest/evidence_digest/phase6_handoff_id/phase6_handoff_digest/read_baseline_digest/read_admission_revision/read_admission_digest/action_platform_id/action_platform_revision/action_platform_manifest_digest/envelope_schema_version/envelope_canonical_sha256/status/version/created_at`. It has a full-Scope FK to the successor, and the successor has full-Scope FKs to the Phase 6 baseline/rollout/decision. Status is `SEALED|SUPERSEDED|EXPIRED|REVOKED`; only append-only status events may change effective state—binding row itself is immutable.

Every digest uses 64 lowercase hex. Every revision is positive. All timestamps are finite UTC. Install a common `reject_governed_immutable_mutation()` trigger on Definition、Plan binding、Policy snapshot、Reauth proof、Approval decision、Verification check、Receipt and Drill result before enabling production rows.

- [ ] **Step 4: Add attempt/recovery tables and safely replace legacy production closure**

`action_attempts` binds `action_id/action_plan_id/attempt/lease_epoch/runner_id/write_realm_id/phase6_handoff_digest/read_baseline_digest/read_admission_revision/read_admission_digest/action_platform_id/action_platform_revision/action_platform_manifest_digest/admission_digest/policy_snapshot_id/approval_set_digest/credential_revocation_id/status/version`. Identity/binding columns never change；status/version can only advance under matching lease epoch + expected version. Status is `ADMITTING|ADMITTED|RUNNING|FINALIZING|VERIFYING|RECONCILING|ROLLBACK_PENDING|ROLLING_BACK|VERIFIED|FAILED|ROLLED_BACK|HUMAN_REQUIRED`.

`action_mutation_steps` binds Scope、Attempt、fixed ordinal、operation code、request digest、`SEND_INTENT` time、definite/unknown outcome、safe external operation ID and result digest. `(Scope, attempt_id, step_ordinal)` is unique；an ordinal can be anchored once and finalized once under the same fence, never deleted/reopened. The database rejects ordinals not declared by the immutable Definition graph.

Alter existing tables only after all new constraints exist:

```sql
ALTER TABLE action_queue
    ADD COLUMN action_plan_id uuid,
    ADD COLUMN action_definition_revision bigint,
    ADD COLUMN action_gate_revision bigint,
    ADD COLUMN action_platform_id uuid,
    ADD COLUMN action_platform_revision bigint,
    ADD COLUMN action_platform_manifest_digest text,
    ADD COLUMN write_realm_id uuid,
    ADD CONSTRAINT action_queue_production_v2_shape_ck CHECK (
        production = false OR (
            action_plan_id IS NOT NULL
            AND action_definition_revision IS NOT NULL
            AND action_gate_revision IS NOT NULL
            AND action_platform_id IS NOT NULL
            AND action_platform_revision IS NOT NULL
            AND action_platform_manifest_digest ~ '^[a-f0-9]{64}$'
            AND write_realm_id IS NOT NULL
        )
    );

ALTER TABLE runner_registrations
    ADD COLUMN write_realm_id uuid,
    ADD CONSTRAINT runner_registration_write_realm_shape_ck CHECK (
        (runner_pool = 'WRITE' AND write_realm_id IS NOT NULL)
        OR (runner_pool <> 'WRITE' AND write_realm_id IS NULL)
    );

ALTER TABLE credential_revocations
    ADD COLUMN action_attempt_id uuid,
    ADD CONSTRAINT credential_production_attempt_ck CHECK (
        production = false OR action_attempt_id IS NOT NULL
    );
```

Then drop only `action_queue_no_active_production_write_ck`, `execution_leases_no_active_production_write_ck` and `credential_revocations_non_production_ck`. Preserve active-target uniqueness and the global single-production-write index as an initial blast-radius ceiling. Package 6 may only relax the global ceiling through a future migration after canary evidence; this phase does not.

- [ ] **Step 5: Implement guarded down and run migration tests**

Down refuses if any `000021` table is nonempty, any queue/credential has `production=true`, or any Runner has `write_realm_id`. Empty rollback restores the three legacy closure constraints before dropping new columns/tables.

Run:

```bash
AIOPS_TEST_POSTGRES_DSN="$AIOPS_TEST_POSTGRES_DSN" go test ./internal/store/postgres ./internal/actioncatalog/postgres -run 'TestGovernedActions' -count=1
```

Expected: PASS；prerequisite、Scope、immutability、closed gate、attempt/credential uniqueness and guarded round-trip all pass.

- [ ] **Step 6: Commit**

```bash
git add migrations/000021_governed_actions.up.sql migrations/000021_governed_actions.down.sql internal/store/postgres/migrations_integration_test.go internal/actioncatalog/postgres/migration_test.go
git commit -m "feat: add governed action persistence contract"
```

### Task 2: Implement the fixed Action Catalog and ActionEnvelope V2

**Files:**
- Create: `internal/actioncatalog/definition.go`
- Create: `internal/actioncatalog/definition_test.go`
- Create: `internal/actioncatalog/builtins.go`
- Create: `internal/actioncatalog/builtins_test.go`
- Create: `internal/actioncatalog/canonical.go`
- Create: `internal/actioncatalog/schemas/k8s-rollout-restart.v1.json`
- Create: `internal/actioncatalog/schemas/k8s-scale.v1.json`
- Create: `internal/actioncatalog/schemas/gitops-revert.v1.json`
- Create: `internal/actioncatalog/schemas/awx-service-restart.v1.json`
- Modify: `internal/action/envelope.go`
- Modify: `internal/action/envelope_test.go`
- Create: `internal/actionplan/plan.go`
- Create: `internal/actionplan/plan_test.go`
- Create: `internal/actionplan/canonical.go`
- Create: `internal/actionplan/canonical_test.go`

**Interfaces:**
- Consumes: existing typed `action.Envelope` V1 validators and Ed25519 `action.Seal/Verify`。
- Produces:

```go
func actioncatalog.Builtins() []actioncatalog.Definition
func actioncatalog.Digest(actioncatalog.Definition) (string, error)
func action.ValidateForProduction(action.Envelope, time.Time) error
func actionplan.New(
    actionplan.CreateCommand,
    action.Envelope,
    time.Time,
) (actionplan.Plan, error)
```

- [ ] **Step 1: Write failing catalog, V2 and hash tests**

```go
func TestBuiltinsContainOnlyReviewedTypedActions(t *testing.T)
func TestBuiltinDefinitionDigestsAreDeterministic(t *testing.T)
func TestProductionEnvelopeRequiresEveryGovernanceDigest(t *testing.T)
func TestProductionEnvelopeRequiresPhase6HandoffAndActionPlatformSuccessor(t *testing.T)
func TestPlanHashChangesForEverySnapshotRuntimePolicyOrKillBinding(t *testing.T)
func TestProductionEnvelopeRejectsArbitraryCommandSQLAndEndpointFields(t *testing.T)
func TestLegacyEnvelopeRemainsNonExecutableInProduction(t *testing.T)
func TestNewPlanCopiesAllSlicesAndCanonicalBytes(t *testing.T)
```

Use a table that independently mutates Tenant、Environment、Asset revision、Snapshot、Target、Runtime、Definition、Policy、Kill Switch、Evidence、Phase 6 handoff、READ baseline/admission、Action platform successor/manifest、parameter、verification、compensation and credential scope; every mutation must change PlanHash or fail validation.

- [ ] **Step 2: Run tests to verify failure**

Run:

```bash
go test ./internal/action ./internal/actioncatalog ./internal/actionplan -count=1
```

Expected: FAIL because Catalog, V2 governance binding and ActionPlan domain do not exist.

- [ ] **Step 3: Implement exact catalog types and built-ins**

`internal/actioncatalog/definition.go`:

```go
package actioncatalog

import (
    "time"

    "github.com/seaworld008/aiops-system/internal/action"
    "github.com/seaworld008/aiops-system/internal/assetcatalog"
)

type AdapterFamily string
type GateStatus string

const (
    AdapterKubernetes AdapterFamily = "KUBERNETES"
    AdapterGitOps AdapterFamily = "GITOPS"
    AdapterAWX AdapterFamily = "AWX"

    GateClosed GateStatus = "CLOSED"
    GateNonProductionReady GateStatus = "NON_PRODUCTION_READY"
    GateDrilling GateStatus = "DRILLING"
    GateCanaryApproved GateStatus = "CANARY_APPROVED"
    GateCanaryRunning GateStatus = "CANARY_RUNNING"
    GateAvailable GateStatus = "AVAILABLE"
    GateSuspended GateStatus = "SUSPENDED"
)

type Definition struct {
    Scope assetcatalog.Scope
    ActionType action.ActionType
    Revision int64
    Adapter AdapterFamily
    ParameterSchemaVersion string
    ParameterSchema []byte
    ParameterSchemaDigest string
    VerificationMode string
    CompensationMode string
    CredentialPermission string
    MaxCredentialTTL time.Duration
    Digest string
}

type GateRevision struct {
    Scope assetcatalog.Scope
    ActionType action.ActionType
    Revision int64
    Status GateStatus
    DefinitionRevision int64
    DefinitionDigest string
    DrillCount int
    VerifiedDrillCount int
    UnauthorizedMutationCount int
    DuplicateMutationCount int
    EvidenceDigest string
    DecisionID string
    CreatedBy string
    CreatedAt time.Time
}
```

`Builtins` returns exactly four copied Definitions. Schema JSON has `additionalProperties:false` and no `command/args/env/sql/url/endpoint/headers/body/payload` property. Runtime validation remains typed Go code in `internal/action`; JSON Schema is for contract/UI parity, not an executable adapter template.

Fixed mapping:

| Type | Adapter | Verification | Compensation | Credential permission | TTL |
|---|---|---|---|---|---:|
| K8S_ROLLOUT_RESTART | KUBERNETES | KUBERNETES_ROLLOUT | MANUAL_ONLY | PATCH_DEPLOYMENT_RESTART | 300s |
| K8S_SCALE | KUBERNETES | KUBERNETES_ROLLOUT | EXACT_SCALE_RESTORE | PATCH_DEPLOYMENT_SCALE | 300s |
| GITOPS_REVERT | GITOPS | ARGO_CD_HEALTH | NEW_PLAN_ONLY | CREATE_REVERT_MR | 300s |
| AWX_SERVICE_RESTART | AWX | AWX_SERVICE_HEALTH | MANUAL_ONLY | LAUNCH_SERVICE_RESTART_TEMPLATE | 300s |

- [ ] **Step 4: Add the complete V2 governance binding**

Extend `action.Envelope`:

```go
const SchemaVersionV2 = "action-envelope.v2"

type PlatformBinding struct {
    Phase6HandoffID string `json:"phase6_handoff_id"`
    Phase6HandoffDigest string `json:"phase6_handoff_digest"`
    ReadBaselineDigest string `json:"read_baseline_digest"`
    ReadAdmissionRevision int64 `json:"read_admission_revision"`
    ReadAdmissionDigest string `json:"read_admission_digest"`
    ActionPlatformID string `json:"action_platform_id"`
    ActionPlatformRevision int64 `json:"action_platform_revision"`
    ActionPlatformManifestDigest string `json:"action_platform_manifest_digest"`
    ActionManifestDigest string `json:"action_manifest_digest"`
}

type GovernanceBinding struct {
    TenantID string `json:"tenant_id"`
    WorkspaceID string `json:"workspace_id"`
    EnvironmentID string `json:"environment_id"`
    ServiceID string `json:"service_id"`
    ActionDefinitionRevision int64 `json:"action_definition_revision"`
    ActionDefinitionDigest string `json:"action_definition_digest"`
    AssetID string `json:"asset_id"`
    AssetRevision int64 `json:"asset_revision"`
    AssetSnapshotID string `json:"asset_snapshot_id"`
    AssetSnapshotDigest string `json:"asset_snapshot_digest"`
    TargetDigest string `json:"target_digest"`
    RuntimePublicationID string `json:"runtime_publication_id"`
    RuntimeBundleDigest string `json:"runtime_bundle_digest"`
    PolicyDigest string `json:"policy_digest"`
    KillSwitchRevision string `json:"kill_switch_revision"`
    KillSwitchDigest string `json:"kill_switch_digest"`
    EvidenceDigest string `json:"evidence_digest"`
    Platform PlatformBinding `json:"platform"`
}

type Envelope struct {
    SchemaVersion string `json:"schema_version"`
    ActionID string `json:"action_id"`
    WorkspaceID string `json:"workspace_id"`
    IncidentID string `json:"incident_id"`
    RequestedBy string `json:"requested_by"`
    ActionType ActionType `json:"action_type"`
    Governance GovernanceBinding `json:"governance"`
    Target TargetRef `json:"target_ref"`
    Parameters ActionParameters `json:"parameters"`
    ObservedState ObservedState `json:"observed_state"`
    Preconditions Preconditions `json:"preconditions"`
    Verification VerificationPlan `json:"verification"`
    Compensation CompensationPlan `json:"compensation"`
    Risk RiskAssessment `json:"risk"`
    PolicyVersion string `json:"policy_version"`
    PlanHash string `json:"plan_hash"`
    CredentialScope CredentialScope `json:"credential_scope"`
    IdempotencyKey string `json:"idempotency_key"`
    NotBefore time.Time `json:"not_before"`
    ExpiresAt time.Time `json:"expires_at"`
    TraceID string `json:"trace_id"`
    Signature Signature `json:"signature"`
}
```

`ValidateForProduction` requires V2、all IDs、positive revisions、64-hex digests、matching duplicated Workspace/Environment/Service, Definition mapping, nonempty Phase 6 handoff、current READ admission snapshot、exact ACCEPTED Action platform successor, ≤30-minute envelope validity and ≤5-minute credential TTL. Existing `Seal` includes Governance in JCS automatically. V1 can still validate for historical non-production receipts but production submission returns `ErrProductionBindingRequired`.

- [ ] **Step 5: Implement immutable Plan type and run tests**

```go
type Status string

const (
    StatusSealed Status = "SEALED"
    StatusSuperseded Status = "SUPERSEDED"
    StatusExpired Status = "EXPIRED"
    StatusRevoked Status = "REVOKED"
)

type Plan struct {
    ID string
    Scope assetcatalog.Scope
    IncidentID string
    InvestigationID string
    Envelope action.Envelope
    PlanHash string
    CanonicalSHA256 string
    Status Status
    Version int64
    CreatedBy string
    CreatedAt time.Time
}
```

`New` verifies production V2, copies nested host IDs/reason codes/schema bytes, requires `PlanHash == Envelope.PlanHash` and hashes canonical sealed envelope. No method mutates a sealed Plan; supersede/revoke creates append-only state event in Task 3.

Run:

```bash
go test ./internal/action ./internal/actioncatalog ./internal/actionplan -count=1
go test -race ./internal/action ./internal/actioncatalog ./internal/actionplan -count=1
```

Expected: PASS；four exact definitions, V2 negative fields, mutation matrix, deep-copy and deterministic hashes pass.

- [ ] **Step 6: Commit**

```bash
git add internal/action internal/actioncatalog internal/actionplan
git commit -m "feat: define fixed governed action plans"
```

### Task 3: Persist built-ins and seal proposals against trusted Phase 1–6 facts

**Files:**
- Create: `internal/actioncatalog/repository.go`
- Create: `internal/actioncatalog/postgres/repository.go`
- Create: `internal/actioncatalog/postgres/repository_test.go`
- Create: `internal/actionplatform/repository.go`
- Create: `internal/actionplatform/postgres/repository.go`
- Create: `internal/actionplatform/postgres/repository_test.go`
- Create: `internal/actionplatform/service.go`
- Create: `internal/actionplatform/service_test.go`
- Create: `internal/actionplan/repository.go`
- Create: `internal/actionplan/unit_of_work.go`
- Create: `internal/actionplan/postgres/repository.go`
- Create: `internal/actionplan/postgres/unit_of_work.go`
- Create: `internal/actionplan/postgres/unit_of_work_test.go`
- Create: `internal/actionplan/postgres/repository_test.go`
- Create: `internal/actionplan/service.go`
- Create: `internal/actionplan/service_test.go`
- Modify: `cmd/control-plane/main.go`
- Modify: `cmd/control-plane/main_test.go`

**Interfaces:**
- Consumes: Phase 1 exact Asset；Phase 2 Published Target/Runtime；Phase 4 exact `actionproposal.HandoffLoader.LoadTrustedForActionPlanDerivation(context.Context, pgx.Tx, actionproposal.HandoffRequest) (actionproposal.TrustedDerivationSource, error)`；Phase 6 immutable platform/rollout/readiness handoff and live READ admission；Task 2 definitions and signer。
- Produces: content-addressed Action platform successor repository；`SealUnitOfWork.WithinSerializable`；tx-aware remaining-facts resolver；`PlanRepository.CreateInTx`；one atomically sealed trusted dual-platform closure。

```go
type CatalogRepository interface {
    EnsureBuiltins(
        context.Context,
        assetcatalog.Scope,
        []actioncatalog.Definition,
        string,
    ) error
    GetDefinition(
        context.Context,
        assetcatalog.Scope,
        action.ActionType,
        int64,
    ) (actioncatalog.Definition, error)
    CurrentGate(
        context.Context,
        assetcatalog.Scope,
        action.ActionType,
    ) (actioncatalog.GateRevision, error)
}

type SuccessorRepository interface {
    PublishValidated(
        context.Context,
        actionplatform.SuccessorRevision,
    ) error
    Accept(
        context.Context,
        assetcatalog.Scope,
        string,
        int64,
        string,
    ) error
    CurrentAccepted(
        context.Context,
        assetcatalog.Scope,
    ) (actionplatform.SuccessorRevision, error)
}

type PlanRepository interface {
    CreateInTx(
        ctx context.Context,
        tx pgx.Tx,
        plan actionplan.Plan,
        idempotencyKey string,
        requestHash string,
    ) (actionplan.Plan, bool, error)
    Get(
        context.Context,
        assetcatalog.Scope,
        string,
    ) (actionplan.Plan, error)
    List(
        context.Context,
        actionplan.ListRequest,
    ) (actionplan.Page, error)
    AppendState(
        context.Context,
        actionplan.StateEvent,
        int64,
    ) (actionplan.Plan, error)
}

type TrustedFactsResolver interface {
    ResolveRemainingForSeal(
        ctx context.Context,
        tx pgx.Tx,
        source actionproposal.TrustedDerivationSource,
    ) (actionplan.TrustedFacts, error)
}

type SealUnitOfWork interface {
    WithinSerializable(
        ctx context.Context,
        fn func(context.Context, pgx.Tx) error,
    ) error
}
```

Phase 4 `TrustedDerivationSource` is the only source for the reloaded ActionProposal ID/digest、typed intent、Catalog revision/digest、Evidence IDs/content hashes/digest、Snapshot ID/digest and Asset binding. `TrustedFacts` preserves that closure and adds exact Scope、Incident/Investigation、Asset lifecycle/mapping、Target digest、Runtime Publication/Bundle digest/status、Policy version/digest、Kill Switch revision/digest/effective enabled、typed target/observed state、allowed Credential Reference/WRITE Realm and the complete `PlatformClosure` below. It contains no endpoint or credential material.

```go
type PlatformClosure struct {
    Phase6HandoffID              string
    Phase6HandoffDigest          string
    ReadPlatformID               string
    ReadPlatformRevision         int64
    ReadRolloutID                string
    ReadRolloutRevision          int64
    ReadinessDecisionRevision    int64
    ReadBaselineDigest           string
    ReadAdmissionRevision        int64
    ReadAdmissionDigest          string
    ActionPlatformID             string
    ActionPlatformRevision       int64
    ActionPlatformManifestDigest string
    ActionManifestDigest         string
}
```

- [ ] **Step 1: Write failing repository and sealing tests**

```go
func TestEnsureBuiltinsIsIdempotentAndRejectsDigestDrift(t *testing.T)
func TestCreatePlanCommitsCorePlanAndBindingAtomically(t *testing.T)
func TestCreatePlanReplayUsesScopeKeyAndSemanticHash(t *testing.T)
func TestSealUsesHandoffLoaderResolverAndCreateInSameSerializableTransaction(t *testing.T)
func TestSealBuildsHandoffRequestFromAuthenticatedPrincipalAndFullTWESURLScope(t *testing.T)
func TestSealRejectsMissingMismatchedOrBodySuppliedServiceScopeBeforeHandoff(t *testing.T)
func TestSealLoadsHandoffBeforeResolvingRemainingTrustedFacts(t *testing.T)
func TestSealRollsBackPlanAndIdempotencyWhenProposalCatalogEvidenceOrSnapshotDrifts(t *testing.T)
func TestSealRollsBackPlanAndIdempotencyWhenRemainingTrustedFactsDrift(t *testing.T)
func TestSealRejectsStaleQuarantinedOrNonExactAsset(t *testing.T)
func TestSealRejectsSnapshotRuntimePolicyOrKillDrift(t *testing.T)
func TestSealRejectsMissingExpiredOrChangedPhase6Handoff(t *testing.T)
func TestSealRejectsUnacceptedOrMismatchedActionPlatformSuccessor(t *testing.T)
func TestSealLoadsPersistedProposalAndRejectsUnknownOrCrossScopeID(t *testing.T)
func TestSealRejectsProposalCatalogEvidenceDigestOrIntentDrift(t *testing.T)
func TestSealRecomputesAndConstantTimeComparesBothExpectedDigests(t *testing.T)
func TestSealCopiesTrustedFactsInsteadOfProposalBindings(t *testing.T)
func TestSealReconstructsEverySafetyParameterFromTrustedFacts(t *testing.T)
func TestSealIntentContainsOnlyHumanConfirmationFields(t *testing.T)
func TestSealComputesRequestHashServerSideAndTakesIdempotencyKeyOutOfBand(t *testing.T)
func TestSealDerivesRequesterAndWindowFromPrincipalPolicyAndDefinition(t *testing.T)
func TestControlPlaneFailsClosedWhenBuiltinPersistenceFails(t *testing.T)
func TestControlPlaneFailsClosedWithoutHandoffLoaderOrSealUnitOfWork(t *testing.T)
```

Create the proposal fixture through the real Phase 4 append-only Repository. The integration test begins one serializable UnitOfWork and proves the exact same `pgx.Tx` reaches `HandoffLoader`、`ResolveRemainingForSeal` and `CreateInTx` in that order. It mutates full T/W/E/S Scope、Proposal、Catalog、Evidence、Snapshot and each later trusted fact between attempts；every error must leave zero Plan/binding/idempotency row. The request repeats only expected digests、Action type and typed parameters as an exact human confirmation；a mismatch is rejected, never treated as an edit。Proposal ID identifies the candidate but grants no authority；authority comes only from Principal + service-qualified URL Scope + current server facts. Add malicious variants with tenant、workspace、environment、service、requester、subject、role、auth time、execution window、verification、compensation、target digest、Runtime digest、credential scope、endpoint、command、approval、`idempotency_key` and `request_hash` fields；the closed request schema must reject every forbidden field before service invocation.

- [ ] **Step 2: Run tests to verify failure**

Run:

```bash
go test ./internal/actioncatalog/postgres ./internal/actionplan/... ./cmd/control-plane -run 'Builtin|Plan|Seal' -count=1
```

Expected: FAIL because repositories and sealing service do not exist.

- [ ] **Step 3: Implement exact seal command and trusted-facts checks**

```go
type SealIntent struct {
    ProposalID             string
    ExpectedProposalDigest string
    ExpectedIntentDigest   string
    ActionType             action.ActionType
    TypedParameters action.ActionParameters
    ChangeReason    string
}

type Service struct {
    Plans    PlanRepository
    Facts    TrustedFactsResolver
    Handoffs actionproposal.HandoffLoader
    SealUOW  SealUnitOfWork
    Signer   action.Signer
    IDSource func() string
    Clock    func() time.Time
}

func (service *Service) SealProposal(
    ctx context.Context,
    principal authn.Principal,
    scope investigationgrant.Scope,
    intent SealIntent,
    idempotencyKey string,
) (actionplan.Plan, error)
```

`SealProposal` receives `principal` only from verified OIDC middleware、the complete `investigationgrant.Scope{TenantID,WorkspaceID,EnvironmentID,ServiceID}` only from authenticated Tenant plus canonical `/workspaces/{workspace_id}/environments/{environment_id}/services/{service_id}` path context，and `idempotencyKey` only from the validated header；none is decoded from request JSON or a Proposal pre-read. The service validates all four nonempty Scope components and current Principal authorization before opening the transaction，then computes `requestHash = SHA-256(JCS(principal subject + exact T/W/E/S Scope + SealIntent))` server-side and never accepts a caller hash.

`SealUOW.WithinSerializable` owns the complete operation. Inside its callback the Service's first proposal-related action is `actionproposal.NewHandoffRequest(principal, scope, intent.ProposalID, intent.ExpectedProposalDigest)`；before that call neither handler nor Service may query Proposal/Catalog/Evidence/Snapshot or derive ServiceID from Proposal. It then passes that request and the callback's exact `pgx.Tx` to `Handoffs.LoadTrustedForActionPlanDerivation`. The Loader locks/reloads and revalidates the persisted `PROPOSAL_ONLY` ActionProposal、Catalog、Evidence and Snapshot closure against the full T/W/E/S Scope，从数据库事实重算 Proposal digest 并对 expected digest 做固定长度恒时比较。Only after it returns `TrustedDerivationSource` may the Service 从该可信来源重新 canonicalize typed intent、重算 intent digest 并与 `ExpectedIntentDigest` 做固定长度恒时比较，再逐字段确认 Action type/typed parameters，then call `Facts.ResolveRemainingForSeal(ctx, tx, trustedSource)` to load the exact Phase 1–3/5/6 facts。两个 expected digest 都只是并发/漂移条件，绝不是 Proposal、Intent 或授权事实源。It requires `ACTIVE+EXACT` Asset、immutable matching Snapshot、`APPLIED` Runtime、available exact read evidence、all six Kill Switch levels enabled、current `APPROVE_PRODUCTION_READ_ONLY` Phase 6 decision/handoff and one exact `ACCEPTED` Action platform successor.

Within that same callback the Service recomputes both baseline/successor manifests, loads exact Definition/Policy, derives requester、not-before/expiry window、verification、compensation and Credential/Governance bindings exclusively from Principal/Definition/Policy/trusted facts, calls `action.Seal` with the OIDC subject, then calls `Plans.CreateInTx(ctx, tx, plan, idempotencyKey, requestHash)`. The server reconstructs scale minimum/maximum/HPA/PDB/quota facts、Git provider/base/head/diff/tree facts and every AWX Job Template/Service/OS/serial field from trusted Snapshot/Definition；a submitted mismatch is rejected. Handoff、digest、qualification、remaining-fact、seal、idempotency or insert failure returns from the callback and rolls back the whole transaction, leaving no partial Plan/binding/idempotency success. The plan can be reviewed while Gate is CLOSED, but no method here queues execution.

- [ ] **Step 4: Implement PostgreSQL transactions and production bootstrap**

`EnsureBuiltins` inserts missing revision 1 rows and CLOSED gate revision 1 in one transaction. Existing identical digests are replay; any same revision/different digest is fatal. `cmd/control-plane` performs this for every configured Scope before enabling ActionPlan routes，并显式构造/注入 Phase 4 PostgreSQL `actionproposal.HandoffLoader`、PostgreSQL `SealUnitOfWork`、tx-aware remaining-facts resolver 和 `PlanRepository`；任一依赖缺失或被 memory/fake 生产实现替代时启动失败并关闭全部 ActionPlan mutation。

`PublishValidated` reloads the Phase 6 decision through its full `(Scope, rollout, decision, handoff_id, handoff_digest)` key, requires `APPROVE_PRODUCTION_READ_ONLY`, recomputes the immutable READ baseline digest and JCS successor manifest, and proves all READ-owned chart/image/config/identity/network entries are byte-identical. Its `action_manifest_digest` enumerates every WRITE API、binary、image、ServiceAccount、Realm、NetworkPolicy、credential issuer、claim route and provider permission; an undeclared or missing surface rejects publication. `Accept` requires Package 6 signed assembly/gate evidence and appends a new immutable ACCEPTED row while superseding only the prior projection. One partial unique index permits one current ACCEPTED successor per Scope. Missing/changed handoff, closed live READ admission, altered READ path or `UNAUTHORIZED_WRITE_SURFACE_ABSENT != PASS` closes all production action submission/claim.

Plan sealing always uses `SERIALIZABLE` and one transaction boundary: `Phase 4 HandoffLoader exact fixed lock order (Investigation → Incident → proactive_run/Grant → Snapshot/Item → Evidence UUID order → Catalog facts → proposal-digest advisory lock) and trusted Proposal closure reload → Phase 6 readiness/handoff → READ platform/rollout → Action platform successor → Asset binding/lifecycle → Target/Runtime Publication → Kill Switch revisions → Action Definition/Policy → core action_plans → action_plan_bindings → idempotency`. The ActionPlan Service has no non-transactional Catalog lookup path；all seal-time Definition/Policy and remaining facts come through `ResolveRemainingForSeal(ctx, tx, trustedSource)`. It must not call a non-transactional `Create` method，and the resolver must reject a different/missing `pgx.Tx`. Every SELECT/INSERT carries complete Scope；commit occurs only after `CreateInTx` succeeds。若 PostgreSQL 返回 serialization failure，UnitOfWork 只能以相同 Principal/Scope/SealIntent/header key 从 `NewHandoffRequest` 开始重跑整个 callback；不得跨事务复用旧 `TrustedDerivationSource` 或部分 Plan。`AppendState` inserts an immutable state event and updates only the core projection version/status under expected version；it never changes envelope/hash/binding.

- [ ] **Step 5: Run repository, race and PostgreSQL tests**

Run:

```bash
go test ./internal/actioncatalog/... ./internal/actionplan/... ./cmd/control-plane -count=1
go test -race ./internal/actioncatalog/... ./internal/actionplan/... -count=1
AIOPS_TEST_POSTGRES_DSN="$AIOPS_TEST_POSTGRES_DSN" go test ./internal/actionplan/postgres -run 'Atomic|Replay|Scope|Serializable|Handoff|Drift|CreateInTx' -count=1
```

Expected: all PASS；built-in drift fails startup；same service-qualified path/header/body replay returns one Plan；T/W/E/S 任一缺失/错配在 Handoff 前 fail closed；the exact same serializable `pgx.Tx` crosses Handoff reload、remaining-fact resolution and `CreateInTx`；Proposal/Catalog/Evidence/Snapshot or later trusted-fact drift rolls back Plan/binding/idempotency completely.

- [ ] **Step 6: Commit**

```bash
git add internal/actioncatalog internal/actionplatform internal/actionplan cmd/control-plane
git commit -m "feat: seal governed plans from trusted facts"
```
