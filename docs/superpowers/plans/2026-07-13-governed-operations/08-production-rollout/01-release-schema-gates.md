# Production Release Governance Schema and Gates Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Persist immutable production release candidates, scoped rollout waves, gate evidence, independent decisions, and fail-closed promotion state.

**Architecture:** Treat a release as a content-addressed projection over accepted component revisions, infrastructure configuration, eligible Asset/Capability/Action sets, and required gates. Store evidence append-only; compute promotion eligibility in the domain and revalidate it transactionally before a wave transition. HTTP handlers expose projections and decision commands but never accept a caller-supplied final state.

**Tech Stack:** Go 1.26.5, PostgreSQL 18.4, pgx v5, OpenAPI 3.1, existing OIDC/authz/Problem Details conventions, Testify, and PostgreSQL integration tests.

## Global Constraints

- 每个 Task 严格采用 Red → Green → Refactor：先运行并保存预期失败，再做最小生产实现，复跑指定测试后才允许重构和提交。
- Baseline is `main@ad50d9f`; execute after Phase 7 acceptance from an isolated worktree without a nested `.worktrees` directory.
- Release acceptance never grants a capability. It can only promote already accepted, explicitly listed Asset/Capability/Action revisions.
- The server derives canonical digests and gate status. Browser and model input cannot set `PROMOTED`, bypass soak time, replace evidence, or widen eligibility.
- Evidence and decisions are append-only. Correction creates a new record and preserves the original.
- Production write promotion requires separation of proposer, approver, and release decider identities and fresh reauthentication at the decision boundary.
- Fakes are allowed in unit tests only. Production assembly must use the PostgreSQL repository.
- Migration is exactly `000022_production_release_governance`; it checks that required `000020_production_platform` and `000021_governed_actions` relations exist and never rewrites either migration. Accepted/current row checks occur transactionally when a release candidate is created, not during schema installation.
- Every release identity、primary key、unique key and foreign key carries `tenant_id/workspace_id/environment_id`; a synthetic single-column Scope identifier is not a substitute for the three-column Scope contract.

### Task 1: Add release-governance migration and database invariants

**Files:**
- Create: `migrations/000022_production_release_governance.up.sql`
- Create: `migrations/000022_production_release_governance.down.sql`
- Create: `internal/releasegovernance/postgres/migration_integration_test.go`
- Modify: `internal/store/postgres/migrations_integration_test.go`

**Interfaces:**
- Consumes: Tenant/Workspace/Environment Scope, accepted Phase 6 platform/read decision plus immutable handoff tuple, accepted Phase 7 `production_action_platform_revisions` successor and Action-type gate revisions, audit actor identity and lowercase SHA-256 digest convention
- Produces: immutable release, wave, evidence, decision, and transition persistence boundary

- [ ] **Step 1: Write failing migration integration tests**

Create table-driven tests that apply migrations through `000022` and assert:

```go
func TestReleaseGovernanceConstraints(t *testing.T) {
    db := migratedPostgres(t)
    releaseID := insertReleaseCandidate(t, db, acceptedReleaseFixture())

    t.Run("digest is unique within scope", func(t *testing.T) {
        _, err := db.Exec(context.Background(), duplicateReleaseSQL, releaseID)
        require.Error(t, err)
    })
    t.Run("wave scope must match release scope", func(t *testing.T) {
        _, err := db.Exec(context.Background(), crossScopeWaveSQL, releaseID)
        require.Error(t, err)
    })
    t.Run("accepted phase six and seven inputs are required", func(t *testing.T) {
        _, err := db.Exec(context.Background(), missingAcceptedInputsSQL, releaseID)
        require.Error(t, err)
    })
    t.Run("phase seven successor must bind the same phase six handoff", func(t *testing.T) {
        _, err := db.Exec(context.Background(), mismatchedSuccessorHandoffSQL, releaseID)
        require.Error(t, err)
    })
    t.Run("evidence cannot be updated or deleted", func(t *testing.T) {
        evidenceID := insertGateEvidence(t, db, releaseID)
        _, updateErr := db.Exec(context.Background(), "UPDATE release_gate_evidence SET status='PASS' WHERE id=$1", evidenceID)
        _, deleteErr := db.Exec(context.Background(), "DELETE FROM release_gate_evidence WHERE id=$1", evidenceID)
        require.Error(t, updateErr)
        require.Error(t, deleteErr)
    })
}
```

Run:

```bash
AIOPS_TEST_POSTGRES_DSN="$AIOPS_TEST_POSTGRES_DSN" go test ./internal/releasegovernance/postgres -run TestReleaseGovernanceConstraints -count=1
```

Expected: FAIL because migration `000022` and the repository test helpers do not exist.

- [ ] **Step 2: Implement the schema with explicit state checks**

The migration first asserts only that `production_platform_revisions`, `production_readiness_decisions`, `production_action_platform_revisions`, `action_definition_revisions` and `action_type_gate_revisions` exist. Candidate insertion later requires accepted/current rows through composite FKs and a transaction-local trigger；an empty up/down/up migration remains valid. Then create every table with the exact Tenant/Workspace/Environment Scope, UTC timestamps, actor digests, revisions and composite foreign keys:

```sql
CREATE TABLE production_release_candidates (
    tenant_id uuid NOT NULL,
    workspace_id uuid NOT NULL,
    environment_id uuid NOT NULL,
    id uuid NOT NULL,
    sequence_no bigint NOT NULL CHECK (sequence_no > 0),
    digest char(64) NOT NULL CHECK (digest ~ '^[a-f0-9]{64}$'),
    specification_revision char(64) NOT NULL CHECK (specification_revision ~ '^[a-f0-9]{64}$'),
    platform_id uuid NOT NULL,
    platform_revision bigint NOT NULL,
    production_read_rollout_id uuid NOT NULL,
    production_read_rollout_revision bigint NOT NULL,
    production_read_decision_revision bigint NOT NULL,
    phase6_handoff_id uuid NOT NULL,
    phase6_handoff_digest char(64) NOT NULL CHECK (phase6_handoff_digest ~ '^[a-f0-9]{64}$'),
    read_baseline_digest char(64) NOT NULL CHECK (read_baseline_digest ~ '^[a-f0-9]{64}$'),
    action_platform_id uuid NOT NULL,
    action_platform_revision bigint NOT NULL,
    action_platform_manifest_digest char(64) NOT NULL CHECK (action_platform_manifest_digest ~ '^[a-f0-9]{64}$'),
    action_manifest_digest char(64) NOT NULL CHECK (action_manifest_digest ~ '^[a-f0-9]{64}$'),
    chart_digest char(64) NOT NULL CHECK (chart_digest ~ '^[a-f0-9]{64}$'),
    values_schema_digest char(64) NOT NULL CHECK (values_schema_digest ~ '^[a-f0-9]{64}$'),
    images_lock_digest char(64) NOT NULL CHECK (images_lock_digest ~ '^[a-f0-9]{64}$'),
    workload_identity_digest char(64) NOT NULL CHECK (workload_identity_digest ~ '^[a-f0-9]{64}$'),
    network_policy_digest char(64) NOT NULL CHECK (network_policy_digest ~ '^[a-f0-9]{64}$'),
    component_manifest jsonb NOT NULL,
    eligible_manifest jsonb NOT NULL,
    state text NOT NULL CHECK (state IN ('DRAFT','GATES_PENDING','READY','ACTIVE','REJECTED','SUPERSEDED')),
    created_by_digest char(64) NOT NULL CHECK (created_by_digest ~ '^[a-f0-9]{64}$'),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, workspace_id, environment_id, id),
    UNIQUE (tenant_id, workspace_id, environment_id, sequence_no),
    UNIQUE (tenant_id, workspace_id, environment_id, digest),
    FOREIGN KEY (tenant_id, workspace_id, environment_id, platform_id, platform_revision)
      REFERENCES production_platform_revisions (tenant_id, workspace_id, environment_id, id, revision),
    FOREIGN KEY (tenant_id, workspace_id, environment_id, production_read_rollout_id, production_read_rollout_revision, production_read_decision_revision, phase6_handoff_id, phase6_handoff_digest)
      REFERENCES production_readiness_decisions (tenant_id, workspace_id, environment_id, rollout_id, rollout_revision, decision_revision, handoff_id, handoff_digest),
    FOREIGN KEY (tenant_id, workspace_id, environment_id, action_platform_id, action_platform_revision)
      REFERENCES production_action_platform_revisions (tenant_id, workspace_id, environment_id, id, revision),
    FOREIGN KEY (tenant_id, workspace_id, environment_id)
      REFERENCES environments (tenant_id, workspace_id, id) ON DELETE RESTRICT,
    CHECK (jsonb_typeof(component_manifest) = 'object' AND jsonb_typeof(eligible_manifest) = 'object')
);

CREATE TABLE production_release_waves (
    tenant_id uuid NOT NULL,
    workspace_id uuid NOT NULL,
    environment_id uuid NOT NULL,
    id uuid NOT NULL,
    release_id uuid NOT NULL,
    wave text NOT NULL CHECK (wave IN ('INTERNAL_OPERATORS','ONE_NONCRITICAL_SERVICE','TEN_PERCENT_ELIGIBLE','THIRTY_PERCENT_ELIGIBLE','FULL_ELIGIBLE_SCOPE')),
    state text NOT NULL CHECK (state IN ('PENDING','RUNNING','SOAKING','HELD','PROMOTED','ROLLING_BACK','ROLLED_BACK','FAILED')),
    hold_reason text,
    started_at timestamptz,
    soak_not_before timestamptz,
    finished_at timestamptz,
    version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
    PRIMARY KEY (tenant_id, workspace_id, environment_id, id),
    UNIQUE (tenant_id, workspace_id, environment_id, release_id, wave),
    FOREIGN KEY (tenant_id, workspace_id, environment_id, release_id)
      REFERENCES production_release_candidates(tenant_id, workspace_id, environment_id, id),
    FOREIGN KEY (tenant_id, workspace_id, environment_id)
      REFERENCES environments (tenant_id, workspace_id, id) ON DELETE RESTRICT,
    CHECK ((state = 'HELD') = (hold_reason IS NOT NULL)),
    CHECK (started_at IS NULL OR soak_not_before IS NULL OR started_at <= soak_not_before),
    CHECK (started_at IS NULL OR finished_at IS NULL OR started_at <= finished_at)
);
```

Add `production_release_eligible_actions`, `release_gate_requirements`, `release_gate_evidence`, `release_decisions`, `production_release_acceptance_decisions`, and `release_transition_outbox`. The normalized eligible-action relation carries the three Scope columns and exact `action_type/action_gate_revision`, with a composite FK to the Phase 7 gate relation；JSON manifests are projections, not referential truth. A candidate trigger requires the referenced Phase 6 decision to equal `APPROVE_PRODUCTION_READ_ONLY`, its handoff tuple to match the referenced accepted/current `production_action_platform_revisions` row, live READ admission to remain open, `UNAUTHORIZED_WRITE_SURFACE_ABSENT=PASS`, and every referenced Action gate to equal `AVAILABLE`. It compares candidate `platform_id/platform_revision` with successor `read_platform_id/read_platform_revision`, the rollout/decision columns with `read_rollout_id/read_rollout_revision/readiness_decision_revision`, and all explicit handoff/read-baseline/action-platform/action-manifest/chart/schema/image/identity/network digests with the successor row. Any mismatch rejects the insert；candidate JSON never overrides these typed facts. Every wave decision re-runs these current checks rather than treating candidate-time PASS as permanent. Gate evidence stores `gate_key`, `observed_window`, schema-versioned `summary`, opaque artifact URI/digest, producer workload identity, and `PASS|FAIL|UNKNOWN`.

`release_decisions` is wave-scoped and stores only `PROMOTE|HOLD|ROLL_BACK`. `production_release_acceptance_decisions` is separately append-only and stores exactly `HOLD|ROLL_BACK|PRODUCTION_CLOSED_LOOP_ACCEPTED`, binding the complete release digest、Phase 6 platform/read/handoff tuple、Phase 7 action-platform successor、ordered final evidence-set digest、final wave digest、chart/image/schema/policy/runtime manifests、independent signer set、recent-auth times and signature-set digest. A partial or unknown evidence set cannot produce acceptance；unique constraints allow only one accepted decision for a release digest, while correction creates a successor candidate. Every child relation uses `(tenant_id,workspace_id,environment_id,release_id,...)` keys and composite FKs.

Create database triggers that reject `UPDATE` and `DELETE` on evidence and decisions. Down migration drops triggers/functions before tables in reverse dependency order.

- [ ] **Step 3: Prove migration round-trip and constraints**

Run:

```bash
AIOPS_TEST_POSTGRES_DSN="$AIOPS_TEST_POSTGRES_DSN" go test ./internal/releasegovernance/postgres -run 'TestReleaseGovernanceConstraints|TestMigration000022RoundTrip' -count=1
```

Expected: PASS; a down/up round trip preserves earlier migrations and every negative constraint fails closed.

- [ ] **Step 4: Commit the migration boundary**

```bash
git add migrations/000022_production_release_governance.* internal/releasegovernance/postgres/migration_integration_test.go internal/store/postgres/migrations_integration_test.go
git commit -m "feat(release): add production release governance schema"
```

### Task 2: Implement canonical release candidates and gate evaluation

**Files:**
- Create: `internal/releasegovernance/model.go`
- Create: `internal/releasegovernance/canonical.go`
- Create: `internal/releasegovernance/gates.go`
- Create: `internal/releasegovernance/model_test.go`
- Create: `internal/releasegovernance/gates_test.go`

**Interfaces:**
- Consumes: accepted revision IDs/digests, typed eligible manifests, policy-defined SLO and soak requirements
- Produces: canonical ReleaseCandidate digest and deterministic `GateEvaluation`

- [ ] **Step 1: Write failing canonicalization and gate tests**

Cover field-order independence, duplicate eligible IDs, unknown gate state, expired evidence, insufficient soak, failed credential cleanup, nonzero duplicate executions, and separation-of-duty violations.

```go
func TestEvaluatePromotionFailsClosedOnUnknownEvidence(t *testing.T) {
    evaluation := EvaluatePromotion(Requirements{
        Required: []GateKey{GateAvailability, GateVerification, GateCredentialCleanup},
    }, []Evidence{
        {GateKey: GateAvailability, Status: GatePass},
        {GateKey: GateVerification, Status: GatePass},
    }, DecisionContext{SoakComplete: true, SeparationOfDuty: true})

    require.False(t, evaluation.Eligible)
    require.Equal(t, []GateKey{GateCredentialCleanup}, evaluation.Unknown)
}
```

Run:

```bash
go test ./internal/releasegovernance -run 'TestCanonical|TestEvaluatePromotion' -count=1
```

Expected: FAIL because the package does not exist.

- [ ] **Step 2: Implement immutable domain types and canonical digest**

Define typed states and a constructor that rejects empty or duplicate revisions:

```go
type ReleaseCandidate struct {
    ID                    uuid.UUID
    Scope                 assetcatalog.Scope
    SequenceNo            int64
    SpecificationRevision Digest
    Phase6PlatformID      uuid.UUID
    Phase6PlatformRevision int64
    Phase6RolloutID       uuid.UUID
    Phase6RolloutRevision int64
    Phase6DecisionRevision int64
    Phase6HandoffID       uuid.UUID
    Phase6HandoffDigest   Digest
    ReadBaselineDigest    Digest
    ActionPlatformID      uuid.UUID
    ActionPlatformRevision int64
    ActionPlatformManifestDigest Digest
    ActionManifestDigest  Digest
    ChartDigest           Digest
    ValuesSchemaDigest    Digest
    ImagesLockDigest      Digest
    WorkloadIdentityDigest Digest
    NetworkPolicyDigest   Digest
    Components            ComponentManifest
    Eligible              EligibleManifest
    Digest                Digest
    State                 ReleaseState
    CreatedByDigest       Digest
    CreatedAt             time.Time
}

type ReleaseAcceptanceDecisionKind string

const (
    ReleaseAcceptanceHold       ReleaseAcceptanceDecisionKind = "HOLD"
    ReleaseAcceptanceRollBack   ReleaseAcceptanceDecisionKind = "ROLL_BACK"
    ReleaseAcceptanceClosedLoop ReleaseAcceptanceDecisionKind = "PRODUCTION_CLOSED_LOOP_ACCEPTED"
)

func NewReleaseCandidate(input CandidateInput, now time.Time) (ReleaseCandidate, error)
func CanonicalDigest(candidate ReleaseCandidate) (Digest, error)
func EvaluatePromotion(requirements Requirements, evidence []Evidence, ctx DecisionContext) GateEvaluation
```

Canonical JSON must sort Asset, Capability, Action, chart, image, migration, policy, and runtime revision lists and use the repository's RFC 8785-compatible canonicalization library. Reject non-lowercase 64-character digest values at construction.

- [ ] **Step 3: Pass tests and expose metrics labels with bounded cardinality**

Add counters/gauges to the existing metrics registry using only `wave`, `gate_key`, `status`, and `decision`; never use asset, release, tenant, actor, or digest as a metric label.

Run:

```bash
go test -race -shuffle=on -count=1 ./internal/releasegovernance/...
go vet ./internal/releasegovernance/...
```

Expected: PASS with no race or vet findings.

- [ ] **Step 4: Commit domain logic**

```bash
git add internal/releasegovernance
git commit -m "feat(release): evaluate immutable production gates"
```

### Task 3: Add PostgreSQL repository and transactional transitions

**Files:**
- Create: `internal/releasegovernance/repository.go`
- Create: `internal/releasegovernance/postgres/repository.go`
- Create: `internal/releasegovernance/postgres/repository_integration_test.go`

**Interfaces:**
- Consumes: ReleaseCandidate, GateEvidence, Decision command, expected state/version, request metadata
- Produces: durable projections and exactly one outbox transition per accepted state change

- [ ] **Step 1: Write failing concurrency and fencing integration tests**

Test two simultaneous `PROMOTE` decisions, stale state/version, evidence insertion idempotency, repeated artifact digest, late failed evidence, transaction rollback, and outbox uniqueness.

Run:

```bash
AIOPS_TEST_POSTGRES_DSN="$AIOPS_TEST_POSTGRES_DSN" go test -race ./internal/releasegovernance/postgres -run 'TestRepository|TestConcurrentPromotion' -count=1
```

Expected: FAIL until the repository exists.

- [ ] **Step 2: Implement scoped repository operations**

```go
type Repository interface {
    CreateCandidate(context.Context, ReleaseCandidate) error
    AppendEvidence(context.Context, Evidence) error
    GetProjection(context.Context, assetcatalog.Scope, uuid.UUID) (Projection, error)
    DecideWave(context.Context, DecisionCommand) (Wave, error)
    RecordReleaseAcceptance(context.Context, ReleaseAcceptanceCommand) (ReleaseAcceptanceDecision, error)
    ListActive(context.Context, assetcatalog.Scope, Page) ([]Projection, Cursor, error)
}

type DecisionCommand struct {
    Scope              assetcatalog.Scope
    ReleaseID          uuid.UUID
    WaveID             uuid.UUID
    ExpectedState      WaveState
    ExpectedVersion    int64
    Decision           DecisionKind
    ActorID            uuid.UUID
    ReauthenticatedAt  time.Time
    RequestID          uuid.UUID
}
```

`DecideWave` must lock the release/wave row, reload current evidence, evaluate gates inside the transaction, enforce actor separation and reauthentication freshness, update using expected version, and insert the outbox row before commit. A stale or unknown condition returns a typed conflict/failed-precondition error without a partial update.

- [ ] **Step 3: Pass integration and repository-wide tests**

```bash
AIOPS_TEST_POSTGRES_DSN="$AIOPS_TEST_POSTGRES_DSN" go test -race ./internal/releasegovernance/... -count=1
go test ./internal/outbox/... ./internal/store/... -count=1
```

Expected: PASS; exactly one transition survives concurrent promotion and its audit/outbox record is in the same transaction.

- [ ] **Step 4: Commit persistence**

```bash
git add internal/releasegovernance
git commit -m "feat(release): persist gated rollout transitions"
```

### Task 4: Publish read projections and decision commands through OpenAPI

**Files:**
- Modify: `internal/authz/authorizer.go`
- Modify: `internal/authz/authorizer_test.go`
- Modify: `api/openapi/control-plane-v1.yaml`
- Create: `internal/httpapi/release_handlers.go`
- Create: `internal/httpapi/release_handlers_test.go`
- Modify: `internal/httpapi/router.go`
- Regenerate: `web/src/shared/api/schema.d.ts`

**Interfaces:**
- Consumes: release repository, OIDC actor, existing Scope/service ownership and signer-group assignments, reauthentication proof, Problem Details
- Produces: explicit `PRODUCTION_RELEASE_READ`/`PRODUCTION_RELEASE_DECIDE` authorization, server-computed `effective_actions`, typed release list/detail/evidence/decision API and generated browser contract

- [ ] **Step 1: Add failing contract and authorization tests**

Cover scoped `GET /api/v1/workspaces/{workspace_id}/environments/{environment_id}/production-releases`, detail, wave evidence/decision operations and `POST .../production-releases/{release_id}/acceptance-decisions` under the same prefix. Assert Tenant/Workspace/Environment isolation, cursor stability, redacted evidence summaries, idempotency key requirement, stale state conflict, missing reauthentication, self-approval denial, incomplete final evidence rejection and effective actions. Authorization tests must prove VIEWER/AUDITOR may receive `PRODUCTION_RELEASE_READ` only within assigned Scope；ADMIN、SRE、APPROVER and service owner receive no decision right merely from role；`PRODUCTION_RELEASE_DECIDE` requires an independently assigned release-signer group、current Scope binding、recent authentication and signer separation from candidate creator、Action approver and prior wave signer.

Run:

```bash
go test ./internal/authz ./internal/httpapi -run 'TestProductionRelease' -count=1
```

Expected: FAIL with missing routes and schema.

- [ ] **Step 2: Add exact OpenAPI schemas and handlers**

Define the permissions in the existing authorizer and compute actions per resource state；never infer them in handlers or the browser:

```go
const (
    PermissionProductionReleaseRead   Permission = "PRODUCTION_RELEASE_READ"
    PermissionProductionReleaseDecide Permission = "PRODUCTION_RELEASE_DECIDE"
)
```

`PRODUCTION_RELEASE_DECIDE` is not included in any broad default role. A durable, reviewed signer-group assignment is intersected with Scope, current wave/candidate ownership, separation-of-duties facts and recent OIDC authentication on every response and mutation. Cross-Scope IDs use the same safe `403/404` projection, and a stale assignment immediately removes the action.

The decision request contains only:

```yaml
ProductionWaveDecisionRequest:
  type: object
  additionalProperties: false
  required: [expected_state, expected_version, decision, rationale_code, reauthentication_proof]
  properties:
    expected_state: { $ref: '#/components/schemas/ProductionWaveState' }
    expected_version: { type: integer, format: int64, minimum: 1 }
    decision: { type: string, enum: [PROMOTE, HOLD, ROLL_BACK] }
    rationale_code: { type: string, maxLength: 80 }
    reauthentication_proof: { type: string, minLength: 20, maxLength: 4096, writeOnly: true }
```

The release-level request uses a different closed schema: `decision` is `HOLD|ROLL_BACK|PRODUCTION_CLOSED_LOOP_ACCEPTED`, `final_evidence_set_digest` and `expected_release_digest` are required lowercase hashes, and the server derives the ordered signer set from independently validated recent-auth proofs. The wave endpoint can never write a release acceptance row.

Every proof is validated and discarded; it is never logged, persisted, returned, or placed in audit details. Handlers derive actor/Scope, require `Idempotency-Key`, and return RFC 9457 Problem Details.

- [ ] **Step 3: Regenerate and verify contracts**

```bash
pnpm --dir web generate:api
go test ./internal/authz -run 'TestProductionRelease' -count=1
go test ./internal/httpapi -run 'TestProductionRelease' -count=1
pnpm --dir web typecheck
git diff --check -- web/src/shared/api/schema.d.ts
```

Expected: handler tests and typecheck pass; the generated schema has no whitespace error and its reviewed diff matches only the new release contract. The final phase audit reruns generation after this change is committed and requires a clean diff.

- [ ] **Step 4: Commit API boundary**

```bash
git add internal/authz api/openapi/control-plane-v1.yaml internal/httpapi web/src/shared/api/schema.d.ts
git commit -m "feat(api): expose production release gates"
```
