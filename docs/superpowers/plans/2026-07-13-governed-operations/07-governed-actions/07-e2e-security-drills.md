# Governed Action Production Assembly, Security Drills, and Canary Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 用真实 PostgreSQL/OIDC/PKI/Vault/WRITE Runner/provider 完成四种 Action 的端到端安全验收、至少 20 次非生产演练和逐类型 supervised production canary，并持久化 Release Gate、运行手册和证据。

**Architecture:** Phase 6 HA platform 装配真实 Phase 7 services，E2E 环境运行构建产物和真实 kind Kubernetes、GitLab/Argo CD、AWX、Vault，不加载 MSW/in-memory repository。`actiongate` 只从签名 Receipt/Drill records 计算门槛，promotion 使用双人 recent-auth decision；每种 Action 独立开放或关闭。

**Tech Stack:** Go 1.26.5、PostgreSQL 18.4+、Temporal、Keycloak Server 26.6.3 OIDC、Vault、mTLS/SPIFFE、kind/Kubernetes、GitLab、Argo CD、AWX、Docker Compose/Helm、Playwright 1.61.1、axe 4.12.1、Prometheus/Grafana、gitleaks。

## Global Constraints

- 每个 Task 严格采用 Red → Green → Refactor：先运行并保存预期失败，再做最小生产实现，复跑指定测试后才允许重构和提交。
- E2E/Drill 使用真实 production binaries、migrations、HTTP/mTLS protocols、OIDC authorization-code+PKCE、dynamic credential issuer/revoker and provider APIs；fixture only seeds facts/accounts。
- Production assembly startup fails if PostgreSQL/Temporal/OIDC/PKI/Vault/Realm/Policy/Kill/Runtime/Signer/provider dependency is missing；no fake/in-memory fallback。
- Every Action type requires ≥20 non-production positive drills、≥19 VERIFIED successes (≥95%)、0 unauthorized mutations、0 duplicate mutations before CANARY_APPROVED。
- Adversarial/negative drills are additional and do not inflate positive denominator；any unauthorized/duplicate mutation forces Gate SUSPENDED regardless of ratio。
- Canary is one Action type、one non-critical Asset、one maintenance window、one active execution，with named operator/approver/on-call/rollback owner and live dashboards。
- Canary failure, UNKNOWN, credential cleanup uncertainty, verification failure or missing audit closes only that Action type and opens human escalation。
- Production AVAILABLE is not inherited by new Definition revision；new revision restarts at CLOSED。
- Playwright production project has no request interception/MSW/service worker and authenticates through real OIDC UI。
- Test artifacts/logs/screenshots are scanned for secrets、tokens、PEM、DSN、Vault paths、provider responses and customer-sensitive values。
- Phase 8 still owns broad rollout/capacity/compliance/DR acceptance；Phase 7 ends at individually supervised canaries。

---

### Task 1: Wire real production services and build the no-fake end-to-end stack

**Files:**
- Modify: `cmd/control-plane/main.go`
- Modify: `cmd/control-plane/main_test.go`
- Modify: `cmd/worker/main.go`
- Modify: `cmd/worker/main_test.go`
- Modify: `cmd/write-runner/main.go`
- Modify: `cmd/write-runner/main_test.go`
- Modify: `internal/actionplatform/service.go`
- Modify: `internal/actionplatform/service_test.go`
- Create: `internal/actionplatform/assembly.go`
- Create: `internal/actionplatform/assembly_test.go`
- Modify: `internal/productionrollout/admission.go`
- Modify: `internal/productionrollout/admission_test.go`
- Modify: `deploy/images.lock`
- Modify: `test/production/images.lock`
- Modify: `deploy/helm/aiops/Chart.yaml`
- Modify: `deploy/helm/aiops/values.yaml`
- Modify: `deploy/helm/aiops/values.schema.json`
- Modify: `deploy/helm/aiops/templates/serviceaccounts.yaml`
- Modify: `deploy/helm/aiops/templates/pdb.yaml`
- Modify: `deploy/helm/aiops/templates/hpa.yaml`
- Modify: `deploy/helm/aiops/templates/networkpolicy.yaml`
- Modify: `deploy/helm/aiops/chart_contract_test.go`
- Create: `deploy/helm/aiops/action-surface-manifest.yaml`
- Create: `deploy/helm/aiops/templates/write-runner-deployment.yaml`
- Create: `deploy/helm/aiops/templates/write-runner-networkpolicy.yaml`
- Create: `deploy/helm/aiops/templates/action-workers-deployment.yaml`
- Create: `test/e2e/governed-actions/stack.go`
- Create: `test/e2e/governed-actions/stack_test.go`
- Create: `test/e2e/governed-actions/fixtures.go`
- Create: `test/e2e/docker-compose.governed-actions.yaml`
- Modify: `web/playwright.config.ts`
- Create: `web/e2e/governed-actions.spec.ts`
- Create: `web/e2e/governed-actions-security.spec.ts`
- Create: `web/e2e/governed-actions-accessibility.spec.ts`

**Interfaces:**
- Consumes: packages 01–05 and accepted Phase 6 Helm/OIDC/Temporal/PKI/Vault/observability contracts, immutable handoff and READ baseline。
- Produces: exact Action surface manifest, separately content-addressed ACCEPTED Action platform successor, dual-revision READ/WRITE admission, fail-closed multi-replica production assembly and real-protocol E2E stack。

- [ ] **Step 1: Write failing assembly and production-path tests**

```go
func TestControlPlaneRejectsMissingGovernedActionDependencies(t *testing.T)
func TestWorkerRecoversVerificationAndReconciliationButNeverRepeatsMutation(t *testing.T)
func TestWriteRunnerRequiresProductionWriteRealmAndIssuerProfile(t *testing.T)
func TestProductionDependencyGraphsContainNoMemoryFakeOrDevServer(t *testing.T)
func TestHelmSeparatesReadValidationWriteServiceAccountsAndNetworkPolicies(t *testing.T)
func TestActionPlatformSuccessorBindsPhase6HandoffReadBaselineAndObservedManifest(t *testing.T)
func TestChartRejectsUndeclaredWriteSurfaceAndAcceptsOnlyRegisteredManifest(t *testing.T)
func TestReadAdmissionRequiresCurrentAcceptedActionPlatformSuccessor(t *testing.T)
func TestGovernedActionStackUsesRealOIDCMTLSVaultAndProviders(t *testing.T)
```

- [ ] **Step 2: Run tests to verify failure**

Run:

```bash
go test ./cmd/control-plane ./cmd/worker ./cmd/write-runner ./test/e2e/governed-actions -run 'GovernedAction|WriteRunner|Production' -count=1
helm lint deploy/helm/aiops
```

Expected: FAIL because full production assembly, manifests and E2E stack are absent.

- [ ] **Step 3: Implement fail-closed process and Helm assembly**

Control Plane assembles PostgreSQL Catalog/Plan/Policy/Reauth/Approval/API; Worker assembles execution/verification/reconciliation/rollback/recovery/receipt; WRITE Runner assembles mTLS client、WRITE issuer registry、isolated Executor and typed adapters. Each exposes readiness only after migrations、built-ins CLOSED gates、keyrings、Phase 6 handoff/current READ admission、the exact ACCEPTED Action platform successor and dependencies are verified.

`action-surface-manifest.yaml` enumerates every permitted WRITE API operation ID/route, binary/image digest, ServiceAccount/SPIFFE Realm, issuer profile, NetworkPolicy egress, queue claim kind, adapter family and provider permission. `values.schema.json` adds only strict `actionWorkers` and `writeRunner` branches with `additionalProperties:false` and safe default `enabled:false`; `Chart.yaml` creates a reviewed successor version；both image locks pin every new binary by SHA-256. Chart contract tests render disabled/enabled modes, prove all Phase 6 READ-owned resources/digests unchanged and compare the observed WRITE set byte-for-byte with the accepted manifest. Any extra/missing route、template、identity、port、issuer、permission or claim makes `UNAUTHORIZED_WRITE_SURFACE_ABSENT` fail.

`actionplatform.Assembly` recomputes chart/schema/image/identity/network/action-manifest digests from build artifacts, reloads the full Phase 6 decision/handoff composite key and immutable READ baseline, and publishes then accepts one successor only after signed chart/security/E2E evidence passes. `productionrollout.AdmissionResolver` continues to validate the Phase 6 READ baseline and additionally requires the current ACCEPTED successor; it does not rerun the predecessor’s empty-WRITE predicate. New READ and WRITE admission both close on changed READ-owned bytes, closed READ admission, successor drift or any observed WRITE surface outside the accepted manifest.

Helm uses separate ServiceAccounts/workload identities/secrets/NetworkPolicies:

- Control Plane: OIDC/PostgreSQL/signing, no provider WRITE egress;
- Action Worker: PostgreSQL/Temporal/READ verification, no raw credential issuer;
- WRITE Runner: Gateway + exact provider endpoints + WRITE issuer only;
- READ/Validation Runners: no WRITE issuer/provider mutation egress.

ServiceAccounts、PDB、HPA and exact NetworkPolicies cover both new components under the existing HA rules; no component inherits a READ/VALIDATION identity. Certificate roots and Realm revisions mount read-only; pods run non-root, read-only rootfs, drop capabilities and use seccomp RuntimeDefault.

- [ ] **Step 4: Build the real provider/OIDC stack and scenarios**

`stack.go` creates ephemeral CA/certs/Vault policies at runtime in `0700` temp storage, boots PostgreSQL 18.4 + migrations、Temporal、the locked Keycloak Server 26.6.3 test Realm、two Control Planes、two Workers、two WRITE Runners、kind cluster、GitLab、Argo CD and AWX. It persists a real Phase 6 approved READ handoff, renders and verifies the Action surface manifest, publishes an exact ACCEPTED successor, then seeds exact Assets/Snapshots/Runtime/Policy/Kill/Realm/Definition gates and non-secret test facts. No component is replaced by a mock server or caller-forged acceptance row.

Backend/browser scenarios:

1. seal/review/reauth/approve/execute/verify each of four Action types;
2. requester self-approval and insufficient HIGH approvals denied;
3. wrong READ/VALIDATION/WRITE root, Realm, Scope revision and certificate denied;
4. drift Plan/Asset/Snapshot/Target/Runtime/Policy/Kill/approval between every boundary;
5. concurrent submit/claim/start/complete creates one mutation/Attempt/Receipt;
6. kill Runner before send, after send and during cleanup; no duplicate mutation;
7. provider timeout/reset after send enters UNKNOWN→reconciliation;
8. scale verification failure performs only eligible exact rollback;
9. restart/GitOps/AWX uncertainty escalates without opposite mutation;
10. browser reload resumes Operation and shows safe Receipt;
11. network/DOM/console/trace/screenshot scan finds no forbidden material.

- [ ] **Step 5: Run production assembly and real E2E**

Run:

```bash
go test ./cmd/control-plane ./cmd/worker ./cmd/write-runner ./test/e2e/governed-actions -count=1
helm lint deploy/helm/aiops
docker compose -f test/e2e/docker-compose.governed-actions.yaml up -d --build
go test ./test/e2e/governed-actions -run TestGovernedActionLifecycle -count=1
pnpm --dir web test:e2e -- --grep "governed action"
pnpm --dir web test:a11y -- --grep "governed action"
docker compose -f test/e2e/docker-compose.governed-actions.yaml down -v
```

Expected: all PASS；real OIDC/mTLS/Vault/providers used；no MSW/interception；all failure paths are durable and no duplicate write occurs.

- [ ] **Step 6: Commit**

```bash
git add cmd/control-plane cmd/worker cmd/write-runner internal/actionplatform internal/productionrollout deploy/images.lock deploy/helm/aiops test/production/images.lock test/e2e web/playwright.config.ts web/e2e
git commit -m "test: verify governed actions on real protocols"
```

### Task 2: Persist per-type drill evidence and gate supervised canaries

**Files:**
- Create: `internal/actiongate/types.go`
- Create: `internal/actiongate/types_test.go`
- Create: `internal/actiongate/repository.go`
- Create: `internal/actiongate/postgres/repository.go`
- Create: `internal/actiongate/postgres/repository_test.go`
- Create: `internal/actiongate/service.go`
- Create: `internal/actiongate/service_test.go`
- Create: `cmd/action-drill/main.go`
- Create: `cmd/action-drill/main_test.go`
- Modify: `internal/httpapi/action_gates.go`
- Modify: `internal/httpapi/action_gates_test.go`
- Modify: `api/openapi/control-plane-v1.yaml`
- Modify: `api/openapi/control_plane_v1_test.go`

**Interfaces:**
- Consumes: signed `ActionReceipt`、`action_drill_results`、immutable Definition/Gate revisions、recent-auth/approval and Package 1 real E2E stack。
- Produces:

```go
type Repository interface {
    AppendDrill(context.Context, DrillResult) error
    ListDrills(context.Context, actioncatalog.Scope, action.ActionType) ([]DrillResult, error)
    CurrentGate(context.Context, actioncatalog.Scope, action.ActionType) (GateRevision, error)
    AppendGate(context.Context, GateRevision, int64) error
}

type Readiness struct {
    PositiveRuns          int
    IndependentlyVerified int
    UnauthorizedMutations int
    DuplicateMutations    int
    CleanCredentialRuns   int
    CompleteReceiptRuns   int
    Eligible              bool
    BlockingCodes         []string
}
```

Gate states are `CLOSED|NON_PRODUCTION_READY|DRILLING|CANARY_APPROVED|CANARY_RUNNING|AVAILABLE|SUSPENDED`. Gate revisions are append-only and Scope + Action type + Definition revision specific.

- [ ] **Step 1: Write failing repository, readiness and transition tests**

```go
func TestReadinessRequiresTwentyPositiveAndNineteenVerifiedRuns(t *testing.T)
func TestAdversarialRunsDoNotIncreasePositiveDenominator(t *testing.T)
func TestAnyUnauthorizedOrDuplicateMutationSuspendsType(t *testing.T)
func TestPromotionRequiresCurrentDefinitionAndCompleteSignedReceipts(t *testing.T)
func TestPromotionRequiresTwoDistinctRecentAuthenticatedHumans(t *testing.T)
func TestCanaryBindsOneAssetWindowAndNamedOwners(t *testing.T)
func TestNewDefinitionRevisionStartsClosed(t *testing.T)
func TestGateCannotSkipStagesOrReopenWithoutRemediationDecision(t *testing.T)
func TestConcurrentGatePromotionAppendsOneRevision(t *testing.T)
func TestAvailableRequiresVerifiedCanaryAndCleanCredential(t *testing.T)
```

Repository tests use real PostgreSQL to prove append-only revisions, optimistic expected-revision conflicts, cross-Scope rejection and one active canary per Action type. Add OpenAPI tests proving gate responses expose counts/digests/owner subject IDs but no raw drill body or credential/provider material.

- [ ] **Step 2: Run tests to verify failure**

Run:

```bash
AIOPS_TEST_POSTGRES_DSN="$AIOPS_TEST_POSTGRES_DSN" go test ./internal/actiongate/... ./internal/httpapi ./api/openapi ./cmd/action-drill -run 'Gate|Readiness|Canary|Drill' -count=1
```

Expected: FAIL because repository, state machine, CLI and HTTP contracts are absent.

- [ ] **Step 3: Implement exact integer readiness and fail-closed transitions**

`RecordDrill` accepts only a server-issued Receipt ID, reloads immutable records from PostgreSQL, then verifies Receipt signature/chain, Definition/Plan/Attempt/verification digests and environment class before append. It never trusts caller-supplied counts, outcomes or digests. A positive run counts only when it used a supported Action type against a declared non-production Asset through the production binary/protocol path. A run contributes to `IndependentlyVerified` only when every required check is VERIFIED, credential cleanup is CONFIRMED and Receipt is complete.

The only forward path is `CLOSED→NON_PRODUCTION_READY→DRILLING→CANARY_APPROVED→CANARY_RUNNING→AVAILABLE`; no state can be skipped. `NON_PRODUCTION_READY` requires the exact Definition、adapter、verifier、issuer/Realm and negative contract suites for that revision. `DRILLING` additionally requires the real non-production provider bindings and named drill owner. Readiness uses integer comparison `verified * 100 >= positive * 95`; it never rounds floating-point ratios. `DRILLING→CANARY_APPROVED` requires positive ≥20, verified ≥19, unauthorized=0, duplicate=0 and complete cleanup/Receipt evidence for all counted runs. Any unauthorized/duplicate mutation, invalid signature, unexplained ledger gap or stale Definition immediately appends `SUSPENDED`; `SUSPENDED→CLOSED` requires a distinct human remediation decision and evidence digest. A new Definition revision starts a new `CLOSED` gate and inherits no drills.

Promotion is two-step: an SRE/APPROVER with recent plan-bound authentication requests it, then a distinct ADMIN with a separate recent proof decides it. The decision binds Gate/Definition revision, exact non-critical production Asset, maintenance window, operator, approver, on-call and rollback/escalation owner. Start re-evaluates current bindings and allows one active canary; completion reaches AVAILABLE only from a verified terminal Receipt with confirmed cleanup and zero audit gaps. Failure/UNKNOWN appends SUSPENDED and escalation.

- [ ] **Step 4: Add safe API and an authenticated drill recorder**

Add scoped endpoints:

```text
GET  /api/v1/workspaces/{workspace_id}/environments/{environment_id}/action-gates
GET  /api/v1/workspaces/{workspace_id}/environments/{environment_id}/action-gates/{action_type}
POST /api/v1/workspaces/{workspace_id}/environments/{environment_id}/action-gates/{action_type}:request-promotion
POST /api/v1/workspaces/{workspace_id}/environments/{environment_id}/action-gates/{action_type}:decide-promotion
POST /api/v1/workspaces/{workspace_id}/environments/{environment_id}/action-gates/{action_type}:start-canary
```

Mutation routes require exact `If-Match`、Idempotency-Key、recent-auth proof and server `effective_actions`. They return durable Operation or stable 409/412/428 and cannot directly set state/counts. `action-drill` authenticates against Keycloak Server 26.6.3 by device flow, starts real non-production Actions through the API, waits for terminal signed Receipts, records only safe digests, and exits non-zero on denominator, ratio, unauthorized, duplicate, cleanup or chain failure. Tokens are held in memory and never accepted as command arguments.

- [ ] **Step 5: Run state-machine, PostgreSQL, API, race and CLI tests**

Run:

```bash
AIOPS_TEST_POSTGRES_DSN="$AIOPS_TEST_POSTGRES_DSN" go test ./internal/actiongate/... ./internal/httpapi ./api/openapi ./cmd/action-drill -count=1
go test -race ./internal/actiongate/... ./internal/httpapi -count=1
go vet ./internal/actiongate/... ./cmd/action-drill
go build ./cmd/action-drill
```

Expected: all PASS；promotion cannot bypass evidence/dual control；concurrent requests append one revision；unsafe evidence suspends only its Action type.

- [ ] **Step 6: Commit**

```bash
git add internal/actiongate cmd/action-drill internal/httpapi/action_gates.go internal/httpapi/action_gates_test.go api/openapi
git commit -m "feat: gate governed actions with signed drill evidence"
```

### Task 3: Run security drills and persist canary operations evidence

**Files:**
- Create: `test/security/governedactions/authorization_test.go`
- Create: `test/security/governedactions/credentials_test.go`
- Create: `test/security/governedactions/fencing_test.go`
- Create: `test/security/governedactions/uncertainty_test.go`
- Create: `test/security/governedactions/redaction_test.go`
- Modify: `.github/workflows/ci.yml`
- Create: `deploy/observability/governed-actions-rules.yaml`
- Create: `internal/actiongate/docs_contract_test.go`
- Create: `docs/adr/0010-governed-production-action-gates.md`
- Create: `docs/adr/0011-verification-reconciliation-rollback.md`
- Modify: `docs/design/frontend/governed-actions.md`
- Create: `docs/operations/governed-actions/kubernetes.md`
- Create: `docs/operations/governed-actions/gitops.md`
- Create: `docs/operations/governed-actions/awx.md`
- Create: `docs/operations/governed-actions/uncertain-outcome.md`
- Create: `docs/operations/governed-actions/credential-cleanup.md`
- Create: `docs/operations/governed-actions/production-canary.md`
- Modify: `docs/status/current.md`
- Modify: `docs/architecture/implementation-blueprint-v4.md`
- Modify: `docs/README.md`
- Modify: `AGENTS.md`

**Interfaces:**
- Consumes: Tasks 1–2、all four accepted packages 01–05 and real non-production/provider environments owned by the operator。
- Produces: reproducible signed drill ledgers、two canonical ADRs、frontend/runbook/SLO contracts and one supervised-canary decision per Action type。

- [ ] **Step 1: Write failing adversarial, documentation and alert-contract tests**

Use a table-driven denial suite whose expected result is both a stable denial code and zero provider mutation:

```go
var denied = []struct {
    name string
    code string
}{
    {"arbitrary shell field", "ACTION_SCHEMA_UNKNOWN_FIELD"},
    {"sql or generic endpoint payload", "ACTION_TYPE_UNSUPPORTED"},
    {"cross scope asset", "ACTION_BINDING_SCOPE_MISMATCH"},
    {"read credential on write runner", "CREDENTIAL_REALM_MISMATCH"},
    {"expired approval or reauth", "AUTHORIZATION_BUNDLE_EXPIRED"},
    {"drift after approval", "ACTION_BINDING_DRIFT"},
    {"stale fence", "ACTION_ATTEMPT_FENCE_STALE"},
    {"duplicate claim", "ACTION_ALREADY_CLAIMED"},
}
```

Also test Kill Switch changes at every boundary, revocation unknown, crash before/after send, network partition, ambiguous provider response, verification failure, ineligible rollback, audit/Receipt gaps, cross-tenant enumeration, stored/reflected text and secret scanning. Documentation contract tests require exact metrics, owner/escalation fields, fixed Action matrices, `CLOSED` defaults and no unverified “production ready” claim.

- [ ] **Step 2: Run tests to verify failure**

Run:

```bash
go test ./test/security/governedactions ./internal/actiongate -run 'Security|Docs|Alert|Denied' -count=1
promtool check rules deploy/observability/governed-actions-rules.yaml
```

Expected: FAIL because negative suites, rules, ADRs and runbooks are absent.

- [ ] **Step 3: Implement security gates, alerts, ADRs and operator documentation**

CI runs unit/integration/race, OpenAPI generation check, `web` type/lint/unit/Playwright/axe, Helm lint, migration tests and secret scans. The manual protected real-environment job runs E2E/drills; CI never fabricates canary approval or marks AVAILABLE.

Prometheus rules cover queue age, admission denials, policy/Kill drift, credential issue/cleanup/expiry, lease/fence conflict, duplicate-send invariant, mutation UNKNOWN, verification latency/failure, reconciliation backlog, rollback failure, audit/Receipt gaps and gate suspension. Each alert links a named runbook, severity, owner and bounded first response.

ADR 0010 fixes typed catalogs, exact Plan bindings, dual-control gate state and no generic write interface. ADR 0011 fixes executor-not-verifier, UNKNOWN reconciliation, no blind retry and scale-only exact rollback. Frontend design persists information architecture, 12-column desktop/8-column tablet grids, typography/tokens, evidence→diff→hash→approval→reauth→execution→verification→receipt states, focus/error/keyboard/loading/reload behavior, `effective_actions`, responsive rules and explicit no-chat/no-terminal/no-arbitrary-JSON constraints.

Runbooks list exact owner/prerequisite/safe observation/stop condition/revoke/reconcile/rollback eligibility/escalation/evidence digest steps. They never print credentials, provider raw responses or copyable generic mutation commands.

- [ ] **Step 4: Execute at least 20 positive non-production drills per Action type**

Run with a protected operator session and real non-production Assets:

```bash
go run ./cmd/action-drill run --oidc-device-flow --environment-class non-production --action-type K8S_ROLLOUT_RESTART --asset-file "$AIOPS_K8S_RESTART_DRILL_ASSETS" --count 20
go run ./cmd/action-drill run --oidc-device-flow --environment-class non-production --action-type K8S_SCALE --asset-file "$AIOPS_K8S_SCALE_DRILL_ASSETS" --count 20
go run ./cmd/action-drill run --oidc-device-flow --environment-class non-production --action-type GITOPS_REVERT --asset-file "$AIOPS_GITOPS_REVERT_DRILL_ASSETS" --count 20
go run ./cmd/action-drill run --oidc-device-flow --environment-class non-production --action-type AWX_SERVICE_RESTART --asset-file "$AIOPS_AWX_RESTART_DRILL_ASSETS" --count 20
go run ./cmd/action-drill verify --all-initial-types --require-positive 20 --require-verified-percent 95 --require-unauthorized 0 --require-duplicate 0
```

Expected: every type reports positive ≥20、independently verified ≥19、ratio ≥95%、unauthorized=0、duplicate=0、clean credential/complete Receipt for every counted run. Any violation returns non-zero, appends SUSPENDED and stops before production.

- [ ] **Step 5: Run one supervised production canary per eligible Action type**

For one type at a time, the operator requests a canary; a distinct administrator approves it in a second Keycloak Server 26.6.3 session. Both commands are interactive and store only decision digests:

```bash
go run ./cmd/action-drill request-canary --oidc-device-flow --action-type "$AIOPS_CANARY_ACTION_TYPE" --asset-id "$AIOPS_CANARY_ASSET_ID" --window-id "$AIOPS_CANARY_WINDOW_ID"
go run ./cmd/action-drill decide-canary --oidc-device-flow --request-id "$AIOPS_CANARY_REQUEST_ID" --decision approve
go run ./cmd/action-drill watch-canary --request-id "$AIOPS_CANARY_REQUEST_ID" --require-verified --require-clean-credential --require-complete-receipt
```

Expected: live dashboard and named on-call are active; exactly one logical production Action occurs and no catalog-declared mutation step is duplicated; independent verification, cleanup, audit and Receipt finish. Only then append AVAILABLE for that type. UNKNOWN/failure/cleanup uncertainty suspends it, revokes access and opens human escalation; do not repeat any mutation step.

- [ ] **Step 6: Run full release evidence gates and update the truthful status**

Run:

```bash
go test ./... -count=1
go test -race -shuffle=on -count=1 ./internal/action/... ./internal/actioncatalog/... ./internal/actionplan/... ./internal/actionauthorization/... ./internal/actionapproval/... ./internal/actiongate/... ./internal/actionverification/... ./internal/actionreconciliation/... ./internal/actionrollback/... ./internal/actionreceipt/... ./internal/actionrecovery/... ./internal/execution/... ./internal/writeexecution/... ./internal/writecredential/... ./internal/credential/... ./internal/runnergateway/... ./internal/writeadapter/...
go vet ./...
go build ./...
AIOPS_TEST_POSTGRES_DSN="$AIOPS_TEST_POSTGRES_DSN" go test ./internal/store/postgres ./internal/actioncatalog/postgres ./internal/actiongate/postgres -count=1
pnpm --dir web generate:api:check
pnpm --dir web typecheck
pnpm --dir web lint
pnpm --dir web test
pnpm --dir web check
pnpm --dir web test:e2e -- --grep "governed action"
pnpm --dir web test:a11y -- --grep "governed action"
helm lint deploy/helm/aiops
promtool check rules deploy/observability/governed-actions-rules.yaml
gitleaks detect --no-banner --redact --source .
git diff --check
```

Expected: all PASS. Update `docs/status/current.md` only after attaching immutable evidence digests and commit IDs; record each Action type independently as AVAILABLE/SUSPENDED/CLOSED, the exact Definition/Gate revision, canary Receipt digest, limitations and owner. A plan or failed command is never described as deployed evidence.

- [ ] **Step 7: Commit**

```bash
git add test/security/governedactions .github/workflows/ci.yml deploy/observability/governed-actions-rules.yaml internal/actiongate/docs_contract_test.go docs/adr/0010-governed-production-action-gates.md docs/adr/0011-verification-reconciliation-rollback.md docs/design/frontend/governed-actions.md docs/operations/governed-actions docs/status/current.md docs/architecture/implementation-blueprint-v4.md docs/README.md AGENTS.md
git commit -m "docs: persist governed action production evidence"
```
