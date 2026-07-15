# Production Ownership, Runbooks, Final E2E, and Durable Handoff Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prove the complete governed production loop under both verified-success and uncertain-result paths, assign sustained operating ownership, and replace fragmented project knowledge with small authoritative documents that future workers must follow.

**Architecture:** Treat operations evidence and documentation as versioned production interfaces. Runbooks link alerts to bounded actions and escalation owners; final E2E tests exercise real production assemblies and immutable records; concise V4/status/ADR/frontend documents link to deeper module pages instead of creating another monolith. Final acceptance is an independently signed release record, not a test log or narrative claim.

**Tech Stack:** Existing Go/Temporal/PostgreSQL/Gateway/Runner production stack, React/Playwright/axe, Helm/Kubernetes, VictoriaMetrics/VictoriaLogs/VictoriaTraces, Markdown/JSON Schema, OpenAPI generation, and repository CI/release governance.

## Global Constraints

- 每个 Task 严格采用 Red → Green → Refactor：先运行并保存预期失败，再做最小生产实现，复跑指定测试后才允许重构和提交。
- Production ownership must name a primary team/role, secondary, escalation target, response objective and access path; “engineering” or an individual-only owner is invalid.
- Runbooks never contain raw credentials, DSNs, private endpoints, arbitrary shell/SQL, bypass instructions or reusable privileged tokens.
- A runbook cannot widen an Action envelope. It may invoke only a fixed server-published diagnostic/Action type through normal authorization.
- Final E2E uses real durable repositories, OIDC, policy, Vault/PKI, mTLS Gateway/Runner, Temporal, observability and audit. Fakes remain test-only.
- An uncertain production effect is never retried automatically. Credential revocation, reconciliation and human escalation are required before a terminal classification.
- Documentation describes only accepted capabilities. Closed or untested providers/actions remain explicitly closed.
- Normative documents are split into indexes and bounded topic files; no generated dump becomes the project truth source.

### Task 1: Assign service ownership, on-call, and executable runbooks

**Files:**
- Create: `docs/operations/production/README.md`
- Create: `docs/operations/production/ownership.md`
- Create: `docs/operations/production/on-call.md`
- Create: `docs/operations/production/kill-switch.md`
- Create: `docs/operations/production/credential-cleanup.md`
- Create: `docs/operations/production/runner-realm.md`
- Create: `docs/operations/production/policy-and-approval.md`
- Create: `docs/operations/production/uncertain-action.md`
- Create: `docs/operations/production/audit-and-outbox.md`
- Create: `docs/operations/production/release-hold-rollback.md`
- Create: `docs/operations/production/runbook.schema.json`
- Create: `tests/documentation/runbook_contract_test.go`
- Modify: `.github/CODEOWNERS`

**Interfaces:**
- Consumes: alerts/SLO catalog, Kill Switch, Grant/credential/action/release state machines, organizational team aliases
- Produces: validated runbook index, RACI/on-call coverage and code ownership

- [ ] **Step 1: Write failing runbook-contract tests**

The test discovers every production alert and requires exactly one existing runbook with:

```json
{
  "schema_version": 1,
  "alert_key": "write_credential_cleanup_missed",
  "severity": "critical",
  "owner": "platform-operations",
  "secondary": "security-operations",
  "acknowledge_within": "5m",
  "prerequisites": ["operator OIDC", "effective_actions:credential_cleanup_read"],
  "stop_condition": "state or scope cannot be proven",
  "escalation": "incident-commander"
}
```

The human-readable section must include meaning, impact, safe first checks, decision tree, stop/escalate, recovery verification, evidence to preserve and post-incident action. Tests reject secret patterns, shell/SQL code blocks, unknown effective actions, nonexistent links and ownerless pages.

Run:

```bash
go test ./tests/documentation -run TestRunbookContract -count=1
```

Expected: FAIL until the runbook set and schema exist.

- [ ] **Step 2: Implement ownership and on-call contracts**

`ownership.md` assigns product/control-plane, platform/Kubernetes, database, identity/Keycloak, security/Vault/PKI, Temporal, observability, frontend and each connector/Action family. Include change approval, incident authority, Kill Switch authority, data owner and release signer separation.

`on-call.md` defines severity, paging route, handoff, incident commander, communication, audit/evidence preservation and dependency escalation. A production Action incident pages service owner plus platform/security according to reason.

Use group aliases from the organization directory in final implementation. The release gate verifies they resolve to at least two active humans for privileged roles and are not the same signer group.

- [ ] **Step 3: Implement bounded operational runbooks**

Each diagnostic command is a UI/API operation name or fixed Capability, never arbitrary code. Example decision flow for uncertain action:

```text
OUTCOME_UNCERTAIN
  -> activate Action-type/target Kill Switch
  -> verify WRITE credential revoked or expiry proven
  -> freeze automatic retry and related wave
  -> run independent typed reconciliation read
     -> effect absent: human decides new ActionPlan
     -> exact approved effect present: verify and issue Receipt
     -> divergent/unknown: preserve evidence and escalate
  -> rollback only when the original immutable plan contains an approved safe rollback
```

Link every runbook to relevant dashboard, Problem reason codes, ownership and immutable evidence lookup. Document dependency outage behavior and when only Shadow/READ_ONLY may reopen.

- [ ] **Step 4: Validate and commit operations ownership**

```bash
go test ./tests/documentation -run TestRunbookContract -count=1
rg -n 'BEGIN .*PRIVATE KEY|password\\s*=|token\\s*=|postgres(ql)?://' docs/operations/production
git add docs/operations/production tests/documentation .github/CODEOWNERS
git commit -m "docs(operations): assign production ownership and runbooks"
```

Expected: contract test passes; secret scan exits `1` with no matches.

### Task 2: Prove the real governed success and uncertain-result loops

**Files:**
- Create: `tests/production/closed_loop_success_test.go`
- Create: `tests/production/closed_loop_uncertain_test.go`
- Create: `tests/production/closed_loop_unauthorized_test.go`
- Create: `tests/production/helpers/records.go`
- Create: `tests/production/helpers/telemetry.go`
- Create: `web/e2e/production-closed-loop.spec.ts`
- Create: `docs/operations/production/closed-loop-acceptance.schema.json`
- Create: `docs/operations/production/closed-loop-test.md`

**Interfaces:**
- Consumes: a supervised approved noncritical production target/action, real alert source, all Phase 1–8 production integrations
- Produces: canonical end-to-end record graph and signed acceptance evidence

- [ ] **Step 1: Write failing graph and invariant assertions**

The helper loads records by stable IDs and verifies this exact chain:

```go
type ClosedLoopGraph struct {
    Trigger              TriggerRecord
    Incident             IncidentRecord
    Asset                AssetRecord
    Connection           ConnectionRevisionRecord
    Target               TargetRecord
    Capability           CapabilityRecord
    Runtime              RuntimePublicationRecord
    AssetSnapshot        AssetSnapshotRecord
    InvestigationGrant   GrantRecord
    ReadCredential       CredentialRecord
    Evidence             EvidenceRecord
    ActionProposal       ActionProposalRecord
    HumanPlanRequest     HumanPlanRequestRecord
    ProposalDerivation   ProposalDerivationRecord
    RequesterReauth      ReauthenticationRecord
    ReadPlatform         ProductionReadClosureRecord
    ActionPlatform       ProductionActionSuccessorRecord
    AcceptedActionManifest ActionManifestRecord
    ActionPlan           ActionPlanRecord
    PolicyDecision       PolicyDecisionRecord
    Approval             ApprovalRecord
    ApproverReauth       []ReauthenticationRecord
    WriteCredential      CredentialRecord
    Execution            ExecutionRecord
    Verification         VerificationRecord
    Reconciliation       *ReconciliationRecord
    Rollback             *RollbackRecord
    HumanEscalation      *HumanEscalationRecord
    Receipt              ReceiptRecord
    AuditRange           AuditRange
    Release              ReleaseReference
}

func (g ClosedLoopGraph) VerifyDigestsAndScope() error
func (g ClosedLoopGraph) VerifyHumanRequestedAtomicProposalHandoff() error
func (g ClosedLoopGraph) VerifyRequesterApproverSeparationAndReauth() error
func (g ClosedLoopGraph) VerifyDualPlatformClosureAndLiveAdmission() error
func (g ClosedLoopGraph) VerifyCredentialCleanup(now time.Time) error
func (g ClosedLoopGraph) VerifyNoUnauthorizedOrDuplicateEffect() error
func (g ClosedLoopGraph) VerifyExactlyOneTerminalOutcomePath() error
```

Assert every adjacent ID/digest/full-Scope/revision link from Connection/Target/Capability/Runtime through Snapshot/Evidence/Proposal/HumanPlanRequest/ProposalDerivation/Plan, plus the Phase 6 decision/handoff/READ baseline/live-admission tuple and Phase 7 accepted successor/Action manifest tuple bound by the Plan、queue、claim、admission、execution、verification and Release records. `HumanPlanRequest` must be an immutable event from a verified human Principal through the exact T/W/E/S create route and closed six-field body; it binds the header Idempotency-Key digest and server-computed request hash without treating either expected digest as authority.

`ProposalDerivation` must bind exact Proposal/Catalog/Evidence/Snapshot/intent trusted digests, full T/W/E/S Scope, human subject, Plan ID/hash and one durable transaction/audit group. Its proof must show `HandoffLoader -> remaining trusted-facts resolver -> CreateInTx` used the same serializable PostgreSQL transaction and one commit marker; a background/scheduler/model request, Proposal pre-read, split transaction, missing audit member, expected/trusted digest mismatch or partial commit fails the graph. The test loads the immutable handoff and Plan-seal audit events, transaction-group digest and outbox commit record rather than trusting application log text.

Also prove requester reauthentication freshness and binding to the exact Plan request/hash, every approver's separate fresh reauthentication and approval binding, requester/approver subject and duty separation, target version, lease/fencing, single effect, independent verifier, Receipt digest, audit sequence and both credential cleanup records. The success graph requires null Reconciliation/Rollback/HumanEscalation and an independently verified terminal success；the uncertain graph requires `OUTCOME_UNCERTAIN -> RECONCILING -> VERIFIED|SAFE_ROLLBACK|HUMAN_ESCALATION`, exactly one terminal branch and no automatic write retry. Missing closure, human-request, handoff, reauthentication or audit records and prose-only assertions cannot satisfy final acceptance.

Run:

```bash
go test ./tests/production -run 'TestClosedLoop' -count=1
pnpm --dir web test:e2e -- --grep "production closed loop"
```

Expected: FAIL until the integrated fixtures and browser scenario exist.

- [ ] **Step 2: Execute the supervised verified-success path**

Use an accepted fixed Action on one explicitly approved noncritical production service during its maintenance window:

1. Receive a real alert/event and deduplicate it.
2. Resolve exact eligible Asset/Connection/Target/Capability/Runtime snapshot and revalidate the Phase 6 READ handoff/live admission plus Phase 7 Action successor/manifest closure.
3. Issue bounded READ Grant and short credential through the real issuer.
4. Run typed read investigation and admit redacted Evidence.
5. Persist an Evidence-backed typed `PROPOSAL_ONLY` ActionProposal and prove that no ActionPlan, approval, queue or credential side effect appears automatically.
6. Have an authenticated human explicitly request a Plan through the full T/W/E/S route after requester reauthentication. In one serializable transaction, call the Phase 4 Handoff Loader first, reload/recompute the Proposal/Catalog/Evidence/Snapshot/intent closure, resolve remaining trusted facts and `CreateInTx` the immutable ActionPlan with exact target/version/diff/server-derived verification/rollback policy; persist the atomic derivation/audit proof.
7. Evaluate current policy, require each distinct human approver to complete a separate fresh reauthentication, and bind approval to the exact immutable Plan hash.
8. Issue one-purpose WRITE credential and execute through WRITE Gateway/Runner with lease/fencing.
9. Verify independently through READ path and SLO observation.
10. Revoke credential and emit Receipt/Audit.
11. Query the graph and submit its signed bounded summary to the release gate.

No step is simulated in production. A precondition mismatch cancels the test and records a nonpassing gate rather than changing the target to “make it work.”

- [ ] **Step 3: Exercise uncertainty and unauthorized paths safely**

The uncertain path uses the Phase 7 approved fault-injection hook on the same Action type in production-equivalent infrastructure and, only under an independently approved game-day plan, a supervised noncritical production Canary. It drops Runner completion after the target effect, proves no retry, revokes credential, activates scoped stop, reconciles independently and escalates if exact state cannot be proven.

The unauthorized path attempts missing/non-human Plan request, scheduler/model auto-seal, wrong/missing Service Scope, Proposal pre-read, split Handoff/Plan transactions, expected/trusted Proposal or intent digest mismatch, missing/stale requester reauth, requester self-approval, missing/stale approver reauth, stale approval/hash, expired credential, changed target version, disabled Kill Switch, wrong Runner Realm and duplicate Claim. Every attempt must deny before target effect, leave no partial Plan/idempotency success where sealing failed and create bounded audit records.

- [ ] **Step 4: Pass browser and backend E2E, then commit support**

```bash
AIOPS_E2E_ENVIRONMENT=production-equivalent go test ./tests/production -run 'TestClosedLoopSuccess|TestClosedLoopUncertain|TestClosedLoopUnauthorized' -count=1 -timeout=60m
pnpm --dir web test:e2e -- --grep "production closed loop"
git add tests/production web/e2e docs/operations/production/closed-loop-acceptance.schema.json docs/operations/production/closed-loop-test.md
git commit -m "test(e2e): prove governed production closed loop"
```

Expected: all code/tests pass in production-equivalent infrastructure. The separately approved supervised production run submits signed runtime evidence; no production identifier or evidence body is committed.

### Task 3: Publish small authoritative architecture, ADR, status, and frontend documents

**Files:**
- Modify: `docs/architecture/implementation-blueprint-v4.md`
- Create: `docs/architecture/v4/README.md`
- Create: `docs/architecture/v4/trust-and-identity.md`
- Create: `docs/architecture/v4/assets-connections-runtime.md`
- Create: `docs/architecture/v4/investigation-and-evidence.md`
- Create: `docs/architecture/v4/actions-verification-recovery.md`
- Create: `docs/architecture/v4/production-platform.md`
- Verify: `docs/adr/0001-operational-asset-catalog-overlay.md`
- Verify: `docs/adr/0002-connection-compilation-publication.md`
- Verify: `docs/adr/0003-victoria-ecosystem-read-boundary.md`
- Verify: `docs/adr/0004-investigation-grants-and-live-kill-switches.md`
- Verify: `docs/adr/0005-remote-diagnostic-boundary.md`
- Verify: `docs/adr/0006-postgresql-named-read-diagnostics.md`
- Verify: `docs/adr/0007-read-write-credential-isolation.md`
- Verify: `docs/adr/0008-evidence-and-dlp.md`
- Verify: `docs/adr/0009-production-read-platform.md`
- Verify: `docs/adr/0010-governed-production-action-gates.md`
- Verify: `docs/adr/0011-verification-reconciliation-rollback.md`
- Create: `docs/adr/0012-production-release-governance.md`
- Create: `docs/design/frontend/README.md`
- Create: `docs/design/frontend/information-architecture.md`
- Create: `docs/design/frontend/visual-system.md`
- Create: `docs/design/frontend/interaction-and-state.md`
- Create: `docs/design/frontend/accessibility-responsive.md`
- Create: `docs/design/frontend/page-inventory.md`
- Modify: `docs/status/current.md`
- Modify: `docs/README.md`
- Modify: `AGENTS.md`
- Create: `tests/documentation/normative_docs_test.go`

**Interfaces:**
- Consumes: accepted implementation, OpenAPI, migrations, production evidence and prior V3/archive documents
- Produces: one concise future-work entry point and explicit inherit/supersede map

- [ ] **Step 1: Write failing documentation consistency tests**

Check all links, ADR status/date/decision/consequences, migration numbers, OpenAPI operation references, frontend routes, Action/Capability names, state enums, V3 inheritance map, status evidence links and file-size ceiling. Enforce a 500-line maximum for new normative topic files and 300 lines for indexes; generated OpenAPI is exempt.

Run:

```bash
go test ./tests/documentation -run TestNormativeDocs -count=1
```

Expected: FAIL until the new document set exists.

- [ ] **Step 2: Write concise V4 and ADRs**

`implementation-blueprint-v4.md` is an executive index, not another full dump. It declares:

- the governed trusted-executor invariant;
- four planes and real process topology;
- exact production closed loop and stop paths;
- stable identifiers/digests/state machines;
- production SLO/RPO/RTO and release waves;
- links to five bounded architecture chapters, active ADRs, OpenAPI, frontend spec, runbooks and status;
- a section-by-section V3 `INHERITED|REPLACED|RETIRED` map.

Each ADR records context, decision, alternatives, consequences, security invariants, migration/rollback and verification. ADR `0012` explicitly fixes the three-layer reference chain—immutable Phase 6 platform/read approval plus handoff, accepted Phase 7 `production_action_platform_revisions` successor, and Phase 8 release/wave/final-acceptance decision—and forbids JSON-only authority or reinterpretation of READ approval as WRITE approval. Do not copy implementation steps into ADRs.

- [ ] **Step 3: Persist the frontend master specification and current truth**

The frontend index owns the low-AI, high-fidelity enterprise console baseline: navy navigation, restrained blue actions, light dense surfaces, 4–6px radii, 1px borders, stable grids/tables, no chat/avatar/neon/glow/gradient/glass/bento decoration. Topic files define exact navigation, routes, responsive breakpoints, keyboard/focus, WCAG 2.2 AA, reduced motion, loading/error/empty/partial/stale states, URL state, generated contracts and `effective_actions` behavior.

`docs/status/current.md` becomes the sole completion truth: accepted release digest, deployed version, read capabilities, each available/closed Action type, rollout wave, SLO/DR/security status, known limitations with owner/expiry, active plan and next gate. It links evidence digests without copying sensitive details.

`AGENTS.md` requires future workers to read status, V4 index, affected ADRs, active phase/task pack, frontend spec and OpenAPI before changing code; material trust-boundary changes require an ADR and renewed gates.

- [ ] **Step 4: Validate and commit normative documentation**

```bash
go test ./tests/documentation -run TestNormativeDocs -count=1
rg -n 'T[B]D|T[O]DO|F[I]XME|implement l[a]ter|待[定]|待[补]|Runtime Bundle v18|Runtime Bundle v19' docs/status docs/architecture docs/adr docs/design AGENTS.md
git add docs/architecture docs/adr docs/design docs/status/current.md docs/README.md AGENTS.md tests/documentation
git commit -m "docs(architecture): publish governed operations V4"
```

Expected: documentation test passes and the empty-marker scan exits `1` with no matches.

### Task 4: Run final release audit and accept sustained production operation

**Files:**
- Verify: `api/openapi/control-plane-v1.yaml`
- Verify: `web/src/shared/api/schema.d.ts`
- Verify: `deploy/helm/aiops/`
- Verify: `docs/status/current.md`
- Verify: `docs/architecture/implementation-blueprint-v4.md`
- Verify: `docs/operations/production/`
- Verify: `docs/security/production-readiness.md`
- Verify: `migrations/000020_production_platform.up.sql`
- Verify: `migrations/000022_production_release_governance.up.sql`
- Verify: `docs/adr/0009-production-read-platform.md`
- Verify: `docs/adr/0012-production-release-governance.md`
- Verify: `test/production/verify-all.sh`
- Verify: `test/recovery/run-all.sh`
- Create: `docs/operations/production/final-release-checklist.md`
- Create: `docs/operations/production/post-release-review.md`

**Interfaces:**
- Consumes: all accepted Phase 1–8 commits and runtime evidence
- Produces: `PRODUCTION_CLOSED_LOOP_ACCEPTED` decision and sustained review cadence

- [ ] **Step 1: Run repository-wide deterministic verification**

From a clean isolated worktree:

```bash
go test -race -shuffle=on -count=1 ./...
go vet ./...
go build ./cmd/...
pnpm --dir web install --frozen-lockfile
pnpm --dir web generate:api
pnpm --dir web generate:api:check
pnpm --dir web check
pnpm --dir web test:e2e
helm lint deploy/helm/aiops --strict
bash scripts/verify-production-chart.sh
bash scripts/security/verify-release-artifacts.sh
./test/production/verify-all.sh
./test/recovery/run-all.sh
go test ./tests/documentation ./tests/security ./tests/production -count=1
git diff --check
git status --short
```

Expected: every command exits `0` and final status is clean. If generated contracts differ, commit the intentional source/generated change and rerun from the start.

- [ ] **Step 2: Review runtime release evidence**

The independent review confirms exact release/chart/image/schema/policy/runtime/eligible-manifest digests, all wave decisions and soak windows, capacity headroom, security/access/audit gates, clean-room DR RPO/RTO, success/uncertain E2E, credential cleanup, Kill Switch drills, on-call ownership and no unresolved blocking incident/finding.

Allowed final decisions are `HOLD`, `ROLL_BACK` or `PRODUCTION_CLOSED_LOOP_ACCEPTED`. After independent review, the authorized release signers submit the chosen value through the scoped release-acceptance API, with expected release and final evidence-set digests；the server persists the append-only `production_release_acceptance_decisions` row and returns its signature-set digest. An incomplete or unknown item cannot be waived verbally, and a Markdown status edit cannot create acceptance.

- [ ] **Step 3: Record acceptance and post-release cadence**

On acceptance, `final-release-checklist.md` references the signed release decision and bounded evidence digests. `post-release-review.md` defines:

- daily heightened review for the first seven days;
- weekly credential cleanup, verification and audit-gap review during the first month;
- monthly SLO/error-budget and Action-type review;
- quarterly access, restore, Kill Switch and incident drills;
- renewal gates after material schema/policy/identity/Runner/Action/infrastructure change;
- immediate hold on unauthorized mutation, duplicate effect, credential leak, unverifiable outcome or audit integrity loss.

- [ ] **Step 4: Commit the handoff record**

```bash
git add docs/operations/production/final-release-checklist.md docs/operations/production/post-release-review.md docs/status/current.md
git commit -m "docs(release): hand off sustained production operations"
git status --short
git log --oneline --decorate -30
```

Expected: clean status and small reviewable commits aligned to Phase 8 tasks. Runtime acceptance signatures remain in the governed store; source documents reference their immutable digests.
