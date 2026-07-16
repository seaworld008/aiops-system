# Staged Production Rollout, SLOs, and Automated Stop Decisions Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Roll accepted read and individually accepted write capabilities through deterministic production waves, promote only on fresh SLO/security evidence, and automatically halt claims when safety or reliability becomes uncertain.

**Architecture:** A durable rollout controller consumes release-transition outbox events, computes immutable wave membership, evaluates server-owned SLO/gate windows and proposes transitions. It may automatically hold a wave and activate the applicable Kill Switch, but promotion and production rollback remain explicit independently approved decisions. A dense operations page renders the same server projection without deriving roles, gates or health in the browser.

**Tech Stack:** Go 1.26.5, PostgreSQL 18.4+, Temporal, existing outbox and Kill Switch services, Prometheus-compatible metrics/alert rules, VictoriaMetrics/VictoriaLogs/VictoriaTraces dashboards, OpenAPI-generated React 19.2.7/TanStack clients, TypeScript 5.9.3, Vitest/MSW, Playwright and axe.

## Global Constraints

- 每个 Task 严格采用 Red → Green → Refactor：先运行并保存预期失败，再做最小生产实现，复跑指定测试后才允许重构和提交。
- Membership is content-addressed and pinned in the release candidate. A later Asset, Capability, Action, policy or ownership change cannot silently enter a running wave.
- Production Action availability remains per Action type and exact eligible Asset set. A read wave never opens write; one Action's acceptance never opens another.
- Automated logic can `HOLD`, deny new claims, revoke grants/credentials and escalate. It cannot `PROMOTE` or execute a mutation rollback without the exact approved decision path.
- Any `UNKNOWN` safety signal is blocking, not healthy. Missing telemetry is an incident condition.
- Rollout and UI never expose raw credentials, model prompts, full Evidence payloads, unredacted logs or arbitrary query editors.
- Frontend permissions come only from `effective_actions`; route visibility is not authorization.
- Production controller uses PostgreSQL, Temporal and real telemetry APIs. Test clocks/repositories/metrics are unreachable from production assembly.

## Decision Scope

- Wave decisions are only `PROMOTE|HOLD|ROLL_BACK` and persist through `release_decisions`.
- Final release acceptance is a separate `HOLD|ROLL_BACK|PRODUCTION_CLOSED_LOOP_ACCEPTED` command persisted through `production_release_acceptance_decisions` after the full eligible wave.
- Automated control may emit `HOLD` and a scoped Kill Switch command；it cannot emit promotion or final acceptance.
- Every decision binds the composite Tenant/Workspace/Environment Scope, release/wave/membership/evidence digests, expected version, independent actor and recent authentication.

### Task 1: Define SLOs, gate windows, alerts, and bounded telemetry

**Files:**
- Create: `docs/operations/production/slo-catalog.md`
- Create: `deploy/observability/alerts/production-release.yaml`
- Create: `deploy/observability/dashboards/production-overview.json`
- Create: `deploy/observability/dashboards/release-wave.json`
- Create: `internal/releasegovernance/sloevaluator.go`
- Create: `internal/releasegovernance/sloevaluator_test.go`
- Create: `tests/observability/production_rules_test.go`

**Interfaces:**
- Consumes: bounded metrics/log/trace queries, accepted release and wave time windows, Phase 6 baseline SLOs
- Produces: deterministic `PASS|FAIL|UNKNOWN` SLO evidence and actionable alerts

- [ ] **Step 1: Write failing SLO-evaluator and alert-rule tests**

Cover empty series, partial datasource failure, stale sample, counter reset, insufficient window, bad label cardinality, 99.9% availability breach, investigation success below 95%, Action verification below 95%, nonzero unauthorized/duplicate mutation, credential cleanup miss, audit/outbox gap and DLP rejection indicating possible exposure.

```go
func TestEvaluateWaveSLOTreatsMissingSeriesAsUnknown(t *testing.T) {
    result := EvaluateWaveSLO(ApprovedSLOs(), Window{Start: start, End: end}, Series{
        Availability: validAvailability(),
    })
    require.Equal(t, GateUnknown, result.Status)
    require.Contains(t, result.Missing, "credential_cleanup")
}
```

Run:

```bash
go test ./internal/releasegovernance ./tests/observability -run 'TestEvaluateWaveSLO|TestProductionRules' -count=1
```

Expected: FAIL until evaluator, rules and fixtures exist.

- [ ] **Step 2: Lock the initial production SLO catalog**

The catalog includes server-owned definitions and owners for:

- Control Plane monthly availability >=99.9%.
- Real governed investigation terminal success >=95%, excluding explicitly canceled user requests but not dependency failures.
- Evidence citation presence =100%; key-fact accuracy sampling >=95%; unsupported-fact sampling <=1%.
- Per eligible Action type, independent verification success >=95%.
- Unauthorized mutation count =0 and duplicate target effect count =0.
- Audit/outbox terminal delivery =100% within the documented delay budget.
- Credential terminal cleanup =100% within the issuer-specific grace; any credential usable after grace is a release stop.
- DLP/schema/budget denials are measured separately; a denial is not converted into success.
- Queue age, claim latency, Runner availability and dependency saturation thresholds inherited from the accepted capacity envelope.

Metric labels use bounded enums (`component`, `realm`, `capability_family`, `action_type`, `outcome`, `reason_code`, `wave`); never IDs, tenant, endpoint, query, actor or digest.

- [ ] **Step 3: Implement fail-closed telemetry evaluation and alerts**

Use typed query templates for VictoriaMetrics/VictoriaLogs/VictoriaTraces from Phase 3. Pin tenant, datasource and time range server-side. Require complete datasource responses and freshness. Hash the canonical query profile and result summary into Gate evidence.

Alerts cover fast/slow availability burn, authorization denial anomaly, missing audit/outbox, credential cleanup miss, duplicate effect, verification failure, DLP/security signal, telemetry absence, queue saturation, release-controller stall and Kill Switch state. Every page names severity, owner, first action and runbook URL.

Run:

```bash
go test -race ./internal/releasegovernance ./tests/observability -count=1
promtool check rules deploy/observability/alerts/production-release.yaml
jq -e . deploy/observability/dashboards/*.json
```

Expected: PASS; malicious high-cardinality labels and missing data fail tests.

- [ ] **Step 4: Commit SLO and observability contracts**

```bash
git add docs/operations/production/slo-catalog.md deploy/observability internal/releasegovernance tests/observability
git commit -m "feat(observability): evaluate production release SLOs"
```

### Task 2: Implement deterministic wave membership and durable rollout control

**Files:**
- Create: `internal/releasecontroller/controller.go`
- Create: `internal/releasecontroller/membership.go`
- Create: `internal/releasecontroller/controller_test.go`
- Create: `internal/releasecontroller/membership_test.go`
- Create: `internal/releasecontroller/postgres/repository.go`
- Create: `internal/releasecontroller/postgres/repository_integration_test.go`
- Create: `internal/releasecontroller/temporal/workflow.go`
- Create: `internal/releasecontroller/temporal/workflow_test.go`
- Modify: `cmd/worker/main.go`
- Modify: `cmd/worker/main_test.go`

**Interfaces:**
- Consumes: accepted release/wave records, eligible manifest, service criticality/ownership, gate evidence, decision outbox, Kill Switch
- Produces: immutable membership, soak workflow, hold/escalation commands and next-wave proposal

- [ ] **Step 1: Write failing membership, concurrency, and failure tests**

Assert:

- `INTERNAL_OPERATORS` contains only explicitly named internal test services.
- `ONE_NONCRITICAL_SERVICE` contains exactly one owner-approved tier-3/noncritical service.
- 10% and 30% cohorts are stable under list ordering and process restarts.
- Cohorts are nested and never include ineligible, critical, unmapped, non-`EXACT` or ownerless Assets.
- Full wave equals the pinned eligible manifest only.
- Two controllers cannot start/promote the same wave.
- A failed/unknown gate immediately enters `HELD` and invokes the correct scoped Kill Switch once.
- Stale release/policy/runtime/Kill Switch revisions stop the workflow.
- A controller crash resumes without resetting soak time or duplicating a decision.

Run:

```bash
go test ./internal/releasecontroller/... -count=1
```

Expected: FAIL because the package does not exist.

- [ ] **Step 2: Implement canonical membership**

Use SHA-256 over `release_digest + tenant_id + workspace_id + environment_id + service_id`, convert the first eight bytes to an unsigned score, sort by score then UUID, and select the exact ceiling count for 10%/30%. Persist the resulting ordered IDs and digest before a wave starts. Membership computation takes only the server-pinned eligible projection.

```go
func BuildMembership(release Digest, wave Wave, eligible []ServiceEligibility) (Membership, error)
func VerifyNested(previous, next Membership) error
```

The one-service wave is an explicit ID approved in the release manifest; the controller never guesses “noncritical” from a label alone.

- [ ] **Step 3: Implement the Temporal soak workflow and transactional controller**

Initial minimum soak windows:

| Wave | Minimum healthy soak |
|---|---:|
| `INTERNAL_OPERATORS` | 24 hours |
| `ONE_NONCRITICAL_SERVICE` | 24 hours |
| `TEN_PERCENT_ELIGIBLE` | 48 hours |
| `THIRTY_PERCENT_ELIGIBLE` | 72 hours |
| `FULL_ELIGIBLE_SCOPE` | seven days heightened monitoring after promotion |

The workflow records start, pauses on alert/unknown data, never counts held time as healthy soak, and requires a fresh evidence window after recovery. It writes commands through activities backed by expected-version transactions and outbox, not direct workflow-side SQL.

On safety failure it atomically records `HELD`/reason, activates the narrowest safe Kill Switch, denies new affected claims and opens human escalation. Active execution follows its existing safe stop/reconciliation protocol; it is not killed blindly.

- [ ] **Step 4: Wire real production assembly and commit**

```bash
AIOPS_TEST_POSTGRES_DSN="$AIOPS_TEST_POSTGRES_DSN" go test -race ./internal/releasecontroller/... -count=1
go test ./cmd/worker -run 'TestProduction.*ReleaseController|TestNoFakeReleaseController' -count=1
git add internal/releasecontroller cmd/worker
git commit -m "feat(release): control deterministic rollout waves"
```

Expected: PASS; production worker has exactly one durable release-controller assembly path.

### Task 3: Build the high-fidelity release command center

**Files:**
- Create: `web/src/features/releases/routes/releasesRoute.tsx`
- Create: `web/src/features/releases/routes/releaseDetailRoute.tsx`
- Modify: `web/src/app/router.tsx`
- Modify: `web/src/app/navigation.ts`
- Create: `web/src/features/releases/api.ts`
- Create: `web/src/features/releases/model.ts`
- Create: `web/src/features/releases/ReleaseHeader.tsx`
- Create: `web/src/features/releases/WaveRail.tsx`
- Create: `web/src/features/releases/GateMatrix.tsx`
- Create: `web/src/features/releases/EligibilityPanel.tsx`
- Create: `web/src/features/releases/DecisionDrawer.tsx`
- Create: `web/src/features/releases/ReleaseTimeline.tsx`
- Create: `web/src/features/releases/release.module.css`
- Create: `web/src/features/releases/ReleaseCommandCenter.test.tsx`
- Create: `web/src/features/releases/DecisionDrawer.test.tsx`
- Create: `web/e2e/production-release.spec.ts`
- Create: `docs/design/frontend/production-release-command-center.md`

**Interfaces:**
- Consumes: generated release OpenAPI types, release/wave/evidence projection, `effective_actions`, OIDC reauthentication flow
- Produces: accessible operator review, hold/promote/rollback decision flow and evidence navigation

- [ ] **Step 1: Write failing component and interaction tests**

Test loading/error/empty/partial states independently, URL-restored filters/tab, live update reconnect, gate unknown vs fail, keyboard navigation, reduced motion, permission denial, stale version conflict, reauth cancel/expiry, self-approval denial, idempotent decision resubmit, evidence redaction and responsive layout.

Run:

```bash
pnpm --dir web test -- --run src/features/releases
pnpm --dir web test:e2e -- --grep "production release"
```

Expected: FAIL because routes/components do not exist.

- [ ] **Step 2: Persist and implement the command-center layout**

Use the established light enterprise shell, not a chat or AI assistant surface:

Before component implementation, write `docs/design/frontend/production-release-command-center.md` as the durable UI contract: exact routes/search schema、page hierarchy、component ownership、all orthogonal states、Gate/Wave/Eligibility field definitions、decision drawer/reauth/conflict/failure interactions、1440/1024/390 layouts、visual tokens、keyboard/focus/live-region/reduced-motion/WCAG rules、real OIDC/`effective_actions` boundary and forbidden chat/AI/terminal/arbitrary-edit patterns. Component tests and final design compendium must link to this document；a screenshot alone is not a design contract.

Register `/production/releases` and `/production/releases/$releaseId` through the existing central `web/src/app/router.tsx` using the project's TanStack parameter syntax；expose the entry through `web/src/app/navigation.ts`. The feature owns route components under `web/src/features/releases/routes/` and must not introduce a second top-level file-router convention.

- Header: release sequence, immutable digest copy affordance, state, environment, created time and independent signers.
- Five-step horizontal/vertical WaveRail with exact membership count, start/healthy-soak/decision times and current Hold reason.
- Dense GateMatrix rows for availability, investigation, verification, authorization, credential cleanup, audit, DLP, security, capacity and DR; columns show status, threshold, observed value/window, freshness, owner and evidence link.
- EligibilityPanel separates READ capabilities from each Action type and shows exact eligible/excluded counts/reasons.
- Timeline shows append-only evidence, automated holds, Kill Switch changes and human decisions.
- Sticky decision bar appears only for API-provided actions; `PROMOTE` is unavailable until every gate is fresh PASS and soak complete.

Colors remain restrained navy/blue with semantic red/amber/green plus icon/text. Use 4–6px radius, 1px borders, tabular numerals, 44px targets, persistent labels, visible focus and no gradient/glow/avatar/conversational copy.

- [ ] **Step 3: Implement reauthenticated decision drawer**

The drawer shows exact release/wave/membership/policy/runtime digests, affected capabilities, evidence window, open incidents, Kill Switch, proposed state and consequences. Operator enters a bounded rationale code, performs OIDC reauthentication, then submits expected state/version and idempotency key. The proof remains memory-only and is cleared on close/result.

On `409` or `412`, discard the stale decision and reload; never auto-resubmit against new evidence. On timeout, query idempotency result before allowing retry.

- [ ] **Step 4: Pass UI quality and commit**

```bash
pnpm --dir web generate:api
pnpm --dir web check
pnpm --dir web test:e2e -- --grep "production release"
pnpm --dir web exec playwright test --grep @a11y
git add web docs/design/frontend/production-release-command-center.md
git commit -m "feat(web): add production release command center"
```

Expected: tests pass at desktop/tablet/mobile widths, keyboard-only and reduced-motion modes; no accessibility serious/critical finding.

### Task 4: Execute the fixed waves and record Go/No-Go decisions

**Files:**
- Create: `docs/operations/production/staged-rollout.md`
- Create: `docs/operations/production/release-decision-record.schema.json`
- Create: `tests/production/rollout_e2e_test.go`
- Create: `tests/production/automated_hold_test.go`
- Modify: `docs/status/current.md`

**Interfaces:**
- Consumes: accepted release, chart, memberships, all fresh gate evidence, independent decision identities
- Produces: wave-by-wave `PROMOTE|HOLD|ROLL_BACK` records and final eligible-scope release state

- [ ] **Step 1: Write failing rollout E2E tests**

Use production-equivalent infrastructure to prove normal promotion, missing telemetry hold, SLO burn hold, unauthorized attempt hold, credential cleanup hold, duplicate effect hold, active incident hold, decision race, stale version and safe rollback-to-previous-release behavior.

Run:

```bash
AIOPS_E2E_CLUSTER=production-equivalent go test ./tests/production -run 'TestRollout|TestAutomatedHold' -count=1 -timeout=45m
```

Expected: FAIL until controller, telemetry and decision paths are integrated.

- [ ] **Step 2: Execute internal and one-service waves**

For each wave:

1. Freeze and sign membership/release digests.
2. Verify no open blocking incident/finding and all credentials/identities/policies are current.
3. Approve start with proposer/decider separation.
4. Observe the full healthy soak; held time does not count.
5. Run success plus stop/cleanup probe.
6. Collect and sign gate evidence.
7. Record `PROMOTE`, `HOLD` or `ROLL_BACK` with reauthentication and independent signer.

Do not compress soak windows to finish a schedule. A hold restarts the required healthy observation window after correction.

- [ ] **Step 3: Execute 10%, 30%, and full-eligible waves**

Apply the same sequence. Before each larger wave, validate nested membership, capacity headroom, service-owner notification, on-call coverage, rollback target and exact per-Action availability. Critical or separately regulated services remain excluded unless explicitly accepted by their additional policy gate.

After full promotion, maintain seven days of heightened monitoring; a blocking signal returns the release to `HELD` and activates the scoped stop path.

- [ ] **Step 4: Verify and commit rollout support**

```bash
AIOPS_E2E_CLUSTER=production-equivalent go test ./tests/production -run 'TestRollout|TestAutomatedHold' -count=1 -timeout=45m
go test -race -shuffle=on -count=1 ./internal/releasegovernance/... ./internal/releasecontroller/...
pnpm --dir web check
git add docs/operations/production/staged-rollout.md docs/operations/production/release-decision-record.schema.json tests/production docs/status/current.md
git commit -m "docs(release): record staged production rollout"
```

Expected: code/tests are committed. Runtime decision evidence remains in the governed evidence store and is referenced by digest from `docs/status/current.md` rather than fabricated in source control.
