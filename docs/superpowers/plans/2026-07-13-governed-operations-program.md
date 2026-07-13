# Governed Operations Program Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver the approved governed-operations control plane as a complete, supportable production closed loop spanning governed investigation, approved execution, verification, recovery, audit, and staged rollout.

**Architecture:** Build from authoritative asset projections to versioned connection publication, typed VictoriaMetrics capabilities, short-lived investigation grants, host/database diagnostics, and production-grade platform assembly. Treat production read-only as an intermediate gate, then add only fixed, typed, approved actions with short credentials, post-action verification, reconciliation, rollback/escalation, and finally complete HA/DR/security/capacity rollout evidence. Every phase consumes only explicit earlier interfaces and ships database, domain, API, frontend, operations, audit, and end-to-end proof together.

**Tech Stack:** Go 1.26.5, PostgreSQL 18.4, Temporal Go SDK 1.46.0, Keycloak Server 26.6.3/keycloak-js 26.2.4, Vault, mTLS Runner protocols, OpenAPI 3.1, Node.js 24 LTS, pnpm 10.34.0, React 19.2.7, TypeScript 7.0.2, Vite 8.1.4, TanStack Router/Query/Table, CSS Modules, Vitest, MSW, Playwright, and axe. Exact planning pins and verification sources live in the [version baseline](2026-07-13-governed-operations/version-baseline.md).

**Navigation:** [current status](../../status/current.md) · [small-document index](2026-07-13-governed-operations/README.md) · [specification coverage](2026-07-13-governed-operations/coverage-matrix.md) · [version baseline](2026-07-13-governed-operations/version-baseline.md) · [approved design](../specs/2026-07-13-operational-assets-controlled-access-design.md)

## Global Constraints

- The model is never an authorization principal and is not part of the trusted computing base.
- Only `ACTIVE + EXACT + PUBLISHED + AVAILABLE` asset capabilities may enter a live investigation.
- The browser, model, Task payload, and Runner payload never carry a Secret, private key, raw credential, arbitrary endpoint, arbitrary header/body, command text, script, or SQL text.
- Every live run pins an immutable Asset Snapshot, Target, Capability Snapshot, Runtime Bundle, policy revision, Kill Switch revision, and Grant digest.
- Credentials are single-asset, single-Capability, single-Task/Attempt, non-renewable, and expire no later than both Grant and Lease.
- Alert, incident, and approved schedule triggers may create short read-only investigations and append-only `PROPOSAL_ONLY` ActionProposals；a separate human-requested governed-action path may derive and seal an immutable ActionPlan from one current Proposal, then execute only fixed reviewed types after current policy/gates, recent authentication, distinct human approval, one-attempt short credential, typed mutation, independent verification and complete audit。
- No phase ever enables interactive SSH/WinRM, PTY, port forwarding, SFTP, arbitrary shell, arbitrary SQL, unconstrained database writes, or Metrics/Logs/Traces ingestion. Production mutation stays closed through Phase 6; Phase 7 may open only individually reviewed fixed Action/Runbook types bound to an immutable plan, policy decision, human approval, short credential, verification, rollback/reconciliation, and audit chain.
- Manual assets are registered operational references, not desired-state resource controllers or replacements for external CMDB/cloud/Kubernetes/Operator facts.
- The frontend uses the approved light, dense enterprise console: navy navigation, restrained blue actions, 4–6px radius, 1px borders, no chat shell, AI avatar, neon, glow, gradient, glassmorphism, or decorative bento layout.
- Frontend state dimensions remain orthogonal; permissions come from API `effective_actions`, never from frontend role-name inference.
- Browser OIDC uses `login-required`; access tokens live only in memory, are refreshed before requests, and are never persisted to localStorage, sessionStorage, IndexedDB, or application cookies. Missing production OIDC configuration fails closed.
- Accessibility target is WCAG 2.2 AA with visible focus, persistent labels, keyboard operation, reduced motion, non-color status cues, and 44px touch targets.
- All implementation work runs in an isolated worktree whose module root does not contain nested `.worktrees`; do not delete or modify the user's existing worktrees to make architecture-boundary tests pass.
- Migration ownership is fixed: `000015` assets, `000016` connections/runtime/realms, `000017` VictoriaMetrics, `000018` grants/policies, `000019` host/PostgreSQL, `000020` production platform, `000021` governed actions, `000022` release governance.
- Each phase follows TDD, ends in a reviewable commit sequence, and must leave `go test ./...`, `go vet ./...`, `go build ./cmd/...`, and `pnpm --dir web check` green before the next phase starts.

---

## Plan Set and File Ownership

| Order | Detailed plan | Migration | Primary output |
|---:|---|---|---|
| 1 | [Asset Catalog and Discovery Control Plane](2026-07-13-governed-operations/01-assets/README.md) | `000015_assets_catalog` | Versioned Sources, provider adapters, asset facts, discovery worker, mapping, Control Plane contract, frontend shell |
| 2 | [Connection and Runtime Publication](2026-07-13-governed-operations/02-connections/README.md) | `000016_connection_runtime_publication` | Versioned connections, validation Runner, credential references, Runtime publication |
| 3 | [VictoriaMetrics Ecosystem](2026-07-13-governed-operations/03-victoriametrics/README.md) | `000017_victoriametrics_ecosystem` | Full Operator discovery and typed Metrics/Logs/Traces READ capabilities |
| 4 | [Investigation Grants and Proactive Policies](2026-07-13-governed-operations/04-proactive-grants/README.md) | `000018_investigation_grants_proactive_policies` | Immutable snapshots, short Grants, event/schedule policy, budgets, Kill Switch, append-only ActionProposal |
| 5 | [Host and PostgreSQL Read Diagnostics](2026-07-13-governed-operations/05-host-postgresql/README.md) | `000019_host_postgresql_read_diagnostics` | Fixed host probes/AWX and named PostgreSQL diagnostic queries |
| 6 | [Production Platform and Read Path](2026-07-13-governed-operations/06-production-platform/README.md) | `000020_production_platform` | Live HA assembly, SLO, recovery, Shadow and production read-only operation |
| 7 | [Governed Production Actions](2026-07-13-governed-operations/07-governed-actions/README.md) | `000021_governed_actions` | Fixed approved actions, short credentials, verification, reconciliation and rollback |
| 8 | [Production Rollout and Operations](2026-07-13-governed-operations/08-production-rollout/README.md) | `000022_production_release_governance` | Capacity, security, DR, compliance, staged rollout and sustained ownership |

The detailed plans own all code-level TDD steps. This program file owns ordering, integration gates, shared names, and the final handoff only; it must not be used to skip a detailed plan.

## Cross-plan Interface Contract

| Producer | Stable output consumed later |
|---|---|
| Plan 1 | `internal/assetcatalog` domain/repository, immutable AssetSource revisions, CSV/API/CMDB/vSphere/Proxmox/OpenStack/cloud discovery adapters, durable cursor/lease/fence/rate limit, `cmd/discovery-worker`, authoritative lifecycle and mapping eligibility, Overview/source UI, `api/openapi/control-plane-v1.yaml`, `web/` shell and common Problem Details/`effective_actions` handling |
| Plan 2 | `internal/connectionprofile`, `internal/capability`, `internal/runtimepublication`, Opaque `credential_references`, `runner_realms`, Validation Runner protocol, immutable Target/Capability/Runtime digests |
| Plan 3 | VictoriaMetrics asset taxonomy/details, Operator observation projector, Metrics/Logs/Traces connector contracts, executor profile revision, Evidence schemas, Victoria-specific UI projections |
| Plan 4 | `asset_snapshots`, `InvestigationGrant`, proactive policy revisions/runs, six-level Kill Switch, budget accounting, Gateway Claim/Start/Heartbeat/Complete grant admission, append-only `PROPOSAL_ONLY` ActionProposal with Evidence/Catalog digests and read-only API |
| Plan 5 | fixed host-probe/AWX and PostgreSQL adapter families, READ credential issuers/revokers, named diagnostic query registry, DLP-safe evidence |
| Plan 6 | production HA process assembly, rollout revisions, immutable READ baseline/handoff, SLO/alerts, backup/recovery proof, security drill evidence, production read-only readiness |
| Plan 7 | accepted Action platform successor/manifest, fixed Action catalog, exact `ActionEnvelope`, approval binding, WRITE credentials/Runner, post-action verification, reconciliation, rollback and human escalation |
| Plan 8 | load/capacity and chaos evidence, DR exercise, security/compliance sign-off, canary waves, operating ownership, release decision and normative documentation |

Cross-plan identifiers are UUIDs on persistence/API boundaries. Content-addressed objects use lowercase 64-character SHA-256 hex digests. Public JSON uses `snake_case`; Go exported fields use `PascalCase`; frontend TypeScript consumes generated OpenAPI types rather than handwritten duplicate DTOs.

Phase 1 的稳定接口进一步锁定：Source/Asset revision 使用 `int64`；`asset_source_revisions.canonical_revision_digest` 就是覆盖完整不可变可用性绑定的 `BindingDigest`，`source_definition_digest` 仅表示 Provider definition；资产类型在 `000015` 以命名闭集约束 `assets_kind_check` 建立并由 `000017` 扩展；跨 Environment Relationship 显式携带 source/target Environment；Binding 软删除状态为 `INACTIVE`；所有 Mapping mutation 都返回持久 `MutationReceipt`。后续任务包只能消费这些定义，不得重定义平行 DTO、摘要语义或软删除状态。

## Program State Machine

```text
SPEC_APPROVED
  → ASSET_CONTROL_PLANE_ACCEPTED
  → CONNECTION_PUBLICATION_ACCEPTED
  → VICTORIAMETRICS_ACCEPTED
  → PROACTIVE_READ_ACCEPTED
  → HOST_DATABASE_READ_ACCEPTED
  → SHADOW_PILOT_ACCEPTED
  → PRODUCTION_READ_ONLY_PILOT_ACCEPTED
  → GOVERNED_WRITE_NONPRODUCTION_ACCEPTED
  → GOVERNED_WRITE_CANARY_ACCEPTED
  → PRODUCTION_CLOSED_LOOP_ACCEPTED
```

Production write transitions exist only after production read-only acceptance and only for fixed Action types that satisfy Phase 7 gates. A failed or uncertain gate leaves the program at the last accepted state, disables the affected Action/Capability, and opens a corrective or human-escalation task in the active detailed plan.

### Task 1: Establish the isolated execution baseline

**Files:**
- Read: `docs/superpowers/specs/2026-07-13-operational-assets-controlled-access-design.md`
- Read: `docs/superpowers/plans/2026-07-13-governed-operations/01-assets/README.md`
- Verify: `go.mod`
- Verify: `Makefile`

**Interfaces:**
- Consumes: approved design commit `ad50d9f83b117663de35c7285891434b6c48150c`
- Produces: a clean isolated worktree and recorded baseline result used by every detailed plan

- [ ] **Step 1: Create the execution worktree through the required Superpowers worktree skill**

Use `superpowers:using-git-worktrees` and create branch `codex/governed-operations-assets`. The chosen worktree's module root must not contain a child `.worktrees` directory.

- [ ] **Step 2: Verify repository and toolchain identity**

Run:

```bash
git rev-parse --show-toplevel
git status --short
go version
node --version
pnpm --version
```

Expected: the new worktree root, no status output, Go `1.26.5`, Node `v24.x`, and pnpm `10.x`.

- [ ] **Step 3: Run the backend baseline**

Run:

```bash
go test ./...
go vet ./...
go build ./cmd/...
```

Expected: all commands exit `0`. If architecture tests report duplicate production calls under `.worktrees/*`, the execution location is invalid; create a clean worktree instead of changing tests or deleting user worktrees.

- [ ] **Step 4: Record the baseline without creating a code commit**

Run:

```bash
git status --short
```

Expected: no output. Baseline verification creates no repository mutation.

### Task 2: Execute and accept the asset control plane

**Files:**
- Execute: `docs/superpowers/plans/2026-07-13-governed-operations/01-assets/README.md`
- Verify: `migrations/000015_assets_catalog.up.sql`
- Verify: `api/openapi/control-plane-v1.yaml`
- Verify: `web/package.json`

**Interfaces:**
- Consumes: Task 1 clean baseline
- Produces: Plan 1 interfaces listed in the cross-plan contract and frontend command surface `generate:api`, `typecheck`, `lint`, `test`, `build`, `test:e2e`, `check`

- [ ] **Step 1: Execute every unchecked Plan 1 task in order**

Use the task-level tests and commits from the detailed plan. Do not begin Plan 2 while any Plan 1 checkbox remains unchecked.

- [ ] **Step 2: Verify migration and API ownership**

Run:

```bash
test -f migrations/000015_assets_catalog.up.sql
test -f migrations/000015_assets_catalog.down.sql
test -f api/openapi/control-plane-v1.yaml
test -f web/src/shared/api/schema.d.ts
```

Expected: exit `0` with no output.

- [ ] **Step 3: Run the Plan 1 acceptance suite**

Run:

```bash
go test -race -shuffle=on -count=1 ./internal/assetcatalog/... ./internal/assetdiscovery/... ./internal/httpapi/...
pnpm --dir web check
pnpm --dir web test:e2e -- --grep "asset|mapping|source"
```

Expected: backend packages pass, frontend check exits `0`, and asset/mapping/source Playwright scenarios pass.

- [ ] **Step 4: Review the gate evidence**

Confirm that cross-scope foreign keys fail; every non-manual Source type has an implemented adapter and remains `UNAVAILABLE` until its own validation/E2E gate passes; cursor/lease/fence/rate limit and soft-delete/recovery survive worker takeover; discovery cannot silently overwrite manual governance fields; non-`EXACT` assets have no diagnostic action; browser fixtures contain no secret material; and URL state restores Overview, source inventory and asset workbench.

### Task 3: Execute and accept connection publication

**Files:**
- Execute: `docs/superpowers/plans/2026-07-13-governed-operations/02-connections/README.md`
- Verify: `migrations/000016_connection_runtime_publication.up.sql`
- Verify: `internal/connectionprofile/`
- Verify: `internal/runtimepublication/`

**Interfaces:**
- Consumes: Plan 1 Asset identity, scope, lifecycle, mapping, OpenAPI, and frontend shell
- Produces: Plan 2 immutable connection/runtime and Validation Runner interfaces

- [ ] **Step 1: Execute every unchecked Plan 2 task in order**

Use the detailed TDD loops and commits; do not substitute an in-process fake for the isolated Validation Runner publication gate.

- [ ] **Step 2: Verify fail-closed publication artifacts**

Run:

```bash
test -f migrations/000016_connection_runtime_publication.up.sql
test -d internal/connectionprofile
test -d internal/runtimepublication
test -d internal/connectionvalidation
test -d internal/validationrunner
```

Expected: exit `0` with no output.

- [ ] **Step 3: Run the Plan 2 acceptance suite**

Run:

```bash
go test -race -shuffle=on -count=1 ./internal/connectionprofile/... ./internal/capability/... ./internal/runtimepublication/... ./internal/connectionvalidation/... ./internal/validationrunner/... ./internal/runnergateway/...
pnpm --dir web check
pnpm --dir web test:e2e -- --grep "connection|validation|publication"
```

Expected: all tests pass; the E2E flow creates a new revision, validates through the mTLS protocol, reauthenticates, and publishes without changing an active investigation's digest.

- [ ] **Step 4: Review the gate evidence**

Confirm that unavailable Validation Runners close publication, validation output is bounded, credential references are opaque, revisions are immutable, an initial `DISCOVERED|STALE + EXACT` Asset becomes `ACTIVE` only after exact Runtime apply and terminal credential cleanup, and no browser response includes Secret, Token, PEM, DSN, Vault path, or raw upstream error.

### Task 4: Execute and accept VictoriaMetrics coverage

**Files:**
- Execute: `docs/superpowers/plans/2026-07-13-governed-operations/03-victoriametrics/README.md`
- Verify: `migrations/000017_victoriametrics_ecosystem.up.sql`
- Verify: `internal/assetdiscovery/victoriametrics/`
- Verify: `internal/readconnector/`
- Verify: `internal/readexecutor/`

**Interfaces:**
- Consumes: Plans 1–2 asset, connection, Target, Capability, Runtime, and Realm contracts
- Produces: Plan 3 full VictoriaMetrics discovery and typed read capability set

- [ ] **Step 1: Execute every unchecked Plan 3 task in order**

Use the detailed plan's provider-by-provider tests. Do not expose Operator-created Secret data or any ingestion endpoint.

- [ ] **Step 2: Verify official resource and query-family coverage**

Run:

```bash
go test ./internal/assetdiscovery/victoriametrics/... -run 'TestOperatorResourceCoverage|TestSecretProjectionDenied'
go test ./internal/readconnector/... ./internal/readexecutor/... -run 'TestVictoriaMetrics|TestVictoriaLogs|TestVictoriaTraces'
```

Expected: all resource coverage, typed request, bounded response, and negative ingestion tests pass.

- [ ] **Step 3: Run the Plan 3 acceptance suite**

Run:

```bash
go test -race -shuffle=on -count=1 ./internal/assetdiscovery/victoriametrics/... ./internal/readconnector/... ./internal/readtarget/... ./internal/readexecutor/... ./internal/readruntime/...
pnpm --dir web check
pnpm --dir web test:e2e -- --grep "VictoriaMetrics|VictoriaLogs|VictoriaTraces"
```

Expected: all tests pass and the browser differentiates virtual machines from the VictoriaMetrics ecosystem.

- [ ] **Step 4: Review the gate evidence**

Confirm that `vminsert`, `vlinsert`, `vtinsert`, OTLP, log writes, `vmctl`, `vmbackup`, `vmrestore`, and `vmalert-tool` have no investigation Grant capability.

### Task 5: Execute and accept proactive read authorization

**Files:**
- Execute: `docs/superpowers/plans/2026-07-13-governed-operations/04-proactive-grants/README.md`
- Verify: `migrations/000018_investigation_grants_proactive_policies.up.sql`
- Verify: `internal/investigationgrant/`
- Verify: `internal/proactivepolicy/`

**Interfaces:**
- Consumes: Plans 1–3 immutable Asset/Capability/Runtime and Runner Realm publications
- Produces: Plan 4 Snapshot, Grant, policy, budget, Kill Switch, four-boundary Gateway authorization and non-authoritative ActionProposal

- [ ] **Step 1: Execute every unchecked Plan 4 task in order**

Follow the detailed TDD sequence; each trigger resolves a fresh Asset Snapshot and issues a new non-renewable Grant.

- [ ] **Step 2: Run the Grant and policy security suite**

Run:

```bash
go test -race -shuffle=on -count=1 ./internal/investigationgrant/... ./internal/proactivepolicy/... ./internal/runnergateway/... ./internal/readtask/...
```

Expected: tests pass for expiry, revocation, scope mismatch, budget exhaustion, all six Kill Switch levels, and Claim/Start/Heartbeat/Complete revalidation.

- [ ] **Step 3: Run frontend and E2E acceptance**

Run:

```bash
pnpm --dir web check
pnpm --dir web test:e2e -- --grep "proactive|Grant|Kill Switch|Shadow|investigation|policy|ActionProposal"
```

Expected: policy preview, revision publication, run proof, independent failure states, and read-only wording pass.

- [ ] **Step 4: Review the gate evidence**

Confirm maximum 12 tool calls, maximum three concurrent calls per source, enforced duration/evidence/model budgets, `SHADOW` target isolation, ActionProposal append-only/`PROPOSAL_ONLY` semantics, and inability to reuse a READ Grant/credential or ActionProposal as execution authority. No Phase 4 API can create, approve, queue or execute an ActionPlan.

### Task 6: Execute and accept host and PostgreSQL diagnostics

**Files:**
- Execute: `docs/superpowers/plans/2026-07-13-governed-operations/05-host-postgresql/README.md`
- Verify: `migrations/000019_host_postgresql_read_diagnostics.up.sql`
- Verify: `internal/hostdiagnostic/`
- Verify: `internal/hostprobe/`
- Verify: `internal/postgresdiagnostic/`
- Verify: `internal/postgresrunner/`

**Interfaces:**
- Consumes: Plans 1–4 assets, connections, typed capabilities, realms, Grants, budgets, credentials, and Evidence admission
- Produces: Plan 5 fixed host/AWX and named PostgreSQL diagnostic capabilities

- [ ] **Step 1: Execute every unchecked Plan 5 task in order**

Keep host and database adapters in separate trust domains and Runner Realms; neither accepts a caller-supplied command, path, script, DSN, or SQL statement.

- [ ] **Step 2: Run negative security suites**

Run:

```bash
go test ./internal/hostdiagnostic/... ./internal/hostprobe/... -count=1
go test ./internal/postgresdiagnostic/... ./internal/postgresrunner/... -count=1
```

Expected: shell metacharacters, argv/env, path escape, PTY, forwarding, arbitrary SQL, multiple statements, DDL/DML, `COPY`, functions, extensions, and timeout overrides are rejected.

- [ ] **Step 3: Run Plan 5 acceptance**

Run:

```bash
go test -race -shuffle=on -count=1 ./internal/hostdiagnostic/... ./internal/hostprobe/... ./internal/postgresdiagnostic/... ./internal/postgresrunner/... ./internal/readcredential/...
pnpm --dir web check
pnpm --dir web test:e2e -- --grep "host diagnostic|PostgreSQL diagnostic"
```

Expected: all tests pass and Evidence contains only bounded, schema-valid, redacted fields.

- [ ] **Step 4: Review the gate evidence**

Confirm that every credential is durably revoked on completion, cancellation, timeout, and crash, and that an uncertain revocation stops the investigation and opens human escalation.

### Task 7: Execute and accept the production platform and read path

**Files:**
- Execute: `docs/superpowers/plans/2026-07-13-governed-operations/06-production-platform/README.md`
- Verify: `migrations/000020_production_platform.up.sql`
- Modify through detailed plan: `cmd/control-plane/`
- Modify through detailed plan: `cmd/worker/`
- Modify through detailed plan: `cmd/discovery-worker/`
- Modify through detailed plan: `cmd/read-runner/`

**Interfaces:**
- Consumes: every interface and gate from Plans 1–5
- Produces: Plan 6 HA read-path assembly, production SLO/DR evidence, normative operations contracts, and production-read decision record

- [ ] **Step 1: Execute every unchecked Plan 6 implementation task in order**

Wire real Control Worker, Discovery Worker, Outbox, Gateway, Validation Runner, READ Runner, runtime publications, metrics, alerts, horizontal scaling, recovery, and runbooks. WRITE claims stay closed until Plan 7.

- [ ] **Step 2: Pass repository-wide quality gates**

Run:

```bash
go test -race -shuffle=on -count=1 ./...
go vet ./...
go build ./cmd/...
pnpm --dir web check
pnpm --dir web test:e2e
```

Expected: all commands exit `0`.

- [ ] **Step 3: Execute the staged pilot gates**

Run the detailed plan's Preview, non-production `READ_ONLY`, production `SHADOW`, and supervised production `READ_ONLY` drills in order. Save each drill's immutable policy, Asset Snapshot, Grant, Runtime, credential-revocation, Evidence, Receipt, and Audit digests.

- [ ] **Step 4: Verify write closure**

Run:

```bash
go test ./test/security/production ./deploy/helm/aiops ./test/production -count=1
```

Expected: all security/chart/production tests actually execute and pass；the observed WRITE surface exactly matches the Phase 6 accepted empty Action manifest, so no production mutation capability is claimable.

- [ ] **Step 5: Complete the Go/No-Go review**

The allowed decisions at this gate are `NO_GO`, `CONTINUE_SHADOW`, or `APPROVE_PRODUCTION_READ_ONLY`. Approval is an input to Plan 7, not the end of the program.

### Task 8: Execute and accept governed production actions

**Files:**
- Execute: `docs/superpowers/plans/2026-07-13-governed-operations/07-governed-actions/README.md`
- Verify: `migrations/000021_governed_actions.up.sql`
- Modify through detailed plan: `internal/action/`
- Modify through detailed plan: `internal/execution/`
- Create through detailed plan: `internal/actionverification/`
- Modify through detailed plan: `cmd/write-runner/`

**Interfaces:**
- Consumes: production-accepted read path, exact assets/connections, Phase 4 ActionProposal, server-sealed immutable plans, policy/approval, Runner Realm, credentials, Evidence and audit from Plans 1–6
- Produces: fixed production Action catalog, approval-bound execution, post-action verification, reconciliation, rollback and human escalation

- [ ] **Step 1: Execute every unchecked Plan 7 task in order**

Open fixed actions one type at a time. The initial production candidates are reviewed Kubernetes, GitOps and AWX `ActionEnvelope` operations already expressible without arbitrary payloads; host, database, network, DNS, cloud and secret mutation remain closed unless their own ADR, typed contract and negative suite are added to this plan before execution.

- [ ] **Step 2: Pass the authorization and execution security suites**

Run:

```bash
go test -race -shuffle=on -count=1 ./internal/action/... ./internal/policy/... ./internal/execution/... ./internal/actionverification/... ./internal/credential/...
```

Expected: plan digest mismatch, target drift, expired approval, stale policy, unavailable credential, duplicate claim, verification failure and uncertain result all fail closed and produce durable audit/escalation state.

- [ ] **Step 3: Pass the complete operator journey**

Run:

```bash
pnpm --dir web check
pnpm --dir web test:e2e -- --grep "ActionPlan|approval|execution|verification|rollback|escalation"
```

Expected: an operator can review exact evidence and diff, reauthenticate, approve the immutable hash, observe short-credential issuance, follow execution/verification, and see either a verified receipt or a stopped/reconciled human-escalation outcome.

- [ ] **Step 4: Complete non-production and production canary gates**

Each Action type must pass the detailed plan's adversarial suite, at least 20 non-production drills with at least 95% verification success, and a supervised production canary with zero unauthorized or duplicate mutations before its individual gate can become `AVAILABLE`.

### Task 9: Execute production rollout and sustained operations

**Files:**
- Execute: `docs/superpowers/plans/2026-07-13-governed-operations/08-production-rollout/README.md`
- Verify: `migrations/000022_production_release_governance.up.sql`
- Verify: `deploy/helm/aiops/`
- Verify: `docs/operations/production/`
- Verify: `docs/security/production-readiness.md`

**Interfaces:**
- Consumes: accepted production read path and individually accepted governed Action types
- Produces: capacity/security/DR evidence, staged rollout decisions, on-call ownership, production SLOs and a sustained production closed loop

- [ ] **Step 1: Execute every unchecked Plan 8 task in order**

Complete multi-replica deployment, PostgreSQL/Temporal/Keycloak/Vault/PKI production integration, NetworkPolicy, pod/workload identity, backup/restore, zero-downtime migration, capacity/load, chaos, dependency-failure and incident drills.

- [ ] **Step 2: Pass full-system release verification**

Run:

```bash
go test -race -shuffle=on -count=1 ./...
go vet ./...
go build ./cmd/...
pnpm --dir web check
pnpm --dir web test:e2e
helm lint deploy/helm/aiops
```

Expected: every command exits `0`; generated contracts are clean; no test-only identity, credential, endpoint, fake Runner or in-memory repository is reachable from a production assembly.

- [ ] **Step 3: Run staged production rollout**

Follow the detailed gate sequence: internal operators → one non-critical service → 10% eligible services → 30% → full eligible scope. Each wave requires SLO, security, credential cleanup, verification, rollback and audit thresholds to remain green for its defined soak window.

- [ ] **Step 4: Accept the production closed loop**

Acceptance requires alert/event/approved schedule → governed read-only investigation → bounded Evidence → append-only `PROPOSAL_ONLY` ActionProposal or Human Review Finding → explicit human request → same-transaction trusted reload and immutable ActionPlan sealing → policy/reauth/approval → short credential → typed execution → independent post-action verification → Receipt/Audit, with failure paths proving stop, revoke, reconcile, rollback where safe, and human escalation. The release evidence must also prove that a Proposal, browser DTO, model output, READ Grant, or READ credential can never become execution authority.

### Task 10: Final documentation and handoff audit

**Files:**
- Verify: `docs/status/current.md`
- Verify: `docs/architecture/implementation-blueprint-v4.md`
- Verify: `docs/adr/`
- Verify: `docs/design/frontend/`
- Verify: `AGENTS.md`
- Verify: `api/openapi/control-plane-v1.yaml`

**Interfaces:**
- Consumes: accepted Plans 1–8 and their test/audit/production evidence
- Produces: one unambiguous future-work entry point for humans and agentic workers

- [ ] **Step 1: Verify required normative documents exist**

Run:

```bash
test -f docs/status/current.md
test -f docs/architecture/implementation-blueprint-v4.md
test -d docs/adr
test -d docs/design/frontend
test -f AGENTS.md
test -f api/openapi/control-plane-v1.yaml
```

Expected: exit `0` with no output.

- [ ] **Step 2: Scan for prohibited incomplete markers and stale version examples**

Run:

```bash
rg -n 'T[B]D|T[O]DO|F[I]XME|implement l[a]ter|待[定]|待[补]|Runtime Bundle v18|Runtime Bundle v19' \
  docs/status docs/architecture docs/adr docs/design api/openapi AGENTS.md
```

Expected: exit `1` with no matches.

- [ ] **Step 3: Verify the clean final tree and commit history**

Run:

```bash
git status --short
git log --oneline --decorate -20
```

Expected: no status output; the log contains small, reviewable commits aligned to detailed-plan task boundaries.

- [ ] **Step 4: Hand off the production system**

Provide links to `docs/status/current.md`, the V4 blueprint, active ADRs, frontend specification, OpenAPI, production readiness evidence, operating ownership, SLO dashboards, rollback/DR runbooks, and the exact accepted release commit. Capabilities that did not pass their individual gate remain explicitly closed and must not be described as production behavior.
