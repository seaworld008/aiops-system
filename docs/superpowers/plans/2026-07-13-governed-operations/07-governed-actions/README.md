# 07 — Governed Production Actions 阶段索引

本阶段在 Phase 1–6 的生产只读验收之后，逐 Action 类型打开受治理生产变更。它不是通用写代理，也不是模型、聊天界面或浏览器获得目标系统权限；唯一生产路径固定为：

```text
Accepted Evidence / append-only PROPOSAL_ONLY ActionProposal
  → explicit authenticated human request through full T/W/E/S Scope
  → same-transaction trusted Handoff reload and immutable ActionPlan seal
  → exact ActionPlan hash
  → current policy + live Kill Switch evaluation
  → plan-bound recent OIDC authentication
  → distinct human approval
  → one Action / one Asset / one Attempt WRITE credential
  → mTLS WRITE Realm claim + fenced admission
  → typed non-interactive mutation
  → independent post-action verification
  → Receipt / Audit
  → reconcile / safe rollback / human escalation when uncertain
```

任何 plan、target、Asset Snapshot、Runtime、Policy、Kill Switch、Approval、Realm 或 Credential 绑定漂移都会停止执行。执行结果不确定时绝不盲重试副作用。

## Entry Criteria

Phase 7 只能在以下 Phase 1–6 验收证据均存在时开始：

- Asset Catalog 的 exact scoped Asset/Revision 和隔离/漂移语义；
- immutable Connection/Target/Capability/Runtime Publication 和 Runner Realm；
- VictoriaMetrics、Host、PostgreSQL 的 typed READ Evidence；
- Asset Snapshot、InvestigationGrant、六级 Kill Switch、Evidence 和无授权能力的 append-only `PROPOSAL_ONLY` ActionProposal；
- 真实 OIDC、PostgreSQL、Temporal、Vault/Issuer、PKI、Gateway、READ/Validation Runner 的 HA 生产装配；
- Phase 6 decision 为 `APPROVE_PRODUCTION_READ_ONLY`，且生产 WRITE claim 仍关闭。
- Phase 6 immutable handoff ID/digest、READ baseline digest and live READ admission are current；Phase 7 must publish a separately content-addressed Action platform successor before any production queue claim。

已有 `internal/action`、`internal/policy`、`internal/execution`、`internal/credential`、`internal/runnergateway` 和 `cmd/write-runner` 是安全基线。`000008` 中的 production-WRITE 数据库关闭约束必须一直保留，直到本阶段的 `000021` 用逐 Action gate、exact binding 和负向测试替代；不能先删除再补控制。

## Initial Reviewed Action Types

| Action type | Fixed mutation | Independent verification | Safe compensation |
|---|---|---|---|
| `K8S_ROLLOUT_RESTART` | exact Deployment UID/resourceVersion 的 restart annotation patch | rollout generation/updated/available/readiness | `MANUAL_ONLY` |
| `K8S_SCALE` | exact Deployment scale subresource to signed replicas | observed generation + desired/available replicas | exact no-intervening-change 时恢复 original replicas |
| `GITOPS_REVERT` | exact repository/application/path/head 的 revert change request | merged commit/tree + Argo desired/live/health | new reviewed ActionPlan only |
| `AWX_SERVICE_RESTART` | exact Inventory snapshot、Host IDs、Job Template revision，serial=1 | AWX job receipt + independent service health | `MANUAL_ONLY` |

以下类型保持 `UNSUPPORTED`：任意 shell/command/argv/env、SQL/DDL/DML、通用 HTTP endpoint/payload/header、任意或其他 Host 写（上表固定 `AWX_SERVICE_RESTART` 是唯一已审查例外）、DB/Network/DNS/Cloud/Secret 写、交互 SSH/WinRM、PTY、port forwarding、SFTP、observability ingestion。未来开放任一类型前必须先增加独立 ADR、typed contract、credential scope、verification/compensation 语义和负向套件，再修改本阶段计划。

## Fixed Package Order

| Order | Task package | Outcome | Depends on |
|---:|---|---|---|
| 1 | [01-action-catalog-schema.md](./01-action-catalog-schema.md) | `000021`、fixed Action catalog、immutable ActionPlan V2/bindings/gates | Phase 1–6 |
| 2 | [02-policy-approval-reauth.md](./02-policy-approval-reauth.md) | multi-boundary policy、plan-bound recent auth、normalized approvals | 01 |
| 3 | [03-write-credentials-runner.md](./03-write-credentials-runner.md) | isolated WRITE Realm/issuer、single-attempt credential、fenced typed Runner | 01–02 |
| 4 | [04-verification-reconciliation-rollback.md](./04-verification-reconciliation-rollback.md) | independent verification、uncertain reconciliation、safe rollback、Receipt | 01–03 |
| 5 | [05-incident-audit-workspace.md](./05-incident-audit-workspace.md) | scoped Incident/Investigation/Evidence/Audit API and high-fidelity upstream workspace | 01–04 |
| 6 | [06-api-web-operator-journey.md](./06-api-web-operator-journey.md) | safe Action API and evidence-first operator journey | 01–05 |
| 7 | [07-e2e-security-drills.md](./07-e2e-security-drills.md) | real-protocol E2E/security drills、per-Type canary gate、ADR/runbooks/status | 01–06 |

后一包只消费前一包 `Interfaces / Produces`。Package 3 和 4 不得通过前端/API 才能维持安全；浏览器只是 Control Plane 客户端。

## Cross-package Invariants

- ActionPlan V2 canonical hash binds Tenant/Workspace/Environment/Service/Incident、Action Definition revision、Asset/Revision、Asset Snapshot digest、exact target digest、Runtime Publication/Bundle digest、Policy version/digest、Kill Switch revision/digest、Evidence digest、typed parameters、verification、compensation and credential scope。
- The same Plan/Authorization Bundle/Attempt/Verification/Receipt binds Phase 6 handoff、immutable READ baseline、current READ admission snapshot and exact ACCEPTED Action platform successor/manifest；queue、claim、admission、credential issue、pre-mutation、verification and every new READ admission revalidate the dual revision closure。
- Proposal is not executable. Seal、policy decision、reauth proof、approval set、attempt、verification、rollback and receipt are separate immutable/durable records。
- Requester cannot approve their own production Action. HIGH risk requires two distinct qualified approvers; LOW/MEDIUM requires one distinct qualified approver. Every approval uses recent OIDC authentication no older than 5 minutes and expires after 10 minutes or with the plan, whichever is earlier.
- Policy and Kill Switch are re-evaluated at plan submission、approval completion、queue submit、claim、start/admission、credential issue、immediately before mutation and post-action verification。
- READ/VALIDATION/WRITE roots、issuer profiles、Realm、queue tables/protocols and credentials do not interoperate. WRITE Runner receives no READ Grant and cannot claim READ/Validation work。
- Production WRITE credential TTL is at most 5 minutes, cannot renew, and is bound to one Action ID、Asset ID、Attempt、lease epoch、typed permission and exact resource. Credential cleanup is durable and required before any terminal success。
- Duplicate request/claim/start/complete uses Idempotency-Key + semantic hash + fencing. Same semantic request returns original state; mismatch conflicts; stale lease never mutates or finalizes。
- Executor output is not verification. Independent trusted readers determine post-state. `UNKNOWN` stops, revokes, reconciles facts, performs only pre-authorized safe compensation, otherwise opens human escalation。
- No production assembly may use memory repositories, fake identity/issuer/adapter, MSW or test endpoint. Test fixtures remain test-only。
- Frontend only renders server `effective_actions`, uses structured evidence/diff/timeline, and never exposes a chat composer, terminal, arbitrary JSON editor or “AI autonomously changed” language。

## Per-Action Release Gate

Every Action type starts `CLOSED` and advances independently:

```text
CLOSED
  → NON_PRODUCTION_READY
  → DRILLING
  → CANARY_APPROVED
  → CANARY_RUNNING
  → AVAILABLE
```

Promotion requires at least 20 non-production positive drills, at least 19 independently verified successes (>=95%), and zero unauthorized or duplicate mutations across positive and adversarial runs. Then one supervised production canary requires an operator, recent auth, approval, exact maintenance window, live dashboards and rollback/escalation owner. A failure returns only the affected type to `CLOSED` or `SUSPENDED`; other types do not inherit acceptance.

## Phase Exit Evidence

Phase 7 is accepted only when:

- real PostgreSQL migration and rollback guard pass;
- Go unit/integration/race/vet/build and generated OpenAPI/Web checks pass;
- real mTLS WRITE Runner, issuer/revoker and every adapter run without fake/in-memory production fallback;
- accepted Action platform successor exactly references the Phase 6 handoff/READ baseline, preserves all READ-owned digests, and its observed WRITE surface equals the registered Action manifest with no extra or missing member;
- every initial Action type has its own drill ledger, verification ratio, zero unauthorized/duplicate evidence and supervised canary decision;
- plan drift、approval expiry、Kill Switch、duplicate claim、Runner crash、credential uncertainty、mutation uncertainty and verification failure all prove stop/revoke/reconcile/rollback-or-escalate;
- browser journey shows evidence、diff、plan hash、policy、approval、reauth、live execution、verification and final Receipt without secret or raw target response;
- ADR、frontend specification、runbooks、SLO/alert and `docs/status/current.md` are updated with real evidence。

## Execution Tracking

| Package | Status | Evidence commit |
|---|---|---|
| 01 | NOT_STARTED | — |
| 02 | NOT_STARTED | — |
| 03 | NOT_STARTED | — |
| 04 | NOT_STARTED | — |
| 05 Incident/Audit | NOT_STARTED | — |
| 06 Action API/Web | NOT_STARTED | — |
| 07 E2E/Drills | NOT_STARTED | — |

Execute each task package with `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans`. Do not mark a package complete from code inspection alone; run every named command and persist evidence at its commit boundary.
