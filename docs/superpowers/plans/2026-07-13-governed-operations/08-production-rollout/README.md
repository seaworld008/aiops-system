# Phase 8: Production Rollout and Sustained Operations

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 把已通过只读生产门与逐 Action 类型写入门的系统，落成可容量规划、可灰度、可回退、可灾备、可审计、有人值守的生产服务，并以持久化的 `PRODUCTION_CLOSED_LOOP_ACCEPTED` 或安全的 HOLD/ROLL_BACK 决策收口。

**Architecture:** Phase 8 消费 Phase 6 的 `000020`/ADR 0009/只读平台与 Phase 7 的 `000021`/逐类型 Action gates，在 `000022_production_release_governance` 中持久化复合 Scope 的 release、wave、evidence、wave decision 与最终 acceptance decision。它只在原路径上 harden Phase 6 Chart 和 Phase 7 WRITE 增量，使用真实多副本基础设施、容量/故障/恢复/安全证据与固定 rollout waves 驱动显式决策；PostgreSQL 仍是领域事实源，Temporal 只编排，浏览器只呈现服务端投影。

**Tech Stack:** Go 1.26.5、PostgreSQL 18.4+、Temporal、Keycloak Server 26.6.3/keycloak-js 26.2.4、Vault/PKI、Kubernetes 1.36.2、Helm 3、OpenAPI 3.1、React 19.2.7/TanStack、pnpm 10.34.0、Playwright/axe、OpenTelemetry、Prometheus/VictoriaMetrics/VictoriaLogs/VictoriaTraces、k6、Chaos Mesh、Cosign/Syft/Grype、S3-compatible immutable evidence storage。

## Global Constraints

- 状态为规划完成、尚未执行；实现基线固定为 `main@ad50d9f`，执行时先验收 Phase 1–7 的实际产物与证据。
- migration 固定为 `000022_production_release_governance`；不得改写 `000020_production_platform` 或 `000021_governed_actions`。
- 所有 release/wave/evidence/decision 主键、唯一键和外键携带 `tenant_id/workspace_id/environment_id`；不能以单一 synthetic Scope ID 替代。
- ADR 0009 继续拥有生产 READ 平台决策；ADR 0012 只拥有 release governance 与持续运维，不能重写 0009 或 Phase 7 的 ADR 0010/0011。
- Kubernetes 版本唯一固定为 `1.36.2`；Helm render、kubeconform、Kind、生产等价集群与正式集群使用相同 API 基线。
- Phase 6 创建基础 Chart；Phase 7 只增加 WRITE Runner、WRITE NetworkPolicy 和 Action Worker；Phase 8 原路径 Modify/harden，任何新文件必须明确 `Create`。
- Phase 8 不创建第二个 chart、第二份 OpenAPI、第二个 generated TypeScript 文件、第二套身份根或替代性 production stack。
- AWX-enabled release 必须消费 Phase 5 唯一 `deploy/awx/governed-admission/` bundle，并把 AWX 24.6.1 governed image、HA EnrollmentCleanupBroker/L7 gateway、Vault 2.0.3 KV/Transit、authority keyring 和 host-attestor evidence 纳入同一 release manifest；不得恢复 stock launch、单副本 Broker 或平行部署事实源。
- Phase 6 的 `test/production/` 与 `test/recovery/` 脚本是底层机制测试；Phase 8 新建 `scripts/` 只做 release-level orchestration 并复用这些机制。
- 最终 acceptance 必须进入 append-only `production_release_acceptance_decisions`；状态文档、Git tag、CI 成功或人工口头确认都不能替代。
- 页面可用或单次 Canary 成功不构成上线完成；完整闭环必须同时证明成功与不确定结果路径。

## Entry Gate

- Phase 6 已签署 `APPROVE_PRODUCTION_READ_ONLY`，其 HA、SLO、备份恢复、生产 Shadow/READ_ONLY 证据仍有效。
- Phase 7 release eligible manifest 中列出的每个固定 Kubernetes、GitOps 或 AWX Action 类型都已通过各自非生产演练和 supervised production canary，且至少包含一个 Action 类型以证明写闭环；未通过的类型必须从该 manifest 排除并继续保持 `UNAVAILABLE`。
- 生产身份、Vault/PKI、PostgreSQL、Temporal、审计存储、Runner Realm 和 Kill Switch 均有明确 owner 与告警接收人。
- 不存在通用 shell、SQL、endpoint、payload、交互终端或浏览器 Secret 通道。

## Task-pack Order

1. [Release governance schema and gates](01-release-schema-gates.md)
2. [Helm, HA, and production infrastructure](02-helm-ha-infrastructure.md)
3. [Capacity, load, chaos, and disaster recovery](03-capacity-chaos-dr.md)
4. [Security, identity, supply chain, and compliance](04-security-compliance.md)
5. [Staged rollout, SLOs, and automated stop decisions](05-staged-rollout-slos.md)
6. [Ownership, runbooks, final E2E, and durable handoff](06-ownership-runbooks-final-e2e.md)

Task packs are cumulative. Each task is implemented through its Red/Green/Refactor loop and committed before the next task starts.

## Interfaces

**Consumes**

- Phase 1 authoritative assets, scopes, mappings, lifecycle, OpenAPI and frontend shell.
- Phase 2 immutable connection/runtime publications, credential references, Runner Realms and validation protocol.
- Phase 3 typed VictoriaMetrics, VictoriaLogs and VictoriaTraces read capabilities and Evidence schemas.
- Phase 4 immutable snapshots, Grants, budgets, proactive policies and six-level Kill Switch.
- Phase 5 host/PostgreSQL fixed diagnostics, DLP and durable READ-credential cleanup.
- Phase 6 production read assembly, baseline SLOs, HA/DR evidence and read-only Go/No-Go record.
- Phase 7 individually gated Action catalog, approval-bound WRITE execution, verification, reconciliation, rollback and escalation.

**Produces**

- Migration `000022_production_release_governance` and durable release/wave/evidence/decision records.
- `deploy/helm/aiops/` production chart with multi-replica process separation, NetworkPolicies, workload identity and fail-closed configuration.
- Repeatable capacity, load, dependency-failure, chaos, backup/restore, regional recovery and credential-cleanup evidence.
- Security hardening, SBOM/provenance, image policy, access review, audit retention and incident response controls.
- SLO-gated rollout from internal operators to full eligible scope, with automated halt and explicit rollback authority.
- `docs/operations/production/`, `docs/security/production-readiness.md`, V4 architecture/status/ADR/frontend/OpenAPI handoff and on-call ownership.

## Cross-Phase Ownership Law

Ownership is path-based, not intent-based. A later phase cannot silently replace a file with a synonym, move a workload to another template, or create a parallel script with the same responsibility.

- `Create` means the path does not exist in an accepted earlier phase and this task owns its first durable contract.
- `Modify` means the exact path already exists in the repository or an accepted earlier phase.
- `Verify` means the path is consumed unchanged and must be checked by the task's tests or commands.
- A rename requires a dedicated migration task、compatibility plan and ownership-test update；none is authorized in Phase 8.
- Phase 8 may add release-only files, but it cannot recreate Phase 6 read or Phase 7 write implementation under a new name.
- Commit commands include only files declared by the current Task plus generated output from a declared source.
- CI tests compare this registry with Task `Files:` blocks and reject duplicate Create、unknown Modify and undeclared command inputs.

### Helm Path Registry

| Exact path | Created by | Phase 8 operation | Purpose |
|---|---|---|---|
| `deploy/helm/aiops/Chart.yaml` | Phase 6; Phase 7 bumps version for WRITE increment | Modify | chart metadata/version |
| `deploy/helm/aiops/values.yaml` | Phase 6; Phase 7 adds WRITE values | Modify | safe defaults and references |
| `deploy/helm/aiops/values.schema.json` | Phase 6; Phase 7 adds closed WRITE branches | Modify | closed production values contract |
| `deploy/images.lock` | Phase 6; Phase 7 adds accepted WRITE/Action image digests | Verify | complete image closure for the release digest |
| `deploy/helm/aiops/chart_contract_test.go` | Phase 6; Phase 7 adds registered WRITE paths | Modify | exact chart path/render allowlist |
| `deploy/helm/aiops/action-surface-manifest.yaml` | Phase 7 | Verify | exact accepted WRITE resource/path/identity manifest |
| `deploy/helm/aiops/templates/_helpers.tpl` | Phase 6 | Modify | stable names/labels/selectors |
| `deploy/helm/aiops/templates/config.yaml` | Phase 6 | Modify | role-safe non-secret configuration |
| `deploy/helm/aiops/templates/control-plane.yaml` | Phase 6 | Modify | Control Plane deployment |
| `deploy/helm/aiops/templates/control-worker.yaml` | Phase 6 | Modify | Control Worker deployment |
| `deploy/helm/aiops/templates/outbox-dispatcher.yaml` | Phase 6 | Modify | Outbox Dispatcher deployment |
| `deploy/helm/aiops/templates/scheduler.yaml` | Phase 6 | Modify | Scheduler deployment |
| `deploy/helm/aiops/templates/discovery-worker.yaml` | Phase 6 | Modify | fenced source-discovery deployment |
| `deploy/helm/aiops/templates/runner-gateway.yaml` | Phase 6 | Modify | Runner Gateway deployment/service target |
| `deploy/helm/aiops/templates/validation-runner.yaml` | Phase 6 | Modify | Validation Runner deployment |
| `deploy/helm/aiops/templates/read-runner.yaml` | Phase 6 | Modify | READ Runner deployment |
| `deploy/helm/aiops/templates/services.yaml` | Phase 6 | Modify | Control Plane/Gateway services |
| `deploy/helm/aiops/templates/pdb.yaml` | Phase 6; Phase 7 adds WRITE/Action budgets | Modify | all workload disruption budgets |
| `deploy/helm/aiops/templates/hpa.yaml` | Phase 6; Phase 7 adds WRITE/Action scaling | Modify | bounded autoscaling policies |
| `deploy/helm/aiops/templates/serviceaccounts.yaml` | Phase 6; Phase 7 adds WRITE/Action identities | Modify | distinct workload identities |
| `deploy/helm/aiops/templates/networkpolicy.yaml` | Phase 6; Phase 7 adds manifest-bound WRITE/Action rules | Modify | base default-deny/read plus exact accepted additions |
| `deploy/helm/aiops/templates/networkpolicy_test.go` | Phase 6 | Modify | manifest-aware policy render tests |
| `deploy/helm/aiops/templates/recovery-job.yaml` | Phase 6 | Modify | disabled-by-default recovery job |
| `deploy/helm/aiops/templates/recovery-job_test.go` | Phase 6 | Modify | recovery job safety/render tests |
| `deploy/helm/aiops/templates/write-runner-deployment.yaml` | Phase 7 | Modify | gated WRITE Runner deployment |
| `deploy/helm/aiops/templates/write-runner-networkpolicy.yaml` | Phase 7 | Modify | exact WRITE egress policy |
| `deploy/helm/aiops/templates/action-workers-deployment.yaml` | Phase 7 | Modify | Action Worker deployment |
| `deploy/helm/aiops/README.md` | Phase 8 | Create | production chart operations contract |
| `deploy/helm/aiops/templates/NOTES.txt` | Phase 8 | Create | safe post-render instructions |
| `deploy/helm/aiops/templates/podmonitors.yaml` | Phase 8 | Create | scrape declarations without secret labels |
| `deploy/helm/aiops/tests/values_contract_test.yaml` | Phase 8 | Create | closed values tests |
| `deploy/helm/aiops/tests/network_policy_test.yaml` | Phase 8 | Create | policy matrix tests |
| `deploy/helm/aiops/tests/identity_separation_test.yaml` | Phase 8 | Create | ServiceAccount isolation tests |
| `deploy/helm/aiops/tests/fixtures/production-values.yaml` | Phase 8 Task 1 | Create then Verify | deterministic production fixture |
| `deploy/helm/aiops/tests/golden/production-manifests.yaml` | Phase 8 | Create | reviewed deterministic render |

Alternate deployment/configuration names or pluralized PDB/HPA/NetworkPolicy template aliases are forbidden. A test derives the accepted path set from this registry and fails on every unregistered Helm template.

### Script and Test-Stack Registry

| Exact path | Ownership | Phase 8 use |
|---|---|---|
| `test/production/up.sh` | Phase 6 Create | Verify and reuse for production-equivalent stack |
| `test/production/down.sh` | Phase 6 Create | Verify cleanup/idempotency |
| `test/production/wait-ready.sh` | Phase 6 Create | Verify dependency/readiness semantics |
| `test/production/verify-all.sh` | Phase 6 Create | Execute in final audit |
| `test/production/bootstrap-keycloak.sh` | Phase 6 Create | Verify Keycloak Server 26.6.3 bootstrap/revocation |
| `test/production/bootstrap-vault.sh` | Phase 6 Create | Verify Vault auth/PKI bootstrap/revocation |
| `test/production/images.lock` | Phase 6 Create; Phase 7 WRITE-only Modify | Verify exact equality with `deploy/images.lock` |
| `test/production/pilot/start-preview.sh` | Phase 6 Create | Preserve accepted READ pilot proof |
| `test/production/pilot/start-nonproduction-readonly.sh` | Phase 6 Create | Preserve nonproduction READ proof |
| `test/production/pilot/start-production-shadow.sh` | Phase 6 Create | Preserve production Shadow proof |
| `test/production/pilot/start-supervised-readonly.sh` | Phase 6 Create | Preserve supervised READ proof |
| `test/production/pilot/collect-gates.sh` | Phase 6 Create | Verify Phase 6 handoff gates |
| `test/production/pilot/decide.sh` | Phase 6 Create | Verify ADR 0009 decision digest |
| `test/recovery/verify-rpo-rto.sh` | Phase 6 Create | Reuse fixed RPO/RTO mechanism |
| `test/recovery/verify-corrupt-backup.sh` | Phase 6 Create | Reuse corruption denial test |
| `test/recovery/verify-lost-wal.sh` | Phase 6 Create | Reuse missing-WAL denial test |
| `test/recovery/verify-kms-vault-outage.sh` | Phase 6 Create | Reuse recovery dependency failure test |
| `test/recovery/verify-cleanroom.sh` | Phase 6 Create | Reuse clean-room mechanism |
| `test/recovery/run-all.sh` | Phase 6 Create | Execute in final Phase 8 audit |
| `scripts/verify-production-chart.sh` | Phase 8 Create | release-level chart verification |
| `scripts/run-production-load.sh` | Phase 8 Create | bounded capacity run orchestration |
| `scripts/backup/verify-postgres-backup.sh` | Phase 8 Create | release-level backup selection/verification |
| `scripts/backup/restore-clean-room.sh` | Phase 8 Create | release-level clean-room orchestration |
| `scripts/security/verify-release-artifacts.sh` | Phase 8 Create | provenance/SBOM/signature gate |
| `scripts/security/verify-image-policy.sh` | Phase 8 Create | cluster image admission gate |

Phase 8 backup scripts call Phase 6 recovery mechanisms and production APIs；they do not contain a second backup driver, arbitrary restore command, embedded DSN, credential or direct status update. All scripts use bounded deadlines, cleanup traps, safe structured output and non-production destination guards.

The directory distinction is deliberate and tested: singular `test/production` and `test/recovery` are Phase 6 reusable infrastructure/drill mechanisms that Phase 8 only verifies or invokes；plural `tests/load`、`tests/chaos`、`tests/recovery`、`tests/security`、`tests/production` and `tests/documentation` are new Phase 8 release-verification suites. No file may be mirrored across the two trees under an alternate name.

The Phase 6 READ baseline remains immutable. Phase 7 chart changes are a separately content-addressed successor bound to an accepted Action manifest, and Phase 8 release candidates bind both digests. `UNAUTHORIZED_WRITE_SURFACE_ABSENT` means the observed WRITE surface exactly equals that accepted manifest；it does not require a valid Phase 7/8 deployment to erase all registered WRITE resources. Candidate creation and every wave/final decision require the gate to be current PASS together with open READ admission；candidate-time evidence is never a permanent bypass.

### Migration and ADR Registry

| Artifact | Owner | Phase 8 rule |
|---|---|---|
| `migrations/000020_production_platform.up.sql` | Phase 6 | Verify unchanged and accepted |
| `migrations/000020_production_platform.down.sql` | Phase 6 | Verify guarded rollback remains intact |
| `docs/adr/0009-production-read-platform.md` | Phase 6 | Verify active; never rewrite READ approval as WRITE approval |
| `migrations/000021_governed_actions.up.sql` | Phase 7 | Verify individually accepted Action gates |
| `migrations/000021_governed_actions.down.sql` | Phase 7 | Verify production WRITE down guard |
| `production_action_platform_revisions` relation | Phase 7 migration `000021` | Bind accepted successor to the immutable Phase 6 platform/rollout/decision/handoff tuple |
| `docs/adr/0010-governed-production-action-gates.md` | Phase 7 | Verify typed write gates |
| `docs/adr/0011-verification-reconciliation-rollback.md` | Phase 7 | Verify uncertain-result policy |
| `migrations/000022_production_release_governance.up.sql` | Phase 8 | Create composite-Scope release schema |
| `migrations/000022_production_release_governance.down.sql` | Phase 8 | Create guarded reverse-order down migration |
| `docs/adr/0012-production-release-governance.md` | Phase 8 | Create release/wave/final-acceptance decision record |

`000022` refuses to apply without the required `000020` platform/read decision/handoff relation and the `000021` `production_action_platform_revisions` plus Action-type gate relations；schema installation does not require environment-specific accepted rows. Every release candidate then carries composite FKs to an immutable accepted Phase 6 approval/handoff and accepted/current Phase 7 successor；a transaction-local trigger proves both describe the same READ baseline and Action manifest. It never copies their authority into JSON only：normalized relations and composite foreign keys preserve exact accepted revisions.

### Documentation Registry

| Path family | Owner/action | Contract |
|---|---|---|
| `docs/operations/production-read/` | Phase 6 Create; Phase 8 Verify | read-platform deployment/failure/recovery truth |
| `docs/status/production-readiness.md` | Phase 6 Create; Phase 8 Verify | accepted read decision and evidence digests |
| `docs/design/frontend/production-read-platform.md` | Phase 6 Create; Phase 8 Verify | read platform page/interaction baseline |
| `docs/operations/governed-actions/` | Phase 7 Create; Phase 8 Verify | per-provider write and uncertainty runbooks |
| `docs/design/frontend/governed-actions.md` | Phase 7 Create; Phase 8 Verify | Action operator workflow baseline |
| `docs/design/frontend/production-release-command-center.md` | Phase 8 Create | release list/detail, gates, waves, eligibility and reauthenticated decision UX |
| `docs/operations/production/README.md` | Phase 8 Create | final operations index |
| `docs/operations/production/ownership.md` | Phase 8 Create | service/data/security owners |
| `docs/operations/production/on-call.md` | Phase 8 Create | escalation and rotation contract |
| `docs/operations/production/kill-switch.md` | Phase 8 Create | cross-plane stop orchestration linking Phase 6 |
| `docs/operations/production/credential-cleanup.md` | Phase 8 Create | READ/WRITE cleanup escalation |
| `docs/operations/production/runner-realm.md` | Phase 8 Create | Realm identity/network operations |
| `docs/operations/production/policy-and-approval.md` | Phase 8 Create | policy/recent-auth/separation rules |
| `docs/operations/production/uncertain-action.md` | Phase 8 Create | reconcile/rollback/escalate path |
| `docs/operations/production/audit-and-outbox.md` | Phase 8 Create | gap detection and replay rules |
| `docs/operations/production/release-hold-rollback.md` | Phase 8 Create | wave hold/rollback procedure |
| `docs/operations/production/capacity-envelope.md` | Phase 8 Create | approved load/headroom |
| `docs/operations/production/chaos-game-day.md` | Phase 8 Create | bounded experiment process |
| `docs/operations/production/backup-restore.md` | Phase 8 Create | release-level recovery order |
| `docs/operations/production/zone-and-region-recovery.md` | Phase 8 Create | fence/promotion/failback |
| `docs/operations/production/security-incident-response.md` | Phase 8 Create | security containment |
| `docs/operations/production/credential-compromise.md` | Phase 8 Create | revoke/rotate/evidence handling |
| `docs/operations/production/audit-gap-response.md` | Phase 8 Create | admission closure and repair |
| `docs/operations/production/slo-catalog.md` | Phase 8 Create | final SLI/SLO ownership |
| `docs/operations/production/staged-rollout.md` | Phase 8 Create | fixed wave procedure |
| `docs/operations/production/closed-loop-test.md` | Phase 8 Create | success/uncertain full-path proof |
| `docs/operations/production/final-release-checklist.md` | Phase 8 Create | signed acceptance checklist |
| `docs/operations/production/post-release-review.md` | Phase 8 Create | sustained review cadence |
| `docs/operations/production/data-classification.md` | Phase 8 Create | source-of-truth/encryption/retention classification |
| `docs/operations/production/runbook.schema.json` | Phase 8 Create | closed runbook metadata contract |
| `docs/operations/production/release-decision-record.schema.json` | Phase 8 Create | wave decision record contract |
| `docs/operations/production/recovery-evidence.schema.json` | Phase 8 Create | recovery evidence contract |
| `docs/operations/production/closed-loop-acceptance.schema.json` | Phase 8 Create | final acceptance artifact contract |
| `docs/security/threat-model-v4.md` | Phase 8 Create | threat/control mapping |
| `docs/security/production-readiness.md` | Phase 8 Create | security gate summary |
| `docs/security/identity-and-access.md` | Phase 8 Create | access lifecycle/review |
| `docs/security/security-invariants.yaml` | Phase 8 Create | machine-checked invariant catalog |
| `docs/security/production-signoff.schema.json` | Phase 8 Create | independent security signoff contract |
| `docs/security/retention-policy.schema.json` | Phase 8 Create | closed retention-policy schema |
| `docs/security/production-retention-policy.json` | Phase 8 Create | reviewed production retention instance |
| `docs/architecture/v4/README.md` | Phase 8 Create | bounded architecture index |
| `docs/architecture/v4/trust-and-identity.md` | Phase 8 Create | trust/identity boundaries |
| `docs/architecture/v4/assets-connections-runtime.md` | Phase 8 Create | asset/connection/runtime flow |
| `docs/architecture/v4/investigation-and-evidence.md` | Phase 8 Create | investigation/evidence flow |
| `docs/architecture/v4/actions-verification-recovery.md` | Phase 8 Create | action/verification/recovery flow |
| `docs/architecture/v4/production-platform.md` | Phase 8 Create | production topology and release model |
| `docs/architecture/implementation-blueprint-v4.md` | Prior phase Create; Phase 8 Modify | concise authoritative V4 index |
| `docs/status/current.md` | Prior phase Create; Phase 8 sequential Modify | rollout truth then final accepted truth |
| `docs/README.md` | Prior phase Create; Phase 8 Modify | normative entry-point map |
| `docs/adr/0001-operational-asset-catalog-overlay.md` | Phase 1 Create; Phase 8 Verify | preserve asset overlay decision |
| `docs/adr/0002-connection-compilation-publication.md` | Phase 2 Create; Phase 8 Verify | preserve connection publication decision |
| `docs/adr/0003-victoria-ecosystem-read-boundary.md` | Phase 3 Create; Phase 8 Verify | preserve Victoria READ boundary |
| `docs/adr/0004-investigation-grants-and-live-kill-switches.md` | Phase 4 Create; Phase 8 Verify | preserve grant/Kill Switch decision |
| `docs/adr/0005-remote-diagnostic-boundary.md` | Phase 5 Create; Phase 8 Verify | preserve remote diagnostic boundary |
| `docs/adr/0006-postgresql-named-read-diagnostics.md` | Phase 5 Create; Phase 8 Verify | preserve named diagnostic decision |
| `docs/adr/0007-read-write-credential-isolation.md` | Phase 5 Create; Phase 8 Verify | preserve credential isolation |
| `docs/adr/0008-evidence-and-dlp.md` | Phase 5 Create; Phase 8 Verify | preserve evidence/DLP decision |
| `docs/design/frontend/README.md` | Phase 8 Create | master frontend index |
| `docs/design/frontend/information-architecture.md` | Phase 8 Create | navigation/routes/scope |
| `docs/design/frontend/visual-system.md` | Phase 8 Create | low-AI enterprise tokens |
| `docs/design/frontend/interaction-and-state.md` | Phase 8 Create | decision/loading/error/stale behavior |
| `docs/design/frontend/accessibility-responsive.md` | Phase 8 Create | WCAG/responsive contract |
| `docs/design/frontend/page-inventory.md` | Phase 8 Create | complete page ownership |

The Phase 8 production documents compose and link earlier bounded runbooks；they do not delete or silently supersede Phase 6/7 evidence. The V4 index records `INHERITED|REPLACED|RETIRED` explicitly for every older normative section.

## Production Component Baseline

| Component | Minimum replicas | Phase owner | Durable coordination |
|---|---:|---|---|
| Control Plane | 3 | Phase 6 | PostgreSQL idempotency |
| Control Worker | 3 | Phase 6 | Temporal task queues/versioning |
| Outbox Dispatcher | 2 | Phase 6 | PostgreSQL claim/fence |
| Scheduler | 2 | Phase 6 | Temporal Schedule + DB revision |
| Discovery Worker | 2 | Phase 6 | PostgreSQL source-run lease/fence + durable cursor |
| Runner Gateway | 3 | Phase 6 | PostgreSQL Grant/task/fence transaction |
| Validation Runner | 2 per Realm | Phase 6 | Gateway claim/identity fence |
| READ Runner | 2 per Realm/family | Phase 6 | Gateway claim/identity fence |
| Action Worker | 2 when enabled | Phase 7 | Temporal + PostgreSQL Action state |
| WRITE Runner | 2 per accepted Realm | Phase 7 | Gateway claim/attempt/fence |

Phase 8 changes replica/resources/topology only inside the accepted capacity envelope and chart schema. It cannot merge roles, share ServiceAccounts, combine READ/WRITE queues, enable an unavailable Action type or bypass the Phase 6 admission handoff.

## Release Persistence Contract

`000022` owns these normalized facts:

- immutable release candidates bound to exact platform、read decision、Action gate、chart、image、schema、policy and runtime revisions;
- normalized eligible assets/capabilities/actions with composite Scope FKs;
- fixed ordered rollout waves and content-addressed memberships;
- append-only typed gate requirements and observations;
- wave-scoped `PROMOTE|HOLD|ROLL_BACK` decisions;
- release-scoped `HOLD|ROLL_BACK|PRODUCTION_CLOSED_LOOP_ACCEPTED` acceptance decisions;
- transactional transition outbox records;
- signed final evidence-set and signer-set digests.

The final decision is not a wave decision. `PRODUCTION_CLOSED_LOOP_ACCEPTED` requires the full eligible wave, all final gates, complete healthy soak, success/uncertain E2E, RPO/RTO, security sign-off and independent signer set. A failure or unknown produces HOLD/ROLL_BACK and keeps acceptance absent.

## Gate Classes

| Class | Examples | Unknown behavior |
|---|---|---|
| platform input | Phase 6 decision, Phase 7 Action gates, migration/schema digests | HOLD |
| availability | Control/Gateway/Runner SLO, dependency health | HOLD and scoped stop |
| authorization | denied unauthorized mutation, self-approval, stale policy | HOLD and incident |
| identity/network | Keycloak, PKI, ServiceAccount, Realm, NetworkPolicy | HOLD and revoke |
| credential | issuance scope, TTL, cleanup, post-grace usability | HOLD and Kill Switch |
| execution | duplicate effect, fence, idempotency, one-send ledger | ROLL_BACK or HUMAN_REQUIRED |
| verification | independent post-state, UNKNOWN reconciliation | HOLD; never blind retry |
| evidence/audit | artifact digest, Receipt, outbox/audit delivery | HOLD |
| capacity | headroom, saturation, queue/claim latency | HOLD |
| recovery | backup age, clean-room RPO/RTO, DR fence | HOLD |
| security/compliance | DLP, provenance, vulnerabilities, access review | HOLD |
| rollout | membership, soak, signer separation, no open incident | HOLD |

All gate observations are append-only and freshness-bounded. Automated controllers may create a HOLD and activate the narrowest Kill Switch；only independently authorized humans may promote or persist final acceptance.

## Frontend Release Contract

- The release command center uses the single generated `web/src/shared/api/schema.d.ts` contract.
- Routes preserve Workspace/Environment plus release/wave/filter state in the URL；Tenant is derived exclusively from the verified OIDC/server context and any tenant query/body injection is rejected and audited.
- `effective_actions` exclusively controls decision visibility and enabled state.
- The browser cannot derive gate PASS, membership, eligibility, signer separation or final acceptance.
- Reauthentication proof remains in memory and is discarded after one decision attempt.
- A stale version or evidence digest forces reload；there is no automatic resubmit against new facts.
- READ capabilities and each Action type appear in separate eligibility groups.
- HOLD、ROLL_BACK and acceptance consequences are explicit before confirmation.
- Missing telemetry is shown as UNKNOWN, never a green empty chart.
- Timeline rows remain append-only and link safe evidence digests.
- Desktop、tablet and mobile inspection are supported；production promotion follows the approved operator-device policy.
- Keyboard、focus、reduced motion and WCAG 2.2 AA behavior are acceptance gates.
- The visual system remains navy/light/dense with restrained blue actions、4–6px radii and 1px borders.
- Chat、avatar、neon、glow、gradient、glass、bento decoration、terminal and arbitrary JSON editing remain absent.

## Phase 8 Execution Invariants

- Execute task packs in listed order and Tasks in numeric order.
- Every Task begins with a failing test or contract command and ends with one focused commit.
- Later Tasks may `Modify` files created by earlier Phase 8 Tasks；earlier Tasks cannot invoke a later-created fixture.
- The production values fixture is created in Pack 02 Task 1 before any render command consumes it.
- Runtime acceptance evidence stays in governed storage；source documents contain only safe digests.
- A clean Git tree is required before final deterministic generation comparison.
- Required CI jobs cannot use `continue-on-error`, environment-based skipping or fabricated evidence.
- Real OIDC、mTLS、Vault、PostgreSQL、Temporal、Runner and target protocols are required for production-equivalent E2E.
- Fault injection is one bounded experiment at a time and always has cleanup/abort limits.
- Capacity、recovery and security evidence is regenerated after material chart/topology/identity changes.

## Fixed Release Waves

```text
INTERNAL_OPERATORS
  -> ONE_NONCRITICAL_SERVICE
  -> TEN_PERCENT_ELIGIBLE
  -> THIRTY_PERCENT_ELIGIBLE
  -> FULL_ELIGIBLE_SCOPE
```

Each wave has a minimum soak window, queryable immutable evidence, and an explicit `PROMOTE`, `HOLD`, or `ROLL_BACK` decision. “Full eligible scope” means only assets and Action types whose individual gates are `AVAILABLE`; it never silently broadens authorization.

## Exit Evidence

- Repository-wide backend/frontend/E2E/Helm/security contract checks pass from a clean isolated worktree.
- Restore and dependency-loss drills meet the approved RPO/RTO and leave no orphaned READ/WRITE credential.
- Every promoted wave meets availability, latency, authorization-denial, credential cleanup, verification, duplicate-execution, DLP and audit-delivery thresholds for its soak window.
- Kill Switch activation, release halt, capability revocation and human escalation are each exercised and timestamped.
- On-call, security, database, platform and product owners sign the final release record; no single self-approval can promote production write.
- The final E2E proves both the verified-success path and the uncertain-result stop/reconcile/escalation path.
- `docs/status/current.md` describes the exact available capabilities and keeps every ungated capability explicitly closed.

## Program Completion Rule

Only the accepted `PRODUCTION_CLOSED_LOOP_ACCEPTED` release revision may be called production complete. A later material schema, policy, credential, Runner, verification, infrastructure or Action change creates a new release candidate and re-enters the applicable gates rather than inheriting acceptance automatically.
