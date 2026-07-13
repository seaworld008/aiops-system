# VictoriaMetrics Ecosystem E2E Operations and Documentation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 用真实 Operator、三类 Victoria 产品、生产装配 Runner 和浏览器证明 Phase 3 的完整闭环，并持久化 HA、容量、监控、告警、恢复、升级、安全事件与架构文档。

**Architecture:** Kind 集群运行固定版本 Operator 与真实 CR，隔离 seeder 预置 metrics/logs/traces 后退出；真实 Control Plane、discovery worker、validation runner、read executor 通过 PostgreSQL、mTLS、对象存储和网络策略完成 discovery→asset→connection→validation→publication→task→evidence。浏览器直连生产 build，不使用 MSW；运维验证脚本执行双实例接管、drift/rollback、预算和敏感信息扫描。

**Tech Stack:** Go 1.26.5、PostgreSQL 18.4+、Kind/Kubernetes v1.36.2、VictoriaMetrics Operator v0.73.1、VictoriaMetrics v1.147.0、VictoriaLogs v1.51.0、VictoriaTraces v0.9.4、Docker Compose、MinIO/S3、mTLS、Prometheus/Alertmanager/Grafana、OpenTelemetry Collector、pnpm 10.34.0、Playwright、axe-core、k6。

## Global Constraints

- 每个 Task 严格采用 Red → Green → Refactor：先运行并保存预期失败，再做最小生产实现，复跑指定测试后才允许重构和提交。
- E2E 必须使用生产 `cmd/*` 装配、真实 PostgreSQL、真实 mTLS、真实 Operator/产品 HTTP 服务和真实浏览器；fake client、httptest upstream、MSW、in-memory repository 只允许单元测试。
- 产品镜像与 chart 按版本和 digest 固定；升级必须显式更新 fixture、compatibility profile 和 golden evidence，不得使用 `latest`。
- Seeder 是测试基础设施，不是调查 runtime。它在独立 namespace/network policy 中调用 ingestion，完成后必须退出且网络凭据撤销；read executor 永远无法到达 insert/OTLP 端口。
- 真实 Runner 只执行 18 个列出的只读能力；E2E 负向测试证明 ingestion/tool 路径在 capability registry、Target、network policy、UI 和 transport guard 五层关闭。
- `VMUser` 测试故意生成 Secret 和 canary credential；发现 worker 的 audit/request capture 必须证明从未请求 Secret，全部日志/DB/API/HAR/artifact 必须无 canary。
- E2E 失败也必须执行 cleanup，销毁 Kind、Compose volume、临时证书、对象存储和浏览器 artifact 中的敏感 fixture。
- 性能验收不通过时不得通过放宽证据预算、允许 partial、扩大 timeout、减少安全检查或关闭 DLP 修复。
- 指标 labels 只能是固定 family/operation/result/reason/resource kind/profile version；不得包含 Scope、asset、connection、tenant、endpoint、query、trace ID 或错误原文。
- 告警与 runbook 必须一一对应；每个 critical 告警有 owner、影响、确认、止血、恢复、验证和升级路径。
- 文档只在对应真实命令产生 PASS 证据后标记 ready；记录 commit SHA、migration、镜像 digest、测试时间和已知限制。
- Phase 3 仍是只读生产闭环基础；文档不得暗示已开放自动授权或生产写入。
- 新增行为严格 TDD，每个 Task 独立提交。

---

## End-to-End Coverage Matrix

| Boundary | Positive proof | Negative proof |
|---|---|---|
| Operator discovery | 21 resource catalog, v1/v1beta1 resolution, component topology | Secret zero request, partial list no missing-marking, wrong owner UID no relation |
| Taxonomy/version | runtime/config/tool all visible, exact current profile supported | unknown version unsupported, config/tool/insert/storage no Target |
| Metrics | six operations against real VMSingle/VMCluster select | vminsert/write/import/delete/storage unreachable |
| Logs | six operations against real VLSingle/VLCluster select | vlinsert/log push/delete/storage unreachable; partial rejected |
| Traces | six operations against real VTSingle/VTCluster select | vtinsert/OTLP/Jaeger/Zipkin ingestion/storage unreachable |
| Evidence | exact schema, JCS digest, DLP-safe artifact/completion | over bytes/items/time/depth, canary, malformed/partial produce no artifact |
| Runtime | legacy N and Victoria N+1 coexist; APPLIED admits new grants | incompatible closure, drift, revoked credential/profile stop execution |
| UI | ecosystem, topology, compatibility, capability/security states | no tenant/secret/query controls or network payloads; “虚拟机” never conflated |
| HA/operations | dual workers/executors, restart/takeover, rollback, backup/restore | stale worker cannot complete; split-brain and artifact substitution rejected |

### Task 1: Build a real Victoria E2E environment and backend acceptance suite

**Files:**
- Create: `test/e2e/victoria/kind-config.yaml`
- Create: `test/e2e/victoria/docker-compose.victoria.yaml`
- Create: `test/e2e/victoria/images.lock`
- Create: `test/e2e/victoria/up.sh`
- Create: `test/e2e/victoria/down.sh`
- Create: `test/e2e/victoria/wait-ready.sh`
- Create: `test/e2e/victoria/manifests/operator-values.yaml`
- Create: `test/e2e/victoria/manifests/namespaces.yaml`
- Create: `test/e2e/victoria/manifests/all-public-resources.yaml`
- Create: `test/e2e/victoria/manifests/network-policies.yaml`
- Create: `test/e2e/victoria/manifests/seed-job.yaml`
- Create: `test/e2e/victoria/e2e_test.go`
- Create: `test/e2e/victoria/operator_discovery_test.go`
- Create: `test/e2e/victoria/metrics_test.go`
- Create: `test/e2e/victoria/logs_test.go`
- Create: `test/e2e/victoria/traces_test.go`
- Create: `test/e2e/victoria/runtime_test.go`
- Create: `test/e2e/victoria/security_scan_test.go`

**Interfaces:**
- Consumes: all Phase 3 production commands, migrations, chart/RBAC, OpenAPI and runtime profiles.
- Produces: reproducible real-service acceptance evidence and sanitized artifact directory.
- Safety: seeder and read realms have deny-by-default, disjoint ServiceAccounts/network policies; tests assert the read realm cannot resolve/connect to insert services.

- [ ] **Step 1: Write the failing environment contract tests first**

```go
func TestVictoriaE2EUsesPinnedImagesAndNoFakeAssembly(t *testing.T)
func TestVictoriaE2EReadRealmCannotReachAnyIngestionService(t *testing.T)
func TestVictoriaE2ECleanupIsIdempotent(t *testing.T)
func TestVictoriaE2EArtifactsContainNoSensitiveCanary(t *testing.T)
```

Parse manifests/compose/scripts in the tests: reject `latest`, mutable tag-only image, wildcard RBAC, Secret read, host networking, shared seeder/read ServiceAccount, fake/MSW flags and commands without cleanup traps.

- [ ] **Step 2: Run environment contract tests and verify failure**

```bash
go test ./test/e2e/victoria -run 'TestVictoriaE2EUsesPinned|TestVictoriaE2EReadRealm|TestVictoriaE2ECleanup|TestVictoriaE2EArtifacts' -count=1
```

Expected: FAIL because the E2E environment does not exist.

- [ ] **Step 3: Implement deterministic environment lifecycle**

`images.lock` records the immutable image reference and sha256 digest for Kind node、Operator、VictoriaMetrics、VictoriaLogs、VictoriaTraces、PostgreSQL、MinIO and OTel Collector. `up.sh` verifies each pulled image against this lock, then performs these exact phases with `set -euo pipefail` and an EXIT cleanup trap on incomplete setup:

1. verify Docker, Kind, kubectl, Helm, Go, Node 24 and pnpm 10;
2. create a unique Kind cluster from `kind-config.yaml`;
3. install Operator v0.73.1 with chart/image digest pinning;
4. apply namespaces and deny-by-default network policies;
5. apply schema-valid examples for all 21 public resources, including VM/VL/VT single and cluster;
6. wait for select/single health but allow config-only/VMAnomaly asset visibility when runtime is intentionally unavailable;
7. run the isolated seed job for deterministic metric series, log records, traces and servicegraph edges;
8. wait for seed completion, delete its credentials and deny its egress;
9. start PostgreSQL/MinIO/OTel and production app containers from Compose;
10. apply migrations through 000017, bootstrap compatibility profiles and wait for readiness;
11. write only nonsecret endpoints/run IDs into `.state/e2e.json` with mode 0600.

`down.sh` is idempotent and removes containers/volumes, Kind cluster, temporary CA/client certificates, state and browser artifact canaries.

- [ ] **Step 4: Write failing real backend flow tests**

```go
func TestOperatorResourceCoverageE2E(t *testing.T)
func TestSecretProjectionDeniedE2E(t *testing.T)
func TestVictoriaMetricsAllCapabilitiesE2E(t *testing.T)
func TestVictoriaLogsAllCapabilitiesE2E(t *testing.T)
func TestVictoriaTracesAllCapabilitiesE2E(t *testing.T)
func TestVictoriaIngestionAndToolCapabilitiesAbsentE2E(t *testing.T)
func TestVictoriaUnknownVersionVisibleButClosedE2E(t *testing.T)
func TestVictoriaEvidenceBudgetsDLPAndCanonicalDigestE2E(t *testing.T)
func TestVictoriaRuntimeNAndNPlusOneE2E(t *testing.T)
```

Each family test executes all six operations through the public task flow and validates operation-specific evidence. Security test queries DB/API/object storage/audit/application logs/Kubernetes API audit and fails if tenant or credential canary appears.

- [ ] **Step 5: Implement real test flows**

Use public API to wait for complete discovery, select exact assets, create connection revision, validate through real mTLS runner, publish N+1, submit a read task and fetch evidence summary. Direct upstream access is allowed only in test assertions to compare known fixture counts, never to create system evidence. Test each insertion/tool kind has no capability definition/set item/Target and that transport request counters remain zero on forced malformed attempts.

- [ ] **Step 6: Run the real backend suite**

```bash
./test/e2e/victoria/up.sh
go test -tags=e2e ./test/e2e/victoria -run 'TestOperatorResourceCoverageE2E|TestSecretProjectionDeniedE2E|TestVictoriaMetricsAllCapabilitiesE2E|TestVictoriaLogsAllCapabilitiesE2E|TestVictoriaTracesAllCapabilitiesE2E|TestVictoriaIngestionAndToolCapabilitiesAbsentE2E|TestVictoriaUnknownVersionVisibleButClosedE2E|TestVictoriaEvidenceBudgetsDLPAndCanonicalDigestE2E|TestVictoriaRuntimeNAndNPlusOneE2E' -count=1 -timeout=45m
./test/e2e/victoria/down.sh
```

Expected: PASS; 18 capability flows succeed, every unsafe surface is absent/unreachable, N and N+1 coexist and scans find zero canary.

- [ ] **Step 7: Commit the real backend E2E suite**

```bash
git add test/e2e/victoria
git commit -m "test(victoria): verify real ecosystem read flow"
```

### Task 2: Add real-browser workflow, visual, accessibility and security E2E

**Files:**
- Modify: `web/playwright.config.ts`
- Create: `web/e2e/victoria/ecosystem.spec.ts`
- Create: `web/e2e/victoria/asset-detail.spec.ts`
- Create: `web/e2e/victoria/connection-publication.spec.ts`
- Create: `web/e2e/victoria/capability-catalog.spec.ts`
- Create: `web/e2e/victoria/security.spec.ts`
- Create: `web/e2e/victoria/accessibility.spec.ts`
- Create: `web/e2e/victoria/visual.spec.ts`
- Create: `web/e2e/victoria/fixtures.ts`

**Interfaces:**
- Consumes: production web build and real Phase 3 APIs from Task 1.
- Produces: user-workflow, three-viewport, keyboard, axe, visual and browser-network evidence.
- Safety: Playwright fails on service-worker/MSW interception, request to unknown origin, tenant/credential/query canary in request/response/console/HAR/trace.

- [ ] **Step 1: Write failing browser acceptance scenarios**

```ts
test('distinguishes virtual machines from VictoriaMetrics ecosystem')
test('filters every family taxonomy class role and compatibility through URL state')
test('inspects exact cluster topology with query and closed components')
test('shows config tool anomaly insert and storage assets without investigation actions')
test('publishes a supported connection without tenant path header or query controls')
test('blocks unknown versions and explains compatibility closure')
test('shows all eighteen capabilities with exact endpoints hidden')
test('uses equivalent keyboard topology list and restores selected node URL')
test('has no serious axe violation at 1440 1024 and 390 pixels')
test('leaks no secret tenant query endpoint or trace canary to browser surfaces')
```

- [ ] **Step 2: Run tests and verify failure**

```bash
pnpm --dir web test:e2e -- --grep 'VictoriaMetrics|VictoriaLogs|VictoriaTraces'
```

Expected: FAIL because the specs do not exist.

- [ ] **Step 3: Implement production-only Playwright setup**

Build once, serve the built output, authenticate through the real test OIDC/session flow and use the real API base URL. Add a route listener that rejects MSW/service-worker scripts and any network origin outside the UI/control-plane allowlist. Capture HAR/trace/screenshot only on failure, then run the sensitive scanner before upload.

- [ ] **Step 4: Implement semantic and visual assertions**

Assert full names in headings/badges, role/compatibility reason text, absence of action controls for closed kinds and absence of forbidden form labels/inputs. Exercise keyboard-only filter/detail/topology/wizard. Visual snapshots cover ecosystem list, supported cluster detail, unsupported detail, connection review and mobile capability cards; mask only timestamps/trace IDs, not status or security content.

- [ ] **Step 5: Run browser suite against the real stack**

```bash
./test/e2e/victoria/up.sh
pnpm --dir web build
pnpm --dir web test:e2e -- --grep 'VictoriaMetrics|VictoriaLogs|VictoriaTraces'
pnpm --dir web test:a11y -- --grep 'VictoriaMetrics|VictoriaLogs|VictoriaTraces'
go test ./test/e2e/victoria -run 'TestVictoriaE2EArtifactsContainNoSensitiveCanary' -count=1
./test/e2e/victoria/down.sh
```

Expected: PASS at all viewports, zero serious/critical axe violations, visual baselines stable and browser surfaces clean.

- [ ] **Step 6: Commit browser E2E**

```bash
git add web/playwright.config.ts web/e2e/victoria
git commit -m "test(web): verify Victoria ecosystem experience"
```

### Task 3: Add production telemetry, alerts, HA/load/chaos verification

**Files:**
- Create: `internal/observability/victoria.go`
- Create: `internal/observability/victoria_test.go`
- Create: `deploy/monitoring/rules/victoria-ecosystem.yaml`
- Create: `deploy/monitoring/rules/victoria-ecosystem_test.go`
- Create: `deploy/monitoring/dashboards/victoria-ecosystem.json`
- Create: `deploy/monitoring/dashboards/victoria-ecosystem_test.go`
- Create: `test/operations/victoria/verify-discovery-ha.sh`
- Create: `test/operations/victoria/verify-read-runtime-ha.sh`
- Create: `test/operations/victoria/verify-drift-rollback.sh`
- Create: `test/operations/victoria/verify-backup-restore.sh`
- Create: `test/operations/victoria/scan-sensitive-artifacts.sh`
- Create: `test/load/victoria-read.js`
- Create: `test/operations/victoria/operations_test.go`

**Interfaces:**
- Consumes: bounded metrics from discovery/validation/publication/executor, PostgreSQL/object-store backup and E2E stack.
- Produces: safe dashboards/alerts and executable HA/capacity/recovery evidence.
- Safety: metric schema test rejects high-cardinality or sensitive labels; scripts never print credentials/tenant/routes/upstream bodies.

- [ ] **Step 1: Write failing metric/dashboard/alert contract tests**

```go
func TestVictoriaMetricsHaveOnlyBoundedLabels(t *testing.T)
func TestVictoriaAlertsReferenceExistingMetricsAndRunbooks(t *testing.T)
func TestVictoriaDashboardHasDiscoveryCompatibilityRuntimeEvidenceAndSecurityRows(t *testing.T)
func TestVictoriaOperationsScriptsUseProductionProcessesAndCleanupTraps(t *testing.T)
func TestVictoriaLoadScenarioCannotCallIngestionOrArbitraryQuery(t *testing.T)
```

- [ ] **Step 2: Run tests and verify failure**

```bash
go test ./internal/observability ./deploy/monitoring/rules ./deploy/monitoring/dashboards ./test/operations/victoria -run 'TestVictoria' -count=1
```

Expected: FAIL because telemetry assets are absent.

- [ ] **Step 3: Register the fixed metric schema**

```text
aiops_victoria_discovery_runs_total{result}
aiops_victoria_discovery_resources_total{resource_kind,result}
aiops_victoria_discovery_duration_seconds{result}
aiops_victoria_compatibility_decisions_total{family,result,reason}
aiops_victoria_publications_total{family,result}
aiops_victoria_publication_drift{family}
aiops_victoria_read_requests_total{family,operation,result}
aiops_victoria_read_duration_seconds{family,operation,result}
aiops_victoria_read_response_bytes{family,operation,result}
aiops_victoria_evidence_rejections_total{family,reason}
aiops_victoria_endpoint_guard_rejections_total{family,reason}
aiops_victoria_tenant_injection_failures_total{family}
aiops_victoria_runtime_profile_mismatch_total{family}
aiops_victoria_active_executions{family,operation}
```

`reason` is a fixed enum. Tests gather every metric, reject any unknown label and scan help/labels for fixture canaries.

- [ ] **Step 4: Add exact alerts and dashboard rows**

Alerts:

| Alert | Expression/for | Severity |
|---|---|---|
| `VictoriaDiscoveryNoSuccessfulSnapshot` | no successful run for 30m while source active / 10m | warning |
| `VictoriaSecretRequestDenied` | increase of secret-deny counter >0 / 0m | critical |
| `VictoriaRuntimePublicationDrifted` | drift gauge >0 / 2m | critical |
| `VictoriaRuntimeProfileMismatch` | increase >0 / 0m | critical |
| `VictoriaEvidenceDLPRejected` | increase >0 / 0m | warning/security |
| `VictoriaReadErrorRateHigh` | errors >5% with at least 20 requests / 10m | warning |
| `VictoriaReadLatencyNearBudget` | p95 >15s / 10m | warning |
| `VictoriaTenantInjectionFailure` | increase >0 / 0m | critical |

Dashboard rows: discovery/resource coverage; taxonomy/version support; validation/publication/drift; request rate/latency/bytes by bounded operation; evidence/schema/DLP rejects; endpoint/tenant/profile safety; HA locks/active executions. Each panel links its runbook.

- [ ] **Step 5: Implement HA, load, drift and recovery exercises**

`verify-discovery-ha.sh` runs two workers, kills the lock holder during list/watch and proves one complete reconcile plus takeover without false missing. `verify-read-runtime-ha.sh` kills an executor during bounded requests and proves retry/idempotent completion with no cross-realm execution. `verify-drift-rollback.sh` substitutes one artifact byte, observes DRIFTED/closed admission, then rolls future grants back to N while captured tasks remain unchanged. `verify-backup-restore.sh` restores PostgreSQL and evidence metadata into an isolated stack, verifies digests and keeps credentials revoked.

`victoria-read.js` runs 10 minutes at 50 concurrent virtual users distributed across 18 operations. Acceptance: no scope/evidence mix-up, zero budget/DLP bypass, control-plane 5xx below 1%, queue depth returns to baseline within 2 minutes, and runtime memory remains bounded. Upstream latency is reported, not hidden by increasing the 20-second maximum.

- [ ] **Step 6: Run operations verification**

```bash
./test/e2e/victoria/up.sh
./test/operations/victoria/verify-discovery-ha.sh
./test/operations/victoria/verify-read-runtime-ha.sh
./test/operations/victoria/verify-drift-rollback.sh
./test/operations/victoria/verify-backup-restore.sh
k6 run test/load/victoria-read.js
./test/operations/victoria/scan-sensitive-artifacts.sh
./test/e2e/victoria/down.sh
```

Expected: all commands exit 0, alerts can be synthetically fired/resolved, takeover and rollback satisfy invariants, scanner finds zero sensitive canary.

- [ ] **Step 7: Commit telemetry and operations tests**

```bash
git add internal/observability/victoria.go internal/observability/victoria_test.go deploy/monitoring/rules/victoria-ecosystem.yaml deploy/monitoring/rules/victoria-ecosystem_test.go deploy/monitoring/dashboards/victoria-ecosystem.json deploy/monitoring/dashboards/victoria-ecosystem_test.go test/operations/victoria test/load/victoria-read.js
git commit -m "ops(victoria): verify HA telemetry and recovery"
```

### Task 4: Persist architecture, runbooks, stage status and CI gates

**Files:**
- Modify: `docs/architecture/overview.md`
- Modify: `docs/architecture/implementation-blueprint-v4.md`
- Modify: `docs/README.md`
- Modify: `docs/status/current.md`
- Modify: `docs/operations/governed-operations-stage-status.md`
- Create: `docs/adr/0003-victoria-ecosystem-read-boundary.md`
- Create: `docs/operations/victoria-operator-discovery.md`
- Create: `docs/operations/victoria-read-runtime.md`
- Create: `docs/operations/victoria-version-upgrade.md`
- Create: `docs/operations/victoria-runtime-rollback.md`
- Create: `docs/operations/victoria-security-incident.md`
- Create: `docs/operations/victoria-ha-capacity-and-recovery.md`
- Modify: `.github/workflows/ci.yml`

**Interfaces:**
- Consumes: implemented contracts and observed PASS output from Tasks 1–3.
- Produces: durable architecture/design decisions, actionable runbooks, truthful stage status and mandatory CI gates.
- Safety: docs contain no live endpoint/tenant/credential/query/evidence example; status remains not-ready until all evidence exists.

- [ ] **Step 1: Write the documentation acceptance tests/checklist first**

Each operations document must include Scope/owner、trigger/impact、safe signals、forbidden data、preconditions、diagnosis decision tree、containment、recovery、verification、rollback/escalation、exact commands and last exercise evidence. Commands use IDs/digests from safe API output and environment variables, never hard-coded secret or tenant values.

ADR records: three taxonomy classes; 21-resource coverage; Secret zero-read/opaque reference; server-owned tenant; exact version profiles; only select/single/governed proxy query targets; VMAnomaly/config/tools/insert/storage closure; strict evidence/DLP; N/N+1 compatibility; rejected alternatives and consequences.

- [ ] **Step 2: Update architecture and truthful stage status**

Blueprint diagrams discovery→asset/relations→connection contract→compatibility closure→runtime publication→typed executor→evidence. Status records commit SHA, migration `000015..000017`, Operator/product/Kubernetes/PostgreSQL/Node/pnpm versions and image digests, test commands/results, alert/runbook drill links, remaining risks and handoff to Phase 4 grants. It explicitly says production write and proactive authorization remain disabled.

- [ ] **Step 3: Add mandatory CI jobs without weakening earlier gates**

CI jobs:

1. Go unit/race/vet/build including exact resource and secret tests;
2. PostgreSQL `000017` up/down/up and scoped repository integration;
3. OpenAPI/generated/typecheck/lint/unit/build;
4. real Operator/product/Runner backend E2E;
5. real browser three-viewport/a11y/security E2E;
6. HA/drift/rollback smoke exercise;
7. metric/alert/dashboard schema validation;
8. sensitive-pattern scan over DB dump, logs, API, object metadata, HAR, trace, screenshots and test reports.

No Phase 3 job uses `continue-on-error`, test skip for missing Docker, mutable images, production MSW or unuploaded failure diagnostics. Expensive real-service jobs may be path-filtered only when Phase 3 code/docs/charts are untouched.

- [ ] **Step 4: Run the complete backend gate in a clean worktree**

```bash
test ! -d .worktrees
go test ./... -count=1
go test -race -shuffle=on -count=1 ./internal/assetdiscovery/victoriametrics/... ./internal/readconnector/... ./internal/readtarget/... ./internal/readexecutor/... ./internal/readruntime/... ./internal/victoriametrics/...
go vet ./...
go build ./cmd/control-plane ./cmd/discovery-worker ./cmd/validation-runner ./cmd/read-runner
AIOPS_TEST_POSTGRES_DSN="$AIOPS_TEST_POSTGRES_DSN" go test ./internal/store/postgres ./internal/victoriametrics/postgres -count=1
```

Expected: all commands exit 0 with race shuffle enabled and no architecture scanner false positive from nested worktrees.

- [ ] **Step 5: Run the complete frontend and production E2E gate**

```bash
pnpm --dir web generate:api:check
pnpm --dir web check
pnpm --dir web test -- --run
pnpm --dir web build
./test/e2e/victoria/up.sh
go test -tags=e2e ./test/e2e/victoria -count=1 -timeout=45m
pnpm --dir web test:e2e -- --grep 'VictoriaMetrics|VictoriaLogs|VictoriaTraces'
pnpm --dir web test:a11y -- --grep 'VictoriaMetrics|VictoriaLogs|VictoriaTraces'
./test/operations/victoria/verify-discovery-ha.sh
./test/operations/victoria/verify-read-runtime-ha.sh
./test/operations/victoria/verify-drift-rollback.sh
./test/operations/victoria/scan-sensitive-artifacts.sh
./test/e2e/victoria/down.sh
```

Expected: all commands exit 0; no MSW interception, no sensitive canary, all 18 capabilities and unsafe negative surfaces covered.

- [ ] **Step 6: Perform the final production-readiness review**

Record evidence that:

- 21 Operator resources and both served API versions are covered;
- discovery made zero Secret request and no secret material survived;
- all 37 Victoria asset kinds have one taxonomy class;
- only Single/Select/Governed Proxy receives query capability;
- all 18 exact operations pass schema/budget/DLP and tenant-isolation tests;
- insertion/OTLP/import/write/delete/storage/tools have no capability and zero read-runner network reachability;
- unknown versions and closure drift fail closed;
- legacy N continues while new grants require APPLIED N+1;
- dual worker/executor takeover, artifact drift, rollback and isolated restore drills passed;
- API/browser/log/metric/evidence/object artifacts contain no tenant/credential/query canary;
- virtual machines and VictoriaMetrics ecosystem are visually/semantically distinct;
- dashboards, alerts and all six runbooks exist and were exercised;
- Phase 4 receives immutable Asset/Target/Capability/Runtime publications, but no proactive grant is implemented here.

- [ ] **Step 7: Commit documentation and CI**

```bash
git add docs/architecture docs/README.md docs/status/current.md docs/operations docs/adr/0003-victoria-ecosystem-read-boundary.md .github/workflows/ci.yml
git commit -m "docs(victoria): operationalize ecosystem read closure"
```

## Final Acceptance Gate

After all commits, from a clean tree run:

```bash
go test ./internal/assetdiscovery/victoriametrics/... -run 'TestOperatorResourceCoverage|TestSecretProjectionDenied' -count=1
go test ./internal/readconnector/... ./internal/readexecutor/... -run 'TestVictoriaMetrics|TestVictoriaLogs|TestVictoriaTraces' -count=1
go test -race -shuffle=on -count=1 ./internal/assetdiscovery/victoriametrics/... ./internal/readconnector/... ./internal/readtarget/... ./internal/readexecutor/... ./internal/readruntime/...
pnpm --dir web check
pnpm --dir web test:e2e -- --grep 'VictoriaMetrics|VictoriaLogs|VictoriaTraces'
git diff --check
```

Expected: all commands exit 0; browser distinguishes virtual machines from VictoriaMetrics ecosystem; `vminsert`, `vlinsert`, `vtinsert`, OTLP, log writes, `vmctl`, `vmbackup`, `vmrestore`, `vmalert-tool` have no investigation capability.
