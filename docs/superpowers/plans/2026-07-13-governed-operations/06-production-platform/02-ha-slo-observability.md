# Production HA SLO and Observability Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 让生产只读路径在多副本、滚动升级、依赖故障和 Runner crash 下保持一次性领域结果、旧 fence 失效、可观测且满足 99.9% SLO，并把可批准的 SLO/HA 证据持久化。

**Architecture:** PostgreSQL row/advisory lease 与 attempt epoch 是 Outbox/Gateway/Runner 的 fence；Temporal Workflow/Activity ID 和 worker build compatibility 是控制编排 fence；所有副作用用业务 idempotency key 与 immutable digest 去重。OpenTelemetry 生成固定低基数 RED/USE/安全指标，SLO evaluator 从可信 metrics snapshots 计算 rolling 30-day budget，任何缺失/漂移产生 INCONCLUSIVE gate。真实多副本负载和故障注入验证而不是进程内 fake。

**Tech Stack:** Go 1.26.5、PostgreSQL 18.4+、Temporal SDK 1.46.0、OpenTelemetry Metrics/Trace、Prometheus、Alertmanager、Grafana、Kubernetes HPA/PDB/topology spread、k6、Toxiproxy/Chaos Mesh（测试环境）。

## Global Constraints

- 每个 Task 严格采用 Red → Green → Refactor：先运行并保存预期失败，再做最小生产实现，复跑指定测试后才允许重构和提交。
- HA 不能通过 sticky session、单例进程、本地 lock/file/cache 或 leader 环境变量实现。
- 每个 claim/lease 有递增 epoch/fencing token；旧 epoch 的 heartbeat/complete/ack/revoke/decision 永远拒绝。
- 重放、重试、Pod 重启、网络重复、Temporal Activity retry 只能产生一个 Task、Evidence、Receipt、Audit 和 cleanup terminal result。
- RUNNING Runner 失联先进入 UNCERTAIN 并持久 cleanup/reconcile；不得盲重试可能产生重复目标读取或 credential 使用。
- rolling upgrade 保留旧 Worker/Runner profile 直至其固定任务清空；新 workflow/grant 才绑定 N+1。
- readiness/drain 与 lease 分开：不 ready 阻止新流量，drain 关闭 claim，已有工作仍必须受 fence/expiry/Kill Switch。
- 99.9 SLO 使用 rolling 30d 和固定误差分类；不能把拒绝、安全失败、目标失败改标签来粉饰 availability。
- 指标 label 只允许固定 component/family/operation/boundary/result/reason/stage；禁止 Scope、ID、endpoint、query、credential、trace ID、error text。
- Metrics/alert backend 故障不自动停止已授权安全执行，但使 readiness decision gate INCONCLUSIVE 并冻结 rollout。
- 审计/outbox backlog 超门槛关闭新生产 READ；不得丢弃或绕过审计以恢复可用性。
- dashboard/alert/runbook 名称和 gate code 必须交叉测试，无 orphan alert。
- load/chaos 不降低预算、DLP、TLS、Gate 频率、timeout 或 credential cleanup 语义。
- 未经 accepted Action manifest 登记的 WRITE availability/claim 始终为 0 并作为 SLI 监测；Phase 6 的 accepted manifest 为空。
- 新增行为严格 TDD，每个 Task 独立 commit。

---

### Task 1: Make every production role multi-replica, fenced and drainable

**Files:**
- Create: `internal/platformha/lease.go`
- Create: `internal/platformha/lease_test.go`
- Create: `internal/platformha/drain.go`
- Create: `internal/platformha/drain_test.go`
- Create: `internal/platformha/temporal_versioning.go`
- Create: `internal/platformha/temporal_versioning_test.go`
- Modify: `internal/outbox/dispatcher.go`
- Modify: `internal/outbox/dispatcher_test.go`
- Modify: `internal/readtask/postgres/repository.go`
- Modify: `internal/readtask/postgres/runner_tx_test.go`
- Modify: `internal/readgateway/backend.go`
- Modify: `internal/readgateway/backend_test.go`
- Modify: `internal/readcredential/cleanupworker/worker.go`
- Modify: `internal/readcredential/cleanupworker/worker_test.go`
- Modify: `internal/proactiveworkflow/registration.go`
- Create: `internal/proactiveworkflow/registration_test.go`
- Modify: `internal/proactiveworkflow/workflow.go`
- Modify: `internal/proactiveworkflow/workflow_test.go`

**Interfaces:**
- Consumes: Phase 1 Outbox claim token, Phase 4 Grant/Gateway four-boundary transactions, Phase 5 credential cleanup attempts, Phase 6 Platform revision.
- Produces: common lease/fence/drain contract and Temporal build compatibility for all roles.
- Safety: lease owner is workload identity digest；old fence cannot emit any durable terminal fact.

- [ ] **Step 1: Write failing replica/race/upgrade tests**

```go
func TestTwoOutboxReplicasPublishOneEventAndOnlyCurrentFenceAcks(t *testing.T)
func TestTwoGatewayReplicasClaimOneAttemptAndRejectOldFenceCompletion(t *testing.T)
func TestRunnerCrashMovesRunningToUncertainBeforeReconcile(t *testing.T)
func TestCleanupTakeoverUsesHigherEpochAndOneTerminalReceipt(t *testing.T)
func TestDrainStopsClaimsBeforeWaitingAndPersistsUnfinishedWork(t *testing.T)
func TestTemporalNAndNPlusOneWorkersKeepPinnedWorkflowsCompatible(t *testing.T)
func TestRollingUpgradeNeverRoutesPinnedNTaskToNPlusOneProfile(t *testing.T)
```

- [ ] **Step 2: Run tests and verify failure**

```bash
go test ./internal/platformha ./internal/outbox/... ./internal/readtask/postgres ./internal/readgateway ./internal/readcredential ./internal/proactiveworkflow -run 'Test(Two|RunnerCrash|CleanupTakeover|Drain|TemporalN|RollingUpgrade)' -count=1
```

Expected: FAIL because shared production HA/drain/version contract is absent.

- [ ] **Step 3: Implement durable lease and fence primitives**

```go
type Lease struct {
    ResourceID              string
    Epoch                   int64
    OwnerIdentityDigest     string
    AcquiredAt              time.Time
    HeartbeatAt             time.Time
    ExpiresAt               time.Time
}

type Store interface {
    Claim(context.Context, ResourceKey, string, time.Duration) (Lease, error)
    Heartbeat(context.Context, ResourceKey, int64, string, time.Duration) (Lease, error)
    Complete(context.Context, ResourceKey, int64, string, string) error
    Expire(context.Context, time.Time, int) ([]Lease, error)
}
```

Use DB time, positive monotonic epoch, `SELECT ... FOR UPDATE SKIP LOCKED`, lease 30s/heartbeat 10s for dispatcher/cleanup and task-specific bounded lease for runners. Completion compares resource+epoch+owner+idempotency digest in one transaction. Lease expiry never auto-completes RUNNING work.

- [ ] **Step 4: Implement deterministic drain and Temporal compatibility**

`DrainController` states `SERVING→DRAINING→DRAINED|UNCERTAIN`; first action closes admission and readiness, then stops pollers, waits max 60s, persists remaining leases and exits. Temporal Worker registers `PlatformBuildID=sha256(platform revision manifest)` and explicit compatible set only after replay tests；old build remains until zero open workflow/activity/task and soak expiry.

- [ ] **Step 5: Run race and real PostgreSQL concurrency tests**

```bash
AIOPS_TEST_POSTGRES_DSN="$AIOPS_TEST_POSTGRES_DSN" go test -race -shuffle=on ./internal/platformha ./internal/outbox/... ./internal/readtask/postgres ./internal/readgateway ./internal/readcredential ./internal/proactiveworkflow -run 'Test(Two|RunnerCrash|CleanupTakeover|Drain|TemporalN|RollingUpgrade)' -count=10
```

Expected: PASS；each iteration has one terminal effect and stale epochs always fail.

- [ ] **Step 6: Commit HA semantics**

```bash
git add internal/platformha internal/outbox internal/readtask/postgres internal/readgateway internal/readcredential internal/proactiveworkflow
git commit -m "feat(platform): fence production replicas"
```

### Task 2: Add safe platform telemetry, dashboards and alerts

**Files:**
- Create: `internal/platformobservability/metrics.go`
- Create: `internal/platformobservability/metrics_test.go`
- Create: `internal/platformobservability/tracing.go`
- Create: `internal/platformobservability/tracing_test.go`
- Create: `internal/platformobservability/audit.go`
- Create: `internal/platformobservability/audit_test.go`
- Create: `deploy/monitoring/rules/production-read-platform.yaml`
- Create: `deploy/monitoring/rules/production-read-platform_test.go`
- Create: `deploy/monitoring/dashboards/production-read-platform.json`
- Create: `deploy/monitoring/dashboards/production-read-platform_test.go`

**Interfaces:**
- Consumes: role lifecycle, dependency probes, Grant/Gateway/task/credential/evidence/audit/rollout events.
- Produces: bounded metrics/traces/audit projection, alert rules and dashboard rows linked to runbooks.
- Safety: no sensitive/high-cardinality attribute; trace sampling never includes bodies/payloads.

- [ ] **Step 1: Write failing telemetry contract tests**

```go
func TestPlatformMetricsUseOnlyFixedLowCardinalityAttributes(t *testing.T)
func TestPlatformTracesContainDigestsNotBodiesOrIdentifiers(t *testing.T)
func TestPlatformAuditProjectionIsAppendOnlyAndSecretSafe(t *testing.T)
func TestPlatformAlertsReferenceExistingMetricsAndRunbooks(t *testing.T)
func TestPlatformDashboardCoversDependenciesSLOHAReadAndWriteClosure(t *testing.T)
```

- [ ] **Step 2: Run tests and verify failure**

```bash
go test ./internal/platformobservability ./deploy/monitoring/rules ./deploy/monitoring/dashboards -run 'TestPlatform' -count=1
```

Expected: FAIL because production telemetry assets are absent.

- [ ] **Step 3: Implement the fixed metric catalog**

```text
aiops_platform_component_ready{component,result}
aiops_platform_dependency_checks_total{dependency,result,reason}
aiops_platform_dependency_check_duration_seconds{dependency,result}
aiops_platform_leases{component,state}
aiops_platform_fence_rejections_total{component,boundary}
aiops_platform_outbox_backlog{event_family}
aiops_platform_outbox_oldest_age_seconds{event_family}
aiops_platform_workflow_starts_total{workflow,result}
aiops_platform_gateway_requests_total{boundary,result,reason}
aiops_platform_gateway_duration_seconds{boundary,result}
aiops_platform_runner_attempts_total{realm_family,result,reason}
aiops_platform_credential_cleanup_total{result,reason}
aiops_platform_evidence_completion_total{family,result,reason}
aiops_platform_rollout_gate{stage,gate,result}
aiops_platform_write_availability{surface}
```

Attribute validators are shared by metric/trace/audit. Unknown enum or canary causes record rejection and a fixed internal counter, not dynamic label creation.

- [ ] **Step 4: Add exact alerts and dashboard rows**

Alerts include `PlatformSLOFastBurn14x`, `PlatformSLOSlowBurn6x`, `PlatformPostgresUnavailable`, `PlatformTemporalUnavailable`, `PlatformKeycloakUnavailable`, `PlatformVaultPKIUnavailable`, `PlatformAuditBacklogBlocking`, `PlatformCredentialCleanupUncertain`, `PlatformFenceRejectionSpike`, `PlatformRuntimeDrift`, `PlatformShadowSideEffect`, `PlatformWriteSurfaceAvailable`, `PlatformBackupRPOBreached`. Critical security/write/shadow alerts fire immediately；dependency/SLO alerts use stated windows.

Dashboard rows: platform revision/rollout safety；component replicas/leases/drain；dependency matrix；API/Gateway/Runner RED；Temporal/Outbox；credential/evidence/audit；30-day SLO/burn；backup/RPO/RTO；Shadow side effects and write closure.

- [ ] **Step 5: Run telemetry tests**

```bash
go test -race ./internal/platformobservability ./deploy/monitoring/rules ./deploy/monitoring/dashboards -count=1
```

Expected: PASS；no orphan alert, unknown label or canary.

- [ ] **Step 6: Commit observability assets**

```bash
git add internal/platformobservability deploy/monitoring/rules/production-read-platform.yaml deploy/monitoring/rules/production-read-platform_test.go deploy/monitoring/dashboards/production-read-platform.json deploy/monitoring/dashboards/production-read-platform_test.go
git commit -m "feat(platform): observe production read path"
```

### Task 3: Evaluate SLO/error budget and persist gate evidence

**Files:**
- Create: `internal/productionplatform/slo.go`
- Create: `internal/productionplatform/slo_test.go`
- Create: `internal/productionplatform/gate_collector.go`
- Create: `internal/productionplatform/gate_collector_test.go`
- Create: `internal/productionplatform/postgres/gate_collector.go`
- Create: `internal/productionplatform/postgres/gate_collector_test.go`
- Modify: `internal/productionplatform/postgres/repository.go`
- Modify: `internal/productionplatform/postgres/repository_test.go`

**Interfaces:**
- Consumes: signed/query-authenticated metric snapshots plus platform/audit/backup/security sources.
- Produces: deterministic rolling SLI/burn results and immutable `production_rollout_gate_evidence` rows.
- Safety: missing/stale/inconsistent samples are INCONCLUSIVE, never zero-error PASS.

- [ ] **Step 1: Write failing SLO/gate tests**

```go
func TestAvailabilitySLOUsesRollingThirtyDaysAndExactClassification(t *testing.T)
func TestErrorBudgetIsPointOnePercentAndComputesBothBurnWindows(t *testing.T)
func TestMissingStaleOrResetMetricsAreInconclusive(t *testing.T)
func TestSecurityCleanupWriteAndShadowGatesRequireExactZeroOrTerminal(t *testing.T)
func TestGateCollectorBindsSamplesToPlatformAndRolloutDigests(t *testing.T)
func TestGateEvidenceReplayIsIdempotentButDifferentDigestConflicts(t *testing.T)
```

- [ ] **Step 2: Run tests and verify failure**

```bash
go test ./internal/productionplatform/... -run 'Test(AvailabilitySLO|ErrorBudget|MissingStale|SecurityCleanup|GateCollector|GateEvidence)' -count=1
```

Expected: FAIL because evaluator/collector are absent.

- [ ] **Step 3: Implement exact SLI evaluation**

```go
type SLIWindow struct {
    Start        time.Time
    End          time.Time
    Eligible     uint64
    Good         uint64
    BadPlatform  uint64
    ExcludedUser uint64
    ExcludedTarget uint64
    SourceDigest string
}

type SLOResult struct {
    Objective        float64
    Availability     float64
    BudgetRemaining  float64
    BurnRateOneHour  float64
    BurnRateSixHours float64
    Result           GateResult
}
```

Objective literal `0.999`; platform bad is eligible internal 5xx/timeout/unavailable；authz denial, invalid caller, Kill Switch and upstream target failure are separately excluded and reported. Counter reset/gap >2 scrape intervals, source older than 5m or signature mismatch is INCONCLUSIVE.

- [ ] **Step 4: Collect complete gate set transactionally**

Collector requires all 22 README registry gate codes, exact platform/rollout/source digest, freshness, minimum sample/soak thresholds and safe counts. It stores only counts/times/result/digest. Any FAIL rejects rollout；INCONCLUSIVE keeps RUNNING and freezes decisions.

- [ ] **Step 5: Run SLO and repository tests**

```bash
go test -race ./internal/productionplatform/... -run 'Test(AvailabilitySLO|ErrorBudget|MissingStale|SecurityCleanup|GateCollector|GateEvidence)' -count=1
```

Expected: PASS with golden 99.9/burn calculations and no missing-data PASS.

- [ ] **Step 6: Commit SLO gates**

```bash
git add internal/productionplatform/slo.go internal/productionplatform/slo_test.go internal/productionplatform/gate_collector.go internal/productionplatform/gate_collector_test.go internal/productionplatform/postgres
git commit -m "feat(platform): gate rollout on SLO evidence"
```

### Task 4: Prove capacity, rolling HA and dependency failures under load

**Files:**
- Create: `test/load/production-read.js`
- Create: `test/load/production-read-contract_test.go`
- Create: `test/chaos/production-read/ha_test.go`
- Create: `test/chaos/production-read/dependencies_test.go`
- Create: `test/chaos/production-read/runner_crash_test.go`
- Create: `test/chaos/production-read/rolling_upgrade_test.go`
- Create: `test/chaos/production-read/write_closure_test.go`
- Create: `test/chaos/production-read/run.sh`

**Interfaces:**
- Consumes: real production chart stack, k6 API users, fault injection API and telemetry/gate collector.
- Produces: load/HA/failure evidence digest suitable for gate persistence.
- Safety: load input is typed public requests only；chaos cannot access credentials or target write networks.

- [ ] **Step 1: Write failing load/chaos contract tests**

```go
func TestLoadProfileCoversHumanEventScheduleAndEveryReadFamily(t *testing.T)
func TestLoadProfileContainsNoEndpointQueryCommandSQLOrWriteRequest(t *testing.T)
func TestDependencyFaultMatrixHasEveryMandatoryDependency(t *testing.T)
func TestChaosAssertsOneTerminalEffectAndCurrentFence(t *testing.T)
func TestChaosAlwaysRestoresAndScansArtifacts(t *testing.T)
```

- [ ] **Step 2: Run contract tests and verify failure**

```bash
go test ./test/load ./test/chaos/production-read -run 'Test(LoadProfile|DependencyFault|Chaos)' -count=1
```

Expected: FAIL because scenarios do not exist.

- [ ] **Step 3: Implement representative load**

Run 60 minutes with ramp 0→50→150 concurrent users and a 15-minute 2× burst. Mix 20% asset/connection reads, 15% Preview/Shadow, 20% manual/event/schedule starts, 35% Gateway read lifecycle across Victoria/Host/PostgreSQL, 10% evidence/status. Acceptance: Control/Gateway SLO green, no duplicate durable effect, cleanup 100% terminal by 5m, queue returns to baseline in 5m, no security/DLP budget relaxation.

- [ ] **Step 4: Implement fault matrix**

During load, restart/partition one replica, kill current lease holder, roll N→N+1, and independently fail PostgreSQL、Temporal、Keycloak、Vault/PKI、audit、evidence store、metrics、Gateway、Runner. Assert the README failure contract, recover without manual DB edits, and collect sanitized evidence.

- [ ] **Step 5: Run real load/chaos suite**

```bash
./test/production/up.sh
k6 run test/load/production-read.js
./test/chaos/production-read/run.sh
go test ./test/chaos/production-read -count=1 -timeout=90m
./test/production/down.sh
```

Expected: PASS；99.9/error budget gate remains valid or correctly blocks, no duplicate/fence bypass/write surface.

- [ ] **Step 6: Commit load/chaos tests**

```bash
git add test/load/production-read.js test/load/production-read-contract_test.go test/chaos/production-read
git commit -m "test(platform): prove HA and SLO under failure"
```

## Pack Completion Gate

```bash
go test -race -shuffle=on ./internal/platformha ./internal/platformobservability ./internal/productionplatform/... -count=1
go test ./deploy/monitoring/rules ./deploy/monitoring/dashboards ./test/load ./test/chaos/production-read -count=1
go vet ./internal/platformha ./internal/platformobservability ./internal/productionplatform/...
git diff --check
```

Expected: all commands exit 0；multi-replica and rolling behavior fenced/idempotent, telemetry safe, SLO missing-data closed and chaos matrix complete.
