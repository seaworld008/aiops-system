# VictoriaTraces and Versioned Runtime Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 实现 VictoriaTraces 的六个类型化 Jaeger 只读能力，并将 Metrics/Logs/Traces 全部能力纳入可并存、可验证、可回滚的 runtime profile N/N+1 发布闭环。

**Architecture:** Trace connector 固定 service/operation/tag projection/hidden-field policy，任务只提供受限 lookback 或 trace ID。Executor 用 Jaeger API 固定路径查询并投影为最小 Trace evidence，原始 tags/logs/process 不跨隔离边界。Versioned Profile Registry 保留 legacy v1 digest，同时引入内容寻址的新 profile；dispatcher 依据 task 捕获的 publication/profile digest 执行，drift 或闭包不匹配立即停机。

**Tech Stack:** Go 1.26.5、现有 read runtime、VictoriaTraces Jaeger API、`net/http`、strict JSON、RFC 8785 JCS、SHA-256、Phase 2 Runtime Publication/Validation state machine、Prometheus/OpenTelemetry。

## Global Constraints

- 每个 Task 严格采用 Red → Green → Refactor：先运行并保存预期失败，再做最小生产实现，复跑指定测试后才允许重构和提交。
- VictoriaTraces 只实现 `list_services`、`list_operations`、`find_traces`、`get_trace`、`dependencies`、`cluster_health`。
- `vtinsert`、OTLP HTTP/gRPC、Jaeger ingestion、Zipkin ingestion、storage/admin、import/delete 路由永远不形成 capability。
- Tenant 只由私有 Target 注入 `AccountID`/`ProjectID`；值必须是 uint32，任何公共面都不得看到。
- Service/operation filters、tag filters、tag allowlist、hidden-field filters、limit、duration 均由 Capability Definition 持有；任务只可从 definition allowlist 选择 `list_operations` 的 service，不能自由提交新值。
- `get_trace` 的 task input 只接受 lowercase 16 或 32 位十六进制 trace ID；ID 可以进入 schema-valid evidence，但不得成为 metric label 或日志字段。
- 原始 Jaeger `tags`、`logs`、`processes`、warnings 和 upstream body 不得直接进入 evidence；只投影允许字段并再次 DLP。
- `dependencies` 是实验性读能力；只有 compatibility profile 声明 servicegraph 已启用且验证通过时发布，否则稳定显示 `UNSUPPORTED_DEPENDENCY_GRAPH`。
- legacy `read-executor-profile.v1` digest 固定为 `d776a2e45f33496a8a2558fba82096064c3aed10be588627a337e70983485e63`，任何测试都不得更新 golden。
- N 与 N+1 的 Target/Connector/Evidence/Profile artifacts 都不可变；dispatcher 不进行自动 schema 升级或 fallback。
- 新 grant 只能引用 APPLIED N+1；已运行 N task 可由 v1 registry 完成。Rollback 不重写 task，只切换后续 grant 的 active publication。
- runtime drift、kill switch、credential revision、network policy、realm、scope、asset lifecycle/mapping、profile status 任一不符都停止。
- 新增行为严格 TDD，每个 Task 独立提交。

---

## Fixed Trace API Mapping

| Operation | Method | Exact path | Server-owned parameters |
|---|---|---|---|
| `list_services` | GET | `/select/jaeger/api/services` | none |
| `list_operations` | GET | `/select/jaeger/api/services/{service_name}/operations` | service allowlist member |
| `find_traces` | GET | `/select/jaeger/api/traces` | service, operation, tags, start/end μs, duration, limit |
| `get_trace` | GET | `/select/jaeger/api/traces/{trace_id}` | task trace ID only |
| `dependencies` | GET | `/select/jaeger/api/dependencies` | endTs ms, lookback ms |
| `cluster_health` | GET | `/health` | none |

Every request except health receives private tenant headers after audit-safe metadata capture. Redirect、proxy、compression and partial response remain disabled.

### Task 1: Define VictoriaTraces connectors and minimal evidence schemas

**Files:**
- Modify: `internal/readconnector/types.go`
- Modify: `internal/readconnector/contracts.go`
- Modify: `internal/readconnector/contracts_test.go`
- Create: `internal/readconnector/victoriatraces.go`
- Create: `internal/readconnector/victoriatraces_test.go`
- Create: `internal/readconnector/schema/victoriatraces.go`
- Create: `internal/readconnector/schema/victoriatraces_test.go`

**Interfaces:**
- Consumes: published trace capability definitions and safe task input.
- Produces: `KindVictoriaTraces`, six operations, canonical manifest and operation-specific evidence validators.
- Safety: typed union rejects arbitrary Jaeger parameters, query paths and upstream response fields.

- [ ] **Step 1: Write failing connector and schema tests**

```go
func TestVictoriaTracesCapabilitiesAreCompleteAndUnique(t *testing.T)
func TestVictoriaTracesDefinitionOwnsFiltersProjectionAndBudgets(t *testing.T)
func TestVictoriaTracesTaskInputAllowsOnlyLookbackAllowedServiceOrTraceID(t *testing.T)
func TestVictoriaTracesRejectsUppercaseMalformedAndOversizeTraceID(t *testing.T)
func TestVictoriaTracesManifestDigestBindsEverySecurityField(t *testing.T)
func TestVictoriaTracesEvidenceRejectsRawTagsLogsProcessesAndWarnings(t *testing.T)
func TestVictoriaTracesEvidenceSchemasRejectUnknownFieldsAndBudgets(t *testing.T)
```

- [ ] **Step 2: Run tests and verify failure**

```bash
go test ./internal/readconnector ./internal/readconnector/schema ./internal/readtask -run 'TestVictoriaTraces' -count=1
```

Expected: FAIL because trace connector types are absent.

- [ ] **Step 3: Implement the exact trace typed union**

```go
const KindVictoriaTraces Kind = "VICTORIATRACES"

const (
    OpVTListServices   Operation = "list_services"
    OpVTListOperations Operation = "list_operations"
    OpVTFindTraces     Operation = "find_traces"
    OpVTGetTrace       Operation = "get_trace"
    OpVTDependencies   Operation = "dependencies"
    OpVTClusterHealth  Operation = "cluster_health"
)

type VictoriaTracesDefinition struct {
    CapabilityCode       string
    Operation            Operation
    ServiceNames         []string
    OperationNames       []string
    TagFilters           map[string]string
    AllowedTagKeys       []string
    HiddenFieldsFilters  []string
    MinLookbackSeconds   int
    MaxLookbackSeconds   int
    MinDurationMicros    int64
    MaxDurationMicros    int64
    Limit                int
    ServiceGraphRequired bool
    MaxResultItems       int
    MaxResultBytes       int
    MaxDurationSeconds   int
    EvidenceSchema       string
    DLPProfileDigest     string
}

type VictoriaTracesTaskInput struct {
    LookbackSeconds *int   `json:"lookback_seconds,omitempty"`
    ServiceName     string `json:"service_name,omitempty"`
    TraceID         string `json:"trace_id,omitempty"`
}
```

Service/operation strings are UTF-8, trimmed, `1..256` bytes and maximum 32 entries; tag key/value `1..128/512` bytes and maximum 16 pairs; hidden filters maximum 16 fixed strings; limit `1..200`; lookback `60..86400`; durations nonnegative and ordered; common budget ranges follow README. `list_operations` requires `ServiceName` to equal one literal `ServiceNames` allowlist member; `get_trace` requires TraceID; find/dependencies require lookback; every operation rejects fields belonging to another union branch; list-services/health accept an empty object only.

- [ ] **Step 4: Implement minimal evidence DTOs**

```go
type TraceSummary struct {
    TraceID        string   `json:"trace_id"`
    Services       []string `json:"services"`
    Operations     []string `json:"operations"`
    StartTimeMicros int64   `json:"start_time_micros"`
    DurationMicros int64    `json:"duration_micros"`
    SpanCount      int      `json:"span_count"`
    ErrorSpanCount int      `json:"error_span_count"`
}

type SpanSummary struct {
    SpanID          string            `json:"span_id"`
    ParentSpanID    string            `json:"parent_span_id,omitempty"`
    Service         string            `json:"service"`
    Operation       string            `json:"operation"`
    StartTimeMicros int64             `json:"start_time_micros"`
    DurationMicros  int64             `json:"duration_micros"`
    Status          string            `json:"status"`
    AllowedTags     map[string]string `json:"allowed_tags,omitempty"`
}

type TraceDetail struct {
    Summary TraceSummary  `json:"summary"`
    Spans   []SpanSummary `json:"spans"`
}

type DependencyEdge struct {
    Parent    string `json:"parent"`
    Child     string `json:"child"`
    CallCount uint64 `json:"call_count"`
}
```

Services/operations evidence is a sorted unique string array. Find returns summaries only. Get returns one detail with at most the published span limit. Dependencies sort by call count descending, then parent/child. Status is strict `OK|ERROR|UNSET`; only allowed tags survive projection, then DLP validates their values.

- [ ] **Step 5: Run connector tests**

```bash
go test ./internal/readconnector ./internal/readconnector/schema ./internal/readtask -run 'TestVictoriaTraces' -count=1
```

Expected: PASS with stable manifests across randomized map/list order.

- [ ] **Step 6: Commit trace contracts**

```bash
git add internal/readconnector/types.go internal/readconnector/contracts.go internal/readconnector/contracts_test.go internal/readconnector/victoriatraces.go internal/readconnector/victoriatraces_test.go internal/readconnector/schema/victoriatraces.go internal/readconnector/schema/victoriatraces_test.go
git commit -m "feat(read): define VictoriaTraces contracts"
```

### Task 2: Execute Jaeger queries with tenant isolation and DLP

**Files:**
- Create: `internal/readexecutor/victoriatraces.go`
- Create: `internal/readexecutor/victoriatraces_test.go`
- Modify: `internal/readexecutor/endpoint_guard.go`
- Modify: `internal/readexecutor/endpoint_guard_test.go`
- Modify: `internal/readexecutor/dlp.go`
- Modify: `internal/readexecutor/dlp_test.go`
- Modify: `internal/readtask/evidence_fields.go`
- Modify: `internal/readtask/evidence_fields_test.go`

**Interfaces:**
- Consumes: private Traces Target, compiled connector manifest, task input and runtime security closure.
- Produces: schema/DLP-valid canonical trace evidence and low-sensitivity completion.
- Safety: upstream Jaeger object is an internal parse-only type; projector copies approved fields and zeroes source buffers before artifact write.

- [ ] **Step 1: Write failing endpoint, parser and safety tests**

```go
func TestVictoriaTracesExecutesEveryOperation(t *testing.T)
func TestVictoriaTracesUsesServerOwnedTenantHeaders(t *testing.T)
func TestVictoriaTracesFindUsesMicrosecondsAndDependenciesMilliseconds(t *testing.T)
func TestVictoriaTracesProjectorDropsUnapprovedTagsLogsProcessesAndWarnings(t *testing.T)
func TestVictoriaTracesRejectsDLPBeforeEvidenceCompletion(t *testing.T)
func TestVictoriaTracesRejectsPartialOversizeAndMalformedJaegerResponses(t *testing.T)
func TestVictoriaTracesIngestionEndpointsHaveZeroNetworkRequests(t *testing.T)
func TestVictoriaTracesErrorsLogsAndEvidenceDoNotContainTenantOrCanary(t *testing.T)
```

Negative table includes `/insert/opentelemetry/v1/traces`, `/v1/traces`, `/api/traces`, `/api/v2/spans`, Zipkin ingestion, vtinsert port 10481, vtstorage port 10491, `/internal`, `/admin`, `/delete` and any POST body carrying spans.

- [ ] **Step 2: Run tests and verify failure**

```bash
go test ./internal/readexecutor ./internal/readtask -run 'TestVictoriaTraces' -count=1
```

Expected: FAIL because trace executor is absent.

- [ ] **Step 3: Implement exact request builders**

URL-escape validated service and trace IDs as path segments. `find_traces` uses current UTC time, calculates `[start,end)` in microseconds, and adds definition-owned service/operation/tags/minDuration/maxDuration/limit. `dependencies` calculates `endTs` and `lookback` in milliseconds. Append each fixed `hidden_fields_filters` value from the definition. Sort query keys/values before encoding.

- [ ] **Step 4: Parse and project Jaeger responses**

Require HTTP 200, `data` of the expected shape, no nonempty errors, no partial marker and exact EOF. Use `io.LimitReader(max+1)` and a depth-limited decoder. Map process IDs to service names only in parse memory; compute summary and approved span fields; do not retain raw tag/log/process maps after projection. Validate trace/span IDs as lowercase hex, duration/start as nonnegative safe integers, counts and array limits before DLP.

- [ ] **Step 5: Extend endpoint and DLP guards**

Endpoint guard permits only GET on the six paths and only Single/Select/Governed Proxy roles. It rejects every insertion/storage/admin path before network. DLP applies existing key/value detectors plus configured customer identifier patterns to service, operation and tag values; a match returns `VICTORIAMETRICS_EVIDENCE_DLP_REJECTED` with count only.

- [ ] **Step 6: Run trace execution tests**

```bash
go test -race ./internal/readexecutor ./internal/readtask -run 'TestVictoriaTraces' -count=1
```

Expected: PASS; ingestion cases make zero requests, rejected evidence creates no artifact/completion and canaries are absent from all captured surfaces.

- [ ] **Step 7: Commit trace execution**

```bash
git add internal/readexecutor/victoriatraces.go internal/readexecutor/victoriatraces_test.go internal/readexecutor/endpoint_guard.go internal/readexecutor/endpoint_guard_test.go internal/readexecutor/dlp.go internal/readexecutor/dlp_test.go internal/readtask/evidence_fields.go internal/readtask/evidence_fields_test.go
git commit -m "feat(read): execute governed VictoriaTraces queries"
```

### Task 3: Introduce a backward-compatible runtime profile registry

**Files:**
- Modify: `internal/readexecutor/profile.go`
- Modify: `internal/readexecutor/profile_test.go`
- Create: `internal/readexecutor/profile_registry.go`
- Create: `internal/readexecutor/profile_registry_test.go`
- Modify: `internal/readruntime/bundle.go`
- Modify: `internal/readruntime/bundle_test.go`
- Create: `internal/readruntime/validator.go`
- Create: `internal/readruntime/validator_test.go`

**Interfaces:**
- Consumes: immutable Target/Connector/Evidence artifacts, Compatibility Profile and runtime publication digest.
- Produces: exact profile lookup, v1 compatibility and a new Victoria profile supporting all 18 operations.
- Safety: registry keys by full SHA-256 digest; no “latest” fallback occurs during execution.

- [ ] **Step 1: Write failing compatibility and closure tests**

```go
func TestLegacyReadExecutorProfileDigestNeverChanges(t *testing.T)
func TestProfileRegistryResolvesLegacyAndVictoriaProfilesByDigest(t *testing.T)
func TestProfileRegistryRejectsUnknownDigestWithoutFallback(t *testing.T)
func TestVictoriaProfileContainsExactlyEighteenOperations(t *testing.T)
func TestRuntimeBundleRequiresMatchingTargetConnectorEvidenceAndExecutorVersions(t *testing.T)
func TestRuntimeBundleRejectsCrossScopeCrossRealmAndNonAppliedPublication(t *testing.T)
func TestRuntimeBundleNAndNPlusOneCanValidateConcurrently(t *testing.T)
```

- [ ] **Step 2: Run tests and verify failure**

```bash
go test ./internal/readexecutor ./internal/readruntime -run 'TestLegacyReadExecutor|TestProfileRegistry|TestVictoriaProfile|TestRuntimeBundle' -count=1
```

Expected: FAIL because only singleton profile construction exists.

- [ ] **Step 3: Preserve v1 and add explicit registry APIs**

```go
const LegacyProfileDigest = "d776a2e45f33496a8a2558fba82096064c3aed10be588627a337e70983485e63"

type ProfileRegistry struct {
    byDigest map[string]Profile
}

func NewProfileRegistry(profiles ...Profile) (*ProfileRegistry, error)
func (r *ProfileRegistry) Get(digest string) (Profile, error)
func LegacyProfileV1() Profile
func VictoriaProfileV2() Profile
```

Keep existing `NewProfile()` returning byte-identical v1 for source compatibility. `VictoriaProfileV2` has a new profile ID, canonical operation list, exact accepted Target/Connector/Evidence schema versions and all endpoint guard rules. Its digest is calculated from canonical bytes and pinned in a golden test after implementation review.

- [ ] **Step 4: Validate the full bundle closure**

```go
type VersionClosure struct {
    TargetSchemaVersion    string
    ConnectorSchemaVersion string
    EvidenceSchemaVersion  string
    ExecutorProfileDigest  string
    CompatibilityDigest    string
    RuntimePublicationDigest string
}

func (v *Validator) ValidateBundle(context.Context, Bundle, VersionClosure) error
```

Validator checks artifact digests, schema versions, Scope, target reference, capability definition revision, credential/network/realm closure, Asset ACTIVE/EXACT, compatibility PUBLISHED, runtime publication APPLIED and profile registry membership. Every mismatch returns `CAPABILITY_PROFILE_INCOMPATIBLE` without executing.

- [ ] **Step 5: Run registry and bundle tests**

```bash
go test -race ./internal/readexecutor ./internal/readruntime -run 'TestLegacyReadExecutor|TestProfileRegistry|TestVictoriaProfile|TestRuntimeBundle' -count=1
```

Expected: PASS; legacy golden remains exact and N/N+1 validate simultaneously.

- [ ] **Step 6: Commit versioned profiles**

```bash
git add internal/readexecutor/profile.go internal/readexecutor/profile_test.go internal/readexecutor/profile_registry.go internal/readexecutor/profile_registry_test.go internal/readruntime/bundle.go internal/readruntime/bundle_test.go internal/readruntime/validator.go internal/readruntime/validator_test.go
git commit -m "feat(runtime): version Victoria read profiles"
```

### Task 4: Publish, dispatch, drift-stop and roll back N/N+1 safely

**Files:**
- Modify: `internal/runtimepublication/service.go`
- Modify: `internal/runtimepublication/service_test.go`
- Create: `internal/runtimepublication/victoria_validator.go`
- Create: `internal/runtimepublication/victoria_validator_test.go`
- Create: `internal/readruntime/dispatcher.go`
- Create: `internal/readruntime/dispatcher_test.go`
- Create: `internal/readruntime/drift_monitor.go`
- Create: `internal/readruntime/drift_monitor_test.go`
- Modify: `cmd/read-runner/main.go`
- Modify: `cmd/read-runner/main_test.go`

**Interfaces:**
- Consumes: validated Connection Contract/Profile closure, runtime artifact repository and profile registry.
- Produces: APPLIED N+1 publication, task-captured profile dispatch, drift stop and explicit rollback.
- Safety: validation sends only health and schema-safe read probes; no insertion or arbitrary query is ever used.

- [ ] **Step 1: Write failing rollout and dispatcher tests**

```go
func TestVictoriaPublicationValidatesAllArtifactDigestsBeforeApplying(t *testing.T)
func TestVictoriaPublicationValidationNeverCallsIngestionEndpoint(t *testing.T)
func TestNewGrantUsesOnlyAppliedNPlusOne(t *testing.T)
func TestInFlightNTaskContinuesOnLegacyProfile(t *testing.T)
func TestDispatcherRejectsProfileSubstitutionAndCrossScopeTask(t *testing.T)
func TestDriftStopsNewAndQueuedExecution(t *testing.T)
func TestRollbackSwitchesNewGrantToNWithoutRewritingTasks(t *testing.T)
func TestReadRunnerProductionAssemblyRegistersBothProfiles(t *testing.T)
```

- [ ] **Step 2: Run tests and verify failure**

```bash
go test ./internal/runtimepublication ./internal/readruntime ./cmd/read-runner -run 'TestVictoriaPublication|TestNewGrant|TestInFlightN|TestDispatcher|TestDrift|TestRollback|TestReadRunner' -count=1
```

Expected: FAIL because Victoria rollout integration and registry assembly are absent.

- [ ] **Step 3: Implement safe publication validation**

Validation order is: Scope/Asset/contract status → compatibility closure → artifact digest/signature → profile registry → TLS/network/credential/realm → health endpoint → one definition-owned smallest read probe per family → evidence schema/DLP → cleanup receipt. Metrics probe is label names with 60-second window and limit 1; Logs probe is field values with 60-second window and limit 1; Traces probe is list services with limit 1. Unknown version or response shape remains REJECTED.

- [ ] **Step 4: Bind dispatch to captured publication/profile**

Persist `runtime_publication_id`, `runtime_publication_digest`, `executor_profile_digest`, Target/Connector/Evidence schema versions and compatibility digest on task creation. Dispatcher loads exactly those values and profile; it never resolves the currently active version for an existing task.

- [ ] **Step 5: Implement drift and rollback behavior**

Drift monitor periodically hashes deployed artifacts and compares runtime heartbeat profile digest. A mismatch moves publication to DRIFTED, closes admission and cancels queued/not-started tasks with stable code; already running request is canceled at the next context boundary. Rollback transaction activates a prior APPLIED, unrevoked publication for future grants and records audit/outbox; task rows remain immutable.

- [ ] **Step 6: Assemble both profiles in production**

`cmd/read-runner/main.go` constructs `NewProfileRegistry(LegacyProfileV1(), VictoriaProfileV2())`, registers Metrics/Logs/Traces executors and endpoint guard, and requires the registry before health becomes ready. No fake client or permissive default is present.

- [ ] **Step 7: Run rollout tests**

```bash
go test -race ./internal/runtimepublication ./internal/readruntime ./cmd/read-runner -run 'TestVictoriaPublication|TestNewGrant|TestInFlightN|TestDispatcher|TestDrift|TestRollback|TestReadRunner' -count=1
```

Expected: PASS; legacy N and new N+1 run concurrently, drift stops execution and rollback changes only future admission.

- [ ] **Step 8: Commit runtime rollout**

```bash
git add internal/runtimepublication/service.go internal/runtimepublication/service_test.go internal/runtimepublication/victoria_validator.go internal/runtimepublication/victoria_validator_test.go internal/readruntime/dispatcher.go internal/readruntime/dispatcher_test.go internal/readruntime/drift_monitor.go internal/readruntime/drift_monitor_test.go cmd/read-runner/main.go cmd/read-runner/main_test.go
git commit -m "feat(runtime): publish Victoria read bundle safely"
```

## Pack Completion Gate

```bash
go test -race ./internal/readconnector ./internal/readconnector/schema ./internal/readexecutor ./internal/readtask ./internal/readruntime ./internal/runtimepublication ./cmd/read-runner -run 'TestVictoriaTraces|TestLegacyReadExecutor|TestProfileRegistry|TestVictoriaProfile|TestRuntimeBundle|TestVictoriaPublication|TestNewGrant|TestInFlightN|TestDrift|TestRollback|TestReadRunner' -count=1
go vet ./internal/readconnector ./internal/readconnector/schema ./internal/readexecutor ./internal/readtask ./internal/readruntime ./internal/runtimepublication ./cmd/read-runner
git diff --check
```

Expected: all commands exit 0; six trace capabilities are bounded and DLP-safe; legacy digest unchanged; profile substitution, ingestion, drift and incompatible closure are closed before unsafe side effects.
