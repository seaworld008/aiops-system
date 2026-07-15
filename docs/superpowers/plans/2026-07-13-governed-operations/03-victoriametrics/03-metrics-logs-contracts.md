# VictoriaMetrics and VictoriaLogs Read Contracts Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 实现 VictoriaMetrics 与 VictoriaLogs 共 12 个类型化只读能力，从服务端 Capability Definition 到私有 Target route、隔离执行、严格证据 schema 与 ingestion/tool 负向封锁形成闭环。

**Architecture:** Connector manifest 固定查询、字段、投影和预算，任务只携带有限时间窗口或评估偏移；私有 Target 从 Connection Contract 构造产品/拓扑/租户路由。Executor 依据 `(kind,operation,schema_version)` 选择唯一请求 builder，固定 method/path/headers，流式限额解析后执行 schema、JCS、DLP，再生成 evidence completion。

**Tech Stack:** Go 1.26.5、现有 `readconnector`/`readtarget`/`readexecutor`/`readtask` runtime、Prometheus HTTP API、VictoriaLogs LogsQL API、`net/http`、`json.Decoder`、RFC 8785 JCS、SHA-256。

## Global Constraints

- 每个 Task 严格采用 Red → Green → Refactor：先运行并保存预期失败，再做最小生产实现，复跑指定测试后才允许重构和提交。
- 保留 legacy `PROMETHEUS/range_query` 与 `VICTORIALOGS/search` manifest bytes 和 profile digest；本包新增版本化定义，不原地改变已发布 bundle N。
- 只实现 README 能力矩阵中的 12 个 operation；未知 operation、schema 或 provider fail closed。
- Query、LogsQL、label/field、projection、match selector、step、limit、topN 全部属于服务端 Capability Definition；task/model 不能自由提交。
- Dynamic task input 只允许 schema 明示的 `lookback_seconds`、`evaluation_offset_seconds`；其他键、路径、URL、header、tenant、query 字符串一律拒绝。
- Tenant route 只从私有 Target artifact 注入。公共 API、日志、metric label、错误、evidence 与 completion 不得出现 tenant value。
- Metrics query/labels 使用 POST form；health/capacity 使用 GET。Logs 全部使用 POST form。禁止 redirect、proxy、compression、HTTP/2 connection coalescing 和跨 origin DNS/IP 漂移。
- Executor 必须先验证 endpoint origin、TLS 1.3、network policy、credential revision、realm、runtime publication 和 manifest digest，再发送请求。
- 响应必须在 duration/items/bytes/depth/string budget 内完整解析；任何 partial、截断、未知顶层字段、重复 JSON key、NaN/Inf 或 trailing bytes 都拒绝。
- DLP 发生在 evidence artifact/completion 之前；失败只返回固定低敏 code 和计数。
- Insert/import/write/delete/admin/storage/tool 路由在 builder 与 transport guard 两层拒绝，并有网络零请求证明。
- 新增行为严格 TDD，每个 Task 独立提交。

---

## Capability Contract Summary

| Family | Operation | Method/path suffix | Evidence schema |
|---|---|---|---|
| Metrics | `instant_query` | POST `/api/v1/query` | `victoriametrics.instant-query.evidence.v1` |
| Metrics | `range_query` | POST `/api/v1/query_range` | `victoriametrics.range-query.evidence.v1` |
| Metrics | `label_names` | POST `/api/v1/labels` | `victoriametrics.label-names.evidence.v1` |
| Metrics | `label_values` | POST `/api/v1/label/{label_name}/values` | `victoriametrics.label-values.evidence.v1` |
| Metrics | `cluster_health` | GET `/health` | `victoria.health.evidence.v1` |
| Metrics | `capacity_snapshot` | GET `/api/v1/status/tsdb` | `victoriametrics.capacity.evidence.v1` |
| Logs | `search` | POST `/select/logsql/query` | `victorialogs.search.evidence.v1` |
| Logs | `hits` | POST `/select/logsql/hits` | `victorialogs.hits.evidence.v1` |
| Logs | `facets` | POST `/select/logsql/facets` | `victorialogs.facets.evidence.v1` |
| Logs | `stats_range` | POST `/select/logsql/stats_query_range` | `victorialogs.stats-range.evidence.v1` |
| Logs | `field_values` | POST `/select/logsql/field_values` | `victorialogs.field-values.evidence.v1` |
| Logs | `cluster_health` | GET `/health` | `victoria.health.evidence.v1` |

Cluster Metrics prefixes the suffix with `/select/{account[:project]}/prometheus` or `/select/prometheus` under a validated header profile. Logs path stays exact and receives server-owned headers. Governed proxy uses an allowlisted route profile whose resolved prefix is part of the Target digest.

### Task 1: Add typed VictoriaMetrics connector definitions and evidence schemas

**Files:**
- Modify: `internal/readconnector/types.go`
- Modify: `internal/readconnector/contracts.go`
- Modify: `internal/readconnector/contracts_test.go`
- Create: `internal/readconnector/victoriametrics.go`
- Create: `internal/readconnector/victoriametrics_test.go`
- Create: `internal/readconnector/schema/victoriametrics.go`
- Create: `internal/readconnector/schema/victoriametrics_test.go`

**Interfaces:**
- Consumes: published capability definitions and safe task input.
- Produces: `KindVictoriaMetrics`, six exact operations, canonical connector manifests and six evidence validators.
- Safety: definition/task fields are disjoint; connector digest binds query, projection, budgets and schema revisions.

- [ ] **Step 1: Write failing connector contract tests**

```go
func TestVictoriaMetricsCapabilitiesAreCompleteAndUnique(t *testing.T)
func TestVictoriaMetricsDefinitionOwnsQueryAndProjection(t *testing.T)
func TestVictoriaMetricsTaskInputRejectsQueryPathHeaderAndTenant(t *testing.T)
func TestVictoriaMetricsManifestDigestChangesWithEverySecurityField(t *testing.T)
func TestVictoriaMetricsEvidenceSchemasRejectUnknownFieldsAndBudgets(t *testing.T)
func TestVictoriaMetricsEvidenceRejectsNaNInfinityAndDuplicateKeys(t *testing.T)
```

Mutation-test every field: capability code, operation, query, label name, selectors, allowed labels, lookback bounds, step, topN, duration, items, bytes, evidence schema and DLP profile. Each mutation must change manifest digest or make validation fail.

- [ ] **Step 2: Run tests and verify failure**

```bash
go test ./internal/readconnector ./internal/readconnector/schema ./internal/readtask -run 'TestVictoriaMetrics' -count=1
```

Expected: FAIL because `KindVictoriaMetrics` and definitions are absent.

- [ ] **Step 3: Implement the exact typed union**

```go
const KindVictoriaMetrics Kind = "VICTORIAMETRICS"

const (
    OpVMInstantQuery     Operation = "instant_query"
    OpVMRangeQuery       Operation = "range_query"
    OpVMLabelNames       Operation = "label_names"
    OpVMLabelValues      Operation = "label_values"
    OpVMClusterHealth    Operation = "cluster_health"
    OpVMCapacitySnapshot Operation = "capacity_snapshot"
)

type VictoriaMetricsDefinition struct {
    CapabilityCode     string
    Operation          Operation
    Query              string
    LabelName          string
    MatchSelectors     []string
    AllowedLabelKeys   []string
    MinLookbackSeconds int
    MaxLookbackSeconds int
    StepSeconds        int
    TopN               int
    MaxDurationSeconds int
    MaxResultItems     int
    MaxResultBytes     int
    EvidenceSchema     string
    DLPProfileDigest   string
}

type VictoriaMetricsTaskInput struct {
    LookbackSeconds         *int `json:"lookback_seconds,omitempty"`
    EvaluationOffsetSeconds *int `json:"evaluation_offset_seconds,omitempty"`
}
```

Validation rules: query length `1..4096`; label names match `[a-zA-Z_][a-zA-Z0-9_]*`; selectors length `1..512`, maximum 8 and sorted unique; allowed labels maximum 32; lookback `60..86400`; step `1..3600` and not greater than lookback; topN `1..100`; duration `1..20`; items `1..1000`; bytes `1024..1048576`. Health has no dynamic input; capacity only uses server-owned topN.

- [ ] **Step 4: Implement exact evidence DTOs and validators**

```go
type MetricSample struct {
    Labels    map[string]string `json:"labels"`
    Timestamp int64             `json:"timestamp_ms"`
    Value     string            `json:"value"`
}

type MetricSeries struct {
    Labels  map[string]string `json:"labels"`
    Samples []MetricPoint     `json:"samples"`
}

type MetricPoint struct {
    Timestamp int64  `json:"timestamp_ms"`
    Value     string `json:"value"`
}

type NameCount struct {
    Name  string `json:"name"`
    Count uint64 `json:"count"`
}

type CapacitySnapshot struct {
    SeriesCountByMetricName   []NameCount `json:"series_count_by_metric_name"`
    LabelValueCountByName     []NameCount `json:"label_value_count_by_name"`
    SeriesCountByLabelPair    []NameCount `json:"series_count_by_label_pair"`
}
```

Project only allowed label keys, sort label maps during canonicalization, normalize timestamps to integer milliseconds and numeric values to finite decimal strings. Labels/values are string arrays sorted bytewise with duplicates removed. Capacity arrays are at most TopN and sorted by count descending then name ascending. Health evidence is exactly `{"healthy":true,"checked_at":"RFC3339Nano"}`; upstream body is never copied.

- [ ] **Step 5: Run connector and schema tests**

```bash
go test ./internal/readconnector ./internal/readconnector/schema ./internal/readtask -run 'TestVictoriaMetrics' -count=1
```

Expected: PASS; manifests are deterministic over 100 input permutations.

- [ ] **Step 6: Commit Metrics connector contracts**

```bash
git add internal/readconnector/types.go internal/readconnector/contracts.go internal/readconnector/contracts_test.go internal/readconnector/victoriametrics.go internal/readconnector/victoriametrics_test.go internal/readconnector/schema/victoriametrics.go internal/readconnector/schema/victoriametrics_test.go
git commit -m "feat(read): define VictoriaMetrics contracts"
```

### Task 2: Build private Metrics routes and isolated execution

**Files:**
- Create: `internal/readtarget/victoria.go`
- Create: `internal/readtarget/victoria_test.go`
- Create: `internal/readexecutor/victoriametrics.go`
- Create: `internal/readexecutor/victoriametrics_test.go`
- Create: `internal/readexecutor/dlp.go`
- Create: `internal/readexecutor/dlp_test.go`
- Create: `internal/readexecutor/endpoint_guard.go`
- Create: `internal/readexecutor/endpoint_guard_test.go`
- Modify: `internal/readexecutor/executor.go`
- Modify: `internal/readexecutor/executor_test.go`

**Interfaces:**
- Consumes: private Connection Contract, compiled Metrics connector manifest, task input and existing fixed bearer/TLS/network-policy target closure.
- Produces: exact HTTP requests and schema-validated evidence bytes/digest.
- Safety: route builder owns tenant; guard denies every non-query Victoria endpoint before DNS/network access.

- [ ] **Step 1: Write failing routing and execution tests**

```go
func TestVictoriaMetricsSingleRoutesEveryOperation(t *testing.T)
func TestVictoriaMetricsClusterPathTenantIsServerOwned(t *testing.T)
func TestVictoriaMetricsClusterHeaderTenantIsServerOwned(t *testing.T)
func TestVictoriaMetricsGovernedProxyRequiresExactRouteDigest(t *testing.T)
func TestVictoriaMetricsExecutorEnforcesMethodContentTypeAndNoRedirect(t *testing.T)
func TestVictoriaMetricsExecutorParsesEveryEvidenceShape(t *testing.T)
func TestVictoriaMetricsExecutorRejectsPartialOversizeAndUnknownFields(t *testing.T)
func TestVictoriaMetricsExecutorRejectsDLPBeforeEvidenceCompletion(t *testing.T)
func TestVictoriaMetricsIngestionEndpointsHaveZeroNetworkRequests(t *testing.T)
func TestVictoriaMetricsErrorsLogsAndEvidenceDoNotContainTenant(t *testing.T)
```

The negative table includes `/api/v1/write`, `/api/v1/import`, `/api/v1/import/prometheus`, `/insert/0/prometheus`, `/delete/0/prometheus`, `/snapshot/create`, `/internal/resetRollupResultCache`, vminsert port 8480 and vmstorage port 8482.

- [ ] **Step 2: Run tests and verify failure**

```bash
go test ./internal/readtarget ./internal/readexecutor -run 'TestVictoriaMetrics' -count=1
```

Expected: FAIL because Victoria Target and executor do not exist.

- [ ] **Step 3: Implement the private route artifact**

```go
type VictoriaTarget struct {
    Family               victoriametrics.Family
    Topology             victoriametrics.Topology
    TargetRole           victoriametrics.Role
    Origin               HTTPSOrigin
    TenantRoute          victoriametrics.TenantRoute
    RouteProfileDigest   string
    CredentialRevision   CredentialRevisionRef
    NetworkPolicyRef     string
    RunnerRealmID        string
    TargetSchemaVersion  string
    ContractDigest       string
}

func CompileVictoriaTarget(victoriametrics.ConnectionContract, HTTPSOrigin, SecurityClosure) (VictoriaTarget, error)
func (t VictoriaTarget) RequestRoute(readconnector.Operation) (PrivateRequestRoute, error)
```

`PrivateRequestRoute` is not serializable to public DTOs. Metrics Single prefixes nothing; cluster path constructs `strconv.FormatUint(account,10)` plus optional `:` project; header mode uses `/select/prometheus` and injects decimal `AccountID`/`ProjectID`; governed proxy resolves only a registry-known prefix matching `RouteProfileDigest`.

- [ ] **Step 4: Implement exact Metrics request builders**

`instant_query` sends server query and `time=now-evaluation_offset`; `range_query` sends query/start/end/step; labels send start/end and fixed `match[]`; label values additionally URL-escapes validated label name; capacity sends fixed `topN`; health has no parameters. Use UTC epoch seconds with no client-provided absolute timestamps. Form keys are sorted before encoding.

- [ ] **Step 5: Implement the transport guard and streaming parser**

The guard checks family/role/port/path against a literal operation table after path construction and again immediately before `RoundTrip`. It rejects insert/storage roles and any path containing `/write`, `/insert`, `/import`, `/delete`, `/snapshot`, `/internal`, `/admin`, `/otlp`, `/prometheus/api/v1/write`. HTTP client uses no environment proxy, redirect returns `http.ErrUseLastResponse`, compression is disabled and response body is read through `io.LimitReader(maxBytes+1)`.

Prometheus responses require `status=success`, exact `data.resultType` for the operation and no `warnings`/`isPartial`/unknown top-level fields. Non-2xx body is discarded after 4 KiB and converted to a stable code. Run the shared fixed DLP profile over allowed label names/values and capacity names before JCS/artifact construction；secret-like key/value, disallowed email/IP/customer identifier or overlong text returns `VICTORIAMETRICS_EVIDENCE_DLP_REJECTED` without retaining the match.

- [ ] **Step 6: Run execution tests**

```bash
go test -race ./internal/readtarget ./internal/readexecutor -run 'TestVictoriaMetrics' -count=1
```

Expected: PASS; all negative endpoint cases record zero upstream requests and tenant canaries never appear in observable output.

- [ ] **Step 7: Commit Metrics execution**

```bash
git add internal/readtarget/victoria.go internal/readtarget/victoria_test.go internal/readexecutor/victoriametrics.go internal/readexecutor/victoriametrics_test.go internal/readexecutor/dlp.go internal/readexecutor/dlp_test.go internal/readexecutor/endpoint_guard.go internal/readexecutor/endpoint_guard_test.go internal/readexecutor/executor.go internal/readexecutor/executor_test.go
git commit -m "feat(read): execute governed VictoriaMetrics queries"
```

### Task 3: Add typed VictoriaLogs connector definitions and evidence schemas

**Files:**
- Modify: `internal/readconnector/types.go`
- Modify: `internal/readconnector/contracts.go`
- Modify: `internal/readconnector/contracts_test.go`
- Create: `internal/readconnector/victorialogs_v2.go`
- Create: `internal/readconnector/victorialogs_v2_test.go`
- Create: `internal/readconnector/schema/victorialogs.go`
- Create: `internal/readconnector/schema/victorialogs_test.go`

**Interfaces:**
- Consumes: published VictoriaLogs capability definitions and safe time-window task input.
- Produces: six v2 operations without changing legacy v1 `VICTORIALOGS/search` bytes.
- Safety: LogsQL, fields and projection live only in definition; dynamic time window cannot expand published maximum.

- [ ] **Step 1: Write failing Logs connector and schema tests**

```go
func TestVictoriaLogsCapabilitiesAreCompleteAndUnique(t *testing.T)
func TestVictoriaLogsV1ManifestRemainsByteIdentical(t *testing.T)
func TestVictoriaLogsDefinitionOwnsLogsQLFieldsAndProjection(t *testing.T)
func TestVictoriaLogsTaskInputRejectsQueryFieldPathHeaderAndTenant(t *testing.T)
func TestVictoriaLogsEvidenceSchemasMatchAllFiveQueryShapes(t *testing.T)
func TestVictoriaLogsEvidenceRejectsUnknownFieldsDepthAndLongStrings(t *testing.T)
```

- [ ] **Step 2: Run tests and verify failure**

```bash
go test ./internal/readconnector ./internal/readconnector/schema -run 'TestVictoriaLogs' -count=1
```

Expected: FAIL because v2 operations and schemas are absent.

- [ ] **Step 3: Implement the Logs definition**

```go
const (
    OpVLSearch        Operation = "search"
    OpVLHits          Operation = "hits"
    OpVLFacets        Operation = "facets"
    OpVLStatsRange    Operation = "stats_range"
    OpVLFieldValues   Operation = "field_values"
    OpVLClusterHealth Operation = "cluster_health"
)

type VictoriaLogsDefinition struct {
    CapabilityCode     string
    Operation          Operation
    LogsQL             string
    FieldName          string
    AllowedFields      []string
    MinLookbackSeconds int
    MaxLookbackSeconds int
    StepSeconds        int
    Limit              int
    MaxDurationSeconds int
    MaxResultItems     int
    MaxResultBytes     int
    EvidenceSchema     string
    DLPProfileDigest   string
}
```

LogsQL length is `1..4096`; field names match `[A-Za-z_][A-Za-z0-9_.-]{0,127}`; allowed fields maximum 32; limit `1..1000`; lookback `60..86400`; step `1..3600`; common budgets match README. Health definition leaves LogsQL/field/time empty.

- [ ] **Step 4: Implement exact Logs evidence shapes**

```go
type LogRecord struct {
    Timestamp string            `json:"timestamp"`
    Fields    map[string]string `json:"fields"`
}

type HitsBucket struct {
    Fields     map[string]string `json:"fields"`
    Timestamps []string          `json:"timestamps"`
    Values     []uint64          `json:"values"`
    Total      uint64            `json:"total"`
}

type FacetValue struct {
    Value string `json:"value"`
    Hits  uint64 `json:"hits"`
}

type Facet struct {
    FieldName string       `json:"field_name"`
    Values    []FacetValue `json:"values"`
}

type FieldValue struct {
    Value string `json:"value"`
    Hits  uint64 `json:"hits"`
}
```

Stats range reuses `MetricSeries` with a schema-specific type. Project only allowed fields, normalize timestamps to RFC3339Nano UTC, sort maps and stable arrays, reject negative/overflow counts and mismatched `timestamps`/`values` lengths.

- [ ] **Step 5: Run Logs connector tests**

```bash
go test ./internal/readconnector ./internal/readconnector/schema -run 'TestVictoriaLogs' -count=1
```

Expected: PASS and legacy manifest digest unchanged.

- [ ] **Step 6: Commit Logs contracts**

```bash
git add internal/readconnector/types.go internal/readconnector/contracts.go internal/readconnector/contracts_test.go internal/readconnector/victorialogs_v2.go internal/readconnector/victorialogs_v2_test.go internal/readconnector/schema/victorialogs.go internal/readconnector/schema/victorialogs_test.go
git commit -m "feat(read): define VictoriaLogs query contracts"
```

### Task 4: Execute all VictoriaLogs operations with DLP and partial-response denial

**Files:**
- Create: `internal/readexecutor/victorialogs_v2.go`
- Create: `internal/readexecutor/victorialogs_v2_test.go`
- Modify: `internal/readexecutor/dlp.go`
- Modify: `internal/readexecutor/dlp_test.go`
- Modify: `internal/readexecutor/endpoint_guard.go`
- Modify: `internal/readexecutor/endpoint_guard_test.go`
- Modify: `internal/readtask/evidence_fields.go`
- Modify: `internal/readtask/evidence_fields_test.go`

**Interfaces:**
- Consumes: private Logs Target, v2 connector manifest, bounded lookback input and fixed credential/network/runtime closure.
- Produces: canonical schema-valid evidence completion for search/hits/facets/stats/field-values/health.
- Safety: `AccountID`/`ProjectID` are injected after logging hooks; partial response and DLP match prevent artifact creation.

- [ ] **Step 1: Write failing executor, DLP and negative-path tests**

```go
func TestVictoriaLogsExecutesEveryOperation(t *testing.T)
func TestVictoriaLogsUsesServerOwnedTenantHeaders(t *testing.T)
func TestVictoriaLogsSearchEnforcesLimitPlusOne(t *testing.T)
func TestVictoriaLogsRejectsPartialResponses(t *testing.T)
func TestVictoriaLogsRejectsDLPBeforeEvidenceCompletion(t *testing.T)
func TestVictoriaLogsIngestionEndpointsHaveZeroNetworkRequests(t *testing.T)
func TestVictoriaLogsToolsHaveNoConnectorDefinition(t *testing.T)
func TestVictoriaLogsErrorsLogsAndEvidenceDoNotContainTenantOrCanary(t *testing.T)
```

Negative routes include `/insert/jsonline`, `/insert/elasticsearch`, `/insert/loki/api/v1/push`, `/api/v1/write`, `/internal/force_merge`, `/delete`, vlinsert port 9481, vlstorage port 9491, and tool kinds `VMCTL`, `VMBACKUP`, `VMRESTORE`, `VMALERT_TOOL`.

- [ ] **Step 2: Run tests and verify failure**

```bash
go test ./internal/readexecutor ./internal/readtask -run 'TestVictoriaLogs' -count=1
```

Expected: FAIL because v2 executor and DLP are absent.

- [ ] **Step 3: Implement exact request forms**

All forms include server-owned query and `[start,end)` UTC timestamps. Search adds `limit=MaxResultItems+1` and fixed projected fields; hits adds fixed `field`; facets adds fixed `field` and `limit`; stats range adds fixed `step`; field values adds fixed `field` and `limit`. Never send `allow_partial_response=1`. Inject tenant headers in the final RoundTripper after audit-safe request metadata is recorded.

- [ ] **Step 4: Stream and validate upstream responses**

Search parses JSON Lines with a token/line length cap and fails if item `max+1` is observed. Other endpoints use `json.Decoder.DisallowUnknownFields`: hits requires `{hits:[...]}`, facets `{facets:[...]}`, field-values `{values:[...]}`, stats-range Prometheus matrix. Reject a partial marker in header, trailer or JSON; reject 206; require complete EOF before evidence construction.

- [ ] **Step 5: Implement the fixed DLP profile**

```go
type DLPProfile struct {
    Digest              string
    AllowedFieldNames   map[string]struct{}
    AllowedEmailFields  map[string]struct{}
    AllowedIPFields     map[string]struct{}
    SecretKeyPatterns   []*regexp.Regexp
    SecretValuePatterns []*regexp.Regexp
    CustomerIDPatterns  []*regexp.Regexp
    MaxStringBytes      int
    MaxDepth            int
}

type DLPResult struct {
    Allowed       bool
    ReasonCode    string
    MatchCount    int
}

func ValidateEvidence(profile DLPProfile, value any) DLPResult
```

Fixed key detectors cover password/passwd/secret/token/bearer/authorization/cookie/session/private_key/client_secret/access_key/dsn. Value detectors cover bearer/basic auth, PEM private key headers, credential URI and JWT-shaped values. Tokenize remaining strings and classify email、IPv4/IPv6 via `net/mail`/`net/netip` plus configured customer-ID patterns；only fields explicitly allowlisted for that class can pass. The result never stores matching key/value. Reject rather than redact so the canonical schema remains predictable.

- [ ] **Step 6: Ensure completion happens only after validation**

Order is: byte limit → parse → item/depth/string limits → operation schema → DLP → JCS → SHA-256 → artifact write → `EvidenceCompletion`. Any earlier failure produces no artifact URI/digest and no completion event.

- [ ] **Step 7: Run Logs execution tests**

```bash
go test -race ./internal/readexecutor ./internal/readtask -run 'TestVictoriaLogs' -count=1
```

Expected: PASS; partial/DLP/over-limit cases create no artifact, and all ingestion/tool cases make zero network requests.

- [ ] **Step 8: Commit Logs execution**

```bash
git add internal/readexecutor/victorialogs_v2.go internal/readexecutor/victorialogs_v2_test.go internal/readexecutor/dlp.go internal/readexecutor/dlp_test.go internal/readexecutor/endpoint_guard.go internal/readexecutor/endpoint_guard_test.go internal/readtask/evidence_fields.go internal/readtask/evidence_fields_test.go
git commit -m "feat(read): execute governed VictoriaLogs queries"
```

## Pack Completion Gate

```bash
go test -race ./internal/readconnector ./internal/readconnector/schema ./internal/readtarget ./internal/readexecutor ./internal/readtask -run 'TestVictoriaMetrics|TestVictoriaLogs' -count=1
go vet ./internal/readconnector ./internal/readconnector/schema ./internal/readtarget ./internal/readexecutor ./internal/readtask
git diff --check
```

Expected: all commands exit 0; 12 capabilities have exact endpoint/schema coverage; tenant/query material is server-owned; partial, DLP, ingestion and tool negatives fail before evidence or network side effects.
