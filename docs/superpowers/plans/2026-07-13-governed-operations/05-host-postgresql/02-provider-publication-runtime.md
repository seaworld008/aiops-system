# Host Probe, AWX, and PostgreSQL Provider Publication Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 把 `HOST_PROBE_MTLS`、`AWX_API`、`POSTGRESQL` 从 Provider 判别修订、Opaque Credential Reference 和真实隔离验证一路编译为内容寻址的 Target、Capability 与 Runtime，补齐已发布 AWX Runtime 驱动的 `AWX_INVENTORY` 增量发现，并证明 N/N+1 发布与各 Provider 门禁独立、可恢复且默认关闭。

**Architecture:** 本包扩展 Phase 2 唯一 Connection/Validation/Runtime 纵向链，不建立第二套连接系统，也不新增 `000019` 表。Control Plane 只接受引用 Asset 既有网络身份的判别结构，服务端解析为私有 Capsule；独立 Validation Runner 使用三种固定协议探针，成功且凭据清理确定后，compiler 才生成 Provider 专属不可变 Runtime。Runtime N+1 与 N 并存到精确 attestation 和 drain 完成，任一 Provider 的失败只关闭自身 gate；只有 exact AWX gate `AVAILABLE` 后，隔离 Source Runner 才可用同一内容寻址 Runtime 增量读取 Inventory 并交给 Phase 1 Reconciler。

**Tech Stack:** Go 1.26.5、PostgreSQL 18.4+、pgx/v5、TLS 1.3 mTLS、AWX REST API v2、RFC 8785 JCS、SHA-256、Phase 2 `connectionprofile`/`credentialreference`/`connectionvalidation`/`validationrunner`/`capability`/`runtimepublication`/`readruntime`。

## Global Constraints

- 每个 Task 严格执行 Red → Green → Refactor；必须先保存指定失败，再做最小实现，全部绿灯后才整理命名与提交。
- 只扩展 Phase 2 的稳定 Profile、immutable Revision、Validation lease/fencing、Published Target/Capability 和 Runtime Publication；不得复制表、队列、状态机或公共 DTO。
- 浏览器、模型、Task、Operation 和 Runner claim 不得携带 Secret、私钥、完整 DSN、任意 endpoint/header/body、命令、脚本或 SQL；私有 Capsule 只能携带服务端从同 Scope Asset 身份解析并签名的固定目标。
- `HOST_PROBE_MTLS` 仅固定身份/健康探针；`AWX_API` 仅固定 ping、身份、Inventory 与已发布只读模板元数据探针；`POSTGRESQL` 仅固定 TLS/只读事务/命名最小查询探针。
- Credential Reference 必须同 Scope、同 Provider、同固定 usage role 且 `ACTIVE`；Credential 只在 Start 后单次交付，成功前 cleanup 必须为 `REVOKED|NO_CREDENTIAL`。
- 未验证、未 attested、drift、cross-Scope、身份不匹配、凭据吊销不确定或结果 Schema 不确定的 Provider 保持 `UNAVAILABLE`；不能从其他 Provider 的状态推断可用。
- N 与 N+1 都不可变；新 admission 仅在 N+1 精确 `APPLIED` 后切换，在途运行固定 N，N+1 失败回滚到 N，drain 前不得删除或改写 N。
- `AWX_INVENTORY` Source 必须绑定同 Scope canonical Integration ID 与 exact AWX Runtime closure；增量页不做缺失判定，只有成功完成的全量 reconciliation 才能 soft-stale 缺失资产，恢复仍需重新验证后激活。
- fake、loopback transport 与内存 repository 只允许在 `*_test.go`；生产装配缺 Provider trust、issuer/revoker、Realm、Network Policy、Validation Runner 或 distributor 即 fail closed。

## Red → Green → Refactor

1. **Red:** Provider 联合、Capsule、探针、compiler、N/N+1 与独立 gate 测试先失败，失败原因必须是缺少新契约而非测试环境损坏。
2. **Green:** 只实现三种明确 Provider 和固定协议，不引入通用 HTTP/TCP/SQL/命令执行抽象。
3. **Refactor:** 绿灯后抽取仅含安全结构的共享 helper，运行 architecture/secret scan，确认没有扩大现有 Prometheus/VictoriaLogs 能力。

---

## Package Position

- 顺序：2 / 8；前置包 01 已创建 000019 contract facts 与 Registry，Phase 1–4/Phase 2 Connection 基线已验收。
- 交付给下一包：三种封闭 Provider Revision、真实 Validation Probe、typed Provider Runtime N/N+1、独立 readiness gate 与 `AWX_INVENTORY` Source Adapter。
- 本包只打开已独立验收的 Provider readiness 和 AWX discovery gate，不打开 Host/PostgreSQL diagnostic capability 或全局 READ Admission。

### Task 3: 扩展 Provider 判别修订、Credential Reference 与私有 Validation Capsule

**Files:**
- Modify: `internal/connectionprofile/types.go`
- Modify: `internal/connectionprofile/revision.go`
- Modify: `internal/connectionprofile/revision_test.go`
- Create: `internal/connectionprofile/diagnostic_provider.go`
- Create: `internal/connectionprofile/diagnostic_provider_test.go`
- Modify: `internal/credentialreference/reference.go`
- Create: `internal/credentialreference/provider_admission.go`
- Create: `internal/credentialreference/provider_admission_test.go`
- Modify: `internal/connectionvalidation/capsule.go`
- Modify: `internal/connectionvalidation/capsule_test.go`
- Create: `internal/connectionvalidation/diagnostic_capsule.go`
- Create: `internal/connectionvalidation/diagnostic_capsule_test.go`
- Modify: `api/openapi/runner-v1.json`
- Modify: `api/openapi/runner_v1_test.go`

**Interfaces:**
- Consumes: Phase 1 same-Scope `assetcatalog.Asset`/network identity；Phase 2 `connectionprofile.Revision`、`credentialreference.Reference`、signed `connectionvalidation.Capsule`、VALIDATION Realm/lease。
- Produces:

```go
const (
    ProviderHostProbe  connectionprofile.Provider = "HOST_PROBE_MTLS"
    ProviderAWX        connectionprofile.Provider = "AWX_API"
    ProviderPostgreSQL connectionprofile.Provider = "POSTGRESQL"
)

type DiagnosticEndpoint interface {
    Provider() connectionprofile.Provider
    AssetIdentityID() string
    CanonicalDigest() string
    diagnosticEndpoint()
}

type HostProbeEndpoint struct {
    AssetNetworkIdentityID string
    ServerName             string
    ListenerProfile        string // HOST_PROBE_8443 | HOST_PROBE_9443
}

type AWXEndpoint struct {
    IntegrationID               string
    ControllerAssetID          string
    ControllerNetworkIdentityID string
    OrganizationReference     string
}

type PostgreSQLEndpoint struct {
    DatabaseAssetID        string
    AssetNetworkIdentityID string
    ServerName             string
    PortProfile            string // POSTGRESQL_5432 | POSTGRESQL_6432
    DatabaseReference      string
    ReplicaPreference      string // PRIMARY_ALLOWED | READ_REPLICA_REQUIRED
}

func AdmitDiagnosticReference(
    scope assetcatalog.Scope,
    provider connectionprofile.Provider,
    reference credentialreference.Reference,
) error

func BuildDiagnosticCapsule(
    connectionvalidation.BuildInput,
    DiagnosticEndpoint,
) (connectionvalidation.Capsule, error)
```

固定 Credential usage role：Host Probe 为 `HOST_PROBE_VALIDATION`，AWX 为 `AWX_READ_VALIDATION`，PostgreSQL 为 `POSTGRES_READ_VALIDATION`。三种 Capsule variant 只含服务端解析的字面 IP 集合、SNI/证书身份摘要、固定 probe ID、预算、Network Policy/Realm digest 和 Opaque reference digest；不含调用方 URL、header/body、SQL、命令、AWX token/template 数字 ID 或 DSN。AWX `IntegrationID` 必须来自 Phase 1 canonical installed Integration，Provider/Workspace 与 Connection 完全匹配，供发布后 Source 绑定，不能由浏览器生成。

- [ ] **Step 1: 写失败的 Provider 联合、引用与 Capsule 负向测试**

```go
func TestDiagnosticRevisionRequiresProviderDiscriminatedEndpoint(t *testing.T)
func TestDiagnosticRevisionRejectsForeignProviderFields(t *testing.T)
func TestDiagnosticRevisionRequiresAssetOwnedNetworkIdentity(t *testing.T)
func TestDiagnosticCredentialReferenceRequiresExactScopeProviderRoleAndRevision(t *testing.T)
func TestDiagnosticCapsuleRejectsURLHeaderBodyCommandSQLAndTemplateID(t *testing.T)
func TestDiagnosticCapsuleBindsRealmNetworkTrustAndRevisionDigests(t *testing.T)
func TestDiagnosticCapsuleDoesNotMarshalCredentialOrEndpointSource(t *testing.T)
```

测试表至少包含：Host payload 注入 `command/argv/path`；AWX payload 注入 `url/header/body/inventory_id/template_id/extra_vars`；PostgreSQL payload 注入 `dsn/sql/search_path/timeout`；未知字段、跨 Scope reference、错误 usage role、过期 reference、非 Asset-owned identity 均拒绝。

- [ ] **Step 2: 运行测试并确认 Red**

Run:

```bash
go test ./internal/connectionprofile ./internal/credentialreference ./internal/connectionvalidation ./api/openapi -run 'Diagnostic|HostProbe|AWX|PostgreSQL' -count=1
```

Expected: FAIL，因为三种 Provider 常量、判别 endpoint、引用 admission 和 Capsule variant 尚不存在。

- [ ] **Step 3: 实现严格 Provider schema 与 Credential Reference admission**

`NewRevision` 按 `provider_kind` 只接收一个 concrete endpoint；先以 `assetcatalog.NetworkIdentityReader` 解析 opaque ID，再校验 identity 属于 Revision Asset 或已治理 AWX Controller Asset、Scope 完全相同且 source-valid。Host/AWX/PostgreSQL 的 port 只能来自固定 profile enum，不能接受整数或 URL；PostgreSQL database 只能引用服务端 allowlist ID。

```go
var diagnosticUsageRole = map[connectionprofile.Provider]string{
    ProviderHostProbe:  "HOST_PROBE_VALIDATION",
    ProviderAWX:        "AWX_READ_VALIDATION",
    ProviderPostgreSQL: "POSTGRES_READ_VALIDATION",
}

func AdmitDiagnosticReference(
    scope assetcatalog.Scope,
    provider connectionprofile.Provider,
    reference credentialreference.Reference,
) error {
    role, ok := diagnosticUsageRole[provider]
    if !ok || reference.Scope() != scope ||
        reference.ProviderKind() != string(provider) ||
        reference.UsageRole() != role ||
        reference.Status() != credentialreference.StatusActive {
        return credentialreference.ErrReferenceUnavailable
    }
    return nil
}
```

所有 concrete endpoint 自己构造 canonical wire 并计算 SHA-256；不得提供 `map[string]any`、raw JSON 或通用 URL getter。公开 `Revision` projection 只返回 identity/reference ID、固定 enum 和 digest，不返回解析地址。

- [ ] **Step 4: 扩展私有 Capsule 和 Runner OpenAPI union**

Runner `capsule.payload` 仍是签名 opaque bytes。内部 wire 用 `provider_kind` 判别 `host_probe_v1|awx_v1|postgresql_v1`，`additionalProperties:false`，每个 variant 含固定 `probe_id`：

```text
host.identity-and-health.v1
awx.identity-inventory-readiness.v1
postgresql.tls-readonly-readiness.v1
```

Builder 固定解析地址、端口、SNI、允许 CIDR、证书/Realm/Network/Revision digest；签名域继续使用 Phase 2 `aiops.connection-validation-capsule.v1`。Verifier 在返回 typed getter 前重新计算所有 digest、时间窗和 Scope；未知 variant 或多 variant 同时出现立即拒绝。

- [ ] **Step 5: 运行 Green、Refactor 与边界检查**

Run:

```bash
go test ./internal/connectionprofile ./internal/credentialreference ./internal/connectionvalidation ./api/openapi -count=1
go test -race ./internal/connectionprofile ./internal/credentialreference ./internal/connectionvalidation -count=1
go test ./internal/architecture -count=1
```

Expected: PASS；判别联合封闭、unsafe key 扫描为零、Prometheus/VictoriaLogs Capsule 回归不变。

- [ ] **Step 6: Commit**

```bash
git add internal/connectionprofile internal/credentialreference internal/connectionvalidation api/openapi/runner-v1.json api/openapi/runner_v1_test.go
git commit -m "feat: add diagnostic connection provider contracts"
```

---

### Task 4: 实现三种真实 Validation Runner 固定协议 Probe

**Files:**
- Modify: `internal/connectionvalidation/queue.go`
- Modify: `internal/connectionvalidation/queue_test.go`
- Create: `internal/connectionvalidation/provider_checks.go`
- Create: `internal/connectionvalidation/provider_checks_test.go`
- Modify: `internal/validationrunner/executor.go`
- Modify: `internal/validationrunner/executor_test.go`
- Create: `internal/validationrunner/hostprobe.go`
- Create: `internal/validationrunner/hostprobe_test.go`
- Create: `internal/validationrunner/awx.go`
- Create: `internal/validationrunner/awx_test.go`
- Create: `internal/validationrunner/postgresql.go`
- Create: `internal/validationrunner/postgresql_test.go`
- Modify: `internal/runnergateway/validation_routes.go`
- Modify: `internal/runnergateway/validation_routes_test.go`
- Modify: `api/openapi/runner-v1.json`
- Modify: `api/openapi/runner_v1_test.go`
- Modify: `cmd/validation-runner/main.go`
- Modify: `cmd/validation-runner/main_test.go`

**Interfaces:**
- Consumes: Task 3 typed verified Capsule；Phase 2 claim/start/heartbeat/complete protocol、single-delivery Credential、literal-IP dialer、credential cleanup。
- Produces:

```go
type Probe interface {
    Provider() connectionprofile.Provider
    Execute(
        context.Context,
        connectionvalidation.VerifiedCapsule,
        credential.SensitiveValue,
    ) connectionvalidation.Completion
}

func NewExecutor(options Options, probes ...Probe) (*Executor, error)
```

`Completion.Checks` 只允许固定集合：共同的 `TARGET_IDENTITY/TLS_TRUST/NETWORK_POLICY/CREDENTIAL_ISSUE/CREDENTIAL_REVOKE/RESULT_SCHEMA/BUDGET/DLP` 加一个 Provider check `HOST_PROBE_HEALTH|AWX_READINESS|POSTGRES_READ_ONLY`。每个 check 只含 status、低基数 code、latency bucket 与 digest。

- [ ] **Step 1: 写失败的真实协议与逃逸测试**

```go
func TestHostProbeValidationRequiresTLS13MTLSAndExpectedSPIFFEIdentity(t *testing.T)
func TestHostProbeValidationUsesOnlyFixedIdentityHealthRoute(t *testing.T)
func TestAWXValidationUsesOnlyPingMeInventoryAndPublishedTemplateMetadataGETs(t *testing.T)
func TestAWXValidationNeverLaunchesJobOrAcceptsExtraVars(t *testing.T)
func TestPostgreSQLValidationUsesTLSAndFixedReadOnlyTransaction(t *testing.T)
func TestPostgreSQLValidationRejectsWritableSessionUnexpectedColumnsAndMultipleResults(t *testing.T)
func TestDiagnosticValidationRejectsRedirectProxyDNSRebindAndRawUpstreamError(t *testing.T)
func TestEachDiagnosticProviderCompletesOnlyAfterCredentialCleanup(t *testing.T)
func TestDiagnosticValidationProtocolCarriesOnlySignedCapsuleFenceAndFixedChecks(t *testing.T)
func TestDiagnosticValidationProtocolRejectsProviderPayloadAndUnknownCheck(t *testing.T)
```

测试服务必须记录实际 method/path/DB statements；断言 Host 只有 `GET /probe/v1/identity` 与 `GET /probe/v1/health`，AWX 只有固定 GET，PostgreSQL 只有 executor 内嵌 statement digest 对应的单事务序列。用 canary 证明 response/error/log/Completion 不出现 Credential、上游 body、地址或 SQL。

- [ ] **Step 2: 运行测试并确认 Red**

Run:

```bash
go test ./internal/connectionvalidation ./internal/validationrunner ./internal/runnergateway ./api/openapi ./cmd/validation-runner -run 'HostProbe|AWX|PostgreSQL|Diagnostic' -count=1
```

Expected: FAIL，因为三种 Probe 未注册，Provider check allowlist 尚未扩展。

- [ ] **Step 3: 实现 Host Probe 与 AWX 固定读取探针**

Host transport 固定 TLS 1.3、mTLS client identity、Capsule SNI/CA/SPKI、禁 proxy/redirect/compression/keepalive，只 dial Capsule 已签名字面 IP；响应上限 32 KiB，JSON 只允许 version、probe identity、OS family、health enum 与 nonce digest。

AWX transport 使用相同网络限制，Bearer Credential 只在 Runner 内存，固定请求顺序：

```text
GET /api/v2/ping/
GET /api/v2/me/
GET /api/v2/inventories/{server-owned-id}/
GET /api/v2/job_templates/{server-owned-id}/
```

数字 ID 只来自已发布 `awx_read_template_revisions` 私有解析结果，不从 Capsule 公共 draft、Task 或模型输入获取。只验证 inventory/template 存在、组织匹配、template 已启用且 launch 配置不要求调用方提供任意变量；禁止 `POST`、job launch、自由 limit、extra_vars 和 raw body 回传。

- [ ] **Step 4: 实现 PostgreSQL 固定最小只读事务探针**

使用 pgx config 由 typed Capsule 构造，不解析 DSN 字符串；固定 TLS ServerName/RootCA、禁 fallback、连接超时与 Network Policy。executor 内嵌并对 statements 做 golden digest：

```sql
BEGIN READ ONLY;
SET LOCAL search_path = pg_catalog;
SET LOCAL statement_timeout = '5s';
SET LOCAL lock_timeout = '1s';
SET LOCAL idle_in_transaction_session_timeout = '5s';
SELECT current_setting('transaction_read_only') = 'on' AS read_only,
       pg_is_in_recovery() AS in_recovery;
COMMIT;
```

只接受恰好两列 boolean；server writable、额外 result、notice、copy、通知、unknown OID、statement digest 变化或 cleanup 不确定均失败。SQL bytes 不进入 Capsule、Completion、Receipt、日志或审计。

- [ ] **Step 5: 注册 Provider、完成协议 Green 并 Refactor**

Runner claim/start/heartbeat/complete 路由保持 Phase 2 固定形状：claim 只返回签名 Capsule 与 fence；start 只单次返回 Credential；heartbeat 不接收 Provider 状态；complete 只接收固定 check code/status/latency bucket/digest。严格 OpenAPI 与 route decoder 拒绝 endpoint/header/body/command/SQL/template ID、raw response、Provider-specific arbitrary payload 和未知 check。

`cmd/validation-runner` 必须显式装配三个 Probe 的 trust、Credential resolver 和 transport；缺一个 Provider 依赖只令该 Provider binding `UNAVAILABLE`，不能回退通用 HTTP/pgx executor。Executor 发现 duplicate Provider 或 typed-nil Probe 直接启动失败。

Run:

```bash
go test ./internal/connectionvalidation ./internal/validationrunner ./internal/runnergateway ./api/openapi ./cmd/validation-runner -count=1
go test -race ./internal/connectionvalidation ./internal/validationrunner ./internal/runnergateway -count=1
go test ./internal/architecture -count=1
```

Expected: PASS；三种真实协议路径和负向矩阵通过，Validation/READ/WRITE Pool 仍双向不互认。

- [ ] **Step 6: Commit**

```bash
git add internal/connectionvalidation internal/validationrunner internal/runnergateway api/openapi/runner-v1.json api/openapi/runner_v1_test.go cmd/validation-runner
git commit -m "feat: validate diagnostic providers with fixed probes"
```

---

### Task 5: 编译 typed Target/Capability/Runtime 并实现 N/N+1 独立门禁

**Files:**
- Modify: `internal/capability/compiler.go`
- Modify: `internal/capability/compiler_test.go`
- Create: `internal/capability/diagnostic_compiler.go`
- Create: `internal/capability/diagnostic_compiler_test.go`
- Create: `internal/readtarget/host_probe.go`
- Create: `internal/readtarget/host_probe_test.go`
- Create: `internal/readtarget/awx.go`
- Create: `internal/readtarget/awx_test.go`
- Create: `internal/readtarget/postgresql.go`
- Create: `internal/readtarget/postgresql_test.go`
- Modify: `internal/readruntime/bundle.go`
- Modify: `internal/readruntime/bundle_test.go`
- Modify: `internal/runtimepublication/service.go`
- Modify: `internal/runtimepublication/service_test.go`
- Modify: `internal/runtimepublication/worker.go`
- Modify: `internal/runtimepublication/worker_test.go`
- Create: `internal/runtimepublication/provider_gate.go`
- Create: `internal/runtimepublication/provider_gate_test.go`
- Create: `internal/assetdiscovery/awx/adapter.go`
- Create: `internal/assetdiscovery/awx/adapter_test.go`
- Create: `internal/assetdiscovery/awx/cursor.go`
- Create: `internal/assetdiscovery/awx/cursor_test.go`
- Create: `internal/assetdiscovery/awx/provenance.go`
- Create: `internal/assetdiscovery/awx/provenance_test.go`
- Modify: `internal/assetcatalog/postgres/discovery.go`
- Modify: `internal/assetcatalog/postgres/discovery_test.go`
- Create: `internal/assetdiscovery/awx/runner.go`
- Create: `internal/assetdiscovery/awx/runner_test.go`
- Create: `cmd/asset-source-runner/main.go`
- Create: `cmd/asset-source-runner/main_test.go`

**Interfaces:**
- Consumes: immutable `VALIDATED` Revision、Task 4 Provider Validation receipt、terminal Credential cleanup、Task 3 Provider schema/Capsule digests、Phase 2 compiler/distributor/attestor。此处不消费尚未由包 04–06 验收的 Host/PostgreSQL 诊断执行合同。
- Produces:

```go
type ProviderCompileInput struct {
    Scope                  assetcatalog.Scope
    Asset                  assetcatalog.Asset
    Revision               connectionprofile.Revision
    ValidationResultDigest string
    CredentialCleanup      connectionprofile.CredentialCleanup
    ProviderSchemaDigest   string
    ValidationProbeDigest  string
    RealmDigest            string
    NetworkPolicyDigest    string
}

type ProviderRuntimeClosure struct {
    Provider          connectionprofile.Provider
    ConnectionID      string
    ConnectionRevision int64
    TargetRef         string
    TargetDigest      string
    CapabilitySetDigest string
    BundleDigest      string
    AdapterFamily     string
    RealmMode         string
}

func CompileProviderRuntime(
    ProviderCompileInput,
) (ProviderRuntimeClosure, []capability.CompiledCapability, error)

type ProviderGateReader interface {
    Status(
        context.Context,
        assetcatalog.Scope,
        connectionprofile.Provider,
        string,
        int64,
    ) (runtimepublication.GateStatus, error)
}

type AWXRuntimeResolver interface {
    ResolveAvailable(
        context.Context,
        assetcatalog.Scope,
        string, // canonical Integration ID
    ) (runtimepublication.PinnedRuntime, error)
}

type AWXInventoryAdapter interface {
    FetchPage(
        context.Context,
        assetcatalog.SourceRunFence,
        runtimepublication.PinnedRuntime,
        assetdiscovery.SealedCheckpoint,
        int,
    ) (assetdiscovery.Batch, assetdiscovery.SealedCheckpoint, error)
}
```

固定映射：Host Probe → `HOST_PROBE_V1/READ_HOST`；AWX → `AWX_READ_V1/READ_AUTOMATION`；PostgreSQL → `POSTGRES_WIRE_READ_V1/READ_DATABASE`。本 Task 只编译私有 `HOST_PROVIDER_READINESS`、`AWX_PROVIDER_READINESS`、`POSTGRES_PROVIDER_READINESS` 和可执行的 `AWX_INVENTORY_DISCOVERY` typed Capability；readiness 只供 publication/admission 证明，不能被 Investigation 调用。七个 Host diagnostic 和六个 PostgreSQL Query capability 继续 `CLOSED_BY_GATE`，分别等待包 04、05、06 的合同/executor 和包 08 的真实 E2E，不能因 Provider Runtime 可用而提前打开。

- [ ] **Step 1: 写失败的编译、版本与独立门禁测试**

```go
func TestCompileProviderRuntimeProducesTypedContentAddressedClosure(t *testing.T)
func TestCompileProviderRuntimeRejectsUnvalidatedCleanupOrSchemaDrift(t *testing.T)
func TestCompileProviderRuntimeRejectsCommandSQLURLAndUnknownCapability(t *testing.T)
func TestProviderRuntimeAvailabilityDoesNotOpenDiagnosticCapabilities(t *testing.T)
func TestRuntimeNPlusOneDoesNotMutateOrDeleteN(t *testing.T)
func TestNewAdmissionsSwitchOnlyAfterExactNPlusOneAttestation(t *testing.T)
func TestInFlightRunRemainsPinnedToNAndRollbackRestoresN(t *testing.T)
func TestProviderAvailabilityGatesAreIndependent(t *testing.T)
func TestSingleProviderDriftClosesOnlyThatProviderAndRevision(t *testing.T)
func TestAWXInventoryAdapterRequiresExactAvailableRuntime(t *testing.T)
func TestAWXInventoryCursorAndPageApplyUseCurrentHAFence(t *testing.T)
func TestAWXIncrementalPagePersistsAllowlistedFieldProvenance(t *testing.T)
func TestAWXIncrementalRunNeverMarksMissingAssetStale(t *testing.T)
func TestAWXFullRunSoftStalesMissingAndRestoreRequiresRevalidation(t *testing.T)
func TestAWXRateLimitPreservesCursorAndDefersRunWithoutBusyRetry(t *testing.T)
```

独立门禁测试构造 Host `AVAILABLE`、AWX `FAILED`、PostgreSQL `PENDING`，断言不得生成 aggregate `AVAILABLE`，只有 Host 对应 exact connection revision 通过 Provider publication admission；Host diagnostic capability 仍为 `CLOSED_BY_GATE`。

- [ ] **Step 2: 运行测试并确认 Red**

Run:

```bash
go test ./internal/capability ./internal/readtarget ./internal/readruntime ./internal/runtimepublication -run 'Diagnostic|Provider|NPlusOne' -count=1
```

Expected: FAIL，因为 Provider typed compiler、Target、独立 gate 与 AWX Inventory Source Adapter 尚不存在。

- [ ] **Step 3: 实现 Provider typed compiler 与 canonical artifacts**

Compiler 重新读取同一事务下的 Asset、Revision、Validation receipt、cleanup、Provider schema/validation probe 和 Realm/Network binding；只接受 `ACTIVE+EXACT` Asset、`VALIDATED` Revision、`REVOKED|NO_CREDENTIAL`、全部 digest 相等。各 Target 的 private manifest 由 concrete builder 生成，公共对象只含 `target_ref/digest/provider/schema_revision`。

```go
switch input.Revision.Provider() {
case connectionprofile.ProviderHostProbe:
    return compileHostProbe(input)
case connectionprofile.ProviderAWX:
    return compileAWX(input)
case connectionprofile.ProviderPostgreSQL:
    return compilePostgreSQL(input)
default:
    return ProviderRuntimeClosure{}, nil, capability.ErrUnsupportedProvider
}
```

Host/PostgreSQL 只编译不可由 Investigation 调用的 Provider readiness contract；AWX 额外编译 Source Runner 专用 `AWX_INVENTORY_DISCOVERY`，其 inventory mapping 来自 server-owned Integration。任何 manifest 出现 `command|argv|script|url|header|body|sql|dsn|extra_vars` 键即拒绝 publication。后续包只能以新的 immutable Runtime/Capability revision 增加已经验收的 diagnostic capability，不能修改本 Task artifact。

- [ ] **Step 4: 实现 N/N+1 publication、drain、rollback 和独立 Gate**

Publication 事务规则：

1. `N` 必须是当前精确 `APPLIED` immutable revision；
2. `N+1` 以新 Target/Capability/Bundle digest 写入 `PENDING`，不更新 N artifact；
3. distributor 只 stage N+1，attestor 必须回报 Scope/Provider/Connection/Revision/Bundle/Realm/identity 全等；
4. 精确 attestation 后原子把新 admission pointer 切到 N+1，同时 N 保持可读供在途运行；
5. drain receipt 证明 N 无在途 run 后才标记 `SUPERSEDED`，artifact 继续留存；
6. stage/rollout/attestation/drain 任一不确定关闭该 Provider+Revision gate，并回到最后精确 APPLIED N；不影响其他 Provider gate。

Gate key 固定为 `(Scope, provider_kind, connection_id, connection_revision, target_digest, capability_set_digest, bundle_digest, realm_digest)`，没有 workspace-wide 总绿灯。

- [ ] **Step 5: 实现 AWX_INVENTORY 增量 Source Adapter 与 HA 恢复**

Source 使用 Phase 1 已存在的 `asset_sources/asset_source_runs/asset_observations` 与 `assetdiscovery.Reconciler`，不新增表。`source.source_kind=AWX_INVENTORY`、`source.provider_kind=AWX_API`、`source.integration_id` 必须与 AWX Connection 的 canonical Integration ID 一致。Source revision 的 authority scope 列出允许的 Environment；每个 Environment 必须恰好解析到一个同 Integration 的 exact `AVAILABLE` AWX Runtime closure。每次 claim 和每页提交都绑定对应完整 Scope、run ID、单调 `fence_epoch`、token hash、heartbeat sequence、Connection revision 与 Bundle digest；缺失/重复 Runtime、旧 fence、drift 或 Gate 关闭会回滚整页并停止。

Adapter 请求只允许同源固定路径 `/api/v2/inventories/{server-owned-id}/hosts/`，排序/分页由代码拥有；不得跟随 AWX `next` URL。密封 cursor 的明文仅在 Source Runner 内存，结构固定为 `(mode, modified_at_utc, host_id, page_sequence, full_scan_epoch)`，数据库 checkpoint 保存 AES-256-GCM ciphertext，审计/API 只保存 SHA-256。每次 CAS 同时递增 checkpoint version 与 page sequence。

规范化字段 allowlist 固定为 `display_name/enabled/provider_modified_at/inventory_reference/asset_kind`；每个 source-owned 字段必须附 `FieldProvenance{FieldCode, ProviderPathCode, Ownership=SOURCE, SourceRevision, ObservedAt, Confidence}`，不采集 host variables、facts、Credential、endpoint、description 或 raw Provider JSON。Asset kind 只来自已治理 Integration mapping enum，不能读取变量猜测。

`INCREMENTAL` 页始终 `Complete=false`，只新增/更新，不以缺失判定删除。定期 `FULL_RECONCILE` 从密封 full-scan cursor 开始，只有所有页在同一 run fence 与 Runtime digest 下成功后最后一页才 `Complete=true`；Phase 1 Reconciler 把缺失 `ACTIVE` 资产变为 `STALE`、软退役 source-owned relations，不硬删历史。重新出现追加 restore Observation/event 但保持 `STALE`，直到 exact Connection/Capability revalidation 允许激活。

HTTP 429 只接受 1–900 秒 `Retry-After`，保持 cursor 不变、持久化 `not_before` 和低基数 `RATE_LIMITED`、释放 lease，由另一个 Runner 到期后重新 claim；禁止进程内 sleep loop。401/403、5xx、错误 Schema 与原始 body 只映射稳定 code，不推进 cursor，不透传正文。`cmd/asset-source-runner` 只装配 AWX adapter、专用 issuer/revoker、SourceRun repository 与 checkpoint protector，不导入 Action/WRITE/模型包。

- [ ] **Step 6: 运行 Green、race、架构与回归测试**

Run:

```bash
go test ./internal/capability ./internal/readtarget ./internal/readruntime ./internal/runtimepublication ./internal/assetdiscovery/... ./internal/assetcatalog/postgres ./cmd/asset-source-runner -count=1
go test -race ./internal/capability ./internal/readtarget ./internal/readruntime ./internal/runtimepublication ./internal/assetdiscovery/... ./cmd/asset-source-runner -count=1
go test ./internal/architecture -count=1
```

Expected: PASS；canonical bytes 稳定，任一 digest 变化关闭 admission，N/N+1/in-flight/rollback、Provider 独立 gate、AWX cursor/HA fence/provenance/soft-delete/restore/rate-limit 全通过。

- [ ] **Step 7: Commit**

```bash
git add internal/capability internal/readtarget internal/readruntime internal/runtimepublication internal/assetdiscovery internal/assetcatalog/postgres/discovery.go internal/assetcatalog/postgres/discovery_test.go cmd/asset-source-runner
git commit -m "feat: publish diagnostic runtimes and awx discovery"
```

## Package Acceptance

- [ ] 三种 Connection Revision 均为封闭判别联合，Credential Reference exact Scope/Provider/role/revision；unsafe 字段负向测试全绿。
- [ ] 三种 Validation Runner 使用真实固定协议、单次 Credential 和确定 cleanup；无通用 HTTP/TCP/SQL/命令 fallback。
- [ ] typed Target/readiness/AWX discovery Capability/Runtime 全部内容寻址并绑定 Asset/Revision/Validation/ProviderSchema/Realm/Network digest；Provider 可用不提前打开任何 diagnostic capability。
- [ ] N/N+1、in-flight pin、drain、rollback 与 drift 通过；Host/AWX/PostgreSQL 独立 `AVAILABLE` gate，无总状态推断。
- [ ] `AWX_INVENTORY` 只消费 exact published AWX Runtime；cursor/HA fence/provenance、增量/全量、soft-stale/restore 与 rate-limit 恢复均通过且无任意 job/template/command。
- [ ] `go test -race`、architecture 和 secret/unsafe key scan 通过后才允许执行下一包。
