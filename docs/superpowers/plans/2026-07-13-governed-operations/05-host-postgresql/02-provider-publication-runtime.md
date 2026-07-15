# Host Probe, AWX, and PostgreSQL Provider Publication Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 把 `HOST_PROBE_MTLS`、`AWX_API`、`POSTGRESQL` 从 Provider 判别修订、Opaque Credential Reference 和真实隔离验证一路编译为内容寻址的 Target、Capability 与 Runtime，补齐已发布 AWX Runtime 驱动的 `AWX_INVENTORY` 增量发现，并证明 N/N+1 发布与各 Provider 门禁独立、可恢复且默认关闭。

**Architecture:** 本包扩展 Phase 2 唯一 Connection/Validation/Runtime 纵向链，不建立第二套连接系统，也不新增 `000019` 表。Control Plane 只接受引用 Asset 既有网络身份的判别结构，服务端解析为私有 Capsule；独立 Validation Runner 使用三种固定协议探针，成功且凭据清理确定后，compiler 才生成 Provider 专属不可变 Runtime。Runtime N+1 与 N 并存到精确 attestation 和 drain 完成，任一 Provider 的失败只关闭自身 gate；只有 exact AWX gate `AVAILABLE` 后，现有 `cmd/discovery-worker` 中的隔离 AWX Provider 才可用同一内容寻址 Runtime 增量读取 Inventory 并交给 Phase 1 Reconciler。

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

所有 Go 测试示例必须是可编译 wrapper，并在同一 RED commit 提供各自真实 helper body；undefined helper、`t.Skip`、compile-only failure 或一个模糊共享断言均禁止。

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
- Modify: `internal/connectionprofile/postgres/repository.go`
- Modify: `internal/connectionprofile/postgres/repository_test.go`
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
    OrganizationReference       string
    AssetKind                    assetcatalog.Kind // LINUX_VM | WINDOWS_VM | BARE_METAL_HOST
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

固定 Credential usage role：Host Probe 为 `HOST_PROBE_VALIDATION`，AWX 为 `AWX_READ_VALIDATION`，PostgreSQL 为 `POSTGRES_READ_VALIDATION`。三种 Capsule variant 只含服务端解析的字面 IP 集合、SNI/证书身份摘要、固定 probe ID、预算、Network Policy/Realm digest 和 Opaque reference digest；不含调用方 URL、header/body、SQL、命令、AWX token/template 数字 ID 或 DSN。For AWX only, Control Plane resolves the immutable opaque `OrganizationReference` to one JCS-safe numeric organization locator and its digest，then seals both inside the signed private Capsule variant；the public draft/history keeps only the opaque reference/digest, and Runner accepts the locator only after signature/Scope/Connection/fence verification。AWX `IntegrationID` 必须来自 Phase 1 canonical installed Integration，Provider/Workspace 与 Connection 完全匹配，供发布后 Source 绑定，不能由浏览器生成。

- [ ] **Step 1: 写失败的 Provider 联合、引用与 Capsule 负向测试**

```go
func TestDiagnosticRevisionRequiresProviderDiscriminatedEndpoint(t *testing.T) { assertProviderDiscriminatedEndpoint(t) }
func TestDiagnosticRevisionRejectsForeignProviderFields(t *testing.T) { assertForeignProviderFieldsRejected(t) }
func TestDiagnosticRevisionRequiresAssetOwnedNetworkIdentity(t *testing.T) { assertAssetOwnedNetworkIdentity(t) }
func TestDiagnosticCredentialReferenceRequiresExactScopeProviderRoleAndRevision(t *testing.T) { assertCredentialReferenceBinding(t) }
func TestDiagnosticCapsuleRejectsURLHeaderBodyCommandSQLAndTemplateID(t *testing.T) { assertCapsuleForbiddenFields(t) }
func TestDiagnosticCapsuleBindsRealmNetworkTrustAndRevisionDigests(t *testing.T) { assertCapsuleTrustClosure(t) }
func TestDiagnosticCapsuleDoesNotMarshalCredentialOrEndpointSource(t *testing.T) { assertCapsuleRedaction(t) }
```

测试表至少包含：Host payload 注入 `command/argv/path`；AWX payload 注入 `url/header/body/inventory_id/template_id/extra_vars`；PostgreSQL payload 注入 `dsn/sql/search_path/timeout`；未知字段、跨 Scope reference、错误 usage role、过期 reference、非 Asset-owned identity 均拒绝。

- [ ] **Step 2: 运行测试并确认 Red**

Run:

```bash
go test ./internal/connectionprofile ./internal/connectionprofile/postgres ./internal/credentialreference ./internal/connectionvalidation ./api/openapi -run 'Diagnostic|HostProbe|AWX|PostgreSQL' -count=1
```

Expected: FAIL，因为三种 Provider 常量、判别 endpoint、引用 admission 和 Capsule variant 尚不存在。

- [ ] **Step 3: 实现严格 Provider schema 与 Credential Reference admission**

`NewRevision` 按 `provider_kind` 只接收一个 concrete endpoint；先以 `assetcatalog.NetworkIdentityReader` 解析 opaque ID，再校验 identity 属于 Revision Asset 或已治理 AWX Controller Asset、Scope 完全相同且 source-valid。AWX `OrganizationReference` is a server-resolved opaque reference，`AssetKind` is the closed governed mapping semantic；the PostgreSQL repository writes/reads the exact 000019 `awx_integration_id/awx_organization_reference_digest/awx_asset_kind/awx_connection_binding_digest` projection and recomputes `awx-connection-binding.v1` before commit/after scan。Other Providers require all four SQL fields NULL；neither numeric organization/inventory ID nor mutable Integration config is accepted。Host/AWX/PostgreSQL 的 port 只能来自固定 profile enum，不能接受整数或 URL；PostgreSQL database 只能引用服务端 allowlist ID。

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
go test ./internal/connectionprofile ./internal/connectionprofile/postgres ./internal/credentialreference ./internal/connectionvalidation ./api/openapi -count=1
go test -race ./internal/connectionprofile ./internal/connectionprofile/postgres ./internal/credentialreference ./internal/connectionvalidation -count=1
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
- Modify: `internal/connectionvalidation/postgres/repository.go`
- Modify: `internal/connectionvalidation/postgres/repository_test.go`
- Create: `internal/connectionvalidation/postgres/awx_selection_recovery_integration_test.go`
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

type AWXSelectionResultV1 struct {
    Schema                      string            `json:"schema"` // awx-inventory-selection-result.v1
    InventoryID                 int64             `json:"inventory_id"`
    AssetKind                   assetcatalog.Kind `json:"asset_kind"`
    OrganizationReferenceDigest string           `json:"organization_reference_digest"`
    ConnectionBindingDigest     string            `json:"connection_binding_digest"`
    SelectionFactDigest         string            `json:"selection_fact_digest"`
}
```

`Completion.Checks` preserves the Phase 2 exact ordered codes `TARGET_IDENTITY/TLS_SNI_CA/NETWORK_POLICY/CREDENTIAL_ISSUE/FIXED_PROBE/OUTPUT_SCHEMA/BUDGET/DLP/CREDENTIAL_REVOKE`；the verified Capsule provider selects the closed `FIXED_PROBE` implementation, so no new database check code is added。Each check only carries status、low-cardinality code、latency bucket and digest。Completion has one optional closed `awx_selection_result` union arm；it is required only for an AWX `FIXED_PROBE/PASSED` result and forbidden everywhere else。The strict Runner OpenAPI uses `additionalProperties:false`、safe integer/enum/digest bounds and max 2 KiB canonical body；this is the sole typed Provider result extension, not arbitrary payload。No second application signature is invented：the existing mutually authenticated Runner channel、registered workload identity、Run/attempt/fence and exact request digest are the authenticated submission envelope。

- [ ] **Step 1: 写失败的真实协议与逃逸测试**

```go
func TestHostProbeValidationRequiresTLS13MTLSAndExpectedSPIFFEIdentity(t *testing.T) { assertHostProbeTLSIdentity(t) }
func TestHostProbeValidationUsesOnlyFixedIdentityHealthRoute(t *testing.T) { assertHostProbeFixedRoutes(t) }
func TestAWXValidationUsesOnlyPingMeAndExactOrganizationInventorySelectionGETs(t *testing.T) { assertAWXValidationGETClosure(t) }
func TestAWXValidationNeverLaunchesJobOrAcceptsExtraVars(t *testing.T) { assertAWXValidationNoLaunch(t) }
func TestAWXSelectionResultIsClosedSignedBoundedAndRedacted(t *testing.T) { assertAWXSelectionResultClosure(t) }
func TestAWXSelectionStagesBeforeCleanupAndRecoversExactReplay(t *testing.T) { assertAWXSelectionCleanupReplay(t) }
func TestAWXSelectionRejectsWrongFenceSignatureDigestAndPrivateFieldDrift(t *testing.T) { assertAWXSelectionTrustDrift(t) }
func TestPostgreSQLValidationUsesTLSAndFixedReadOnlyTransaction(t *testing.T) { assertPostgreSQLValidationTransaction(t) }
func TestPostgreSQLValidationRejectsWritableSessionUnexpectedColumnsAndMultipleResults(t *testing.T) { assertPostgreSQLValidationNegatives(t) }
func TestDiagnosticValidationRejectsRedirectProxyDNSRebindAndRawUpstreamError(t *testing.T) { assertDiagnosticTransportBoundaries(t) }
func TestEachDiagnosticProviderCompletesOnlyAfterCredentialCleanup(t *testing.T) { assertProviderCleanupClosure(t) }
func TestDiagnosticValidationProtocolCarriesOnlySignedCapsuleFenceAndFixedChecks(t *testing.T) { assertValidationProtocolClosure(t) }
func TestDiagnosticValidationProtocolRejectsProviderPayloadAndUnknownCheck(t *testing.T) { assertValidationProtocolNegatives(t) }
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
GET /api/v2/organizations/{server-owned-id}/inventories/?page_size=2&order_by=id
```

The terminal AWX Connection-validation transaction uses the existing `FIXED_PROBE/PASSED` row and sets its digest to the exact selection proof；`000019` adds private selection columns to that same immutable row, so no second check enum is invented。Compiler and Source admission reload it by exact Scope/Connection revision/run and verified AWX provider rather than accepting request-carried proof。The Runner never follows AWX `next`；the fixed bounded response must report a complete first page, so truncation cannot manufacture “exactly one”。

Organization numeric ID is resolved only inside the Runner from the signed private Capsule；it never appears in public draft、Task、model、audit or history。The response must contain exactly one enabled non-smart Inventory under that organization and its ID must be in `1..9007199254740991`；zero/multiple matches、pagination beyond the bounded result、organization drift or unsafe integer fail validation。The Runner submits only the immutable `awx-inventory-selection-fact.v1` fields in the closed result arm；it cannot assert cleanup。The Gateway authenticates the mTLS workload identity and exact Run/attempt/fence/request digest，recomputes the fact，then `connectionvalidation/postgres` atomically stages the four write-once `awx_pending_*` run columns before starting Broker cleanup。After cleanup, the recovery-safe terminal transaction verifies the exact receipt and inserts the final AWX `FIXED_PROBE/PASSED` check once with five private columns and `awx-inventory-selection.v1` proof digest。A crash after staging or cleanup is resumed from PostgreSQL with exact replay；no private ID must be resent by a caller。Diagnostic `awx_read_template_revisions` are a later independent contract and are never this Source mapping truth。禁止 `POST`、job launch、自由 limit、extra_vars 和 raw body 回传。

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

Runner claim/start/heartbeat/complete 路由保持 Phase 2 identity/fence shape：claim 只返回签名 Capsule 与 fence；start 只单次返回 Credential；heartbeat 不接收 Provider 状态；complete receives fixed checks and only the closed optional `awx_selection_result` arm above。严格 OpenAPI 与 route decoder 拒绝 endpoint/header/body/command/SQL/template ID、raw response、any other Provider payload and unknown check/union arm。Gateway/log/audit formatting redacts the typed result to schema/fact digest only。

`cmd/validation-runner` 必须显式装配三个 Probe 的 trust、Credential resolver 和 transport；缺一个 Provider 依赖只令该 Provider binding `UNAVAILABLE`，不能回退通用 HTTP/pgx executor。Executor 发现 duplicate Provider 或 typed-nil Probe 直接启动失败。

Run:

```bash
go test ./internal/connectionvalidation/... ./internal/validationrunner ./internal/runnergateway ./api/openapi ./cmd/validation-runner -count=1
go test -race ./internal/connectionvalidation/... ./internal/validationrunner ./internal/runnergateway -count=1
AIOPS_TEST_POSTGRES_DSN="$AIOPS_TEST_POSTGRES_DSN" go test ./internal/connectionvalidation/postgres -run 'TestAWXSelection' -count=1
go test ./internal/architecture -count=1
```

Expected: PASS；三种真实协议路径和负向矩阵通过，AWX private result staging/cleanup/crash replay is durable and redacted，Validation/READ/WRITE Pool 仍双向不互认。

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
- Modify: `internal/assetdiscovery/awx/source_profile.go`
- Modify: `internal/assetdiscovery/awx/source_profile_test.go`
- Modify: `internal/assetcatalog/postgres/discovery.go`
- Modify: `internal/assetcatalog/postgres/discovery_test.go`
- Create: `internal/assetdiscovery/awx/runner.go`
- Create: `internal/assetdiscovery/awx/runner_test.go`
- Modify: `cmd/discovery-worker/main.go`
- Modify: `cmd/discovery-worker/main_test.go`
- Modify: `cmd/control-plane/main.go`
- Modify: `cmd/control-plane/main_test.go`

**Interfaces:**
- Consumes: immutable `VALIDATED` Revision、Task 4 Provider Validation receipt、terminal Credential cleanup、Task 3 Provider schema/Capsule digests、Phase 2 compiler/distributor/attestor，以及 `000019`-owned `public.asset_catalog_future_source_gate_admitted(public.asset_sources)` AWX successor admission。此处不消费尚未由包 04–06 验收的 Host/PostgreSQL 诊断执行合同。
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
        runtimepublication.PinnedRuntime,
        discoverysource.DiscoverRequest,
    ) (discoverysource.DiscoverOutcome, error)
}
```

`AWXInventoryAdapter` never receives `LeaseFence`；the existing `cmd/discovery-worker` validates the fence before/after the call and only Phase 1 `PageCommitter` consumes it. The Adapter returns the exact closed `Page|Delay` outcome，so `(outcome,error)` obeys the Phase 1 XOR contract and HTTP 429 cannot be represented as a data page.

固定映射：Host Probe → `HOST_PROBE_V1/READ_HOST`；AWX → `AWX_READ_V1/READ_AUTOMATION`；PostgreSQL → `POSTGRES_WIRE_READ_V1/READ_DATABASE`。本 Task 只编译私有 `HOST_PROVIDER_READINESS`、`AWX_PROVIDER_READINESS`、`POSTGRES_PROVIDER_READINESS` 和可执行的 `AWX_INVENTORY_DISCOVERY` typed Capability；readiness 只供 publication/admission 证明，不能被 Investigation 调用。七个 Host diagnostic 和六个 PostgreSQL Query capability 继续 `CLOSED_BY_GATE`，分别等待包 04、05、06 的合同/executor 和包 08 的真实 E2E，不能因 Provider Runtime 可用而提前打开。

- [ ] **Step 1: 写失败的编译、版本与独立门禁测试**

```go
func TestCompileProviderRuntimeProducesTypedContentAddressedClosure(t *testing.T) { assertProviderRuntimeClosure(t) }
func TestCompileProviderRuntimeRejectsUnvalidatedCleanupOrSchemaDrift(t *testing.T) { assertProviderRuntimeValidationClosure(t) }
func TestCompileProviderRuntimeRejectsCommandSQLURLAndUnknownCapability(t *testing.T) { assertProviderRuntimeForbiddenFields(t) }
func TestProviderRuntimeAvailabilityDoesNotOpenDiagnosticCapabilities(t *testing.T) { assertReadinessDoesNotOpenDiagnostics(t) }
func TestRuntimeNPlusOneDoesNotMutateOrDeleteN(t *testing.T) { assertRuntimeNPlusOneImmutability(t) }
func TestNewAdmissionsSwitchOnlyAfterExactNPlusOneAttestation(t *testing.T) { assertRuntimeAdmissionCAS(t) }
func TestInFlightRunRemainsPinnedToNAndRollbackRestoresN(t *testing.T) { assertRuntimePinDrainRollback(t) }
func TestProviderAvailabilityGatesAreIndependent(t *testing.T) { assertProviderGateIsolation(t) }
func TestSingleProviderDriftClosesOnlyThatProviderAndRevision(t *testing.T) { assertProviderDriftIsolation(t) }
func TestAWXInventoryAdapterRequiresExactAvailableRuntime(t *testing.T) { assertAWXAdapterRuntimeClosure(t) }
func TestAWXInventoryCursorAndPageApplyUseCurrentHAFence(t *testing.T) { assertAWXCursorFence(t) }
func TestAWXIncrementalPagePersistsAllowlistedFieldProvenance(t *testing.T) { assertAWXFieldProvenance(t) }
func TestAWXIncrementalRunNeverMarksMissingAssetStale(t *testing.T) { assertAWXIncrementalNoStale(t) }
func TestAWXFullRunSoftStalesMissingAndRestoreRequiresRevalidation(t *testing.T) { assertAWXFullSoftStaleRestore(t) }
func TestAWXRateLimitPreservesCursorAndDefersRunWithoutBusyRetry(t *testing.T) { assertAWXRateLimitDelay(t) }
func TestAWXProfileRegistersWithExistingDiscoveryWorker(t *testing.T) { assertAWXProfileProductionWiring(t) }
func TestAWXSameRunReceiptReplayIsReadOnly(t *testing.T) { assertAWXReceiptFirstReplay(t) }
func TestAWXInventoryAdmissionUses000019FutureSourceGate(t *testing.T) { assertAWXFutureSourceGate(t) }
func TestAWXInventoryAdmissionPreservesKubernetesOperatorBranch(t *testing.T) { assertAWXSuccessorPreservesVictoria(t) }
func TestAWXInventoryAdmissionRejectsProfileSchemaRuntimeAndDigestDrift(t *testing.T) { assertAWXAdmissionDrift(t) }
func TestAWXInventoryAdmissionRecoversOnlyAfterExactRepublishAndRevalidation(t *testing.T) { assertAWXAdmissionRecovery(t) }
```

独立门禁测试构造 Host `AVAILABLE`、AWX `FAILED`、PostgreSQL `PENDING`，断言不得生成 aggregate `AVAILABLE`，只有 Host 对应 exact connection revision 通过 Provider publication admission；Host diagnostic capability 仍为 `CLOSED_BY_GATE`。Future Source 测试必须通过数据库同签名 hook 而非 Go 副本证明：Provider/Profile/Runtime registry presence alone cannot create/open AWX；exact Runtime+base revision+authority child 才能通过 initial creation closure，随后 queued validation 只能进入 `VALIDATING`，terminal proof 完成后才可 `AVAILABLE`；错误 profile/schema、missing/duplicate Runtime、Connection/Bundle/attestation/published/validated binding digest 漂移在首个 HTTP 调用前 fail closed且不阻断已有 Source 收敛到 `SUSPENDED/UNAVAILABLE`；新 immutable Runtime 与 Source revision 完成 republish/revalidation 后才恢复；同一 `000019` body 下 Phase 3 Kubernetes positive/negative truth table 保持不变。

- [ ] **Step 2: 运行测试并确认 Red**

Run:

```bash
go test ./internal/capability ./internal/readtarget ./internal/readruntime ./internal/runtimepublication ./internal/assetdiscovery/... ./internal/assetcatalog/postgres ./cmd/discovery-worker -run 'Diagnostic|Provider|NPlusOne|AWXInventoryAdmission' -count=1
```

Expected: FAIL，因为 Provider typed compiler、Target、独立 gate 与 AWX Inventory Source Adapter 尚不存在。

- [ ] **Step 3: 实现 Provider typed compiler 与 canonical artifacts**

Compiler 重新读取同一 transaction 下的 Asset、Revision、Validation receipt/cleanup、Provider schema/probe、Realm/Network binding and, for AWX only, the exact private columns of its immutable `FIXED_PROBE` check；safe `ProviderCompileInput` carries no proof or numeric ID。AWX accepts only `ACTIVE+EXACT` Asset、`VALIDATED` Revision、actual cleanup `REVOKED` and matching digests，then recomputes both selection domains before artifact creation；`NO_CREDENTIAL` is MANUAL-only and a negative fixture here。The private row is scanned into an unexported, non-serializable compiler closure with redacted `String/GoString` and rejecting `MarshalJSON`；architecture/log tests prove it cannot enter API、Task、audit or logs。各 Target 的 private manifest 由 concrete builder 生成，公共对象只含 `target_ref/digest/provider/schema_revision`。

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

Host/PostgreSQL 只编译不可由 Investigation 调用的 Provider readiness contract；AWX 额外编译现有 `cmd/discovery-worker` 专用 `AWX_INVENTORY_DISCOVERY`。Its bootstrap inventory mapping comes only from immutable Connection Revision OrganizationReference/AssetKind plus exact selection proof；the compiler emits the fixed 000019 `AWX_INVENTORY_MAPPING` bytes and binds the hash into manifest/Bundle/attestation。It deliberately contains no Host/Asset/Observation/fingerprint/identity entry，because those do not exist until this Runtime admits Source discovery。Package 04 later consumes the immutable Source observations and signed local-attestor enrollment to verify/publish separate `AWX_READ_TEMPLATE_FINGERPRINT` and `AWX_HOST_IDENTITY_BINDINGS` artifacts in an N+1 Runtime；neither artifact is retrofitted into bootstrap mapping or becomes an initial Source-hook prerequisite。任何 manifest 出现 `command|argv|script|url|header|body|sql|dsn|extra_vars` 键即拒绝 publication。

- [ ] **Step 4: 实现 N/N+1 publication、drain、rollback 和独立 Gate**

Publication 事务规则：

1. `N` 必须是当前精确 `APPLIED` immutable revision；
2. `N+1` 以新 Target/Capability/Bundle digest 写入 `PENDING`，不更新 N artifact；
3. distributor 只 stage N+1，attestor 必须回报 Scope/Provider/Connection/Revision/Bundle/Realm/identity 全等；
4. 精确 attestation 后原子把新 admission pointer 切到 N+1，同时 N 保持可读供在途运行；
5. drain receipt 证明 N 无在途 run 后才标记 `SUPERSEDED`，artifact 继续留存；
6. stage/rollout/attestation/drain 任一不确定关闭该 Provider+Revision gate，并回到最后精确 APPLIED N；不影响其他 Provider gate。

Gate key 固定为 `(Scope, provider_kind, connection_id, connection_revision, target_digest, capability_set_digest, bundle_digest, realm_digest, provider_artifact_set_digest)`，没有 workspace-wide 总绿灯。For AWX the last digest binds the exact mapping-artifact SHA and selection-proof digest；for Host/PostgreSQL it binds their closed readiness artifact set。

Runtime publication 只产生 `000019` hook 所需的不可变事实，不直接打开 Source。Source admission service 必须在 Phase 1 deferred creation/gate-transition PostgreSQL truth path 中调用同一 `public.asset_catalog_future_source_gate_admitted(source)`；creation branch 只准入 same-transaction initial facts，pre-validation branch 只准入 exact `VALIDATING`，live branch 还要求 terminal proof 才能 `AVAILABLE|DEGRADED`。Source validation reloads the exact selection check、mapping artifact、Runtime manifest/Bundle/attestation and persists the 000019 `awx-inventory-source-validation.v1` digest；it never accepts an opaque caller receipt。N/N+1 pointer、Connection、selection proof、mapping artifact、Bundle or attestation 任一漂移都使 AWX live branch 返回 false并触发 Source fail-close，但不得阻断已有 Source 收敛到 `SUSPENDED/UNAVAILABLE`，也不得影响 `000017` 保留的 Kubernetes branch或其他 Provider gate。

- [ ] **Step 5: 实现 AWX_INVENTORY 增量 Source Adapter 与 HA 恢复**

Source 使用 Phase 1 已存在的 `asset_sources/asset_source_runs/asset_observations`、durable Queue、sealed `LeaseFence`、typed checkpoint codec 与 fenced `assetdiscovery.Reconciler`，不新增表、队列或 runner。`source.source_kind=AWX_INVENTORY`、`source.provider_kind=AWX_API`，且已发布 exact `revision.integration_id` 必须与 AWX Connection 的 canonical Integration ID 一致；stable Source 不得提供第二个 Integration ID。This Task only consumes and registers Task 1-owned immutable `AWXReadProfileManifestV1()` RFC 8785 bytes/hash through the single Phase 1 `SourceProfileAdmissionResolver` used by Control Plane and Worker；it may not regenerate、redefine or update that fixture，and `000019`/Task 1 parity tests remain the byte truth。The built profile is `AWX_READ_V1/SINGLE_ENVIRONMENT/OBJECT_TIME_SEQUENCE` with closed AWX parser/path/relationship semantics and limits；Source revision authority scope 恰好一个 Environment，该 Environment 必须恰好解析到一个同 Integration 的 exact `AVAILABLE` AWX Runtime closure；AWX wire host 不能选择 Catalog Environment。Missing/duplicate registry entry、same-code bytes/hash drift or absent production injection closes Source create/validation and Worker readiness。

Source 验证前由 `000019` pre-validation branch 检查 exact Runtime/revision/queued Run；Queue enqueue/claim、每次 AWX request 前后、每页提交和 terminal closure 则重新读取 database truth 并要求 Phase 1 generic gate 与 live successor branch 同时为 true；不得缓存 admission 到下一页或在 Adapter/Registry 复制更宽松 predicate。每次 claim 和每页提交都绑定对应 Source Scope、item Environment、Run ID、单调 `fence_epoch`、token hash、heartbeat sequence、Connection revision 与 Bundle digest；缺失/重复 Runtime、旧 fence、错误 profile/schema、Integration/Runtime/Bundle/attestation/validation digest drift 或 Gate 关闭会在 HTTP/checkpoint/projection mutation 前回滚整页、完成确定 cleanup 并停止。hook 永不阻断 closed-state cleanup。恢复只能发布新的 immutable Connection/Runtime/Source revision、重做 validation proof/cleanup 并再次通过同一 hook；切换 enum、单独标记 Runtime `AVAILABLE`、直接更新 gate 或复用旧 receipt 都不能恢复。

Adapter 请求只允许同源固定路径 `/api/v2/inventories/{server-owned-id}/hosts/`，排序/分页由代码拥有；不得跟随 AWX `next` URL。密封 cursor 的明文仅在 `cmd/discovery-worker` 内存，结构固定为 `(mode, modified_at_utc, host_id, page_sequence, full_scan_epoch)`，数据库 checkpoint 保存 Phase 1 common typed `CheckpointAAD` AES-256-GCM ciphertext，审计/API 只保存 SHA-256；AAD includes key ID and excludes gate/fence. Adapter 只能返回 typed next-checkpoint，只有 `PageCommitter.ApplyPage(ctx,fence,batch)` 可以对 exact input hash/version 执行 CAS，并在同一事务单调递增 checkpoint version 与 page sequence。

规范化字段 allowlist 固定为 `display_name/enabled/provider_modified_at/inventory_reference/asset_kind`；AWX `host_id` and artifact `inventory_id` must each be in `1..9007199254740991`，and each item uses Profile-locked `OBJECT_TIME_SEQUENCE{OrderTime=provider_modified_at UTC microsecond,OrderSequence=host_id,ProviderVersionSHA256=SHA256(FramedTupleV1("awx-host-version.v1",inventory_id,host_id,provider_modified_at,normalized_document_sha256))}`。`provider_modified_at` 必须先规范为 UTC microsecond，`normalized_document_sha256` 由固定 schema canonical bytes计算；Adapter 不得提交另一个 provider-fact digest。Phase 1 Repository constructs common fact/relation/provenance digests and persists the complete Observation chain。This discovery Adapter never collects host variables、facts、Credential、endpoint、description、identity key or raw Provider JSON；package 04 identity enrollment is a separate fixed signed workflow against the already discovered exact Host and local attestor，and cannot mutate Source facts。Asset kind only comes from exact Connection revision + selection proof + bootstrap mapping，never mutable Integration config/provider vars。

`INCREMENTAL` intermediate pages set both flags false and its last page uses `(FinalPage=true,CompleteSnapshot=false)`，只新增/更新，不以缺失判定删除。定期 `FULL_RECONCILE` 从密封 full-scan cursor 开始，只有所有页在同一 Run fence 与 Runtime digest 下无拒绝成功后最后一页才用 `(true,true)`；Phase 1 Reconciler 把缺失 `ACTIVE` 资产变为 `STALE`、软退役 source-owned relations，不硬删历史。重新出现追加 restore Observation/event 但保持 `STALE`，直到 exact Connection/Capability revalidation 允许激活。Same-Run page/terminal replay 只有在 exact request/page/result digest 命中已封存 receipt 时才 receipt-first 返回原结果；此旧 fence 例外是纯读且不 heartbeat、不推进 checkpoint、不投影、不 cleanup，未命中或 digest 漂移仍拒绝。Later Run unchanged host 仍 append Observation/chain but no Type Detail/business projection change.

HTTP 429 只接受 1–60 秒 `Retry-After`。此时 Adapter 必须返回 Phase 1 closed `Delay{Reason: PROVIDER_RETRY_AFTER,RetryAfter: 1..60s}`；该类型没有 Items/Relations/checkpoint/final flags，Worker 不调用 `ApplyPage`。它先完成 Broker-backed credential/session cleanup，再通过 Phase 1 Queue 持久化 `Delay(PROVIDER_RETRY_AFTER,not_before)` 并释放 lease，由另一 Worker 到期后重新 claim，禁止进程内 sleep loop。401/403、5xx、错误 Schema 与原始 body 只映射稳定 code，不推进 cursor，不透传正文。`AWX_READ_V1/AWX_INVENTORY` Profile and worker factory register in the existing immutable registries；`cmd/control-plane` replaces the MANUAL-only resolver with the extended registry implementing that same interface, while `cmd/discovery-worker` injects the same manifest digest plus AWX adapter、issuer/revoker、Phase 1 Queue/SourceRun repository and checkpoint protector。Either assembly rejects nil/typed-nil/duplicate/missing profile and imports no Action/WRITE/model package。

- [ ] **Step 6: 运行 Green、race、架构与回归测试**

Run:

```bash
go test ./internal/capability ./internal/readtarget ./internal/readruntime ./internal/runtimepublication ./internal/assetdiscovery/... ./internal/assetcatalog/postgres ./cmd/discovery-worker ./cmd/control-plane -count=1
go test -race ./internal/capability ./internal/readtarget ./internal/readruntime ./internal/runtimepublication ./internal/assetdiscovery/... ./internal/assetcatalog/postgres ./cmd/discovery-worker ./cmd/control-plane -count=1
go test ./internal/architecture -count=1
```

Expected: PASS；canonical bytes 稳定，任一 digest 变化关闭 admission，N/N+1/in-flight/rollback、Provider 独立 gate、AWX cursor/HA fence/provenance/soft-delete/restore/rate-limit 全通过；Control Plane Profile resolver 的 missing/duplicate/hash-drift/typed-nil fixtures 均 fail closed。

- [ ] **Step 7: Commit**

```bash
git add internal/capability internal/readtarget internal/readruntime internal/runtimepublication internal/assetdiscovery internal/assetcatalog/postgres/discovery.go internal/assetcatalog/postgres/discovery_test.go cmd/discovery-worker cmd/control-plane
git commit -m "feat: publish diagnostic runtimes and awx discovery"
```

## Package Acceptance

- [ ] 三种 Connection Revision 均为封闭判别联合，Credential Reference exact Scope/Provider/role/revision；unsafe 字段负向测试全绿。
- [ ] 三种 Validation Runner 使用真实固定协议、单次 Credential 和确定 cleanup；无通用 HTTP/TCP/SQL/命令 fallback。
- [ ] typed Target/readiness/AWX discovery Capability/Runtime 全部内容寻址并绑定 Asset/Revision/Validation/ProviderSchema/Realm/Network digest；Provider 可用不提前打开任何 diagnostic capability。
- [ ] N/N+1、in-flight pin、drain、rollback 与 drift 通过；Host/AWX/PostgreSQL 独立 `AVAILABLE` gate，无总状态推断。
- [ ] `AWX_INVENTORY` 只消费 exact published AWX Runtime；cursor/HA fence/provenance、增量/全量、soft-stale/restore 与 rate-limit 恢复均通过且无任意 job/template/command。
- [ ] `go test -race`、architecture 和 secret/unsafe key scan 通过后才允许执行下一包。
