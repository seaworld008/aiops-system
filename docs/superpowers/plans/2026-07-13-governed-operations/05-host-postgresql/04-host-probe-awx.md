# Fixed Host Probe and AWX Read Execution Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 将七个 Host 只读能力接入真实 mTLS Host Probe 与 AWX 预发布只读 Job Template，并以固定协议、网络边界、结果投影、DLP 和 Receipt 证明调用方无法退化为远程终端。

**Architecture:** `hostdiagnostic.Registry` 先把持久 Task、Snapshot/Grant 与已发布 Runtime 解析为不可序列化执行合同；READ Runner 依据 Provider 选择 mTLS Probe 或 AWX executor。两条路径都由 executor 自己构造固定请求、使用私有 Target、限制网络与响应，再交给独立 Evidence validator；Runner 请求从不携带 endpoint、命令或模板 ID。

**Tech Stack:** Go 1.26.5、`net/http`、TLS 1.3 mTLS、`x509`、现有 `readconnector`/`readtarget`/`readexecutor`/`readruntime`/`readtask`/`readgateway`/`runnergateway`、AWX REST API v2、RFC 8785 JCS、SHA-256。

## Global Constraints

- 每个 Task 严格采用 Red → Green → Refactor：先运行并保存预期失败，再做最小生产实现，复跑指定测试后才允许重构和提交。
- 只支持 `HOST_PROBE_MTLS` 与 `AWX_API`；未知 Provider、contract revision 或 response schema fail closed。
- Host Probe 请求只含固定 probe ID、typed canonical input、Task/Attempt fence 摘要、nonce 和过期时间；没有 command/argv/env/path/script/stdin/header/endpoint 字段。
- Host Probe 必须 TLS 1.3、双向证书认证、精确 ServerName、受 Network Policy 限定的 DNS/IP、禁 Proxy/redirect/cookie/compression/connection reuse。
- 不实现 SSH、WinRM、shell、PTY、Agent Forwarding、local/remote/dynamic port forwarding、SFTP、SCP 或文件浏览。
- AWX 只能启动 000019 中预发布的 inventory/job template/limit enum；模板必须 `ask_*_on_launch=false`，不得 prompt inventory/credential/variables/limit/job tags。
- AWX 不读取 stdout、artifact 原文或任意 event_data；只读取专用 `host_diagnostic.v1` 结构化结果并按合同投影。
- Host service/unit/log source 等动态值先解析为合同中的 enum，再变成固定 opaque ID；不能进入路径、命令片段、extra_vars key 或任意字符串模板。
- 结果在内存中先执行 byte/item/depth/string cap、严格 schema、DLP；只有安全 Evidence 进入 Gateway completion。
- Claim/Start/Heartbeat/Complete 继续执行 Phase 4 GrantGate；本包 authorizer 不能代替身份、Runtime 或 Grant 复验。
- 包 02 的 Provider Runtime `AVAILABLE` 只证明连接/transport 就绪，不打开 Host diagnostic；本包必须生成新的 immutable Host Capability successor，状态保持 `PENDING` 到包 08 真实 E2E 独立验收。
- Production 使用真实 Host Probe/AWX client；fake server 仅测试。
- 每个 Task 严格 TDD、独立 commit。

---

## Package Position

- 顺序：4 / 8；前置包 01–03 必须完成。
- 前置接口：`hostdiagnostic.Registry.Resolve`、Phase 2 Published Target/Runtime/Realm、Phase 4 GrantGate 与现有 READ Runner protocol。
- 交付给下一包：Host provider execution profile、结构化 Evidence validator、Host diagnostic receipt projection。
- 本包不实现 PostgreSQL、不开放公共 API、不创建前端。

### Task 9: 实现固定 mTLS Host Probe 协议与 executor

**Files:**
- Modify: `internal/readconnector/types.go`
- Modify: `internal/readconnector/contracts.go`
- Modify: `internal/readconnector/registry.go`
- Modify: `internal/readtarget/types.go`
- Modify: `internal/readexecutor/profile.go`
- Create: `internal/hostprobe/protocol.go`
- Create: `internal/hostprobe/client.go`
- Create: `internal/hostprobe/evidence.go`
- Create: `internal/hostprobe/protocol_test.go`
- Create: `internal/hostprobe/client_test.go`
- Create: `internal/hostprobe/evidence_test.go`
- Create: `internal/readexecutor/host_probe.go`
- Create: `internal/readexecutor/host_probe_test.go`
- Modify: `cmd/read-runner/main.go`
- Modify: `cmd/read-runner/main_test.go`

**Interfaces:**
- Consumes: `hostdiagnostic.ExecutionContract` 的 mTLS view、`readtarget.Target`、`readtask.Descriptor` 与受认证 attempt fence。
- Produces: `hostprobe.Client.Run(context.Context, RunRequest) (Result, error)`、`readexecutor.ExecuteHostProbe`、严格 Host Evidence completion。

- [ ] **Step 1: 写协议字段、禁止词与零网络失败测试**

~~~go
func TestRunRequestContainsOnlyFixedProbeFields(t *testing.T) {
    request := validRunRequest(t)
    encoded, err := json.Marshal(request)
    if err != nil { t.Fatal(err) }
    assertExactJSONKeys(t, encoded, []string{
        "schema_version", "probe_id", "input", "task_binding",
        "nonce", "not_before", "expires_at",
    })
    assertNoCaseInsensitiveKeys(t, encoded, []string{
        "command", "argv", "env", "path", "glob", "script", "stdin",
        "shell", "pty", "ssh", "winrm", "forward", "sftp", "endpoint", "header",
    })
}

func TestInvalidHostInputPerformsZeroDNSAndNetwork(t *testing.T) {
    fixture := newProbeClientFixture(t)
    for _, input := range []json.RawMessage{
        []byte(`{"unit_id":"sshd.service;id"}`),
        []byte(`{"log_source_id":"../../var/log/auth.log"}`),
        []byte(`{"command":"uname -a"}`),
        []byte(`{"lookback_seconds":3600}`),
    } {
        _, err := fixture.execute(input)
        if !errors.Is(err, hostprobe.ErrRequestRejected) { t.Fatalf("error = %v", err) }
    }
    if fixture.lookups != 0 || fixture.dials != 0 || fixture.credentials != 0 {
        t.Fatalf("side effects lookups=%d dials=%d creds=%d", fixture.lookups, fixture.dials, fixture.credentials)
    }
}

func TestProbeClientRejectsRedirectProxyTLS12AndServerNameDrift(t *testing.T) {
    for _, mutation := range []string{"redirect", "proxy", "tls12", "wrong-server-name", "dns-rebind"} {
        t.Run(mutation, func(t *testing.T) {
            fixture := newMutatedProbeFixture(t, mutation)
            _, err := fixture.run()
            if !errors.Is(err, hostprobe.ErrTransportRejected) { t.Fatalf("error = %v", err) }
        })
    }
}

func TestProbeResponseRejectsUnknownFieldsOversizeAndBadAttestation(t *testing.T) {
    for _, body := range [][]byte{
        responseWithUnknownField(), responseWithTooManyItems(),
        responseOverByteLimit(), responseWithWrongInputHash(), responseWithBadSignature(),
    } {
        if _, err := DecodeResult(bytes.NewReader(body), validResultPolicy());
            !errors.Is(err, hostprobe.ErrResultRejected) {
            t.Fatalf("DecodeResult() error = %v", err)
        }
    }
}
~~~

- [ ] **Step 2: 运行测试并确认协议尚未实现**

Run:

~~~bash
go test ./internal/hostprobe ./internal/readexecutor -run 'Test(RunRequest|InvalidHost|ProbeClient|ProbeResponse)' -count=1
~~~

Expected: FAIL because `internal/hostprobe` and the Host execution profile do not exist.

- [ ] **Step 3: 定义唯一 Host Probe wire contract**

`internal/hostprobe/protocol.go` 的公开 wire 结构固定如下；所有结构实现 `Validate`，decoder 使用 `DisallowUnknownFields`、单值 JSON、重复键检测与 body limit：

~~~go
package hostprobe

const (
    RunRequestSchema = "host-probe-run-request.v1"
    RunResultSchema  = "host-probe-run-result.v1"
    MaximumBodyBytes = 262144
)

type TaskBinding struct {
    TaskID string `json:"task_id"`
    AttemptEpoch string `json:"attempt_epoch"`
    ScopeRevision string `json:"scope_revision"`
    DescriptorDigest string `json:"descriptor_digest"`
    ContractDigest string `json:"contract_digest"`
    InputHash string `json:"input_hash"`
}

type RunRequest struct {
    SchemaVersion string `json:"schema_version"`
    ProbeID string `json:"probe_id"`
    Input json.RawMessage `json:"input"`
    TaskBinding TaskBinding `json:"task_binding"`
    Nonce string `json:"nonce"`
    NotBefore time.Time `json:"not_before"`
    ExpiresAt time.Time `json:"expires_at"`
}

type Attestation struct {
    ProbeBuildDigest string `json:"probe_build_digest"`
    HostIdentityDigest string `json:"host_identity_digest"`
    RequestDigest string `json:"request_digest"`
    ResultDigest string `json:"result_digest"`
    CertificateSHA256 string `json:"certificate_sha256"`
    Signature string `json:"signature"`
}

type RunResult struct {
    SchemaVersion string `json:"schema_version"`
    ProbeID string `json:"probe_id"`
    InputHash string `json:"input_hash"`
    CollectedAt time.Time `json:"collected_at"`
    Items []json.RawMessage `json:"items"`
    Truncated bool `json:"truncated"`
    Attestation Attestation `json:"attestation"`
}
~~~

`RunRequest` 只由 executor 从私有 contract 构造。Nonce 恰好 32 个随机 bytes 的 base64url；有效窗口最大 20 秒且不得超过 Task lease、Grant、Runner certificate 或 Runtime expiry。Host Probe 根据自身预编译 probe registry 执行 `ProbeID`，该服务端实现同样不得将 ProbeID 映射到 shell string；若 Probe 组件不在本仓库，必须把其版本化协议、兼容矩阵和独立验收 fixture 持久化到 `docs/contracts/host-probe-v1.md`，不能以文档替代客户端负向测试。

- [ ] **Step 4: 实现一次性 mTLS transport 与固定请求**

~~~go
type ClientConfig struct {
    Origin url.URL
    ServerName string
    RootCAs *x509.CertPool
    ClientCertificate tls.Certificate
    AllowedPrefixes []netip.Prefix
    ProbeSigningKeys map[string]ed25519.PublicKey
}

type Client struct { /* private immutable config, resolver and dialer */ }

func (client *Client) Run(ctx context.Context, request RunRequest) (RunResult, error)
~~~

Run 固定 `POST /probe/v1/diagnostics:run`、`Content-Type: application/json`、`Accept: application/json`；不接受 caller header。Transport 必须 `Proxy:nil`、`DisableCompression:true`、`DisableKeepAlives:true`、`MaxConnsPerHost:1`、`CheckRedirect` 返回错误、TLS Min/Max 1.3、ALPN 固定 `h2` 或固定 `http/1.1`（由 Runtime contract 选择且不可调用方覆盖）。DNS 先解析全部地址并逐个验证 Network Policy，dial 使用 IP literal 后仍核对 `RemoteAddr`；任一不允许地址使整体失败，不能挑一个可用地址绕过。

响应先用 `io.LimitReader(limit+1)`，再验证 Content-Type、status 200、严格 JSON、schema/probe/input hash、时间窗口、items/bytes、JCS digest 和 Ed25519 attestation。错误只映射 `host_probe_unavailable|host_probe_timeout|host_probe_result_rejected|host_probe_attestation_rejected`，不传播 body、URL、certificate subject 或系统错误。

- [ ] **Step 5: 接入 readconnector/readtarget/readexecutor 与 Evidence validator**

新增 `readconnector.KindHost`，Operation 仍使用七个低基数 capability operation；`Definition` 增加恰好一个 `HostDiagnosticV1` union，不能把 Host contract 泛化为自由 HTTP。`readtarget` 增加 Host mTLS client certificate reference 与 attestation key reference 的私有字段，但 Target JSON 继续 redacted。

`ExecuteHostProbe` 顺序固定：

1. 验证 descriptor、attempt epoch、scope revision、connector/target/executor/runtime digest；
2. 验证 GrantGate 已在同一 Start/Heartbeat boundary 通过；
3. 从 contract 生成 canonical input、request digest 和有效窗口；
4. 建立一次性 Client，运行固定请求；
5. 按 capability evidence schema 投影；
6. 运行 DLP（listener 地址、日志消息、unit description 等字段）；
7. 生成 `readtask.EvidenceCompletion`，清空响应 buffer。

Evidence schema 每行字段白名单、类型、最大 bytes 固定。`HOST_BOUNDED_LOG_WINDOW` 必须删除 secret/token/password/key 模式，Host/username/IP 按 classification HMAC 或 redact；发现无法安全分类的嵌套对象直接 `DLP_REJECTED`，不得以 truncated 代替拒绝。

- [ ] **Step 6: 验证、race、fuzz 与提交**

Run:

~~~bash
go test -race -shuffle=on -count=1 ./internal/hostprobe ./internal/readconnector ./internal/readtarget ./internal/readexecutor ./cmd/read-runner
go test ./internal/hostprobe -run '^Fuzz' -fuzz=FuzzDecodeResult -fuzztime=20s
~~~

Expected: PASS；fuzz 无 panic/OOM，invalid input 保持零 DNS/网络/凭据，所有 buffer 在成功/失败后清理。

- [ ] **Step 7: Commit**

~~~bash
git add internal/hostprobe internal/readconnector internal/readtarget internal/readexecutor cmd/read-runner
git commit -m "feat: execute fixed mtls host probes"
~~~

### Task 10: 实现 AWX 预发布只读模板与 Gateway Receipt

**Files:**
- Modify: `internal/connectors/awx/client.go`
- Modify: `internal/connectors/awx/client_test.go`
- Create: `internal/connectors/awx/diagnostic.go`
- Create: `internal/connectors/awx/diagnostic_test.go`
- Create: `internal/readexecutor/awx_host.go`
- Create: `internal/readexecutor/awx_host_test.go`
- Create: `internal/diagnosticreceipt/types.go`
- Create: `internal/diagnosticreceipt/postgres/repository.go`
- Create: `internal/diagnosticreceipt/postgres/repository_integration_test.go`
- Modify: `internal/readgateway/backend.go`
- Modify: `internal/readgateway/backend_test.go`
- Modify: `internal/runnergateway/read_validate.go`
- Modify: `internal/runnergateway/read_router_test.go`
- Modify: `cmd/control-plane/runner_gateway.go`
- Create: `internal/capability/host_diagnostic_publication.go`
- Create: `internal/capability/host_diagnostic_publication_test.go`
- Modify: `internal/runtimepublication/service.go`
- Modify: `internal/runtimepublication/service_test.go`

**Interfaces:**
- Consumes: `hostdiagnostic.ExecutionContract.AWX()` 私有 view、现有 AWX client、Phase 4 GrantGate、`readtask.Completion`。
- Produces: `awx.Client.RunDiagnostic`、AWX Host executor、`diagnosticreceipt.Repository.PersistCompletionTx`、Gateway Host completion authorizer，以及绑定 exact Provider Runtime/executor/contract digest 的 Host Capability successor `PENDING` publication。

- [ ] **Step 1: 写模板完整性、自由参数与 stdout 封锁测试**

~~~go
func TestRunDiagnosticUsesOnlyPublishedInventoryTemplateAndLimit(t *testing.T) {
    fixture := newAWXFixture(t)
    result, err := fixture.client.RunDiagnostic(fixture.ctx, fixture.contract, typedInput())
    if err != nil { t.Fatal(err) }
    if result.JobID == 0 { t.Fatal("missing job id") }
    launch := fixture.singleLaunch(t)
    assertExactJSONKeys(t, launch, []string{"inventory", "limit", "extra_vars"})
    assertEqual(t, launch["inventory"], float64(fixture.contract.InventoryID()))
    assertEqual(t, launch["limit"], fixture.contract.Limit())
}

func TestAWXRejectsPromptableOrMutableTemplateBeforeLaunch(t *testing.T) {
    for _, field := range []string{
        "ask_inventory_on_launch", "ask_credential_on_launch", "ask_variables_on_launch",
        "ask_limit_on_launch", "ask_tags_on_launch", "ask_job_type_on_launch",
    } {
        fixture := newPromptableAWXFixture(t, field)
        _, err := fixture.run()
        if !errors.Is(err, awx.ErrTemplateRejected) { t.Fatalf("%s error = %v", field, err) }
        if fixture.launches != 0 { t.Fatalf("%s launched", field) }
    }
}

func TestAWXNeverFetchesStdoutOrAcceptsCallerExtraVars(t *testing.T) {
    fixture := newAWXFixture(t)
    _, err := fixture.execute(json.RawMessage(`{"extra_vars":{"shell":"id"}}`))
    if !errors.Is(err, hostdiagnostic.ErrInputRejected) { t.Fatal(err) }
    if fixture.anyRequestPathContains("stdout") || fixture.launches != 0 { t.Fatal("unsafe AWX request") }
}

func TestAWXCompletionRequiresCleanupSafeReceipt(t *testing.T) {
    fixture := newGatewayHostFixture(t)
    fixture.receipt.cleanup = diagnosticreceipt.CleanupUncertain
    _, err := fixture.complete()
    if !errors.Is(err, readtask.ErrProjectionRejected) { t.Fatalf("error = %v", err) }
    if fixture.evidenceWrites != 0 { t.Fatalf("evidence writes = %d", fixture.evidenceWrites) }
}

func TestHostCapabilitySuccessorRequiresExactProviderRuntimeExecutorAndContract(t *testing.T)
func TestHostAndAWXCapabilitySuccessorsRemainPendingUntilIndependentE2E(t *testing.T)
~~~

- [ ] **Step 2: 运行失败测试**

Run:

~~~bash
go test ./internal/connectors/awx ./internal/readexecutor ./internal/readgateway -run 'Test(AWX|RunDiagnostic)' -count=1
~~~

Expected: FAIL because diagnostic launch, fixed projection and Receipt integration do not exist.

- [ ] **Step 3: 扩展 AWX client 的固定诊断方法**

~~~go
type DiagnosticContract interface {
    InventoryID() int64
    JobTemplateID() int64
    TemplateDigest() string
    Limit() string
    BuildExtraVars(json.RawMessage) (json.RawMessage, error)
    ValidateProjectedResult(json.RawMessage) error
    PollDeadline() time.Duration
}

type DiagnosticResult struct {
    JobID int64
    CollectedAt time.Time
    Items []json.RawMessage
    ResultDigest string
}

func (client *Client) RunDiagnostic(
    context.Context,
    DiagnosticContract,
    json.RawMessage,
) (DiagnosticResult, error)
~~~

方法固定执行：GET template → 验证 immutable contract fields 与 template digest → POST launch → GET job status 有界轮询 → GET 固定 page-size 的 `job_events` → 仅提取 `event_data.res.host_diagnostic_v1` → 严格投影。launch body 只含合同中的 inventory、由 Asset 绑定预解析的 limit 和固定 extra_vars；调用方不提交 limit key。extra_vars keys 由 capability 固定，例如 `diagnostic_schema_version`、`probe_id`、`sample_window_seconds`，值来自 enum。禁止 caller labels、tags、credential、forks、verbosity、timeout、scm branch、diff mode。

HTTP client 固定 no redirect/no cookie/no proxy、单 origin、body caps、bearer single-delivery；AWX job 超时后请求固定 cancel endpoint，但 cancellation/cleanup 不确定仍返回 stable failure 并关闭后续 attempt。不得删除远端 Job 记录来“清理”。

- [ ] **Step 4: 实现 AWX executor、Receipt 与 Gateway 复验**

AWX executor 复用 Task/Runtime/Target/Realm digest 验证和 Phase 4 GrantGate，不复用 mTLS Host endpoint。结果投影后运行与 mTLS 相同 DLP/Evidence validator，使相同 Capability 的 Evidence schema 与 Provider 无关。

`diagnosticreceipt.Repository.PersistCompletionTx` 必须在 Gateway Complete 事务中：

~~~go
type PersistInput struct {
    Scope assetcatalog.Scope
    InvestigationID string
    TaskID string
    AttemptEpoch int64
    AssetID string
    CapabilityID string
    Contract ContractBinding
    InputHash string
    Result ResultSummary
    EvidenceID string
    EvidenceContentHash string
    RunnerReceiptID string
    CredentialLeaseID string
    Cleanup CleanupState
    Outcome readtask.CompletionOutcome
    FailureCode readtask.FailureCode
    AuditRecordID string
}

type Repository interface {
    PersistCompletionTx(context.Context, pgx.Tx, PersistInput) (Receipt, error)
    Get(context.Context, Scope, string) (Receipt, error)
}
~~~

Host 无动态 credential 时固定 `CleanupNoCredential`。Gateway 先实时 Grant/Runtime authorizer，再验证 Host contract/evidence/DLP/attestation，随后在同事务写 Evidence、runner receipt、diagnostic receipt 和 audit/outbox。任何一步失败回滚；completion replay 必须返回同一 receipt hash，不重复 Evidence 或预算。

- [ ] **Step 5: 发布不可变 Host Capability successor 但保持运行门关闭**

对 `HOST_PROBE_MTLS` 与 `AWX_API` 分别编译七个固定 capability 的新 CapabilitySet/Runtime successor，绑定包 02 exact Provider Runtime、000019 contract revision/digest、executor binary digest、result/DLP policy、READ Realm/Network Policy 与 provider-specific Target。两个 Provider 的 successor/gate 独立；不得用 Host Probe 验收结果打开 AWX。

publication 初始固定 `PENDING`，包 07 API 可展示但 `effective_actions` 不含 `RUN_DIAGNOSTIC`。只有包 08 对 exact `(Scope,provider,connection revision,target,capability set,bundle,executor,contract)` 运行真实协议、cleanup、Evidence、negative suite 并写独立 attestation 后，才允许该 Provider+Capability revision 进入 `AVAILABLE`；任一 digest drift 关闭精确 gate，不回退包 02 readiness capability。

- [ ] **Step 6: 覆盖远程执行负向矩阵与真实事务**

增加表驱动用例，至少覆盖：shell metacharacter、newline/NUL、argv array、env map、绝对/相对 path、glob、script、interpreter、stdin、PTY、SSH/WinRM、forwarding、SFTP/SCP、任意 AWX inventory/template/limit/extra_vars、stdout、重定向、跨 origin、oversize、unknown fields、partial Job、cancel uncertain。所有输入层拒绝用 spy 证明零网络；上游恶意结果用 fake TLS/AWX server 证明零 Evidence。

Run:

~~~bash
go test -race -shuffle=on -count=1 ./internal/connectors/awx ./internal/readexecutor ./internal/diagnosticreceipt/... ./internal/readgateway ./internal/runnergateway
AIOPS_TEST_POSTGRES_DSN="$AIOPS_TEST_POSTGRES_DSN" go test -race -count=1 ./internal/diagnosticreceipt/postgres -run 'TestRepository'
~~~

Expected: PASS；Receipt 与 Evidence 同事务，replay 幂等，所有终端能力负向路径无远程请求或无 Evidence。

- [ ] **Step 7: Commit**

~~~bash
git add internal/connectors/awx internal/readexecutor internal/diagnosticreceipt internal/readgateway internal/runnergateway internal/capability/host_diagnostic_publication.go internal/capability/host_diagnostic_publication_test.go internal/runtimepublication cmd/control-plane
git commit -m "feat: run published awx host diagnostics"
~~~
