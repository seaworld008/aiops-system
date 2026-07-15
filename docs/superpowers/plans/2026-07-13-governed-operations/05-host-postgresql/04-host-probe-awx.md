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
- AWX 只能启动 000019 中预发布的 inventory/job template/limit enum；模板必须 `ask_limit_on_launch=true`、`survey_enabled=true`，其余十五个 24.6.1 prompt flags 全 false。受治理 endpoint 外层 POST 固定为 contract 的九键对象，其中 AWX prompt override 子集只含 `limit+extra_vars`；不得调用 stock launch 或 override inventory/credential/其他字段。
- AWX 不读取 stdout、artifact 原文或任意 event_data；只读取专用 `event_data.res.host_diagnostic_v1` 最终安全结构与固定身份元数据。
- Host service/unit/log source 等动态值先解析为合同中的 enum，再变成固定 opaque ID；不能进入路径、命令片段、extra_vars key 或任意字符串模板。
- Host Probe/签名 AWX module 必须在各自本地进程内先 HMAC/redact/DLP/sort/严格验证，raw endpoint/path/event/message 不能进入 Provider/Runner payload；Executor/Gateway 只复验最终 schema、identity、caps 与 canary。
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

`RunRequest` 只由 executor 从私有 contract 构造。Nonce 恰好 32 个随机 bytes 的 base64url；有效窗口最大 20 秒且不得超过 Task lease、Grant、Runner certificate 或 Runtime expiry。Host Probe 根据预编译 registry 执行 `ProbeID`，不得映射到 shell string；它为每次执行在本进程生成 fresh 256-bit HMAC key，先把 raw endpoint/path/event ref 转成 `HMAC_EXECUTION`、对文本执行 allowlist/redaction/DLP、canonical sort and final evidence-schema validation，再构造 `RunResult`，随后销毁 key/raw buffers。Raw 值不能进入 wire/error/log。若 Probe 组件不在本仓库，必须把版本化协议、兼容矩阵、服务端净化契约和独立 fixture 持久化到 `docs/contracts/host-probe-v1.md`，文档不能替代客户端负向测试。

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

响应先用 `io.LimitReader(limit+1)`，再验证 Content-Type、status 200、严格 JSON、schema/probe/input hash、时间窗口、final item classifications/order/bytes、JCS digest and Ed25519 attestation；secret/raw canary 命中即拒绝整份结果。错误只映射 `host_probe_unavailable|host_probe_timeout|host_probe_result_rejected|host_probe_attestation_rejected`，不传播 body、URL、certificate subject 或系统错误。

- [ ] **Step 5: 接入 readconnector/readtarget/readexecutor 与 Evidence validator**

新增 `readconnector.KindHost`，Operation 仍使用七个低基数 capability operation；`Definition` 增加恰好一个 `HostDiagnosticV1` union，不能把 Host contract 泛化为自由 HTTP。`readtarget` 增加 Host mTLS client certificate reference 与 attestation key reference 的私有字段，但 Target JSON 继续 redacted。

`ExecuteHostProbe` 顺序固定：

1. 验证 descriptor、attempt epoch、scope revision、connector/target/executor/runtime digest；
2. 验证 GrantGate 已在同一 Start/Heartbeat boundary 通过；
3. 从 contract 生成 canonical input、request digest 和有效窗口；
4. 建立一次性 Client，运行固定请求；
5. 复验 Probe 已生成的 final `host-diagnostic-evidence.v1` schema、HMAC/DLP classification、canonical order、caps and canaries；
6. 生成 `readtask.EvidenceCompletion`，清空响应 buffer。

Evidence schema 每行字段白名单、类型、最大 bytes 固定。`HOST_BOUNDED_LOG_WINDOW` 的 secret/token/password/key、raw Host/username/IP 必须已在 Probe 内删除/HMAC/redact；Executor 不接收 raw 也不补救净化。发现无法安全分类的嵌套对象直接 `DLP_REJECTED`，不得以 truncated 代替拒绝。

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
- Create: `internal/awxhostidentity/authority.go`, `internal/awxhostidentity/enrollment.go`, `internal/awxhostidentity/artifact.go`, `internal/awxhostidentity/worker.go`, `internal/awxhostidentity/publication.go`
- Create: `internal/awxhostidentity/authority_test.go`, `internal/awxhostidentity/enrollment_test.go`, `internal/awxhostidentity/artifact_test.go`, `internal/awxhostidentity/worker_test.go`, `internal/awxhostidentity/publication_test.go`
- Create: `internal/awxhostidentity/postgres/repository.go`, `internal/awxhostidentity/postgres/repository_integration_test.go`
- Create: `internal/enrollmentcleanup/types.go`, `internal/enrollmentcleanup/broker.go`, `internal/enrollmentcleanup/client.go`, `internal/enrollmentcleanup/vault/store.go`, `internal/enrollmentcleanup/vault/store_integration_test.go`
- Create: `cmd/enrollment-cleanup-broker/main.go`, `cmd/enrollment-cleanup-broker/main_test.go`
- Create: `internal/awxgovernedadmission/client.go`, `internal/awxgovernedadmission/client_test.go`, `deploy/awx/governed-admission/` patch/source/migration/tests/build manifest
- Create: `internal/hostattestor/protocol.go`, `internal/hostattestor/server.go`, `internal/hostattestor/verifier.go`, `internal/hostattestor/*_test.go`, `cmd/host-attestor/main.go`, `cmd/host-attestor/main_test.go`
- Create: `automation/awx/collections/ansible_collections/aiops/governed/` fixed enrollment/diagnostic modules, playbooks, build/SBOM/signature tests
- Create: `internal/readcredential/types.go`, `internal/readcredential/lease.go`, `internal/readcredential/broker.go`, `internal/readcredential/delivery.go`, `internal/readcredential/worker.go`, `internal/readcredential/broker_test.go`, `internal/readcredential/worker_test.go`
- Create: `internal/readcredential/postgres/repository.go`, `internal/readcredential/postgres/repository_integration_test.go`
- Create: `internal/readcredential/awx/profile.go`, `internal/readcredential/awx/client.go`, `internal/readcredential/awx/client_test.go`
- Modify: `internal/config/config.go`, `internal/config/config_test.go`

**Interfaces:**
- Consumes: `docs/contracts/awx-host-identity-enrollment-v1.md`、`docs/contracts/awx-governed-launch-admission-v1.md`、`docs/contracts/host-identity-attestor-v1.md`、server-only signed enrollment authority、APPLIED mapping-only bootstrap AWX Runtime、exact Source/Asset/Observation cohort、`hostdiagnostic.ExecutionContract.AWX()` 私有 view、Phase 4 GrantGate、`readtask.Completion`。
- Produces: durable enrollment Operation/Attempt repository and worker、verified two-template fingerprint+identity artifacts、`PENDING→APPLIED` Runtime successor handoff、generic Investigation-only `readcredential` saga、AWX diagnostic issuer/revoker、`awx.Client.RunDiagnostic`、Receipt authorizer，以及绑定 exact Runtime/executor/contract digest 的 Host Capability successor `PENDING` publication。

- [ ] **Step 1: 写模板完整性、自由参数与 stdout 封锁测试**

~~~go
func TestRunDiagnosticUsesOnlyPublishedInventoryTemplateAndLimit(t *testing.T) {
    fixture := newAWXFixture(t)
    result, err := fixture.client.RunDiagnostic(fixture.ctx, fixture.contract, typedInput())
    if err != nil { t.Fatal(err) }
    if result.JobID == 0 { t.Fatal("missing job id") }
    preview := fixture.singleLaunchPreview(t)
    assertPreviewEqualsFingerprint(t, preview, fixture.contract)
    admission := fixture.singleGovernedAdmission(t)
    assertExactJSONKeys(t, admission, []string{
        "expected_host_id", "expected_host_name_sha256", "expected_manifest_sha256",
        "extra_vars", "idempotency_key", "launch_request_sha256", "limit", "purpose", "worker_fence_digest",
    })
    assertOnlyAWXPromptOverrides(t, admission, []string{"limit", "extra_vars"})
    assertEqual(t, admission["limit"], fixture.contract.Limit())
}

func TestAWXRequiresExactTwoTemplateBundleSixteenPromptsSurveysAndPreviews(t *testing.T) { assertExactAWXTemplateBundleAndRemoteClosure(t) }
func TestAWXRejectsNonemptyTemplateExtraVarsLimitLabelsOrFallback(t *testing.T) { assertAWXStoredDefaultsFailClosed(t) }
func TestAWXRejectsIgnoredLaunchFieldEvenWhenAWXReturns201(t *testing.T) { assertAWXIgnoredFieldsFailClosed(t) }
func TestAWXIdentityEnrollmentIsReleaseAuthorizedDurableAndIndependentOfInvestigation(t *testing.T) { assertAWXEnrollmentOperationAttemptProtocol(t) }
func TestAWXIdentityEnrollmentResponseLossCleanupCohortAndNPlusOneAreRecoverable(t *testing.T) { assertAWXEnrollmentCrashAndSealProtocol(t) }
func TestAWXGovernedAdmissionPreventsEveryPreviewLaunchRaceBeforeJobCreation(t *testing.T) { assertAWXGovernedAdmissionAtomicity(t) }
func TestAWXEnrollmentRequiresVerifiedHardwareBoundHostAttestor(t *testing.T) { assertHostAttestorProductionProfiles(t) }
func TestAWXReadAutomationLeaseRevokesOnEveryTerminalPath(t *testing.T) { assertAWXDiagnosticCredentialLifecycle(t) }

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

func TestHostCapabilitySuccessorRequiresExactProviderRuntimeExecutorAndContract(t *testing.T) { assertHostCapabilitySuccessorClosure(t) }
func TestHostAndAWXCapabilitySuccessorsRemainPendingUntilIndependentE2E(t *testing.T) { assertHostCapabilitySuccessorsRemainPending(t) }
~~~

Every called helper is implemented in the same RED commit with real fixtures/assertions；undefined helper、Skip、compile-only failure or one shared vague assertion is forbidden。Enrollment helpers execute the exact authority/table/state/fence/launch-marker/cleanup/crypto/artifact/seal contract and 1/128/129/10000-Host cohort cases from `docs/contracts/awx-host-identity-enrollment-v1.md`。

- [ ] **Step 2: 运行失败测试**

Run:

~~~bash
go test ./internal/awxhostidentity/... ./internal/enrollmentcleanup/... ./internal/readcredential/... ./internal/connectors/awx ./internal/readexecutor ./internal/readgateway ./internal/capability ./internal/runtimepublication ./internal/config ./cmd/enrollment-cleanup-broker -run 'Test(AWX|Enrollment|RunDiagnostic|HostCapability)' -count=1
AIOPS_TEST_POSTGRES_DSN="$AIOPS_TEST_POSTGRES_DSN" go test ./internal/awxhostidentity/postgres ./internal/readcredential/postgres -run 'TestRepository' -count=1
AIOPS_TEST_VAULT_ADDR="$AIOPS_TEST_VAULT_ADDR" go test ./internal/enrollmentcleanup/vault -run 'TestStoreIntegration' -count=1
~~~

Expected: FAIL because enrollment Operation/Attempt persistence、template verification、identity seal/rollout、diagnostic launch、fixed projection and Receipt integration do not exist；an unset PostgreSQL DSN is an unmet prerequisite, not a Skip。

- [ ] **Step 3: 实现 enrollment Operation/Attempt、HA CleanupBroker 与固定诊断 client**

Enrollment 严格实现三个 contracts 的 mapping-only 顺序：Authority service 在一个 serializable transaction 内验证 APPLIED authority-keyring Runtime、release statement/purpose/expiry/one-use nonce、capacity profile、Source/Revision/Connection/APPLIED mapping Runtime，并先计算完整 eligible cohort；超过 effective limit 以 `HOST_IDENTITY_COHORT_CAPACITY_EXCEEDED` 在零 Operation/凭据/网络下关门。合法请求只插入 `PENDING` root。独立 coordinator 以 version/fence claim root，先通过 purpose=`AWX_HOST_IDENTITY_TEMPLATE_VERIFY` 的 Broker attempt 获取 verifier self-PAT，按 durable marker→两模板 governed manifest GET→bundle/prospective hash→exact revoke/receipt persistence 的顺序推进；只有 cleanup proof `REVOKED|NO_CREDENTIAL` 后，一个 serializable transaction 才可重载 discovery facts、生成完整 immutable cohort/Attempt request digests 并进入 `RUNNING`。

每个 remotely eligible Host Attempt 使用持久 template semaphore/rate/deadline、`FOR UPDATE SKIP LOCKED`、256-bit fence hash、epoch/heartbeat 与独立 Broker attempt；unsafe limit token 直接无网络 `UNAVAILABLE`。Worker 赢得 slot 后才 issue self-PAT，持久 marker 后只调用 governed launch admission；AWX-side serializable lock transaction在 signal前重验 template与单 Host selector，任何 preview竞态 Job count=0。固定 signed module只调用 local `host-attestor-v1`，并验证平台声明、Ed25519 challenge、complete Job/event/Host summary、fact/binding，最后 exact revoke/receipt。未知 Job/cleanup只进 manual containment。Finalizer只锁并离线验数据库 proof facts，原子写 artifacts、diagnostic-family `PENDING` Runtime、Audit/Outbox 和 `SEALED`；外部 rollout/APPLIED 不改变 discovery Runtime/Source checkpoint。

`EnrollmentCleanupBroker` 是独立生产服务，不复用 Investigation `read_credential_leases`。它用 mTLS 接受 exact opaque attempt request，在专用 Vault KV v2 mount 以 CAS 保存 marker/state/version/issuer revision/encrypted accessor/HMAC/cleanup attempts/receipt，并用独立 Transit key 加密 accessor；acknowledged marker 必须已由 HA Vault durable commit。两个 active broker 实例以 KV version+随机 claim fence 竞争，所有 API 以 opaque Attempt ID exact-idempotent，禁止 list/prefix/delete-by-value。Control Plane 保存 opaque ID 与完整 safe immutable proof envelope/digest/key/signature hash，Secret/accessor 仍只在 Broker。Vault mount/token/三把 Transit key、AWX profile和证书均为固定启动配置；缺少真实 issue→RBAC negatives→revoke、CAS contention、Transit rotation、live-quorum acknowledged-marker RPO=0 proof 或按声明 RPO 的 snapshot/region DR recovery 时 enrollment admission fail closed。

~~~go
type DiagnosticContract interface {
    InventoryID() int64
    JobTemplateID() int64
    TemplateFingerprintManifestDigest() string
    TemplateFingerprintDigest() string
    SurveySpecDigest() string
    ContractDigest() string
    ResolveHostBinding(string) (HostBinding, error)
    Limit() string
    BuildExtraVars(TypedInput, HostBinding, [32]byte) (json.RawMessage, error)
    ValidateSafeProjectedResult(json.RawMessage) error
    PollDeadline() time.Duration
}

type DiagnosticResult struct {
    JobID int64
    HostID int64
    HostBindingDigest string
    CollectedAt time.Time
    Items []json.RawMessage
    Truncated bool
    ResultDigest string
    IdentityProof HostIdentityProof
}

func (client *Client) RunDiagnostic(
    context.Context,
    DiagnosticContract,
    json.RawMessage,
) (DiagnosticResult, error)
~~~

方法固定执行：reload diagnostic-family 的 mapping/fingerprint/identity 三个 private Runtime artifacts → 逐项重算完整 manifest/fingerprint/contract → 将 server-resolved 单 Host `limit` 与 2,446-byte schema 生成的 `extra_vars` 作为唯一 AWX prompt overrides 封入 exact 九键 governed admission request → 只接受其 exact admission receipt/Job ID → bounded poll Job/status/host summaries/events → 只提取 final `event_data.res.host_diagnostic_v1`。Stock launch endpoint 对该模板恒拒绝；AWX-side serializable lock transaction 必须在 Job signal 前重载 template/project/EE/credentials/instance groups/survey 与单 Host selector，消除 GET→launch 竞态。extra_vars 必含 fresh nonce、expected Host ID/binding/identity key/platform attestation、input hash、probe ID and exact branch enums；caller 不提交任何 key。Created Job 的 template/inventory/limit/final merged extra-vars/project SCM/EE/credentials/instance group/unique Host snapshot 必须与 admission receipt 闭包相等，否则立即 cancel、cleanup、零 Evidence。

HTTP client 固定 no redirect/no cookie/no proxy、单 origin、body caps、bearer single-delivery；AWX job 超时后请求固定 cancel endpoint，但 cancellation/cleanup 不确定仍返回 stable failure 并关闭后续 attempt。不得删除远端 Job 记录来“清理”。签名 module 在任何诊断前通过固定 local Host attestor 验证 TPM-sealed、platform-attested Ed25519 identity；明文 seed 短暂存在 measured attestor process，因此该进程隔离属于 TCB，契约不声称硬件原生不可导出。Module 在本机生成独立 per-execution HMAC key，把 raw references/messages 变成最终 `HMAC_EXECUTION`/DLP-safe items 后才构造 event；raw 值在 AWX event、Runner payload 和 Gateway 中从不存在。

Task 10 separately implements the generic 000019 durable lease/cleanup state machine only for Investigation `READ_AUTOMATION` diagnostics；package 06 later extends those interfaces for `READ_DATABASE`。The diagnostic profile's fixed AWX execution user calls only `POST /api/v2/users/{same-user-id}/personal_tokens/` after the durable marker，with `application=null` and OAuth scope `write`；AWX 24.6.1 therefore returns one access token/numeric accessor and no refresh token。`write` permits launch but adds no RBAC：the user has only execute/use on the exact diagnostic template/inventory/credential and negative tests deny CRUD、ad-hoc commands、enrollment template and every other Job Template。Issuer/revoker are separate trusted components and credential sources for that same AWX user—not falsely distinct AWX actors—and revocation uses exact `DELETE /api/v2/tokens/{id}/` plus detail GET/404。Application token、cross-user PAT、refresh token、list/search/prefix/delete-by-value or lifetime >5m is rejected。Response loss after issue marker、unknown token ID、ambiguous delete or missing self-service guarantee becomes `UNCERTAIN→MANUAL_REQUIRED` and suspends new diagnostic claims；all terminal paths prove `REVOKED|NO_CREDENTIAL` before success。

Diagnostic keys are fixed server startup inputs only：`AIOPS_READ_AWX_ORIGIN`、`AIOPS_READ_AWX_SERVER_NAME`、`AIOPS_READ_AWX_CA_FILE`、`AIOPS_READ_AWX_ISSUER_TOKEN_FILE`、`AIOPS_READ_AWX_REVOKER_TOKEN_FILE`、`AIOPS_READ_AWX_EXECUTION_USER_ID`、`AIOPS_READ_AWX_ACCESS_TOKEN_MAX_SECONDS` and `AIOPS_READ_CREDENTIAL_KEYRING_FILE`。Enrollment Broker additionally requires fixed broker/L7 gateway mTLS、dedicated Vault `ADDR|SERVER_NAME|CA_FILE|KV_MOUNT|TRANSIT_MOUNT|ACCESSOR_KEY|HMAC_KEY|RECEIPT_SIGNING_KEY|TOKEN_FILE`，and separate verifier/enrollment self-PAT profiles。No origin/path/user/TTL comes from Task/Runner/model。Within each profile issuer/revoker sources differ locally while AWX actor correctly remains same-user；users/sources differ across verifier/enrollment/diagnostic/WRITE/Vault purposes。Startup performs real self-issue→RBAC/L7 path negatives→self-revoke、governed admission image/route and host-attestor profile checks；missing guarantee closes only the affected admission。

- [ ] **Step 4: 实现 AWX executor、Receipt 与 Gateway 复验**

AWX executor 复用 Task/Runtime/Target/Realm digest 与 Phase 4 GrantGate，不复用 mTLS Host endpoint。它先验证 module 已完成的 local identity/HMAC/DLP final projection，再独立验证 challenge signature、unique Job Host summary、schema/caps/canaries；只把 provider-neutral `host-diagnostic-evidence.v1` items 与 `Truncated` 交给 Gateway，不能在 Gateway 接收 raw 后再净化。

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

Host Probe 无动态 credential 时固定 `CleanupNoCredential`；AWX 必须绑定同 Attempt 的 `READ_AUTOMATION` lease 与确认 cleanup。Gateway 先实时 Grant/Runtime authorizer，再验证 contract/final Evidence/identity/DLP canary，随后同事务写 Evidence、runner receipt、diagnostic receipt and audit/outbox。任何一步失败回滚；completion replay 返回同一 receipt hash，不重复 Evidence 或预算。

- [ ] **Step 5: 发布不可变 Host Capability successor 但保持运行门关闭**

对 `HOST_PROBE_MTLS` 与 `AWX_API` 分别编译七个固定 capability 的新 CapabilitySet/Runtime successor。AWX 顺序固定为 mapping-only bootstrap Runtime → Source discovery → signed identity enrollment/template verification with dedicated cleanup → complete fingerprint/identity artifacts → N+1 Runtime containing mapping/fingerprint/identity artifacts → external rollout/attestation APPLIED CAS → server-only contract Publisher → `PENDING` capability；任一 Host 无 attestor只影响其 capability，不能伪造 mapping。两个 Provider gate 独立；不得用 Host Probe 验收结果打开 AWX。

publication 初始固定 `PENDING`，包 07 API 可展示但 `effective_actions` 不含 `RUN_DIAGNOSTIC`。只有包 08 对 exact `(Scope,provider,connection revision,target,capability set,bundle,executor,contract)` 运行真实协议、cleanup、Evidence、negative suite 并写独立 attestation 后，才允许该 Provider+Capability revision 进入 `AVAILABLE`；任一 digest drift 关闭精确 gate，不回退包 02 readiness capability。

- [ ] **Step 6: 覆盖远程执行负向矩阵与真实事务**

增加表驱动用例，至少覆盖：shell metacharacter、newline/NUL、argv array、env map、绝对/相对 path、glob、script、interpreter、stdin、PTY、SSH/WinRM、forwarding、SFTP/SCP、任意 AWX inventory/template/limit/extra_vars、stdout、重定向、跨 origin、oversize、unknown fields、partial Job、cancel uncertain。所有输入层拒绝用 spy 证明零网络；上游恶意结果用 fake TLS/AWX server 证明零 Evidence。

Run:

~~~bash
go test -race -shuffle=on -count=1 ./internal/awxhostidentity/... ./internal/awxgovernedadmission ./internal/hostattestor ./internal/enrollmentcleanup/... ./internal/readcredential/... ./internal/connectors/awx ./internal/readexecutor ./internal/diagnosticreceipt/... ./internal/readgateway ./internal/runnergateway ./internal/capability ./internal/runtimepublication ./internal/config ./cmd/control-plane ./cmd/enrollment-cleanup-broker ./cmd/host-attestor
AIOPS_TEST_POSTGRES_DSN="$AIOPS_TEST_POSTGRES_DSN" go test -race -count=1 ./internal/awxhostidentity/postgres ./internal/readcredential/postgres ./internal/diagnosticreceipt/postgres -run 'TestRepository'
AIOPS_TEST_VAULT_ADDR="$AIOPS_TEST_VAULT_ADDR" go test -race -count=1 ./internal/enrollmentcleanup/vault -run 'TestStoreIntegration'
~~~

Expected: PASS；Receipt 与 Evidence 同事务，replay 幂等，所有终端能力负向路径无远程请求或无 Evidence。

- [ ] **Step 7: Commit**

~~~bash
git add internal/connectors/awx internal/awxhostidentity internal/awxgovernedadmission internal/hostattestor internal/enrollmentcleanup internal/readcredential internal/readexecutor internal/diagnosticreceipt internal/readgateway internal/runnergateway internal/capability/host_diagnostic_publication.go internal/capability/host_diagnostic_publication_test.go internal/runtimepublication internal/config automation/awx deploy/awx cmd/control-plane cmd/enrollment-cleanup-broker cmd/host-attestor
git commit -m "feat: run published awx host diagnostics"
~~~
