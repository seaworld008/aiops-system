# PostgreSQL Read Runner and Credential Lifecycle Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 建立与 WRITE 完全隔离的 PostgreSQL READ 凭据 issuer/revoker、一次性交付、固定只读事务执行和持久 cleanup/recovery，使 Complete、Cancel、Timeout 与 crash 都以确认吊销或人工停止收敛。

**Architecture:** Gateway Start 先在 Phase 4 GrantGate 事务内固定单 Asset/Capability/Task/Attempt lease，再通过独立 READ issuer saga 签发短期数据库凭据；accessor 加密落盘，secret 只经 Runner mTLS 加密单次交付。Runner 消费 `CompiledQuery` 建立受 Network Policy 限定的 TLS PostgreSQL 连接并执行固定 READ ONLY transaction。任何终结路径先持久化 cleanup，再由独立 revoker worker 确认，只有 `REVOKED|NO_CREDENTIAL` 才生成成功 Receipt。

**Tech Stack:** Go 1.26.5、PostgreSQL 18.4+、pgx/v5、HashiCorp Vault Database secrets engine、TLS 1.3、`crypto/ecdh` X25519、HKDF-SHA256、AES-256-GCM、现有 Runner mTLS Gateway、Phase 4 GrantGate、000019 repositories。

## Global Constraints

- 每个 Task 严格采用 Red → Green → Refactor：先运行并保存预期失败，再做最小生产实现，复跑指定测试后才允许重构和提交。
- 新包必须叫 `readcredential`；READ issuer/revoker/profile/repository/worker 与 `credential.DurableBroker` WRITE 类型、Vault token、mount、role、表和配置完全分离。
- READ issuer 只能签发 `READ_DATABASE`，单 Asset/Capability/Task/Attempt；不得接收 Action、WRITE permission、SQL、role name、mount path 或 endpoint 的 caller override。
- Credential TTL 为 contract max、Grant expiry、Task lease、Runner certificate、Runtime expiry 五者最小值，最大 5 分钟、最小 30 秒、不可续期。
- Secret 永不持久化；username/password 只在 issuer 临时 buffer、加密 Start response 和 Runner 内存出现，用后清零。
- Accessor/lease ID 只以 AEAD ciphertext + key ID + HMAC 落盘；日志、Trace、Metric label、Audit、Temporal 与公共 API 不显示它。
- Start 响应单次交付；HTTP 响应丢失、重复 Start 或无法确定 Runner 是否收到时，不再返回 credential，立即 cleanup 并以 `credential_delivery_uncertain` 终止。
- Complete、Cancel、Timeout、Runner crash、Gateway crash、issuer partial failure 都必须有持久 cleanup intent；不允许 finally-only 内存清理。
- 吊销不确定不是成功；关闭受影响 Scope/issuer 的新 Claim，停止运行，置 `MANUAL_REQUIRED` 并告警。
- PostgreSQL executor 不解析 caller DSN、不接受 SQL/timeout/search_path；只消费 package-private `CompiledQuery` 和 private Target。
- 每个数据库事务固定 READ ONLY 与 timeout；任一只读验证失败、返回超限、DLP 拒绝、cleanup 未确认都不写成功 Evidence。
- production wiring 缺 issuer、revoker、protector、PostgreSQL repository 或 worker 任一依赖即启动失败；fake 只用于测试。
- 严格 TDD；每个 Task 独立 commit。

---

## Package Position

- 顺序：6 / 8；前置包 01–05 必须完成。
- 前置接口：000019 lease/cleanup/receipt 表、`CompiledQuery`、private PostgreSQL Target、Phase 4 GrantGate、Runner mTLS identity。
- 交付给下一包：可查询诊断运行/cleanup 状态、真实 PostgreSQL Evidence、稳定 failure codes 与生产装配。
- 本包不开放浏览器凭据或 SQL，不打开生产 Admission。

### Task 13: 实现独立 READ issuer/revoker、持久 lease 与单次交付

**Files:**
- Create: `internal/readcredential/types.go`
- Create: `internal/readcredential/lease.go`
- Create: `internal/readcredential/broker.go`
- Create: `internal/readcredential/broker_test.go`
- Create: `internal/readcredential/postgres/repository.go`
- Create: `internal/readcredential/postgres/repository_integration_test.go`
- Create: `internal/readcredential/vault/profile.go`
- Create: `internal/readcredential/vault/issuer.go`
- Create: `internal/readcredential/vault/revoker.go`
- Create: `internal/readcredential/vault/client_test.go`
- Create: `internal/readcredential/isolation_test.go`
- Modify: `internal/config/config.go`
- Modify: `internal/config/config_test.go`

**Interfaces:**
- Consumes: 000019 `read_credential_leases`、Grant/Task/Target/Runtime/Realm 的 trusted snapshot、Vault READ profile。
- Produces: `readcredential.Broker.PrepareIssue/FinalizeIssue`、`ReadIssuer`、`ReadRevoker`、`Repository`、encrypted `Delivery`。

- [ ] **Step 1: 写 READ/WRITE 类型隔离、TTL 与 secret persistence 失败测试**

~~~go
func TestReadCredentialInterfacesCannotUseWriteDurableIssuer(t *testing.T) {
    source := readGoFiles(t, "internal/readcredential")
    for _, forbidden := range []string{
        "credential.DurableBroker", "credential.DurableIssuer",
        "credential.DurableIssuerResolveRequest", "PermissionExecutionRequest",
        "ActionType", "WRITE_DATABASE",
    } {
        if strings.Contains(source, forbidden) { t.Fatalf("READ package imports WRITE symbol %s", forbidden) }
    }
}

func TestPrepareIssueBindsOneAttemptAndUsesShortestNonRenewableTTL(t *testing.T) {
    now := fixedTime()
    request := validIssueRequest(now)
    request.ContractExpiresAt = now.Add(4 * time.Minute)
    request.GrantExpiresAt = now.Add(2 * time.Minute)
    request.LeaseExpiresAt = now.Add(30 * time.Second)
    prepared, err := broker.PrepareIssue(ctx, request)
    if err != nil { t.Fatal(err) }
    if prepared.ExpiresAt() != now.Add(30*time.Second) || prepared.Renewable() {
        t.Fatalf("prepared ttl = %s renewable=%t", prepared.ExpiresAt(), prepared.Renewable())
    }
}

func TestRepositoryPersistsAccessorButNeverCredentialValue(t *testing.T) {
    fixture := newCredentialRepositoryFixture(t)
    issued := fixture.issue(t)
    row := fixture.rawLeaseRow(t, issued.ID())
    assertNotContainsSensitive(t, row, issued.UsernameForTest(), issued.PasswordForTest(), issued.AccessorForTest())
    if len(row.AccessorCiphertext) == 0 || row.AccessorHMAC == "" || row.AccessorKeyID == "" {
        t.Fatalf("missing protected accessor: %#v", row)
    }
}

func TestPrepareIssueRejectsSecondDeliveryAndQueuesCleanup(t *testing.T) {
    fixture := newBrokerFixture(t)
    prepared := fixture.prepare(t)
    first, err := fixture.broker.FinalizeIssue(ctx, prepared, fixture.issueRemote(t))
    if err != nil { t.Fatal(err) }
    defer first.Destroy()
    _, err = fixture.broker.PrepareIssue(ctx, fixture.sameAttemptRequest())
    if !errors.Is(err, readcredential.ErrDeliveryUncertain) { t.Fatalf("error = %v", err) }
    assertCleanupState(t, fixture.repository, prepared.ID(), readcredential.CleanupPending)
}
~~~

- [ ] **Step 2: 运行测试并确认 READ credential 包缺失**

Run:

~~~bash
go test ./internal/readcredential/... ./internal/config -run 'Test(ReadCredential|PrepareIssue|RepositoryPersists)' -count=1
~~~

Expected: FAIL because `internal/readcredential` and dedicated config do not exist.

- [ ] **Step 3: 定义独立、窄且不可序列化的接口**

~~~go
package readcredential

type IssueRequest struct {
    Scope assetcatalog.Scope
    InvestigationID string
    TaskID string
    AttemptEpoch int64
    AssetID string
    CapabilityDefinitionID string
    CapabilityDefinitionRevision int64
    TargetID string
    TargetDigest string
    RuntimePublicationID string
    RuntimeDigest string
    RunnerRealmID string
    GrantID string
    GrantDigest string
    CredentialReferenceID string
    CredentialReferenceRevision int64
    UsageRole string
    ContractExpiresAt time.Time
    GrantExpiresAt time.Time
    LeaseExpiresAt time.Time
    RunnerCertificateExpiresAt time.Time
    RuntimeExpiresAt time.Time
}

type Issued struct {
    Username SensitiveValue
    Password SensitiveValue
    Accessor SensitiveReference
    ExpiresAt time.Time
}

type ReadIssuer interface {
    ID() string
    Revision() string
    IssueReadDatabase(context.Context, IssueRequest) (Issued, error)
}

type ReadRevoker interface {
    ID() string
    Revision() string
    RevokeReadDatabase(context.Context, SensitiveReference) (RevokeResult, error)
}

type Repository interface {
    PrepareIssue(context.Context, PrepareInput) (Lease, error)
    FinalizeIssue(context.Context, FinalizeInput) (Lease, error)
    MarkIssueUncertain(context.Context, Scope, string, string) error
    RequestCleanup(context.Context, CleanupRequest) error
    ClaimCleanup(context.Context, ClaimRequest) (CleanupClaim, error)
    CompleteCleanup(context.Context, CleanupCompletion) error
    Get(context.Context, Scope, string) (Lease, error)
}
~~~

`SensitiveValue`/`SensitiveReference` 在本包自己实现 owner pointer、Destroy、Bytes callback；禁止 JSON/String，复制共享 destroyed state。若复用现有加密原语，只能通过无业务语义的 `AccessorProtector` interface 适配，不能让 READ broker 依赖 WRITE broker/profile/permission。

Broker 构造器要求 immutable `IssuerRegistry` 和独立 `RevokerRegistry`；ID/revision/provider/usage role/Scope 必须精确匹配。typed nil、panic、timeout 或 unknown error 一律 fail closed。

- [ ] **Step 4: 实现 Vault READ 专用 profile/client**

配置键固定隔离：

~~~text
AIOPS_READ_VAULT_ADDR
AIOPS_READ_VAULT_SERVER_NAME
AIOPS_READ_VAULT_CA_FILE
AIOPS_READ_VAULT_ISSUER_TOKEN_FILE
AIOPS_READ_VAULT_REVOKER_TOKEN_FILE
AIOPS_READ_VAULT_DATABASE_MOUNT
AIOPS_READ_VAULT_DATABASE_ROLE
AIOPS_READ_CREDENTIAL_KEYRING_FILE
~~~

拒绝与 `AIOPS_WRITE_*` 或现有 manager/revoker token file 相同的 inode、realpath、token source ID 或 mount+role。READ 与 WRITE 可以连接同一受管 Vault cluster/CA，但必须使用不同 token、policy、mount/role 和审计身份；不能要求运营方复制 Vault 集群来伪造隔离。Issuer token policy 只允许目标 READ database role 的 credentials read，Revoker token 只允许 lease revoke；两者互不替代。Vault profile 不接受 HTTP/Task 动态 path，mount/role 在启动时以 `^[a-z0-9][a-z0-9_-]{0,63}$` 验证后固化。

Issue 固定 `GET /v1/{read_mount}/creds/{read_role}`，验证 `lease_id`、`lease_duration`、`renewable=false`、data 中恰好 username/password。实际 TTL 必须不超过请求；超限立即持久 cleanup，不能截断后使用。Revoke 固定 `PUT /v1/sys/leases/revoke`，body 只含解密 accessor；204/200 且后续 lookup 证明不存在才是 REVOKED，明确不存在为 NO_CREDENTIAL，timeout/5xx/协议异常均 UNCERTAIN。

- [ ] **Step 5: 实现 PostgreSQL repository 状态机与隔离集成测试**

Prepare 在同一事务复验 Task attempt RUNNING 前置、单 Attempt 唯一、Grant/Asset/Capability/Target/Runtime/Realm digest，插入 `NOT_ISSUED`。Finalize 使用 expected version/fence，AEAD 加密 accessor，写 HMAC 与 `PENDING`，不保存 secret；同一 remote issuance replay 只触发 cleanup，不重新交付。

允许状态：`NOT_ISSUED→ISSUED|NO_CREDENTIAL`；正常执行期间保持 `ISSUED`，不会被 cleanup worker 提前 claim；任一终结条件原子执行 `ISSUED→CLEANUP_PENDING` 并写 reason；`CLEANUP_PENDING→CLEANUP_CLAIMED`；`CLEANUP_CLAIMED→REVOKED|NO_CREDENTIAL|CLEANUP_PENDING|UNCERTAIN`；`UNCERTAIN→CLEANUP_CLAIMED|MANUAL_REQUIRED`。禁止 terminal 回退。每次变化同事务写 audit/outbox，payload 仅 lease ID、task ID、state、reason、attempt count。

Run:

~~~bash
go test -race -shuffle=on -count=1 ./internal/readcredential/... ./internal/config
AIOPS_TEST_POSTGRES_DSN="$AIOPS_TEST_POSTGRES_DSN" go test -race -count=1 ./internal/readcredential/postgres -run 'TestRepository'
~~~

Expected: PASS；WRITE 类型/配置隔离、TTL、单 Attempt、secret-free persistence、状态机与并发 finalize 全通过。

- [ ] **Step 6: Commit**

~~~bash
git add internal/readcredential internal/config
git commit -m "feat: isolate read database credentials"
~~~

### Task 14: 实现 PostgreSQL Runner 固定只读事务与一次性交付

**Files:**
- Create: `internal/postgresrunner/executor.go`
- Create: `internal/postgresrunner/transport.go`
- Create: `internal/postgresrunner/transaction.go`
- Create: `internal/postgresrunner/executor_test.go`
- Create: `internal/postgresrunner/transaction_integration_test.go`
- Modify: `internal/readexecutor/execution_types.go`
- Modify: `internal/readexecutor/profile.go`
- Create: `internal/readexecutor/postgres.go`
- Create: `internal/readexecutor/postgres_test.go`
- Modify: `internal/runnergateway/read_types.go`
- Modify: `internal/runnergateway/read_routes.go`
- Modify: `internal/runnergateway/read_validate.go`
- Modify: `internal/readrunnerclient/types.go`
- Modify: `internal/readrunnerclient/client.go`
- Modify: `internal/readrunnerclient/client_test.go`
- Modify: `internal/readrunneractivity/activity.go`
- Modify: `internal/readrunneractivity/activity_test.go`

**Interfaces:**
- Consumes: private `CompiledQuery`、private Target、Start-bound encrypted READ credential delivery。
- Produces: `postgresrunner.Executor.Execute`、Runner credential delivery lifecycle、bounded PostgreSQL Evidence completion。

- [ ] **Step 1: 写任意 SQL/timeout、只读事务与单次 secret 失败测试**

~~~go
func TestExecutorHasNoSQLOrTimeoutArguments(t *testing.T) {
    method, ok := reflect.TypeOf((*postgresrunner.Executor)(nil)).Elem().MethodByName("Execute")
    if !ok { t.Fatal("missing Execute") }
    for i := 0; i < method.Type.NumIn(); i++ {
        name := method.Type.In(i).String()
        if name == "string" || strings.Contains(name, "RawMessage") {
            t.Fatalf("unsafe Execute argument %s", name)
        }
    }
}

func TestTransactionAlwaysSetsReadOnlySearchPathAndTimeouts(t *testing.T) {
    fixture := newPostgresExecutorIntegrationFixture(t)
    result, err := fixture.execute(QueryServerHealth, `{}`)
    if err != nil { t.Fatal(err) }
    if !result.Valid() { t.Fatal("invalid result") }
    assertRecordedStatements(t, fixture, []string{
        "BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY",
        "SET LOCAL search_path = pg_catalog",
        "SET LOCAL statement_timeout = '1500ms'",
        "SET LOCAL lock_timeout = '100ms'",
        "SET LOCAL idle_in_transaction_session_timeout = '2500ms'",
    })
}

func TestWriteOrMultiStatementCannotReachDatabase(t *testing.T) {
    fixture := newExecutorFixture(t)
    for _, input := range []string{
        `{"sql":"UPDATE assets SET lifecycle='ACTIVE'"}`,
        `{"sql":"SELECT 1; SELECT 2"}`,
        `{"query":"COPY evidence TO STDOUT"}`,
        `{"function":"pg_sleep"}`, `{"explain_analyze":true}`,
    } {
        _, err := fixture.executeRaw(input)
        if !errors.Is(err, postgresdiagnostic.ErrInputRejected) { t.Fatalf("%s: %v", input, err) }
    }
    if fixture.dials != 0 || fixture.issues != 0 { t.Fatalf("dials=%d issues=%d", fixture.dials, fixture.issues) }
}

func TestCredentialDeliveryDecryptsOnceAndDestroysOnAllOutcomes(t *testing.T) {
    fixture := newDeliveryFixture(t)
    start, err := fixture.start()
    if err != nil { t.Fatal(err) }
    if err := start.WithDatabaseCredential(func(username, password []byte) error { return nil }); err != nil { t.Fatal(err) }
    if err := start.WithDatabaseCredential(func(_, _ []byte) error { return nil });
        !errors.Is(err, readrunnerclient.ErrCredentialDestroyed) { t.Fatalf("second use = %v", err) }
    fixture.assertBuffersZeroed(t)
}
~~~

- [ ] **Step 2: 运行失败测试**

Run:

~~~bash
go test ./internal/postgresrunner ./internal/readexecutor ./internal/readrunnerclient ./internal/readrunneractivity -run 'Test(Executor|Transaction|WriteOrMulti|CredentialDelivery)' -count=1
~~~

Expected: FAIL because PostgreSQL executor and credential delivery do not exist.

- [ ] **Step 3: 实现 Start 单次加密交付协议**

PostgreSQL Task 的 Runner client 在 Start 内部生成 X25519 ephemeral key pair，request 额外包含 `credential_delivery_public_key`；非 PostgreSQL Task 必须省略。Gateway 根据持久 descriptor 而非 request 判断是否需要 credential，执行 Prepare → external Issue → Finalize saga，并用 ephemeral ECDH + HKDF-SHA256 派生 AES-256-GCM key，AAD 固定 TaskID/attempt epoch/contract digest/input hash。

~~~go
type EncryptedCredentialDelivery struct {
    SchemaVersion string `json:"schema_version"`
    GatewayPublicKey string `json:"gateway_public_key"`
    Nonce string `json:"nonce"`
    Ciphertext string `json:"ciphertext"`
    ExpiresAt time.Time `json:"expires_at"`
}
~~~

该对象只存在 Runner Gateway Start response，access log 禁 body，JSON type String/Marshal 不在应用日志中使用。Client 验证 response binding 后解密到 owner buffer，立即清理 private key/ciphertext；`StartCapability.WithDatabaseCredential` 单次 callback，callback 后无条件清零。Start replay 不含 delivery，返回 stable `credential_delivery_uncertain` 并已持久 cleanup。

- [ ] **Step 4: 实现固定 PostgreSQL transport 与 transaction**

`postgresrunner.Executor` 从 Target 构造 `pgx.ConnConfig`，不调用 caller `ParseConfig`：Host/Port/Database/TLS ServerName/RootCAs/Network Policy 全部私有固定；User/Password 只在 callback 内设置，连接成功后清空 config copy。Dial 先全量 DNS allowlist 校验，再 IP literal 单次连接并核对 RemoteAddr；TLS 1.3、禁止 fallback、单 connection、无 tunnel/proxy。

~~~go
type Executor interface {
    Execute(
        context.Context,
        postgresdiagnostic.CompiledQuery,
        readtarget.Target,
        *readexecutor.ExecutionStart,
        CredentialSource,
    ) (readexecutor.Result, error)
}
~~~

Execute 顺序：验证所有 digest/fence → 取一次 credential → connect deadline → `BeginTx(RepeatableRead, ReadOnly)` → 五个固定 SET/验证 `transaction_read_only=on` → 执行 KnownQuery 一次 → projector/DLP → rollback/commit read-only tx → close connection → clear args/secret/result raw buffers。任何 context cancellation 同时 cancel query、close connection、返回 bounded failure；不能在取消后继续读 partial rows。

不得使用 superuser、owner 或 write-capable role。真实集成 fixture 在事务外尝试由同一 Vault role `CREATE TEMP TABLE`、`INSERT`、`COPY FROM`、`SELECT lo_create`，全部必须 permission denied；固定诊断仍成功。

- [ ] **Step 5: 运行真实 PostgreSQL、race、timeout 与 read-only 权限测试**

Run:

~~~bash
go test -race -shuffle=on -count=1 ./internal/postgresrunner ./internal/readexecutor ./internal/readrunnerclient ./internal/readrunneractivity ./internal/runnergateway
AIOPS_TEST_POSTGRES_DSN="$AIOPS_TEST_POSTGRES_DSN" go test -race -count=1 ./internal/postgresrunner -run 'TestTransaction'
~~~

Expected: PASS；固定事务设置按 Query policy，写能力全部拒绝，credential 单次使用并清零，超时/取消无 partial Evidence。

- [ ] **Step 6: Commit**

~~~bash
git add internal/postgresrunner internal/readexecutor internal/runnergateway internal/readrunnerclient internal/readrunneractivity
git commit -m "feat: execute postgres diagnostics read only"
~~~

### Task 15: 实现 cleanup worker、crash recovery 与生产装配

**Files:**
- Create: `internal/readcredential/cleanupworker/worker.go`
- Create: `internal/readcredential/cleanupworker/worker_test.go`
- Create: `internal/readcredential/recovery.go`
- Create: `internal/readcredential/recovery_test.go`
- Modify: `internal/diagnosticreceipt/postgres/repository.go`
- Modify: `internal/diagnosticreceipt/postgres/repository_integration_test.go`
- Modify: `internal/readgateway/backend.go`
- Modify: `internal/readgateway/backend_test.go`
- Modify: `internal/readtask/recovery.go`
- Modify: `internal/readtask/recovery_test.go`
- Modify: `cmd/control-plane/runner_gateway.go`
- Modify: `cmd/control-plane/main.go`
- Modify: `cmd/control-plane/main_test.go`
- Modify: `internal/runtimepublication/service.go`
- Modify: `internal/runtimepublication/service_test.go`

**Interfaces:**
- Consumes: `readcredential.Repository`、`ReadRevokerRegistry`、Task recovery、diagnostic Receipt repository、GrantGate Admission。
- Produces: durable cleanup worker、stale-attempt sweeper、uncertain revoke containment、真实 production wiring，以及写入 package 05 PostgreSQL successor 的 executor-readiness evidence；diagnostic gate 仍保持 `PENDING` 到 package 08。

- [ ] **Step 1: 写 complete/cancel/timeout/crash 与 uncertain containment 测试**

~~~go
func TestEveryTerminalPathPersistsCleanupBeforeTaskTerminal(t *testing.T) {
    for _, path := range []string{"complete", "cancel", "timeout", "runner-crash", "gateway-crash"} {
        t.Run(path, func(t *testing.T) {
            fixture := newRecoveryFixture(t, path)
            fixture.trigger(t)
            assertOrder(t, fixture.events, "cleanup_intent_committed", "task_terminal")
        })
    }
}

func TestCleanupUncertainClosesAdmissionAndRequiresManualResolution(t *testing.T) {
    fixture := newCleanupFixture(t)
    fixture.revoker.result = readcredential.RevokeUncertain
    fixture.worker.RunOnce(ctx)
    assertLeaseState(t, fixture.repository, fixture.leaseID, readcredential.CleanupManualRequired)
    if fixture.admission.Open() { t.Fatal("admission remained open") }
    if fixture.receipts != 0 { t.Fatalf("success receipts=%d", fixture.receipts) }
}

func TestProductionAssemblyRejectsMissingOrWriteCredentialDependencies(t *testing.T) {
    for _, mutation := range []string{"nil-read-issuer", "nil-read-revoker", "write-profile", "shared-token", "memory-repository"} {
        _, err := assembleDiagnostics(mutatedProductionConfig(t, mutation))
        if !errors.Is(err, config.ErrInvalid) { t.Fatalf("%s error=%v", mutation, err) }
    }
}

func TestRunnerReadinessEvidenceBindsExactExecutorIssuerRevokerAndCleanupDigests(t *testing.T)
func TestRunnerReadinessNeverMarksDiagnosticCapabilityAvailable(t *testing.T)
~~~

- [ ] **Step 2: 运行失败测试**

Run:

~~~bash
go test ./internal/readcredential/... ./internal/readgateway ./internal/readtask ./cmd/control-plane -run 'Test(EveryTerminal|CleanupUncertain|ProductionAssembly)' -count=1
~~~

Expected: FAIL because worker, recovery binding and production dependencies do not exist.

- [ ] **Step 3: 实现 durable cleanup claim/retry/人工状态**

Worker 使用 `FOR UPDATE SKIP LOCKED` claim，独立 32-byte claim token hash，claim 30 秒；解密 accessor 后调用与 lease 精确 issuer ID/revision 匹配的 ReadRevoker。明确成功/不存在写 terminal；连接前失败可指数退避 `1s,5s,30s,2m`；请求已发出后的 timeout/EOF/5xx 直接 UNCERTAIN，不盲重试。UNCERTAIN 做一次 lookup/reconcile，仍不确定即 MANUAL_REQUIRED、关闭 admission、发 Pager 事件。

Worker panic、进程 crash 或 claim expiry 由下一实例恢复；cleanup attempt append-only。每次调用清理 accessor buffer。超过 credential expiry 仍必须 revoke/reconcile，不能假定自动过期等于吊销。

- [ ] **Step 4: 把所有终结路径与 Receipt 收敛绑定**

Complete 先在内存完成严格投影/DLP 并计算 request/content hash；第一事务只持久 completion request hash 与 cleanup intent，不写 Evidence 或成功 Receipt。bounded foreground revoke 成功后，第二事务重新复验 Gate/attempt/fence 和同一 request hash，再原子写 Evidence、runner receipt、diagnostic receipt 并终结 Task/Attempt。若进程在两事务之间 crash，Runner 以同一 completion 重放；若 Evidence 已丢失则 cleanup 后安全终结为 FAILED，不能凭 hash 伪造成功。Cancel/Timeout/recovery 不保存 Evidence，cleanup 确认后写 failure Receipt；MANUAL_REQUIRED 可写失败 Receipt，但绝不写成功 Evidence。Gateway crash 在 issuer 返回后、Finalize 前通过 issuer request correlation + Vault lease lookup/reconcile；无法确定是否签发视为 UNCERTAIN。

Sweeper 扫描：过期 Task lease、Runner cert invalid、Grant revoked/expired、Runtime revoked/drifted、Realm disabled、heartbeat stale、credential expires soon。任何命中先取消执行/关闭 heartbeat，再 cleanup。只有无 credential 或已确认 revoke 时 Task 才 terminal；manual required 在 UI/ops 可见但不向 Runner暴露内部原因。

- [ ] **Step 5: 真实装配与端到端生命周期测试**

`cmd/control-plane` production mode 必须装配 PostgreSQL repositories、Vault READ issuer/revoker、keyring protector、cleanup worker、Host/Postgres registries、GrantGate 和 diagnostics admission。不能 fallback 到 in-memory、static password 或现有 WRITE broker。Startup 执行 manager/revoker self-check、role TTL/nonrenewable/read-only preflight；失败退出。

生产装配通过后只把 `executor binary/READ issuer/revoker/role/cleanup worker/Realm/Network Policy` digests 写为 package 05 exact successor 的 executor-readiness evidence。该写入不可把 capability 改为 `AVAILABLE`；package 08 仍必须以真实 Query E2E、负向安全、credential cleanup、DLP/Evidence 与独立 attestation 完成最后门禁。

Run:

~~~bash
go test -race -shuffle=on -count=1 ./internal/readcredential/... ./internal/readgateway ./internal/readtask ./internal/diagnosticreceipt/... ./cmd/control-plane
AIOPS_TEST_POSTGRES_DSN="$AIOPS_TEST_POSTGRES_DSN" AIOPS_TEST_VAULT_ADDR="$AIOPS_TEST_VAULT_ADDR" go test -race -count=1 ./internal/readcredential/vault ./internal/postgresrunner -run 'TestIntegration'
~~~

Expected: PASS；complete/cancel/timeout/crash 全路径 cleanup，uncertain containment，真实 Vault 动态 READ role、真实 PostgreSQL transaction 与生产 fail-closed wiring 全通过。

- [ ] **Step 6: Commit**

~~~bash
git add internal/readcredential internal/diagnosticreceipt internal/readgateway internal/readtask cmd/control-plane
git commit -m "feat: recover read credential cleanup durably"
~~~
