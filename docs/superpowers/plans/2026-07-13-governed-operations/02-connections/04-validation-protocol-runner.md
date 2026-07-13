# Validation Protocol and Runner Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 实现可 HA 恢复的 Validation lease/credential cleanup 协议，以及只执行固定 Provider Probe 的真实隔离 Runner。

**Architecture:** PostgreSQL queue 负责 claim/start/heartbeat/complete 与 fencing；Gateway 仅在 VALIDATION mTLS listener 暴露协议；Runner 验签 Capsule 后执行固定 Prometheus/VictoriaLogs Probe 并返回低敏结果。

**Tech Stack:** Go 1.26.5、PostgreSQL 18.4+、chi v5、pgx v5、mTLS、Ed25519、HTTP/TLS。
## Global Constraints

- 每个 Task 严格采用 Red → Green → Refactor：先运行并保存预期失败，再做最小生产实现，复跑指定测试后才允许重构和提交。
- 本任务包交付真实 mTLS Validation Runner，不是同进程 fake；测试 fake 只允许存在于 `*_test.go`。
- 每个数据库读写显式绑定 Tenant/Workspace/Environment；lease 使用单调 attempt 与 fencing token，旧持有者永远不能 heartbeat/complete。
- Validation 与 Investigation 使用独立 Root、SPIFFE Pool、Realm、队列、凭据 issuer 和 Gateway 路由，任何身份或协议不得互认。
- 每个短 Credential 绑定 run/attempt/target/role/TTL，成功前必须持久记录 `REVOKED` 或 `NO_CREDENTIAL` cleanup。
- Runner 只执行固定 Prometheus/VictoriaLogs Probe，不能接受任意 URL、query、header、body 或动态脚本。
- 响应、日志、指标、审计和 error 禁止 Credential、token、DSN、PEM、Vault path、raw upstream body。
- HA 正确性来自 PostgreSQL lease/fencing/cleanup，进程退出后另一个 Runner 可安全接管。
- 新增行为遵循 TDD，任务末运行 race 与 mTLS 边界测试。

### Task 8: Implement the Validation lease, credential cleanup, and mTLS protocol

**Files:**
- Create: `internal/connectionvalidation/queue.go`
- Create: `internal/connectionvalidation/queue_test.go`
- Create: `internal/connectionvalidation/credential.go`
- Create: `internal/connectionvalidation/credential_test.go`
- Create: `internal/connectionvalidation/postgres/repository.go`
- Create: `internal/connectionvalidation/postgres/repository_test.go`
- Create: `internal/connectionvalidation/postgres/credential.go`
- Create: `internal/connectionvalidation/postgres/credential_test.go`
- Create: `internal/runnergateway/validation_routes.go`
- Create: `internal/runnergateway/validation_routes_test.go`
- Modify: `internal/runnergateway/router.go`
- Modify: `internal/runnergateway/router_test.go`
- Modify: `api/openapi/runner-v1.json`
- Modify: `api/openapi/runner_v1_test.go`

**Interfaces:**
- Consumes: package 03 Task 6 authenticated `PoolValidation` identity and Realm；package 03 Task 7 `SignedCapsule`；`credential.AESGCMProtector` only for accessor-at-rest protection, not WRITE authorization。
- Produces:

```go
type Repository interface {
    Enqueue(context.Context, connectionprofile.Revision, operation.Operation) error
    Claim(context.Context, AuthenticatedRunner, time.Duration) (Claim, error)
    Start(context.Context, AuthenticatedRunner, Fence) (StartResult, error)
    Heartbeat(context.Context, AuthenticatedRunner, Fence, int64) (HeartbeatResult, error)
    Complete(context.Context, AuthenticatedRunner, Fence, Completion) error
}
```

- [ ] **Step 1: Write failing lease and route tests**

```go
func TestValidationRoutesRequireValidationPoolAndNeverReturnRawFailures(t *testing.T) {
    backend := &recordingValidationBackend{
        claim: connectionvalidation.Claim{
            OperationID: "95000000-0000-4000-8000-000000000001",
            Epoch: 1,
            LeaseToken: []byte("0123456789abcdef0123456789abcdef"),
            LeaseExpiresAt: time.Now().Add(time.Minute),
            Capsule: signedCapsuleFixture(t),
        },
    }
    handler := runnergateway.NewRouterWithProtocols(
        verifierFixture(t),
        disabledWriteBackend{},
        disabledReadBackend{},
        backend,
    )
    response := serveMTLSRequest(
        t, handler, validationClientFixture(t),
        http.MethodPost, "/runner/v1/connection-validations:claim",
        `{"max_items":1}`,
    )
    if response.Code != http.StatusOK ||
        !strings.Contains(response.Body.String(), `"capsule"`) {
        t.Fatalf("claim response = %d %s", response.Code, response.Body.String())
    }
    for _, forbidden := range []string{
        "vault_path", "private_key", "upstream_body", "raw_error",
    } {
        if strings.Contains(strings.ToLower(response.Body.String()), forbidden) {
            t.Fatalf("claim leaked %q: %s", forbidden, response.Body.String())
        }
    }

    denied := serveMTLSRequest(
        t, handler, readClientFixture(t),
        http.MethodPost, "/runner/v1/connection-validations:claim",
        `{"max_items":1}`,
    )
    if denied.Code != http.StatusForbidden {
        t.Fatalf("READ identity validation claim status = %d", denied.Code)
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
go test ./internal/connectionvalidation/... ./internal/runnergateway -run Validation -count=1
```

Expected: FAIL because queue and Validation routes are undefined.

- [ ] **Step 3: Implement exact queue and wire DTOs**

`internal/connectionvalidation/queue.go`:

```go
package connectionvalidation

import (
    "context"
    "errors"
    "time"

    "github.com/seaworld008/aiops-system/internal/connectionprofile"
    "github.com/seaworld008/aiops-system/internal/operation"
)

var (
    ErrNoValidationAvailable = errors.New("no validation operation available")
    ErrValidationFence = errors.New("validation lease rejected")
    ErrValidationConflict = errors.New("validation operation conflict")
    ErrValidationCredentialCleanup = errors.New("validation credential cleanup incomplete")
)

type AuthenticatedRunner interface {
    RunnerID() string
    TenantID() string
    RealmID() string
    ScopeRevision() int64
    CertificateSHA256() string
    ValidationPool() bool
}

type Fence struct {
    OperationID string
    Epoch int64
    LeaseToken []byte
}

type Claim struct {
    OperationID string
    Epoch int64
    LeaseToken []byte
    LeaseExpiresAt time.Time
    Capsule SignedCapsule
}

type StartResult struct {
    Credential []byte
    CredentialExpiresAt time.Time
}

type HeartbeatResult struct {
    Sequence int64
    LeaseExpiresAt time.Time
    Continue bool
}

type CheckStatus string

const (
    CheckPassed CheckStatus = "PASSED"
    CheckFailed CheckStatus = "FAILED"
)

type CheckResult struct {
    Code string `json:"code"`
    Status CheckStatus `json:"status"`
    LatencyMilliseconds int `json:"latency_ms,omitempty"`
    ResultDigest string `json:"result_digest"`
}

type Completion struct {
    Succeeded bool `json:"succeeded"`
    FailureCode string `json:"failure_code,omitempty"`
    Checks []CheckResult `json:"checks"`
    ResultDigest string `json:"result_digest"`
}

type Repository interface {
    Enqueue(context.Context, connectionprofile.Revision, operation.Operation) error
    Claim(context.Context, AuthenticatedRunner, time.Duration) (Claim, error)
    Start(context.Context, AuthenticatedRunner, Fence) (StartResult, error)
    Heartbeat(context.Context, AuthenticatedRunner, Fence, int64) (HeartbeatResult, error)
    Complete(context.Context, AuthenticatedRunner, Fence, Completion) error
}
```

固定事务规则：

1. Claim 只选 `QUEUED` 且 Scope/Realm/Provider binding 与当前数据库身份完全匹配的最早 Operation，使用 `FOR UPDATE SKIP LOCKED`。
2. Lease token 恰好 32 个随机字节，只在 Claim 响应和 Runner 内存出现；数据库只存 SHA-256。
3. Start 只允许一次 `LEASED → RUNNING`；相同 Fence 重放不得再次返回 Credential，返回 `validation_credential_delivery_uncertain`，持久化 cleanup 并失败。
4. Heartbeat sequence 从 1 逐一递增；每次重新验证 Registration、Certificate、Scope Revision、Realm、Capsule expiry 和 Credential TTL。
5. Completion 仅含九个固定 check code、稳定 failure code、延迟和 Digest；未知字段、重复 check、原始正文和超预算全部拒绝。
6. Complete 先保存 immutable result receipt，再触发 Credential revoke；Operation 保持 `RUNNING/CREDENTIAL_REVOKE`。只有 cleanup 为 `REVOKED/NO_CREDENTIAL` 才原子写 `SUCCEEDED/FAILED` 并推进 Revision；`UNCERTAIN` 固定失败且禁止发布。

- [ ] **Step 4: Implement an independent validation credential broker**

`internal/connectionvalidation/credential.go`:

```go
package connectionvalidation

import (
    "context"
    "net"
    "time"

    "github.com/seaworld008/aiops-system/internal/credential"
)

type CredentialIssueRequest struct {
    OperationID string
    Epoch int64
    TenantID string
    WorkspaceID string
    EnvironmentID string
    ConnectionID string
    ConnectionRevision int64
    ReferenceID string
    ReferenceRevision int64
    ProviderKind string
    UsageRole string
    RequestedTTL time.Duration
    LeaseExpiresAt time.Time
    CapsuleExpiresAt time.Time
}

type IssuedCredential struct {
    Value credential.SensitiveValue
    Accessor *credential.SensitiveReference
    ExpiresAt time.Time
}

type ValidationIssuer interface {
    IssueValidation(context.Context, CredentialIssueRequest) (IssuedCredential, error)
}

type ValidationRevoker interface {
    RevokeValidation(context.Context, *credential.SensitiveReference) error
}

type CredentialProfile struct {
    ReferenceID string
    ReferenceRevision int64
    IssuerID string
    IssuerRevision string
    ProviderKind string
    UsageRole string
    MaxTTL time.Duration
    Issuer ValidationIssuer
    Revoker ValidationRevoker
}

type CredentialResolver interface {
    ResolveValidationCredential(
        context.Context,
        CredentialIssueRequest,
    ) (CredentialProfile, error)
}
```

实现独立 immutable Registry，精确匹配 Reference ID/Revision/Scope/Provider/`CONNECTION_VALIDATION`；不导入 `execution`、`action` 或 WRITE Broker。TTL 取 `profile.MaxTTL、lease expiry、capsule expiry` 三者最小值，最少 30 秒；Accessor 用现有 Protector 加密，Secret 永不持久化。Revocation worker 的 claim token 与 Validation lease token 分离。

- [ ] **Step 5: Register strict internal routes**

固定路由：

```text
POST /runner/v1/connection-validations:claim
POST /runner/v1/connection-validations/{operation_id}:start
POST /runner/v1/connection-validations/{operation_id}:heartbeat
POST /runner/v1/connection-validations/{operation_id}:complete
```

请求/响应 Schema 固定为：

```json
{
  "claim_request": {"max_items": 1},
  "claim_response": {
    "operation_id": "95000000-0000-4000-8000-000000000001",
    "epoch": "1",
    "lease_token": "base64url-43-characters",
    "lease_expires_at": "2026-07-13T08:01:00Z",
    "capsule": {
      "schema_version": "connection-validation-signed-capsule.v1",
      "payload": "base64url",
      "digest": "64-lowercase-hex",
      "key_id": "validation-2026-07",
      "signature": "base64url"
    }
  },
  "start_request": {"epoch": "1", "lease_token": "base64url-43-characters"},
  "start_response": {
    "credential": "single-delivery-base64url",
    "credential_expires_at": "2026-07-13T08:00:50Z"
  },
  "heartbeat_request": {
    "epoch": "1",
    "lease_token": "base64url-43-characters",
    "sequence": "1"
  },
  "complete_request": {
    "epoch": "1",
    "lease_token": "base64url-43-characters",
    "succeeded": true,
    "checks": [
      {
        "code": "TARGET_IDENTITY",
        "status": "PASSED",
        "latency_ms": 4,
        "result_digest": "64-lowercase-hex"
      }
    ],
    "result_digest": "64-lowercase-hex"
  }
}
```

实际 OpenAPI 把四个对象拆成独立 Schema，不使用上面的聚合 envelope。所有 epoch/sequence 使用 canonical decimal string；所有响应加 `Cache-Control: no-store` 和 `X-Content-Type-Options: nosniff`。Credential 只在 Start 200 响应出现一次，HTTP access log 必须禁止 body。

- [ ] **Step 6: Run protocol, persistence, and race tests**

Run:

```bash
go test ./internal/connectionvalidation/... ./internal/runnergateway ./api/openapi -count=1
go test -race ./internal/connectionvalidation/... ./internal/runnergateway -count=1
```

Expected: PASS；旧 epoch/token、跳号 heartbeat、错误 Pool/Realm/证书、重复 Start、未知 check、cleanup `UNCERTAIN` 和原始错误字段全部拒绝。

- [ ] **Step 7: Commit**

```bash
git add internal/connectionvalidation internal/runnergateway api/openapi/runner-v1.json api/openapi/runner_v1_test.go
git commit -m "feat: add validation runner lease protocol"
```

### Task 9: Build the isolated Validation Runner and fixed Provider probes

**Files:**
- Create: `internal/validationrunner/client.go`
- Create: `internal/validationrunner/client_test.go`
- Create: `internal/validationrunner/executor.go`
- Create: `internal/validationrunner/executor_test.go`
- Create: `internal/validationrunner/prometheus.go`
- Create: `internal/validationrunner/prometheus_test.go`
- Create: `internal/validationrunner/victorialogs.go`
- Create: `internal/validationrunner/victorialogs_test.go`
- Create: `internal/validationrunner/architecture_boundary_test.go`
- Create: `cmd/validation-runner/main.go`
- Create: `cmd/validation-runner/main_test.go`
- Modify: `Makefile`

**Interfaces:**
- Consumes: 本文件 Task 8 mTLS protocol and Credential single delivery；package 03 Task 7 `VerifyCapsule`。
- Produces: `validationrunner.Run(context.Context) error` and fixed `Executor.Execute(context.Context, Capsule, []byte) Completion`。

- [ ] **Step 1: Write failing fixed-probe and dependency-boundary tests**

```go
func TestExecutorRejectsRedirectProxyCompressionAndRawUpstreamFailure(t *testing.T) {
    upstream := httptest.NewTLSServer(http.HandlerFunc(func(
        response http.ResponseWriter,
        request *http.Request,
    ) {
        if request.URL.Path != "/api/v1/query_range" {
            t.Fatalf("path = %q", request.URL.Path)
        }
        response.Header().Set("Content-Encoding", "gzip")
        response.WriteHeader(http.StatusBadGateway)
        _, _ = response.Write([]byte("SECRET-UPSTREAM-CANARY"))
    }))
    defer upstream.Close()

    executor := validationrunner.NewExecutor(validationrunner.Options{
        Resolver: fixedResolverForServer(t, upstream),
        Clock: time.Now,
    })
    result := executor.Execute(
        context.Background(),
        verifiedPrometheusCapsuleForServer(t, upstream),
        []byte("0123456789abcdef0123456789abcdef"),
    )
    if result.Succeeded || result.FailureCode != "UPSTREAM_UNAVAILABLE" {
        t.Fatalf("Execute() = %#v", result)
    }
    encoded, err := json.Marshal(result)
    if err != nil {
        t.Fatal(err)
    }
    if strings.Contains(string(encoded), "SECRET-UPSTREAM-CANARY") {
        t.Fatalf("result leaked upstream body: %s", encoded)
    }
}

func TestValidationRunnerDependencyGraphExcludesInvestigationAndWrite(t *testing.T) {
    command := exec.Command(
        "go", "list", "-deps", "-f", "{{.ImportPath}}",
        "../../cmd/validation-runner",
    )
    output, err := command.Output()
    if err != nil {
        t.Fatalf("go list dependencies: %v", err)
    }
    for _, dependency := range strings.Fields(string(output)) {
        for _, forbidden := range []string{
            "/internal/action",
            "/internal/execution",
            "/internal/investigation",
            "/internal/readtask",
            "/internal/model",
        } {
            if strings.Contains(dependency, forbidden) {
                t.Fatalf("Validation Runner imports forbidden %q", dependency)
            }
        }
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
go test ./internal/validationrunner ./cmd/validation-runner -count=1
```

Expected: FAIL because the package and command do not exist.

- [ ] **Step 3: Implement the fixed executor**

`internal/validationrunner/executor.go`:

```go
package validationrunner

import (
    "context"
    "time"

    "github.com/seaworld008/aiops-system/internal/connectionvalidation"
)

type Resolver interface {
    Resolve(context.Context, string) ([]net.IP, error)
}

type Options struct {
    Resolver Resolver
    Clock func() time.Time
}

type Executor struct {
    options Options
}

func NewExecutor(options Options) *Executor {
    return &Executor{options: options}
}

func (executor *Executor) Execute(
    ctx context.Context,
    capsule connectionvalidation.Capsule,
    credential []byte,
) connectionvalidation.Completion {
    if executor == nil || executor.options.Resolver == nil ||
        executor.options.Clock == nil || len(credential) < 16 ||
        len(credential) > 4096 {
        return failedCompletion("RESULT_SCHEMA_REJECTED")
    }
    defer clear(credential)
    switch capsule.ProviderKind() {
    case "PROMETHEUS":
        return executor.executePrometheus(ctx, capsule, credential)
    case "VICTORIALOGS":
        return executor.executeVictoriaLogs(ctx, capsule, credential)
    default:
        return failedCompletion("RESULT_SCHEMA_REJECTED")
    }
}
```

HTTP Transport 固定：

```go
transport := &http.Transport{
    Proxy: nil,
    ForceAttemptHTTP2: false,
    DisableCompression: true,
    DisableKeepAlives: true,
    TLSClientConfig: &tls.Config{
        MinVersion: tls.VersionTLS13,
        MaxVersion: tls.VersionTLS13,
        RootCAs: roots,
        ServerName: endpoint.ServerName,
        NextProtos: []string{"http/1.1"},
        SessionTicketsDisabled: true,
        Renegotiation: tls.RenegotiateNever,
    },
    DialContext: admittedLiteralDialer(
        executor.options.Resolver, endpoint, capsule.AllowedPrefixes(),
    ),
    TLSHandshakeTimeout: 5 * time.Second,
    ResponseHeaderTimeout: 10 * time.Second,
    MaxResponseHeaderBytes: 32 << 10,
}
client := &http.Client{
    Transport: transport,
    Timeout: time.Duration(capsule.Budget().MaxDurationSeconds) * time.Second,
    CheckRedirect: func(*http.Request, []*http.Request) error {
        return errors.New("redirect rejected")
    },
}
```

要求全部 DNS 答案位于 Capsule 固定 CIDR，拒绝 loopback/link-local/multicast/metadata/IPv4-in-IPv6；只允许字面 IP dial 到解析集合。Request 只由 Provider 代码生成，固定 POST form、`Authorization: Bearer` 和 content type；不接受任意 Header、Cookie、Proxy、Redirect、Retry 或 Compression。

- [ ] **Step 4: Implement exact Prometheus and VictoriaLogs probes**

Prometheus：

```go
values := url.Values{
    "query": []string{probe.Expression},
    "start": []string{start.UTC().Format(time.RFC3339Nano)},
    "end": []string{end.UTC().Format(time.RFC3339Nano)},
    "step": []string{strconv.Itoa(probe.StepSeconds)},
    "timeout": []string{"10s"},
}
request, err := http.NewRequestWithContext(
    ctx, http.MethodPost, endpoint.Origin+"/api/v1/query_range",
    strings.NewReader(values.Encode()),
)
```

VictoriaLogs：

```go
values := url.Values{
    "query": []string{probe.Query},
    "start": []string{start.UTC().Format(time.RFC3339Nano)},
    "end": []string{end.UTC().Format(time.RFC3339Nano)},
    "limit": []string{strconv.Itoa(probe.Limit)},
}
request, err := http.NewRequestWithContext(
    ctx, http.MethodPost, endpoint.Origin+"/select/logsql/query",
    strings.NewReader(values.Encode()),
)
```

两者读取上限 `1 MiB + 1`，超限返回 `BUDGET_EXHAUSTED`；严格验证 JSON Schema、Content-Type、时间窗、item/byte budget 和 DLP。固定 check 顺序为：

```text
TARGET_IDENTITY
TLS_SNI_CA
NETWORK_POLICY
CREDENTIAL_ISSUE
FIXED_PROBE
OUTPUT_SCHEMA
BUDGET
DLP
CREDENTIAL_REVOKE
```

Runner 不自行声称 `CREDENTIAL_REVOKE` 通过；Complete 前该 check 省略，Gateway cleanup 成功后由服务端追加并重算最终 result digest。

- [ ] **Step 5: Implement the process loop and build target**

`cmd/validation-runner/main.go` 只加载独立 Validation client certificate、server CA、Capsule public keyring 和固定 Gateway origin。循环为 Claim → Verify Capsule → Start → Execute → Complete；每 10 秒 heartbeat，context cancel 时清空 credential 并 Complete 固定 `VALIDATION_CANCELLED`。禁止环境变量覆盖 endpoint、query、CIDR、budget 或 Provider。

Modify `Makefile`:

```make
build:
	go build ./cmd/control-plane ./cmd/worker ./cmd/read-runner ./cmd/write-runner ./cmd/validation-runner ./cmd/executor
```

- [ ] **Step 6: Run Runner tests**

Run:

```bash
go test ./internal/validationrunner ./cmd/validation-runner -count=1
go test -race ./internal/validationrunner ./cmd/validation-runner -count=1
go build ./cmd/validation-runner
```

Expected: all commands PASS；固定 Probe 成功、TLS/Network/DLP/预算失败、cancel 和 Credential 清零均有测试，依赖图不含 Investigation 或 WRITE 包。

- [ ] **Step 7: Commit**

```bash
git add internal/validationrunner cmd/validation-runner Makefile
git commit -m "feat: execute fixed connection validation probes"
```
