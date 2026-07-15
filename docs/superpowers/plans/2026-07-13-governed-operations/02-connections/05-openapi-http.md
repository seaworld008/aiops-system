# Connection Control Plane OpenAPI and HTTP Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 发布浏览器安全、权限完备、幂等且可恢复的 Connection/Credential/Capability/Runtime/Operation Control Plane API。

**Architecture:** OpenAPI 是唯一浏览器契约；HTTP handler 复用 Scope、ETag、Idempotency、cursor、strict JSON 和 Problem helpers；public API 与 mTLS Runner API 使用不同 listener 和依赖。

**Tech Stack:** Go 1.26.5、chi v5、OpenAPI 3.1、OIDC、PostgreSQL 18.4+。
## Global Constraints

- 每个 Task 严格采用 Red → Green → Refactor：先运行并保存预期失败，再做最小生产实现，复跑指定测试后才允许重构和提交。
- Public Control Plane 与 Validation Runner mTLS API 使用独立 listener/router；public router 永不注册 claim/start/heartbeat/complete。
- 每个请求显式绑定 Tenant/Workspace/Environment，并重新执行当前 OIDC/authz；公共 Connection 路由按已批准规范保持 workspace path，Environment 由 required `environment_id` query（以及写 DTO 中的同值字段）绑定，两者不一致即拒绝；404/403 不泄露对象存在性。
- 所有 mutation 使用 Idempotency-Key；revision/publish/revoke 使用 If-Match；replay 与 Operation 从 PostgreSQL 恢复。
- Credential/Connection/Runtime/Operation 响应是低敏安全投影并加 `Cache-Control: no-store`；禁止 token、DSN、PEM、Vault path、raw error。
- Production dependency 缺 PostgreSQL、OIDC、Signer、Realm/Credential/Trust/Network registry 任一项时 validate/publish fail closed，无 memory fake fallback。
- 本阶段 API 只暴露 read capability publication，不添加 write action。
- 新增行为遵循 TDD；OpenAPI path、handler、authorization、redaction、ETag、cursor 和 Problem 一一由测试锁定。

### Task 10: Publish the Control Plane OpenAPI and HTTP endpoints

**Files:**
- Modify: `internal/authz/authorizer.go`
- Modify: `internal/authz/authorizer_test.go`
- Modify: `api/openapi/control-plane-v1.yaml`
- Modify: `api/openapi/control_plane_v1_test.go`
- Create: `internal/httpapi/connections.go`
- Create: `internal/httpapi/connections_test.go`
- Create: `internal/httpapi/credential_references.go`
- Create: `internal/httpapi/credential_references_test.go`
- Create: `internal/httpapi/capabilities.go`
- Create: `internal/httpapi/capabilities_test.go`
- Create: `internal/httpapi/runtime_publications.go`
- Create: `internal/httpapi/runtime_publications_test.go`
- Create: `internal/httpapi/runner_realms.go`
- Create: `internal/httpapi/runner_realms_test.go`
- Create: `internal/httpapi/operations.go`
- Create: `internal/httpapi/operations_test.go`
- Modify: `internal/httpapi/router.go`
- Modify: `internal/httpapi/router_test.go`
- Modify: `cmd/control-plane/main.go`
- Modify: `cmd/control-plane/main_test.go`

**Interfaces:**
- Consumes: package 02 Task 3 services/repositories；package 02 Task 5 publication service；前序 Operational Asset Catalog 阶段的 HTTP contract helpers。
- Produces: browser-safe `/api/v1/workspaces/{workspace_id}` Connections/Credential/Capability/Runtime/Operation APIs and generated TypeScript contract。

- [ ] **Step 1: Write failing authorization and redaction tests**

```go
func TestConnectionPublishRequiresAdminRecentAuthentication(t *testing.T) {
    authorizer, err := authz.NewAuthorizer(5*time.Minute, fixedNow)
    if err != nil {
        t.Fatal(err)
    }
    request := authz.Request{
        Permission: authz.PermissionConnectionPublish,
        WorkspaceID: "workspace-1",
        EnvironmentID: "PROD",
        Production: true,
    }
    stale := validPrincipal(authn.RoleAdmin)
    stale.AuthenticatedAt = fixedNow().Add(-6 * time.Minute)
    if err := authorizer.Authorize(stale, request); !errors.Is(
        err, authz.ErrReauthenticationRequired,
    ) {
        t.Fatalf("Authorize(stale admin) error = %v", err)
    }
}

func TestConnectionDetailResponseContainsOnlySafeProjection(t *testing.T) {
    router := connectionRouterFixture(t)
    request := authenticatedRequest(
        http.MethodGet,
        "/api/v1/workspaces/"+testWorkspaceID+
            "/connections/"+testConnectionID+
            "?environment_id="+testEnvironmentID,
        nil,
    )
    response := httptest.NewRecorder()
    router.ServeHTTP(response, request)
    if response.Code != http.StatusOK {
        t.Fatalf("GET connection = %d %s", response.Code, response.Body.String())
    }
    body := strings.ToLower(response.Body.String())
    for _, forbidden := range []string{
        "secret_ref", "vault_path", "vault_url", "token", "password",
        "private_key", "ca_pem", "dsn", "raw_error", "contract_document",
    } {
        if strings.Contains(body, forbidden) {
            t.Fatalf("response leaked %q: %s", forbidden, body)
        }
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
go test ./internal/authz ./internal/httpapi ./api/openapi -run 'Connection|CredentialReference|Capability|RuntimePublication|Operation' -count=1
```

Expected: FAIL because permissions, schemas and handlers are absent.

- [ ] **Step 3: Add permissions and role matrix**

```go
const (
    PermissionConnectionRead Permission = "CONNECTION_READ"
    PermissionConnectionManage Permission = "CONNECTION_MANAGE"
    PermissionConnectionValidate Permission = "CONNECTION_VALIDATE"
    PermissionConnectionPublish Permission = "CONNECTION_PUBLISH"
    PermissionCredentialReferenceRead Permission = "CREDENTIAL_REFERENCE_READ"
    PermissionCapabilityRead Permission = "CAPABILITY_READ"
    PermissionRunnerRead Permission = "RUNNER_READ"
)

type Request struct {
    Permission Permission
    WorkspaceID string
    EnvironmentID string
    ServiceID string
    Production bool
}
```

角色矩阵固定：

| Role | Read | Manage | Validate | Publish | Credential | Capability |
|---|---:|---:|---:|---:|---:|---:|
| VIEWER | 安全摘要 | 否 | 否 | 否 | 否 | 安全摘要 |
| SRE | 是 | 否 | 是 | 否 | 是 | 是 |
| SERVICE_OWNER | 所属服务 | 否 | 否 | 否 | 否 | 所属服务摘要 |
| APPROVER | 审批上下文摘要 | 否 | 否 | 否 | 否 | 审批摘要 |
| AUDITOR | 是 | 否 | 否 | 否 | 是 | 是 |
| ADMIN | 是 | 是 | 是 | 是 | 是 | 是 |

当前代码尚无 `VIEWER` 时，在 `authn` 同一任务加入角色常量和解析测试。ADMIN 不自动获得业务调查/执行权限。`CONNECTION_PUBLISH` 总是 recent auth；`CONNECTION_VALIDATE` 仅 `Production=true` 时 recent auth。

- [ ] **Step 4: Add complete public paths and safe schemas**

OpenAPI path 固定为下列已批准的 workspace 级路由；每个 operation 都声明 required UUID query `environment_id`，列表只返回该 Environment，写 DTO 若也含 `environment_id` 必须与 query 相同：

```text
GET  /api/v1/workspaces/{workspace_id}/connections
POST /api/v1/workspaces/{workspace_id}/connections
GET  /api/v1/workspaces/{workspace_id}/connections/{connection_id}
POST /api/v1/workspaces/{workspace_id}/connections/{connection_id}/revisions
POST /api/v1/workspaces/{workspace_id}/connections/{connection_id}/revisions/{revision}:validate
POST /api/v1/workspaces/{workspace_id}/connections/{connection_id}/revisions/{revision}:publish
POST /api/v1/workspaces/{workspace_id}/connections/{connection_id}:revoke
GET  /api/v1/workspaces/{workspace_id}/connections/{connection_id}/health-history
GET  /api/v1/workspaces/{workspace_id}/published-targets
GET  /api/v1/workspaces/{workspace_id}/capabilities
GET  /api/v1/workspaces/{workspace_id}/runtime-publications
GET  /api/v1/workspaces/{workspace_id}/credential-references
GET  /api/v1/workspaces/{workspace_id}/credential-references/{reference_id}
POST /api/v1/workspaces/{workspace_id}/credential-references/{reference_id}:validate
GET  /api/v1/workspaces/{workspace_id}/runner-realms
GET  /api/v1/workspaces/{workspace_id}/runner-realms/{realm_id}
GET  /api/v1/workspaces/{workspace_id}/runner-realms/{realm_id}/capability-bindings
GET  /api/v1/workspaces/{workspace_id}/operations/{operation_id}
```

`ConnectionRevision` 安全 Schema：

```yaml
ConnectionRevision:
  type: object
  additionalProperties: false
  required:
    - connection_id
    - revision
    - provider_kind
    - endpoint
    - trust
    - credential_reference
    - network_policy_reference
    - runner_realm
    - capabilities
    - status
    - version
    - effective_actions
  properties:
    connection_id:
      type: string
      format: uuid
    revision:
      type: integer
      format: int64
      minimum: 1
    provider_kind:
      type: string
      enum: [PROMETHEUS, VICTORIALOGS]
    endpoint:
      $ref: '#/components/schemas/SafeEndpointIdentity'
    trust:
      $ref: '#/components/schemas/SafeTrustProjection'
    credential_reference:
      $ref: '#/components/schemas/CredentialReference'
    network_policy_reference:
      type: string
      pattern: '^[a-z0-9][a-z0-9_.-]{0,59}-v1-[a-f0-9]{64}$'
    runner_realm:
      $ref: '#/components/schemas/RunnerRealmSummary'
    capabilities:
      type: array
      minItems: 1
      maxItems: 32
      items:
        $ref: '#/components/schemas/CapabilitySummary'
    status:
      type: string
      enum: [DRAFT, VALIDATING, VALIDATED, REJECTED, PUBLISHED, REVOKED, SUPERSEDED]
    version:
      type: integer
      format: int64
      minimum: 1
    effective_actions:
      type: array
      items:
        type: string
        enum: [CREATE_REVISION, VALIDATE, PUBLISH, REVOKE]
```

CredentialReference Schema 必须 `additionalProperties: false` 且只含 `id/display_name/owner_group/provider_kind/revision/issuer_kind/issuer_id/issuer_revision/usage_role/max_ttl_seconds/status/last_validated_at/last_used_at/redacted`。`redacted` 固定 enum `[true]`。Operation Schema 包含 `id/kind/resource_id/resource_revision/status/phase/progress_percent/failure_code/trace_id/version/created_at/started_at/heartbeat_at/completed_at/effective_actions`，不包含 Runner、Lease、Capsule、Credential 或 raw error。

- [ ] **Step 5: Implement handlers with common contract helpers**

`internal/httpapi/connections.go` 依赖接口：

```go
type ConnectionManager interface {
    List(context.Context, authn.Principal, connectionprofile.ListRequest) (connectionprofile.Page, error)
    Get(context.Context, authn.Principal, assetcatalog.Scope, string) (connectionprofile.Profile, []connectionprofile.Revision, error)
    Create(context.Context, authn.Principal, connectionprofile.CreateProfileCommand, string) (connectionprofile.Profile, connectionprofile.Revision, error)
    CreateRevision(context.Context, authn.Principal, connectionprofile.CreateRevisionCommand, string, int64) (connectionprofile.Revision, error)
    Validate(context.Context, authn.Principal, connectionprofile.ValidateCommand) (operation.Operation, error)
    Publish(context.Context, authn.Principal, runtimepublication.PublishCommand) (operation.Operation, error)
    Revoke(context.Context, authn.Principal, connectionprofile.RevokeCommand) (connectionprofile.Profile, error)
}
```

所有 POST：

- `decodeStrictJSON`，4–32 KiB 精确上限。
- `parseIdempotencyKey`；revision/publish/revoke 还用 `parseVersionETag`。
- 202 返回 Operation 和 `Location`；create 返回 201、`Location`、ETag。
- 401/403/404 不泄露对象是否存在；typed-nil dependency 返回 503。
- Connection/Credential/Runtime/Operation 响应加 `Cache-Control: no-store`。
- 稳定错误码至少覆盖规范第 16 节全部 Connection/Target/Runtime/Credential code。

- [ ] **Step 6: Wire Control Plane dependencies and keep public/internal APIs separate**

在 `httpapi.Dependencies` 增加 ConnectionManager、CredentialReferenceReader/Validator、CapabilityReader、RuntimePublicationReader、RunnerRealmReader、OperationReader；handler 只从 principal Tenant、workspace path 与 required Environment query 组装 `assetcatalog.Scope`，绝不接受 OIDC claim 覆盖请求 Scope。`cmd/control-plane/main.go` 只在 PostgreSQL、OIDC、Signer、Realm/Credential/Trust/Network registries 全部可用时装配管理与 Validation 后端。缺任何安全依赖时 GET 可按权限返回 503，validate/publish 必须关闭；不得回退到 memory 或进程内 fake。

Validation Runner routes 继续只存在 mTLS Gateway listener，不注册到 public `httpapi.Router`。

- [ ] **Step 7: Run API, contract and redaction tests**

Run:

```bash
go test ./internal/authz ./internal/httpapi ./api/openapi ./cmd/control-plane -count=1
go test -race ./internal/httpapi -count=1
```

Expected: PASS；OpenAPI 路由与 handler 一一对应，401/403/404/409/412/428/503、recent auth、cursor、ETag、Idempotency 和 redaction 均通过。

- [ ] **Step 8: Commit**

```bash
git add internal/authz internal/authn api/openapi/control-plane-v1.yaml api/openapi/control_plane_v1_test.go internal/httpapi cmd/control-plane
git commit -m "feat: expose connection publication control plane APIs"
```

### Task 11: Lock generated operation IDs, OIDC session behavior, and API recovery semantics

**Files:**
- Modify: `api/openapi/control-plane-v1.yaml`
- Modify: `api/openapi/control_plane_v1_test.go`
- Modify: `internal/authn/authenticator_test.go`
- Modify: `internal/httpapi/connections_test.go`
- Modify: `internal/httpapi/operations_test.go`
- Modify: `internal/httpapi/router_test.go`

**Interfaces:**
- Consumes: 本文件 Task 10 handlers and configured OIDC verifier。
- Produces: stable generated-client operation IDs；recoverable Location/Operation contract；same-origin browser security headers and safe trace correlation。

- [ ] **Step 1: Write failing contract-hardening tests**

```go
func TestControlPlaneSpecHasStableConnectionOperationIDs(t *testing.T)
func TestConnectionMutationLocationResolvesToSameOperation(t *testing.T)
func TestOperationReplaySurvivesHandlerRestart(t *testing.T)
func TestOIDCClaimsCannotOverrideRequestedWorkspaceEnvironmentScope(t *testing.T)
func TestConnectionResponsesAreNoStoreAndNosniff(t *testing.T)
func TestProblemTraceIDContainsNoInternalError(t *testing.T)
```

Exact `operationId` values:

```text
listConnections createConnection getConnection
createConnectionRevision
validateConnectionRevision publishConnectionRevision revokeConnection
listConnectionHealthHistory listCredentialReferences getCredentialReference
validateCredentialReference
listCapabilities listPublishedTargets listRuntimePublications
listRunnerRealms getRunnerRealm listRunnerRealmCapabilityBindings getOperation
```

- [ ] **Step 2: Verify failure**

Run:

```bash
go test ./api/openapi ./internal/authn ./internal/httpapi -run 'OperationID|Location|Replay|OIDC|NoStore|TraceID' -count=1
```

Expected: FAIL until operation IDs and all recovery/security assertions are explicit.

- [ ] **Step 3: Implement the hardened contract**

- all mutation `Location` values are absolute-path same-origin Operation URLs and the body ID matches;
- handler restart reads replay/Operation from PostgreSQL, never process memory;
- OIDC issuer/audience/expiry/subject are verified and authorization is evaluated against the Workspace path plus required Environment query；claims cannot replace either requested value;
- API rejects browser credential-in-query and unexpected content types;
- safe responses include `Cache-Control: no-store` and `X-Content-Type-Options: nosniff`;
- Problem exposes stable code/title/status/trace ID only; internal error remains server-side redacted telemetry;
- OpenAPI declares all success/error responses, ETag, Idempotency-Key, If-Match, Location and request size bounds.

- [ ] **Step 4: Run API gates**

Run:

```bash
go test ./api/openapi ./internal/authn ./internal/authz ./internal/httpapi ./cmd/control-plane -count=1
go test -race ./internal/httpapi -count=1
```

Expected: PASS；generated operation IDs stable；OIDC Scope, replay recovery and security headers pass.

- [ ] **Step 5: Commit**

```bash
git add api/openapi internal/authn internal/httpapi
git commit -m "test: lock connection API recovery contract"
```
