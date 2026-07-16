# Host and PostgreSQL Diagnostics API and Web Experience Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 提供只暴露固定 capability、typed 参数、安全 Evidence、脱敏摘要与 cleanup 状态的 Control Plane API，并在唯一前端中交付企业级 Asset“固定诊断”体验，绝不出现终端或 SQL 编辑器。

**Architecture:** 应用服务从 Asset/Connection/Target/Capability/Runtime/Snapshot/Grant/Receipt 投影安全 DTO，并以服务端授权与对象状态计算 `effective_actions`。OpenAPI 是唯一契约，HTTP 严格解析并调用 Phase 4 TriggerStarter；React 只使用生成类型、URL 状态与 Query cache，固定表单由 discriminated schema 显式组件实现，不动态解释任意 JSON Schema。

**Tech Stack:** Go 1.26.5、go-chi/v5、OIDC/Keycloak Server 26.6.3、浏览器 `keycloak-js` 26.2.4、现有 authn/authz、OpenAPI 3.1、RFC 9457；Node >=24 <25、pnpm 10.34.0、React 19.2.7、TypeScript 5.9.3、Vite 8.1.4、TanStack Router/Query/Table、React Hook Form、Zod、Radix UI、`lucide-react` 1.24.0、CSS Modules、Vitest、Testing Library、MSW。

## Global Constraints

- 每个 Task 严格采用 Red → Green → Refactor：先运行并保存预期失败，再做最小生产实现，复跑指定测试后才允许重构和提交。
- 浏览器只访问 Control Plane；不得访问 Runner Gateway、Host Probe、AWX、Vault、PostgreSQL 或 Temporal。
- API request 只允许 `capability_id`、schema 对应 typed parameters 和可选 incident context；不得接受 Provider、ProbeID、QueryID、Target、Runtime、Realm、endpoint、DSN、credential、SQL、command、timeout、budget 或 Runner。
- API response 不返回内部 inventory/template 数字 ID、SQL、command、database name、TargetRef、credential reference、Vault/AWX URL、Runner identity、raw error 或完整原始结果。
- 发起运行必须使用 Phase 4 同一 Snapshot/Grant/TriggerStarter；Handler 不直接构造 Task、Grant 或调用 Runner。
- 每次运行只含一个 Asset、一个 Capability；server 固定 Provider/Contract/Target/Runtime/Realm 与预算。
- `effective_actions` 由服务端按 Permission、Service Scope、Asset/Mapping、Capability/Runtime/Grant/Kill Switch、run/cleanup 状态计算；前端不按角色猜。
- `CAPABILITY_READ`、`DIAGNOSTIC_READ`、`DIAGNOSTIC_RUN`、`DIAGNOSTIC_CANCEL`、`SENSITIVE_EVIDENCE_READ` 五个权限完全独立；RUN 不推断 READ/CANCEL，普通 READ 不推断敏感 Evidence。Sensitive Evidence 独立要求 recent auth；ADMIN 不因角色自动得到业务诊断权限。
- 所有 POST 要求 Idempotency-Key；cancel 要求 If-Match；列表使用 signed opaque cursor 和稳定 `(created_at DESC,id DESC)`。
- 所有 schema `additionalProperties:false`、bounded、discriminated；错误为 RFC 9457 stable code + trace_id，不含内部原因。
- Web 必须复用 Phase 1 唯一 `web/`、AppShell、tokens、generated API client、OIDC memory token；若尚未执行 Phase 1，先完成前置，不创建第二应用。
- UI 无 terminal、shell prompt、SQL editor、query text、raw JSON dump、AI 聊天框、头像、霓虹、发光、玻璃拟态。
- WCAG 2.2 AA、键盘、可见焦点、Reduced Motion、44px target；1440/1024/390 三断点。
- 严格 TDD；每个 Task 独立 commit。

---

## Package Position

- 顺序：7 / 8；前置包 01–06 必须完成。
- 前置接口：`DiagnosticRunManager` 所需 repositories、Phase 4 TriggerStarter、diagnostic Receipt/cleanup、authz、Asset detail API。
- 交付给最后一包：稳定公共 API、生成类型、完整 UI、MSW fixtures 与持久化设计规范。
- 本包单元/组件测试通过后仍不能打开生产 Admission，E2E/运维门槛在包 08。

### Task 16: 扩展权限矩阵与唯一 OpenAPI 安全合同

**Files:**
- Modify: `internal/authz/authorizer.go`
- Modify: `internal/authz/authorizer_test.go`
- Modify: `api/openapi/control-plane-v1.yaml`
- Modify: `api/openapi/control_plane_v1_test.go`
- Create: `api/openapi/security_contract_test.go`
- Modify: `web/src/shared/api/schema.d.ts`（只由生成命令更新）

**Interfaces:**
- Consumes: existing Principal、published Service Scope/Service-Asset binding、server-owned requester subject、published on-call roster revision 与 Phase 4 Grant facts。
- Produces: `CAPABILITY_READ`、`DIAGNOSTIC_READ`、`DIAGNOSTIC_RUN`、`DIAGNOSTIC_CANCEL`、`SENSITIVE_EVIDENCE_READ` 五个显式权限，五条 diagnostics paths，strict request/response schemas 和生成 TypeScript types。

- [ ] **Step 1: 写权限分离与 recent-auth 失败测试**

~~~go
func TestDiagnosticPermissionsAreExplicitAndServiceScoped(t *testing.T) {
    cases := []struct {
        role authn.Role
        permission authz.Permission
        allowed bool
    }{
        {authn.RoleViewer, authz.PermissionCapabilityRead, true},
        {authn.RoleViewer, authz.PermissionDiagnosticRead, false},
        {authn.RoleViewer, authz.PermissionDiagnosticRun, false},
        {authn.RoleViewer, authz.PermissionDiagnosticCancel, false},
        {authn.RoleServiceOwner, authz.PermissionCapabilityRead, true},
        {authn.RoleServiceOwner, authz.PermissionDiagnosticRead, true},
        {authn.RoleServiceOwner, authz.PermissionDiagnosticRun, false},
        {authn.RoleSRE, authz.PermissionDiagnosticRun, true},
        {authn.RoleSRE, authz.PermissionDiagnosticRead, true},
        {authn.RoleSRE, authz.PermissionDiagnosticCancel, true},
        {authn.RoleSRE, authz.PermissionSensitiveEvidenceRead, false},
        {authn.RoleIncidentCommander, authz.PermissionDiagnosticRead, true},
        {authn.RoleIncidentCommander, authz.PermissionDiagnosticCancel, true},
        {authn.RoleIncidentCommander, authz.PermissionSensitiveEvidenceRead, true},
        {authn.RoleAdmin, authz.PermissionDiagnosticRun, false},
    }
    assertRolePermissionTable(t, cases)
}

func TestSensitiveEvidenceRequiresRecentAuthentication(t *testing.T) {
    principal := incidentCommanderPrincipal(authenticatedAt(time.Now().Add(-6 * time.Minute)))
    err := authorizer.Authorize(ctx, principal, authz.Request{
        Permission: authz.PermissionSensitiveEvidenceRead,
        Scope: serviceScope(),
    })
    if !errors.Is(err, authz.ErrReauthenticationRequired) { t.Fatalf("error = %v", err) }
}

func TestDiagnosticRunDoesNotImplyReadOrCancel(t *testing.T)
func TestDiagnosticCancelRequiresPermissionAndRequesterOrPublishedOnCall(t *testing.T)
func TestDiagnosticReadAndCancelRejectCrossServiceAndCrossScope(t *testing.T)
func TestSensitiveEvidenceRequiresPublishedOnCallAndRecentAuthentication(t *testing.T)
~~~

权限常量固定：

~~~go
const (
    PermissionCapabilityRead Permission = "CAPABILITY_READ"
    PermissionDiagnosticRead Permission = "DIAGNOSTIC_READ"
    PermissionDiagnosticRun Permission = "DIAGNOSTIC_RUN"
    PermissionDiagnosticCancel Permission = "DIAGNOSTIC_CANCEL"
    PermissionSensitiveEvidenceRead Permission = "SENSITIVE_EVIDENCE_READ"
)
~~~

Capability read 可展示公开参数/预算；Diagnostic read 查看同 Service Scope 的 run 和非敏感安全摘要；Run 只创建运行；Cancel 在显式权限之后还要求当前 subject 是该 run requester 或服务端已发布 on-call roster 的当班成员，caller-supplied owner/on-call claim 无效；只有 classification `SENSITIVE` 的 item details 才要求 Sensitive Evidence、published on-call 关系和 5 分钟 recent auth。Own-run/on-call 是对象关系限制，不能替代任何权限。任何 denied 响应与 not found 对跨 Scope/Service ID 统一，防枚举。

- [ ] **Step 2: 写 OpenAPI path、字段 allowlist 与敏感属性失败测试**

~~~go
func TestDiagnosticContractContainsOnlySafeScopedPaths(t *testing.T) {
    document := loadControlPlaneOpenAPI(t)
    for _, path := range []string{
        "/api/v1/workspaces/{workspace_id}/environments/{environment_id}/assets/{asset_id}/diagnostic-capabilities",
        "/api/v1/workspaces/{workspace_id}/environments/{environment_id}/assets/{asset_id}/diagnostic-runs",
        "/api/v1/workspaces/{workspace_id}/environments/{environment_id}/diagnostic-runs/{run_id}",
        "/api/v1/workspaces/{workspace_id}/environments/{environment_id}/diagnostic-runs/{run_id}:cancel",
        "/api/v1/workspaces/{workspace_id}/environments/{environment_id}/diagnostic-runs/{run_id}/evidence",
    } { assertPath(t, document, path) }
    assertNoDiagnosticSchemaPropertyMatches(t, document,
        `(?i)(command|argv|env|path|script|shell|pty|ssh|winrm|forward|sftp|sql|query_text|dsn|password|secret|token|vault|endpoint|server_name|inventory_id|template_id|runner_id|raw_error|raw_result|timeout)`)
}

func TestDiagnosticRunRequestIsAClosedTypedUnion(t *testing.T) {
    schema := diagnosticRunRequestSchema(t)
    assertRequiredOnly(t, schema, []string{"capability_id", "parameters"})
    assertDiscriminator(t, schema, "capability_id", []string{
        "HOST_SYSTEM_INFO", "HOST_CPU_MEMORY_SNAPSHOT", "HOST_DISK_USAGE",
        "HOST_NETWORK_LISTENERS", "HOST_SYSTEMD_STATUS", "HOST_WINDOWS_SERVICE_STATUS",
        "HOST_BOUNDED_LOG_WINDOW", "POSTGRES_SERVER_HEALTH", "POSTGRES_CONNECTION_SNAPSHOT",
        "POSTGRES_LOCK_SNAPSHOT", "POSTGRES_REPLICATION_SNAPSHOT",
        "POSTGRES_DATABASE_SIZE", "POSTGRES_SLOW_QUERY_SUMMARY",
    })
}
~~~

- [ ] **Step 3: 运行失败测试**

Run:

~~~bash
go test ./internal/authz ./api/openapi -run 'Test(Diagnostic|SensitiveEvidence)' -count=1
~~~

Expected: FAIL because permissions and diagnostics OpenAPI paths/schemas do not exist.

- [ ] **Step 4: 增量实现 OpenAPI 3.1 paths 与 schema**

所有路径要求 `workspace_id` 与 `environment_id` UUID path；handler 从 path 与 Principal Tenant 组装唯一 Scope，不接受 query/body/claim 覆盖。定义：

- `DiagnosticCapabilityPage`：asset ID、items、page meta、collection `effective_actions`；item 只有 capability ID、display name、description、provider display enum、parameter schema discriminator、budget、availability/reason、classification、effective_actions。
- `DiagnosticRunRequest`：oneOf 十三个 capability request；Host/PostgreSQL 参数枚举与包 01/05 完全一致。可选 `incident_id` UUID 只用于关联，不扩大 Scope。
- `DiagnosticRun`：run/asset/capability ID、status、phase、phase timeline、安全 parameter summary、budget/usage、result summary、DLP summary、cleanup summary、Evidence summary、failure code、trace/audit ID、version/etag/timestamps、effective_actions。
- `DiagnosticEvidencePage`：schema version、classification、typed item union、count/bytes/truncated/redaction_count、collected_at、content_hash；不含 raw download URL。
- `DiagnosticRunPage`：Asset 历史列表 signed cursor。

状态枚举固定：Run `QUEUED|AUTHORIZED|RUNNING|CLEANING_UP|SUCCEEDED|FAILED|CANCELLED|TIMED_OUT|MANUAL_REQUIRED`；phase `SNAPSHOT|GRANT|CLAIM|CREDENTIAL|EXECUTE|DLP|EVIDENCE|CLEANUP|TERMINAL`；cleanup `NOT_REQUIRED|PENDING|REVOKED|NO_CREDENTIAL|UNCERTAIN|MANUAL_REQUIRED`；DLP `NOT_RUN|PASSED|REDACTED|REJECTED`。EffectiveAction 固定增加 `RUN_DIAGNOSTIC|CANCEL_DIAGNOSTIC|READ_DIAGNOSTIC_EVIDENCE`，分别只从对应权限和对象事实计算，不能由 RUN 派生。

POST run 返回 202 + Location；相同 idempotency key/body 返回同 run，不同 body 409。Cancel 需要 Idempotency-Key 与 If-Match，返回 202。Evidence classification sensitive 时 401 reauthentication-required 或 403，不降级返回部分字段。

- [ ] **Step 5: 生成类型并验证契约**

Run:

~~~bash
go test ./internal/authz ./api/openapi -count=1
pnpm --dir web generate:api
pnpm --dir web generate:api:check
pnpm --dir web typecheck
git diff --check -- web/src/shared/api/schema.d.ts
~~~

Expected: Go tests and typecheck PASS；生成文件发生预期 diff、无 whitespace error，且只由 OpenAPI 生成，无手工类型副本。最终阶段验收会在提交后重新生成并要求 clean diff。

- [ ] **Step 6: Commit**

~~~bash
git add internal/authz api/openapi/control-plane-v1.yaml api/openapi web/src/shared/api/schema.d.ts
git commit -m "feat: define diagnostic control plane api"
~~~

### Task 17: 实现 Diagnostics 应用服务与严格 HTTP 边界

**Files:**
- Create: `internal/diagnosticapi/types.go`
- Create: `internal/diagnosticapi/service.go`
- Create: `internal/diagnosticapi/service_test.go`
- Create: `internal/diagnosticapi/postgres/queries.go`
- Create: `internal/diagnosticapi/postgres/queries_integration_test.go`
- Create: `internal/httpapi/diagnostic_capabilities.go`
- Create: `internal/httpapi/diagnostic_runs.go`
- Create: `internal/httpapi/diagnostic_evidence.go`
- Create: `internal/httpapi/diagnostics_test.go`
- Modify: `internal/httpapi/router.go`
- Modify: `cmd/control-plane/main.go`
- Modify: `cmd/control-plane/main_test.go`

**Interfaces:**
- Consumes: Asset Reader、Phase 2 published projections、Phase 4 TriggerStarter/Grant、000019 registries/receipt/cleanup、authz、idempotency store。
- Produces: `CapabilityManager`、`RunManager`、`EvidenceManager` 与五条公共 handlers。

- [ ] **Step 1: 写服务端固定解析、effective_actions 与跨 Scope 失败测试**

~~~go
func TestRequestRunIgnoresNoCallerRuntimeChoicesBecauseTheyDoNotExist(t *testing.T) {
    command := diagnosticapi.RequestRunCommand{
        Scope: scope(), AssetID: assetID,
        CapabilityID: "POSTGRES_LOCK_SNAPSHOT",
        Parameters: json.RawMessage(`{"minimum_wait_seconds":5}`),
        IdempotencyKey: "diag-20260713-001", Actor: actor(),
    }
    run, err := service.RequestRun(ctx, command)
    if err != nil { t.Fatal(err) }
    started := starter.singleRequest(t)
    assertServerResolved(t, started, snapshotID, grantID, targetDigest, runtimeDigest, realmID, queryContractDigest)
    if run.Status != diagnosticapi.RunQueued { t.Fatalf("status=%s", run.Status) }
}

func TestEffectiveActionsRespectObjectStateAndAuthorization(t *testing.T) {
    cases := []struct { state fixtureState; want []diagnosticapi.EffectiveAction }{
        {eligibleState(), []diagnosticapi.EffectiveAction{diagnosticapi.ActionRun}},
        {quarantinedState(), nil}, {mappingAmbiguousState(), nil},
        {runtimeDriftedState(), nil}, {killSwitchClosedState(), nil},
        {cleanupUncertainState(), nil},
    }
    for _, tc := range cases { assertEffectiveActions(t, service, tc.state, tc.want) }
}

func TestCrossScopeRunAndEvidenceAreIndistinguishableFromUnknown(t *testing.T) {
    crossErr := service.GetRun(ctx, otherScopeRequest(runID))
    unknownErr := service.GetRun(ctx, scopeRequest(unknownID))
    if !errors.Is(crossErr, store.ErrNotFound) || reflect.TypeOf(crossErr) != reflect.TypeOf(unknownErr) {
        t.Fatalf("cross=%v unknown=%v", crossErr, unknownErr)
    }
}

func TestGetRunRequiresDiagnosticReadEvenForRequester(t *testing.T)
func TestCancelRequiresDiagnosticCancelAndRequesterOrCurrentOnCall(t *testing.T)
func TestCancelRejectsTerminalRunStaleETagAndCrossScope(t *testing.T)
func TestSensitiveEvidenceRequiresPermissionOnCallAndRecentAuth(t *testing.T)
func TestCapabilitiesRequireCapabilityReadNotDiagnosticRun(t *testing.T)
~~~

- [ ] **Step 2: 运行测试并确认 manager 缺失**

Run:

~~~bash
go test ./internal/diagnosticapi/... ./internal/httpapi -run 'Test(RequestRun|EffectiveActions|CrossScope)' -count=1
~~~

Expected: FAIL because diagnostics service/handlers do not exist.

- [ ] **Step 3: 实现窄 manager 与单资产 TriggerStarter 组合**

~~~go
type CapabilityManager interface {
    List(context.Context, ListCapabilitiesRequest) (CapabilityPage, error)
}

type RunManager interface {
    Request(context.Context, RequestRunCommand) (RunView, error)
    ListForAsset(context.Context, ListRunsRequest) (RunPage, error)
    Get(context.Context, GetRunRequest) (RunView, error)
    Cancel(context.Context, CancelRunCommand) (RunView, error)
}

type EvidenceManager interface {
    Get(context.Context, GetEvidenceRequest) (EvidencePage, error)
}
~~~

Request 流程固定：严格参数 → authorize `DIAGNOSTIC_RUN` + published Service scope → Asset 必须 ACTIVE/EXACT → 实时 Capability/Target/Runtime/Realm available → Phase 4 Preview single asset/capability → 新 Snapshot/Grant → 同一 TriggerStarter。客户端 budget 被结构上排除；服务端从 capability 与 Grant 取交集。SHADOW policy 不可由该接口转换为执行。

Get/List 从 Receipt、Task、Grant、cleanup、Evidence 安全投影联结，禁止 N+1 secret lookup；始终先以 Scope+Service 读取安全 ownership facts，再授权 `DIAGNOSTIC_READ`，即使 requester 查看自己的 run 也不能跳过。Cancel 独立授权 `DIAGNOSTIC_CANCEL`，并要求 requester subject 相等或当前 published on-call roster membership；只允许非 terminal 且 ETag 当前。Evidence manager 在读取 details 前独立授权 `DIAGNOSTIC_READ`，对 sensitive details 再授权 `SENSITIVE_EVIDENCE_READ`、published on-call 与 recent auth；公开 run 只保留 summary。`effective_actions` 排序去重，Run/Cancel/Read Evidence 分别只在自身权限和对象条件满足时出现。

- [ ] **Step 4: 实现 strict HTTP、幂等、ETag 与缓存策略**

Handlers 用全局 strict decoder（unknown/duplicate/trailing/body cap），从 OIDC/context 取 Scope/Actor，绝不信 body identity。所有响应 `Cache-Control: no-store`、`X-Content-Type-Options:nosniff`；Evidence 再加 `Content-Security-Policy: default-src 'none'`。Cursor 验签并绑定 Scope/Asset/filter。

Run request body 最大 8 KiB；Evidence response 最大 512 KiB，实际 capability cap 更小。Idempotency hash 用 JCS 绑定 Scope、Asset、capability、parameters、incident context；cancel 绑定 run/version/reason。ETag 为强版本 `"diagnostic-run-{version}"`。错误映射：invalid 400、reauth 401、forbidden 403、not found 404、conflict 409、precondition 412、admission/kill switch 423、budget 429、dependency 503；detail 固定且不含上游错误。

- [ ] **Step 5: 运行 HTTP、真实 PostgreSQL query 与 secret scan**

Run:

~~~bash
go test -race -shuffle=on -count=1 ./internal/diagnosticapi/... ./internal/httpapi ./cmd/control-plane
AIOPS_TEST_POSTGRES_DSN="$AIOPS_TEST_POSTGRES_DSN" go test -race -count=1 ./internal/diagnosticapi/postgres -run 'TestQueries'
~~~

Expected: PASS；Service Scope、own-run/on-call、五权限分离、cancel、跨 Scope、idempotency、ETag、recent auth、safe projection、effective_actions 和 response headers 全部通过。

- [ ] **Step 6: Commit**

~~~bash
git add internal/diagnosticapi internal/httpapi cmd/control-plane
git commit -m "feat: expose governed diagnostic runs"
~~~

### Task 18: 持久化并实现企业级“固定诊断”前端

**Files:**
- Create: `docs/design/frontend/host-postgresql-diagnostics.md`
- Modify: `web/src/features/assets/AssetDetailPage.tsx`
- Create: `web/src/features/diagnostics/api.ts`
- Create: `web/src/features/diagnostics/types.ts`
- Create: `web/src/features/diagnostics/DiagnosticsTab.tsx`
- Create: `web/src/features/diagnostics/CapabilityRail.tsx`
- Create: `web/src/features/diagnostics/DiagnosticParameterForm.tsx`
- Create: `web/src/features/diagnostics/RunTimeline.tsx`
- Create: `web/src/features/diagnostics/EvidencePanel.tsx`
- Create: `web/src/features/diagnostics/CleanupStatus.tsx`
- Create: `web/src/features/diagnostics/RunHistory.tsx`
- Create: `web/src/features/diagnostics/diagnostics.module.css`
- Create: `web/src/features/diagnostics/DiagnosticsTab.test.tsx`
- Create: `web/src/features/diagnostics/DiagnosticParameterForm.test.tsx`
- Create: `web/src/features/diagnostics/EvidencePanel.test.tsx`
- Create: `web/src/test/msw/fixtures/diagnostics.ts`
- Create: `web/src/test/msw/handlers/diagnostics.ts`
- Modify: `web/src/test/msw/handlers.ts`
- Modify: `web/src/test/msw/browser.ts`
- Modify: `web/src/test/msw/server.ts`

**Interfaces:**
- Consumes: generated diagnostics DTO、唯一 API client、Asset Detail route/AppShell/tokens、server `effective_actions`。
- Produces: 可深链、响应式、无障碍的 capability 选择、固定表单、运行轨道、Evidence/cleanup/history UI 与完整设计文档。

- [ ] **Step 1: 先写交互、URL、权限与危险状态组件测试**

~~~tsx
it("restores the selected capability and run from the URL", async () => {
  renderAssetDiagnostics("?tab=diagnostics&diagnostic_capability=POSTGRES_LOCK_SNAPSHOT&diagnostic_run=run-1");
  expect(await screen.findByRole("heading", { name: "锁等待快照" })).toBeVisible();
  expect(screen.getByRole("dialog", { name: "诊断运行详情" })).toHaveAttribute("data-run-id", "run-1");
});

it("never renders terminal, SQL, endpoint, or free-form command controls", async () => {
  renderAssetDiagnostics("?tab=diagnostics");
  await screen.findByText("固定诊断");
  for (const name of [/terminal/i, /sql editor/i, /command/i, /endpoint/i, /dsn/i]) {
    expect(screen.queryByRole("textbox", { name })).not.toBeInTheDocument();
  }
});

it("uses effective_actions and persists cleanup uncertainty", async () => {
  server.use(diagnosticRunHandler({
    status: "MANUAL_REQUIRED", cleanup: { state: "UNCERTAIN" }, effective_actions: [],
  }));
  renderAssetDiagnostics("?tab=diagnostics&diagnostic_run=run-uncertain");
  expect(await screen.findByText("凭据吊销结果不确定")).toBeVisible();
  expect(screen.getByText("已停止新的诊断运行")).toBeVisible();
  expect(screen.queryByRole("button", { name: "再次运行" })).not.toBeInTheDocument();
});

it("keeps redaction and truncation visible beside evidence", async () => {
  server.use(diagnosticEvidenceHandler({ truncated: true, redaction_count: 4 }));
  renderEvidence();
  expect(await screen.findByText("已截断到安全上限")).toBeVisible();
  expect(screen.getByText("4 个敏感值已脱敏")).toBeVisible();
});
~~~

- [ ] **Step 2: 运行组件测试并确认页面缺失**

Run:

~~~bash
pnpm --dir web vitest run src/features/diagnostics
~~~

Expected: FAIL because diagnostics feature and design components do not exist.

- [ ] **Step 3: 写完整前端设计持久化文档**

`docs/design/frontend/host-postgresql-diagnostics.md` 必须是后续实现唯一细节依据，至少固定：

1. 用户/任务：SRE 选择固定诊断、Incident Commander 查看 Evidence、值班人员识别 cleanup uncertain；明确非目标为远程管理和 SQL 分析台。
2. 信息架构：Asset Header → Overview/Connections/Capabilities/Fixed Diagnostics/Audit；Diagnostics Tab 内 capability rail、parameter workspace、run history；run detail 为 URL 可寻址侧抽屉。
3. 1440 布局：12 列网格，rail 280px、workspace minmax 480–720px、context 320px；详情抽屉 560px；表格密度 40px row。
4. 1024 布局：rail 240px + workspace，预算/context 下移；抽屉 52vw/min 480px。
5. 390 布局：capability 使用可搜索 sheet，表单单列，run detail full-screen，Evidence table 转 key/value cards；sticky action footer 不遮焦点。
6. 视觉 token：只引用 Phase 1 CSS variables；neutral canvas、white surface、1px border、4–6px radius；status 用 icon+text+color，禁止仅颜色表达。
7. Type scale、spacing、table、badge、empty/skeleton/error/forbidden/reauth/partial/budget/DLP/cleanup/manual states 的精确组件行为。
8. 十三个 capability 的中文名、说明、参数 label/help、默认枚举、预算文案与 Evidence column mapping。
9. 运行轨道八阶段与状态映射；active pulse 在 Reduced Motion 下静态；失败停在对应阶段并显示 stable guidance。
10. Evidence DLP：脱敏值显示 `••••` + “已脱敏”，HMAC 显示稳定短指纹；禁止 reveal/copy raw；截断提示永不只用 Toast。
11. 行为：运行确认摘要、不二次输入；202 打开 run drawer 并轮询指数退避；Cancel 说明 cleanup 会继续；412 刷新 diff；401 调用 Phase 1 `reauthenticate(returnURL)` 强制新登录并回到原动作，后端仍校验 `auth_time`。
12. URL、Query keys、缓存隔离、focus restore、keyboard order、ARIA live、screen reader label、44px target、contrast 与 locale/date rules。
13. analytics 只记录 capability enum、status、duration bucket，不记录参数值/Evidence/Asset name。
14. 明确禁止组件：terminal emulator、code editor、textarea SQL、raw JSON、download raw、copy command、自由路径输入、AWX/DB internal links。

- [ ] **Step 4: 实现显式 capability 表单与数据 hooks**

不要运行时渲染任意 JSON Schema。`DiagnosticParameterForm` 对十三个 capability 使用 exhaustiveness-checked switch 和生成 DTO：无参数显示“无需输入”；其余只用 Select/Radio，禁止自由 text。Systemd/Windows service/log source 的 enum option 来自 Capability response 的公开 opaque ID/display label，提交 ID，页面不显示 path。

Query keys 全部含 tenant/workspace/environment/asset；route search schema 固定 `tab`、`diagnostic_capability`、`diagnostic_run`。POST 使用 UUID idempotency；成功 invalidate capability/history/run，不把 sensitive Evidence放入持久 cache。Evidence query `gcTime:0`，切换 Scope/关闭抽屉/re-auth failure 时显式 remove。

- [ ] **Step 5: 实现高保真页面、运行轨道与 Evidence**

Desktop capability rail 显示 category、availability、上次状态；workspace 顶部是说明与 Provider display，中央为固定表单，右侧预算卡展示最大 duration/items/bytes/classification。Primary CTA 文案“运行固定诊断”，只有 `RUN_DIAGNOSTIC` 时存在。

Run drawer 顶部固定 Asset/Capability/status/audit ID，八阶段轨道置于 Evidence 前；cleanup 即使查询成功也保持可见直到确认。Evidence 按 capability 使用语义化 table/definition list/chart-free snapshot；无原始 JSON。History 显示 start time、capability、outcome、duration、DLP、cleanup，支持 cursor，不支持全文结果搜索。

所有 asynchronous state 是页面内持久区域；Toast 只用于“已复制 audit ID”等低风险反馈。Fatal/uncertain 提供“查看处置指引”链接到安全文档，不提供重试直到 server effective action 恢复。

- [ ] **Step 6: 运行组件、类型、lint 与 build**

Run:

~~~bash
pnpm --dir web vitest run src/features/diagnostics
pnpm --dir web typecheck
pnpm --dir web lint
pnpm --dir web build
~~~

Expected: PASS；URL 恢复、effective_actions、typed form、all states、responsive class contracts 与 secret-free fixture 全通过。

- [ ] **Step 7: Commit**

~~~bash
git add docs/design/frontend/host-postgresql-diagnostics.md web/src/features/diagnostics web/src/features/assets/AssetDetailPage.tsx web/src/test/msw
git commit -m "feat: add fixed diagnostic asset experience"
~~~
