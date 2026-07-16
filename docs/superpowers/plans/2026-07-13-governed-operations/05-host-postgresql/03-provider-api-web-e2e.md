# Diagnostic Provider API, Publication Wizard, and Availability E2E Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 通过唯一 OpenAPI、OIDC/authz 和企业级六步连接向导完整交付 Host Probe、AWX、PostgreSQL 三条发布路径，交付发布后可绑定的 `AWX_INVENTORY` 增量来源，并以真实协议 E2E 证明服务端分配 canonical Connection ID/Revision、最近认证发布、N/N+1 和各 Provider 独立 `AVAILABLE` 门禁。

**Architecture:** 公共 API 扩展 Phase 2 workspace 级 Connection 路由，所有请求显式绑定 required `environment_id`；创建草稿和 N+1 修订由服务器分配身份并返回 canonical `Location/ETag`。前端只消费生成类型和安全引用，第一次持久化后立即从临时 `/connections/new` 跳转 canonical Revision 路由。E2E 使用真实 Keycloak Server 26.6.3、PostgreSQL、mTLS Validation Gateway/Runner、Host Probe、AWX 和 PostgreSQL，公共浏览器链与 Runner 私有协议不混用。

**Tech Stack:** OpenAPI 3.1、Go 1.26.5、chi v5、Keycloak Server 26.6.3、浏览器 `keycloak-js` 26.2.4/OIDC、PostgreSQL 18.4+、Node 24、pnpm 10.34.0、React 19.2.7、TypeScript 5.9.3、Vite 8.1.4、TanStack Router/Query、React Hook Form、Zod、`lucide-react` 1.24.0、CSS Modules、Vitest、MSW（测试）、Playwright 1.61.1、axe 4.12.1、Docker Compose。

## Global Constraints

- 每个 Task 严格执行 Red → Green → Refactor；OpenAPI/authz、HTTP、生成类型、Web、真实协议 E2E 必须同包验收，不能用静态页面或 MSW 代替生产链。
- 公共 Connection 路径保持 Phase 2 已批准形式；Workspace 来自 path、Environment 来自 required query 与 DTO 同值，Tenant 来自已验证 principal，三者不一致即 fail closed。
- Connection ID、Revision、Operation ID、Runtime digest、Target ref 均由服务器生成；浏览器不得自称 canonical 身份、验证成功、最近认证、Provider 可用或 Runtime 已应用。
- Host/AWX/PostgreSQL draft 只含安全判别字段和 opaque reference；禁止任意 URL/IP/header/body、Secret、PEM、DSN、SQL、命令、路径、脚本、template/inventory 数字 ID 或 extra_vars。
- `CONNECTION_MANAGE` 只允许草稿；validate 必须 `CONNECTION_VALIDATE`，publish 必须 `CONNECTION_PUBLISH`、最近认证、If-Match、Idempotency-Key 与 change reason；读 Credential/Capability/Realm 分别校验已有权限。
- Provider `AVAILABLE` 是 exact Scope+Connection+Revision+Target+CapabilitySet+Bundle+Realm gate；前端不得把一个 Provider 的绿灯、Connection 健康或 Validation 成功推断为其他 Provider/Revision 可运行。
- 草稿只存服务端；Web 不使用 localStorage/sessionStorage/Redux 保存 API body、Credential 或 Token。OIDC Authorization Code + PKCE、`login-required`、内存 Token 和请求前刷新保持不变。
- 低 AI 感高保真控制台：浅色高密度、海军蓝导航、克制蓝色动作、32px 控件、38–40px 表格行、4–6px 圆角；禁止聊天气泡、机器人头像、霓虹、发光、渐变、玻璃和营销卡片。

## Red → Green → Refactor

1. **Red:** 先让权限、Scope、canonical route、三 Provider 表单、真实协议和独立 gate 测试因缺少扩展而失败。
2. **Green:** 只实现服务端明确拥有的 draft/revision 与三种判别分支，所有治理状态以 API 事实为准。
3. **Refactor:** 全绿后抽取安全表单原语和 Provider gate 展示，不抽象成任意 JSON Schema renderer、URL builder 或通用连接测试器。

---

## Package Position

- 顺序：3 / 8；前置包 01–02 必须完成，所有 Provider/Runtime/Source identities 均来自其 `Produces`。
- 交付给包 04–08：稳定 OpenAPI/authz、server draft→canonical route、三 Provider 六步 UI、真实协议 Provider/AWX Source evidence。
- 本包完成仍不授权 Host/PostgreSQL diagnostic capability；后续 contract/executor/E2E 必须逐能力打开，生产 READ Admission 保持关闭。

### Task 6: 扩展 OpenAPI、authz、HTTP 与服务端 canonical Draft/Revision 流

**Files:**
- Modify: `internal/authz/authorizer.go`
- Modify: `internal/authz/authorizer_test.go`
- Modify: `internal/connectionprofile/service.go`
- Modify: `internal/connectionprofile/service_test.go`
- Modify: `internal/httpapi/connections.go`
- Modify: `internal/httpapi/connections_test.go`
- Modify: `internal/httpapi/capabilities.go`
- Modify: `internal/httpapi/capabilities_test.go`
- Modify: `internal/httpapi/runtime_publications.go`
- Modify: `internal/httpapi/runtime_publications_test.go`
- Modify: `internal/httpapi/asset_sources.go`
- Modify: `internal/httpapi/asset_sources_test.go`
- Modify: `internal/httpapi/router.go`
- Modify: `internal/httpapi/router_test.go`
- Modify: `api/openapi/control-plane-v1.yaml`
- Modify: `api/openapi/control_plane_v1_test.go`
- Modify: `cmd/control-plane/main.go`
- Modify: `cmd/control-plane/main_test.go`

**Interfaces:**
- Consumes: Task 3–5 Provider schema、Credential admission、Validation Operation、Provider Runtime Gate；Phase 2 Connection/Credential/Capability/Realm/Operation services。
- Produces: existing API paths with new safe discriminated schemas and exact operation IDs:

```text
POST /api/v1/workspaces/{workspace_id}/connections
  operationId: createConnection
POST /api/v1/workspaces/{workspace_id}/connections/{connection_id}/revisions
  operationId: createConnectionRevision
POST /api/v1/workspaces/{workspace_id}/connections/{connection_id}/revisions/{revision}:validate
  operationId: validateConnectionRevision
POST /api/v1/workspaces/{workspace_id}/connections/{connection_id}/revisions/{revision}:publish
  operationId: publishConnectionRevision
GET  /api/v1/workspaces/{workspace_id}/capabilities
GET  /api/v1/workspaces/{workspace_id}/runtime-publications
GET  /api/v1/workspaces/{workspace_id}/operations/{operation_id}
POST /api/v1/workspaces/{workspace_id}/asset-sources
  operationId: createAssetSource
```

所有路径要求 `environment_id`。Create 返回 `201`、canonical body、`Location: /api/v1/workspaces/{workspace_id}/connections/{connection_id}?environment_id=...`、Revision `ETag`；validate/publish 返回 durable Operation `202` 和 Operation `Location`。

- [ ] **Step 1: 写失败的权限、Scope、canonical ID 与 redaction 测试**

```go
func TestCreateDiagnosticDraftRequiresConnectionManageAndServerAssignedIdentity(t *testing.T)
func TestCreateDiagnosticNPlusOneRequiresIfMatchAndMonotonicServerRevision(t *testing.T)
func TestValidateDiagnosticRevisionRequiresConnectionValidate(t *testing.T)
func TestPublishDiagnosticRevisionRequiresPublishRecentAuthAndChangeReason(t *testing.T)
func TestDiagnosticProviderRoutesRejectCrossEnvironmentAndCrossWorkspaceReferences(t *testing.T)
func TestDiagnosticConnectionResponsesRedactEndpointCredentialAndProviderInternals(t *testing.T)
func TestDiagnosticRuntimeDTOKeepsProviderGatesIndependent(t *testing.T)
func TestPublicRouterDoesNotExposeDiagnosticValidationRunnerProtocol(t *testing.T)
func TestAWXInventorySourceRequiresMatchingAvailableIntegrationRuntime(t *testing.T)
func TestAWXInventorySourceRequestCannotOverrideCursorEndpointCredentialOrTemplate(t *testing.T)
```

权限矩阵还必须证明 `CONNECTION_READ` 不能创建/验证/发布，`CONNECTION_MANAGE` 不能验证/发布，`CONNECTION_VALIDATE` 不能发布，Credential/Capability/Realm read 不从 `CONNECTION_READ` 推断；同一不存在或越界对象的 403/404 不泄露存在性。

- [ ] **Step 2: 运行测试并确认 Red**

Run:

```bash
go test ./internal/authz ./internal/connectionprofile ./internal/httpapi ./api/openapi ./cmd/control-plane -run 'Diagnostic|HostProbe|AWX|PostgreSQL|ConnectionDraft' -count=1
```

Expected: FAIL，因为 OpenAPI union、server-assigned flow 与 Provider gate DTO 尚未扩展。

- [ ] **Step 3: 锁定公共判别 Schema 与安全响应**

OpenAPI `DiagnosticConnectionDraft` 使用 `oneOf + discriminator(provider_kind)`，三个 variant 都 `additionalProperties:false`：

```yaml
HostProbeConnectionDraft:
  required: [provider_kind, asset_id, asset_network_identity_id, server_name, listener_profile, trust_reference_id, credential_reference_id, credential_reference_revision, network_policy_reference_id, runner_realm_id, capability_definition_refs]
  properties:
    provider_kind: {type: string, const: HOST_PROBE_MTLS}
    listener_profile: {type: string, enum: [HOST_PROBE_8443, HOST_PROBE_9443]}
AWXConnectionDraft:
  required: [provider_kind, asset_id, integration_id, controller_asset_id, controller_network_identity_id, organization_reference, trust_reference_id, credential_reference_id, credential_reference_revision, network_policy_reference_id, runner_realm_id, capability_definition_refs]
  properties:
    provider_kind: {type: string, const: AWX_API}
PostgreSQLConnectionDraft:
  required: [provider_kind, asset_id, database_asset_id, asset_network_identity_id, server_name, port_profile, database_reference, replica_preference, trust_reference_id, credential_reference_id, credential_reference_revision, network_policy_reference_id, runner_realm_id, capability_definition_refs]
  properties:
    provider_kind: {type: string, const: POSTGRESQL}
    port_profile: {type: string, enum: [POSTGRESQL_5432, POSTGRESQL_6432]}
    replica_preference: {type: string, enum: [PRIMARY_ALLOWED, READ_REPLICA_REQUIRED]}
```

`integration_id` 只接受 Phase 1 canonical installed Integration UUID，服务器重读其 Provider/Workspace；它不是 endpoint 或 Credential。显式 `not`/contract test 禁止 `connection_id/revision/status/url/endpoint/ip/header/body/credential/secret/token/pem/dsn/sql/command/argv/path/script/inventory_id/template_id/extra_vars`。Response 只含 canonical ID/revision、safe endpoint projection、reference IDs/revisions、四类正交状态、digests、timestamps、`effective_actions`。

现有 `createAssetSource` 必须复用 Phase 1 完整命令，只接受名称、服务端返回的 opaque `source_profile_id`、允许的 authority Environment 选择与固定 sync/schedule 选项；客户端不得提交 `source_kind/provider_kind/integration_id`。AWX Connection 详情 API 只有在 exact published `AWX_API` Connection Runtime gate 可用时才返回一个 eligible Profile selector；Manager 由该 selector 解析 `AWX_INVENTORY/AWX_READ_V1`、canonical Integration、限流/freshness/mapping 和当前 revision binding，并从 installed Integration authority scope 解析恰好一个 Environment。不存在、重复、非 `AVAILABLE`、revision/digest drift 或 Scope 不匹配返回稳定 `RUNTIME_PUBLICATION_NOT_READY`，不创建 Source。请求不能提交 cursor、schedule payload、endpoint、Credential、inventory/template ID 或 Provider JSON。

- [ ] **Step 4: 实现服务端 Draft → canonical ID/Revision 与授权链**

既有 `createConnection` operation 的产品语义固定为“创建 stable Profile 与首个 DRAFT Revision”。它在一个 PostgreSQL 事务内从 authenticated principal/required Scope 构造命令；使用 Phase 2 已注入的服务端 ID source 生成 canonical UUID Connection ID；固定首个 Revision `1`；重新读取 Asset/network/Credential/Realm/Capability references；写 stable Profile+immutable Revision+idempotency snapshot；返回 canonical projection。请求携带 ID/revision/status 一律 strict JSON 拒绝。

既有 `createConnectionRevision` operation 锁 Profile，创建下一个 DRAFT Revision；它要求 `If-Match` 当前 Profile version，以 `max(revision)+1` 分配 N+1，不能覆盖、删除或复用 N。validate/publish 分别重新授权并重读当前事实；publish additionally 要求 `auth_time` 在 5 分钟内、非空 change reason、validated digest、terminal cleanup、exact provider binding，并创建 Runtime Operation。不得另增平行 draft API 或改写 Phase 2 锁定的 operationId。

```go
type DraftCreated struct {
    ConnectionID string
    Revision     int64
    ETag         string
    Location     string
}

func (service *Service) CreateDiagnosticDraft(
    context.Context,
    authz.Principal,
    CreateDiagnosticDraftCommand,
) (DraftCreated, error)
```

HTTP handler 不读取 Subject/Role/auth_time override；ID generator、Clock、Repository、Asset/Network/Credential/Realm/Capability readers 任一缺失时 mutation 返回稳定 503，绝不回退 memory。

- [ ] **Step 5: 运行 Green、生成契约与 Refactor**

Run:

```bash
go test ./internal/authz ./internal/connectionprofile ./internal/httpapi ./api/openapi ./cmd/control-plane -count=1
pnpm --dir web generate:api
pnpm --dir web generate:api:check
git diff --exit-code -- web/src/shared/api/schema.d.ts
```

Expected: PASS；OpenAPI/handler/operationId 一一对应，生成类型 clean，Scope/recent-auth/ETag/idempotency/redaction 测试全绿。

- [ ] **Step 6: Commit**

```bash
git add internal/authz internal/connectionprofile internal/httpapi api/openapi/control-plane-v1.yaml api/openapi/control_plane_v1_test.go cmd/control-plane web/src/shared/api/schema.d.ts
git commit -m "feat: expose diagnostic connection publication api"
```

---

### Task 7: 实现三 Provider 六步高保真连接向导与 canonical 路由恢复

**Files:**
- Modify: `web/src/features/connections/api/connectionApi.ts`
- Modify: `web/src/features/connections/api/connectionApi.test.ts`
- Modify: `web/src/features/connections/routes/connectionCreateRoute.tsx`
- Create: `web/src/features/connections/routes/connectionRevisionEditRoute.tsx`
- Modify: `web/src/features/connections/wizard/connectionWizardSchema.ts`
- Modify: `web/src/features/connections/wizard/ConnectionPublicationWizard.tsx`
- Modify: `web/src/features/connections/wizard/ConnectionPublicationWizard.test.tsx`
- Modify: `web/src/features/connections/wizard/steps/ScopeProviderStep.tsx`
- Modify: `web/src/features/connections/wizard/steps/EndpointTrustStep.tsx`
- Modify: `web/src/features/connections/wizard/steps/CredentialReferenceStep.tsx`
- Modify: `web/src/features/connections/wizard/steps/CapabilitiesRealmStep.tsx`
- Modify: `web/src/features/connections/wizard/steps/ValidationStep.tsx`
- Modify: `web/src/features/connections/wizard/steps/ReviewPublishStep.tsx`
- Modify: `web/src/features/connections/wizard/OperationPanel.tsx`
- Create: `web/src/features/connections/wizard/providers/HostProbeFields.tsx`
- Create: `web/src/features/connections/wizard/providers/AWXFields.tsx`
- Create: `web/src/features/connections/wizard/providers/PostgreSQLFields.tsx`
- Create: `web/src/features/connections/wizard/ProviderAvailabilityGate.tsx`
- Create: `web/src/features/connections/wizard/ProviderAvailabilityGate.test.tsx`
- Create: `web/src/features/connections/components/AWXInventorySourceCard.tsx`
- Create: `web/src/features/connections/components/AWXInventorySourceCard.test.tsx`
- Modify: `web/src/features/connections/wizard/wizard.module.css`
- Modify: `web/src/features/connections/routes/connectionDetailRoute.tsx`
- Modify: `web/src/app/router.tsx`
- Modify: `web/src/test/msw/fixtures.ts`
- Modify: `web/src/test/msw/handlers.ts`

**Interfaces:**
- Consumes: Task 6 generated `schema.d.ts` and operation IDs；Phase 1 Scope context/OIDC recent-auth helper；existing six-step wizard/Operation polling。
- Produces: canonical routes `/connections/new` and `/connections/$connectionId/revisions/$revision/edit`；three explicit provider forms；independent Runtime gate presentation。

- [ ] **Step 1: 写失败的三分支、canonical route 与安全 UI 测试**

```tsx
it("persists the first server draft then replaces the temporary route with canonical id and revision")
it("renders only Host Probe fields and rejects command path and free port")
it("renders only AWX references and never accepts URL inventory ID template ID or extra vars")
it("renders only PostgreSQL references and never accepts DSN SQL or caller timeout")
it("filters credential references by exact provider role scope and revision")
it("restores step operation and revision from the canonical URL after refresh")
it("shows validation health runtime and provider gate as separate states")
it("does not infer AWX or PostgreSQL availability from a Host Probe green gate")
it("requires effective_actions and real recent-auth return before publish")
it("offers AWX Inventory source binding only after the exact AWX runtime is available")
it("creates an AWX Inventory source with only the canonical integration reference")
```

同时扫描 DOM、MSW fixture、route search、Query cache serialization 和 screenshot name，拒绝 `secret/token/password/pem/dsn/sql/command/extra_vars/raw_error` canary。

- [ ] **Step 2: 运行测试并确认 Red**

Run:

```bash
pnpm --dir web test -- --run web/src/features/connections
```

Expected: FAIL，因为三种 Provider 分支、canonical revision route 与独立 gate 组件尚不存在。

- [ ] **Step 3: 实现服务器草稿持久化与 canonical route 接管**

`/connections/new?environment_id=...&provider=...&step=1` 只保存尚未提交的低敏最小字段在 React Hook Form 内存。用户完成第 1 步即调用既有 `createConnection`；收到 201 后使用 `router.navigate({replace:true})` 跳转：

```text
/connections/{connection_id}/revisions/{revision}/edit
  ?environment_id={environment_id}
  &step=2
```

后续刷新只从 API 重新取得 immutable draft projection；不把 form body 写进 URL/localStorage/sessionStorage。编辑已发布 N 时必须先显式“创建下一修订”，服务端返回 N+1 后进入其 canonical route；412 保留页面上下文、展示安全差异并要求重新审阅。

- [ ] **Step 4: 实现六步三 Provider 明确分支**

固定六步：

1. Scope/Asset/Provider；
2. Endpoint/Trust；
3. Opaque Credential Reference；
4. Capability/Budget/Runner Realm；
5. controlled Validation；
6. diff/review/recent-auth/publish。

Provider 字段只使用 select/combobox/radio：Host 选择 Asset-owned network identity、SNI、listener profile；AWX 选择 canonical installed Integration、governed Controller Asset/network identity、organization reference；PostgreSQL 选择 Database Asset/network identity、SNI、port profile、database reference、replica preference。没有自由 URL、IP、port、header/body、terminal、SQL editor、JSON editor、命令或 template 数字 ID 输入。

Validation step 使用持久 Operation 轨道：`目标身份 → TLS/SNI/CA → Network Policy/Realm → 短凭据 → 固定 Probe → Schema/预算/DLP → 凭据吊销`；只显示稳定 code、时间、digest 和 trace ID，不显示上游 body。Review 独立列出 Connection/Validation/Health/Runtime/Gate 状态和 N→N+1 diff。

AWX 发布并精确 `AVAILABLE` 后，详情页显示紧凑“AWX Inventory 来源”区：若尚未绑定且响应 `effective_actions` 含 `CREATE_SOURCE`，可输入来源名称并选择固定 `INCREMENTAL_WITH_FULL_RECONCILE` 模式；实际请求只发送服务端给出的 opaque `source_profile_id`、名称、唯一 authority Environment 与该固定模式，不发送 SourceKind、ProviderKind 或 Integration ID。创建成功进入既有 `/asset-sources?...&sourceId=...` 页面；卡片展示 cursor digest、最近增量/全量 Run、rate-limit/HA takeover/soft-stale 计数，不显示 raw cursor、endpoint、Credential、host variables 或 AWX error。

- [ ] **Step 5: 完成高保真样式、响应式与 Green/Refactor**

桌面 wizard 最大 920px、字段列 640px、Review 使用全宽 diff；Provider 状态使用紧凑 38–40px 行，不用大卡。1024px 转完整 route；390px 单列、44px touch target、无水平页面滚动。键盘顺序覆盖 stepper/combobox/error summary/Operation live region；状态不只靠颜色，Focus 轮廓至少 2px，动画 120–180ms 且尊重 reduced motion。

Run:

```bash
pnpm --dir web test -- --run web/src/features/connections
pnpm --dir web typecheck
pnpm --dir web build
```

Expected: PASS；canonical route/refresh/N+1/reauth/permission/三 Provider/安全字段/响应式单元契约全绿，生产 bundle 不含 MSW。

- [ ] **Step 6: Commit**

```bash
git add web/src/features/connections web/src/app/router.tsx web/src/test/msw
git commit -m "feat: add diagnostic provider publication wizard"
```

---

### Task 8: 用真实协议验收三 Provider、canonical 发布与独立 AVAILABLE gate

**Files:**
- Create: `test/e2e/docker-compose.diagnostic-providers.yaml`
- Create: `test/e2e/diagnosticproviders/bootstrap.go`
- Create: `test/e2e/diagnosticproviders/bootstrap_test.go`
- Create: `test/e2e/diagnosticproviders/hostprobe/main.go`
- Create: `test/e2e/diagnosticproviders/hostprobe/protocol_test.go`
- Create: `test/e2e/diagnosticproviders/awx/bootstrap.yml`
- Create: `test/e2e/diagnosticproviders/awx/protocol_test.go`
- Create: `test/e2e/diagnosticproviders/awx/discovery_test.go`
- Create: `test/e2e/diagnosticproviders/postgresql/bootstrap.sql`
- Create: `test/e2e/diagnosticproviders/postgresql/protocol_test.go`
- Create: `test/e2e/diagnosticproviders/publication_test.go`
- Create: `test/e2e/diagnosticproviders/security_test.go`
- Modify: `test/e2e/connections/keycloak-realm.json`
- Create: `web/e2e/diagnostic-provider-publication.spec.ts`
- Create: `web/e2e/diagnostic-provider-security.spec.ts`
- Create: `web/e2e/diagnostic-provider-responsive.spec.ts`
- Modify: `web/playwright.config.ts`
- Modify: `.github/workflows/ci.yml`

**Interfaces:**
- Consumes: built Control Plane/Web/Validation Gateway/two Validation Runner replicas；real PostgreSQL、Keycloak Server 26.6.3 与浏览器 `keycloak-js` 26.2.4、mTLS PKI；real Host Probe binary、AWX API、PostgreSQL wire protocol；Runtime distributor/attestor fixture implementing production protocol。
- Produces: per-Provider signed validation/publication/attestation evidence；N/N+1 rollback evidence；browser canonical-route/accessibility evidence；security scan results。

- [ ] **Step 1: 写失败的跨协议和独立门禁 E2E**

```go
func TestHostProbeConnectionDraftValidatePublishAndAttest(t *testing.T)
func TestAWXConnectionDraftValidatePublishAndAttest(t *testing.T)
func TestPostgreSQLConnectionDraftValidatePublishAndAttest(t *testing.T)
func TestProviderGateFailureNeverOpensSiblingProvider(t *testing.T)
func TestProviderNPlusOnePinsInflightNAndRollsBackOnDrift(t *testing.T)
func TestCrossScopeWrongPoolWrongRealmWrongIdentityAndCredentialRoleFailClosed(t *testing.T)
func TestPublicArtifactsContainNoCredentialEndpointCommandOrSQL(t *testing.T)
func TestAWXInventoryIncrementalCursorHAFenceProvenanceAndRateLimit(t *testing.T)
func TestAWXInventoryFullReconcileSoftDeleteAndRestore(t *testing.T)
```

Playwright 必须先断言 `/connections/new`，完成第 1 步后捕获服务端 201 并断言 URL 被 replace 为 canonical ID/revision；刷新、后退、分享同 URL 均恢复同一步和 Operation。

- [ ] **Step 2: 运行测试并确认 Red**

Run:

```bash
go test ./test/e2e/diagnosticproviders -count=1
pnpm --dir web test:e2e -- --grep "diagnostic provider publication"
```

Expected: FAIL，因为真实依赖 compose、bootstrap 与场景尚不存在。

- [ ] **Step 3: 建立真实协议环境与确定性 fixtures**

Compose 启动：PostgreSQL 18.4+、Keycloak Server 26.6.3、Control Plane、VALIDATION Gateway、两个 Validation Runner、Runtime distributor/attestor、TLS 1.3 Host Probe、AWX、诊断目标 PostgreSQL。浏览器构建锁定 `keycloak-js` 26.2.4。所有证书由测试 PKI 动态签发；Host/AWX/PostgreSQL 使用不同 Credential Reference、Realm 和 Network Policy。fixture 禁止复用生产 Secret，完成后销毁 volume。

Host Probe binary 只注册两个固定 GET；AWX fixture 使用真实 API route 和只读账号，准备多页 Inventory、可控 429、host 缺失/恢复，并运行现有 `cmd/discovery-worker` 的两个 Worker 副本，audit 证明无 job launch；PostgreSQL 开启 statement log 到隔离测试 volume，断言只有固定只读 transaction。Runtime attestor 回报完整 typed digest closure，不能直接改数据库 gate。

- [ ] **Step 4: 实现正向、N/N+1 和独立 Gate 场景**

逐 Provider 执行：OIDC 登录 → 创建 server draft → canonical route → validate → cleanup receipt → recent-auth → publish → Runtime apply/attest → exact Provider gate `AVAILABLE`。每条场景都断言另两条 gate 状态不变。

随后给 Host 发布 N+1，让一条运行固定 N；精确 attestation 后新运行使用 N+1、旧运行完成后 N drain。注入 N+1 attestation digest drift，断言 Host 回滚 N 且 `UNAVAILABLE`/阻塞原因持久化，AWX/PostgreSQL gate 不变化。

AWX gate 可用后创建 `AWX_INVENTORY` Source：第一页后杀死持有 lease 的 `cmd/discovery-worker` 副本，第二个 Worker 副本只能以递增 fence 接管且不会重复 Observation；429 保持 cursor 并按 `not_before` 恢复；增量 Run 不把缺失 host 标记 STALE；成功全量 Run 把缺失资产 soft-stale 并保留历史/关系 provenance；host 恢复只追加 restore 事实且保持 STALE，直到同 AWX Runtime/Capability 重新验证后才激活。浏览器 Source 页面只显示 digest/安全计数。

- [ ] **Step 5: 实现完整负向安全矩阵**

至少覆盖：跨 Tenant/Workspace/Environment；非 Asset-owned endpoint identity；错误 Provider/usage role/reference revision；Credential issue/revoke uncertain；错误 VALIDATION Pool/Realm/SPIFFE/SNI/CA；DNS rebind；redirect/proxy；Host command/path；AWX URL/header/body/数字 inventory/template/extra_vars/job launch；AWX Source 错误 Integration、旧 fence、cursor tamper、page replay、非法 provenance、429 busy retry、partial-run stale；PostgreSQL DSN/SQL/timeout/writable session；未知结果列；Validation/Runtime digest drift；stale If-Match；重复/冲突 Idempotency-Key；recent-auth 过期。

每个失败只返回稳定 Problem code/trace ID，Provider gate 保持关闭，审计/日志/trace/metrics/Temporal/HTTP artifact 不出现 canary。

- [ ] **Step 6: 运行真实后端、浏览器、无障碍与安全门**

Run:

```bash
docker compose -f test/e2e/docker-compose.diagnostic-providers.yaml up -d --build
go test ./test/e2e/diagnosticproviders -count=1
pnpm --dir web test:e2e -- --grep "diagnostic provider publication|diagnostic provider security|diagnostic provider responsive"
pnpm --dir web test:e2e -- --grep "axe|keyboard"
go test -race ./internal/connectionprofile/... ./internal/connectionvalidation/... ./internal/validationrunner/... ./internal/capability/... ./internal/runtimepublication/... ./internal/assetdiscovery/... -count=1
git diff --check
docker compose -f test/e2e/docker-compose.diagnostic-providers.yaml down -v
```

Expected: PASS；1440/1024/390、键盘、axe、canonical route、真实 OIDC/mTLS/Host/AWX/PostgreSQL、N/N+1、独立 gate 与 secret scan 全绿；compose 被清理。

- [ ] **Step 7: Refactor、CI gate 与 Commit**

CI job 必须使用真实 compose，失败时上传脱敏 JUnit/trace/screenshot/provider gate summary，但不得上传 DB statement log、Credential、Capsule payload 或完整网络抓包。重复运行同一 seed 结果确定；不允许 `continue-on-error`。

```bash
git add test/e2e/diagnosticproviders test/e2e/docker-compose.diagnostic-providers.yaml test/e2e/connections/keycloak-realm.json web/e2e web/playwright.config.ts .github/workflows/ci.yml
git commit -m "test: verify diagnostic provider publication gates"
```

## Package Acceptance

- [ ] OpenAPI/authz/HTTP 精确区分 manage/validate/publish/read 权限，Scope、recent-auth、ETag、idempotency、redaction 全绿。
- [ ] 首次 server draft 和 N+1 都由服务端分配 canonical ID/Revision，Web 立即 replace 到 canonical route 并可刷新恢复。
- [ ] 六步向导对 Host/AWX/PostgreSQL 使用三个封闭分支，不出现任意 endpoint、Credential material、命令、SQL 或 Provider payload。
- [ ] 真实协议 E2E 逐 Provider 完成 validate/publish/attest；一个 Provider 的 `AVAILABLE` 永不暗示其他 Provider 可用。
- [ ] AWX 发布后 `AWX_INVENTORY` 通过 canonical Integration 绑定，真实 E2E 覆盖增量 cursor、HA fence、provenance、429、全量 soft-delete/restore，且 audit 无 job launch。
- [ ] N/N+1、in-flight pin、drain、rollback、cross-Scope/identity/credential/drift 负向门全部有持久证据后，才允许进入 Host/AWX/PostgreSQL 诊断执行包。
