# Credential References and Runner Realms Governance Inventory Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 交付生产级 `/credential-references` 与 `/runner-realms` 治理库存页，使授权人员能在精确 Workspace/Environment Scope 内查看安全的凭据引用元数据、Runner Realm 身份/健康和内容寻址 Capability binding，并在不接触任何凭据材料、不扩大 Realm 权限的前提下执行服务端明确授权的现有验证动作。

**Architecture:** 既有 package 05 OpenAPI/HTTP 路由与 package 06 generated client 是唯一契约，本包只加固并扩展它们，不创建平行 API、DTO 或身份源。PostgreSQL Reader 生成低敏安全投影；公共 HTTP 使用真实 OIDC/authz、scope/filter-bound HMAC cursor、ETag、Idempotency-Key 和 `effective_actions`；前端使用 TanStack Router URL state、TanStack Query server state、现有 AppShell/Token 与真实 Keycloak session。Realm capability binding 在本阶段只读，不能从浏览器创建、编辑、提升或绕过发布门。

**Tech Stack:** Go 1.26.5、PostgreSQL 18.4+、OpenAPI 3.1、Node 24、pnpm 10.34.0、React 19.2.7、TypeScript 7.0.2、TanStack Router 1.170.17、TanStack Query 5.101.2、TanStack Table 8.21.3、Zod 4.4.3、radix-ui 1.6.2、lucide-react 1.24.0、CSS Variables/CSS Modules、Keycloak Server 26.6.3、keycloak-js 26.2.4、Playwright 1.61.1、@axe-core/playwright 4.12.1。

## Global Constraints

- 每个 Task 严格采用 Red → Green → Refactor：先写并运行预期失败测试，保存失败原因；只做让测试通过的最小生产实现；全绿后才整理命名/重复代码并复跑同一门禁。
- 只复用 package 05 已批准的 `list/get/validateCredentialReference` 与 `list/get/listRunnerRealmCapabilityBindings` operation；handler/OpenAPI 已存在时必须 `Modify`，不得复制新路由、第二版 DTO 或旁路授权服务。
- 所有请求绑定 principal Tenant + URL `workspace` + URL/API `environment`；Scope 切换中止旧请求并清理旧 Scope cache。403/404 不泄露资源是否存在于其他 Scope。
- Cursor 使用 Phase 1 HMAC codec，绑定 endpoint kind、Tenant/Workspace/Environment、canonical filters、sort 和 keyset；篡改、跨 Scope、跨 filter、跨 endpoint 或超长 cursor 一律 `400`，不退回 offset。
- API、DOM、日志、指标、审计、浏览器网络记录、截图和 Playwright artifact 只允许 schema allowlist 中的低敏名称/Owner、opaque ID、闭集枚举、时间、计数与内容摘要。禁止 Secret、password、token、private key、CA PEM、DSN、Vault path、issuer 内部地址、完整 workload identity、任意 endpoint/header/body、原始错误和上游 payload。
- 浏览器不得创建、粘贴、编辑、读取、回显或复制 Secret，不得发起 credential retrieval/rotation/revocation，不得创建/编辑 Realm binding、临时扩权或直接连接 Runner。
- Credential Reference 仅可展示 API `effective_actions` 中存在的既有 `VALIDATE_REFERENCE`；生产验证仍需服务端 authz、recent authentication、最新 ETag 和 caller-generated Idempotency-Key。既有 `revokeConnection` 仍只属于 Connection 详情；本包不新增 Credential revoke。
- Runner Realm 与 Capability binding 在本阶段始终是安全只读库存；`effective_actions` 为空就不渲染 mutation 控件。后续若治理证书轮换或 binding，必须另有已批准的 typed API/policy/approval 契约，不能把列表页变成通用管理代理。
- Production Web 使用 Keycloak Authorization Code + PKCE、`login-required`、请求前刷新和内存 Token；不得使用角色名推断权限、localStorage Token、假 session、MSW fallback 或 bearer query。
- 视觉是高密度、低 AI 感的企业运维控制台：深海军蓝领域导航、白色工作面、1px 边界、紧凑表格和证据优先详情；禁止 chatbot/机器人/对话气泡、渐变、glow、glass、霓虹、超大营销卡、装饰性 bento 和终端拟态。
- 1440、1024、390 px 全部可操作；键盘、focus return、semantic table/card、aria-live、reduced motion 和 WCAG 2.2 A/AA axe gate 必须通过。390 px 不能靠隐藏治理事实或 mutation 条件实现响应式。
- fake/MSW 只允许 `_test.go`、`web/src/test`、`web/e2e`、`test/e2e`；最终 Playwright full-stack project 使用真实 Control Plane/PostgreSQL/Keycloak，禁止业务 API interception。

## Fixed Public Contract

本包不增加路径，固定消费：

```text
GET  /api/v1/workspaces/{workspace_id}/credential-references
GET  /api/v1/workspaces/{workspace_id}/credential-references/{reference_id}
POST /api/v1/workspaces/{workspace_id}/credential-references/{reference_id}:validate
GET  /api/v1/workspaces/{workspace_id}/runner-realms
GET  /api/v1/workspaces/{workspace_id}/runner-realms/{realm_id}
GET  /api/v1/workspaces/{workspace_id}/runner-realms/{realm_id}/capability-bindings
GET  /api/v1/workspaces/{workspace_id}/operations/{operation_id}
```

`environment_id` 是每个 operation 的 required UUID query。成功和 Problem 均为 `Cache-Control: no-store`、`X-Content-Type-Options: nosniff`；列表 limit 为 1–100，默认 50。

### Safe browser projections

`CredentialReferenceSummary/Detail` 只允许：opaque `id`、`display_name`、`environment_id`、`owner_group`、`provider_kind`、`usage_role`、`revision`、`issuer_kind`、opaque `issuer_id`、`issuer_revision`、issuer registration digest、`max_ttl_seconds`、`status`、`health_status`、`rotation_status`、`expires_at`、`last_validated_at`、`last_used_at`、`version`、固定 `redacted: true` 和 API 计算的 `effective_actions`。`issuer_id` 必须是服务端登记的 opaque identifier，不能承载 URI/path。不得返回 issuer endpoint/path、credential material、原始验证错误或 secret store metadata。

`RunnerRealmSummary/Detail` 只允许：opaque `id`、`display_name`、`environment_id`、`mode`、`adapter_family`、`network_zone`、`status`、`scope_revision`、workload identity digest、`certificate_expires_at`、`last_heartbeat_at`、`capability_binding_count`、binding-set digest、runtime attestation digest、`kill_switch_status`、`version` 和 `effective_actions`。Phase 2 尚未生产 Kill Switch 契约时该闭集值只能是中性的 `NOT_CONFIGURED`，绝不能推断为 open/available；后续阶段只能从真实生成 API 扩展。不得返回 SPIFFE URI、证书/私钥、listener、queue、issuer、network endpoint 或 Runner payload。

`RunnerRealmCapabilityBinding` 只允许：opaque binding/capability ID、`provider_kind`、`capability_kind`、`capability_revision`、`mode`、`status`、`target_kind`、definition digest、binding digest、published target count、`attested_at` 与稳定 unavailable reason code。每一项必须来自同 Scope 的 immutable published definition/binding；不能由 Runner 自报，也不能把 Environment 推断为资源级授权。

### Task 15: Harden the existing inventory API, readers, cursor and authorization

**Files:**
- Modify: `internal/credentialreference/reference.go`
- Modify: `internal/credentialreference/reference_test.go`
- Modify: `internal/credentialreference/repository.go`
- Create: `internal/credentialreference/validation.go`
- Create: `internal/credentialreference/validation_test.go`
- Modify: `internal/credentialreference/postgres/repository.go`
- Modify: `internal/credentialreference/postgres/repository_test.go`
- Modify: `internal/connectionvalidation/realm.go`
- Create: `internal/connectionvalidation/realm_test.go`
- Modify: `internal/connectionvalidation/postgres/realm.go`
- Modify: `internal/connectionvalidation/postgres/realm_test.go`
- Modify: `internal/httpapi/control_plane_contract.go`
- Modify: `internal/httpapi/control_plane_contract_test.go`
- Modify: `internal/httpapi/credential_references.go`
- Modify: `internal/httpapi/credential_references_test.go`
- Modify: `internal/httpapi/runner_realms.go`
- Modify: `internal/httpapi/runner_realms_test.go`
- Modify: `internal/authz/authorizer.go`
- Modify: `internal/authz/authorizer_test.go`
- Modify: `api/openapi/control-plane-v1.yaml`
- Modify: `api/openapi/control_plane_v1_test.go`
- Modify: `cmd/control-plane/main.go`
- Modify: `cmd/control-plane/main_test.go`

**Interfaces:**
- Consumes: package 01 `000016` Realm/Credential tables；package 02 PostgreSQL readers；package 05 routes, OIDC/authz and Phase 1 HMAC cursor codec。
- Produces: filtered keyset pages and safe details for Credential References/Runner Realms/bindings；`VALIDATE_REFERENCE` server action；production-wired inventory readers；no new public route。

Exact handler dependencies and cursor extension:

```go
type CredentialReferenceReader interface {
    List(context.Context, credentialreference.ListRequest) (credentialreference.Page, error)
    Get(context.Context, assetcatalog.Scope, string) (credentialreference.Reference, error)
}

type CredentialReferenceValidator interface {
    Validate(
        context.Context,
        authn.Principal,
        credentialreference.ValidateRequest,
    ) (operation.Operation, error)
}

type ValidationRegistry interface {
    ResolveMetadata(
        context.Context,
        credentialreference.RegistryLookup,
    ) (credentialreference.IssuerHealthMetadata, error)
}

type RunnerRealmReader interface {
    List(context.Context, connectionvalidation.RealmListRequest) (connectionvalidation.RealmPage, error)
    Get(context.Context, assetcatalog.Scope, string) (connectionvalidation.RealmDetail, error)
    ListCapabilityBindings(
        context.Context,
        connectionvalidation.BindingListRequest,
    ) (connectionvalidation.BindingPage, error)
}

type controlPlaneCursor struct {
    Kind       string `json:"kind"`
    Sort       string `json:"sort"`
    ScopeHash  string `json:"scope_hash"`
    FilterHash string `json:"filter_hash"`
    Value      string `json:"value"`
    ID         string `json:"id"`
}
```

- [ ] **Step 1 — Red: Write failing reader, projection, cursor and authorization tests**

Required Go cases:

```go
func TestCredentialReferenceInventoryAlwaysScopesFiltersAndKeyset(t *testing.T)
func TestCredentialReferenceResponseContainsSafeOpaqueMetadataOnly(t *testing.T)
func TestCredentialReferenceCursorRejectsScopeFilterSortAndEndpointReplay(t *testing.T)
func TestValidateCredentialReferenceRequiresActionRecentAuthETagAndIdempotency(t *testing.T)
func TestCredentialReferenceValidationNeverIssuesOrReadsCredentialMaterial(t *testing.T)
func TestRunnerRealmInventoryUsesRegisteredIdentityAndAttestedBinding(t *testing.T)
func TestRunnerRealmBindingResponseContainsNoIdentityCertificateOrEndpoint(t *testing.T)
func TestRunnerRealmBindingCursorRejectsCrossRealmReplay(t *testing.T)
func TestPublicRouterHasNoCredentialMaterialOrRealmBindingMutationRoute(t *testing.T)
func TestInventoryEffectiveActionsComeFromCurrentAuthorization(t *testing.T)
func TestProductionAssemblyRejectsMissingInventoryReaderOrCursorKey(t *testing.T)
```

Tests use a forbidden-value canary and assert it never appears in JSON/Problem/headers. pgx expectations include Tenant/Workspace/Environment and deterministic keyset tie-breaker ID.

- [ ] **Step 2 — Red verification: Run the focused tests and save the expected failure**

Run:

```bash
go test ./internal/credentialreference/... ./internal/connectionvalidation/... \
  ./internal/httpapi ./internal/authz ./api/openapi ./cmd/control-plane \
  -run 'CredentialReference|RunnerRealm|Inventory|Cursor|Binding' -count=1
```

Expected: FAIL because inventory filters/pages, safe projections, cursor request binding, `VALIDATE_REFERENCE` admission and production wiring are incomplete.

- [ ] **Step 3 — Green: Implement scoped readers and closed filters**

Credential list accepts only:

```text
environment_id, q, provider_kind, usage_role, status, expiry_state,
sort=display_name_asc|last_used_at_desc|expires_at_asc, cursor, limit
```

Realm list accepts only:

```text
environment_id, mode, adapter_family, network_zone, status,
sort=display_name_asc|last_heartbeat_at_desc|certificate_expires_at_asc,
cursor, limit
```

Binding list accepts only:

```text
environment_id, provider_kind, status,
sort=capability_kind_asc|attested_at_desc, cursor, limit
```

Reject duplicate/unknown/empty query values. Canonicalize enum arrays before computing the filter hash. Repository keysets use `(sort_value, id)` and never offset. The Realm reader joins registered workload identity metadata, certificate expiry and published binding attestation under the same Scope/revision; absence, revision drift, disabled realm, expired certificate or digest mismatch returns explicit safe `UNAVAILABLE`, never guessed `AVAILABLE`.

`RegistryLookup` contains exact Scope, reference ID/revision, Provider and usage role. `IssuerHealthMetadata` contains only issuer kind, opaque registration digest, issuer revision, closed health status and `observed_at`; it has no endpoint, path, credential accessor or issue/read method.

- [ ] **Step 4 — Green: Implement safe DTOs, actions and signed request-bound cursors**

Extend the existing HMAC cursor payload with canonical `scope_hash` and `filter_hash`; encode canonical JSON + HMAC-SHA256 with the dedicated production cursor key, base64url without padding, max 2048 bytes, and constant-time MAC comparison. Never put plaintext Scope, filter values or display names into the cursor.

OpenAPI list pages expose `items/page/effective_actions`; collection actions remain empty because browser creation is forbidden. Credential detail can contain only `VALIDATE_REFERENCE` when current server authorization permits it. `POST ...:validate` requires `CREDENTIAL_REFERENCE_VALIDATE`, production recent auth, exact strong `If-Match`, 16–128-byte Idempotency-Key, immutable reference revision, ACTIVE/healthy issuer metadata and async Operation response. Missing action, stale auth/version or unknown cleanup state fails closed. Realm/binding `effective_actions` are empty in Phase 2 and no POST/PATCH/DELETE route is registered.

Authorization is explicit: SRE and ADMIN may receive `VALIDATE_REFERENCE` inside an authorized Scope; AUDITOR/VIEWER/SERVICE_OWNER/APPROVER never receive it. This action does not grant Connection publish, investigation, credential retrieval, Realm binding or any write capability.

`credentialreference.ValidationService` validates only the immutable reference tuple, exact VALIDATION issuer-registry registration, Provider/usage-role allowlist, TTL bounds and safe issuer health metadata, then records the durable Operation and reference health timestamp. It must never call an issue/read/reveal method or materialize a `SensitiveValue`; real short-credential issue/use/revoke remains exclusively inside Connection validation through the isolated package 04 Runner protocol. This distinction is explicit in API description and UI copy so a metadata validation is never presented as successful target login.

The validation body is exact and typed:

```yaml
ValidateCredentialReferenceRequest:
  type: object
  additionalProperties: false
  required: [reference_revision, reason]
  properties:
    reference_revision: {type: integer, format: int64, minimum: 1}
    reason: {type: string, minLength: 1, maxLength: 512}
```

Update the existing schemas/handlers in place, preserve fixed operation IDs, and make every schema `additionalProperties: false` with bounded closed enums. Production assembly must inject PostgreSQL readers and a dedicated cursor-key source; absent or typed-nil dependency returns startup failure/503, never memory fallback.

Every projected text field must pass the existing safe-label/DLP boundary before serialization: valid UTF-8, bounded length, no control/newline, URI/DSN/PEM/token shape or credential canary. Unsafe legacy content is replaced by a stable unavailable reason and server-side redacted telemetry; it is never partially echoed to the browser.

- [ ] **Step 5 — Green verification: Run contract, PostgreSQL, race and redaction gates**

Run:

```bash
gofmt -w internal/credentialreference internal/connectionvalidation internal/httpapi internal/authz cmd/control-plane
go test ./internal/credentialreference/... ./internal/connectionvalidation/... \
  ./internal/httpapi ./internal/authz ./api/openapi ./cmd/control-plane -count=1
AIOPS_TEST_POSTGRES_DSN="$AIOPS_TEST_POSTGRES_DSN" \
  go test ./internal/credentialreference/postgres ./internal/connectionvalidation/postgres -count=1
go test -race ./internal/credentialreference/... ./internal/connectionvalidation/... ./internal/httpapi -count=1
```

Expected: PASS；every query is Scope-bound；cursor replay/tamper fails；safe DTO keys exactly match OpenAPI；validation is authorized/versioned/idempotent；public router has no credential retrieval or Realm mutation surface.

- [ ] **Step 6 — Refactor: Remove duplicate mapping/filter logic without changing the contract**

Extract only shared canonical filter/cursor helpers into `control_plane_contract.go`; keep credential and Realm DTO mapping type-specific. Re-run Step 5 unchanged. Expected: PASS with identical OpenAPI snapshots and HTTP bodies.

- [ ] **Step 7: Commit**

```bash
git add internal/credentialreference internal/connectionvalidation internal/httpapi internal/authz \
  api/openapi/control-plane-v1.yaml api/openapi/control_plane_v1_test.go cmd/control-plane
git commit -m "feat: expose safe governance inventory APIs"
```

### Task 16: Extend the generated client, URL schema and query state

**Files:**
- Modify: `web/src/shared/api/schema.d.ts` (generated only)
- Modify: `web/src/features/connections/api/connectionApi.ts`
- Modify: `web/src/features/connections/api/connectionApi.test.ts`
- Create: `web/src/features/governance-inventory/model/inventorySearch.ts`
- Create: `web/src/features/governance-inventory/model/inventorySearch.test.ts`
- Create: `web/src/features/governance-inventory/model/inventoryKeys.ts`
- Create: `web/src/features/governance-inventory/model/useCredentialReferenceValidation.ts`
- Create: `web/src/features/governance-inventory/model/useCredentialReferenceValidation.test.tsx`
- Modify: `web/src/test/msw/fixtures.ts`
- Modify: `web/src/test/msw/handlers.ts`

**Interfaces:**
- Consumes: Task 15 OpenAPI operation IDs and safe pages；package 06 `controlPlaneClient`/Operation recovery；global validated Scope state。
- Produces: generated-only types, exact API adapters, canonical URL state, Scope-specific query keys and recoverable credential validation mutation。

Exact browser exports:

```ts
export function parseCredentialReferenceSearch(input: unknown): CredentialReferenceSearch;
export function parseRunnerRealmSearch(input: unknown): RunnerRealmSearch;
export function listCredentialReferences(input: CredentialReferenceListInput): Promise<CredentialReferencePage>;
export function getCredentialReference(input: CredentialReferenceGetInput): Promise<CredentialReferenceDetail>;
export function validateCredentialReference(input: CredentialReferenceValidateInput): Promise<Operation>;
export function listRunnerRealms(input: RunnerRealmListInput): Promise<RunnerRealmPage>;
export function getRunnerRealm(input: RunnerRealmGetInput): Promise<RunnerRealmDetail>;
export function listRunnerRealmCapabilityBindings(input: BindingListInput): Promise<RunnerRealmCapabilityBindingPage>;

export const inventoryKeys: {
  credentialList(scope: ScopeKey, search: CredentialReferenceSearch): readonly unknown[];
  credentialDetail(scope: ScopeKey, referenceId: string): readonly unknown[];
  realmList(scope: ScopeKey, search: RunnerRealmSearch): readonly unknown[];
  realmDetail(scope: ScopeKey, realmId: string): readonly unknown[];
  bindings(scope: ScopeKey, realmId: string, search: RunnerRealmSearch): readonly unknown[];
};
```

- [ ] **Step 1 — Red: Write failing generated-contract, URL and query tests**

Required TypeScript cases:

```ts
it("round-trips credential filters, cursor trail and selected reference in URL")
it("round-trips realm filters, binding tab and nested cursor trail in URL")
it("drops cursor trails when scope, filter or sort changes")
it("uses workspace and environment in every inventory query key")
it("serializes only OpenAPI-declared filters")
it("sends If-Match and Idempotency-Key for reference validation")
it("recovers the validation Operation from URL after reload")
it("never persists response, token, reference metadata or Operation in storage")
```

- [ ] **Step 2 — Red verification: Run generation drift and focused tests**

Run:

```bash
corepack pnpm@10.34.0 --dir web generate:api
corepack pnpm@10.34.0 --dir web test -- \
  src/features/connections/api/connectionApi.test.ts \
  src/features/governance-inventory/model
```

Expected: FAIL because the expanded generated schemas, inventory URL model, keys and validation hook are absent.

- [ ] **Step 3 — Green: Implement canonical URL schemas and typed adapters**

Credential URL search is closed to:

```text
workspace, environment, q, provider, usageRole, status, expiry,
sort, cursor, trail[], referenceId, operationId
```

Realm URL search is closed to:

```text
workspace, environment, mode, adapterFamily, networkZone, status,
sort, cursor, trail[], realmId, tab=overview|bindings,
bindingProvider, bindingStatus, bindingSort, bindingCursor, bindingTrail[]
```

Use Zod bounded strings/enums/UUIDs, cursor max 2048, trail max 20. Sort/deduplicate arrays. Filter/sort/Scope changes clear current and nested cursor trails; selecting/closing details preserves list state. Query keys include Workspace/Environment and canonical filters; aborted Scope requests cannot populate the new Scope cache.

Modify the package 06 API module instead of creating a second HTTP client. All types come from `schema.d.ts`; no handwritten DTO. `validateCredentialReference` accepts the ETag, a stable per-attempt Idempotency-Key and exact reference revision, then delegates to the existing Operation hook. It never logs request headers/body.

- [ ] **Step 4 — Green verification: Run generated type, state and storage gates**

Run:

```bash
corepack pnpm@10.34.0 --dir web generate:api:check
corepack pnpm@10.34.0 --dir web typecheck
corepack pnpm@10.34.0 --dir web lint
corepack pnpm@10.34.0 --dir web test -- \
  src/features/connections/api/connectionApi.test.ts \
  src/features/governance-inventory/model
```

Expected: PASS；generated file clean；URL reload/back/forward deterministic；all calls are exact Scope；storage spies observe no persistence；unknown MSW request fails.

- [ ] **Step 5 — Refactor: Canonicalize shared pagination without merging resource semantics**

Deduplicate URL cursor-trail mechanics while keeping credential/Realm filter schemas, page keys and invalidation separate. Re-run Step 4 unchanged. Expected: PASS with the same serialized URLs and requests.

- [ ] **Step 6: Commit**

```bash
git add web/src/shared/api/schema.d.ts web/src/features/connections/api \
  web/src/features/governance-inventory/model web/src/test/msw
git commit -m "feat(web): add governance inventory data state"
```

### Task 17: Persist the UI design contract and build both high-fidelity pages

**Files:**
- Create: `docs/design/frontend/credential-references-runner-realms.md`
- Create: `web/scripts/check-governance-inventory-design-contract.mjs`
- Create: `web/src/features/governance-inventory/routes/credentialReferencesRoute.tsx`
- Create: `web/src/features/governance-inventory/routes/runnerRealmsRoute.tsx`
- Create: `web/src/features/governance-inventory/model/inventoryPresentation.ts`
- Create: `web/src/features/governance-inventory/components/GovernanceInventoryLayout.tsx`
- Create: `web/src/features/governance-inventory/components/CredentialReferencesPage.tsx`
- Create: `web/src/features/governance-inventory/components/CredentialReferencesTable.tsx`
- Create: `web/src/features/governance-inventory/components/CredentialReferenceDetail.tsx`
- Create: `web/src/features/governance-inventory/components/RunnerRealmsPage.tsx`
- Create: `web/src/features/governance-inventory/components/RunnerRealmsTable.tsx`
- Create: `web/src/features/governance-inventory/components/RunnerRealmDetail.tsx`
- Create: `web/src/features/governance-inventory/components/CapabilityBindingsTable.tsx`
- Create: `web/src/features/governance-inventory/components/governanceInventory.module.css`
- Create: `web/src/features/governance-inventory/components/CredentialReferencesPage.test.tsx`
- Create: `web/src/features/governance-inventory/components/RunnerRealmsPage.test.tsx`
- Modify: `web/src/app/router.tsx`
- Modify: `web/src/app/navigation.ts`

**Interfaces:**
- Consumes: Task 16 URL/data layer；Phase 1 AppShell/tokens/OIDC；server `effective_actions`；safe digest-copy/live-region primitives。
- Produces: canonical top-level routes `/credential-references` and `/runner-realms`；desktop drawer and narrow full-surface details driven by selected IDs in URL；唯一持久设计契约 `docs/design/frontend/credential-references-runner-realms.md`。

Exact presentation constants consumed by routes, components, tests and the design checker:

```ts
export const governanceInventoryRoutes = {
  credentialReferences: "/credential-references",
  runnerRealms: "/runner-realms",
} as const;

export const governanceInventoryBreakpoints = {
  drawer: 1280,
  fullDetail: 1024,
  stackedRows: 600,
  mobileEvidence: 390,
} as const;

export const credentialReferenceColumnIds = [
  "identity", "issuer", "providerRole", "owner", "health",
  "rotationExpiry", "lastValidated", "lastUsed",
] as const;

export const runnerRealmColumnIds = [
  "identity", "mode", "adapterFamily", "networkZone", "realmStatus",
  "scopeRevision", "identityDigest", "certificateExpiry", "heartbeat", "bindings", "killSwitch",
] as const;
```

- [ ] **Step 1 — Red: Write the design checker and failing interaction/a11y tests**

The checker must require exact sections for IA, URL schema, responsive dimensions, component anatomy, state matrix, interaction/focus, tokens, OIDC/effective actions, safe-field allowlist, forbidden patterns and E2E acceptance. It compares the documented routes, column IDs, breakpoint values, stable state labels and semantic CSS variables with source constants.

Required component cases:

```tsx
it("opens credential detail from keyboard and restores the exact row focus")
it("renders only safe reference metadata and no secret-value controls")
it("shows validate only when API effective_actions contains VALIDATE_REFERENCE")
it("requires recent auth, ETag and a bounded change reason before validation")
it("opens realm detail and restores filters, selection and binding tab from URL")
it("keeps identity, certificate, heartbeat, realm and binding states separate")
it("renders exact attested binding digests without any binding mutation control")
it("renders a neutral NOT_CONFIGURED kill switch and never infers admission")
it("uses full detail surfaces below 1024 and stacked labelled rows at 390")
it("distinguishes empty, filtered-empty, 403/404, 412 and 503")
```

- [ ] **Step 2 — Red verification: Run the design and component tests**

Run:

```bash
node web/scripts/check-governance-inventory-design-contract.mjs
corepack pnpm@10.34.0 --dir web test -- src/features/governance-inventory/components
```

Expected: FAIL because the persistent design contract, routes and components do not exist.

- [ ] **Step 3 — Green: Write the durable high-fidelity design specification**

`docs/design/frontend/credential-references-runner-realms.md` is the only detailed design source for these pages. It must persist:

- navigation under `资产与连接`、two canonical routes and complete validated URL schemas;
- 1440 content geometry with 38–40px dense table and 460px detail drawer, 1024 full detail surface, 390 stacked labelled cards/filter sheet and ≥44px touch targets;
- exact columns, detail section order, safe field allowlists, list/detail/loading/empty/filtered-empty/denied/not-found/unavailable/conflict/expired states and stable Chinese copy;
- existing Phase 1 token names, 14/20 body, 12/18 metadata, 22–24 page title, tabular/monospace digests, 4/6px radii, 1px borders, 2px focus and reduced motion; no raw hex in feature CSS;
- pointer/keyboard/touch flows, roving row focus, Enter/select, Escape/close, focus return, filter sheet, tab semantics, live validation status, error summary and WCAG 2.2 A/AA;
- real Keycloak login-required + PKCE, memory Token, same-origin return URL, recent-auth behavior and API-only `effective_actions`;
- prohibited AI/chat/gradient/glow/glass/oversized card patterns, secret reveal/copy/paste/edit, arbitrary endpoint/header/body/command/script/SQL, browser role inference, Realm binding/elevation controls and raw error surfaces.

Any later visual or interaction change must update this document and its checker in the same slice; the implementation plan is not a substitute for the durable design source.

The design document copies—not renames—the locked foundation values and records the shell geometry: 220px expanded/64px collapsed nav, 46px context bar, 24px desktop/16px compact content padding, 40px filter bar minimum, 38–40px data rows and 460px drawer.

```css
--color-bg: #f4f6f8;
--color-surface: #ffffff;
--color-surface-subtle: #eef2f6;
--color-nav: #17212b;
--color-text: #17202a;
--color-muted: #52606d;
--color-border: #d7dde3;
--color-primary: #1f5ea8;
--radius-sm: 4px;
--radius-md: 6px;
```

Success/warning/danger continue using the existing Phase 1 semantic tokens with ≤12% background tint; status always includes Lucide icon + text + optional absolute timestamp and never relies on color alone.

- [ ] **Step 4 — Green: Implement Credential References as a safe governance inventory**

Desktop header is breadcrumb → `凭据引用` title/count → concise boundary text; there is no create button. Direct filters are keyword, Provider, usage role, status and expiry/rotation; active chips are individually removable. Columns in order:

1. display name / opaque ID;
2. issuer kind;
3. Provider / usage role;
4. owner group;
5. health status;
6. rotation / expiry;
7. last validated;
8. last used.

The detail surface orders identity/Scope, allowed Provider/role, issuer kind/opaque ID/registration digest/revision, TTL/expiry/rotation, health/timestamps, version/ETag and server actions. Full digest or opaque ID may be copied with an explicit “安全摘要/资源 ID” label and polite live announcement; no control ever copies or reveals secret material. `VALIDATE_REFERENCE` opens a named confirmation with Reference, Environment, revision, consequence and 1–512-byte reason, then uses real recent-auth and Operation recovery. 412 refetches and requires explicit review；403/404 is non-enumerating；503 offers retry only, never local validation.

- [ ] **Step 5 — Green: Implement Runner Realms and attested binding details**

Realm header has no “连接/登录/添加绑定” primary action. Direct filters are Mode, Adapter Family, Network Zone and Realm status. Columns in order:

1. display name / opaque Realm ID;
2. Mode;
3. Adapter Family;
4. Network Zone;
5. Realm status;
6. Scope Revision;
7. workload identity digest;
8. certificate expiry;
9. last heartbeat;
10. binding count / attestation gate.
11. Kill Switch (`NOT_CONFIGURED` only in Phase 2, neutral and non-actionable).

The global context bar and detail identity keep Workspace/Environment visible at all widths. Detail `overview` keeps Realm status, certificate status, heartbeat freshness, runtime attestation and Kill Switch as separate facts. `NOT_CONFIGURED` is not presented as disabled protection or admission approval. `bindings` lists Provider, capability kind/revision, mode, target kind, status, definition digest, binding digest, published-target count, attested time and safe reason code. A binding is not “available” unless exact published revision/digests match. No edit, attach, clone, elevate, endpoint, shell, terminal, port-forward or arbitrary execution control exists. Empty actions remain visibly read-only instead of being inferred from ADMIN role.

At ≥1280 the selected item opens a 460px labelled modal drawer; from 1024–1279 use a full-width detail route surface within the same canonical URL search; below 600 use stacked definition-list cards. No body horizontal scroll. Route heading receives focus only after navigation; drawer traps focus, Escape closes, and focus returns to the originating row.

- [ ] **Step 6 — Green verification: Run design, type, component and production-build gates**

Run:

```bash
node web/scripts/check-governance-inventory-design-contract.mjs
corepack pnpm@10.34.0 --dir web typecheck
corepack pnpm@10.34.0 --dir web lint
corepack pnpm@10.34.0 --dir web test -- src/features/governance-inventory
corepack pnpm@10.34.0 --dir web build
```

Expected: PASS；design/source constants match；keyboard/focus/URL/state tests pass；DOM contains only safe allowlisted metadata；production chunk has no MSW, fake OIDC, storage Token, role inference or unsafe control.

- [ ] **Step 7 — Refactor: Consolidate presentation primitives without hiding domain states**

Share only layout, status-with-icon, digest and responsive table/card primitives. Do not merge Credential health/rotation or Realm identity/certificate/heartbeat/binding states into a generic badge. Re-run Step 6 unchanged. Expected: PASS with unchanged accessible names, URLs and state matrix.

- [ ] **Step 8: Commit**

```bash
git add docs/design/frontend/credential-references-runner-realms.md \
  web/scripts/check-governance-inventory-design-contract.mjs \
  web/src/features/governance-inventory web/src/app/router.tsx web/src/app/navigation.ts
git commit -m "feat(web): add governed credential and realm inventories"
```

### Task 18: Prove real Keycloak/API behavior, responsive access and artifact safety

**Files:**
- Create: `test/e2e/docker-compose.connections.yaml`
- Create: `test/e2e/connections/keycloak-realm.json`
- Create: `test/e2e/connections/bootstrap.go`
- Create: `test/e2e/connections/bootstrap_test.go`
- Modify: `web/playwright.config.ts`
- Modify: `web/e2e/support/fixtures.ts`
- Modify: `web/e2e/support/oidc.ts`
- Modify: `web/e2e/support/accessibility.ts`
- Create: `web/e2e/credential-references.spec.ts`
- Create: `web/e2e/runner-realms.spec.ts`
- Create: `web/e2e/governance-inventory-security.spec.ts`
- Create: `web/e2e/governance-inventory-responsive.spec.ts`
- Create: `web/scripts/check-governance-inventory-artifacts.mjs`

**Interfaces:**
- Consumes: built production Web/Control Plane；PostgreSQL `000001..000016`；Task 15 safe APIs；Keycloak Server 26.6.3 realm and browser keycloak-js 26.2.4 flow。
- Produces: reusable base `docker-compose.connections.yaml` and bootstrap for package 08 extension；no-MSW full-stack Playwright evidence for both inventory pages at 1440/1024/390。

Exact reusable bootstrap boundary:

```go
type GovernanceInventoryOptions struct {
    WorkspaceID   string
    EnvironmentID string
    DecoyScope    assetcatalog.Scope
    Now           time.Time
}

func BootstrapGovernanceInventory(
    context.Context,
    *pgxpool.Pool,
    GovernanceInventoryOptions,
) (cleanup func(context.Context) error, err error)
```

- [ ] **Step 1 — Red: Write failing bootstrap, real-OIDC, accessibility and leakage tests**

Bootstrap tests require PostgreSQL migrations, same-Scope credential/Realm/binding fixtures, cross-Scope decoys, a disabled/expired/drifted set and a generated forbidden-value canary that exists only behind the production credential boundary. The realm import defines a public PKCE client only; E2E users/passwords come from ephemeral environment/bootstrap and are never committed.

Browser specs are tagged `@governance-inventory`; every axe case is additionally tagged `@a11y`. They must reject `storageState`, bearer injection, business API route interception and any MSW service worker.

- [ ] **Step 2 — Red verification: Run focused tests before the stack exists**

Run:

```bash
go test ./test/e2e/connections -run GovernanceInventory -count=1
corepack pnpm@10.34.0 --dir web test:e2e -- --project=chromium --grep @governance-inventory
```

Expected: FAIL because the real stack bootstrap and browser specs are absent.

- [ ] **Step 3 — Green: Assemble the reusable real inventory stack**

The initial compose owns PostgreSQL 18.4, Keycloak Server 26.6.3, two Control Plane replicas and the production Web build with same-origin API routing. It runs real migrations and production constructors with OIDC verifier, PostgreSQL readers and cursor-key reference. No memory repository, loopback transport, fake verifier or dev MSW flag is allowed. Package 08 later **modifies** this same compose/bootstrap to add mTLS Validation Gateway/Runners, Prometheus, VictoriaLogs and Runtime distributor; it must not create a second stack.

`bootstrap.go` seeds only opaque/safe metadata through production domain/repository paths, generates test credentials/certificates under a temporary `0700` directory and removes it at teardown. Cross-Scope decoys prove non-enumeration. Never print secret/canary values.

- [ ] **Step 4 — Green: Implement full-stack browser scenarios**

Each browser context authenticates through the real Keycloak login UI and is destroyed after the test; no `storageState`, URL Token, app cookie fabrication or fake Keycloak object.

Required scenarios:

1. SRE filters and paginates Credential References, refreshes/deep-links and returns to the same selected item;
2. API `VALIDATE_REFERENCE` triggers recent-auth, exact ETag/Idempotency request and recoverable Operation; stale ETag shows safe 412 review;
3. AUDITOR reads safe reference details but has no validation action; role name never controls the button locally;
4. Realm filters, selection and binding pagination survive reload/back/forward;
5. disabled/expired/drifted Realm/binding stays unavailable with separate reason facts;
6. cross-Scope reference/Realm/binding deep links return the same non-enumerating projection;
7. DOM, console, API response observation, trace, screenshot and report contain no forbidden field/value;
8. no page exposes create/edit/reveal/copy-secret/revoke-credential/bind/elevate/connect/shell/terminal controls.

Network observation may read completed same-origin responses for assertions but may not fulfill, abort or rewrite business requests.

- [ ] **Step 5 — Green: Verify responsive, keyboard and WCAG behavior**

At `1440×1000`, `1024×768` and `390×844`, cover both list/detail flows and Credential validation confirmation. Assert no body horizontal scroll, ≥44px touch targets at 390, table-to-labelled-card semantics, filter sheet focus containment and full detail surface below 1024.

Keyboard scenario covers skip link, domain navigation, filters, roving table focus, Enter open, tab change, digest copy, Escape close/focus return, confirmation/error summary and Operation live region. Run axe with WCAG 2.2 A/AA tags; serious/critical violations fail. `prefers-reduced-motion` tests must observe no transform/slide dependency.

- [ ] **Step 6 — Green verification: Run the real no-MSW E2E and artifact gates**

Run:

```bash
docker compose -f test/e2e/docker-compose.connections.yaml up -d --build
go test ./test/e2e/connections -run GovernanceInventory -count=1
corepack pnpm@10.34.0 --dir web test:e2e -- \
  --project=chromium --grep @governance-inventory
corepack pnpm@10.34.0 --dir web test:e2e -- \
  --project=chromium --grep '@governance-inventory.*@a11y|@a11y.*@governance-inventory'
node web/scripts/check-governance-inventory-artifacts.mjs
docker compose -f test/e2e/docker-compose.connections.yaml down -v
```

Expected: PASS；real Keycloak authorization-code + PKCE and real API/PostgreSQL are observed；no business interception/MSW；all viewports/keyboard/axe pass；artifact checker finds no forbidden key, raw error or generated canary.

- [ ] **Step 7 — Refactor: Reuse the Phase 1 E2E helpers and keep the full-stack boundary explicit**

Deduplicate only OIDC login, viewport and axe helpers. Preserve fresh contexts and the full-stack prohibition on request interception. Re-run Step 6 unchanged. Expected: PASS with identical real network assertions.

- [ ] **Step 8: Commit**

```bash
git add test/e2e/docker-compose.connections.yaml test/e2e/connections \
  web/playwright.config.ts web/e2e web/scripts/check-governance-inventory-artifacts.mjs
git commit -m "test: verify governance inventories against real services"
```

## Execution Handoff

Execute only after packages 01–06 have real PASS evidence. Package 08 consumes and extends this package's compose/bootstrap/specs, re-runs both design-contract checkers and both inventory suites inside the complete Connection/mTLS/Runtime stack, then owns the only Phase 2 completion decision. This package does not claim Phase 2 or production closed-loop acceptance by itself.
