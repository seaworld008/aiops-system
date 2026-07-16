# Connections Web Publication Flow Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 交付生产级 Connections 列表、详情、修订和六步验证/发布体验，让授权用户在不接触凭据材料的前提下完成可恢复的 Runtime 发布。

**Architecture:** OpenAPI 生成类型是唯一前端契约；Connection adapter 只通过 Phase 1 `web/src/shared/api` 的 method/path/operation 类型化 transport 访问同源 API，并复用 `web/src/shared/operations` 的 Operation 投影与轮询 Hook。TanStack Router 保存 Scope/filter/selection/wizard/Operation URL 状态，TanStack Query 保存 server state；React Hook Form + Zod 驱动 Provider 判别表单；MSW 只服务测试和本地 UI 测试，不是生产 fallback。

**Tech Stack:** Node 24、pnpm 10.34.0、React 19.2.7、Vite 8.1.4、TypeScript 5.9.3、TanStack Router 1.170.17、Query 5.101.2、Table 8.21.3、React Hook Form 7.81.0、Zod 4.4.3、radix-ui 1.6.2、lucide-react 1.24.0、CSS Variables/CSS Modules、openapi-typescript 7.13.0、Vitest 4.1.10、Testing Library React 16.3.2、MSW 2.15.0。

## Global Constraints

- 每个 Task 严格采用 Red → Green → Refactor：先运行并保存预期失败，再做最小生产实现，复跑指定测试后才允许重构和提交。
- Production build 只调用真实同源 Control Plane API 并使用真实 OIDC session；MSW 只能由 Vitest、Playwright mock project 或显式开发模式加载。
- Feature 代码不得直接 `fetch`、另建 HTTP client 或复制 Operation polling；只能消费 Phase 1 类型化 `shared/api` transport 与共享 Operation Hook，本阶段只增加 Connection terminal-state mapping 和 query invalidation。
- 前端不得请求、输入、缓存、展示或记录 secret、token、password、private key、CA PEM、DSN、Vault path；只选择 `CredentialReference` 安全投影。
- UI 不合并 Connection status、validation status、health status 和 Runtime rollout status；四者分别显示。
- 所有 mutation 使用 caller-generated 16–128-byte Idempotency-Key；revision/validate/publish/revoke 发送精确 `If-Match`。
- URL/query state 保存 Scope、filter、sort、selected row、wizard step、revision 和 Operation ID；不得用 Redux 或 localStorage 保存 API response。
- 发布生产 Revision 必须 recent-auth；前端只展示服务端 `effective_actions`，不能自行推断权限。
- 1440、1024、390 px 都必须可用；390 px 仍能完成高风险发布，不通过隐藏关键确认来“响应式”。
- 可访问性基线：键盘完整、可见 focus、语义 heading/landmark、错误摘要、aria-live Operation、色彩不作为唯一信号。
- CSS 固定使用 variables + CSS Modules；不引入第二套 design system。

## Persistent UI and Interaction Contract

Visual direction is “quiet operations console”: information-dense, calm, evidence-first. It must not look like a marketing dashboard or use oversized gradient cards. Digests, revisions, state transitions and remediation are first-class.

### Tokens

Phase 1 `web/src/app/styles/tokens.css` 是唯一设计 Token 源，本阶段只能复用或补充语义变量，不能改名或另建一套 palette。基础值保持 `--color-bg:#f4f6f8`、`--color-surface:#fff`、`--color-nav:#17212b`、`--color-text:#17202a`、`--color-muted:#52606d`、`--color-border:#d7dde3`、`--color-primary:#1f5ea8`、成功/警告/危险语义色、4px 间距基线、`--radius-sm:4px`、`--radius-md:6px` 和 2px 可见 focus。若 Connection 页面需要 subdued surface，只新增 `--color-surface-subtle:#eef2f6`；不得在组件中散落 raw hex。

Use the Phase 1 system font stack and monospace treatment for digests/revisions. Body is 14/20 px, secondary 12/18, page title 22–24 px, section title 16/24 semibold. Desktop controls are 32 px high；touch targets become at least 44×44 px on touch breakpoints. Respect `prefers-reduced-motion` by removing transform/slide and keeping state changes immediate.

Every status uses a Lucide icon, text label and optional timestamp. Success/warning/danger background tints remain under 12% opacity; never use solid saturated cards. Digest displays first 12 and last 8 characters, but copy action copies the full value and announces success in a polite live region.

### Shell and responsive dimensions

- desktop navigation 220 px, collapsed 64 px, top context bar 46 px;
- page content padding 24 px at >=1024 and 16 px below;
- filter toolbar minimum 40 px；dense data row 38–40 px；table header sticky under the 46 px context bar;
- detail panel 480 px at >=1280 and 440 px at 1024–1279;
- wizard max width 920 px; form content column 640 px; review diff may use full width;
- under 1024, detail and wizard are full routes, not drawers;
- under 600, filters become a labelled sheet, stepper becomes “第 N/6 步” plus current title, primary action bar sticks to bottom with safe-area inset;
- no viewport may create body-level horizontal scroll; tables at 390 use stacked row cards with the same semantic labels.

### Interaction rules

- page load places no surprise focus; route heading receives programmatic focus after navigation;
- row click and Enter open detail; Space only selects when a selection checkbox is present;
- detail drawer traps focus, Escape closes, and focus returns to the exact row;
- hover never contains unique information; every tooltip is reachable by keyboard and has matching accessible description;
- mutation confirmation names Connection, Revision, Environment and consequence; generic “确定吗？” is forbidden;
- validation failure leads with stable code + plain remediation, then check timeline; no raw error accordion;
- production publish confirmation requires typed Connection display name only after recent-auth succeeds, and keeps Publish disabled until change reason is 1–512 bytes;
- a sticky Operation panel is non-modal, so users may inspect detail while work continues; leaving the route preserves Operation ID in URL;
- toast is only a secondary acknowledgement; persistent page state carries success/failure and next action;
- skeleton appears after 150 ms to avoid flash; retryable 503 uses explicit retry, while 403 has no retry loop.

Frontend scripts remain the Phase 1 definitions；the drift check generates into a temporary file and is independent of Git staging state:

```json
{
  "scripts": {
    "dev": "vite",
    "build": "tsc -b && vite build",
    "typecheck": "tsc -b --pretty false",
    "generate:api": "openapi-typescript ../api/openapi/control-plane-v1.yaml -o src/shared/api/schema.d.ts",
    "generate:api:check": "sh ./scripts/check-generated-api.sh",
    "lint": "eslint . --max-warnings 0",
    "test": "vitest run",
    "test:watch": "vitest",
    "test:e2e": "playwright test",
    "test:a11y": "playwright test --grep @a11y",
    "check": "pnpm generate:api:check && pnpm typecheck && pnpm lint && pnpm test && pnpm build"
  }
}
```

### Task 12: Generate the browser contract and build the data/Operation layer

**Files:**
- Modify: `api/openapi/control-plane-v1.yaml`
- Modify (generated): `web/src/shared/api/schema.d.ts`
- Create: `web/src/features/connections/api/connectionApi.ts`
- Create: `web/src/features/connections/api/connectionApi.test.ts`
- Create: `web/src/features/connections/model/connectionKeys.ts`
- Modify: `web/src/shared/api/operation.ts`
- Modify: `web/src/shared/operations/useOperation.ts`
- Modify: `web/src/shared/operations/useOperation.test.tsx`
- Modify: `web/src/test/msw/fixtures.ts`
- Modify: `web/src/test/msw/handlers.ts`
- Modify: `web/src/test/msw/server.ts`

**Interfaces:**
- Consumes: package 05 OpenAPI operation IDs；Phase 1 `shared/api` 中由 generated `paths`/`operations` 约束 method、path、parameters、body 与 response 的 `controlPlaneClient`；Phase 1 共享 Operation projection/Hook；current Workspace/Environment route context。
- Produces: typed queries/mutations for Connections、Credential References、Capabilities、Runner Realms and Runtime Publications；stable scoped query keys；Connection-specific terminal-state mapping and invalidation。不得产生第二个 Operation DTO、transport 或 polling implementation。

OpenAPI `operationId` names are fixed:

```text
listConnections
createConnection
getConnection
createConnectionRevision
validateConnectionRevision
publishConnectionRevision
revokeConnection
listConnectionHealthHistory
listCredentialReferences
getCredentialReference
validateCredentialReference
listCapabilities
listPublishedTargets
listRuntimePublications
listRunnerRealms
getRunnerRealm
listRunnerRealmCapabilityBindings
getOperation
```

- [ ] **Step 1: Write failing data and polling tests**

```ts
describe("connectionApi", () => {
  it("serializes scoped list filters", async () => {
    const page = await listConnections({
      workspaceId: testWorkspaceId,
      environmentId: testEnvironmentId,
      providerKind: "PROMETHEUS",
      status: "ACTIVE",
      healthStatus: "HEALTHY",
      limit: 50,
    });
    expect(page.items).toHaveLength(2);
    expect(JSON.stringify(page).toLowerCase()).not.toMatch(
      /token|password|private_key|vault_path|ca_pem|raw_error/,
    );
  });

  it("sends version and idempotency headers", async () => {
    const operation = await validateConnectionRevision({
      workspaceId: testWorkspaceId,
      environmentId: testEnvironmentId,
      connectionId: testConnectionId,
      revision: 3,
      version: 7,
      idempotencyKey: "validate-00000000-0000-4000-8000-000000000901",
    });
    expect(operation.status).toBe("QUEUED");
  });
});
```

扩展 Phase 1 `useOperation.test.tsx`，证明 QUEUED→RUNNING→SUCCEEDED polling、terminal stop、visibility/focus-aware pause、`Retry-After`/bounded backoff、URL reload recovery，以及 Connection detail/runtime invalidation；不得让 mutation 或 terminal failure 自动重放。

- [ ] **Step 2: Verify failure**

Run:

```bash
corepack pnpm@10.34.0 --dir web test -- src/features/connections/api/connectionApi.test.ts src/shared/operations/useOperation.test.tsx
```

Expected: FAIL because generated operations and data layer do not exist.

- [ ] **Step 3: Generate types and implement query keys**

```ts
export const connectionKeys = {
  all: (scope: ScopeKey) =>
    ["connections", scope.workspaceId, scope.environmentId] as const,
  list: (scope: ScopeKey, filters: ConnectionListFilters) =>
    [...connectionKeys.all(scope), "list", filters] as const,
  detail: (scope: ScopeKey, connectionId: string) =>
    [...connectionKeys.all(scope), "detail", connectionId] as const,
  revision: (scope: ScopeKey, connectionId: string, revision: number) =>
    [...connectionKeys.detail(scope, connectionId), "revision", revision] as const,
};
```

Operation queries use the Phase 1 shared `operationKeys`；Connection keys must not create an `operations` namespace. All response/body types are extracted from generated `paths`/`operations`；feature adapter 不能以无类型的 path-only generic request、手写 DTO 或类型断言绕过 method/path/response 约束。Functions implement list/get/create/revision/validate/publish/revoke and all supporting reference/runtime reads. Request bodies and Authorization are never logged. Mutations take Idempotency-Key explicitly and are never optimistically applied or automatically retried.

- [ ] **Step 4: Implement Operation recovery and deterministic MSW**

The Phase 1 shared `useOperation` owns polling for `QUEUED|RUNNING`, stops at `SUCCEEDED|FAILED|CANCELLED|EXPIRED`, respects document visibility/focus and server `Retry-After`, and caps transport backoff without replaying a mutation. This task only registers Connection terminal-state mapping and invalidation. Operation ID lives in route search and is removed after terminal state plus query invalidation.

Fixtures use documented UUIDs and fixed `2026-07-13T00:00:00Z`. Credential fixtures always set `redacted: true` and contain no forbidden key. Handlers assert Scope, `If-Match`, Idempotency-Key, cursor and limit; unknown requests fail with `onUnhandledRequest: "error"`. A 412 handler returns current ETag and safe `VERSION_CONFLICT` only.

- [ ] **Step 5: Run contract and unit gates**

Run:

```bash
corepack pnpm@10.34.0 --dir web generate:api
corepack pnpm@10.34.0 --dir web generate:api:check
corepack pnpm@10.34.0 --dir web typecheck
corepack pnpm@10.34.0 --dir web lint
corepack pnpm@10.34.0 --dir web test -- src/features/connections/api/connectionApi.test.ts src/shared/operations/useOperation.test.tsx
```

Expected: all PASS；generated diff clean；MSW has no unhandled request；terminal Operation stops polling.

- [ ] **Step 6: Commit**

```bash
git add api/openapi/control-plane-v1.yaml web/src/shared/api/schema.d.ts web/src/shared/api/operation.ts web/src/shared/operations web/src/features/connections/api web/src/features/connections/model web/src/test/msw
git commit -m "feat: add typed connection publication client"
```

### Task 13: Build the Connections list, detail, revision and reference views

**Files:**
- Create: `web/src/features/connections/routes/connectionsRoute.tsx`
- Create: `web/src/features/connections/routes/connectionDetailRoute.tsx`
- Create: `web/src/features/connections/components/ConnectionsPage.tsx`
- Create: `web/src/features/connections/components/ConnectionsTable.tsx`
- Create: `web/src/features/connections/components/ConnectionDetailPanel.tsx`
- Create: `web/src/features/connections/components/RevisionTimeline.tsx`
- Create: `web/src/features/connections/components/ConnectionHealthHistory.tsx`
- Create: `web/src/features/connections/components/CredentialReferenceCard.tsx`
- Create: `web/src/features/connections/components/RuntimePublicationCard.tsx`
- Create: `web/src/features/connections/components/connections.module.css`
- Create: `web/src/features/connections/components/ConnectionsPage.test.tsx`
- Create: `web/src/features/connections/components/ConnectionDetailPanel.test.tsx`
- Modify: `web/src/app/router.tsx`
- Modify: `web/src/app/navigation.ts`

**Interfaces:**
- Consumes: 本文件 Task 12 hooks/data；AppShell tokens/navigation；server `effective_actions`。
- Produces: canonical routes `/connections` and `/connections/$connectionId`；Workspace/Environment、filter、sort、cursor、selection 和 tab 位于 validated URL search，沿用已批准的稳定路由基线。

- [ ] **Step 1: Write failing interaction and accessibility component tests**

Required cases:

```tsx
it("round-trips filters, sort and selection through URL search")
it("keeps connection, validation, health and runtime statuses separate")
it("opens a labelled detail panel and restores focus when closed")
it("uses a full detail page below 1024px")
it("renders only opaque credential reference metadata")
it("shows disabled actions with the server supplied reason")
it("supports loading, empty, denied, unavailable and retry states")
```

Test keyboard row activation, Escape close, focus return, accessible table headers, error summary, and visible focus.

- [ ] **Step 2: Verify failure**

Run:

```bash
corepack pnpm@10.34.0 --dir web test -- src/features/connections/components
```

Expected: FAIL because routes/components do not exist.

- [ ] **Step 3: Implement information architecture and table**

Desktop layout:

- page title, scope breadcrumb and concise explainer;
- primary action `新建连接` only when `CREATE_REVISION`/manage action is present;
- filter bar: search、Provider、Profile status、health status、runtime status; active filter chips and reset;
- table columns: Name/Asset、Provider、Connection status、Validation、Health、Published revision、Capabilities、Runtime、Updated;
- row selection is URL `connectionId`; pagination is opaque cursor;
- 1440 detail is 480 px right panel; 1024 may use 440 px if content remains readable; below 1024 route to full detail page.

The four status components have icon + label + optional timestamp, never color alone. Loading uses structure-matched skeleton; empty state distinguishes “no data” from “filters returned none”; 403 and 503 have different actions.

- [ ] **Step 4: Implement detail and revision model**

Detail sections in fixed order:

1. identity: display name、Asset link、Provider、owner、Scope;
2. endpoint identity: scheme/host/port/server name only;
3. trust/network: content reference + digest copy action, no closure bytes;
4. Credential Reference card: display name、owner、issuer kind/id/revision、usage、TTL、status、last validated/used、redacted badge;
5. Runner Realm and exact capability limits;
6. Revision timeline with DRAFT/VALIDATING/VALIDATED/REJECTED/PUBLISHED/SUPERSEDED/REVOKED;
7. validation checks showing fixed code/status/timestamp, not upstream response;
8. current Published Target, Capability Set and Runtime Publication digests/status;
9. health history; no inferred “available” when Runtime gate is closed;
10. audit/change reason link and server-provided actions.

412 leaves user context intact, reloads latest detail, displays safe field-level version comparison, and requires explicit retry. 401 routes through the OIDC reauthentication flow and returns to the exact URL.

- [ ] **Step 5: Run component quality gates**

Run:

```bash
corepack pnpm@10.34.0 --dir web typecheck
corepack pnpm@10.34.0 --dir web lint
corepack pnpm@10.34.0 --dir web test -- src/features/connections/components
```

Expected: PASS；no unsafe credential key appears in rendered DOM；keyboard/focus/URL tests pass.

- [ ] **Step 6: Commit**

```bash
git add web/src/features/connections/routes web/src/features/connections/components web/src/app/router.tsx web/src/app/navigation.ts
git commit -m "feat: add connection inventory and detail views"
```

### Task 14: Build the six-step validation and publication wizard

**Files:**
- Create: `docs/design/frontend/connections-runtime.md`
- Create: `web/scripts/check-connections-design-contract.mjs`
- Create: `web/src/features/connections/routes/connectionCreateRoute.tsx`
- Create: `web/src/features/connections/wizard/connectionWizardSchema.ts`
- Create: `web/src/features/connections/wizard/ConnectionPublicationWizard.tsx`
- Create: `web/src/features/connections/wizard/steps/ScopeProviderStep.tsx`
- Create: `web/src/features/connections/wizard/steps/EndpointTrustStep.tsx`
- Create: `web/src/features/connections/wizard/steps/CredentialReferenceStep.tsx`
- Create: `web/src/features/connections/wizard/steps/CapabilitiesRealmStep.tsx`
- Create: `web/src/features/connections/wizard/steps/ValidationStep.tsx`
- Create: `web/src/features/connections/wizard/steps/ReviewPublishStep.tsx`
- Create: `web/src/features/connections/wizard/OperationPanel.tsx`
- Create: `web/src/features/connections/wizard/ConnectionPublicationWizard.test.tsx`
- Create: `web/src/features/connections/wizard/wizard.module.css`
- Modify: `web/src/app/router.tsx`
- Modify: `web/src/features/connections/routes/connectionDetailRoute.tsx`

**Interfaces:**
- Consumes: typed mutations and references；OIDC recent-auth action；server effective actions/ETag。
- Produces: transient `/connections/new` provider-selection route that creates a server `DRAFT` and immediately history-replaces to canonical `/connections/$connectionId/revisions/$revision` with validated search `mode=publish`、`step` and `operationId`；Workspace/Environment Scope 继续由 URL search 提供，Tenant never enters URL/body；唯一持久设计契约 `docs/design/frontend/connections-runtime.md` 及其漂移检查器。

- [ ] **Step 1: Write failing design-contract and wizard tests**

`check-connections-design-contract.mjs` 必须先断言设计文档存在，并锁定以下章节与实现映射：信息架构与稳定路由、URL schema、1440/1024/390 断点、列表/详情/六步向导组件、loading/empty/403/404/409/412/503/Operation 状态、Token 与密度、键盘/focus/WCAG 2.2、OIDC recent-auth、`effective_actions`、禁止模式。检查器还比对 route 常量、六个 step key 和 CSS 语义 Token，防止文档与实现各自漂移。

```tsx
it("requires an ACTIVE EXACT asset before leaving step one")
it("creates one server draft from /connections/new and replaces to its canonical ID revision URL")
it("does not retain a browser-only draft when server creation fails or scope changes")
it("uses provider-discriminated endpoint fields")
it("selects an opaque credential reference without material input")
it("enforces server capability and realm bindings")
it("resumes a validation operation from the URL after reload")
it("prevents publish until the exact revision is validated")
it("requires recent authentication and a change reason")
it("preserves safe edits and shows latest ETag after 412")
it("publishes once when submit is double-clicked")
```

- [ ] **Step 2: Verify failure**

Run:

```bash
node web/scripts/check-connections-design-contract.mjs
corepack pnpm@10.34.0 --dir web test -- src/features/connections/wizard/ConnectionPublicationWizard.test.tsx
```

Expected: FAIL because持久设计文档、检查器目标和 wizard files 尚不存在。

- [ ] **Step 3: Persist the high-fidelity design contract and implement the discriminated draft Schema**

`docs/design/frontend/connections-runtime.md` 是 Connection 前端的唯一细节规范，必须逐项固化：

- IA、导航归属、`/connections`、`/connections/new`、`/connections/$connectionId`、`/connections/$connectionId/revisions/$revision` 及完整 URL schema；
- 1440 桌面 480px 详情抽屉、1024 临界布局、390 堆叠卡片/独立详情/底部安全操作栏，含精确尺寸和无 body 横向滚动要求；
- 列表列序、详情区序、六步向导字段/验证/Review 层级，以及 loading、empty、denied、unavailable、conflict、expired、drifted/rollback 的可见状态；
- Phase 1 Token、排版、图标、密度、边界、focus、reduced-motion 规则；不得建立第二套 palette；
- 鼠标、键盘、触屏、焦点返回、错误摘要、aria-live、WCAG 2.2 A/AA 的完整交互；
- Keycloak Authorization Code + PKCE、`login-required`、Token 仅内存、recent-auth return URL 与仅按 API `effective_actions` 渲染操作；
- 禁止 AI 聊天气泡/机器人、渐变/glow/glass/超大卡片、通用 JSON/Header/Body、任意命令/SQL、Secret/PEM/Token/DSN/Vault path/raw error，以及浏览器权限推断。

文档中的控件名称、状态文案、列序和 breakpoint 必须与测试 fixture 使用同一稳定常量；任何实现判断变化先修改此契约并复核，不能在组件内悄悄形成第二事实源。

`connectionCreateRoute.tsx` contains only Provider selection and the server draft mutation. It sends no Tenant、credential material or endpoint before the Provider contract permits it；on success it uses history `replace` to the returned canonical ID/revision route. All subsequent fields、steps、ETag、Operation and resumability live at that canonical route；reload/back cannot revive a second local draft.

```ts
const endpointSchema = z.discriminatedUnion("providerKind", [
  z.object({
    providerKind: z.literal("PROMETHEUS"),
    scheme: z.literal("https"),
    host: hostnameSchema,
    port: z.number().int().min(1).max(65535),
    serverName: hostnameSchema,
  }),
  z.object({
    providerKind: z.literal("VICTORIALOGS"),
    scheme: z.literal("https"),
    host: hostnameSchema,
    port: z.number().int().min(1).max(65535),
    serverName: hostnameSchema,
  }),
]);
```

Schema also requires scoped Asset ID、content-addressed trust/network references、Credential Reference ID+revision、Realm reference、1–32 exact capability selections and bounded budgets. Refinement requires host/serverName equality and rejects URL paths/query/userinfo. No field accepts PEM, token, password or arbitrary JSON.

- [ ] **Step 4: Implement the six fixed steps**

1. **Scope & Provider:** Workspace/Environment locked from the validated global Scope search；choose a server-returned source-valid、`EXACT` Asset in `DISCOVERED|STALE|ACTIVE` and an installed Prometheus/VictoriaLogs Provider. The UI explains that successful Runtime publication activates the first two states；it never changes lifecycle locally.
2. **Endpoint & Trust:** HTTPS host/port/server name; choose existing trust and network policy references; explain DNS/IP and egress restrictions.
3. **Credential Reference:** searchable safe projection, owner/issuer/TTL/status; disabled references cannot continue; never reveal or paste material.
4. **Capabilities & Realm:** choose server-returned compatible definitions and VALIDATION Realm; edit bounded duration/items/bytes; show compiled read-only action class.
5. **Validate:** submit once with Idempotency-Key/ETag; Operation panel uses aria-live, fixed phases and checks; reload resumes from URL; failure shows stable remediation code.
6. **Review & Publish:** immutable diff, target/capability/bundle digest preview, change reason, recent-auth gate and explicit production confirmation; publishing tracks rolling Runtime Operation through APPLIED or rollback.

Back navigation is allowed before validation. Changing any input after validation creates a new DRAFT Revision and invalidates prior validation; UI never “edits” a validated Revision. Closing the wizard keeps URL-addressable server state and discards only unsaved in-memory form fields after confirmation.

- [ ] **Step 5: Implement Operation, conflict and failure behavior**

- disable repeated submit while mutation is pending; generated Idempotency-Key remains stable across network retry;
- `QUEUED/RUNNING` panel shows phase/progress, cancel only if server effective action exists;
- `FAILED/EXPIRED` preserves safe configuration and offers new validation attempt;
- OIDC recent-auth calls the Phase 1 `reauthenticate(returnURL)` flow (`prompt:login`、`maxAge:0`) and returns to the exact step 6 URL without storing tokens or draft bodies in application persistence；backend `auth_time` remains authoritative;
- 412 refetches latest Revision, shows changed version/digests, and requires explicit “create revision from latest”;
- Runtime `DRIFTED/ROLLED_BACK` never shows success; display last attested bundle and audit reference;
- 403/404 use non-enumerating language; 503 does not offer fake/local validation.

- [ ] **Step 6: Run frontend gates**

Run:

```bash
node web/scripts/check-connections-design-contract.mjs
corepack pnpm@10.34.0 --dir web typecheck
corepack pnpm@10.34.0 --dir web lint
corepack pnpm@10.34.0 --dir web test -- src/features/connections/wizard
corepack pnpm@10.34.0 --dir web build
```

Expected: all PASS；设计文档与 route/step/token 实现一致；six-step happy/failure/reload/conflict flows pass；production bundle has no MSW import.

- [ ] **Step 7: Commit**

```bash
git add docs/design/frontend/connections-runtime.md web/scripts/check-connections-design-contract.mjs \
  web/src/features/connections/wizard web/src/features/connections/routes/connectionCreateRoute.tsx \
  web/src/features/connections/routes/connectionDetailRoute.tsx web/src/app/router.tsx
git commit -m "feat: add governed connection publication wizard"
```
