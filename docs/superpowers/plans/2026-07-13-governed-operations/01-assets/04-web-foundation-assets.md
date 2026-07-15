# Web Foundation and Asset Operations UI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 建立真实 OIDC 保护的统一 React 前端，并交付资产目录、资产详情、映射工作台和发现同步页面的完整交互与安全状态。

**Architecture:** `web/` 是唯一前端，遵循 `app → features → shared` 单向依赖；Go Control Plane 同源提供 `/api/*` 与 `web/dist`，生产不运行 Node。入口先读取匿名 `/api/v1/browser-config`，再注入 `keycloak-js` 内存 Token Provider；OpenAPI 生成唯一 API 类型，页面只消费安全 DTO 与 `effective_actions`。

**Tech Stack:** Node.js 24、pnpm 10.34.0、React 19.2.7、Vite 8.1.4、TypeScript 7.0.2、TanStack Router/Query/Table、React Hook Form、Zod、Radix、lucide-react 1.24.0、keycloak-js 26.2.4、CSS Modules、Vitest、MSW。

## Global Constraints

- 前置任务：按顺序完成 [03-mapping-auth-api.md](./03-mapping-auth-api.md)；前端契约以 `api/openapi/control-plane-v1.yaml` 为唯一事实源。
- 前端根目录固定 `web/`；不得创建第二套 SPA、Next.js/Remix、Node BFF、微前端、Redux/Zustand 或手写生成类型。
- 生产入口必须先校验 `/api/v1/browser-config`，再真实执行 OIDC Authorization Code + PKCE、`login-required`、请求前 `updateToken(30)`；任一步失败都 fail closed。
- Token 只在内存，禁止 localStorage、sessionStorage、IndexedDB、Cookie 或日志。
- fake/MSW 只能用于 Vitest/Playwright 测试入口，不得进入生产 `main.tsx` 或 production bundle。
- 所有网络访问集中在 `shared/api`；业务模块禁止直接 `fetch`。类型化 transport 注入 `getAccessToken`，使用 `credentials: omit`、`cache: no-store`，并解析 RFC 9457 Problem/Trace ID。
- URL 保存 Scope/筛选/排序/Cursor/Tab/非敏感选中 ID；TanStack Query 保存含 Scope 的服务端状态，Scope 切换时取消并清理；RHF+Zod 保存临时表单，局部 React state 只保存抽屉、焦点和展开状态，Context 只保存 auth/scope/theme。
- UI 只使用服务端 `effective_actions`；`STALE`、`QUARANTINED`、`AMBIGUOUS`、`UNRESOLVED` 不显示调查主按钮。
- 管理状态等待服务端确认；仅筛选/展开可乐观更新。治理 Mutation 不自动重试、不自动重放，409 必须展示持久差异并要求重新审阅。
- WCAG 2.2 AA、2px 焦点、Reduced Motion、键盘完整可达、移动触控目标 44px。
- 禁止聊天框、AI 头像、霓虹/发光/玻璃拟态、通用终端、任意 SSH/WinRM/SQL/命令/Header/Body 输入。
- Vite 只用于构建和本地开发；生产由 Go 同源服务不可变 hash 静态资源、CSP 和 OIDC 回调，禁止 `vite preview`、独立 Web 运行时和宽泛 CORS。
- 所有前端写流必须落真实 API/PostgreSQL 并显示服务端审计/Trace 结果；阶段完成仍以 05 的真实 OIDC+PostgreSQL E2E、低基数指标、备份恢复和多副本故障演练为门禁。
- 当前 UI 是完整生产资产治理入口，不是静态 demo；目标写能力将在后续受治理阶段接入，本包不提前展示。
- 每个任务严格按 Red → Green → Refactor；任务末尾提交步骤只包含本任务文件。
- 本包完成后进入 [05-source-ingestion-csv-api.md](./05-source-ingestion-csv-api.md)。

---


### Task 9: Unified React toolchain, generated API client, real browser OIDC, and application shell

**Files:**
- Create: **docs/design/frontend/foundation-assets.md**
- Create: **web/package.json**
- Create: **web/pnpm-lock.yaml**
- Create: **web/index.html**
- Create: **web/tsconfig.json**
- Create: **web/tsconfig.app.json**
- Create: **web/tsconfig.node.json**
- Create: **web/vite.config.ts**
- Create: **web/eslint.config.js**
- Create: **web/scripts/check-generated-api.sh**
- Create: **web/src/main.tsx**
- Create: **web/src/vite-env.d.ts**
- Create: **web/src/app/router.tsx**
- Create: **web/src/app/providers.tsx**
- Create: **web/src/app/AppShell.tsx**
- Create: **web/src/app/AppShell.module.css**
- Create: **web/src/app/navigation.ts**
- Create: **web/src/app/auth/keycloak.ts**
- Create: **web/src/app/auth/AuthBoundary.tsx**
- Create: **web/src/app/scope/ScopeProvider.tsx**
- Create: **web/src/app/styles/tokens.css**
- Create: **web/src/app/styles/global.css**
- Create: **web/src/shared/api/schema.d.ts**
- Create: **web/src/shared/api/browserConfig.ts**
- Create: **web/src/shared/api/controlPlaneClient.ts**
- Create: **web/src/shared/api/operation.ts**
- Create: **web/src/shared/api/problem.ts**
- Create: **web/src/shared/api/queryKeys.ts**
- Create: **web/src/shared/operations/useOperation.ts**
- Create: **web/src/shared/operations/useOperation.test.tsx**
- Create: **web/src/shared/ui/DataTable.tsx**
- Create: **web/src/shared/ui/FilterBar.tsx**
- Create: **web/src/shared/ui/CursorPagination.tsx**
- Create: **web/src/shared/ui/Drawer.tsx**
- Create: **web/src/shared/ui/StatusBadge.tsx**
- Create: **web/src/shared/ui/ProblemPanel.tsx**
- Create: **web/src/shared/ui/OperationTimeline.tsx**
- Create: **web/src/shared/ui/EffectiveActionGate.tsx**
- Create: **web/src/shared/ui/ETagConflictReview.tsx**
- Create: **web/src/shared/ui/ReauthBoundary.tsx**
- Create: **web/src/shared/ui/AbsoluteTime.tsx**
- Create: **web/src/shared/ui/primitives.test.tsx**
- Create: **web/src/test/setup.ts**
- Create: **web/src/test/msw/fixtures.ts**
- Create: **web/src/test/msw/handlers.ts**
- Create: **web/src/test/msw/browser.ts**
- Create: **web/src/test/msw/server.ts**
- Create: **web/src/shared/api/browserConfig.test.ts**
- Create: **web/src/app/auth/keycloak.test.ts**
- Create: **web/src/shared/api/controlPlaneClient.test.ts**
- Create: **web/src/app/AppShell.test.tsx**
- Create: **internal/httpapi/webui.go**
- Create: **internal/httpapi/webui_test.go**
- Modify: **internal/httpapi/router.go**
- Modify: **internal/httpapi/router_test.go**
- Modify: **internal/config/config.go**
- Modify: **internal/config/config_test.go**
- Modify: **cmd/control-plane/main.go**
- Modify: **cmd/control-plane/main_test.go**

**Interfaces:**
- Consumes: `api/openapi/control-plane-v1.yaml`、anonymous `/api/v1/browser-config` and authenticated `/api/v1/session`.
- Produces: private method/path-aware transport with injected `getAccessToken`, generated `paths/components/operations` types, shared Operation projection/hook and reusable governance UI primitives.
- Produces: same-origin Go SPA service; `/api/*` and health/readiness paths never enter SPA fallback.
- Security: production entry has exactly one auth implementation—`keycloak-js` Authorization Code + PKCE, `login-required`, memory-only token.

- [ ] **Step 1: Persist the frontend foundation contract, then pin the exact package graph and scripts**

Before creating code, persist `docs/design/frontend/foundation-assets.md` as the unique Phase 1 application-platform source. It fixes `app → features → shared` boundaries, state ownership, typed API/Problem/Operation flow, shared primitives, route/URL schema, visual/accessibility tokens, runtime Browser Config/OIDC bootstrap, same-origin Go serving/cache/CSP behavior, governance mutation rules, responsive states and the forbidden BFF/chat/AI-avatar/terminal/secret/editor patterns. AI surfaces must render Investigation、Evidence、ActionProposal、ActionPlan、Operation and Audit as governed domain objects rather than a global chat entry. Later tasks may verify and extend domain details but must not create another foundation source.

Create `web/package.json`:

~~~json
{
  "name": "@aiops/control-plane-web",
  "private": true,
  "version": "0.1.0",
  "type": "module",
  "packageManager": "pnpm@10.34.0",
  "engines": {
    "node": ">=24 <25",
    "pnpm": ">=10 <11"
  },
  "scripts": {
    "dev": "vite",
    "generate:api": "openapi-typescript ../api/openapi/control-plane-v1.yaml -o src/shared/api/schema.d.ts",
    "generate:api:check": "sh ./scripts/check-generated-api.sh",
    "typecheck": "tsc -b --pretty false",
    "lint": "eslint . --max-warnings=0",
    "test": "vitest run",
    "build": "tsc -b && vite build",
    "test:e2e": "playwright test",
    "check": "pnpm generate:api:check && pnpm typecheck && pnpm lint && pnpm test && pnpm build"
  },
  "dependencies": {
    "@tanstack/react-query": "5.101.2",
    "@tanstack/react-router": "1.170.17",
    "@tanstack/react-table": "8.21.3",
    "keycloak-js": "26.2.4",
    "lucide-react": "1.24.0",
    "radix-ui": "1.6.2",
    "react": "19.2.7",
    "react-dom": "19.2.7",
    "react-hook-form": "7.81.0",
    "zod": "4.4.3"
  },
  "devDependencies": {
    "@axe-core/playwright": "4.12.1",
    "@eslint/js": "10.0.1",
    "@playwright/test": "1.61.1",
    "@testing-library/jest-dom": "6.9.1",
    "@testing-library/react": "16.3.2",
    "@testing-library/user-event": "14.6.1",
    "@types/node": "24.13.3",
    "@types/react": "19.2.17",
    "@types/react-dom": "19.2.3",
    "@vitejs/plugin-react": "6.0.3",
    "@vitest/coverage-v8": "4.1.10",
    "eslint": "10.7.0",
    "eslint-plugin-react-hooks": "7.1.1",
    "eslint-plugin-react-refresh": "0.5.3",
    "globals": "17.7.0",
    "jsdom": "29.1.1",
    "msw": "2.15.0",
    "openapi-typescript": "7.13.0",
    "typescript": "7.0.2",
    "typescript-eslint": "8.63.0",
    "vite": "8.1.4",
    "vitest": "4.1.10"
  }
}
~~~

If `@types/node` has moved when implementation starts, do not silently float it: verify compatibility with Node 24, update the exact pin and record the reason in the implementation commit. All user-mandated versions above remain fixed.

Generate the lockfile:

Run: `corepack pnpm@10.34.0 --dir web install --lockfile-only`

Expected: exit 0 and a `web/pnpm-lock.yaml` whose importer uses exact versions and contains no workspace link to a second frontend.

- [ ] **Step 2: Configure strict TypeScript, Vite, ESLint, and Vitest**

`tsconfig.app.json` must set `strict`、`noUncheckedIndexedAccess`、`exactOptionalPropertyTypes`、`noImplicitOverride`、`noFallthroughCasesInSwitch`、`noUnusedLocals`、`noUnusedParameters` and `useUnknownInCatchVariables`; set aliases `@/* -> src/*`. Vite proxies `/api` to `VITE_API_PROXY_TARGET` only in development, never bakes an API secret into the bundle.

Use one Vite config:

~~~ts
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

export default defineConfig({
  plugins: [react()],
  resolve: { alias: { "@": new URL("./src", import.meta.url).pathname } },
  build: {
    target: "es2024",
    sourcemap: false,
    manifest: true,
    reportCompressedSize: true,
  },
  test: {
    environment: "jsdom",
    setupFiles: ["./src/test/setup.ts"],
    restoreMocks: true,
    clearMocks: true,
    coverage: {
      provider: "v8",
      reporter: ["text", "json-summary"],
      thresholds: { lines: 85, functions: 85, branches: 80, statements: 85 },
    },
  },
});
~~~

ESLint must ban `console.*` except `console.error` inside the centralized error reporter, explicit `any`, non-null assertions, and direct `fetch` outside `shared/api`; require exhaustive hooks and enforce `app → features → shared`: `shared` imports neither upper layer, `features` imports only itself plus `shared`, and `app` may compose both. Ignore only generated API and Playwright snapshots.

- [ ] **Step 3: Generate and freeze the OpenAPI types**

Create `web/scripts/check-generated-api.sh` so drift detection is independent of Git staging state:

~~~sh
#!/bin/sh
set -eu

generated_file="src/shared/api/schema.d.ts"
temporary_file="$(mktemp)"
trap 'rm -f "$temporary_file"' EXIT HUP INT TERM

pnpm exec openapi-typescript ../api/openapi/control-plane-v1.yaml -o "$temporary_file"
cmp "$temporary_file" "$generated_file"
~~~

Run:

~~~bash
corepack pnpm@10.34.0 --dir web install --frozen-lockfile
corepack pnpm@10.34.0 --dir web generate:api
corepack pnpm@10.34.0 --dir web generate:api:check
~~~

Expected on first implementation: generation creates the file；the independent temporary generation compares byte-for-byte and exits 0 without relying on staged/committed state. Mutate one generated line, confirm `generate:api:check` exits non-zero, restore by `generate:api`, then confirm exit 0. Never hand-edit the generated file.

- [ ] **Step 4: Write failing browser-auth and client tests**

~~~ts
it("loads closed runtime browser config before OIDC and fails closed", async () => {
  const fetcher = vi.fn().mockResolvedValue(new Response(JSON.stringify({
    oidc: { url: "https://identity.example.com", realm: "aiops", client_id: "control-plane-web" },
    api_base_path: "/api/v1",
    build: { version: "1.0.0", commit: "abc123", contract_digest: `sha256:${"0".repeat(64)}` },
  })));
  await expect(loadBrowserConfig(fetcher)).resolves.toMatchObject({ apiBasePath: "/api/v1" });
  expect(fetcher).toHaveBeenCalledWith("/api/v1/browser-config", expect.objectContaining({
    cache: "no-store", credentials: "omit", redirect: "error",
  }));
  await expect(loadBrowserConfig(malformedConfigFetcher())).rejects.toThrow("Browser configuration unavailable");
});

it("refreshes the in-memory token before every API request", async () => {
  const workspaceID = "33333333-3333-4333-8333-333333333333";
  const environmentID = "44444444-4444-4444-8444-444444444444";
  const getAccessToken = vi.fn().mockResolvedValue("ephemeral-token");
  const fetcher = vi.fn().mockResolvedValue(
    new Response(JSON.stringify(assetPageFixture), {
      status: 200,
      headers: { "Content-Type": "application/json", ETag: '"asset:list:v1"' },
    }),
  );
  const client = createControlPlaneClient({ baseURL: "", getAccessToken, fetcher });

  await client.execute("listAssets", {
    parameters: { path: { workspace_id: workspaceID, environment_id: environmentID } },
  });

  expect(getAccessToken).toHaveBeenCalledTimes(1);
  expect(fetcher).toHaveBeenCalledWith(
    `/api/v1/workspaces/${workspaceID}/environments/${environmentID}/assets`,
    expect.objectContaining({
      headers: expect.objectContaining({ Authorization: "Bearer ephemeral-token" }),
      cache: "no-store",
      credentials: "omit",
    }),
  );
});

it("never writes an access token to browser persistence", async () => {
  const storageSpies = [
    vi.spyOn(Storage.prototype, "setItem"),
    vi.spyOn(Storage.prototype, "getItem"),
  ];
  const provider = await createKeycloakAccessTokenProvider(validOIDCConfig, fakeKeycloak());
  await provider.getAccessToken();
  for (const spy of storageSpies) {
    expect(spy).not.toHaveBeenCalled();
  }
  expect(document.cookie).toBe("");
});

it("forces a fresh login and preserves only a validated same-origin return URL", async () => {
  const keycloak = fakeKeycloak();
  const provider = await createKeycloakAccessTokenProvider(validOIDCConfig, keycloak);
  await provider.reauthenticate("/connections/c-1?step=review");
  expect(keycloak.login).toHaveBeenCalledWith({
    prompt: "login",
    maxAge: 0,
    redirectUri: `${window.location.origin}/connections/c-1?step=review`,
  });
  await expect(provider.reauthenticate("https://evil.invalid/steal")).rejects.toThrow(
    "OIDC return URL must be same-origin",
  );
});
~~~

Run: `corepack pnpm@10.34.0 --dir web test -- browserConfig.test.ts keycloak.test.ts controlPlaneClient.test.ts`

Expected: FAIL because auth and API client modules do not exist.

- [ ] **Step 5: Implement real OIDC with an injected memory-only token provider**

~~~ts
import Keycloak from "keycloak-js";

export type AccessTokenProvider = {
  getAccessToken: () => Promise<string>;
  login: () => Promise<void>;
  reauthenticate: (returnURL: string) => Promise<void>;
  logout: () => Promise<void>;
};

export async function createKeycloakAccessTokenProvider(
  config: OIDCConfig,
  keycloak = new Keycloak({
    url: config.url,
    realm: config.realm,
    clientId: config.clientId,
  }),
): Promise<AccessTokenProvider> {
  const authenticated = await keycloak.init({
    onLoad: "login-required",
    pkceMethod: "S256",
    checkLoginIframe: false,
    enableLogging: false,
  });
  if (!authenticated || !keycloak.token) {
    throw new Error("OIDC authentication failed");
  }
  return {
    async getAccessToken() {
      const refreshed = await keycloak.updateToken(30);
      if (!refreshed && !keycloak.token) {
        await keycloak.login();
        throw new Error("OIDC token unavailable");
      }
      if (!keycloak.token) {
        throw new Error("OIDC token unavailable");
      }
      return keycloak.token;
    },
    login: async () => void (await keycloak.login()),
    async reauthenticate(returnURL) {
      const redirectURL = new URL(returnURL, window.location.origin);
      if (redirectURL.origin !== window.location.origin) {
        throw new Error("OIDC return URL must be same-origin");
      }
      await keycloak.login({
        prompt: "login",
        maxAge: 0,
        redirectUri: redirectURL.href,
      });
    },
    logout: async () => void (await keycloak.logout({ redirectUri: window.location.origin })),
  };
}
~~~

`loadBrowserConfig` fetches only same-origin `/api/v1/browser-config` with no Authorization, validates the exact closed shape with Zod, accepts HTTPS OIDC URL outside localhost plus non-empty realm/public client/build identity, and rejects extra/secret-like fields. Production reads no build-time OIDC or API-base variables. `main.tsx` blocks rendering until Browser Config and OIDC initialize in that order; failure provides a trace-free retry/login message, never an anonymous app. `checkLoginIframe:false` is deliberate because CSP grants no cross-origin frame; request-time `updateToken(30)` and API 401 detect expiry. Reauthentication always uses `prompt:login + maxAge:0` and validated same-origin return URL; the backend independently verifies `auth_time`. No module calls browser persistence APIs.

- [ ] **Step 6: Implement the typed API transport**

`operation.ts` derives `OperationID`、path/query/header/body input and success response types exclusively from generated `operations`/`paths`. `controlPlaneClient.ts` exports only `execute<K extends OperationID>(operation: K, input: OperationInput<K>): Promise<OperationResult<K>>`; its fetch transport and operation method/path registry are private and contract-tested against OpenAPI operation IDs. Compile-time tests use `@ts-expect-error` to prove wrong method, path parameter, body or response access cannot compile. Feature adapters expose domain methods and generated aliases, never raw paths or handwritten DTOs.

Every request refreshes the token, sends only declared Idempotency-Key/If-Match headers, uses same-origin Browser Config `api_base_path`, and validates RFC 9457 Problem with Zod. Unknown/malformed errors become `unexpected_response` with the response Trace header. Never log token, request/response body, query values, labels, external ID or raw Problem detail. Query-key factories always include workspace/environment and normalized filters.

`web/src/shared/operations/useOperation.ts` accepts a generated safe projection adapter plus `{workspaceId, environmentId, kind, operationId}`. It keeps `operationId` in URL, pauses while hidden/offline, resumes on focus, honors bounded `Retry-After` or capped backoff, and stops on the adapter's terminal states. It never retries or replays the initiating Mutation; feature modules extend adapters/status invalidation instead of creating another polling hook.

- [ ] **Step 7: Implement same-origin Go SPA serving, the application shell, shared UI, and persisted visual tokens**

`internal/httpapi/webui.go` serves the validated `AIOPS_WEB_ROOT` (`/opt/aiops/web` in the production artifact) from the existing Go Control Plane. `/api/*`、`/healthz`、`/readyz` and non-GET/HEAD requests never receive SPA fallback. Only normalized, extensionless browser GET/HEAD routes accepting HTML may fall back to `index.html`; reject traversal, encoded separators and files outside root. `index.html` uses `no-store`; hashed `/assets/*` uses `public,max-age=31536000,immutable`; missing index/manifest fails production startup and readiness fails if assets later disappear.

Static responses set `nosniff`、`no-referrer` and CSP `default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self' <OIDC-origin>; frame-ancestors 'none'; base-uri 'none'; object-src 'none'; form-action <OIDC-origin>`. No inline script or permissive CORS is allowed. Vite remains build/dev-only and the Go router is the sole production Web/API process.

Build shared `DataTable`、`FilterBar`、`CursorPagination`、`Drawer`、`StatusBadge`、`ProblemPanel`、`OperationTimeline`、`EffectiveActionGate`、`ETagConflictReview` and `ReauthBoundary` once from Radix, TanStack Table and CSS Modules. Features compose them and may not fork permission, Problem, ETag or Operation behavior.

The shell structure is fixed:

~~~text
┌─ 220px #17212B navigation ─┬─ 46px workspace/environment context bar ─────┐
│ product + environment mark │ breadcrumb / scope / user / help             │
│ Run                         ├───────────────────────────────────────────────┤
│   Overview                  │ page header: title, status, one primary action│
│   Incidents                 │ filter/action strip                           │
│   Investigations            │ dense data surface                            │
│   Proactive                 │                                               │
│ Assets & Connections        │ optional 460px detail drawer                  │
│   Asset Catalog             │                                               │
│   Mapping Workbench         │                                               │
│   Connections               │                                               │
│   Discovery & Sync          │                                               │
│   Credential References     │                                               │
│   Runner & Capabilities     │                                               │
│ Governance / Audit          │                                               │
└─────────────────────────────┴───────────────────────────────────────────────┘
~~~

Use Chinese visible labels and full product terms; never abbreviate VictoriaMetrics as “VM”. Routes not implemented in this slice remain visually present only if they already exist; otherwise render them disabled with `aria-disabled=true` and “后续阶段” text, not dead links.

`tokens.css` must define:

~~~css
:root {
  --color-bg: #f4f6f8;
  --color-surface: #ffffff;
  --color-nav: #17212b;
  --color-text: #17202a;
  --color-muted: #52606d;
  --color-border: #d7dde3;
  --color-primary: #1f5ea8;
  --color-success: #287a4b;
  --color-warning: #9a5b0a;
  --color-danger: #b42318;
  --focus-ring: 0 0 0 2px #ffffff, 0 0 0 4px #1f5ea8;
  --nav-width: 220px;
  --context-height: 46px;
  --drawer-width: 460px;
  --table-row-height: 38px;
  --space-1: 4px;
  --space-2: 8px;
  --space-3: 12px;
  --space-4: 16px;
  --space-5: 20px;
  --space-6: 24px;
  --radius-sm: 4px;
  --radius-md: 6px;
}
~~~

Typography uses a system sans stack at 14px body/20px line height, 12px metadata, 20–24px page title, and tabular numerals for counts/time. Shadows are limited to the drawer/popover; panels use 1px borders. No gradients, glass, glow, chatbot, avatar assistant, terminal panel, arbitrary SQL/command input, or oversized marketing cards.

Scope state rules:

- workspace and environment live in URL search/path, never persistence;
- selecting a scope validates it against `/api/v1/session`;
- changing either aborts in-flight queries and clears scope-specific cache;
- an active dirty form opens a blocking Radix AlertDialog; “取消” preserves scope, “放弃并切换” discards only local draft;
- unauthorized deep link renders a scoped 403/404 state without indicating whether the object exists elsewhere.

- [ ] **Step 8: Test shell keyboard, responsive, and failure behavior**

Run:

~~~bash
corepack pnpm@10.34.0 --dir web typecheck
corepack pnpm@10.34.0 --dir web lint
corepack pnpm@10.34.0 --dir web test -- AppShell.test.tsx browserConfig.test.ts keycloak.test.ts controlPlaneClient.test.ts useOperation.test.tsx primitives.test.tsx
corepack pnpm@10.34.0 --dir web build
go test -race ./internal/httpapi ./internal/config ./cmd/control-plane -count=1
~~~

Expected: PASS. Tests verify runtime-config-before-OIDC, operation/path compile-time safety, shared Operation visibility/terminal behavior, UI primitives, skip-link/focus, Scope cancellation/confirmation, no anonymous fallback or mutation auto-retry, SPA reserved-path/fallback/cache/traversal/readiness/CSP rules, generated API drift, no persistence, and a production bundle without source maps or embedded Token/Client Secret.

- [ ] **Step 9: Commit**

~~~bash
git add web/package.json web/pnpm-lock.yaml web/index.html web/tsconfig.json \
  web/tsconfig.app.json web/tsconfig.node.json web/vite.config.ts web/eslint.config.js \
  web/scripts/check-generated-api.sh \
  web/src/main.tsx web/src/vite-env.d.ts web/src/app web/src/shared \
  web/src/test/setup.ts web/src/test/msw docs/design/frontend/foundation-assets.md \
  internal/httpapi/webui.go internal/httpapi/webui_test.go \
  internal/httpapi/router.go internal/httpapi/router_test.go \
  internal/config/config.go internal/config/config_test.go \
  cmd/control-plane/main.go cmd/control-plane/main_test.go
git commit -m "feat(web): establish secure control plane shell"
~~~

### Task 10: Asset catalog, governed detail, and manual registration

**Files:**
- Create: **web/src/features/assets/assetSearch.ts**
- Create: **web/src/features/assets/api.ts**
- Create: **web/src/features/assets/AssetCatalogPage.tsx**
- Create: **web/src/features/assets/AssetCatalogPage.module.css**
- Create: **web/src/features/assets/AssetTable.tsx**
- Create: **web/src/features/assets/AssetDetailDrawer.tsx**
- Create: **web/src/features/assets/AssetDetailPage.tsx**
- Create: **web/src/features/assets/CreateAssetDialog.tsx**
- Create: **web/src/features/assets/GovernanceForm.tsx**
- Create: **web/src/features/assets/AssetCatalogPage.test.tsx**
- Modify: **web/src/app/router.tsx**
- Modify: **web/src/test/msw/fixtures.ts**
- Modify: **web/src/test/msw/handlers.ts**

**Interfaces:**
- Consumes generated `AssetPage`、`AssetDetail`、create/patch/transition schemas and response ETag.
- Produces `/assets` and `/assets/$assetId`; list state is URL state, not component/global persistence.
- Query key: `["assets", workspaceId, environmentId, canonicalSearch]`; mutation success invalidates only that Scope.

- [ ] **Step 1: Write failing URL, keyboard, permission, and unsafe-state tests**

~~~tsx
it("restores filters, cursor trail, selection and tab from the URL", async () => {
  renderAssetCatalog(
    "/assets?workspace=w&environment=e&kind=LINUX_VM&lifecycle=STALE" +
      "&sort=last_observed_at_desc&assetId=a&tab=relations",
  );
  expect(await screen.findByRole("heading", { name: "资产目录" })).toBeVisible();
  expect(screen.getByRole("button", { name: "类型：Linux 虚拟机" })).toBeVisible();
  expect(screen.getByRole("dialog", { name: "payments-api-01 资产详情" })).toBeVisible();
  expect(screen.getByRole("tab", { name: "关系" })).toHaveAttribute("aria-selected", "true");
});

it("uses effective_actions and hides investigation for unsafe assets", async () => {
  server.use(assetPageHandler({ lifecycle: "QUARANTINED", effective_actions: ["RETIRE"] }));
  renderAssetCatalog("/assets?workspace=w&environment=e&assetId=a");
  expect(await screen.findByText("资产已隔离")).toBeVisible();
  expect(screen.getByRole("button", { name: "退役资产" })).toBeEnabled();
  expect(screen.queryByRole("button", { name: /调查|运行诊断/ })).not.toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "编辑治理信息" })).not.toBeInTheDocument();
});

it("opens and closes the detail drawer without losing list state", async () => {
  const user = userEvent.setup();
  renderAssetCatalog("/assets?workspace=w&environment=e&q=payments");
  const row = await screen.findByRole("row", { name: /payments-api-01/ });
  row.focus();
  await user.keyboard("{Enter}");
  expect(screen.getByRole("dialog")).toBeVisible();
  await user.keyboard("{Escape}");
  expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  expect(window.location.search).toContain("q=payments");
});
~~~

Run: `corepack pnpm@10.34.0 --dir web test -- AssetCatalogPage.test.tsx`

Expected: FAIL because feature routes/components do not exist.

- [ ] **Step 2: Implement a closed URL schema and data adapter**

~~~ts
export const assetSearchSchema = z.object({
  workspace: z.string().uuid(),
  environment: z.string().uuid(),
  q: z.string().trim().max(128).optional(),
  kind: z.array(assetKindSchema).max(17).default([]),
  source: z.array(z.string().uuid()).max(20).default([]),
  service: z.string().uuid().optional(),
  mapping: z.array(z.enum(["EXACT", "AMBIGUOUS", "UNRESOLVED"])).max(3).default([]),
  lifecycle: z.array(z.enum(["DISCOVERED", "ACTIVE", "STALE", "QUARANTINED", "RETIRED"])).max(5).default([]),
  sort: z.enum(["display_name_asc", "last_observed_at_desc"]).default("display_name_asc"),
  cursor: z.string().max(2048).optional(),
  trail: z.array(z.string().max(2048)).max(20).default([]),
  assetId: z.string().uuid().optional(),
  tab: z.enum(["overview", "connections", "capabilities", "relations", "audit"]).default("overview"),
});
~~~

Canonicalize arrays by sorting/deduplicating before navigation. Send only supported API filters/sort/cursor. The next-page action appends the current cursor to `trail`; previous pops it. Search/filter/sort changes clear cursor/trail but preserve valid selection only if still returned.

- [ ] **Step 3: Build the dense catalog and responsive detail interaction**

At `≥1024px`, use a 38px-row TanStack Table with sticky identity and status columns and a 460px Radix Dialog drawer. Columns, in order:

1. 名称 / 外部 ID;
2. 类型;
3. Service / Environment;
4. 权威来源;
5. 映射;
6. 生命周期;
7. 连接健康;
8. Capability 门禁;
9. 最近观测（relative text + absolute zoned tooltip).

Header order is breadcrumb → title/count → one primary action → filter bar. Direct filters: keyword/type/service/source/mapping/lifecycle; advanced panel: criticality/data classification/connection/capability. Every active filter is a removable chip with “清除全部”.

Row click updates `assetId` without losing URL context; double click or “在完整页打开” routes to `/assets/$assetId`; ArrowUp/ArrowDown moves roving focus, Enter opens, Escape closes and restores row focus. At `<1024px`, no drawer is mounted: selection navigates to full page. At `<640px`, filters collapse into a sheet and targets are at least 44px.

Drawer/page tabs:

- 概览: stable ID, external ID, source, provider, governance, safe labels, field provenance, version, exact observation time;
- 连接/能力: render server safe summaries; `NOT_CONFIGURED` is an explicit neutral empty state, never a guessed health;
- 关系: typed edges with direction and confidence;
- 审计: show a scoped “审计 API 后续接入” state until a real audit endpoint exists—do not invent records.

Top banners for STALE/QUARANTINED/AMBIGUOUS/UNRESOLVED state reason, impact, and permitted governance entry. No banner offers investigation.

- [ ] **Step 4: Implement governed create/edit/quarantine/retire flows**

“添加资产” is shown only for collection `CREATE_ASSET`. The Radix dialog states: “仅登记可运维引用；不会创建、接管或连接外部资源。” It loads the server-filtered query `usage=manual_asset_create&environment_id=<current environment>` and offers only rows whose server `effective_actions` contains `CREATE_ASSET`；the browser never infers eligibility from status/role names. The server admits only exact `MANUAL/MANUAL_V1 + ACTIVE + PUBLISHED + AVAILABLE` Sources whose immutable revision semantics equal Task 2 `ManualProfileV1()` and whose sole authority child equals the current path Environment. RHF+Zod accepts that opaque `source_id` plus kind/external ID/display name/owner/criticality/data classification/safe labels；服务端固定派生 Provider/revision/freshness/run facts，浏览器不提交。If no eligible MANUAL source exists, show a disabled explanation that Source creation becomes available only after Task 16's complete revision/profile flow；do not invent browser state or a reduced create form. It sends a fresh `crypto.randomUUID()` Idempotency-Key；never renders endpoint, credential, raw JSON, command, SQL, Header, or Body fields.

Edit is shown only for `EDIT_GOVERNANCE`, preloads governance fields, and sends the latest ETag. Quarantine/retire use AlertDialog with asset name/ID, impact, required bounded reason, and ETag. A 409 keeps the dialog open and renders old vs server version with “重新加载并审阅”; it never auto-retries a governance mutation. Success renders a persistent inline result with audit/trace ID and refetches.

- [ ] **Step 5: Verify components**

Run:

~~~bash
corepack pnpm@10.34.0 --dir web typecheck
corepack pnpm@10.34.0 --dir web lint
corepack pnpm@10.34.0 --dir web test -- AssetCatalogPage.test.tsx
~~~

Expected: PASS, including loading skeleton with stable columns, permission/empty/error/stale states, Trace ID display, focus restoration, URL back/forward, ETag conflict, and absence of forbidden field labels.

- [ ] **Step 6: Commit**

~~~bash
git add web/src/features/assets web/src/app/router.tsx \
  web/src/test/msw/fixtures.ts web/src/test/msw/handlers.ts
git commit -m "feat(web): deliver governed asset catalog"
~~~

### Task 11: Mapping workbench and explicit conflict decisions

**Files:**
- Create: **web/src/features/asset-mappings/mappingSearch.ts**
- Create: **web/src/features/asset-mappings/api.ts**
- Create: **web/src/features/asset-mappings/MappingWorkbenchPage.tsx**
- Create: **web/src/features/asset-mappings/MappingWorkbenchPage.module.css**
- Create: **web/src/features/asset-mappings/ConflictQueue.tsx**
- Create: **web/src/features/asset-mappings/ProvenanceComparison.tsx**
- Create: **web/src/features/asset-mappings/ResolveConflictDialog.tsx**
- Create: **web/src/features/asset-mappings/MappingWorkbenchPage.test.tsx**
- Modify: **web/src/app/router.tsx**
- Modify: **web/src/test/msw/fixtures.ts**
- Modify: **web/src/test/msw/handlers.ts**

**Interfaces:**
- Consumes safe `AssetConflictPage`, comparison/provenance fields, ETag and `effective_actions`.
- Produces `/asset-mappings?workspace&environment&status&risk&source&service&age&cursor&conflictId`.
- Never changes `AMBIGUOUS` to `EXACT` without the explicit resolve endpoint.

- [ ] **Step 1: Write failing explicit-decision tests**

~~~tsx
it("requires reason and impact review before confirming an exact mapping", async () => {
  const user = userEvent.setup();
  renderMappingWorkbench("/asset-mappings?workspace=w&environment=e&conflictId=c");
  await user.click(await screen.findByRole("button", { name: "确认精确映射" }));
  expect(screen.getByText("比较键")).toBeVisible();
  expect(screen.getByText("受影响的连接与策略")).toBeVisible();
  const submit = screen.getByRole("button", { name: "确认并记录决定" });
  expect(submit).toBeDisabled();
  await user.type(screen.getByLabelText("审计原因"), "已由服务负责人核对权威资产编号");
  await user.click(submit);
  expect(await screen.findByText("映射决定已记录")).toBeVisible();
});

it("never exposes a resolve action without server effective_actions", async () => {
  server.use(conflictHandler({ effective_actions: [] }));
  renderMappingWorkbench("/asset-mappings?workspace=w&environment=e&conflictId=c");
  expect(await screen.findByText("只读比较")).toBeVisible();
  expect(screen.queryByRole("button", { name: /确认|拒绝|隔离/ })).not.toBeInTheDocument();
});
~~~

Run: `corepack pnpm@10.34.0 --dir web test -- MappingWorkbenchPage.test.tsx`

Expected: FAIL because mapping components do not exist.

- [ ] **Step 2: Build queue, comparison, and decision states**

Desktop layout uses a 340px conflict queue and fluid comparison surface. Queue filters risk/source/service/wait age/status; rows show source, asset/type, candidate service, stable summary code, age and mapping status. Selection is URL-backed and preserves filters/cursor.

Comparison uses four bordered sections: 权威来源事实、现有资产、候选关系、字段级 Provenance. Each field displays source/revision/observed-at/confidence; raw Provider JSON and fingerprint values are never rendered. A neutral system suggestion is labeled “候选建议，不会自动生效”.

Actions are exact:

- `CONFIRM_EXACT`: require service, binding role, reason and impact acknowledgement;
- `REJECT_CANDIDATE`: require reason;
- `KEEP_UNRESOLVED`: require reason and show that investigation remains unavailable;
- `QUARANTINE_ASSET`: destructive AlertDialog with affected connection/policy counts.

Every action uses a new Idempotency-Key and current ETag. Buttons are derived only from `RESOLVE_CONFLICT`. Mutation progress is local to the selected conflict; navigation warns before abandoning a submitted-but-unconfirmed request.

Batch resolve is enabled only when selected conflicts have identical comparison key, target service and intended action. The client still sends one request per conflict, stops on the first 409/403, and renders per-item success/failure; it never claims all-or-nothing atomicity.

- [ ] **Step 3: Verify decision safety**

Run: `corepack pnpm@10.34.0 --dir web typecheck && corepack pnpm@10.34.0 --dir web lint && corepack pnpm@10.34.0 --dir web test -- MappingWorkbenchPage.test.tsx`

Expected: PASS for URL restoration, keyboard queue navigation, no implicit merge, four decision variants, ETag conflict, partial batch results, and safe provenance.

- [ ] **Step 4: Commit**

~~~bash
git add web/src/features/asset-mappings web/src/app/router.tsx \
  web/src/test/msw/fixtures.ts web/src/test/msw/handlers.ts
git commit -m "feat(web): add explicit asset mapping workbench"
~~~

### Task 12: Discovery source inventory and Source Run timeline

**Files:**
- Create: **web/src/features/asset-sources/sourceSearch.ts**
- Create: **web/src/features/asset-sources/api.ts**
- Create: **web/src/features/asset-sources/AssetSourcesPage.tsx**
- Create: **web/src/features/asset-sources/AssetSourcesPage.module.css**
- Create: **web/src/features/asset-sources/SourceRunTimeline.tsx**
- Create: **web/src/features/asset-sources/AssetSourcesPage.test.tsx**
- Verify/Modify: **docs/design/frontend/foundation-assets.md**
- Modify: **web/src/app/router.tsx**
- Modify: **web/src/test/msw/fixtures.ts**
- Modify: **web/src/test/msw/handlers.ts**

**Interfaces:**
- Consumes Source page/detail and existing SourceRun safe counts.
- Produces `/asset-sources?workspace&status&kind&cursor&sourceId&runId`; polling is only for the selected non-terminal run.

- [ ] **Step 1: Write failing async-run and payload-safety tests**

~~~tsx
it("resumes an existing run timeline after refresh without exposing premature actions", async () => {
  renderSources("/asset-sources?workspace=w&sourceId=s&runId=r");
  expect(await screen.findByText("发现完成")).toBeVisible();
  expect(screen.getByText("已创建 2")).toBeVisible();
  expect(screen.queryByRole("button", { name: /创建来源|立即同步/ })).not.toBeInTheDocument();
  expect(screen.queryByText(/raw_payload|access_token|provider_error/)).not.toBeInTheDocument();
});
~~~

Run: `corepack pnpm@10.34.0 --dir web test -- AssetSourcesPage.test.tsx`

Expected: FAIL because discovery UI does not exist.

- [ ] **Step 2: Implement source inventory and run timeline**

The list shows source type/provider/name/authority scope/sync mode/status/last success/current cursor digest. Its `last_run_counts` are the exact `observed/created/changed/unchanged/conflicts/missing/stale/restored/tombstoned/rejected` values from the server's `last_success_run_id` only；a separate current-run area uses `current_run_counts` only while the one nonterminal Run exists. Neither display sums history, and `PARTIAL` remains visible in the timeline without replacing last-success counts. Never show raw cursor, payload, credential, endpoint or provider error.

Pack 04 intentionally renders neither Source creation nor “立即同步”: the complete immutable revision/profile contract is not implemented until Pack 05, and the API returns no such `effective_actions` here. Task 16 extends this same page with the six-step Source+revision workspace and governed sync action; it must not revive a reduced Provider/Integration form.

For a selected existing run, persist `runId` in the URL and hand it to Task 9's shared Operation adapter/hook. Poll `GET asset-source-runs/{runId}` every 2 seconds only while `QUEUED|DELAYED|RUNNING|FINALIZING` and the page is visible；pause while hidden/offline，resume on focus，and stop on `SUCCEEDED|PARTIAL|FAILED|CANCELLED`. Pack 04 never initiates or replays the sync Mutation；Task 16 adds that governed action only after the complete Source revision contract exists.

Timeline renders the server-owned closed stage mapping：`WAITING` 请求已接受/等待执行、`DELAYED` 延迟重试、`VALIDATING` 验证来源、`READING` 读取来源、`NORMALIZING` 规范化、`APPLYING` 合并投影、`CLEANING_UP` 清理凭据、`COMPLETED` 完成. It never derives stage from elapsed time or role/status guesses. Failed runs show stable error code + Trace ID and a permitted retry action, never upstream text. Completion links conflicts to the mapping workbench while preserving workspace/environment.

Verify and extend the Task 9 `foundation-assets.md` only with Source list/run timeline details. Preserve its application-platform contract, navigation IA, flat routes/URL schemas, exact tokens, full failure states, responsive/keyboard/WCAG behavior, Browser Config/Keycloak flow, `effective_actions`, DTO boundaries and forbidden patterns; do not create a parallel foundation file.

- [ ] **Step 3: Verify polling, visibility, and security**

Run: `corepack pnpm@10.34.0 --dir web typecheck && corepack pnpm@10.34.0 --dir web lint && corepack pnpm@10.34.0 --dir web test -- AssetSourcesPage.test.tsx`

Expected: PASS for 202/resume, focus-aware polling, terminal stop, unauthorized action hiding, empty/degraded/failed states, URL restoration, and forbidden payload scanning.

- [ ] **Step 4: Commit**

~~~bash
git add web/src/features/asset-sources web/src/app/router.tsx \
  web/src/test/msw/fixtures.ts web/src/test/msw/handlers.ts \
  docs/design/frontend/foundation-assets.md
git commit -m "feat(web): operate discovery source runs"
~~~
