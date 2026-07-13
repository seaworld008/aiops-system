# Web Foundation and Asset Operations UI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 建立真实 OIDC 保护的统一 React 前端，并交付资产目录、资产详情、映射工作台和发现同步页面的完整交互与安全状态。

**Architecture:** `web/` 是唯一前端；生产入口只注入 `keycloak-js` 内存 Token Provider，所有 API 类型由 OpenAPI 生成。TanStack Router 将 Scope/筛选/排序/Cursor/Tab/选中项持久化到 URL，TanStack Query 按 Scope 隔离缓存；页面只消费安全 DTO 与 `effective_actions`。

**Tech Stack:** Node.js 24、pnpm 10.34.0、React 19.2.7、Vite 8.1.4、TypeScript 7.0.2、TanStack Router/Query/Table、React Hook Form、Zod、Radix、lucide-react 1.24.0、keycloak-js 26.2.4、CSS Modules、Vitest、MSW。

## Global Constraints

- 前置任务：按顺序完成 [03-mapping-auth-api.md](./03-mapping-auth-api.md)；前端契约以 `api/openapi/control-plane-v1.yaml` 为唯一事实源。
- 前端根目录固定 `web/`；不得创建第二套 SPA、手写生成类型或引入 Redux。
- 生产入口必须真实执行 OIDC Authorization Code + PKCE、`login-required`、请求前 `updateToken(30)`；缺少配置 fail closed。
- Token 只在内存，禁止 localStorage、sessionStorage、IndexedDB、Cookie 或日志。
- fake/MSW 只能用于 Vitest/Playwright 测试入口，不得进入生产 `main.tsx` 或 production bundle。
- 所有 API 调用注入 `getAccessToken`，使用 `credentials: omit`、`cache: no-store`，并解析 RFC 9457 Problem/Trace ID。
- UI 只使用服务端 `effective_actions`；`STALE`、`QUARANTINED`、`AMBIGUOUS`、`UNRESOLVED` 不显示调查主按钮。
- 管理状态等待服务端确认；仅筛选/展开可乐观更新。409 必须展示持久差异并要求重新审阅。
- WCAG 2.2 AA、2px 焦点、Reduced Motion、键盘完整可达、移动触控目标 44px。
- 禁止聊天框、AI 头像、霓虹/发光/玻璃拟态、通用终端、任意 SSH/WinRM/SQL/命令/Header/Body 输入。
- 生产部署必须支持多副本静态资源、不可变带 hash 文件、CSP、OIDC 回调 HA；不得依赖浏览器本地持久状态。
- 所有前端写流必须落真实 API/PostgreSQL 并显示服务端审计/Trace 结果；阶段完成仍以 05 的真实 OIDC+PostgreSQL E2E、低基数指标、备份恢复和多副本故障演练为门禁。
- 当前 UI 是完整生产资产治理入口，不是静态 demo；目标写能力将在后续受治理阶段接入，本包不提前展示。
- 每个任务严格按 Red → Green → Refactor；任务末尾提交步骤只包含本任务文件。
- 本包完成后进入 [05-source-ingestion-csv-api.md](./05-source-ingestion-csv-api.md)。

---


### Task 9: Unified React toolchain, generated API client, real browser OIDC, and application shell

**Files:**
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
- Create: **web/src/shared/api/controlPlaneClient.ts**
- Create: **web/src/shared/api/problem.ts**
- Create: **web/src/shared/api/queryKeys.ts**
- Create: **web/src/shared/components/AsyncState.tsx**
- Create: **web/src/shared/components/StatusBadge.tsx**
- Create: **web/src/shared/components/AbsoluteTime.tsx**
- Create: **web/src/test/setup.ts**
- Create: **web/src/test/msw/fixtures.ts**
- Create: **web/src/test/msw/handlers.ts**
- Create: **web/src/test/msw/browser.ts**
- Create: **web/src/test/msw/server.ts**
- Create: **web/src/app/auth/keycloak.test.ts**
- Create: **web/src/shared/api/controlPlaneClient.test.ts**
- Create: **web/src/app/AppShell.test.tsx**

**Interfaces:**
- Consumes: `api/openapi/control-plane-v1.yaml` and existing `/api/v1/session`.
- Produces: `ControlPlaneClient` with injected `getAccessToken` and generated `paths/components/operations` types.
- Security: production entry has exactly one auth implementation—`keycloak-js` Authorization Code + PKCE, `login-required`, memory-only token.

- [ ] **Step 1: Pin the exact package graph and scripts**

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

ESLint must ban `console.*` except `console.error` inside the centralized error reporter, ban explicit `any`, ban non-null assertions, require exhaustive hooks, and ignore only generated API and Playwright snapshots.

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
it("fails closed when production OIDC configuration is incomplete", async () => {
  expect(() =>
    readOIDCConfig({
      PROD: true,
      VITE_OIDC_URL: "",
      VITE_OIDC_REALM: "aiops",
      VITE_OIDC_CLIENT_ID: "control-plane-web",
    }),
  ).toThrow("OIDC configuration is required");
});

it("refreshes the in-memory token before every API request", async () => {
  const getAccessToken = vi.fn().mockResolvedValue("ephemeral-token");
  const fetcher = vi.fn().mockResolvedValue(
    new Response(JSON.stringify(assetPageFixture), {
      status: 200,
      headers: { "Content-Type": "application/json", ETag: '"asset:list:v1"' },
    }),
  );
  const client = createControlPlaneClient({ baseURL: "", getAccessToken, fetcher });

  await client.get("/api/v1/workspaces/w/environments/e/assets");

  expect(getAccessToken).toHaveBeenCalledTimes(1);
  expect(fetcher).toHaveBeenCalledWith(
    "/api/v1/workspaces/w/environments/e/assets",
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

Run: `corepack pnpm@10.34.0 --dir web test -- keycloak.test.ts controlPlaneClient.test.ts`

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

`readOIDCConfig(import.meta.env)` allows only HTTPS issuer URL outside localhost, non-empty realm/client ID, and no client secret. `checkLoginIframe:false` is deliberate：the CSP does not grant a cross-origin frame；logout/session expiry is detected by request-time `updateToken(30)` and the API 401 path. `reauthenticate` always uses `prompt:login + maxAge:0` and a same-origin return URL；the backend still verifies `auth_time` against its configured recent-auth window. The module must contain no `localStorage`、`sessionStorage`、`indexedDB`、cookie or token persistence calls. `main.tsx` blocks rendering until OIDC initializes；error state provides retry/login and a trace-free configuration message, never an anonymous app.

- [ ] **Step 6: Implement the typed API transport**

~~~ts
export type ClientOptions = {
  baseURL: string;
  getAccessToken: () => Promise<string>;
  fetcher?: typeof fetch;
};

export function createControlPlaneClient(options: ClientOptions) {
  const fetcher = options.fetcher ?? fetch;
  return {
    async request<T>(
      path: string,
      init: RequestInit & { idempotencyKey?: string; ifMatch?: string } = {},
    ): Promise<{ data: T; etag: string | null }> {
      const token = await options.getAccessToken();
      const headers = new Headers(init.headers);
      headers.set("Accept", "application/json, application/problem+json");
      headers.set("Authorization", `Bearer ${token}`);
      if (init.body !== undefined) headers.set("Content-Type", "application/json");
      if (init.idempotencyKey) headers.set("Idempotency-Key", init.idempotencyKey);
      if (init.ifMatch) headers.set("If-Match", init.ifMatch);
      const response = await fetcher(`${options.baseURL}${path}`, {
        ...init,
        headers,
        cache: "no-store",
        credentials: "omit",
        redirect: "error",
      });
      if (!response.ok) throw await parseProblem(response);
      const data = response.status === 204 ? undefined : await response.json();
      return { data: data as T, etag: response.headers.get("ETag") };
    },
  };
}
~~~

Validate every Problem with Zod before showing it. Unknown/malformed error bodies become a generic `unexpected_response` with the response trace header. Never log token, request body, response body, URL query values, labels, external ID, or raw Problem detail. Query keys are factories that always include workspace/environment and normalized filters.

- [ ] **Step 7: Implement the application shell and persisted visual tokens**

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
corepack pnpm@10.34.0 --dir web test -- AppShell.test.tsx keycloak.test.ts controlPlaneClient.test.ts
corepack pnpm@10.34.0 --dir web build
~~~

Expected: PASS. Tests verify skip-link focus, active navigation semantics, scope-switch confirmation, no anonymous production fallback, generated API drift-free build, no persistence API use, and a production bundle with no source maps or embedded token/client secret.

- [ ] **Step 9: Commit**

~~~bash
git add web/package.json web/pnpm-lock.yaml web/index.html web/tsconfig.json \
  web/tsconfig.app.json web/tsconfig.node.json web/vite.config.ts web/eslint.config.js \
  web/scripts/check-generated-api.sh \
  web/src/main.tsx web/src/vite-env.d.ts web/src/app web/src/shared \
  web/src/test/setup.ts web/src/test/msw
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

“添加资产” is shown only for collection `CREATE_ASSET`. The Radix dialog states: “仅登记可运维引用；不会创建、接管或连接外部资源。” RHF+Zod accepts an ACTIVE `MANUAL` source selected from the real Source API plus kind/external ID/display name/owner/criticality/data classification/safe labels；服务端从 Source 固定派生 `provider_kind=MANUAL`，浏览器不提交该字段。If no MANUAL source exists, show a disabled explanation that Source creation becomes available only after Task 16's complete revision/profile flow; do not invent browser state or a reduced create form. It sends a fresh `crypto.randomUUID()` Idempotency-Key; never renders endpoint, credential, raw JSON, command, SQL, Header, or Body fields.

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
- Create: **docs/design/frontend/foundation-assets.md**
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
  expect(screen.getByText("新增 2")).toBeVisible();
  expect(screen.queryByRole("button", { name: /创建来源|立即同步/ })).not.toBeInTheDocument();
  expect(screen.queryByText(/raw_payload|access_token|provider_error/)).not.toBeInTheDocument();
});
~~~

Run: `corepack pnpm@10.34.0 --dir web test -- AssetSourcesPage.test.tsx`

Expected: FAIL because discovery UI does not exist.

- [ ] **Step 2: Implement source inventory and run timeline**

The list shows source type/provider/name/authority scope/sync mode/status/last success/current cursor digest and observed/new/changed/conflict/stale/rejected counts. Never show raw cursor, payload, credential, endpoint or provider error.

Pack 04 intentionally renders neither Source creation nor “立即同步”: the complete immutable revision/profile contract is not implemented until Pack 05, and the API returns no such `effective_actions` here. Task 16 extends this same page with the six-step Source+revision workspace and governed sync action; it must not revive a reduced Provider/Integration form.

For a selected existing run, poll `GET asset-source-runs/{runId}` every 2 seconds only while `QUEUED|RUNNING`, pause when the tab is hidden, resume on focus, and stop on `SUCCEEDED|PARTIAL|FAILED|CANCELLED`.

Timeline stages are 请求已接受 → 等待执行 → 读取来源 → 规范化 → 合并投影 → 完成. The server exposes stable stage/status/counts; failed runs show stable error code + Trace ID and a permitted retry action, never upstream text. Completion links conflicts to the mapping workbench while preserving workspace/environment.

Persist `docs/design/frontend/foundation-assets.md` as the unique Phase 1 shell/asset design source. It records the navigation IA, flat route map and validated URL search schema; 220px navigation, 46px Scope bar, spacing/color/type/radius/focus/motion tokens; Asset table/drawer/detail and Mapping workbench components; loading/empty/403/404/409/503/stale/quarantined/ambiguous/offline states; 1440/1024/768/390 breakpoints; mouse/keyboard behavior; WCAG 2.2 AA; Keycloak Server 26.6.3 with browser `keycloak-js` 26.2.4; API `effective_actions`; and the forbidden chat/AI avatar/gradient/glow/glass/Bento/secret/editor patterns. Later plans may link and extend it but must not create a parallel foundation file.

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
