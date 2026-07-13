# Asset Catalog Production Verification, Operations, and Documentation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 用真实 OIDC、真实 PostgreSQL、浏览器 E2E、视觉/无障碍/安全测试、指标、备份恢复、HA 演练和持久化文档完成资产阶段的生产验收。

**Architecture:** 单元/组件测试使用 fake/MSW；full-stack Playwright 使用真实 PostgreSQL 18.4、真实 Control Plane 和真实 Keycloak OIDC 流，不拦截业务 API。独立 projection 项目才拦截安全 DTO，以获得确定的视觉/异常投影。CI 串行验证 OpenAPI 生成漂移、Go/数据库、前端、浏览器和构建产物；运维 Runbook 覆盖扩展迁移、滚动发布、指标告警、恢复与应用回滚。

**Tech Stack:** Go 1.26.5、PostgreSQL 18.4、Prometheus client_golang 1.23.2、Node 24、pnpm 10.34.0、Keycloak Server 26.6.3 test realm、keycloak-js 26.2.4、Playwright 1.61.1、axe 4.12.1、GitHub Actions。

## Global Constraints

- 前置任务：依次完成 [01-schema-domain.md](./01-schema-domain.md)、[02-repository-discovery.md](./02-repository-discovery.md)、[03-mapping-auth-api.md](./03-mapping-auth-api.md)、[04-web-foundation-assets.md](./04-web-foundation-assets.md)、[05-source-ingestion-csv-api.md](./05-source-ingestion-csv-api.md)、[06-source-external-cmdb.md](./06-source-external-cmdb.md)、[07-source-vsphere.md](./07-source-vsphere.md)、[08-source-proxmox-openstack-cloud.md](./08-source-proxmox-openstack-cloud.md)、[09-discovery-worker-ha-e2e.md](./09-discovery-worker-ha-e2e.md) 与 [10-overview-control-room.md](./10-overview-control-room.md)。
- fake、MSW、测试 Keycloak 用户和业务 fixture 只允许出现在 `_test.go`、`web/src/test`、`web/e2e`、`deploy/test`；production bundle/镜像不得包含。
- 浏览器生产入口仍使用真实 OIDC login-required + PKCE；E2E 也必须经过真实 Keycloak 授权码流，不能把 Token 写入 storage/cookie 模拟认证。
- Keycloak 自身 OIDC 会话 Cookie 不等于应用 Token 持久化；测试不得保存 Playwright `storageState`，每个上下文重新认证。
- 集成/E2E 使用合成低敏数据；禁止复制生产备份、Secret、Token、DSN、endpoint、原始 Provider Payload 或错误正文到仓库/快照/日志。
- 指标、日志、Trace 和截图不得使用租户/Subject/资产/外部 ID 作为标签或文件名。
- CI/生产实现必须多副本安全，不依赖单进程锁、本地队列、本地草稿或测试适配器。
- 迁移采取 expand-only；应用可回滚但含数据的 000015 不 down。备份恢复后再开放资产写 API。
- E2E 验证的是完整生产资产治理入口，不是 demo happy path；必须覆盖拒绝、并发、漂移、故障、恢复和权限。
- 当前阶段本身不开放目标系统生产写；项目最终路线明确进入独立审批、策略、短凭据、隔离 Runner 和 Evidence 证明保护的受治理写闭环。
- 每个任务按 Red → Green → Refactor；任务末尾提交步骤只包含本任务文件。

---

### Task 32: Low-cardinality metrics and HA-safe operational signals

**Files:**
- Modify: **go.mod**
- Modify: **go.sum**
- Create: **internal/assetcatalog/metrics.go**
- Create: **internal/assetcatalog/metrics_test.go**
- Create: **internal/assetcatalog/postgres/instrumented.go**
- Create: **internal/assetcatalog/postgres/instrumented_test.go**
- Create: **cmd/control-plane/metrics.go**
- Create: **cmd/control-plane/metrics_test.go**
- Modify: **cmd/control-plane/main.go**
- Modify: **internal/config/config.go**
- Modify: **internal/config/config_test.go**

**Interfaces:**
- Adds `github.com/prometheus/client_golang v1.23.2`.
- Produces a dedicated internal metrics listener configured by `AIOPS_METRICS_LISTEN_ADDR`; it never shares public asset auth routes.
- Repository decorators preserve existing interfaces and do not alter transaction semantics.

- [ ] **Step 1: Write failing metric-name/cardinality/failure tests**

~~~go
func TestAssetMetricsExposeOnlyBoundedLabels(t *testing.T) {
	registry := prometheus.NewRegistry()
	metrics := mustAssetMetrics(registry)
	metrics.ObserveRepository("list_assets", "success", 25*time.Millisecond)
	metrics.ObserveConflictDecision("confirm_exact", "version_conflict")
	metrics.SetOpenConflictOldest("high", 90*time.Second)

	output := gatherText(t, registry)
	for _, name := range []string{
		"aiops_asset_repository_duration_seconds",
		"aiops_asset_repository_total",
		"aiops_asset_conflict_decisions_total",
		"aiops_asset_conflict_oldest_seconds",
	} {
		if !strings.Contains(output, name) {
			t.Errorf("missing %s", name)
		}
	}
	for _, forbidden := range []string{
		"tenant_id", "workspace_id", "environment_id", "asset_id",
		"source_id", "subject", "external_id", "trace_id",
	} {
		if strings.Contains(output, forbidden) {
			t.Errorf("metric output contains high-cardinality label %s", forbidden)
		}
	}
}
~~~

Run: `go test ./internal/assetcatalog ./internal/assetcatalog/postgres ./cmd/control-plane -run TestAssetMetrics -count=1`

Expected: FAIL because metrics types/listener do not exist.

- [ ] **Step 2: Implement explicit allow-listed collectors**

Collectors and label sets are fixed:

~~~text
aiops_asset_http_requests_total{route,method,status_class}
aiops_asset_http_duration_seconds{route,method}
aiops_asset_repository_total{operation,result}
aiops_asset_repository_duration_seconds{operation}
aiops_asset_version_conflicts_total{resource_type}
aiops_asset_idempotency_conflicts_total{operation}
aiops_asset_source_runs_total{source_kind,result}
aiops_asset_source_run_duration_seconds{source_kind}
aiops_asset_conflicts_open{risk}
aiops_asset_conflict_oldest_seconds{risk}
aiops_asset_outbox_pending{event_family}
~~~

`route` is a compile-time template enum, never raw URL. `status_class` is `2xx|4xx|5xx`; result/risk/source kind/operation are validated switches. Histograms use fixed buckets suitable for DB/API latency; no exemplar carries identity.

~~~go
type Metrics interface {
	ObserveRepository(operation, result string, elapsed time.Duration)
	ObserveSourceRun(sourceKind, result string, elapsed time.Duration)
	ObserveConflictDecision(decision, result string)
	ObserveHTTP(route, method, statusClass string, elapsed time.Duration)
}
~~~

Instrument outside transactions so metrics failure cannot roll back data. Repository decorators must preserve context cancellation and error identity. Gauge collection queries aggregate counts/oldest timestamp with statement timeout; scrape failure yields no stale identity-bearing detail.

- [ ] **Step 3: Serve metrics on a separate fail-closed listener**

`AIOPS_METRICS_LISTEN_ADDR` accepts only loopback/private bind addresses and is required by the production config profile. Serve only `GET /metrics` and `/healthz` with server timeouts, max headers, graceful shutdown, no pprof, no CORS, and no request logging. Production network policy must restrict it to the monitoring plane.

Run: `go test -race ./internal/assetcatalog ./internal/assetcatalog/postgres ./internal/config ./cmd/control-plane -count=1`

Expected: PASS; invalid/public binds fail startup; listener shutdown follows Control Plane context; duplicate registry construction is rejected cleanly.

- [ ] **Step 4: Commit**

~~~bash
git add go.mod go.sum internal/assetcatalog/metrics.go internal/assetcatalog/metrics_test.go \
  internal/assetcatalog/postgres/instrumented.go internal/assetcatalog/postgres/instrumented_test.go \
  cmd/control-plane/metrics.go cmd/control-plane/metrics_test.go cmd/control-plane/main.go \
  internal/config/config.go internal/config/config_test.go
git commit -m "feat(assetcatalog): add production telemetry"
~~~

### Task 33: Real-OIDC Playwright, visual regression, accessibility, and security E2E

**Files:**
- Create: **web/playwright.config.ts**
- Create: **web/e2e/support/fixtures.ts**
- Create: **web/e2e/support/oidc.ts**
- Create: **web/e2e/support/apiRoutes.ts**
- Create: **web/e2e/support/accessibility.ts**
- Create: **web/e2e/assets.spec.ts**
- Create: **web/e2e/mappings.spec.ts**
- Create: **web/e2e/sources.spec.ts**
- Create: **web/e2e/security.spec.ts**
- Create: **web/e2e/visual.spec.ts**
- Create: **web/e2e/visual.spec.ts-snapshots/** (Playwright-generated)
- Create: **deploy/test/keycloak/realm-export.json**
- Create: **deploy/test/keycloak/compose.yaml**
- Create: **deploy/test/keycloak/bootstrap-users.sh**
- Create: **deploy/test/postgres/asset-fixtures.sql**
- Create: **web/scripts/check-production-bundle.mjs**
- Modify: **web/package.json**

**Interfaces:**
- Both E2E projects use production `web/src/main.tsx`, Keycloak Server 26.6.3 and browser `keycloak-js` 26.2.4. `full-stack` reaches the real Control Plane/PostgreSQL and forbids business request interception; `projection` may intercept `/api/v1` only for deterministic visual/error states.
- `realm-export.json` defines a public PKCE client with exact localhost redirect origins and synthetic VIEWER/SRE/SERVICE_OWNER/ADMIN users; `bootstrap-users.sh` reads passwords from CI environment with `set +x`, so credentials are not stored in JSON/logs.
- No E2E-only authentication branch exists in production code.

- [ ] **Step 1: Write the failing end-to-end acceptance matrix**

~~~ts
test("admin governs an asset and a viewer remains read-only", async ({ browser }) => {
  const admin = await loginWithOIDC(browser, "admin");
  await admin.goto("/assets?workspace=33333333-3333-4333-8333-333333333333" +
    "&environment=44444444-4444-4444-8444-444444444444");
  await admin.getByRole("row", { name: /payments-api-01/ }).press("Enter");
  await admin.getByRole("button", { name: "编辑治理信息" }).click();
  await admin.getByLabel("关键度").selectOption("CRITICAL");
  await admin.getByRole("button", { name: "保存治理信息" }).click();
  await expect(admin.getByText("治理信息已更新")).toBeVisible();

  const viewer = await loginWithOIDC(browser, "viewer");
  await viewer.goto(admin.url());
  await expect(viewer.getByText("CRITICAL")).toBeVisible();
  await expect(viewer.getByRole("button", { name: "编辑治理信息" })).toHaveCount(0);
});
~~~

Run: `corepack pnpm@10.34.0 --dir web test:e2e`

Expected: FAIL because Playwright/Keycloak fixtures and specs do not exist.

- [ ] **Step 2: Configure deterministic real OIDC and browser fixtures**

Start the pinned test Keycloak container with imported realm, wait on OIDC discovery health, and launch Vite with:

~~~text
VITE_OIDC_URL=http://127.0.0.1:18080
VITE_OIDC_REALM=aiops-e2e
VITE_OIDC_CLIENT_ID=control-plane-web-e2e
VITE_API_BASE_URL=
~~~

`loginWithOIDC` creates a fresh browser context, navigates through the real login page, fills credentials from process environment, verifies return to the app and deletes the context at test end. Do not use `storageState`, URL Token, app cookie, storage or fake Keycloak object. OIDC IdP cookies may exist only inside that fresh context.

Playwright defines two projects:

~~~text
full-stack: real Keycloak -> production web -> real Control Plane -> PostgreSQL 18.4
projection: real Keycloak -> production web -> typed Playwright API routes
~~~

`deploy/test/postgres/asset-fixtures.sql` applies constraint-valid synthetic scopes/sources/assets/conflicts. The full-stack project verifies DB/audit/outbox changes after UI mutations and fails if `/api/v1` interception is registered.

Only projection `apiRoutes.ts` fulfills typed fixture responses and validates each request:

- exactly one Bearer Authorization header exists;
- token never appears in URL/body/log;
- credentials are not sent as app cookies;
- write routes include Idempotency-Key and expected If-Match;
- request body has only OpenAPI fields.

- [ ] **Step 3: Cover production workflows and negative paths**

Full-stack Asset E2E: filters/back-forward/share URL; row keyboard/drawer/full route; manual create/idempotent replay; edit; quarantine; viewer/admin actions; then SQL-assert exactly one domain mutation, audit and outbox result.

Full-stack Mapping E2E resolves a seeded conflict and SQL-asserts conflict/asset/binding versions atomically. Full-stack Source E2E creates a signed `CSV_IMPORT` source revision, validates/publishes it and enqueues one real Source Run against quarantine storage without target-network access；另断言 `MANUAL` source 永远不能进入 Discovery Worker queue。

Projection Asset E2E covers retire impact, forced 409 diff, stale/quarantined no investigation, malformed/slow/unavailable projections and SRE action visibility.

Mapping E2E: conflict queue; safe provenance; all four decisions; reason/impact; ETag conflict; identical-key batch partial failure; never implicit EXACT.

Source E2E: create opaque Integration reference; 202 sync; URL run resume; queued/running/success/failure; focus-aware polling; conflict deep link; no provider payload/error.

Negative E2E: 401 re-login; non-enumerating 403/404; malformed Problem; 503 persistent state; offline retry; slow response cancellation on Scope switch; duplicate click produces one Idempotency-Key mutation.

- [ ] **Step 4: Add visual and WCAG 2.2 AA gates**

For assets/mapping/sources capture deterministic light-theme snapshots at `1440x1000`、`1024x768`、`390x844`. Freeze clock and mask only server-generated UUID/time values, not layout/status/actions. Commit Linux Chromium snapshots.

Run axe on shell, table, drawer/dialog, forms, conflict comparison, timeline, empty/error/409 states; fail on critical/serious violations. Keyboard-only specs verify skip link, nav, filters, rows, tabs, dialogs, focus trap/restore and Escape. CSS test verifies `prefers-reduced-motion` removes non-essential animation and focus ring remains 2px visible.

- [ ] **Step 5: Scan the production bundle**

`check-production-bundle.mjs` fails if `dist/` contains E2E credentials/realm fixture, MSW worker, source map, `localStorage`/`sessionStorage`/`indexedDB`, hard-coded Bearer, client secret, forbidden field labels, or non-hashed JS/CSS names. It also checks `index.html` has no inline script and documents required deployment CSP: `default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self' <OIDC-origin>; frame-ancestors 'none'; base-uri 'none'; form-action <OIDC-origin>`.

Run:

~~~bash
corepack pnpm@10.34.0 --dir web build
node web/scripts/check-production-bundle.mjs
corepack pnpm@10.34.0 --dir web test:e2e
~~~

Expected: PASS for Chromium workflow, snapshots, axe, keyboard, security and bundle scan.

- [ ] **Step 6: Commit**

~~~bash
git add web/playwright.config.ts web/e2e web/scripts/check-production-bundle.mjs \
  deploy/test/keycloak deploy/test/postgres/asset-fixtures.sql web/package.json
git commit -m "test(web): verify asset operations end to end"
~~~

### Task 34: CI, rollout, backup/restore, HA, and migration compatibility gates

**Files:**
- Modify: **Makefile**
- Modify: **.github/workflows/ci.yml**
- Create: **scripts/verify-asset-backup-restore.sh**
- Create: **scripts/verify-asset-ha.sh**
- Create: **scripts/verify-control-plane-openapi.sh**
- Create: **docs/operations/asset-catalog-rollout.md**
- Create: **docs/operations/asset-catalog-backup-restore.md**
- Create: **docs/operations/asset-catalog-observability.md**

**Interfaces:**
- Produces required commands: `pnpm --dir web generate:api`、`typecheck`、`lint`、`test`、`build`、`test:e2e`、`check`.
- `web check` serially runs generated API drift, typecheck, lint, unit tests and build.
- Scripts accept DSNs/credentials only through environment; `set -x` is forbidden and logs are sanitized.

- [ ] **Step 1: Write failing CI/Makefile shape tests**

~~~bash
rg -n 'web-check|web-e2e|verify-asset-backup|verify-asset-ha' Makefile
rg -n 'node-version: 24|pnpm.*10.34.0|postgres:18|test:e2e|generate:api:check' .github/workflows/ci.yml
~~~

Expected: each command misses at least one required gate.

- [ ] **Step 2: Add deterministic CI stages**

Order:

1. secret/dependency/license scan;
2. Go format/vet/unit/race/architecture;
3. PostgreSQL 18 migration/integration/recovery;
4. OpenAPI parse/closed schema/router conformance;
5. Node 24 + pnpm 10 frozen install;
6. `pnpm --dir web check`;
7. Playwright browser install from lock + real Keycloak E2E;
8. bundle/SBOM/artifact checks.

Cache only Go modules/build and pnpm store keyed by lockfile; never cache browser storage, Token, DB volume or test credentials. Upload reports/screenshots only on failure after forbidden-string scan; retention is bounded.

- [ ] **Step 3: Exercise rolling and failure behavior**

`verify-asset-ha.sh` starts two Control Plane replicas against PostgreSQL, sends concurrent idempotent create/update/sync/decision requests through a round-robin proxy, kills one replica mid-request, and asserts exactly one domain mutation/audit/outbox result. It then interrupts a source run, verifies DB lease/advisory lock recovery, and confirms no process-local state is required.

Compatibility matrix:

~~~text
old app + schema 000015: legacy endpoints remain healthy; asset routes absent/fail closed
new app + schema 000014: health available; asset routes 503 migration_required
new app + schema 000015: assets enabled
mixed old/new replicas + schema 000015: legacy and new reads safe; writes route only to ready new replicas
app rollback + populated 000015: schema retained; no down
~~~

- [ ] **Step 4: Automate backup and restore verification**

Create sanitized fixture rows in all nine tables, audits and outbox; take `pg_dump --format=custom` plus WAL/checkpoint metadata; restore into clean PostgreSQL 18; run migrations/checks; compare counts, scoped FK closure, immutable Source Revision/published pointer/checkpoint/fence state, content hashes, versions, conflict/binding state, append-only triggers and pending outbox. The script prints only aggregate counts/checksums and exits nonzero on drift.

Run:

~~~bash
make test
make test-integration
make web-check
make web-e2e
scripts/verify-asset-backup-restore.sh
scripts/verify-asset-ha.sh
~~~

Expected: all PASS in the external isolated worktree. Do not claim the current main workspace `go test ./...` is green while `.worktrees/*` remains inside it; CI checkout and external worktree must be clean.

- [ ] **Step 5: Commit**

~~~bash
git add Makefile .github/workflows/ci.yml scripts/verify-asset-backup-restore.sh \
  scripts/verify-asset-ha.sh scripts/verify-control-plane-openapi.sh \
  docs/operations/asset-catalog-rollout.md docs/operations/asset-catalog-backup-restore.md \
  docs/operations/asset-catalog-observability.md
git commit -m "ci(assetcatalog): gate production asset rollout"
~~~

### Task 35: Persist architecture, frontend design, status, and next-phase handoff

**Files:**
- Modify: **docs/status/current.md**
- Create: **docs/architecture/implementation-blueprint-v4.md**
- Create: **docs/adr/0001-operational-asset-catalog-overlay.md**
- Verify: **docs/design/frontend/foundation-assets.md**
- Verify: **docs/design/frontend/asset-sources.md**
- Verify: **docs/design/frontend/overview.md**
- Modify: **docs/roadmap.md**
- Modify: **docs/README.md**
- Modify: **AGENTS.md**

**Interfaces:**
- These documents become future-session facts; they link this package, confirmed spec, schema, OpenAPI and downstream Connection/Grant plans.
- Status distinguishes planned/implemented/verified/deployed; planning completion must never be marked as implementation completion.

- [ ] **Step 1: Write failing documentation contract test**

Run:

~~~bash
for file in \
  docs/status/current.md \
  docs/architecture/implementation-blueprint-v4.md \
  docs/adr/0001-operational-asset-catalog-overlay.md \
  docs/design/frontend/foundation-assets.md \
  docs/design/frontend/asset-sources.md \
  docs/design/frontend/overview.md \
  AGENTS.md; do test -s "$file"; done
~~~

Expected: FAIL because at least one persistent fact file is missing.

- [ ] **Step 2: Persist exact system and rollout facts**

`current.md`: date/commit/environment; completed vs planned; migrations 000001–000022 ownership; current known `.worktrees` test caveat; active risks; next executable package.

`implementation-blueprint-v4.md`: four planes; source/governance field ownership; nine-table Asset/Source Revision/Run/Observation/conflict/relation/binding model; CSV/API/CMDB/vSphere/Proxmox/OpenStack/AWS/Azure/GCP provider registry; discovery-worker lease/fence/checkpoint/backpressure; lifecycle and per-provider gates; source reconciliation sequence; API/auth/ETag/idempotency; Overview truthful readiness; Connection→Runtime→Snapshot→Grant downstream; HA/backup/metrics; explicit eventual governed production-write chain.

`ADR 0001`: context; decision for hybrid catalog/overlay; append-only observations; explicit cross-source merge; composite scope; alternatives rejected (replace CMDB, opaque JSON runtime, name merge, browser target access); consequences; migration/rollback.

`frontend design`: link the three unique, already-created sources `foundation-assets.md`, `asset-sources.md`, and `overview.md`; verify IA, route/URL schema, exact tokens/dimensions, table/drawer/workbench/six-step Source wizard/Overview readiness/source timeline, every loading/empty/partial/stale/forbidden/not-started/unavailable/degraded/suspended/cleanup-uncertain state, keyboard/focus, 1440/1024/768/390 breakpoints, WCAG 2.2 AA, Keycloak Server 26.6.3 + keycloak-js 26.2.4, `effective_actions`, DTO boundaries, visual/axe policy and forbidden chat/AI/terminal/secret/editor patterns. Do not create a fourth parallel frontend design source.

`AGENTS.md` begins with the user-wide Chinese-response instruction, then requires reading current status/blueprint/spec/package README before changes; locks migrations, `web/`, versions, generated API path, shared HTTP helpers, domain Reader signature, security prohibitions, external worktree rule and test commands.

Roadmap must say:

~~~text
Asset Catalog -> Connection Publication -> VictoriaMetrics Family ->
Short-lived Investigation Grant -> Host/PostgreSQL Diagnostics ->
Governed Production Write (independent policy, approval, credential, runner, proof)
~~~

The final node is a real target, not a pilot; no earlier node may bypass its controls.

- [ ] **Step 3: Link-check, scan, and run final verification**

Run:

~~~bash
rg -n 'T[O]DO|T[B]D|place[h]older|fill i[n]|demo onl[y]|pilot onl[y]' \
  docs/status/current.md docs/architecture/implementation-blueprint-v4.md \
  docs/adr/0001-operational-asset-catalog-overlay.md \
  docs/design/frontend/foundation-assets.md docs/design/frontend/asset-sources.md \
  docs/design/frontend/overview.md AGENTS.md
for file in foundation-assets asset-sources overview; do \
  test "$(rg -l "$file" docs/README.md docs/roadmap.md | wc -l | tr -d ' ')" -ge 1; \
done
corepack pnpm@10.34.0 --dir web check
go test -race ./internal/assetcatalog ./internal/assetcatalog/postgres ./internal/httpapi ./api/openapi
git diff --check
git status --short
~~~

Expected: forbidden-incomplete-marker scan returns no matches; both docs indexes link correctly; focused frontend/Go suites PASS; `git diff --check` PASS; status shows only this implementation's intended files.

- [ ] **Step 4: Commit**

~~~bash
git add docs/status/current.md docs/architecture/implementation-blueprint-v4.md \
  docs/adr/0001-operational-asset-catalog-overlay.md \
  docs/design/frontend/foundation-assets.md docs/design/frontend/asset-sources.md \
  docs/design/frontend/overview.md \
  docs/roadmap.md docs/README.md AGENTS.md
git commit -m "docs(assetcatalog): persist production asset blueprint"
~~~
