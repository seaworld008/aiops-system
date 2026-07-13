# Governed Operations Overview Control Room Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 闭合 `/overview` 产品入口，以 Scope-safe 聚合 API 和低 AI 感高保真控制台分别展示资产、来源、连接、调查、Action 和 Release 的真实完成/可用/新鲜度，未实现能力绝不伪绿。

**Architecture:** Control Plane 用一个只读 aggregation service 查询当前 Tenant/Workspace/Environment 的安全计数、门禁、证据时间和功能就绪度；每个维度独立返回 `NOT_STARTED|UNAVAILABLE|PARTIAL|AVAILABLE|DEGRADED|SUSPENDED`，不把下游表不存在当作零错误或成功。React 页使用高密度状态带、工作队列和新鲜度表，只消费 API `effective_actions`。

**Tech Stack:** Go 1.26.5、PostgreSQL 18.4、OpenAPI 3.1、React 19.2.7、TypeScript 7.0.2、TanStack Query/Router、CSS Modules、Keycloak Server 26.6.3、keycloak-js 26.2.4、Playwright 1.61.1、axe 4.12.1。

## Global Constraints

- 前置完成 [09-discovery-worker-ha-e2e.md](./09-discovery-worker-ha-e2e.md)。
- 每个 Task 严格执行 `Red → Green → Refactor`：先运行并保留预期失败，再做最小生产实现，随后消除重复、复跑指定验证并按 Task 提交；不得跳过失败或弱化断言。
- API 必须从 OIDC Principal + Workspace/Environment DB 关系派生 Tenant；不接受 `tenant_id`，不泄漏其他 Scope 是否存在。
- 资产生命周期、来源 Revision/Gate、连接发布/健康、调查/Grant、Action Gate/Verification、Release Gate 永远是独立维度。
- 当 migration/module 尚未实现时返回 `NOT_STARTED`；已实现但未发布时返回 `UNAVAILABLE`；不得用 `0` 计数、绿色图标或假 fixture 隐藏差异。
- 某聚合依赖超时只使该分区 `PARTIAL/STALE`，页面保留其他可验证数据；不得将上次绿色状态无时间标记地继续显示。
- 页面不使用大卡、营销式 KPI、聊天框、AI 头像、渐变、霓虹、光晕、玻璃或 Bento；遵循 220px 导航、46px Scope bar、38–40px 行、4–6px 圆角。
- URL 始终保存 `workspace` 和 `environment`；切换 Scope 废弃旧 query cache 并从服务器重新获取权限。
- 完成后进入 [11-e2e-docs.md](./11-e2e-docs.md) 的 Phase 1 总验收。

---

### Task 30: Scope-safe overview aggregation API and fail-closed readiness projection

**Files:**
- Create: `internal/overview/types.go`
- Create: `internal/overview/service.go`
- Create: `internal/overview/service_test.go`
- Create: `internal/overview/postgres/repository.go`
- Create: `internal/overview/postgres/repository_test.go`
- Create: `internal/overview/postgres/repository_integration_test.go`
- Modify: `api/openapi/control-plane-v1.yaml`
- Modify: `api/openapi/control_plane_v1_test.go`
- Create: `internal/httpapi/overview.go`
- Create: `internal/httpapi/overview_test.go`
- Modify: `internal/httpapi/router.go`
- Modify: `web/src/shared/api/schema.d.ts` (generated only)

**Interfaces:**
- Produces `GET /api/v1/workspaces/{workspace_id}/environments/{environment_id}/overview`.
- Produces `OverviewSnapshot{Scope,GeneratedAt,Sections,WorkQueues,EffectiveActions}` with closed section keys `ASSETS|SOURCES|CONNECTIONS|INVESTIGATIONS|ACTIONS|RELEASES`.
- Consumes schema/module readiness registry; a missing later-phase relation is `NOT_STARTED`, not a database error fallback.

- [ ] **Step 1: Write failing Scope, not-started, partial, and safe-projection tests**

~~~go
func TestOverviewDoesNotTurnUnimplementedPhasesGreen(t *testing.T) {
	service := newOverviewService(assetAndSourceFactsOnly())
	snapshot, err := service.Get(context.Background(), requestFor(scopeA()))
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Sections["ASSETS"].State != StateAvailable || snapshot.Sections["SOURCES"].State != StateAvailable {
		t.Fatalf("implemented sections = %#v", snapshot.Sections)
	}
	for _, key := range []string{"CONNECTIONS", "INVESTIGATIONS", "ACTIONS", "RELEASES"} {
		if snapshot.Sections[key].State != StateNotStarted {
			t.Errorf("%s state = %s", key, snapshot.Sections[key].State)
		}
	}
}

func TestOverviewCrossScopeIsIndistinguishableFromNotFound(t *testing.T) {
	response := performOverview(t, principalFor(scopeA()), scopeB())
	if response.Code != http.StatusNotFound || strings.Contains(response.Body.String(), scopeB().TenantID) {
		t.Fatalf("unsafe response = %d %s", response.Code, response.Body.String())
	}
}
~~~

Run: `go test ./internal/overview/... ./internal/httpapi ./api/openapi -run Overview -count=1`

Expected: FAIL because overview domain/API do not exist.

- [ ] **Step 2: Implement bounded aggregate queries and explicit readiness**

Asset query returns lifecycle/mapping counts, stale oldest time and open conflict count. Source query returns stable identity/revision/gate/run/backpressure counts and the provider matrix. Queries use the exact composite Scope, statement timeout 500ms, no raw external ID and no row list.

Later sections are driven by a closed readiness registry:

~~~go
type FeatureReadiness interface {
	State(context.Context, assetcatalog.Scope, Feature) (ImplementationState, error)
}

const (
	StateNotStarted  ImplementationState = "NOT_STARTED"
	StateUnavailable ImplementationState = "UNAVAILABLE"
	StatePartial     ImplementationState = "PARTIAL"
	StateAvailable   ImplementationState = "AVAILABLE"
	StateDegraded    ImplementationState = "DEGRADED"
	StateSuspended   ImplementationState = "SUSPENDED"
)
~~~

Phase 1 registry knows Assets/Sources only. Connections/Investigations/Actions/Releases return `NOT_STARTED` until their owning migrations and production assembly register a provider in later plans. A timeout gives only that section `PARTIAL` with safe code and `observed_at`; stale thresholds are 2m for source/asset counts and provider-specific for gate evidence. All counts are nonnegative bounded integers.

- [ ] **Step 3: Implement authorization, caching boundary, and contract generation**

Require `ASSET_READ` for the overview and include only navigation actions backed by permissions: `VIEW_ASSETS`, `VIEW_SOURCES`, later `VIEW_CONNECTIONS|INVESTIGATIONS|ACTIONS|RELEASES` when both permission and implementation state permit. Return `Cache-Control: no-store`, ETag of the safe aggregate digest and `generated_at`. Do not return source endpoint, credential/checkpoint/lease material, raw audit/provider data or tenant ID.

Run:

~~~bash
gofmt -w internal/overview internal/httpapi
go test -race ./internal/overview/... ./internal/httpapi ./api/openapi -count=1
corepack pnpm@10.34.0 --dir web generate:api
corepack pnpm@10.34.0 --dir web generate:api:check
~~~

Expected: PASS for Scope, permission, timeout/partial, stale, `NOT_STARTED`, safe DTO and generated contract.

- [ ] **Step 4: Commit**

~~~bash
git add internal/overview api/openapi/control-plane-v1.yaml \
  api/openapi/control_plane_v1_test.go internal/httpapi/overview.go \
  internal/httpapi/overview_test.go internal/httpapi/router.go web/src/shared/api/schema.d.ts
git commit -m "feat(overview): expose governed operations readiness"
~~~

### Task 31: High-fidelity overview UI, responsive states, accessibility, and real OIDC E2E

**Files:**
- Create: `web/src/features/overview/api.ts`
- Create: `web/src/features/overview/OverviewPage.tsx`
- Create: `web/src/features/overview/OverviewPage.module.css`
- Create: `web/src/features/overview/ReadinessStrip.tsx`
- Create: `web/src/features/overview/WorkQueueTable.tsx`
- Create: `web/src/features/overview/FreshnessTable.tsx`
- Create: `web/src/features/overview/OverviewPage.test.tsx`
- Modify: `web/src/app/router.tsx`
- Modify: `web/src/app/navigation.ts`
- Modify: `web/src/test/msw/handlers.ts`
- Modify: `web/src/test/msw/fixtures.ts`
- Create: `web/e2e/overview.spec.ts`
- Create: `web/e2e/overview-visual.spec.ts`
- Create: `docs/design/frontend/overview.md`

**Interfaces:**
- Produces `/overview?workspace&environment`; no parallel dashboard route or role-derived permissions.
- Consumes generated `OverviewSnapshot`; later phases extend the API section providers without replacing this page.
- Preserves one selected work-queue filter in URL; no security state is optimistic.

- [ ] **Step 1: Write failing truthful-state and accessibility tests**

~~~tsx
it("shows later production dimensions as not started instead of green zeroes", async () => {
  renderOverview("/overview?workspace=w&environment=e", phaseOneOverview());
  expect(await screen.findByRole("heading", { name: "运行总览" })).toBeVisible();
  for (const label of ["连接发布", "主动调查", "受治理动作", "生产发布"]) {
    expect(screen.getByRole("row", { name: new RegExp(`${label}.*NOT_STARTED`) })).toBeVisible();
  }
  expect(screen.queryByText(/AI 助手|智能建议|一切正常/)).not.toBeInTheDocument();
});

it("keeps partial and stale sections visible with recovery detail", async () => {
  renderOverview("/overview?workspace=w&environment=e", partialOverview());
  expect(await screen.findByText("部分数据不可用")).toBeVisible();
  expect(screen.getByText(/Trace ID/)).toBeVisible();
  expect(screen.getByText(/数据时间/)).toBeVisible();
});
~~~

Run: `corepack pnpm@10.34.0 --dir web test -- OverviewPage.test.tsx`

Expected: FAIL because overview UI does not exist.

- [ ] **Step 2: Implement the operations-dense layout and all states**

Page structure:

1. 48px title row: breadcrumb, “运行总览”, absolute `generated_at`, one “刷新” secondary action.
2. 40px `ReadinessStrip`: six equal semantic cells with text+icon+evidence time; horizontal local scroll only below 768px.
3. Main 7/5 grid at ≥1440px: left “需要处理” 38px-row table (open conflicts, stale assets, unavailable/degraded sources); right “新鲜度与门禁” table.
4. Below: compact provider-gate table and latest Source Runs; only server-authorized text links navigate to asset/source pages.

Use white surfaces, 1px `#D7DDE3` borders, navy nav and restrained blue actions. Do not nest cards. Loading skeleton preserves rows/columns; empty means “当前 Scope 无待处理项” and never “系统健康”. `PARTIAL`, stale, forbidden, unavailable and not-started each have distinct copy/icon/structure. A 403 replaces all data with a scoped forbidden panel; 404 does not reveal object existence.

Persist `docs/design/frontend/overview.md` as the unique durable Overview design source: navigation IA and `/overview?workspace&environment&queue` URL schema; exact title/readiness/work-queue/freshness/provider/run component hierarchy; all six readiness dimensions and loading/empty/partial/stale/forbidden/not-started/unavailable/degraded/suspended states; 1440/1024/768/390 layout rules; shared tokens and prohibited visual patterns; keyboard/focus/live-region/WCAG behavior; real Keycloak/OIDC Scope switching; `effective_actions` navigation; evidence-time/copy semantics; and the rule that absent later-phase implementation can never render a green zero.

- [ ] **Step 3: Implement responsive and interaction behavior**

At 1024–1439px use one-column queue/freshness sections and keep readiness/status columns. At 768–1023px use priority columns and independent detail rows. At 390px, show section label/state/time first, preserve 44px actions, no page-wide horizontal scroll, and never hide degraded/suspended states behind hover. Keyboard order follows page; focus is 2px visible; status never relies only on color; live refresh uses polite announcements and respects reduced motion.

- [ ] **Step 4: Run real Keycloak, responsive visual, axe, URL, and failure E2E**

Full-stack project uses Keycloak Server 26.6.3 + keycloak-js 26.2.4, real Control Plane/PostgreSQL and no business API interception. Projection project may inject deterministic safe DTOs for partial/stale/forbidden visual states only. Cover 1440px, 1024px and 390px; refresh/back/share restores Scope; changing Scope invalidates old query data before rendering new facts.

Run:

~~~bash
corepack pnpm@10.34.0 --dir web check
corepack pnpm@10.34.0 --dir web test:e2e -- --grep "overview"
node web/scripts/check-production-bundle.mjs
~~~

Expected: unit, visual, responsive, axe, keyboard, real OIDC/Scope, partial/stale/forbidden/not-started and production-bundle tests PASS; no chat/AI decoration or false-green state exists.

- [ ] **Step 5: Commit**

~~~bash
git add web/src/features/overview web/src/app/router.tsx web/src/app/navigation.ts \
  web/src/test/msw/handlers.ts web/src/test/msw/fixtures.ts \
  web/e2e/overview.spec.ts web/e2e/overview-visual.spec.ts \
  docs/design/frontend/overview.md
git commit -m "feat(web): add truthful operations overview"
~~~
