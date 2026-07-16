import {
  QueryClient,
  QueryClientProvider,
} from "@tanstack/react-query";
import {
  createRootRoute,
  createRoute,
  createRouter,
  Outlet,
  RouterProvider,
} from "@tanstack/react-router";
import {
  act,
  cleanup,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { delay, http, HttpResponse } from "msw";
import {
  type PropsWithChildren,
  useState,
} from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  ControlPlaneRuntimeProvider,
  createControlPlaneClient,
} from "@/shared/api/controlPlaneClient";
import {
  type Scope,
  ScopeRuntimeProvider,
} from "@/shared/api/queryKeys";
import {
  assetDetailFixture,
  assetMutationResultFixture,
  assetPageFixture,
  assetSourcePageFixture,
  environmentID,
  manualSourceID,
  primaryAssetID,
  secondaryAssetDetailFixture,
  secondaryAssetID,
  workspaceID,
} from "@/test/msw/fixtures";
import { testServer } from "@/test/msw/server";

import { assetQueryKeys } from "./api";
import { AssetCatalogPage } from "./AssetCatalogPage";
import { AssetDetailPanel } from "./AssetDetailDrawer";
import { AssetDetailPage } from "./AssetDetailPage";
import {
  assetListHref,
  parseAssetSearch,
  type AssetSearch,
} from "./assetSearch";

const apiAssetPath =
  "/api/v1/workspaces/:workspaceId/environments/:environmentId/assets";
const apiAssetDetailPath = `${apiAssetPath}/:assetId`;
const traceID = "abcdefabcdefabcdefabcdefabcdefab";

function desktopMediaQuery() {
  return {
    matches: true,
    media: "(min-width: 1024px)",
    onchange: null,
    addListener: vi.fn(),
    removeListener: vi.fn(),
    addEventListener: vi.fn(),
    removeEventListener: vi.fn(),
    dispatchEvent: vi.fn(),
  };
}

function renderAssetCatalog(path: string) {
  window.history.replaceState(null, "", path);
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: { retry: false, gcTime: 0 },
      mutations: { retry: false },
    },
  });
  const client = createControlPlaneClient({
    apiBasePath: "/api/v1",
    getAccessToken: vi.fn().mockResolvedValue("ephemeral-test-token"),
  });
  const fallback = {
    workspace: workspaceID,
    environment: environmentID,
  };
  const rootRoute = createRootRoute({ component: Outlet });
  const assetsRoute = createRoute({
    getParentRoute: () => rootRoute,
    path: "/assets",
    validateSearch: (search) => parseAssetSearch(search, fallback),
    component: AssetsRoute,
  });
  const detailRoute = createRoute({
    getParentRoute: () => rootRoute,
    path: "/assets/$assetId",
    validateSearch: (search) => parseAssetSearch(search, fallback),
    component: DetailRoute,
  });

  function AssetsRoute() {
    const search = parseAssetSearch(
      assetsRoute.useSearch() as unknown,
      fallback,
    );
    const navigate = assetsRoute.useNavigate();
    return (
      <AssetCatalogPage
        search={search}
        onSearchChange={(next, options) => {
          void navigate({
            search: next,
            replace: options?.replace ?? false,
          });
        }}
        onOpenAsset={(assetId) => {
          const next: AssetSearch = { ...search };
          delete next.assetId;
          void navigate({
            to: "/assets/$assetId",
            params: { assetId },
            search: next,
          });
        }}
      />
    );
  }

  function DetailRoute() {
    const search = parseAssetSearch(
      detailRoute.useSearch() as unknown,
      fallback,
    );
    const params = detailRoute.useParams() as unknown as {
      assetId: string;
    };
    const assetId = params.assetId;
    const navigate = detailRoute.useNavigate();
    const listSearch: AssetSearch = { ...search };
    delete listSearch.assetId;
    return (
      <AssetDetailPage
        assetId={assetId}
        search={search}
        backHref={assetListHref(listSearch)}
        onBack={() => {
          void navigate({ to: "/assets", search: listSearch });
        }}
        onSearchChange={(next, options) => {
          void navigate({
            search: next,
            replace: options?.replace ?? false,
          });
        }}
      />
    );
  }

  const router = createRouter({
    routeTree: rootRoute.addChildren([assetsRoute, detailRoute]),
    search: { strict: true },
  });
  let updateScope: ((scope: Scope) => void) | undefined;

  function TestScopeProvider({ children }: PropsWithChildren) {
    const [scope, setScope] = useState<Scope>({
      workspaceId: workspaceID,
      environmentId: environmentID,
    });
    updateScope = setScope;
    return (
      <ScopeRuntimeProvider
        scope={scope}
        requestScopeChange={vi.fn()}
        registerDraftGuard={() => () => undefined}
      >
        {children}
      </ScopeRuntimeProvider>
    );
  }

  const result = render(
    <QueryClientProvider client={queryClient}>
      <ControlPlaneRuntimeProvider
        client={client}
        authActions={{
          login: vi.fn().mockResolvedValue(undefined),
          reauthenticate: vi.fn().mockResolvedValue(undefined),
          logout: vi.fn().mockResolvedValue(undefined),
        }}
      >
        <TestScopeProvider>
          <RouterProvider router={router} />
        </TestScopeProvider>
      </ControlPlaneRuntimeProvider>
    </QueryClientProvider>,
  );
  return {
    ...result,
    queryClient,
    router,
    setScope: (scope: Scope) => {
      act(() => {
        updateScope?.(scope);
      });
    },
  };
}

function problem(status: number, code: string, title: string) {
  return HttpResponse.json(
    {
      type: "about:blank",
      title,
      status,
      code,
      detail: "资产目录请求未完成，请使用 Trace ID 联系平台管理员。",
      trace_id: traceID,
    },
    {
      status,
      headers: {
        "Content-Type": "application/problem+json",
        "X-Trace-ID": traceID,
      },
    },
  );
}

beforeEach(() => {
  vi.stubGlobal("matchMedia", vi.fn().mockImplementation(desktopMediaQuery));
  vi.stubGlobal("scrollTo", vi.fn());
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("AssetCatalogPage", () => {
  it("从 URL 恢复并规范化筛选、选择和详情标签", async () => {
    const kind = encodeURIComponent(
      JSON.stringify(["WINDOWS_VM", "LINUX_VM", "LINUX_VM", "UNKNOWN"]),
    );
    const mapping = encodeURIComponent(
      JSON.stringify(["UNRESOLVED", "EXACT", "EXACT", "INVALID"]),
    );
    renderAssetCatalog(
      `/assets?workspace=${workspaceID}&environment=${environmentID}` +
        `&q=payments&kind=${kind}&mapping=${mapping}` +
        `&sort=last_observed_at_desc&cursor=cursor-2` +
        `&trail=${encodeURIComponent(JSON.stringify(["cursor-0", "cursor-1"]))}` +
        `&assetId=${primaryAssetID}&tab=relations`,
    );

    expect(
      await screen.findByRole("heading", { name: "资产目录" }),
    ).toBeVisible();
    expect(
      screen.getByRole("button", { name: "类型：Linux 虚拟机" }),
    ).toBeVisible();
    expect(
      screen.getByRole("button", { name: "类型：Windows 虚拟机" }),
    ).toBeVisible();
    expect(screen.queryByText("UNKNOWN")).not.toBeInTheDocument();
    expect(
      await screen.findByRole("dialog", { name: "payments-api-01 资产详情" }),
    ).toBeVisible();
    expect(screen.getByRole("tab", { name: "关系" })).toHaveAttribute(
      "aria-selected",
      "true",
    );

    await waitFor(() => {
      const search = new URL(window.location.href).searchParams;
      expect(JSON.parse(search.get("kind") ?? "[]")).toEqual([
        "LINUX_VM",
        "WINDOWS_VM",
      ]);
      expect(JSON.parse(search.get("mapping") ?? "[]")).toEqual([
        "EXACT",
        "UNRESOLVED",
      ]);
    });
  });

  it("保留多 Source 与治理筛选，并为每个活动筛选提供可移除 chip", async () => {
    const user = userEvent.setup();
    const secondSourceID = "abababab-abab-4bab-8bab-abababababab";
    const requestedURLs: URL[] = [];
    testServer.use(
      http.get(apiAssetPath, ({ request }) => {
        requestedURLs.push(new URL(request.url));
        return HttpResponse.json(assetPageFixture, {
          headers: { "X-Trace-ID": traceID },
        });
      }),
    );
    renderAssetCatalog(
      `/assets?workspace=${workspaceID}&environment=${environmentID}` +
        `&q=payments&service=${environmentID}` +
        `&source=${encodeURIComponent(JSON.stringify([secondSourceID, manualSourceID]))}` +
        `&criticality=${encodeURIComponent(JSON.stringify(["HIGH", "HIGH", "INVALID"]))}` +
        `&dataClassification=${encodeURIComponent(JSON.stringify(["RESTRICTED", "PUBLIC"]))}`,
    );

    expect(
      await screen.findByRole("heading", { name: "资产目录" }),
    ).toBeVisible();
    expect(screen.getByText("筛选资产").closest("summary")).not.toBeNull();
    expect(
      screen.getByRole("button", { name: "关键字：payments" }),
    ).toBeVisible();
    expect(
      screen.getByRole("button", { name: `Service：${environmentID}` }),
    ).toBeVisible();
    expect(
      screen.getByRole("button", { name: `来源：${manualSourceID}` }),
    ).toBeVisible();
    expect(
      screen.getByRole("button", { name: `来源：${secondSourceID}` }),
    ).toBeVisible();
    expect(
      screen.getByRole("button", { name: "关键度：HIGH" }),
    ).toBeVisible();
    expect(
      screen.getByRole("button", { name: "数据分类：PUBLIC" }),
    ).toBeVisible();
    expect(
      screen.getByRole("button", { name: "数据分类：RESTRICTED" }),
    ).toBeVisible();
    expect(screen.getByLabelText("Source IDs")).toHaveValue(
      `${secondSourceID},${manualSourceID}`,
    );
    await waitFor(() => {
      expect(
        requestedURLs.some(
          (url) =>
            url.searchParams.getAll("criticalities").includes("HIGH") &&
            url.searchParams
              .getAll("data_classifications")
              .some((value) =>
                value.split(",").includes("RESTRICTED"),
              ),
        ),
      ).toBe(true);
    });

    await user.click(
      screen.getByRole("button", { name: `来源：${manualSourceID}` }),
    );
    await waitFor(() => {
      const search = new URL(window.location.href).searchParams;
      expect(JSON.parse(search.get("source") ?? "[]")).toEqual([
        secondSourceID,
      ]);
    });
    expect(screen.getByLabelText("Source IDs")).toHaveValue(secondSourceID);
  });

  it("只按 effective_actions 展示治理动作，并阻止不安全资产出现调查入口", async () => {
    testServer.use(
      http.get(apiAssetDetailPath, () =>
        HttpResponse.json(
          {
            ...assetDetailFixture,
            lifecycle: "QUARANTINED",
            mapping_status: "AMBIGUOUS",
            effective_actions: ["RETIRE"],
          },
          { headers: { ETag: '"asset-7"', "X-Trace-ID": traceID } },
        ),
      ),
    );
    renderAssetCatalog(
      `/assets?workspace=${workspaceID}&environment=${environmentID}` +
        `&assetId=${primaryAssetID}`,
    );

    expect(await screen.findByText("资产已隔离")).toBeVisible();
    expect(screen.getByText(/影响.*新建调查|禁止.*调查/)).toBeVisible();
    expect(screen.getByRole("button", { name: "退役资产" })).toBeEnabled();
    expect(
      screen.queryByRole("button", { name: "编辑治理信息" }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: /调查|运行诊断/ }),
    ).not.toBeInTheDocument();
  });

  it("支持行键盘导航、桌面抽屉关闭后焦点恢复和完整详情路由", async () => {
    const user = userEvent.setup();
    renderAssetCatalog(
      `/assets?workspace=${workspaceID}&environment=${environmentID}&q=payments`,
    );
    const firstRow = await screen.findByRole("row", {
      name: /payments-api-01/,
    });
    const secondRow = screen.getByRole("row", { name: /orders-db-01/ });

    firstRow.focus();
    await user.keyboard("{ArrowDown}");
    expect(secondRow).toHaveFocus();
    await user.keyboard("{Enter}");
    expect(
      await screen.findByRole("dialog", { name: "orders-db-01 资产详情" }),
    ).toBeVisible();
    await user.keyboard("{Escape}");
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(secondRow).toHaveFocus();
    expect(window.location.search).toContain("q=payments");

    await user.dblClick(secondRow);
    await waitFor(() => {
      expect(window.location.pathname).toBe(`/assets/${secondaryAssetID}`);
    });
    expect(
      await screen.findByRole("link", { name: "返回资产列表" }),
    ).toHaveAttribute("href", expect.stringContaining("q=payments"));
  });

  it("手工登记只使用有 CREATE_ASSET 的 opaque Source，并提交闭合字段", async () => {
    const user = userEvent.setup();
    let requestedUsage: string | null = null;
    let requestedEnvironment: string | null = null;
    let submittedBody: unknown;
    let idempotencyKey: string | null = null;
    testServer.use(
      http.get(
        "/api/v1/workspaces/:workspaceId/asset-sources",
        ({ request }) => {
          const search = new URL(request.url).searchParams;
          requestedUsage = search.get("usage");
          requestedEnvironment = search.get("environment_id");
          return HttpResponse.json(assetSourcePageFixture, {
            headers: { "X-Trace-ID": traceID },
          });
        },
      ),
      http.post(apiAssetPath, async ({ request }) => {
        submittedBody = await request.json();
        idempotencyKey = request.headers.get("Idempotency-Key");
        return HttpResponse.json(
          {
            asset: assetDetailFixture,
            mutation_receipt: {
              audit_id: "12121212-1212-4121-8121-121212121212",
              trace_id: traceID,
              idempotent_replay: false,
            },
          },
          { status: 201, headers: { ETag: '"asset-7"' } },
        );
      }),
    );
    renderAssetCatalog(
      `/assets?workspace=${workspaceID}&environment=${environmentID}`,
    );

    await user.click(
      await screen.findByRole("button", { name: "添加资产" }),
    );
    expect(
      screen.getByText("仅登记可运维引用；不会创建、接管或连接外部资源。"),
    ).toBeVisible();
    await user.selectOptions(screen.getByLabelText("登记来源"), manualSourceID);
    await user.selectOptions(screen.getByLabelText("资产类型"), "LINUX_VM");
    await user.type(screen.getByLabelText("外部 ID"), "new-host-01");
    await user.type(screen.getByLabelText("显示名称"), "new-host-01");
    await user.type(screen.getByLabelText("Owner 组"), "sre-core");
    await user.selectOptions(screen.getByLabelText("关键度"), "HIGH");
    await user.selectOptions(screen.getByLabelText("数据分类"), "INTERNAL");
    await user.click(screen.getByRole("button", { name: "登记资产" }));

    await waitFor(() => {
      expect(submittedBody).toEqual({
        source_id: manualSourceID,
        kind: "LINUX_VM",
        external_id: "new-host-01",
        display_name: "new-host-01",
        owner_group: "sre-core",
        criticality: "HIGH",
        data_classification: "INTERNAL",
        labels: [],
      });
    });
    expect(requestedUsage).toBe("manual_asset_create");
    expect(requestedEnvironment).toBe(environmentID);
    expect(idempotencyKey).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i,
    );
    expect(JSON.stringify(submittedBody)).not.toMatch(
      /endpoint|credential|token|secret|command|sql|header|body/i,
    );
  });

  it("禁止敏感标签键进入手工登记请求", async () => {
    const user = userEvent.setup();
    let mutationCount = 0;
    let submittedBody: unknown;
    testServer.use(
      http.post(apiAssetPath, async ({ request }) => {
        mutationCount += 1;
        submittedBody = await request.json();
        return HttpResponse.json(assetMutationResultFixture, {
          status: 201,
        });
      }),
    );
    renderAssetCatalog(
      `/assets?workspace=${workspaceID}&environment=${environmentID}`,
    );

    await user.click(
      await screen.findByRole("button", { name: "添加资产" }),
    );
    await user.selectOptions(
      await screen.findByLabelText("登记来源"),
      manualSourceID,
    );
    await user.type(screen.getByLabelText("外部 ID"), "safe-host-01");
    await user.type(screen.getByLabelText("显示名称"), "safe-host-01");
    await user.type(
      screen.getByLabelText("安全标签（每行 key=value）"),
      "authorization_header=opaque",
    );
    await user.click(screen.getByRole("button", { name: "登记资产" }));

    expect(await screen.findByRole("alert")).toHaveTextContent(
      /禁止|敏感/,
    );
    expect(mutationCount).toBe(0);
    expect(submittedBody).toBeUndefined();
  });

  it("Source 资格刷新中或失败时清空候选并关闭登记提交", async () => {
    const user = userEvent.setup();
    let requestCount = 0;
    testServer.use(
      http.get(
        "/api/v1/workspaces/:workspaceId/asset-sources",
        async () => {
          requestCount += 1;
          if (requestCount > 1) {
            await delay(120);
            return problem(
              503,
              "source_eligibility_unavailable",
              "来源资格不可用",
            );
          }
          return HttpResponse.json(assetSourcePageFixture, {
            headers: { "X-Trace-ID": traceID },
          });
        },
      ),
    );
    renderAssetCatalog(
      `/assets?workspace=${workspaceID}&environment=${environmentID}`,
    );

    await user.click(
      await screen.findByRole("button", { name: "添加资产" }),
    );
    expect(await screen.findByLabelText("登记来源")).toBeEnabled();
    await user.click(screen.getByRole("button", { name: "取消" }));
    await user.click(screen.getByRole("button", { name: "添加资产" }));
    await waitFor(() => {
      expect(requestCount).toBe(2);
    });
    expect(screen.getByLabelText("登记来源")).toBeDisabled();
    expect(
      screen.getByRole("button", { name: "登记资产" }),
    ).toBeDisabled();
    expect(
      screen.queryByRole("option", { name: /生产手工登记源/ }),
    ).not.toBeInTheDocument();

    expect(
      await screen.findByRole("heading", { name: "来源资格不可用" }),
    ).toBeVisible();
    expect(screen.getByLabelText("登记来源")).toBeDisabled();
    expect(
      screen.queryByRole("option", { name: /生产手工登记源/ }),
    ).not.toBeInTheDocument();
  });

  it("治理 mutation 发送 fresh Idempotency-Key 与 If-Match，409 后安全重载但不重发", async () => {
    const user = userEvent.setup();
    let mutationCount = 0;
    let detailCount = 0;
    let idempotencyKey: string | null = null;
    let ifMatch: string | null = null;
    testServer.use(
      http.get(apiAssetDetailPath, () => {
        detailCount += 1;
        return HttpResponse.json(
          {
            ...assetDetailFixture,
            display_name:
              detailCount === 1 ? "payments-api-01" : "payments-api-01-server",
            version: detailCount === 1 ? 7 : 8,
          },
          {
            headers: {
              ETag: detailCount === 1 ? '"asset-7"' : '"asset-8"',
              "X-Trace-ID": traceID,
            },
          },
        );
      }),
      http.post(
        `${apiAssetDetailPath}\\:quarantine`,
        ({ request }) => {
          mutationCount += 1;
          idempotencyKey = request.headers.get("Idempotency-Key");
          ifMatch = request.headers.get("If-Match");
          return problem(409, "version_conflict", "资产版本已变化");
        },
      ),
    );
    const { queryClient } = renderAssetCatalog(
      `/assets?workspace=${workspaceID}&environment=${environmentID}` +
        `&assetId=${primaryAssetID}`,
    );

    await user.click(
      await screen.findByRole("button", { name: "隔离资产" }),
    );
    expect(screen.getByText(primaryAssetID)).toBeVisible();
    await user.type(screen.getByLabelText("原因代码"), "SECURITY_REVIEW");
    await user.click(screen.getByRole("button", { name: "确认隔离" }));

    expect(
      await screen.findByRole("heading", { name: "资源已被其他操作更新" }),
    ).toBeVisible();
    const reloadConflict = screen.getByRole("button", {
      name: "重新加载并审阅",
    });
    expect(reloadConflict).toBeVisible();
    const conflictedSubmit = screen.getByRole("button", {
      name: "确认隔离",
    });
    expect(conflictedSubmit).toBeDisabled();
    await user.click(conflictedSubmit);
    await waitFor(() => {
      expect(detailCount).toBeGreaterThanOrEqual(2);
    });
    expect(mutationCount).toBe(1);
    expect(ifMatch).toBe('"asset-7"');
    expect(idempotencyKey).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i,
    );
    await user.click(reloadConflict);
    expect(await screen.findByLabelText("原因代码")).toHaveValue("");
    expect(
      screen.getByRole("button", { name: "确认隔离" }),
    ).toBeEnabled();
    expect(
      queryClient.getQueryData(
        assetQueryKeys.detail(
          { workspaceId: workspaceID, environmentId: environmentID },
          primaryAssetID,
        ),
      ),
    ).toHaveProperty("etag", '"asset-8"');
  });

  it("治理成功响应缺少 ETag 时清除缓存 ETag 并关闭后续写入", async () => {
    const user = userEvent.setup();
    let mutationCount = 0;
    let detailCount = 0;
    testServer.use(
      http.get(apiAssetDetailPath, () => {
        detailCount += 1;
        return HttpResponse.json(
          {
            ...assetDetailFixture,
            version: detailCount === 1 ? 7 : 9,
          },
          {
            headers: {
              ETag: detailCount === 1 ? '"asset-7"' : '"asset-9"',
              "X-Trace-ID": traceID,
            },
          },
        );
      }),
      http.post(
        `${apiAssetDetailPath}\\:quarantine`,
        () => {
          mutationCount += 1;
          return HttpResponse.json(assetMutationResultFixture, {
            headers: { "X-Trace-ID": traceID },
          });
        },
      ),
    );
    const { queryClient } = renderAssetCatalog(
      `/assets?workspace=${workspaceID}&environment=${environmentID}` +
        `&assetId=${primaryAssetID}`,
    );

    await user.click(
      await screen.findByRole("button", { name: "隔离资产" }),
    );
    await user.type(
      screen.getByLabelText("原因代码"),
      "SECURITY_REVIEW",
    );
    await user.click(screen.getByRole("button", { name: "确认隔离" }));

    expect(
      await screen.findByText("治理变更已由服务端确认"),
    ).toBeVisible();
    expect(
      await screen.findByText(/响应缺少 ETag.*治理写入保持关闭/),
    ).toBeVisible();
    await waitFor(() => {
      expect(
        queryClient.getQueryData(
          assetQueryKeys.detail(
            { workspaceId: workspaceID, environmentId: environmentID },
            primaryAssetID,
          ),
        ),
      ).not.toHaveProperty("etag");
      expect(
        queryClient.getQueryData(
          assetQueryKeys.detail(
            { workspaceId: workspaceID, environmentId: environmentID },
            primaryAssetID,
          ),
        ),
      ).toHaveProperty("asset.version", 9);
    });
    const quarantineButton = screen.getByRole("button", {
      name: "隔离资产",
    });
    expect(quarantineButton).toBeDisabled();
    await user.click(quarantineButton);
    expect(mutationCount).toBe(1);
  });

  it("mutation v8 后的安全 GET v9 不被旧响应覆盖", async () => {
    const user = userEvent.setup();
    let detailCount = 0;
    testServer.use(
      http.get(apiAssetDetailPath, () => {
        detailCount += 1;
        return HttpResponse.json(
          {
            ...assetDetailFixture,
            version: detailCount === 1 ? 7 : 9,
          },
          {
            headers: {
              ETag: detailCount === 1 ? '"asset-7"' : '"asset-9"',
              "X-Trace-ID": traceID,
            },
          },
        );
      }),
      http.post(
        `${apiAssetDetailPath}\\:quarantine`,
        () =>
          HttpResponse.json(
            {
              ...assetMutationResultFixture,
              asset: {
                ...assetMutationResultFixture.asset,
                version: 8,
              },
            },
            {
              headers: {
                ETag: '"asset-8"',
                "X-Trace-ID": traceID,
              },
            },
          ),
      ),
    );
    const { queryClient } = renderAssetCatalog(
      `/assets?workspace=${workspaceID}&environment=${environmentID}` +
        `&assetId=${primaryAssetID}`,
    );

    await user.click(
      await screen.findByRole("button", { name: "隔离资产" }),
    );
    await user.type(
      screen.getByLabelText("原因代码"),
      "SECURITY_REVIEW",
    );
    await user.click(screen.getByRole("button", { name: "确认隔离" }));
    expect(
      await screen.findByText("治理变更已由服务端确认"),
    ).toBeVisible();

    await waitFor(() => {
      expect(
        queryClient.getQueryData(
          assetQueryKeys.detail(
            { workspaceId: workspaceID, environmentId: environmentID },
            primaryAssetID,
          ),
        ),
      ).toMatchObject({
        asset: { version: 9 },
        etag: '"asset-9"',
      });
    });
  });

  it("A 到 B 的抽屉切换隔离治理本地结果与关闭态", async () => {
    const user = userEvent.setup();
    let mutationCount = 0;
    let releasePendingMutation: (() => void) | undefined;
    testServer.use(
      http.post(
        `${apiAssetDetailPath}\\:quarantine`,
        async () => {
          mutationCount += 1;
          if (mutationCount > 1) {
            await new Promise<void>((resolve) => {
              releasePendingMutation = resolve;
            });
          }
          return (
          HttpResponse.json(assetMutationResultFixture, {
              headers:
                mutationCount === 1
                  ? { "X-Trace-ID": traceID }
                  : {
                      ETag: '"asset-8"',
                      "X-Trace-ID": traceID,
                    },
            })
          );
        },
      ),
    );
    const queryClient = new QueryClient({
      defaultOptions: {
        queries: {
          retry: false,
          gcTime: Infinity,
          staleTime: Infinity,
        },
        mutations: { retry: false },
      },
    });
    const client = createControlPlaneClient({
      apiBasePath: "/api/v1",
      getAccessToken: vi.fn().mockResolvedValue("ephemeral-test-token"),
    });
    const scope = {
      workspaceId: workspaceID,
      environmentId: environmentID,
    };
    queryClient.setQueryData(
      assetQueryKeys.detail(scope, primaryAssetID),
      {
        asset: assetDetailFixture,
        etag: '"asset-7"',
        traceId: traceID,
      },
    );
    queryClient.setQueryData(
      assetQueryKeys.detail(scope, secondaryAssetID),
      {
        asset: secondaryAssetDetailFixture,
        etag: '"asset-3"',
        traceId: traceID,
      },
    );
    function DetailHarness({ assetId }: { assetId: string }) {
      return (
        <QueryClientProvider client={queryClient}>
          <ControlPlaneRuntimeProvider
            client={client}
            authActions={{
              login: vi.fn().mockResolvedValue(undefined),
              reauthenticate: vi.fn().mockResolvedValue(undefined),
              logout: vi.fn().mockResolvedValue(undefined),
            }}
          >
            <ScopeRuntimeProvider
              scope={scope}
              requestScopeChange={vi.fn()}
              registerDraftGuard={() => () => undefined}
            >
              <AssetDetailPanel
                scope={scope}
                assetId={assetId}
                tab="overview"
                onTabChange={vi.fn()}
              />
            </ScopeRuntimeProvider>
          </ControlPlaneRuntimeProvider>
        </QueryClientProvider>
      );
    }
    const rendered = render(<DetailHarness assetId={primaryAssetID} />);

    await user.click(
      await screen.findByRole("button", { name: "隔离资产" }),
    );
    await user.type(
      screen.getByLabelText("原因代码"),
      "SECURITY_REVIEW",
    );
    await user.click(screen.getByRole("button", { name: "确认隔离" }));
    expect(
      await screen.findByText("治理变更已由服务端确认"),
    ).toBeVisible();
    expect(
      screen.getByText(/响应缺少 ETag.*治理写入保持关闭/),
    ).toBeVisible();

    rendered.rerender(<DetailHarness assetId={secondaryAssetID} />);
    expect(
      await screen.findByRole("heading", { name: "orders-db-01" }),
    ).toBeVisible();
    expect(
      screen.queryByText("治理变更已由服务端确认"),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByText(/响应缺少 ETag.*治理写入保持关闭/),
    ).not.toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "隔离资产" }),
    ).toBeEnabled();

    queryClient.setQueryData(
      assetQueryKeys.detail(scope, primaryAssetID),
      {
        asset: assetDetailFixture,
        etag: '"asset-7"',
        traceId: traceID,
      },
    );
    rendered.rerender(<DetailHarness assetId={primaryAssetID} />);
    await user.click(
      await screen.findByRole("button", { name: "隔离资产" }),
    );
    await user.type(
      screen.getByLabelText("原因代码"),
      "SECURITY_REVIEW",
    );
    const setQueryData = vi.spyOn(queryClient, "setQueryData");
    await user.click(screen.getByRole("button", { name: "确认隔离" }));
    await waitFor(() => {
      expect(releasePendingMutation).toBeTypeOf("function");
    });

    rendered.rerender(<DetailHarness assetId={secondaryAssetID} />);
    expect(
      await screen.findByRole("heading", { name: "orders-db-01" }),
    ).toBeVisible();
    await act(async () => {
      releasePendingMutation?.();
      await new Promise<void>((resolve) => {
        setTimeout(resolve, 0);
      });
    });
    await waitFor(() => {
      expect(queryClient.isMutating()).toBe(0);
    });
    const oldDetailKey = assetQueryKeys.detail(
      scope,
      primaryAssetID,
    );
    expect(
      setQueryData.mock.calls.some(
        ([queryKey]) =>
          JSON.stringify(queryKey) === JSON.stringify(oldDetailKey),
      ),
    ).toBe(false);
    expect(
      screen.queryByText("治理变更已由服务端确认"),
    ).not.toBeInTheDocument();
  });

  it("窄屏只显示治理桌面关闭态且不暴露 mutation 入口", async () => {
    let mutationCount = 0;
    vi.stubGlobal(
      "matchMedia",
      vi.fn().mockImplementation((query: string) => ({
        ...desktopMediaQuery(),
        matches: false,
        media: query,
      })),
    );
    testServer.use(
      http.post(`${apiAssetDetailPath}\\:quarantine`, () => {
        mutationCount += 1;
        return HttpResponse.json(assetMutationResultFixture);
      }),
    );
    renderAssetCatalog(
      `/assets/${primaryAssetID}?workspace=${workspaceID}` +
        `&environment=${environmentID}`,
    );

    expect(
      await screen.findByText(/请在桌面完成治理操作/),
    ).toBeVisible();
    expect(
      screen.queryByRole("button", { name: "编辑治理信息" }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "隔离资产" }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "退役资产" }),
    ).not.toBeInTheDocument();
    expect(mutationCount).toBe(0);
  });

  it("pending mutation 在 Scope 失效后不重建旧缓存或泄漏结果", async () => {
    const user = userEvent.setup();
    let releaseMutation: (() => void) | undefined;
    testServer.use(
      http.post(
        `${apiAssetDetailPath}\\:quarantine`,
        async () => {
          await new Promise<void>((resolve) => {
            releaseMutation = resolve;
          });
          return HttpResponse.json(assetMutationResultFixture, {
            headers: {
              ETag: '"asset-8"',
              "X-Trace-ID": traceID,
            },
          });
        },
      ),
    );
    const rendered = renderAssetCatalog(
      `/assets?workspace=${workspaceID}&environment=${environmentID}` +
        `&assetId=${primaryAssetID}`,
    );
    const oldDetailKey = assetQueryKeys.detail(
      { workspaceId: workspaceID, environmentId: environmentID },
      primaryAssetID,
    );

    const quarantineButton = await screen.findByRole("button", {
      name: "隔离资产",
    });
    const setQueryData = vi.spyOn(
      rendered.queryClient,
      "setQueryData",
    );
    await user.click(quarantineButton);
    await user.type(
      screen.getByLabelText("原因代码"),
      "SECURITY_REVIEW",
    );
    await user.click(screen.getByRole("button", { name: "确认隔离" }));
    await waitFor(() => {
      expect(releaseMutation).toBeTypeOf("function");
    });

    rendered.queryClient.removeQueries({
      predicate: (query) =>
        query.queryKey[1] === workspaceID &&
        query.queryKey[2] === environmentID,
    });
    expect(
      rendered.queryClient.getQueryCache().findAll({
        predicate: (query) =>
          query.queryKey[1] === workspaceID &&
          query.queryKey[2] === environmentID,
      }),
    ).toHaveLength(0);
    await act(async () => {
      releaseMutation?.();
      await new Promise<void>((resolve) => {
        setTimeout(resolve, 0);
      });
    });
    await waitFor(() => {
      expect(rendered.queryClient.isMutating()).toBe(0);
    });
    rendered.setScope({
      workspaceId: "56565656-5656-4565-8565-565656565656",
      environmentId: "78787878-7878-4787-8787-787878787878",
    });

    expect(
      rendered.queryClient.getQueryCache().findAll({
        predicate: (query) =>
          query.queryKey[1] === workspaceID &&
          query.queryKey[2] === environmentID,
      }),
    ).toHaveLength(0);
    expect(
      setQueryData.mock.calls.some(
        ([queryKey]) =>
          JSON.stringify(queryKey) === JSON.stringify(oldDetailKey),
      ),
    ).toBe(false);
    expect(
      screen.queryByText("治理变更已由服务端确认"),
    ).not.toBeInTheDocument();
  });

  it("缺 ETag 的异步尾部不重新创建已清理的旧 Scope 缓存", async () => {
    const user = userEvent.setup();
    let releaseInvalidation: (() => void) | undefined;
    testServer.use(
      http.post(
        `${apiAssetDetailPath}\\:quarantine`,
        () =>
          HttpResponse.json(assetMutationResultFixture, {
            headers: { "X-Trace-ID": traceID },
          }),
      ),
    );
    const rendered = renderAssetCatalog(
      `/assets?workspace=${workspaceID}&environment=${environmentID}` +
        `&assetId=${primaryAssetID}`,
    );
    const oldDetailKey = assetQueryKeys.detail(
      { workspaceId: workspaceID, environmentId: environmentID },
      primaryAssetID,
    );

    const quarantineButton = await screen.findByRole("button", {
      name: "隔离资产",
    });
    vi.spyOn(
      rendered.queryClient,
      "invalidateQueries",
    ).mockImplementation(
      () =>
        new Promise<void>((resolve) => {
          releaseInvalidation = () => {
            rendered.queryClient.removeQueries({
              queryKey: oldDetailKey,
              exact: true,
            });
            resolve();
          };
        }),
    );
    await user.click(quarantineButton);
    await user.type(
      screen.getByLabelText("原因代码"),
      "SECURITY_REVIEW",
    );
    await user.click(screen.getByRole("button", { name: "确认隔离" }));
    await waitFor(() => {
      expect(releaseInvalidation).toBeTypeOf("function");
    });

    rendered.setScope({
      workspaceId: "56565656-5656-4565-8565-565656565656",
      environmentId: "78787878-7878-4787-8787-787878787878",
    });
    await act(async () => {
      releaseInvalidation?.();
      await Promise.resolve();
      await Promise.resolve();
    });
    expect(
      rendered.queryClient.getQueryData(oldDetailKey),
    ).toBeUndefined();
  });

  it("409 重载后按服务端最新 effective_actions 保持撤销动作关闭", async () => {
    const user = userEvent.setup();
    let detailCount = 0;
    let mutationCount = 0;
    testServer.use(
      http.get(apiAssetDetailPath, () => {
        detailCount += 1;
        return HttpResponse.json(
          {
            ...assetDetailFixture,
            effective_actions:
              detailCount === 1
                ? assetDetailFixture.effective_actions
                : ["RETIRE"],
            version: detailCount === 1 ? 7 : 8,
          },
          {
            headers: {
              ETag: detailCount === 1 ? '"asset-7"' : '"asset-8"',
              "X-Trace-ID": traceID,
            },
          },
        );
      }),
      http.post(`${apiAssetDetailPath}\\:quarantine`, () => {
        mutationCount += 1;
        return problem(409, "version_conflict", "资产版本已变化");
      }),
    );
    renderAssetCatalog(
      `/assets?workspace=${workspaceID}&environment=${environmentID}` +
        `&assetId=${primaryAssetID}`,
    );

    await user.click(
      await screen.findByRole("button", { name: "隔离资产" }),
    );
    await user.type(
      screen.getByLabelText("原因代码"),
      "SECURITY_REVIEW",
    );
    await user.click(screen.getByRole("button", { name: "确认隔离" }));
    const reloadConflict = await screen.findByRole("button", {
      name: "重新加载并审阅",
    });
    await user.click(reloadConflict);

    expect(
      await screen.findByRole("button", { name: "确认隔离" }),
    ).toBeDisabled();
    expect(mutationCount).toBe(1);
  });

  it("详情 path 是唯一资产 ID，规范化移除重复 query assetId", async () => {
    renderAssetCatalog(
      `/assets/${primaryAssetID}?workspace=${workspaceID}` +
        `&environment=${environmentID}&assetId=${secondaryAssetID}`,
    );

    expect(
      await screen.findByRole("heading", { name: "资产详情" }),
    ).toBeVisible();
    expect(await screen.findByText("payments-api-01")).toBeVisible();
    await waitFor(() => {
      expect(
        new URL(window.location.href).searchParams.has("assetId"),
      ).toBe(false);
    });
    expect(window.location.pathname).toBe(`/assets/${primaryAssetID}`);
  });

  it("Scope 变化后清除上一作用域的资产登记结果", async () => {
    const user = userEvent.setup();
    const rendered = renderAssetCatalog(
      `/assets?workspace=${workspaceID}&environment=${environmentID}`,
    );

    await user.click(
      await screen.findByRole("button", { name: "添加资产" }),
    );
    await user.selectOptions(
      await screen.findByLabelText("登记来源"),
      manualSourceID,
    );
    await user.type(screen.getByLabelText("外部 ID"), "scope-host-01");
    await user.type(screen.getByLabelText("显示名称"), "scope-host-01");
    await user.click(screen.getByRole("button", { name: "登记资产" }));
    expect(
      await screen.findByText("资产登记已由服务端确认"),
    ).toBeVisible();

    rendered.setScope({
      workspaceId: "56565656-5656-4565-8565-565656565656",
      environmentId: "78787878-7878-4787-8787-787878787878",
    });
    await waitFor(() => {
      expect(
        screen.queryByText("资产登记已由服务端确认"),
      ).not.toBeInTheDocument();
    });
    rendered.setScope({
      workspaceId: workspaceID,
      environmentId: environmentID,
    });
    await waitFor(() => {
      expect(
        screen.queryByText("资产登记已由服务端确认"),
      ).not.toBeInTheDocument();
    });
  });

  it("保留空态筛选上下文，并在 Problem 状态展示 Trace ID", async () => {
    testServer.use(
      http.get(apiAssetPath, () =>
        HttpResponse.json(
          { ...assetPageFixture, items: [], page: { next_cursor: null } },
          { headers: { "X-Trace-ID": traceID } },
        ),
      ),
    );
    const firstRender = renderAssetCatalog(
      `/assets?workspace=${workspaceID}&environment=${environmentID}&q=missing`,
    );
    expect(await screen.findByText("当前筛选没有资产")).toBeVisible();
    expect(screen.getByDisplayValue("missing")).toBeVisible();
    firstRender.queryClient.clear();
    cleanup();

    testServer.use(
      http.get(apiAssetPath, () =>
        problem(503, "asset_catalog_unavailable", "资产目录暂时不可用"),
      ),
    );
    renderAssetCatalog(
      `/assets?workspace=${workspaceID}&environment=${environmentID}&q=missing`,
    );
    expect(
      await screen.findByRole("heading", { name: "资产目录暂时不可用" }),
    ).toBeVisible();
    expect(screen.getByText("Trace ID")).toBeVisible();
    expect(screen.getByText(traceID)).toBeVisible();
    expect(screen.getByDisplayValue("missing")).toBeVisible();
  });
});
