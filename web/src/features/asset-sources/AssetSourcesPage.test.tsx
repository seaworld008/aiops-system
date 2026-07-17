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
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import { http, HttpResponse } from "msw";
import type { PropsWithChildren } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  ControlPlaneRuntimeProvider,
  createControlPlaneClient,
} from "@/shared/api/controlPlaneClient";
import { ScopeRuntimeProvider } from "@/shared/api/queryKeys";
import {
  assetSourceDetailFixture,
  assetSourcePageFixture,
  currentRunCountsFixture,
  discoverySourceID,
  environmentID,
  lastSuccessRunCountsFixture,
  manualSourceID,
  sourceRunFixture,
  sourceRunID,
  workspaceID,
} from "@/test/msw/fixtures";
import { testServer } from "@/test/msw/server";

import { AssetSourcesPage } from "./AssetSourcesPage";
import { parseSourceSearch } from "./sourceSearch";

const apiRunPath =
  "/api/v1/workspaces/:workspaceId/asset-source-runs/:runId";

function renderSources(path: string) {
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
  const fallback = { workspace: workspaceID };
  const rootRoute = createRootRoute({ component: Outlet });
  const sourcesRoute = createRoute({
    getParentRoute: () => rootRoute,
    path: "/asset-sources",
    validateSearch: (search) => parseSourceSearch(search, fallback),
    component: SourcesRoute,
  });

  function SourcesRoute() {
    const search = parseSourceSearch(
      sourcesRoute.useSearch() as unknown,
      fallback,
    );
    const navigate = sourcesRoute.useNavigate();
    return (
      <AssetSourcesPage
        search={search}
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
    routeTree: rootRoute.addChildren([sourcesRoute]),
    search: { strict: true },
  });

  function TestScopeProvider({ children }: PropsWithChildren) {
    return (
      <ScopeRuntimeProvider
        scope={{
          workspaceId: workspaceID,
          environmentId: environmentID,
        }}
        requestScopeChange={vi.fn()}
        registerDraftGuard={() => () => undefined}
      >
        {children}
      </ScopeRuntimeProvider>
    );
  }

  return render(
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
}

beforeEach(() => {
  vi.stubGlobal("scrollTo", vi.fn());
  Object.defineProperty(document, "visibilityState", {
    configurable: true,
    value: "visible",
  });
  Object.defineProperty(navigator, "onLine", {
    configurable: true,
    value: true,
  });
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

describe("AssetSourcesPage", () => {
  it("从 URL 恢复并规范化来源筛选、来源选择和运行选择", () => {
    expect(
      parseSourceSearch(
        {
          workspace: workspaceID,
          status: JSON.stringify([
            "ACTIVE",
            "ACTIVE",
            "UNKNOWN",
          ]),
          kind: JSON.stringify([
            "MANUAL",
            "MANUAL",
            "UNSUPPORTED",
          ]),
          cursor: "cursor-2",
          sourceId: discoverySourceID,
          runId: sourceRunID,
        },
        { workspace: "workspace-fallback" },
      ),
    ).toEqual({
      workspace: workspaceID,
      status: ["ACTIVE"],
      kind: ["MANUAL"],
      cursor: "cursor-2",
      sourceId: discoverySourceID,
      runId: sourceRunID,
    });
  });

  it("恢复终态运行，分开显示最近成功与当前运行计数且不暴露 payload", async () => {
    testServer.use(
      http.get(
        "/api/v1/workspaces/:workspaceId/asset-sources",
        () =>
          HttpResponse.json({
            ...assetSourcePageFixture,
            raw_payload: "raw_payload_secret",
            access_token: "access_token_secret",
            endpoint: "https://provider.invalid/private",
          }),
      ),
      http.get(
        "/api/v1/workspaces/:workspaceId/asset-sources/:sourceId",
        () =>
          HttpResponse.json({
            ...assetSourceDetailFixture,
            credential: "credential_secret",
          }),
      ),
      http.get(apiRunPath, () =>
        HttpResponse.json({
          ...sourceRunFixture,
          provider_error: "provider_error_secret",
        }),
      ),
    );

    renderSources(
      `/asset-sources?workspace=${workspaceID}` +
        `&sourceId=${discoverySourceID}&runId=${sourceRunID}`,
    );

    expect(
      await screen.findByRole("heading", { name: "发现来源" }),
    ).toBeVisible();
    expect(await screen.findByText("发现完成")).toBeVisible();
    const sourceDetail = screen
      .getByRole("heading", { name: "生产 CMDB 目录" })
      .closest("section");
    expect(sourceDetail).not.toBeNull();
    expect(
      within(sourceDetail as HTMLElement).getByText("计划调度"),
    ).toBeVisible();
    expect(
      within(sourceDetail as HTMLElement).getByText(environmentID),
    ).toBeVisible();
    const last = screen.getByRole("region", {
      name: "最近成功运行计数",
    });
    const current = screen.getByRole("region", {
      name: "当前非终态运行计数",
    });
    expect(
      within(within(last).getByText("已创建").parentElement as HTMLElement)
        .getByText(String(lastSuccessRunCountsFixture.created)),
    ).toBeVisible();
    expect(
      within(within(current).getByText("已创建").parentElement as HTMLElement)
        .getByText(String(currentRunCountsFixture.created)),
    ).toBeVisible();
    expect(
      screen.queryByRole("button", { name: /创建来源|立即同步/ }),
    ).not.toBeInTheDocument();
    expect(document.body).not.toHaveTextContent(
      /raw_payload_secret|access_token_secret|credential_secret|provider_error_secret|provider\.invalid/,
    );
    expect(document.body).not.toHaveTextContent(
      /19191919-1919-4191-8191-191919191919|20202020-2020-4202-8202-202020202020|21212121-2121-4212-8212-212121212121/,
    );
    const conflictLink = screen.getByRole("link", {
      name: /在映射工作台查看/,
    });
    expect(conflictLink).toHaveAttribute(
      "href",
      expect.stringContaining(`workspace=${workspaceID}`),
    );
    expect(conflictLink).toHaveAttribute(
      "href",
      expect.stringContaining(`environment=${environmentID}`),
    );
    await waitFor(() => {
      expect(
        new URL(window.location.href).searchParams.get("operationId"),
      ).toBeNull();
      expect(
        new URL(window.location.href).searchParams.get("runId"),
      ).toBe(sourceRunID);
    });
  });

  it("显式保留 PARTIAL，并且失败只显示稳定错误代码和 Trace ID", async () => {
    testServer.use(
      http.get(apiRunPath, () =>
        HttpResponse.json({
          ...sourceRunFixture,
          status: "PARTIAL",
          work_result_status: "PARTIAL",
        }),
      ),
    );
    const first = renderSources(
      `/asset-sources?workspace=${workspaceID}` +
        `&sourceId=${discoverySourceID}&runId=${sourceRunID}`,
    );
    expect(await screen.findByText("部分完成（PARTIAL）")).toBeVisible();
    expect(
      screen.getByText("发现部分完成；最近成功计数保持独立。"),
    ).toBeVisible();
    first.unmount();

    testServer.use(
      http.get(apiRunPath, () =>
        HttpResponse.json({
          ...sourceRunFixture,
          status: "FAILED",
          stage: "CLEANING_UP",
          failure_code: "source_cleanup_uncertain",
          trace_id: "abcdefabcdefabcdefabcdefabcdefab",
          provider_error: "upstream password rejected",
        }),
      ),
    );
    renderSources(
      `/asset-sources?workspace=${workspaceID}` +
        `&sourceId=${discoverySourceID}&runId=${sourceRunID}`,
    );
    expect(
      await screen.findByText("source_cleanup_uncertain"),
    ).toBeVisible();
    expect(
      screen.getByText("abcdefabcdefabcdefabcdefabcdefab"),
    ).toBeVisible();
    expect(document.body).not.toHaveTextContent(
      "upstream password rejected",
    );
  });

  it("没有选中 runId 时不读取任何 Source Run", async () => {
    let requests = 0;
    testServer.use(
      http.get(apiRunPath, () => {
        requests += 1;
        return HttpResponse.json(sourceRunFixture);
      }),
    );
    renderSources(
      `/asset-sources?workspace=${workspaceID}` +
        `&sourceId=${discoverySourceID}`,
    );
    expect(
      await screen.findByRole("heading", { name: "生产 CMDB 目录" }),
    ).toBeVisible();
    expect(requests).toBe(0);
    expect(
      screen.queryByRole("heading", { name: "Source Run 时间线" }),
    ).not.toBeInTheDocument();
  });

  it("来源与所选非终态 Run 不匹配时首次读取后停止轮询", async () => {
    vi.useFakeTimers();
    let requests = 0;
    testServer.use(
      http.get(apiRunPath, () => {
        requests += 1;
        return HttpResponse.json({
          ...sourceRunFixture,
          status: "RUNNING",
          stage: "READING",
          completed_at: null,
        });
      }),
    );
    renderSources(
      `/asset-sources?workspace=${workspaceID}` +
        `&sourceId=${manualSourceID}&runId=${sourceRunID}`,
    );
    await vi.waitFor(() => expect(requests).toBe(1));
    await vi.waitFor(() => {
      expect(
        screen.getByRole("heading", {
          name: "所选运行不属于当前来源",
        }),
      ).toBeVisible();
    });
    await act(async () => {
      await vi.advanceTimersByTimeAsync(10_000);
    });
    expect(requests).toBe(1);
  });

  it("仅轮询所选非终态运行，hidden/offline 暂停，focus 恢复且终态停止", async () => {
    vi.useFakeTimers();
    let requests = 0;
    testServer.use(
      http.get(apiRunPath, () => {
        requests += 1;
        return HttpResponse.json(
          requests < 3
            ? {
                ...sourceRunFixture,
                status: "RUNNING",
                stage: "READING",
                completed_at: null,
              }
            : sourceRunFixture,
        );
      }),
    );
    renderSources(
      `/asset-sources?workspace=${workspaceID}` +
        `&sourceId=${discoverySourceID}&runId=${sourceRunID}`,
    );
    await vi.waitFor(() => expect(requests).toBe(1));

    act(() => {
      Object.defineProperty(document, "visibilityState", {
        configurable: true,
        value: "hidden",
      });
      document.dispatchEvent(new Event("visibilitychange"));
    });
    await act(async () => {
      await vi.advanceTimersByTimeAsync(10_000);
    });
    expect(requests).toBe(1);

    act(() => {
      Object.defineProperty(document, "visibilityState", {
        configurable: true,
        value: "visible",
      });
      document.dispatchEvent(new Event("visibilitychange"));
      window.dispatchEvent(new Event("focus"));
    });
    await vi.waitFor(() => expect(requests).toBe(2));

    act(() => {
      Object.defineProperty(navigator, "onLine", {
        configurable: true,
        value: false,
      });
      window.dispatchEvent(new Event("offline"));
    });
    await act(async () => {
      await vi.advanceTimersByTimeAsync(10_000);
    });
    expect(requests).toBe(2);

    act(() => {
      Object.defineProperty(navigator, "onLine", {
        configurable: true,
        value: true,
      });
      window.dispatchEvent(new Event("online"));
    });
    await vi.waitFor(() => expect(requests).toBe(3));
    await vi.waitFor(() => {
      expect(screen.getByText("发现完成")).toBeVisible();
    });

    await act(async () => {
      await vi.advanceTimersByTimeAsync(10_000);
    });
    expect(requests).toBe(3);
  });
});
