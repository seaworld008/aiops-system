import { readFileSync } from "node:fs";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import {
  act,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import {
  type PropsWithChildren,
  type ReactNode,
  useState,
} from "react";
import { describe, expect, it, vi } from "vitest";

import type { AccessTokenProvider } from "@/app/auth/keycloak";
import type { BrowserConfig } from "@/shared/api/browserConfig";
import {
  type ControlPlaneAuthActions,
  type ControlPlaneClient,
  useAuthActions,
  useControlPlaneClient,
} from "@/shared/api/controlPlaneClient";
import {
  queryKeys,
  useDraftGuard,
} from "@/shared/api/queryKeys";
import type { components } from "@/shared/api/schema";

import { AppShell } from "./AppShell";
import {
  AppProviders,
  bootstrapApplication,
  type BootstrapDependencies,
} from "./providers";
import { ScopeProvider } from "./scope/ScopeProvider";

type Session = components["schemas"]["Session"];
type AuthActions = ControlPlaneAuthActions;

const workspaceOne = "33333333-3333-4333-8333-333333333333";
const workspaceTwo = "44444444-4444-4444-8444-444444444444";
const environmentOne = "55555555-5555-4555-8555-555555555555";
const environmentTwo = "66666666-6666-4666-8666-666666666666";

const session: Session = {
  subject: "operator-1",
  username: "张三",
  roles: ["ADMIN"],
  workspace_ids: [workspaceOne, workspaceTwo],
  environment_ids: [environmentOne, environmentTwo],
  service_ids: [],
  authenticated_at: "2026-07-17T00:00:00Z",
  expires_at: "2026-07-17T01:00:00Z",
};

function renderShell(options?: {
  dirty?: boolean;
  onDiscardDraft?: () => void;
  queryClient?: QueryClient;
  session?: Session;
  discardClearsDirty?: boolean;
}) {
  const activeSession = options?.session ?? session;
  const queryClient =
    options?.queryClient ??
    new QueryClient({
      defaultOptions: { queries: { retry: false } },
    });
  const Providers = ({ children }: PropsWithChildren) => {
    const [dirty, setDirty] = useState(options?.dirty ?? false);
    return (
      <QueryClientProvider client={queryClient}>
        <ScopeProvider
          session={activeSession}
          isDirty={dirty}
          onDiscardDraft={() => {
            options?.onDiscardDraft?.();
            if (options?.discardClearsDirty !== false) {
              setDirty(false);
            }
          }}
        >
          {children}
        </ScopeProvider>
      </QueryClientProvider>
    );
  };
  return {
    queryClient,
    ...render(
      <AppShell session={activeSession}>
        <h1>应用基础已加载</h1>
      </AppShell>,
      { wrapper: Providers },
    ),
  };
}

function RuntimeContextProbe() {
  const client = useControlPlaneClient();
  const authActions = useAuthActions();
  return (
    <>
      <output data-testid="auth-action-keys">
        {Object.keys(authActions).sort().join(",")}
      </output>
      <button
        type="button"
        onClick={() => {
          void client.execute("getSession", { parameters: {} });
        }}
      >
        调用受类型约束客户端
      </button>
      <button
        type="button"
        onClick={() => {
          void authActions.login();
        }}
      >
        登录
      </button>
      <button
        type="button"
        onClick={() => {
          void authActions.reauthenticate(window.location.href);
        }}
      >
        重新认证
      </button>
      <button
        type="button"
        onClick={() => {
          void authActions.logout();
        }}
      >
        退出
      </button>
    </>
  );
}

function RegisteredDirtyDraft({
  onDiscard,
}: {
  onDiscard: () => void;
}) {
  const [dirty, setDirty] = useState(true);
  useDraftGuard({
    isDirty: () => dirty,
    discard: () => {
      onDiscard();
      setDirty(false);
    },
  });
  return <p>功能草稿已注册</p>;
}

function RegisteredUndiscardableDraft({
  onDiscard,
}: {
  onDiscard: () => void;
}) {
  useDraftGuard({
    isDirty: () => true,
    discard: onDiscard,
  });
  return <p>治理操作正在提交</p>;
}

function RegisteredThrowingDraft({
  failure,
  onDiscard,
}: {
  failure: "isDirty" | "discard";
  onDiscard: () => void;
}) {
  useDraftGuard({
    isDirty: () => {
      if (failure === "isDirty") {
        throw new Error("guard inspection failed");
      }
      return true;
    },
    discard: () => {
      onDiscard();
      throw new Error("guard discard failed");
    },
  });
  return <p>草稿保护回调异常</p>;
}

function renderFormalApplication(
  children: ReactNode,
  options?: {
    queryClient?: QueryClient;
    client?: ControlPlaneClient;
    authActions?: AuthActions;
  },
) {
  const queryClient =
    options?.queryClient ??
    new QueryClient({
      defaultOptions: { queries: { retry: false } },
    });
  const client =
    options?.client ??
    {
      execute: vi.fn().mockResolvedValue({ data: session, status: 200 }),
    };
  const authActions =
    options?.authActions ??
    ({
      login: vi.fn().mockResolvedValue(undefined),
      reauthenticate: vi.fn().mockResolvedValue(undefined),
      logout: vi.fn().mockResolvedValue(undefined),
    } satisfies AuthActions);
  return {
    queryClient,
    client,
    authActions,
    ...render(
      <AppProviders
        queryClient={queryClient}
        session={session}
        client={client}
        authActions={authActions}
      >
        {children}
      </AppProviders>,
    ),
  };
}

async function navigateBack(): Promise<void> {
  await act(async () => {
    await new Promise<void>((resolve) => {
      window.addEventListener("popstate", () => resolve(), { once: true });
      window.history.back();
    });
  });
}

describe("AppShell", () => {
  it("bootstraps Browser Config, OIDC and getSession before rendering", async () => {
    const order: string[] = [];
    const browserConfig: BrowserConfig = {
      oidc: {
        url: "https://identity.example.com",
        realm: "aiops",
        clientId: "control-plane-web",
      },
      apiBasePath: "/api/v1",
      build: {
        version: "test",
        commit: "test",
        contract_digest: `sha256:${"0".repeat(64)}`,
      },
    };
    const tokenProvider: AccessTokenProvider = {
      getAccessToken: vi.fn().mockResolvedValue("token"),
      login: vi.fn().mockResolvedValue(undefined),
      reauthenticate: vi.fn().mockResolvedValue(undefined),
      logout: vi.fn().mockResolvedValue(undefined),
    };
    const client = {
      execute: vi.fn().mockImplementation((operation: string) => {
        order.push(operation);
        return Promise.resolve({ data: session, status: 200 });
      }),
    } as unknown as ReturnType<BootstrapDependencies["createClient"]>;
    const renderApplication = vi.fn().mockImplementation(() => {
      order.push("render");
    });

    await bootstrapApplication({
      loadBrowserConfig: vi.fn().mockImplementation(() => {
        order.push("browser-config");
        return Promise.resolve(browserConfig);
      }),
      initializeOIDC: vi.fn().mockImplementation(() => {
        order.push("oidc");
        return Promise.resolve(tokenProvider);
      }),
      createClient: vi.fn().mockReturnValue(client),
      render: renderApplication,
    });

    expect(order).toEqual(["browser-config", "oidc", "getSession", "render"]);
    expect(renderApplication).toHaveBeenCalledWith(
      expect.objectContaining({ session, tokenProvider, client }),
    );
  });

  it.each(["browser-config", "oidc", "session"] as const)(
    "never renders an anonymous application when %s initialization fails",
    async (failingStage) => {
      const failure = new Error("closed initialization failure");
      const renderApplication = vi.fn();
      const tokenProvider: AccessTokenProvider = {
        getAccessToken: vi.fn().mockResolvedValue("token"),
        login: vi.fn().mockResolvedValue(undefined),
        reauthenticate: vi.fn().mockResolvedValue(undefined),
        logout: vi.fn().mockResolvedValue(undefined),
      };
      const browserConfig: BrowserConfig = {
        oidc: {
          url: "https://identity.example.com",
          realm: "aiops",
          clientId: "control-plane-web",
        },
        apiBasePath: "/api/v1",
        build: {
          version: "test",
          commit: "test",
          contract_digest: `sha256:${"0".repeat(64)}`,
        },
      };
      const client = {
        execute: vi.fn().mockImplementation(() =>
          failingStage === "session"
            ? Promise.reject(failure)
            : Promise.resolve({ data: session, status: 200 }),
        ),
      } as unknown as ReturnType<BootstrapDependencies["createClient"]>;

      await expect(
        bootstrapApplication({
          loadBrowserConfig: vi.fn().mockImplementation(() =>
            failingStage === "browser-config"
              ? Promise.reject(failure)
              : Promise.resolve(browserConfig),
          ),
          initializeOIDC: vi.fn().mockImplementation(() =>
            failingStage === "oidc"
              ? Promise.reject(failure)
              : Promise.resolve(tokenProvider),
          ),
          createClient: vi.fn().mockReturnValue(client),
          render: renderApplication,
        }),
      ).rejects.toBe(failure);
      expect(renderApplication).not.toHaveBeenCalled();
    },
  );

  it("injects the bootstrap client and only safe auth actions through the formal AppProviders path", async () => {
    const user = userEvent.setup();
    const execute = vi.fn().mockResolvedValue({ data: session, status: 200 });
    const client = {
      execute,
    } as unknown as ControlPlaneClient;
    const login = vi.fn().mockResolvedValue(undefined);
    const reauthenticate = vi.fn().mockResolvedValue(undefined);
    const logout = vi.fn().mockResolvedValue(undefined);
    const authActions: AuthActions = {
      login,
      reauthenticate,
      logout,
    };
    renderFormalApplication(<RuntimeContextProbe />, {
      client,
      authActions,
    });

    expect(screen.queryByText("运行时上下文不可用")).not.toBeInTheDocument();
    expect(screen.getByTestId("auth-action-keys")).toHaveTextContent(
      "login,logout,reauthenticate",
    );
    expect(screen.getByTestId("auth-action-keys")).not.toHaveTextContent(
      "getAccessToken",
    );

    await user.click(
      screen.getByRole("button", { name: "调用受类型约束客户端" }),
    );
    await user.click(screen.getByRole("button", { name: "登录" }));
    await user.click(screen.getByRole("button", { name: "重新认证" }));
    await user.click(screen.getByRole("button", { name: "退出" }));

    expect(execute).toHaveBeenCalledWith("getSession", {
      parameters: {},
    });
    expect(login).toHaveBeenCalledTimes(1);
    expect(reauthenticate).toHaveBeenCalledWith(window.location.href);
    expect(logout).toHaveBeenCalledTimes(1);
  });

  it("provides a keyboard skip link, Chinese landmarks and disabled future routes", async () => {
    window.history.replaceState(
      {},
      "",
      `/?workspace=${workspaceOne}&environment=${environmentOne}`,
    );
    const user = userEvent.setup();
    renderShell();

    expect(screen.getByRole("navigation", { name: "领域导航" })).toBeVisible();
    expect(screen.getByText("运行")).toBeVisible();
    expect(screen.getByText("资产与连接")).toBeVisible();
    expect(screen.getByText("治理")).toBeVisible();
    const future = screen.getByText("事件处置").closest("[aria-disabled='true']");
    expect(future).toHaveTextContent("后续阶段");
    expect(screen.queryByRole("link", { name: /事件处置/ })).not.toBeInTheDocument();

    await user.click(screen.getByRole("link", { name: "跳到主内容" }));
    expect(screen.getByRole("main")).toHaveFocus();
    expect(screen.getByText("张三")).toBeVisible();
  });

  it("links only implemented asset pages with the current Scope and no role inference", async () => {
    window.history.replaceState(
      {},
      "",
      `/assets?workspace=${workspaceOne}&environment=${environmentOne}` +
        "&cursor=private-page&assetId=private-selection",
    );
    renderShell({
      session: {
        ...session,
        roles: [],
      },
    });

    expect(
      screen.getByRole("link", { name: /资产目录/ }),
    ).toHaveAttribute(
      "href",
      `/assets?workspace=${workspaceOne}&environment=${environmentOne}`,
    );
    expect(
      screen.getByRole("link", { name: /映射工作台/ }),
    ).toHaveAttribute(
      "href",
      `/asset-mappings?workspace=${workspaceOne}&environment=${environmentOne}`,
    );

    for (const label of [
      "总览",
      "事件处置",
      "调查记录",
      "主动调查",
      "受治理动作",
      "连接与数据源",
      "发现与同步",
      "凭据引用",
      "Runner 与能力",
      "授权与策略",
      "审计日志",
      "生产发布",
    ]) {
      expect(
        screen.getByText(label).closest("[aria-disabled='true']"),
      ).not.toBeNull();
      expect(
        screen.queryByRole("link", { name: new RegExp(label) }),
      ).not.toBeInTheDocument();
    }

    const user = userEvent.setup();
    await user.click(screen.getByRole("link", { name: /映射工作台/ }));
    await waitFor(() => {
      expect(window.location.pathname).toBe("/asset-mappings");
    });
    const search = new URL(window.location.href).searchParams;
    expect(search.get("workspace")).toBe(workspaceOne);
    expect(search.get("environment")).toBe(environmentOne);
    expect(search.get("cursor")).toBeNull();
    expect(search.get("assetId")).toBeNull();
  });

  it("guards dirty drafts before navigating to another implemented page", async () => {
    const currentURL =
      `/assets?workspace=${workspaceOne}&environment=${environmentOne}` +
      "&cursor=private-page&assetId=private-selection";
    window.history.replaceState({}, "", currentURL);
    const user = userEvent.setup();
    const onDiscard = vi.fn();
    renderFormalApplication(
      <AppShell session={session}>
        <RegisteredDirtyDraft onDiscard={onDiscard} />
      </AppShell>,
    );

    await user.click(screen.getByRole("link", { name: /映射工作台/ }));

    expect(
      screen.getByRole("alertdialog", { name: "离开当前页面" }),
    ).toBeVisible();
    expect(window.location.href).toBe(
      new URL(currentURL, window.location.origin).href,
    );
    expect(onDiscard).not.toHaveBeenCalled();

    await user.click(screen.getByRole("button", { name: "取消" }));
    expect(window.location.href).toBe(
      new URL(currentURL, window.location.origin).href,
    );
    expect(onDiscard).not.toHaveBeenCalled();

    await user.click(screen.getByRole("link", { name: /映射工作台/ }));
    await user.click(screen.getByRole("button", { name: "放弃并前往" }));

    await waitFor(() => {
      expect(window.location.pathname).toBe("/asset-mappings");
    });
    const search = new URL(window.location.href).searchParams;
    expect(search.get("workspace")).toBe(workspaceOne);
    expect(search.get("environment")).toBe(environmentOne);
    expect(search.get("cursor")).toBeNull();
    expect(search.get("assetId")).toBeNull();
    expect(onDiscard).toHaveBeenCalledTimes(1);
  });

  it("fails closed when a registered draft remains dirty after discard", async () => {
    const currentURL =
      `/assets?workspace=${workspaceOne}&environment=${environmentOne}` +
      "&assetId=governed-operation-in-flight";
    window.history.replaceState({}, "", currentURL);
    const user = userEvent.setup();
    const onDiscard = vi.fn();
    renderFormalApplication(
      <AppShell session={session}>
        <RegisteredUndiscardableDraft onDiscard={onDiscard} />
      </AppShell>,
    );

    await user.click(screen.getByRole("link", { name: /映射工作台/ }));
    await user.click(screen.getByRole("button", { name: "放弃并前往" }));

    expect(
      await screen.findByRole("alertdialog", {
        name: "无法安全离开当前页面",
      }),
    ).toHaveTextContent(
      "当前操作仍在提交或草稿无法安全丢弃。为避免中断治理操作，已阻止离开当前页面。",
    );
    expect(window.location.href).toBe(
      new URL(currentURL, window.location.origin).href,
    );
    expect(
      screen.queryByRole("button", { name: "放弃并前往" }),
    ).not.toBeInTheDocument();
    expect(onDiscard).toHaveBeenCalledTimes(1);
  });

  it.each(["isDirty", "discard"] as const)(
    "fails closed when a draft guard %s callback throws",
    async (failure) => {
      const currentURL =
        `/assets?workspace=${workspaceOne}&environment=${environmentOne}`;
      window.history.replaceState({}, "", currentURL);
      const user = userEvent.setup();
      const onDiscard = vi.fn();
      renderFormalApplication(
        <AppShell session={session}>
          <RegisteredThrowingDraft
            failure={failure}
            onDiscard={onDiscard}
          />
        </AppShell>,
      );

      await user.click(screen.getByRole("link", { name: /映射工作台/ }));
      await user.click(screen.getByRole("button", { name: "放弃并前往" }));

      expect(
        await screen.findByRole("alertdialog", {
          name: "无法安全离开当前页面",
        }),
      ).toBeVisible();
      expect(window.location.href).toBe(
        new URL(currentURL, window.location.origin).href,
      );
      expect(
        screen.queryByRole("button", { name: "放弃并前往" }),
      ).not.toBeInTheDocument();
      expect(onDiscard).toHaveBeenCalledTimes(
        failure === "discard" ? 1 : 0,
      );
    },
  );

  it("uses the actual current URL when returning from a same-Scope detail route", async () => {
    const listURL =
      `/assets?workspace=${workspaceOne}&environment=${environmentOne}`;
    window.history.replaceState({}, "", listURL);
    const user = userEvent.setup();
    renderShell();

    act(() => {
      window.history.pushState(
        {},
        "",
        `/assets/77777777-7777-4777-8777-777777777777` +
          `?workspace=${workspaceOne}&environment=${environmentOne}` +
          "&tab=relations",
      );
    });
    await user.click(screen.getByRole("link", { name: /资产目录/ }));

    await waitFor(() => {
      expect(window.location.pathname).toBe("/assets");
    });
    expect(window.location.search).toBe(
      `?workspace=${workspaceOne}&environment=${environmentOne}`,
    );
  });

  it("guards dirty drafts on same-Scope browser history navigation", async () => {
    const targetURL =
      `/assets?workspace=${workspaceOne}&environment=${environmentOne}` +
      "&assetId=same-scope-history-target";
    const currentURL =
      `/asset-mappings?workspace=${workspaceOne}&environment=${environmentOne}` +
      "&conflictId=dirty-same-scope";
    window.history.replaceState({}, "", targetURL);
    const onDiscard = vi.fn();
    const user = userEvent.setup();
    renderFormalApplication(
      <AppShell session={session}>
        <RegisteredDirtyDraft onDiscard={onDiscard} />
      </AppShell>,
    );
    act(() => {
      window.history.pushState({}, "", currentURL);
    });

    await navigateBack();
    expect(
      await screen.findByRole("alertdialog", { name: "离开当前页面" }),
    ).toBeVisible();
    expect(window.location.href).toBe(
      new URL(currentURL, window.location.origin).href,
    );
    expect(onDiscard).not.toHaveBeenCalled();

    await user.click(screen.getByRole("button", { name: "取消" }));
    expect(window.location.href).toBe(
      new URL(currentURL, window.location.origin).href,
    );
    expect(onDiscard).not.toHaveBeenCalled();

    window.history.pushState({}, "", targetURL);
    window.history.pushState({}, "", currentURL);
    await navigateBack();
    await user.click(screen.getByRole("button", { name: "放弃并前往" }));

    await waitFor(() => {
      expect(window.location.pathname).toBe("/assets");
    });
    expect(onDiscard).toHaveBeenCalledTimes(1);
    const search = new URL(window.location.href).searchParams;
    expect(search.get("workspace")).toBe(workspaceOne);
    expect(search.get("environment")).toBe(environmentOne);
    expect(search.get("assetId")).toBe("same-scope-history-target");
    expect(search.get("conflictId")).toBeNull();
  });

  it("adds a missing authorized Scope without deleting deep-link parameters on refresh", () => {
    window.history.replaceState(
      {},
      "",
      "/assets?cursor=next-page&assetId=asset-1&operationId=operation-1&selectedId=row-1",
    );
    renderShell();

    const search = new URL(window.location.href).searchParams;
    expect(search.get("workspace")).toBe(workspaceOne);
    expect(search.get("environment")).toBe(environmentOne);
    expect(search.get("cursor")).toBe("next-page");
    expect(search.get("assetId")).toBe("asset-1");
    expect(search.get("operationId")).toBe("operation-1");
    expect(search.get("selectedId")).toBe("row-1");
  });

  it("blocks dirty Scope changes, then cancels old queries and clears old cache", async () => {
    window.history.replaceState(
      {},
      "",
      `/assets?workspace=${workspaceOne}&environment=${environmentOne}` +
        "&cursor=next-page&assetId=asset-1&operationId=operation-1",
    );
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    });
    queryClient.setQueryData(
      ["assets", workspaceOne, environmentOne, {}],
      { items: [] },
    );
    const cancelQueries = vi.spyOn(queryClient, "cancelQueries");
    const removeQueries = vi.spyOn(queryClient, "removeQueries");
    const onDiscardDraft = vi.fn();
    const user = userEvent.setup();
    renderShell({
      dirty: true,
      onDiscardDraft,
      queryClient,
    });

    await user.selectOptions(screen.getByLabelText("环境"), environmentTwo);
    expect(
      screen.getByRole("alertdialog", { name: "切换作用域" }),
    ).toBeVisible();
    await user.click(screen.getByRole("button", { name: "取消" }));
    expect(new URL(window.location.href).searchParams.get("environment")).toBe(
      environmentOne,
    );
    expect(new URL(window.location.href).searchParams.get("cursor")).toBe(
      "next-page",
    );

    await user.selectOptions(screen.getByLabelText("环境"), environmentTwo);
    await user.click(screen.getByRole("button", { name: "放弃并切换" }));

    expect(new URL(window.location.href).searchParams.get("environment")).toBe(
      environmentTwo,
    );
    expect(onDiscardDraft).toHaveBeenCalledTimes(1);
    expect(cancelQueries).toHaveBeenCalled();
    expect(removeQueries).toHaveBeenCalled();
    expect(
      queryClient.getQueryData(["assets", workspaceOne, environmentOne, {}]),
    ).toBeUndefined();
    const search = new URL(window.location.href).searchParams;
    expect(search.get("cursor")).toBeNull();
    expect(search.get("assetId")).toBeNull();
    expect(search.get("operationId")).toBeNull();
  });

  it("keeps scoped queries when a dirty guard cannot be discarded", async () => {
    window.history.replaceState(
      {},
      "",
      `/assets?workspace=${workspaceOne}&environment=${environmentOne}`,
    );
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    });
    const queryKey = ["assets", workspaceOne, environmentOne, {}] as const;
    queryClient.setQueryData(queryKey, { items: ["protected"] });
    const cancelQueries = vi.spyOn(queryClient, "cancelQueries");
    const removeQueries = vi.spyOn(queryClient, "removeQueries");
    const onDiscard = vi.fn();
    const user = userEvent.setup();
    renderFormalApplication(
      <AppShell session={session}>
        <RegisteredUndiscardableDraft onDiscard={onDiscard} />
      </AppShell>,
      { queryClient },
    );

    await user.selectOptions(screen.getByLabelText("环境"), environmentTwo);
    await user.click(screen.getByRole("button", { name: "放弃并切换" }));

    expect(
      await screen.findByRole("alertdialog", {
        name: "无法安全离开当前页面",
      }),
    ).toBeVisible();
    expect(screen.getByLabelText("环境")).toHaveValue(environmentOne);
    expect(new URL(window.location.href).searchParams.get("environment")).toBe(
      environmentOne,
    );
    expect(cancelQueries).not.toHaveBeenCalled();
    expect(removeQueries).not.toHaveBeenCalled();
    expect(queryClient.getQueryData(queryKey)).toEqual({
      items: ["protected"],
    });
    expect(onDiscard).toHaveBeenCalledTimes(1);
  });

  it("keeps scoped queries when provider dirty state cannot be cleared", async () => {
    window.history.replaceState(
      {},
      "",
      `/assets?workspace=${workspaceOne}&environment=${environmentOne}`,
    );
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    });
    const queryKey = ["assets", workspaceOne, environmentOne, {}] as const;
    queryClient.setQueryData(queryKey, { items: ["provider-protected"] });
    const cancelQueries = vi.spyOn(queryClient, "cancelQueries");
    const removeQueries = vi.spyOn(queryClient, "removeQueries");
    const onDiscardDraft = vi.fn();
    const user = userEvent.setup();
    renderShell({
      dirty: true,
      onDiscardDraft,
      queryClient,
      discardClearsDirty: false,
    });

    await user.selectOptions(screen.getByLabelText("环境"), environmentTwo);
    await user.click(screen.getByRole("button", { name: "放弃并切换" }));

    expect(
      await screen.findByRole("alertdialog", {
        name: "无法安全离开当前页面",
      }),
    ).toBeVisible();
    expect(screen.getByLabelText("环境")).toHaveValue(environmentOne);
    expect(cancelQueries).not.toHaveBeenCalled();
    expect(removeQueries).not.toHaveBeenCalled();
    expect(queryClient.getQueryData(queryKey)).toEqual({
      items: ["provider-protected"],
    });
    expect(onDiscardDraft).toHaveBeenCalledTimes(1);
  });

  it("pushes UI Scope changes and restores an authorized deep link on browser back", async () => {
    window.history.replaceState(
      {},
      "",
      `/overview?workspace=${workspaceTwo}&environment=${environmentTwo}`,
    );
    window.history.pushState(
      {},
      "",
      `/assets?workspace=${workspaceOne}&environment=${environmentOne}` +
        "&assetId=asset-from-history",
    );
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    });
    queryClient.setQueryData(
      ["assets", workspaceOne, environmentOne, {}],
      { items: ["workspace-one"] },
    );
    const cancelQueries = vi.spyOn(queryClient, "cancelQueries");
    const removeQueries = vi.spyOn(queryClient, "removeQueries");
    const user = userEvent.setup();
    renderShell({ queryClient });

    await user.selectOptions(screen.getByLabelText("环境"), environmentTwo);
    await waitFor(() => {
      expect(
        new URL(window.location.href).searchParams.get("environment"),
      ).toBe(environmentTwo);
    });
    expect(
      new URL(window.location.href).searchParams.get("assetId"),
    ).toBeNull();
    queryClient.setQueryData(
      ["assets", workspaceOne, environmentTwo, {}],
      { items: ["workspace-two"] },
    );
    cancelQueries.mockClear();
    removeQueries.mockClear();

    await navigateBack();

    await waitFor(() => {
      expect(screen.getByLabelText("环境")).toHaveValue(environmentOne);
    });
    const restored = new URL(window.location.href).searchParams;
    expect(restored.get("environment")).toBe(environmentOne);
    expect(restored.get("assetId")).toBe("asset-from-history");
    expect(cancelQueries).toHaveBeenCalled();
    expect(removeQueries).toHaveBeenCalled();
    expect(
      queryClient.getQueryData(["assets", workspaceOne, environmentTwo, {}]),
    ).toBeUndefined();
  });

  it("blocks dirty browser back, keeps Scope on cancel and applies the saved target on discard", async () => {
    const targetURL =
      `/assets?workspace=${workspaceOne}&environment=${environmentOne}` +
      "&assetId=dirty-history-target";
    const currentURL =
      `/assets?workspace=${workspaceOne}&environment=${environmentTwo}`;
    window.history.replaceState({}, "", targetURL);
    window.history.pushState({}, "", currentURL);
    const onDiscard = vi.fn();
    const user = userEvent.setup();
    renderFormalApplication(
      <AppShell session={session}>
        <RegisteredDirtyDraft onDiscard={onDiscard} />
      </AppShell>,
    );

    await navigateBack();
    expect(
      await screen.findByRole("alertdialog", { name: "切换作用域" }),
    ).toBeVisible();
    expect(new URL(window.location.href).searchParams.get("environment")).toBe(
      environmentTwo,
    );
    expect(screen.getByLabelText("环境")).toHaveValue(environmentTwo);

    await user.click(screen.getByRole("button", { name: "取消" }));
    expect(onDiscard).not.toHaveBeenCalled();
    expect(new URL(window.location.href).searchParams.get("environment")).toBe(
      environmentTwo,
    );
    expect(screen.getByLabelText("环境")).toHaveValue(environmentTwo);

    window.history.pushState({}, "", targetURL);
    window.history.pushState({}, "", currentURL);
    await navigateBack();
    expect(
      await screen.findByRole("alertdialog", { name: "切换作用域" }),
    ).toBeVisible();
    await user.click(screen.getByRole("button", { name: "放弃并切换" }));

    await waitFor(() => {
      expect(screen.getByLabelText("环境")).toHaveValue(environmentOne);
    });
    expect(onDiscard).toHaveBeenCalledTimes(1);
    const restored = new URL(window.location.href).searchParams;
    expect(restored.get("environment")).toBe(environmentOne);
    expect(restored.get("assetId")).toBe("dirty-history-target");
  });

  it("restores the current safe URL when browser history contains an unauthorized Scope", async () => {
    const unsafeURL =
      "/assets?workspace=unauthorized&environment=unauthorized";
    const safeURL =
      `/assets?workspace=${workspaceTwo}&environment=${environmentTwo}`;
    window.history.replaceState({}, "", unsafeURL);
    window.history.pushState({}, "", safeURL);
    renderShell();

    await navigateBack();

    await waitFor(() => {
      const search = new URL(window.location.href).searchParams;
      expect(search.get("workspace")).toBe(workspaceTwo);
      expect(search.get("environment")).toBe(environmentTwo);
    });
    expect(screen.getByLabelText("工作空间")).toHaveValue(workspaceTwo);
    expect(screen.getByLabelText("环境")).toHaveValue(environmentTwo);
    expect(screen.queryByRole("alertdialog")).not.toBeInTheDocument();
  });

  it("lets a feature register and discard a dirty draft through formal providers", async () => {
    window.history.replaceState(
      {},
      "",
      `/assets?workspace=${workspaceOne}&environment=${environmentOne}`,
    );
    const user = userEvent.setup();
    const onDiscard = vi.fn();
    renderFormalApplication(
      <AppShell session={session}>
        <RegisteredDirtyDraft onDiscard={onDiscard} />
      </AppShell>,
    );

    await user.selectOptions(screen.getByLabelText("环境"), environmentTwo);
    expect(
      screen.getByRole("alertdialog", { name: "切换作用域" }),
    ).toBeVisible();
    await user.click(screen.getByRole("button", { name: "取消" }));
    expect(onDiscard).not.toHaveBeenCalled();
    expect(new URL(window.location.href).searchParams.get("environment")).toBe(
      environmentOne,
    );

    await user.selectOptions(screen.getByLabelText("环境"), environmentTwo);
    await user.click(screen.getByRole("button", { name: "放弃并切换" }));
    expect(onDiscard).toHaveBeenCalledTimes(1);
    expect(new URL(window.location.href).searchParams.get("environment")).toBe(
      environmentTwo,
    );
  });

  it("fails closed instead of rendering children for an unauthorized URL Scope", () => {
    window.history.replaceState(
      {},
      "",
      `/?workspace=unknown&environment=${environmentOne}`,
    );
    renderShell();

    expect(screen.getByRole("alert")).toHaveTextContent("当前作用域不可用");
    expect(screen.queryByText("应用基础已加载")).not.toBeInTheDocument();
  });

  it("normalizes scoped query filters deterministically without changing scalar meaning", () => {
    const scope = {
      workspaceId: workspaceOne,
      environmentId: environmentOne,
    };
    const first = queryKeys.scoped("assets", scope, {
      status: ["STALE", "ACTIVE", "STALE"],
      nested: {
        z: 1,
        omitted: undefined,
        enabled: false,
      },
      pageSize: 50,
      search: "01",
    });
    const second = queryKeys.scoped("assets", scope, {
      search: "01",
      pageSize: 50,
      nested: {
        enabled: false,
        z: 1,
      },
      status: ["ACTIVE", "STALE"],
    });

    expect(first).toStrictEqual(second);
    expect(first).toStrictEqual([
      "assets",
      workspaceOne,
      environmentOne,
      {
        nested: {
          enabled: false,
          z: 1,
        },
        pageSize: 50,
        search: "01",
        status: ["ACTIVE", "STALE"],
      },
    ]);
    expect(JSON.stringify(first)).toBe(JSON.stringify(second));
  });

  it("keeps one keyboard-reachable navigation at narrow widths and preserves focus/status contracts", () => {
    window.history.replaceState(
      {},
      "",
      `/?workspace=${workspaceOne}&environment=${environmentOne}`,
    );
    renderShell();
    expect(screen.getAllByRole("navigation", { name: "领域导航" })).toHaveLength(
      1,
    );

    const shellStyles = readFileSync(
      "src/app/AppShell.module.css",
      "utf8",
    );
    const compactStyles = shellStyles.slice(
      shellStyles.indexOf("@media (width < 1024px)"),
    );
    expect(compactStyles).not.toMatch(
      /\.sidebar\s*\{[^}]*display:\s*none/s,
    );
    expect(compactStyles).toMatch(
      /\.sidebar\s*\{[^}]*overflow-x:\s*auto/s,
    );
    expect(shellStyles).not.toMatch(
      /\.main:focus\s*\{[^}]*outline:\s*none/s,
    );

    const globalStyles = readFileSync(
      "src/app/styles/global.css",
      "utf8",
    );
    expect(globalStyles).toMatch(
      /\.status-badge\s*\{[^}]*border-radius:\s*var\(--radius-sm\)/s,
    );
  });

  it("rejects a Vite development proxy target with a non-root path", () => {
    const viteConfig = readFileSync(
      "vite.config.ts",
      "utf8",
    );
    expect(viteConfig).toContain('target.pathname !== "/"');
  });

  it("guards member-form browser network constructors outside shared API", () => {
    const eslintConfig = readFileSync("eslint.config.js", "utf8");
    expect(eslintConfig).toContain("memberNetworkConstructor");
    expect(eslintConfig).toContain(
      'node.callee.object.name === "window"',
    );
    expect(eslintConfig).toContain(
      'node.callee.object.name === "globalThis"',
    );
  });
});
