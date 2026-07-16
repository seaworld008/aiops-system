import {
  QueryClient,
  QueryClientProvider,
} from "@tanstack/react-query";
import {
  act,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import {
  delay,
  http,
  HttpResponse,
} from "msw";
import {
  type PropsWithChildren,
  useState,
} from "react";
import {
  afterEach,
  beforeEach,
  describe,
  expect,
  it,
  vi,
} from "vitest";

import {
  ControlPlaneRuntimeProvider,
  createControlPlaneClient,
} from "@/shared/api/controlPlaneClient";
import {
  ScopeRuntimeProvider,
  type Scope,
} from "@/shared/api/queryKeys";
import type { components } from "@/shared/api/schema";
import { testServer } from "@/test/msw/server";

import {
  MappingWorkbenchPage,
  type MappingWorkbenchPageProps,
} from "./MappingWorkbenchPage";
import {
  changeMappingFilters,
  parseMappingSearch,
  type MappingSearch,
} from "./mappingSearch";

const workspaceID = "33333333-3333-4333-8333-333333333333";
const environmentID = "44444444-4444-4444-8444-444444444444";
const sourceID = "55555555-5555-4555-8555-555555555555";
const serviceID = "66666666-6666-4666-8666-666666666666";
const primaryConflictID = "77777777-7777-4777-8777-777777777777";
const secondConflictID = "88888888-8888-4888-8888-888888888888";
const thirdConflictID = "99999999-9999-4999-8999-999999999999";
const auditID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const traceID = "abcdefabcdefabcdefabcdefabcdefab";
const alternateEnvironmentID =
  "abababab-abab-4aba-8aba-abababababab";
const existingFingerprint = "1".repeat(64);
const candidateFingerprint = "2".repeat(64);
const conflictListPath =
  "/api/v1/workspaces/:workspaceId/asset-conflicts";
const resolveConflictPath =
  "/api/v1/workspaces/:workspaceId/asset-conflicts/:conflictId\\:resolve";

function desktopMediaQuery() {
  return {
    matches: true,
    media: "(min-width: 768px)",
    onchange: null,
    addListener: vi.fn(),
    removeListener: vi.fn(),
    addEventListener: vi.fn(),
    removeEventListener: vi.fn(),
    dispatchEvent: vi.fn(),
  };
}

type AssetConflict = components["schemas"]["AssetConflictDetail"];
type AssetConflictPage = components["schemas"]["AssetConflictPage"];
type ConflictMutation =
  components["schemas"]["AssetConflictMutationResult"];

const baseConflict: AssetConflict = {
  id: primaryConflictID,
  environment_id: environmentID,
  asset: {
    id: "10101010-1010-4010-8010-101010101010",
    display_name: "payments-api-01",
    kind: "LINUX_VM",
    lifecycle: "DISCOVERED",
  },
  candidate_asset: {
    id: "20202020-2020-4020-8020-202020202020",
    display_name: "payments-api-candidate",
    kind: "LINUX_VM",
    lifecycle: "DISCOVERED",
  },
  candidate_service: {
    id: serviceID,
    name: "payments",
  },
  source_id: sourceID,
  observation: {
    id: "30303030-3030-4030-8030-303030303030",
    source_id: sourceID,
    source_revision: 4,
    observed_at: "2026-07-16T03:00:00Z",
  },
  type: "FIELD_CONFLICT",
  field_name: "display_name",
  existing_value_sha256: existingFingerprint,
  candidate_value_sha256: candidateFingerprint,
  status: "OPEN",
  resolution: null,
  resolution_reason_code: null,
  resolved_at: null,
  impact_counts: {
    asset_active_bindings: 1,
    asset_active_relationships: 2,
    candidate_asset_active_bindings: 1,
    candidate_asset_active_relationships: 1,
    candidate_service_active_bindings: 2,
  },
  version: 5,
  etag: `"asset-conflict:${primaryConflictID}:v5"`,
  created_at: "2026-07-15T03:00:00Z",
  updated_at: "2026-07-16T03:00:00Z",
  effective_actions: ["RESOLVE_CONFLICT"],
};

function conflict(
  id: string,
  displayName: string,
  overrides: Partial<AssetConflict> = {},
): AssetConflict {
  return {
    ...baseConflict,
    id,
    asset: {
      ...baseConflict.asset,
      id: id.replace(/^./u, "4"),
      display_name: displayName,
    },
    observation: {
      ...baseConflict.observation,
      id: id.replace(/^./u, "5"),
    },
    etag: `"asset-conflict:${id}:v5"`,
    ...overrides,
  };
}

const conflictPage: AssetConflictPage = {
  items: [baseConflict],
  page: { next_cursor: "next-conflict-page" },
};

function mutationResult(item: AssetConflict): ConflictMutation {
  return {
    conflict: {
      ...item,
      status: "RESOLVED",
      resolution: "CONFIRM_EXACT",
      resolution_reason_code: "SERVICE_OWNER_VERIFIED",
      resolved_at: "2026-07-17T03:00:00Z",
      version: item.version + 1,
      etag: `"asset-conflict:${item.id}:v${item.version + 1}"`,
      effective_actions: [],
    },
    binding: null,
    mutation_receipt: {
      audit_id: auditID,
      trace_id: traceID,
      idempotent_replay: false,
    },
  };
}

function defaultSearch(
  patch: Partial<MappingSearch> = {},
): MappingSearch {
  return parseMappingSearch(
    {
      workspace: workspaceID,
      environment: environmentID,
      status: ["OPEN"],
      risk: [],
      age: "ALL",
      conflictId: primaryConflictID,
      ...patch,
    },
    { workspace: workspaceID, environment: environmentID },
  );
}

function renderWorkbench(
  page: AssetConflictPage = conflictPage,
  search: MappingSearch = defaultSearch(),
) {
  testServer.use(
    http.get(conflictListPath, () =>
      HttpResponse.json(page, {
        headers: { "X-Trace-ID": traceID },
      }),
    ),
  );
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
  const onSearchChange =
    vi.fn<MappingWorkbenchPageProps["onSearchChange"]>();
  const initialScope: Scope = {
    workspaceId: workspaceID,
    environmentId: environmentID,
  };
  let updateScope: ((scope: Scope) => void) | undefined;
  const TestScopeProvider = ({ children }: PropsWithChildren) => {
    const [scope, setScope] = useState(initialScope);
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
  };
  const Wrapper = ({ children }: PropsWithChildren) => (
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
          {children}
        </TestScopeProvider>
      </ControlPlaneRuntimeProvider>
    </QueryClientProvider>
  );
  return {
    ...render(
      <MappingWorkbenchPage
        search={search}
        onSearchChange={onSearchChange}
      />,
      { wrapper: Wrapper },
    ),
    onSearchChange,
    queryClient,
    setScope: (scope: Scope) => {
      act(() => {
        updateScope?.(scope);
      });
    },
  };
}

async function completeConfirmExactForm(user: ReturnType<typeof userEvent.setup>) {
  await user.selectOptions(
    screen.getByLabelText("Binding Role"),
    "PRIMARY_RUNTIME",
  );
  await user.type(
    screen.getByLabelText("审计原因代码"),
    "SERVICE_OWNER_VERIFIED",
  );
  await user.click(
    screen.getByRole("checkbox", {
      name: "我已审阅受影响的连接与策略",
    }),
  );
}

function problem(
  status: 403 | 409,
  code =
    status === 409
      ? "version_conflict"
      : "asset_scope_forbidden",
) {
  return HttpResponse.json(
    {
      type: "about:blank",
      title:
        status === 409
          ? "资源版本已变化"
          : "映射决定被拒绝",
      status,
      code,
      detail:
        status === 409
          ? "冲突已被其他操作更新。"
          : "当前主体不能再解析该冲突。",
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

describe("MappingWorkbenchPage", () => {
  beforeEach(() => {
    vi.stubGlobal(
      "matchMedia",
      vi.fn().mockImplementation(desktopMediaQuery),
    );
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("规范化并恢复 URL 队列、筛选、游标和选择状态", () => {
    const search = parseMappingSearch(
      {
        workspace: workspaceID,
        environment: environmentID,
        status: ["RESOLVED", "OPEN", "OPEN", "INVALID"],
        risk: ["HIGH", "LOW", "HIGH", "UNKNOWN"],
        source: sourceID,
        service: serviceID,
        age: "OVER_72H",
        cursor: "cursor_page_2",
        conflictId: primaryConflictID,
      },
      { workspace: "", environment: "" },
    );

    expect(search).toMatchObject({
      workspace: workspaceID,
      environment: environmentID,
      status: ["OPEN", "RESOLVED"],
      risk: ["HIGH", "LOW"],
      source: sourceID,
      service: serviceID,
      age: "OVER_72H",
      cursor: "cursor_page_2",
      conflictId: primaryConflictID,
    });

    const changed = changeMappingFilters(search, {
      status: ["REJECTED"],
    });
    expect(changed.status).toEqual(["REJECTED"]);
    expect(changed.cursor).toBeUndefined();
    expect(changed.conflictId).toBeUndefined();
  });

  it("无服务端有效动作时只读比较且不暴露 fingerprint 或隐式决定", async () => {
    renderWorkbench({
      ...conflictPage,
      items: [{ ...baseConflict, effective_actions: [] }],
    });

    expect(
      await screen.findByRole("heading", { name: "映射工作台" }),
    ).toBeVisible();
    expect(await screen.findByText("只读比较")).toBeVisible();
    for (const heading of [
      "权威来源事实",
      "现有资产",
      "候选关系",
      "字段级 Provenance",
    ]) {
      expect(
        screen.getByRole("heading", { name: heading }),
      ).toBeVisible();
    }
    expect(
      screen.getByText("候选建议，不会自动生效"),
    ).toBeVisible();
    expect(screen.getByText("服务端未提供，不推断")).toBeVisible();
    expect(screen.queryByText(existingFingerprint)).not.toBeInTheDocument();
    expect(screen.queryByText(candidateFingerprint)).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", {
        name: /确认精确映射|拒绝候选|保持未解析|隔离资产/u,
      }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("checkbox", {
        name: `选择冲突 ${baseConflict.asset.display_name}`,
      }),
    ).not.toBeInTheDocument();
  });

  it("无候选 Service 时关闭确认精确映射并保留其他显式决定", async () => {
    renderWorkbench({
      ...conflictPage,
      items: [{ ...baseConflict, candidate_service: null }],
    });

    expect(
      await screen.findByText(
        "服务端未提供候选 Service；确认精确映射保持关闭，不会猜测目标。",
      ),
    ).toBeVisible();
    expect(
      screen.queryByRole("button", {
        name: "确认精确映射",
      }),
    ).not.toBeInTheDocument();
    for (const label of [
      "拒绝候选",
      "保持未解析",
      "隔离资产",
    ]) {
      expect(
        screen.getByRole("button", { name: label }),
      ).toBeEnabled();
    }
  });

  it("窄屏只提供安全比较且不暴露单项或 batch mutation", async () => {
    vi.stubGlobal(
      "matchMedia",
      vi.fn().mockImplementation((query: string) => ({
        ...desktopMediaQuery(),
        matches: false,
        media: query,
      })),
    );
    const second = conflict(secondConflictID, "payments-api-02");
    renderWorkbench({
      items: [baseConflict, second],
      page: { next_cursor: null },
    });

    expect(
      await screen.findByText(/请在桌面完成映射治理操作/u),
    ).toBeVisible();
    for (const item of [baseConflict, second]) {
      expect(
        screen.queryByRole("checkbox", {
          name: `选择冲突 ${item.asset.display_name}`,
        }),
      ).not.toBeInTheDocument();
    }
    expect(
      screen.queryByRole("button", {
        name: /确认精确映射|拒绝候选|保持未解析|隔离资产/u,
      }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: /批量/u }),
    ).not.toBeInTheDocument();
  });

  it("确认精确映射要求完整影响复核并发送 fresh 幂等键与当前 ETag", async () => {
    const user = userEvent.setup();
    let capturedBody: unknown;
    let capturedIfMatch: string | null = null;
    let capturedIdempotencyKey: string | null = null;
    testServer.use(
      http.post(resolveConflictPath, async ({ request }) => {
        capturedBody = await request.json();
        capturedIfMatch = request.headers.get("If-Match");
        capturedIdempotencyKey =
          request.headers.get("Idempotency-Key");
        return HttpResponse.json(mutationResult(baseConflict), {
          headers: {
            ETag: `"asset-conflict:${primaryConflictID}:v6"`,
            "X-Audit-ID": auditID,
            "X-Trace-ID": traceID,
          },
        });
      }),
    );
    renderWorkbench();

    await user.click(
      await screen.findByRole("button", {
        name: "确认精确映射",
      }),
    );
    const dialog = screen.getByRole("alertdialog");
    expect(within(dialog).getByText("比较键")).toBeVisible();
    expect(
      within(dialog).queryByText(existingFingerprint),
    ).not.toBeInTheDocument();
    expect(
      within(dialog).queryByText(candidateFingerprint),
    ).not.toBeInTheDocument();
    expect(
      within(dialog).getByText("受影响的连接与策略"),
    ).toBeVisible();
    const submit = within(dialog).getByRole("button", {
      name: "确认并记录决定",
    });
    expect(submit).toBeDisabled();

    await completeConfirmExactForm(user);
    expect(submit).toBeEnabled();
    await user.click(submit);

    expect(
      await screen.findByText("映射决定已记录"),
    ).toBeVisible();
    expect(screen.getByText(auditID)).toBeVisible();
    expect(screen.getByText(traceID)).toBeVisible();
    expect(capturedIfMatch).toBe(baseConflict.etag);
    expect(capturedIdempotencyKey).toMatch(
      /^[0-9a-f]{8}-[0-9a-f-]{27}$/u,
    );
    expect(capturedBody).toEqual({
      resolution: "CONFIRM_EXACT",
      service_id: serviceID,
      binding_role: "PRIMARY_RUNTIME",
      reason_code: "SERVICE_OWNER_VERIFIED",
    });
  });

  it.each([
    "idempotency_conflict",
    "invalid_asset_state",
  ] as const)("任何 409（%s）都锁定提交并保留重新审阅上下文", async (code) => {
    const user = userEvent.setup();
    let calls = 0;
    testServer.use(
      http.post(resolveConflictPath, () => {
        calls += 1;
        return problem(409, code);
      }),
    );
    const view = renderWorkbench();
    await user.click(
      await screen.findByRole("button", {
        name: "拒绝候选",
      }),
    );
    testServer.use(
      http.get(conflictListPath, () =>
        HttpResponse.json({
          items: [],
          page: { next_cursor: null },
        } satisfies AssetConflictPage),
      ),
    );
    view.onSearchChange.mockClear();
    await user.type(
      screen.getByLabelText("审计原因代码"),
      "GOVERNANCE_REVIEWED",
    );
    await user.click(
      screen.getByRole("button", {
        name: "确认并记录决定",
      }),
    );

    expect(
      await screen.findByRole("heading", {
        name: "资源已被其他操作更新",
      }),
    ).toBeVisible();
    expect(
      screen.getByRole("button", {
        name: "确认并记录决定",
      }),
    ).toBeDisabled();
    expect(
      screen.getByRole("button", { name: "取消" }),
    ).toBeDisabled();
    expect(
      screen.getByRole("button", {
        name: "重新加载并审阅",
      }),
    ).toBeVisible();
    expect(calls).toBe(1);
    expect(
      view.onSearchChange.mock.calls.some(
        ([next]) => next.conflictId === undefined,
      ),
    ).toBe(false);
  });

  it.each([
    ["拒绝候选", "REJECT_CANDIDATE"],
    ["保持未解析", "KEEP_UNRESOLVED"],
    ["隔离资产", "QUARANTINE_ASSET"],
  ] as const)("只发送显式的 %s 决定", async (label, resolution) => {
    const user = userEvent.setup();
    let capturedBody: unknown;
    testServer.use(
      http.post(resolveConflictPath, async ({ request }) => {
        capturedBody = await request.json();
        return HttpResponse.json(mutationResult(baseConflict), {
          headers: {
            ETag: `"asset-conflict:${primaryConflictID}:v6"`,
            "X-Audit-ID": auditID,
            "X-Trace-ID": traceID,
          },
        });
      }),
    );
    renderWorkbench();

    await user.click(
      await screen.findByRole("button", { name: label }),
    );
    if (resolution === "KEEP_UNRESOLVED") {
      expect(
        screen.getByText("调查仍保持不可用"),
      ).toBeVisible();
    }
    if (resolution === "QUARANTINE_ASSET") {
      expect(
        screen.getByText("隔离会阻止新的调查与 Claim"),
      ).toBeVisible();
    }
    await user.type(
      screen.getByLabelText("审计原因代码"),
      "GOVERNANCE_REVIEWED",
    );
    await user.click(
      screen.getByRole("button", {
        name: "确认并记录决定",
      }),
    );

    expect(
      await screen.findByText("映射决定已记录"),
    ).toBeVisible();
    expect(capturedBody).toEqual({
      resolution,
      reason_code: "GOVERNANCE_REVIEWED",
    });
  });

  it.each([409, 403] as const)(
    "batch 在首个 %s 失败时停止后项且不自动重放",
    async (failureStatus) => {
      const user = userEvent.setup();
      const conflicts = [
        conflict(primaryConflictID, "payments-api-01"),
        conflict(secondConflictID, "payments-api-02"),
        conflict(thirdConflictID, "payments-api-03"),
      ];
      const calls: string[] = [];
      testServer.use(
        http.post(resolveConflictPath, async ({ params }) => {
          const conflictID = String(params.conflictId);
          calls.push(conflictID);
          if (conflictID === secondConflictID) {
            await delay(40);
            return problem(failureStatus);
          }
          const selected =
            conflicts.find((item) => item.id === conflictID) ??
            conflicts[0];
          if (selected === undefined) {
            return problem(403);
          }
          return HttpResponse.json(mutationResult(selected), {
            headers: {
              ETag: `"asset-conflict:${conflictID}:v6"`,
              "X-Audit-ID": auditID,
              "X-Trace-ID": traceID,
            },
          });
        }),
      );
      renderWorkbench(
        { items: conflicts, page: { next_cursor: null } },
        defaultSearch({ conflictId: primaryConflictID }),
      );

      for (const item of conflicts) {
        await user.click(
          await screen.findByRole("checkbox", {
            name: `选择冲突 ${item.asset.display_name}`,
          }),
        );
      }
      await user.click(
        screen.getByRole("button", {
          name: "批量确认精确映射",
        }),
      );
      await completeConfirmExactForm(user);
      await user.click(
        screen.getByRole("button", {
          name: "确认并记录决定",
        }),
      );

      expect(
        await screen.findByText("batch 正在逐项执行"),
      ).toBeVisible();
      expect(
        screen.queryByText("映射决定已记录"),
      ).not.toBeInTheDocument();
      expect(
        await screen.findByText("payments-api-01：成功"),
      ).toBeVisible();
      expect(
        await screen.findByText("payments-api-02：失败"),
      ).toBeVisible();
      expect(
        screen.getByText("payments-api-03：已停止"),
      ).toBeVisible();
      expect(calls).toEqual([primaryConflictID, secondConflictID]);

      await new Promise((resolve) => {
        window.setTimeout(resolve, 100);
      });
      expect(calls).toEqual([primaryConflictID, secondConflictID]);
      if (failureStatus === 409) {
        expect(
          screen.getByRole("heading", {
            name: "资源已被其他操作更新",
          }),
        ).toBeVisible();
      } else {
        expect(
          screen.getByRole("heading", {
            name: "映射决定被拒绝",
          }),
        ).toBeVisible();
        await user.click(
          screen.getByRole("button", { name: "取消" }),
        );
        await user.click(
          screen.getByRole("button", {
            name: /payments-api-03/u,
          }),
        );
        expect(
          await screen.findByText(
            /当前 Scope 的映射治理授权已被服务端拒绝/u,
          ),
        ).toBeVisible();
        expect(
          screen.queryByRole("button", {
            name: /确认精确映射|拒绝候选|保持未解析|隔离资产|批量/u,
          }),
        ).not.toBeInTheDocument();
        expect(
          screen.queryByRole("checkbox", {
            name: /选择冲突/u,
          }),
        ).not.toBeInTheDocument();
        expect(calls).toEqual([
          primaryConflictID,
          secondConflictID,
        ]);
      }
    },
  );

  it("拒绝为 comparison key 不同的选择开放 batch 决定", async () => {
    const user = userEvent.setup();
    const incompatible = conflict(
      secondConflictID,
      "payments-api-02",
      { candidate_value_sha256: "3".repeat(64) },
    );
    renderWorkbench({
      items: [baseConflict, incompatible],
      page: { next_cursor: null },
    });

    for (const item of [baseConflict, incompatible]) {
      await user.click(
        await screen.findByRole("checkbox", {
          name: `选择冲突 ${item.asset.display_name}`,
        }),
      );
    }
    expect(
      screen.getByRole("button", {
        name: "批量确认精确映射",
      }),
    ).toBeDisabled();
  });

  it("服务端撤销已选项 effective action 后移除全部 batch resolve 控件", async () => {
    const user = userEvent.setup();
    const second = conflict(secondConflictID, "payments-api-02");
    const view = renderWorkbench({
      items: [baseConflict, second],
      page: { next_cursor: null },
    });

    for (const item of [baseConflict, second]) {
      await user.click(
        await screen.findByRole("checkbox", {
          name: `选择冲突 ${item.asset.display_name}`,
        }),
      );
    }
    expect(
      screen.getByRole("button", {
        name: "批量确认精确映射",
      }),
    ).toBeVisible();

    act(() => {
      view.queryClient.setQueriesData<AssetConflictPage>(
        { queryKey: ["asset-conflicts"] },
        (current) =>
          current === undefined
            ? current
            : {
                ...current,
                items: current.items.map((item) =>
                  item.id === secondConflictID
                    ? { ...item, effective_actions: [] }
                    : item,
                ),
              },
      );
    });

    await waitFor(() => {
      expect(
        screen.queryByRole("button", { name: /批量/u }),
      ).not.toBeInTheDocument();
    });
    expect(
      screen.queryByRole("checkbox", {
        name: `选择冲突 ${second.asset.display_name}`,
      }),
    ).not.toBeInTheDocument();
  });

  it("refetch 移除已处理项时保留 batch 逐项证据且不自动改写选择", async () => {
    const user = userEvent.setup();
    const conflicts = [
      conflict(primaryConflictID, "payments-api-01"),
      conflict(secondConflictID, "payments-api-02"),
    ];
    let refetches = 0;
    testServer.use(
      http.post(resolveConflictPath, ({ params }) => {
        const selected =
          conflicts.find(
            (item) => item.id === String(params.conflictId),
          ) ?? conflicts[0];
        return selected === undefined
          ? problem(403)
          : HttpResponse.json(mutationResult(selected), {
              headers: {
                ETag: `"asset-conflict:${selected.id}:v6"`,
                "X-Audit-ID": auditID,
                "X-Trace-ID": traceID,
              },
            });
      }),
    );
    const view = renderWorkbench({
      items: conflicts,
      page: { next_cursor: null },
    });
    for (const item of conflicts) {
      await user.click(
        await screen.findByRole("checkbox", {
          name: `选择冲突 ${item.asset.display_name}`,
        }),
      );
    }
    testServer.use(
      http.get(conflictListPath, () => {
        refetches += 1;
        return HttpResponse.json({
          items: [],
          page: { next_cursor: null },
        } satisfies AssetConflictPage);
      }),
    );
    view.onSearchChange.mockClear();
    await user.click(
      screen.getByRole("button", {
        name: "批量拒绝候选",
      }),
    );
    await user.type(
      screen.getByLabelText("审计原因代码"),
      "GOVERNANCE_REVIEWED",
    );
    await user.click(
      screen.getByRole("button", {
        name: "确认并记录决定",
      }),
    );

    expect(
      await screen.findByText("映射决定已记录"),
    ).toBeVisible();
    await waitFor(() => {
      expect(refetches).toBeGreaterThan(0);
      expect(
        screen.queryByRole("alertdialog"),
      ).not.toBeInTheDocument();
    });
    expect(screen.getByText("payments-api-01：成功")).toBeVisible();
    expect(screen.getByText("payments-api-02：成功")).toBeVisible();
    expect(
      view.onSearchChange.mock.calls.some(
        ([next]) => next.conflictId === undefined,
      ),
    ).toBe(false);
  });

  it("旧 403 在 refetch 等待期间失效后不关闭新 Scope", async () => {
    const user = userEvent.setup();
    let releaseRefetch: () => void = () => undefined;
    const refetchGate = new Promise<void>((resolve) => {
      releaseRefetch = resolve;
    });
    let refetchStarted = false;
    const view = renderWorkbench();
    await screen.findByRole("button", { name: "拒绝候选" });
    testServer.use(
      http.post(resolveConflictPath, () => problem(403)),
      http.get(conflictListPath, async () => {
        refetchStarted = true;
        await refetchGate;
        return HttpResponse.json(conflictPage);
      }),
    );

    await user.click(
      screen.getByRole("button", { name: "拒绝候选" }),
    );
    await user.type(
      screen.getByLabelText("审计原因代码"),
      "GOVERNANCE_REVIEWED",
    );
    await user.click(
      screen.getByRole("button", {
        name: "确认并记录决定",
      }),
    );
    await waitFor(() => {
      expect(refetchStarted).toBe(true);
    });

    view.setScope({
      workspaceId: workspaceID,
      environmentId: alternateEnvironmentID,
    });
    act(() => {
      releaseRefetch();
    });
    await waitFor(() => {
      expect(view.queryClient.isFetching()).toBe(0);
    });

    expect(
      await screen.findByRole("button", {
        name: "拒绝候选",
      }),
    ).toBeVisible();
    expect(
      screen.queryByText(
        /当前 Scope 的映射治理授权已被服务端拒绝/u,
      ),
    ).not.toBeInTheDocument();
  });

  it.each(["Scope", "URL"] as const)(
    "%s review context 变化后停止未发送的 batch 后项且不污染结果",
    async (transition) => {
      const user = userEvent.setup();
      const conflicts = [
        conflict(primaryConflictID, "payments-api-01"),
        conflict(secondConflictID, "payments-api-02"),
        conflict(thirdConflictID, "payments-api-03"),
      ];
      const calls: string[] = [];
      testServer.use(
        http.post(resolveConflictPath, async ({ params }) => {
          const conflictID = String(params.conflictId);
          calls.push(conflictID);
          await delay(80);
          const selected =
            conflicts.find((item) => item.id === conflictID) ??
            conflicts[0];
          if (selected === undefined) {
            return problem(403);
          }
          return HttpResponse.json(mutationResult(selected), {
            headers: {
              ETag: `"asset-conflict:${conflictID}:v6"`,
              "X-Audit-ID": auditID,
              "X-Trace-ID": traceID,
            },
          });
        }),
      );
      const view = renderWorkbench({
        items: conflicts,
        page: { next_cursor: null },
      });

      for (const item of conflicts) {
        await user.click(
          await screen.findByRole("checkbox", {
            name: `选择冲突 ${item.asset.display_name}`,
          }),
        );
      }
      await user.click(
        screen.getByRole("button", {
          name: "批量确认精确映射",
        }),
      );
      await completeConfirmExactForm(user);
      await user.click(
        screen.getByRole("button", {
          name: "确认并记录决定",
        }),
      );
      expect(
        await screen.findByText("正在逐项提交…"),
      ).toBeVisible();

      if (transition === "Scope") {
        view.setScope({
          workspaceId: workspaceID,
          environmentId: alternateEnvironmentID,
        });
      } else {
        view.rerender(
          <MappingWorkbenchPage
            search={defaultSearch({
              conflictId: secondConflictID,
            })}
            onSearchChange={view.onSearchChange}
          />,
        );
      }
      await delay(280);

      expect(calls).toEqual([primaryConflictID]);
      expect(
        screen.queryByText("映射决定已记录"),
      ).not.toBeInTheDocument();
      expect(screen.queryByText(auditID)).not.toBeInTheDocument();
      expect(
        screen.queryByRole("alertdialog"),
      ).not.toBeInTheDocument();
    },
  );

  it("键盘队列选择写回 conflictId 且保留其他筛选", async () => {
    const user = userEvent.setup();
    const second = conflict(secondConflictID, "payments-api-02");
    const { onSearchChange } = renderWorkbench({
      items: [baseConflict, second],
      page: { next_cursor: null },
    });
    const firstRow = await screen.findByRole("button", {
      name: /payments-api-01/u,
    });
    firstRow.focus();
    await user.keyboard("{ArrowDown}{Enter}");

    expect(onSearchChange).toHaveBeenCalledWith(
      expect.objectContaining({
        workspace: workspaceID,
        environment: environmentID,
        status: ["OPEN"],
        conflictId: secondConflictID,
      }),
    );
  });
});
