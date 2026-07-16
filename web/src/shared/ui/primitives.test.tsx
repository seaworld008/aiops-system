import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import type { ClientProblem } from "@/shared/api/problem";

import { AbsoluteTime } from "./AbsoluteTime";
import { CursorPagination } from "./CursorPagination";
import { DataTable } from "./DataTable";
import { Drawer } from "./Drawer";
import { ETagConflictReview } from "./ETagConflictReview";
import { EffectiveActionGate } from "./EffectiveActionGate";
import { FilterBar } from "./FilterBar";
import { OperationTimeline } from "./OperationTimeline";
import { ProblemPanel } from "./ProblemPanel";
import { ReauthBoundary } from "./ReauthBoundary";
import { StatusBadge } from "./StatusBadge";

describe("shared UI primitives", () => {
  it("renders a semantic dense table, filters and cursor controls", async () => {
    const user = userEvent.setup();
    const onClear = vi.fn();
    const onPrevious = vi.fn();
    const onNext = vi.fn();
    render(
      <>
        <FilterBar activeCount={2} onClearAll={onClear}>
          <label>
            关键字
            <input name="search" />
          </label>
        </FilterBar>
        <DataTable
          ariaLabel="资产"
          columns={[
            {
              id: "name",
              header: "名称",
              cell: (row: { id: string; name: string }) => row.name,
            },
          ]}
          rows={[{ id: "asset-1", name: "payments-01" }]}
          rowKey={(row) => row.id}
        />
        <CursorPagination
          hasPrevious
          hasNext={false}
          onPrevious={onPrevious}
          onNext={onNext}
        />
      </>,
    );

    expect(screen.getByRole("table", { name: "资产" })).toBeVisible();
    expect(screen.getByRole("columnheader", { name: "名称" })).toBeVisible();
    expect(screen.getByRole("cell", { name: "payments-01" })).toBeVisible();
    await user.click(screen.getByRole("button", { name: "清除全部 2 个筛选" }));
    await user.click(screen.getByRole("button", { name: "上一页" }));
    expect(onClear).toHaveBeenCalledTimes(1);
    expect(onPrevious).toHaveBeenCalledTimes(1);
    expect(screen.getByRole("button", { name: "下一页" })).toBeDisabled();
  });

  it("keeps Drawer keyboard-dismissible with an accessible title", async () => {
    const user = userEvent.setup();
    const onOpenChange = vi.fn();
    render(
      <Drawer
        open
        title="资产详情"
        onOpenChange={onOpenChange}
      >
        <button type="button">详情操作</button>
      </Drawer>,
    );

    expect(screen.getByRole("dialog", { name: "资产详情" })).toBeVisible();
    await user.keyboard("{Escape}");
    expect(onOpenChange).toHaveBeenCalledWith(false);
  });

  it("gates actions only by effective_actions and keeps denied content explicit", () => {
    const { rerender } = render(
      <EffectiveActionGate
        effectiveActions={["RETIRE"]}
        action="EDIT_GOVERNANCE"
        fallback={<p>当前作用域无此操作权限</p>}
      >
        <button type="button">编辑治理信息</button>
      </EffectiveActionGate>,
    );
    expect(screen.queryByRole("button", { name: "编辑治理信息" })).not.toBeInTheDocument();
    expect(screen.getByText("当前作用域无此操作权限")).toBeVisible();

    rerender(
      <EffectiveActionGate
        effectiveActions={["EDIT_GOVERNANCE"]}
        action="EDIT_GOVERNANCE"
      >
        <button type="button">编辑治理信息</button>
      </EffectiveActionGate>,
    );
    expect(screen.getByRole("button", { name: "编辑治理信息" })).toBeEnabled();
  });

  it("renders independent Problem, status, timeline, conflict and reauth states", async () => {
    const user = userEvent.setup();
    const onReload = vi.fn();
    const onReauthenticate = vi.fn().mockResolvedValue(undefined);
    const problem: ClientProblem = {
      type: "about:blank",
      title: "Forbidden",
      status: 403,
      code: "asset_scope_forbidden",
      detail: "当前作用域不允许访问此资源。",
      trace_id: "1".repeat(32),
    };
    render(
      <>
        <ProblemPanel problem={problem} />
        <StatusBadge tone="warning">需要复核</StatusBadge>
        <OperationTimeline
          items={[
            {
              id: "accepted",
              label: "请求已接受",
              status: "complete",
              timestamp: "2026-07-17T00:00:00Z",
            },
            {
              id: "running",
              label: "正在验证",
              status: "current",
            },
          ]}
        />
        <ETagConflictReview
          clientVersion="v1"
          serverVersion="v2"
          diffRows={[
            {
              field: "display_name",
              submittedValue: "payments-new",
              serverValue: "payments-current",
            },
          ]}
          onReload={onReload}
        />
        <ReauthBoundary
          required
          onReauthenticate={onReauthenticate}
        >
          <button type="button">发布修订</button>
        </ReauthBoundary>
      </>,
    );

    expect(screen.getByRole("alert")).toHaveTextContent("asset_scope_forbidden");
    expect(screen.getByRole("alert")).toHaveTextContent("1".repeat(32));
    expect(screen.getByText("需要复核")).toHaveAccessibleName(/警告/);
    expect(screen.getByText("请求已接受")).toBeVisible();
    expect(screen.getByText("正在验证")).toBeVisible();
    expect(screen.getByRole("columnheader", { name: "字段" })).toBeVisible();
    expect(screen.getByRole("columnheader", { name: "提交值" })).toBeVisible();
    expect(screen.getByRole("columnheader", { name: "服务端值" })).toBeVisible();
    expect(screen.getByRole("cell", { name: "display_name" })).toBeVisible();
    expect(screen.getByRole("cell", { name: "payments-new" })).toBeVisible();
    expect(screen.getByRole("cell", { name: "payments-current" })).toBeVisible();
    await user.click(screen.getByRole("button", { name: "重新加载并审阅" }));
    expect(onReload).toHaveBeenCalledTimes(1);
    expect(screen.queryByRole("button", { name: "发布修订" })).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "重新认证" }));
    expect(onReauthenticate).toHaveBeenCalledTimes(1);
  });

  it("shows a closed error and allows retry when reauthentication is rejected", async () => {
    const user = userEvent.setup();
    const onReauthenticate = vi
      .fn()
      .mockRejectedValue(new Error("identity provider unavailable"));
    render(
      <ReauthBoundary
        required
        onReauthenticate={onReauthenticate}
      >
        <button type="button">发布修订</button>
      </ReauthBoundary>,
    );

    await user.click(screen.getByRole("button", { name: "重新认证" }));

    expect(await screen.findByRole("alert")).toHaveTextContent(
      "重新认证失败，请重试",
    );
    expect(screen.getByRole("button", { name: "重新认证" })).toBeEnabled();
    expect(screen.queryByRole("button", { name: "发布修订" })).not.toBeInTheDocument();
  });

  it("provides machine-readable and zoned absolute time", () => {
    render(<AbsoluteTime value="2026-07-17T00:00:00Z" />);
    const time = screen.getByRole("time");
    expect(time).toHaveAttribute("datetime", "2026-07-17T00:00:00.000Z");
    expect(time).toHaveAttribute("title", expect.stringContaining("2026"));
  });
});
