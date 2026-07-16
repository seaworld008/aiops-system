import {
  QueryClient,
  QueryClientProvider,
} from "@tanstack/react-query";
import { act, renderHook } from "@testing-library/react";
import type { PropsWithChildren } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  type OperationPollAdapter,
  type UseOperationOptions,
  useOperation,
} from "./useOperation";

type Projection = {
  status: "RUNNING" | "SUCCEEDED" | "FAILED";
  stage: string;
};

const scope = {
  workspaceId: "33333333-3333-4333-8333-333333333333",
  environmentId: "44444444-4444-4444-8444-444444444444",
  kind: "asset-source-run",
  operationId: "55555555-5555-4555-8555-555555555555",
};

function wrapper() {
  const client = new QueryClient({
    defaultOptions: {
      queries: {
        retry: false,
        gcTime: 0,
      },
    },
  });
  return function TestProviders({ children }: PropsWithChildren) {
    return (
      <QueryClientProvider client={client}>{children}</QueryClientProvider>
    );
  };
}

function adapter(
  read: OperationPollAdapter<Projection>["read"],
): OperationPollAdapter<Projection> {
  return {
    read,
    isTerminal: (value) =>
      value.status === "SUCCEEDED" || value.status === "FAILED",
  };
}

function assertNoMutationSurface(
  value: OperationPollAdapter<Projection>,
) {
  const mutationOption: UseOperationOptions<Projection> = {
    ...scope,
    adapter: value,
    // @ts-expect-error polling options never accept an initiating mutation.
    initiatingMutation: vi.fn(),
  };
  const mutationRetryOption: UseOperationOptions<Projection> = {
    ...scope,
    adapter: value,
    // @ts-expect-error polling options never accept a mutation retry callback.
    retryMutation: vi.fn(),
  };
  void mutationOption;
  void mutationRetryOption;
}

void assertNoMutationSurface;

describe("useOperation", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    window.history.replaceState({}, "", "/asset-sources?workspace=w");
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
    vi.useRealTimers();
  });

  it("keeps the operation ID in the URL and stops permanently at a terminal state", async () => {
    const read = vi
      .fn<OperationPollAdapter<Projection>["read"]>()
      .mockResolvedValue({
        data: { status: "SUCCEEDED", stage: "COMPLETED" },
      });
    const { result } = renderHook(
      () => useOperation({ ...scope, adapter: adapter(read) }),
      { wrapper: wrapper() },
    );

    await vi.waitFor(() =>
      expect(result.current.data?.status).toBe("SUCCEEDED"),
    );
    expect(new URL(window.location.href).searchParams.get("operationId")).toBe(
      scope.operationId,
    );

    await act(async () => {
      await vi.advanceTimersByTimeAsync(60_000);
    });
    expect(read).toHaveBeenCalledTimes(1);
  });

  it("does not read again when visibility, focus or connectivity changes after terminal state", async () => {
    const read = vi
      .fn<OperationPollAdapter<Projection>["read"]>()
      .mockResolvedValue({
        data: { status: "SUCCEEDED", stage: "COMPLETED" },
      });
    const { result } = renderHook(
      () => useOperation({ ...scope, adapter: adapter(read) }),
      { wrapper: wrapper() },
    );
    await vi.waitFor(() =>
      expect(result.current.data?.status).toBe("SUCCEEDED"),
    );

    act(() => {
      Object.defineProperty(document, "visibilityState", {
        configurable: true,
        value: "hidden",
      });
      Object.defineProperty(navigator, "onLine", {
        configurable: true,
        value: false,
      });
      document.dispatchEvent(new Event("visibilitychange"));
      window.dispatchEvent(new Event("offline"));
    });
    act(() => {
      Object.defineProperty(document, "visibilityState", {
        configurable: true,
        value: "visible",
      });
      Object.defineProperty(navigator, "onLine", {
        configurable: true,
        value: true,
      });
      document.dispatchEvent(new Event("visibilitychange"));
      window.dispatchEvent(new Event("online"));
      window.dispatchEvent(new Event("focus"));
    });
    await act(async () => {
      await vi.advanceTimersByTimeAsync(60_000);
    });

    expect(read).toHaveBeenCalledTimes(1);
  });

  it("pauses while hidden or offline and resumes by reading on focus/online", async () => {
    const read = vi
      .fn<OperationPollAdapter<Projection>["read"]>()
      .mockResolvedValue({
        data: { status: "RUNNING", stage: "READING" },
        retryAfterMs: 2_000,
      });
    renderHook(() => useOperation({ ...scope, adapter: adapter(read) }), {
      wrapper: wrapper(),
    });
    await vi.waitFor(() => expect(read).toHaveBeenCalledTimes(1));

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
    expect(read).toHaveBeenCalledTimes(1);

    act(() => {
      Object.defineProperty(document, "visibilityState", {
        configurable: true,
        value: "visible",
      });
      document.dispatchEvent(new Event("visibilitychange"));
      window.dispatchEvent(new Event("focus"));
    });
    await vi.waitFor(() => expect(read).toHaveBeenCalledTimes(2));

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
    expect(read).toHaveBeenCalledTimes(2);

    act(() => {
      Object.defineProperty(navigator, "onLine", {
        configurable: true,
        value: true,
      });
      window.dispatchEvent(new Event("online"));
    });
    await vi.waitFor(() => expect(read).toHaveBeenCalledTimes(3));
  });

  it("honors Retry-After and caps the polling delay", async () => {
    const read = vi
      .fn<OperationPollAdapter<Projection>["read"]>()
      .mockResolvedValueOnce({
        data: { status: "RUNNING", stage: "WAITING" },
        retryAfterMs: 120_000,
      })
      .mockResolvedValue({
        data: { status: "SUCCEEDED", stage: "COMPLETED" },
      });
    renderHook(() => useOperation({ ...scope, adapter: adapter(read) }), {
      wrapper: wrapper(),
    });
    await vi.waitFor(() => expect(read).toHaveBeenCalledTimes(1));

    await act(async () => {
      await vi.advanceTimersByTimeAsync(29_999);
    });
    expect(read).toHaveBeenCalledTimes(1);
    await act(async () => {
      await vi.advanceTimersByTimeAsync(1);
    });
    expect(read).toHaveBeenCalledTimes(2);
  });
});
