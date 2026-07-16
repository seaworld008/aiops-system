import { useQuery } from "@tanstack/react-query";
import { useEffect, useState } from "react";

import { queryKeys } from "@/shared/api/queryKeys";

export type OperationPollContext = {
  workspaceId: string;
  environmentId: string;
  kind: string;
  operationId: string;
  signal: AbortSignal;
};

export type OperationPollResult<Projection> = {
  data: Projection;
  retryAfterMs?: number;
};

export type OperationPollAdapter<Projection> = {
  read: (
    context: OperationPollContext,
  ) => Promise<OperationPollResult<Projection>>;
  isTerminal: (projection: Projection) => boolean;
};

export type UseOperationOptions<Projection> = Omit<
  OperationPollContext,
  "signal"
> & {
  adapter: OperationPollAdapter<Projection>;
  enabled?: boolean;
};

const defaultPollMilliseconds = 2_000;
const maximumPollMilliseconds = 30_000;

export function useOperation<Projection>(
  options: UseOperationOptions<Projection>,
) {
  const [available, setAvailable] = useState(browserAvailable);

  useEffect(() => {
    const update = () => {
      setAvailable(browserAvailable());
    };
    document.addEventListener("visibilitychange", update);
    window.addEventListener("focus", update);
    window.addEventListener("online", update);
    window.addEventListener("offline", update);
    return () => {
      document.removeEventListener("visibilitychange", update);
      window.removeEventListener("focus", update);
      window.removeEventListener("online", update);
      window.removeEventListener("offline", update);
    };
  }, []);

  useEffect(() => {
    const url = new URL(window.location.href);
    if (url.searchParams.get("operationId") !== options.operationId) {
      url.searchParams.set("operationId", options.operationId);
      window.history.replaceState(window.history.state, "", url);
    }
  }, [options.operationId]);

  const query = useQuery({
    queryKey: queryKeys.operation(
      {
        workspaceId: options.workspaceId,
        environmentId: options.environmentId,
      },
      options.kind,
      options.operationId,
    ),
    queryFn: ({ signal }) =>
      options.adapter.read({
        workspaceId: options.workspaceId,
        environmentId: options.environmentId,
        kind: options.kind,
        operationId: options.operationId,
        signal,
      }),
    enabled: (current) => {
      const result = current.state.data;
      return (
        (options.enabled ?? true) &&
        available &&
        (result === undefined || !options.adapter.isTerminal(result.data))
      );
    },
    retry: false,
    refetchOnWindowFocus: false,
    refetchOnReconnect: false,
    refetchIntervalInBackground: false,
    networkMode: "online",
    refetchInterval: (current) => {
      if (!available) {
        return false;
      }
      const result = current.state.data;
      if (result !== undefined && options.adapter.isTerminal(result.data)) {
        return false;
      }
      const requested = result?.retryAfterMs;
      if (requested !== undefined && Number.isFinite(requested)) {
        return clampPollInterval(requested);
      }
      const failures = current.state.fetchFailureCount;
      return Math.min(
        defaultPollMilliseconds * 2 ** Math.min(failures, 4),
        maximumPollMilliseconds,
      );
    },
  });

  return {
    ...query,
    data: query.data?.data,
  };
}

function browserAvailable(): boolean {
  return document.visibilityState === "visible" && navigator.onLine;
}

function clampPollInterval(value: number): number {
  return Math.min(
    Math.max(Math.round(value), defaultPollMilliseconds),
    maximumPollMilliseconds,
  );
}
