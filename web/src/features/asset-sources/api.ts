import type { ControlPlaneClient } from "@/shared/api/controlPlaneClient";
import {
  ControlPlaneProblemError,
  type ClientProblem,
} from "@/shared/api/problem";
import type { Scope } from "@/shared/api/queryKeys";
import type { components } from "@/shared/api/schema";
import type { OperationPollAdapter } from "@/shared/operations/useOperation";

import {
  sourceListSearch,
  type SourceSearch,
} from "./sourceSearch";

export type AssetSourcePage =
  components["schemas"]["AssetSourcePage"];
export type AssetSourceDetail =
  components["schemas"]["AssetSourceDetail"];
export type AssetSourceRun =
  components["schemas"]["AssetSourceRun"];
export type AssetSourceSummary =
  components["schemas"]["AssetSourceSummary"];
export type SourceRunCounts =
  components["schemas"]["SourceRunCounts"];

export const sourceQueryKeys = {
  list: (scope: Scope, search: SourceSearch) =>
    [
      "asset-sources",
      scope.workspaceId,
      scope.environmentId,
      sourceListSearch(search),
    ] as const,
  detail: (scope: Scope, sourceId: string) =>
    [
      "asset-source-detail",
      scope.workspaceId,
      scope.environmentId,
      sourceId,
    ] as const,
};

export async function listAssetSources(
  client: ControlPlaneClient,
  workspaceId: string,
  search: SourceSearch,
  signal?: AbortSignal,
): Promise<AssetSourcePage> {
  const canonical = sourceListSearch(search);
  const response = await client.execute(
    "listAssetSources",
    {
      parameters: {
        path: { workspace_id: workspaceId },
        query: {
          ...(canonical.kind.length === 0
            ? {}
            : { kinds: canonical.kind }),
          ...(canonical.status.length === 0
            ? {}
            : { statuses: canonical.status }),
          limit: 50,
          ...(canonical.cursor === undefined
            ? {}
            : { cursor: canonical.cursor }),
        },
      },
    },
    signal === undefined ? {} : { signal },
  );
  return response.data;
}

export async function getAssetSource(
  client: ControlPlaneClient,
  workspaceId: string,
  sourceId: string,
  signal?: AbortSignal,
): Promise<AssetSourceDetail> {
  const response = await client.execute(
    "getAssetSource",
    {
      parameters: {
        path: {
          workspace_id: workspaceId,
          source_id: sourceId,
        },
      },
    },
    signal === undefined ? {} : { signal },
  );
  return response.data;
}

export function sourceRunPollAdapter(
  client: ControlPlaneClient,
  expectedSourceId?: string,
): OperationPollAdapter<AssetSourceRun> {
  return {
    async read(context) {
      const response = await client.execute(
        "getAssetSourceRun",
        {
          parameters: {
            path: {
              workspace_id: context.workspaceId,
              run_id: context.operationId,
            },
          },
        },
        { signal: context.signal },
      );
      return {
        data: response.data,
        retryAfterMs: 2_000,
      };
    },
    isTerminal: (run) =>
      isTerminalSourceRun(run.status) ||
      (expectedSourceId !== undefined &&
        run.source_id !== expectedSourceId),
  };
}

export function isTerminalSourceRun(
  status: components["schemas"]["RunStatus"],
): boolean {
  return (
    status === "SUCCEEDED" ||
    status === "PARTIAL" ||
    status === "FAILED" ||
    status === "CANCELLED"
  );
}

export function sourceProblemFromError(error: unknown): ClientProblem {
  if (error instanceof ControlPlaneProblemError) {
    return error.problem;
  }
  return {
    type: "about:blank",
    title: "发现来源暂时不可用",
    status: 500,
    code: "unexpected_response",
    detail: "无法读取安全来源投影，请稍后重试。",
  };
}
