import type { QueryClient } from "@tanstack/react-query";

import type { ControlPlaneClient } from "@/shared/api/controlPlaneClient";
import {
  ControlPlaneProblemError,
  type ClientProblem,
} from "@/shared/api/problem";
import type { Scope } from "@/shared/api/queryKeys";
import type { components } from "@/shared/api/schema";

import {
  mappingListSearch,
  type MappingSearch,
} from "./mappingSearch";

export type AssetConflictPage =
  components["schemas"]["AssetConflictPage"];
export type AssetConflict =
  components["schemas"]["AssetConflictDetail"];
export type ResolveAssetConflictRequest =
  components["schemas"]["ResolveAssetConflictRequest"];
export type ConflictMutationResult =
  components["schemas"]["AssetConflictMutationResult"];

export type ConflictMutationResponse = {
  result: ConflictMutationResult;
  etag?: string;
  traceId?: string;
  auditId?: string;
};

export type ConflictBatchResult =
  | {
      conflict: AssetConflict;
      status: "success";
      response: ConflictMutationResponse;
    }
  | {
      conflict: AssetConflict;
      status: "failure";
      problem: ClientProblem;
    }
  | {
      conflict: AssetConflict;
      status: "stopped";
    };

export const mappingQueryKeys = {
  list: (scope: Scope, search: MappingSearch) =>
    [
      "asset-conflicts",
      scope.workspaceId,
      scope.environmentId,
      mappingListSearch(search),
    ] as const,
};

export async function listAssetConflicts(
  client: ControlPlaneClient,
  scope: Scope,
  search: MappingSearch,
  signal?: AbortSignal,
): Promise<AssetConflictPage> {
  const canonical = mappingListSearch(search);
  const response = await client.execute(
    "listAssetConflicts",
    {
      parameters: {
        path: { workspace_id: scope.workspaceId },
        query: {
          environment_id: scope.environmentId,
          ...(canonical.source === undefined
            ? {}
            : { source_id: canonical.source }),
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

export async function resolveAssetConflict(
  client: ControlPlaneClient,
  scope: Scope,
  conflict: AssetConflict,
  request: ResolveAssetConflictRequest,
): Promise<ConflictMutationResponse> {
  const response = await client.execute("resolveAssetConflict", {
    parameters: {
      path: {
        workspace_id: scope.workspaceId,
        conflict_id: conflict.id,
      },
      header: {
        "Idempotency-Key": crypto.randomUUID(),
        "If-Match": conflict.etag,
      },
    },
    requestBody: {
      content: { "application/json": request },
    },
  });
  return {
    result: response.data,
    ...(response.etag === undefined ? {} : { etag: response.etag }),
    ...(response.traceId === undefined
      ? {}
      : { traceId: response.traceId }),
    ...(response.auditId === undefined
      ? {}
      : { auditId: response.auditId }),
  };
}

export async function resolveConflictBatch(
  client: ControlPlaneClient,
  scope: Scope,
  conflicts: readonly AssetConflict[],
  request: ResolveAssetConflictRequest,
  onResult?: (results: readonly ConflictBatchResult[]) => void,
  shouldContinue?: () => boolean,
): Promise<ConflictBatchResult[]> {
  const results: ConflictBatchResult[] = [];
  for (let index = 0; index < conflicts.length; index += 1) {
    if (shouldContinue !== undefined && !shouldContinue()) {
      for (
        let stoppedIndex = index;
        stoppedIndex < conflicts.length;
        stoppedIndex += 1
      ) {
        const stopped = conflicts[stoppedIndex];
        if (stopped !== undefined) {
          results.push({ conflict: stopped, status: "stopped" });
        }
      }
      onResult?.([...results]);
      break;
    }
    const conflict = conflicts[index];
    if (conflict === undefined) {
      continue;
    }
    try {
      const response = await resolveAssetConflict(
        client,
        scope,
        conflict,
        request,
      );
      results.push({ conflict, status: "success", response });
      onResult?.([...results]);
    } catch (error) {
      results.push({
        conflict,
        status: "failure",
        problem: problemFromError(error),
      });
      for (
        let stoppedIndex = index + 1;
        stoppedIndex < conflicts.length;
        stoppedIndex += 1
      ) {
        const stopped = conflicts[stoppedIndex];
        if (stopped !== undefined) {
          results.push({ conflict: stopped, status: "stopped" });
        }
      }
      onResult?.([...results]);
      break;
    }
  }
  return results;
}

export async function invalidateMappingScope(
  queryClient: QueryClient,
  scope: Scope,
): Promise<void> {
  await queryClient.invalidateQueries({
    predicate: (query) =>
      query.queryKey[0] === "asset-conflicts" &&
      query.queryKey[1] === scope.workspaceId &&
      query.queryKey[2] === scope.environmentId,
  });
}

export function problemFromError(error: unknown): ClientProblem {
  if (error instanceof ControlPlaneProblemError) {
    return error.problem;
  }
  return {
    type: "about:blank",
    title: "映射工作台暂时不可用",
    status: 500,
    code: "unexpected_response",
    detail: "无法完成安全映射请求，请稍后重试。",
  };
}

export function isConflictProblem(
  problem: ClientProblem,
): boolean {
  return problem.status === 409;
}

export function isForbiddenProblem(problem: ClientProblem): boolean {
  return problem.status === 403;
}
