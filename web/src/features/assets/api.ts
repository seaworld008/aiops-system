import type { QueryClient } from "@tanstack/react-query";

import type { ControlPlaneClient } from "@/shared/api/controlPlaneClient";
import {
  ControlPlaneProblemError,
  type ClientProblem,
} from "@/shared/api/problem";
import type { Scope } from "@/shared/api/queryKeys";
import type { components } from "@/shared/api/schema";

import {
  canonicalAssetListSearch,
  type AssetSearch,
} from "./assetSearch";

export type AssetPage = components["schemas"]["AssetPage"];
export type AssetDetail = components["schemas"]["AssetDetail"];
export type AssetSourcePage = components["schemas"]["AssetSourcePage"];
export type AssetRelationPage = components["schemas"]["AssetRelationPage"];
export type CreateAssetRequest =
  components["schemas"]["CreateAssetRequest"];
export type PatchAssetRequest =
  components["schemas"]["PatchAssetRequest"];
export type TransitionAssetRequest =
  components["schemas"]["TransitionAssetRequest"];
export type AssetMutationResult =
  components["schemas"]["AssetMutationResult"];

export type AssetDetailResult = {
  asset: AssetDetail;
  etag?: string;
  traceId?: string;
};

export type AssetMutationResponse = {
  result: AssetMutationResult;
  etag?: string;
  traceId?: string;
  auditId?: string;
};

export const assetQueryKeys = {
  list: (scope: Scope, search: AssetSearch) =>
    [
      "assets",
      scope.workspaceId,
      scope.environmentId,
      canonicalAssetListSearch(search),
    ] as const,
  detail: (scope: Scope, assetId: string) =>
    [
      "asset-detail",
      scope.workspaceId,
      scope.environmentId,
      assetId,
    ] as const,
  sourceEligibility: (scope: Scope) =>
    [
      "asset-source-eligibility",
      scope.workspaceId,
      scope.environmentId,
      "manual_asset_create",
    ] as const,
  relations: (scope: Scope, assetId: string) =>
    [
      "asset-relations",
      scope.workspaceId,
      scope.environmentId,
      assetId,
    ] as const,
};

export async function listAssets(
  client: ControlPlaneClient,
  scope: Scope,
  search: AssetSearch,
  signal?: AbortSignal,
): Promise<AssetPage> {
  const canonical = canonicalAssetListSearch(search);
  const response = await client.execute(
    "listAssets",
    {
      parameters: {
        path: {
          workspace_id: scope.workspaceId,
          environment_id: scope.environmentId,
        },
        query: {
          ...(canonical.q === undefined
            ? {}
            : { search: canonical.q }),
          ...(canonical.service === undefined
            ? {}
            : { service_id: canonical.service }),
          ...(canonical.kind.length === 0
            ? {}
            : { kinds: canonical.kind }),
          ...(canonical.source.length === 0
            ? {}
            : { source_ids: canonical.source }),
          ...(canonical.lifecycle.length === 0
            ? {}
            : { lifecycles: canonical.lifecycle }),
          ...(canonical.mapping.length === 0
            ? {}
            : { mapping_statuses: canonical.mapping }),
          ...(canonical.criticality.length === 0
            ? {}
            : { criticalities: canonical.criticality }),
          ...(canonical.dataClassification.length === 0
            ? {}
            : {
                data_classifications: canonical.dataClassification,
              }),
          sort: canonical.sort,
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

export async function getAsset(
  client: ControlPlaneClient,
  scope: Scope,
  assetId: string,
  signal?: AbortSignal,
): Promise<AssetDetailResult> {
  const response = await client.execute(
    "getAsset",
    {
      parameters: {
        path: {
          workspace_id: scope.workspaceId,
          environment_id: scope.environmentId,
          asset_id: assetId,
        },
      },
    },
    signal === undefined ? {} : { signal },
  );
  return {
    asset: response.data,
    ...(response.etag === undefined ? {} : { etag: response.etag }),
    ...(response.traceId === undefined
      ? {}
      : { traceId: response.traceId }),
  };
}

export async function listManualAssetSources(
  client: ControlPlaneClient,
  scope: Scope,
  signal?: AbortSignal,
): Promise<AssetSourcePage> {
  const response = await client.execute(
    "listAssetSources",
    {
      parameters: {
        path: { workspace_id: scope.workspaceId },
        query: {
          usage: "manual_asset_create",
          environment_id: scope.environmentId,
        },
      },
    },
    signal === undefined ? {} : { signal },
  );
  return response.data;
}

export async function listAssetRelations(
  client: ControlPlaneClient,
  scope: Scope,
  assetId: string,
  signal?: AbortSignal,
): Promise<AssetRelationPage> {
  const response = await client.execute(
    "listAssetRelations",
    {
      parameters: {
        path: {
          workspace_id: scope.workspaceId,
          environment_id: scope.environmentId,
        },
        query: { asset_id: assetId },
      },
    },
    signal === undefined ? {} : { signal },
  );
  return response.data;
}

export async function createAsset(
  client: ControlPlaneClient,
  scope: Scope,
  request: CreateAssetRequest,
): Promise<AssetMutationResponse> {
  const response = await client.execute("createAsset", {
    parameters: {
      path: {
        workspace_id: scope.workspaceId,
        environment_id: scope.environmentId,
      },
      header: { "Idempotency-Key": crypto.randomUUID() },
    },
    requestBody: { content: { "application/json": request } },
  });
  return mutationResponse(response);
}

export async function patchAsset(
  client: ControlPlaneClient,
  scope: Scope,
  assetId: string,
  etag: string,
  request: PatchAssetRequest,
): Promise<AssetMutationResponse> {
  const response = await client.execute("patchAsset", {
    parameters: {
      path: {
        workspace_id: scope.workspaceId,
        environment_id: scope.environmentId,
        asset_id: assetId,
      },
      header: {
        "Idempotency-Key": crypto.randomUUID(),
        "If-Match": etag,
      },
    },
    requestBody: { content: { "application/json": request } },
  });
  return mutationResponse(response);
}

export async function transitionAsset(
  client: ControlPlaneClient,
  operation: "quarantineAsset" | "retireAsset",
  scope: Scope,
  assetId: string,
  etag: string,
  request: TransitionAssetRequest,
): Promise<AssetMutationResponse> {
  const input = {
    parameters: {
      path: {
        workspace_id: scope.workspaceId,
        environment_id: scope.environmentId,
        asset_id: assetId,
      },
      header: {
        "Idempotency-Key": crypto.randomUUID(),
        "If-Match": etag,
      },
    },
    requestBody: { content: { "application/json": request } },
  };
  const response =
    operation === "quarantineAsset"
      ? await client.execute("quarantineAsset", input)
      : await client.execute("retireAsset", input);
  return mutationResponse(response);
}

export async function invalidateAssetScope(
  queryClient: QueryClient,
  scope: Scope,
): Promise<void> {
  const permittedDomains = new Set([
    "assets",
    "asset-detail",
    "asset-source-eligibility",
    "asset-relations",
  ]);
  await queryClient.invalidateQueries({
    predicate: (query) =>
      permittedDomains.has(String(query.queryKey[0])) &&
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
    title: "资产目录暂时不可用",
    status: 500,
    code: "unexpected_response",
    detail: "无法读取安全资产投影，请稍后重试。",
  };
}

export function isVersionConflict(error: unknown): boolean {
  return (
    error instanceof ControlPlaneProblemError &&
    error.problem.status === 409 &&
    error.problem.code === "version_conflict"
  );
}

export function isSensitiveAssetLabelKey(key: string): boolean {
  const normalized = key.toLowerCase().replace(/[^a-z0-9]/gu, "");
  return [
    "secret",
    "token",
    "password",
    "credential",
    "dsn",
    "endpoint",
    "header",
    "body",
    "command",
    "script",
    "sql",
    "rawjson",
    "privatekey",
    "pem",
    "vaultpath",
    "authorization",
  ].some((term) => normalized.includes(term));
}

function mutationResponse(response: {
  data: AssetMutationResult;
  etag?: string;
  traceId?: string;
  auditId?: string;
}): AssetMutationResponse {
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
