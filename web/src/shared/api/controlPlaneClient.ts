import {
  createContext,
  createElement,
  type PropsWithChildren,
  useContext,
  useMemo,
} from "react";

import type {
  OperationID,
  OperationInput,
  OperationResult,
} from "./operation";
import {
  ControlPlaneProblemError,
  problemSchema,
  safeTraceID,
  unexpectedResponseProblem,
} from "./problem";
import type { operations } from "./schema";

type Fetcher = (
  input: RequestInfo | URL,
  init?: RequestInit,
) => Promise<Response>;

type ClientOptions = {
  apiBasePath: "/api/v1";
  getAccessToken: () => Promise<string>;
  fetcher?: Fetcher;
};

export type ControlPlaneRequestOptions = {
  signal?: AbortSignal;
};

export type ControlPlaneAuthActions = {
  login: () => Promise<void>;
  reauthenticate: (returnURL: string) => Promise<void>;
  logout: () => Promise<void>;
};

export type ControlPlaneClient = ReturnType<
  typeof createControlPlaneClient
>;

type ControlPlaneRuntimeValue = {
  client: ControlPlaneClient;
  authActions: ControlPlaneAuthActions;
};

type ControlPlaneRuntimeProviderProps = PropsWithChildren<
  ControlPlaneRuntimeValue
>;

const ControlPlaneRuntimeContext = createContext<
  ControlPlaneRuntimeValue | undefined
>(undefined);

export function ControlPlaneRuntimeProvider({
  client,
  authActions,
  children,
}: ControlPlaneRuntimeProviderProps) {
  const runtime = useMemo<ControlPlaneRuntimeValue>(
    () => ({
      client,
      authActions: {
        login: () => authActions.login(),
        reauthenticate: (returnURL) =>
          authActions.reauthenticate(returnURL),
        logout: () => authActions.logout(),
      },
    }),
    [authActions, client],
  );
  return createElement(
    ControlPlaneRuntimeContext.Provider,
    { value: runtime },
    children,
  );
}

export function useControlPlaneClient(): ControlPlaneClient {
  return useControlPlaneRuntime().client;
}

export function useAuthActions(): ControlPlaneAuthActions {
  return useControlPlaneRuntime().authActions;
}

function useControlPlaneRuntime(): ControlPlaneRuntimeValue {
  const value = useContext(ControlPlaneRuntimeContext);
  if (value === undefined) {
    throw new Error("ControlPlaneRuntimeProvider is required");
  }
  return value;
}

type OperationDefinition = {
  method: "GET" | "POST" | "PATCH" | "DELETE";
  path: string;
  successStatus: 200 | 201 | 202 | 204 | readonly (200 | 201 | 202 | 204)[];
  workloadOnly?: true;
};

const operationRegistry: Record<keyof operations, OperationDefinition> = {
  getBrowserConfig: { method: "GET", path: "/browser-config", successStatus: 200 },
  getSession: { method: "GET", path: "/session", successStatus: 200 },
  getOverview: {
    method: "GET",
    path: "/workspaces/{workspace_id}/environments/{environment_id}/overview",
    successStatus: 200,
  },
  listAssets: {
    method: "GET",
    path: "/workspaces/{workspace_id}/environments/{environment_id}/assets",
    successStatus: 200,
  },
  createAsset: {
    method: "POST",
    path: "/workspaces/{workspace_id}/environments/{environment_id}/assets",
    successStatus: 201,
  },
  getAsset: {
    method: "GET",
    path: "/workspaces/{workspace_id}/environments/{environment_id}/assets/{asset_id}",
    successStatus: 200,
  },
  patchAsset: {
    method: "PATCH",
    path: "/workspaces/{workspace_id}/environments/{environment_id}/assets/{asset_id}",
    successStatus: 200,
  },
  quarantineAsset: {
    method: "POST",
    path: "/workspaces/{workspace_id}/environments/{environment_id}/assets/{asset_id}:quarantine",
    successStatus: 200,
  },
  retireAsset: {
    method: "POST",
    path: "/workspaces/{workspace_id}/environments/{environment_id}/assets/{asset_id}:retire",
    successStatus: 200,
  },
  listAssetRelations: {
    method: "GET",
    path: "/workspaces/{workspace_id}/environments/{environment_id}/asset-relations",
    successStatus: 200,
  },
  listServiceAssetBindings: {
    method: "GET",
    path: "/workspaces/{workspace_id}/environments/{environment_id}/service-asset-bindings",
    successStatus: 200,
  },
  createServiceAssetBinding: {
    method: "POST",
    path: "/workspaces/{workspace_id}/environments/{environment_id}/service-asset-bindings",
    successStatus: 201,
  },
  deleteServiceAssetBinding: {
    method: "DELETE",
    path: "/workspaces/{workspace_id}/environments/{environment_id}/service-asset-bindings/{binding_id}",
    successStatus: 204,
  },
  listAssetSources: {
    method: "GET",
    path: "/workspaces/{workspace_id}/asset-sources",
    successStatus: 200,
  },
  createAssetSource: {
    method: "POST",
    path: "/workspaces/{workspace_id}/asset-sources",
    successStatus: 201,
  },
  getAssetSource: {
    method: "GET",
    path: "/workspaces/{workspace_id}/asset-sources/{source_id}",
    successStatus: 200,
  },
  createAssetSourceRevision: {
    method: "POST",
    path: "/workspaces/{workspace_id}/asset-sources/{source_id}/revisions",
    successStatus: 201,
  },
  validateAssetSourceRevision: {
    method: "POST",
    path: "/workspaces/{workspace_id}/asset-sources/{source_id}/revisions/{revision}:validate",
    successStatus: [200, 202],
  },
  publishAssetSourceRevision: {
    method: "POST",
    path: "/workspaces/{workspace_id}/asset-sources/{source_id}/revisions/{revision}:publish",
    successStatus: 200,
  },
  disableAssetSource: {
    method: "POST",
    path: "/workspaces/{workspace_id}/asset-sources/{source_id}:disable",
    successStatus: 200,
  },
  syncAssetSource: {
    method: "POST",
    path: "/workspaces/{workspace_id}/asset-sources/{source_id}:sync",
    successStatus: 202,
  },
  createAssetSourceImport: {
    method: "POST",
    path: "/workspaces/{workspace_id}/asset-sources/{source_id}/imports",
    successStatus: 202,
  },
  createAssetSourceIngestionBatch: {
    method: "POST",
    path: "/workspaces/{workspace_id}/asset-sources/{source_id}/ingestion-batches",
    successStatus: 202,
    workloadOnly: true,
  },
  getAssetSourceRun: {
    method: "GET",
    path: "/workspaces/{workspace_id}/asset-source-runs/{run_id}",
    successStatus: 200,
  },
  listAssetConflicts: {
    method: "GET",
    path: "/workspaces/{workspace_id}/asset-conflicts",
    successStatus: 200,
  },
  resolveAssetConflict: {
    method: "POST",
    path: "/workspaces/{workspace_id}/asset-conflicts/{conflict_id}:resolve",
    successStatus: 200,
  },
};

type RuntimeInput = {
  parameters?: {
    path?: Record<string, unknown>;
    query?: Record<string, unknown>;
    header?: Record<string, unknown>;
  };
  requestBody?: {
    content?: {
      "application/json"?: unknown;
      "multipart/form-data"?: Record<string, unknown>;
    };
  };
};

export function createControlPlaneClient(options: ClientOptions) {
  const fetcher = options.fetcher ?? globalThis.fetch.bind(globalThis);

  return {
    async execute<K extends OperationID>(
      operation: K,
      input: OperationInput<K>,
      requestOptions: ControlPlaneRequestOptions = {},
    ): Promise<OperationResult<K>> {
      const definition = operationRegistry[operation];
      if (definition.workloadOnly === true) {
        throw new Error("Workload-only operation is unavailable to the OIDC browser client");
      }
      const runtimeInput = input as unknown as RuntimeInput;
      const path = renderPath(definition.path, runtimeInput.parameters?.path);
      const query = renderQuery(runtimeInput.parameters?.query);
      const token = await options.getAccessToken();
      if (token.trim() === "") {
        throw new Error("OIDC token unavailable");
      }
      const headers = new Headers({
        Accept: "application/json",
        Authorization: `Bearer ${token}`,
      });
      copyDeclaredHeaders(headers, runtimeInput.parameters?.header);
      const jsonBody = runtimeInput.requestBody?.content?.["application/json"];
      const multipartBody = runtimeInput.requestBody?.content?.["multipart/form-data"];
      if (jsonBody !== undefined && multipartBody !== undefined) {
        throw new Error("Operation request body media type is ambiguous");
      }
      const body =
        jsonBody === undefined
          ? multipartBody === undefined
            ? undefined
            : renderMultipartBody(multipartBody)
          : JSON.stringify(jsonBody);
      if (jsonBody !== undefined) {
        headers.set("Content-Type", "application/json");
      }
      const response = await fetcher(`${options.apiBasePath}${path}${query}`, {
        method: definition.method,
        headers,
        ...(body === undefined ? {} : { body }),
        ...(requestOptions.signal === undefined
          ? {}
          : { signal: requestOptions.signal }),
        cache: "no-store",
        credentials: "omit",
        redirect: "error",
      });
      if (!response.ok) {
        throw await responseProblem(response);
      }
      if (!acceptsSuccessStatus(definition.successStatus, response.status)) {
        throw new ControlPlaneProblemError(
          unexpectedResponseProblem(response.status, safeTraceID(response.headers)),
        );
      }
      const data = await successData(response);
      return {
        data,
        status: response.status,
        ...optionalHeader(response.headers, "ETag", "etag"),
        ...optionalHeader(response.headers, "X-Trace-ID", "traceId"),
        ...optionalHeader(response.headers, "Location", "location"),
        ...optionalHeader(response.headers, "X-Audit-ID", "auditId"),
        ...(response.headers.get("X-Idempotent-Replay") === null
          ? {}
          : {
              idempotentReplay:
                response.headers.get("X-Idempotent-Replay") === "true",
            }),
      } as OperationResult<K>;
    },
  };
}

function renderPath(
  template: string,
  parameters: Record<string, unknown> | undefined,
): string {
  return template.replace(/\{([a-z_]+)\}/g, (_match, name: string) => {
    const value = parameters?.[name];
    if (typeof value === "number") {
      if (!Number.isSafeInteger(value) || value <= 0) {
        throw new Error("Operation path parameters are incomplete");
      }
      return String(value);
    }
    if (typeof value !== "string" || value === "") {
      throw new Error("Operation path parameters are incomplete");
    }
    return encodeURIComponent(value);
  });
}

function renderMultipartBody(values: Record<string, unknown>): FormData {
  const body = new FormData();
  for (const [name, value] of Object.entries(values)) {
    if (typeof value === "string" || value instanceof Blob) {
      body.append(name, value);
      continue;
    }
    throw new Error("Multipart operation contains an unsupported field");
  }
  return body;
}

function acceptsSuccessStatus(
  declared: OperationDefinition["successStatus"],
  actual: number,
): boolean {
  return Array.isArray(declared)
    ? declared.some((status) => status === actual)
    : declared === actual;
}

function renderQuery(parameters: Record<string, unknown> | undefined): string {
  if (parameters === undefined) {
    return "";
  }
  const query = new URLSearchParams();
  for (const [name, value] of Object.entries(parameters)) {
    if (value === undefined) {
      continue;
    }
    if (Array.isArray(value)) {
      query.set(name, value.map(queryScalar).join(","));
      continue;
    }
    query.set(name, queryScalar(value));
  }
  const encoded = query.toString();
  return encoded === "" ? "" : `?${encoded}`;
}

function queryScalar(value: unknown): string {
  if (
    typeof value !== "string" &&
    typeof value !== "number" &&
    typeof value !== "boolean"
  ) {
    throw new Error("Operation query contains an unsupported value");
  }
  return String(value);
}

function copyDeclaredHeaders(
  target: Headers,
  input: Record<string, unknown> | undefined,
): void {
  for (const name of ["Idempotency-Key", "If-Match"] as const) {
    const value = input?.[name];
    if (typeof value === "string" && value !== "") {
      target.set(name, value);
    }
  }
}

async function responseProblem(response: Response): Promise<ControlPlaneProblemError> {
  const traceID = safeTraceID(response.headers);
  const contentType = response.headers.get("Content-Type")?.toLowerCase() ?? "";
  if (contentType.startsWith("application/problem+json")) {
    try {
      const text = await response.text();
      if (new TextEncoder().encode(text).length <= 16_384) {
        const parsed = problemSchema.safeParse(JSON.parse(text));
        if (
          parsed.success &&
          parsed.data.status === response.status &&
          (traceID === undefined || traceID === parsed.data.trace_id)
        ) {
          return new ControlPlaneProblemError(parsed.data);
        }
      }
    } catch {
      // The caller receives a closed unexpected_response projection below.
    }
  }
  return new ControlPlaneProblemError(
    unexpectedResponseProblem(response.status, traceID),
  );
}

async function successData(response: Response): Promise<unknown> {
  if (response.status === 204) {
    return undefined;
  }
  const contentType = response.headers.get("Content-Type")?.toLowerCase() ?? "";
  if (!contentType.startsWith("application/json")) {
    throw new ControlPlaneProblemError(
      unexpectedResponseProblem(response.status, safeTraceID(response.headers)),
    );
  }
  const text = await response.text();
  if (text === "" || new TextEncoder().encode(text).length > 4 * 1024 * 1024) {
    throw new ControlPlaneProblemError(
      unexpectedResponseProblem(response.status, safeTraceID(response.headers)),
    );
  }
  try {
    return JSON.parse(text) as unknown;
  } catch {
    throw new ControlPlaneProblemError(
      unexpectedResponseProblem(response.status, safeTraceID(response.headers)),
    );
  }
}

function optionalHeader<Key extends string>(
  headers: Headers,
  header: string,
  key: Key,
): Partial<Record<Key, string>> {
  const value = headers.get(header);
  return value === null ? {} : ({ [key]: value } as Record<Key, string>);
}
