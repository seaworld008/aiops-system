import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { describe, expect, it, vi } from "vitest";

import { createControlPlaneClient } from "./controlPlaneClient";
import type { OperationID } from "./operation";

const workspaceID = "33333333-3333-4333-8333-333333333333";
const environmentID = "44444444-4444-4444-8444-444444444444";
const sourceID = "55555555-5555-4555-8555-555555555555";

function assertCompileTimeContract(
  client: ReturnType<typeof createControlPlaneClient>,
) {
  // @ts-expect-error operation IDs are the generated closed union.
  void client.execute("deleteEverything", { parameters: {} });
  // @ts-expect-error listAssets requires both generated path parameters.
  void client.execute("listAssets", { parameters: { path: { workspace_id: workspaceID } } });
  // @ts-expect-error getSession has no request body.
  void client.execute("getSession", { parameters: {}, requestBody: { content: { "application/json": {} } } });
  void client.execute(
    "getSession",
    { parameters: {} },
    { signal: new AbortController().signal },
  );
  // @ts-expect-error request options are closed and accept only AbortSignal.
  void client.execute("getSession", { parameters: {} }, { headers: { "X-Unsafe": "value" } });
  void client.execute("getSession", { parameters: {} }).then((result) => {
    // @ts-expect-error Session success data does not expose AssetPage fields.
    void result.data.items;
  });
}

void assertCompileTimeContract;

const controlPlaneOperationIDs = {
  getSession: true,
  listAssets: true,
  createAsset: true,
  getAsset: true,
  patchAsset: true,
  quarantineAsset: true,
  retireAsset: true,
  listAssetRelations: true,
  listServiceAssetBindings: true,
  createServiceAssetBinding: true,
  deleteServiceAssetBinding: true,
  listAssetSources: true,
  createAssetSource: true,
  getAssetSource: true,
  createAssetSourceRevision: true,
  validateAssetSourceRevision: true,
  publishAssetSourceRevision: true,
  disableAssetSource: true,
  syncAssetSource: true,
  createAssetSourceImport: true,
  createAssetSourceIngestionBatch: true,
  getAssetSourceRun: true,
  listAssetConflicts: true,
  resolveAssetConflict: true,
} satisfies Record<OperationID, true>;

describe("createControlPlaneClient", () => {
  it("matches every authenticated OpenAPI operation ID to its exact method and path", async () => {
    const openAPI = parseOpenAPIOperations(
      readFileSync(
        resolve(process.cwd(), "../api/openapi/control-plane-v1.yaml"),
        "utf8",
      ),
    );
    expect(openAPI.get("getBrowserConfig")).toMatchObject({
      method: "GET",
      path: "/api/v1/browser-config",
      successStatus: 200,
    });
    const expectedIDs = Object.keys(controlPlaneOperationIDs).sort();
    const actualIDs = [...openAPI.keys()]
      .filter((operation) => operation !== "getBrowserConfig")
      .sort();
    expect(actualIDs).toEqual(expectedIDs);

    for (const operation of expectedIDs) {
      const contract = openAPI.get(operation);
      expect(contract).toBeDefined();
      if (contract === undefined) {
        continue;
      }
      const fetcher = vi.fn().mockResolvedValue(
        contract.successStatus === 204
          ? new Response(null, { status: 204 })
          : new Response("{}", {
              status: contract.successStatus,
              headers: { "Content-Type": "application/json" },
            }),
      );
      const getAccessToken = vi.fn().mockResolvedValue("ephemeral-token");
      const client = createControlPlaneClient({
        apiBasePath: "/api/v1",
        getAccessToken,
        fetcher,
      });
      const pathParameters: Record<string, string | number> = {};
      for (const match of contract.path.matchAll(/\{([a-z_]+)\}/g)) {
        const name = match[1];
        if (name !== undefined) {
          pathParameters[name] =
            name === "revision"
              ? 1
              : "55555555-5555-4555-8555-555555555555";
        }
      }
      const input = {
        parameters: { path: pathParameters },
        ...(operation === "createAssetSourceImport"
          ? {
              requestBody: {
                content: {
                  "multipart/form-data": {
                    file: "csv-bytes",
                    detached_signature: "detached-signature",
                  },
                },
              },
            }
          : contract.method === "POST" || contract.method === "PATCH"
          ? {
              requestBody: {
                content: { "application/json": {} },
              },
            }
          : {}),
      };
      if (operation === "createAssetSourceIngestionBatch") {
        await expect(
          (
            client.execute as unknown as (
              operation: OperationID,
              input: unknown,
            ) => Promise<unknown>
          )(operation, input),
        ).rejects.toThrow("Workload-only operation");
        expect(getAccessToken).not.toHaveBeenCalled();
        expect(fetcher).not.toHaveBeenCalled();
        continue;
      }
      await (
        client.execute as unknown as (
          operation: OperationID,
          input: unknown,
        ) => Promise<unknown>
      )(operation as OperationID, input);

      const expectedPath = contract.path.replace(
        /\{([a-z_]+)\}/g,
        (_match, name: string) =>
          name === "revision"
            ? "1"
            : "55555555-5555-4555-8555-555555555555",
      );
      expect(fetcher).toHaveBeenCalledWith(
        expectedPath,
        expect.objectContaining({ method: contract.method }),
      );
      if (operation === "createAssetSourceImport") {
        const request = fetcher.mock.calls[0]?.[1] as RequestInit | undefined;
        expect(request?.body).toBeInstanceOf(FormData);
        expect(new Headers(request?.headers).get("Content-Type")).toBeNull();
      }
    }
  });

  it("accepts both synchronous and queued statuses declared for Source validation", async () => {
    const fetcher = vi.fn().mockResolvedValue(
      new Response("{}", {
        status: 202,
        headers: { "Content-Type": "application/json" },
      }),
    );
    const client = createControlPlaneClient({
      apiBasePath: "/api/v1",
      getAccessToken: vi.fn().mockResolvedValue("ephemeral-token"),
      fetcher,
    });

    const result = await client.execute("validateAssetSourceRevision", {
      parameters: {
        path: { workspace_id: workspaceID, source_id: sourceID, revision: 1 },
        header: {
          "Idempotency-Key": "source:validate-1",
          "If-Match": `"asset-source-revision:${sourceID}:r1:sv3:rv1"`,
        },
      },
      requestBody: { content: { "application/json": {} } },
    });

    expect(result.status).toBe(202);
    expect(fetcher).toHaveBeenCalledWith(
      `/api/v1/workspaces/${workspaceID}/asset-sources/${sourceID}/revisions/1:validate`,
      expect.objectContaining({ method: "POST" }),
    );
  });

  it("refreshes the token and executes a generated method/path with safe fetch options", async () => {
    const getAccessToken = vi.fn().mockResolvedValue("ephemeral-token");
    const fetcher = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({
          items: [],
          page: { next_cursor: null },
          effective_actions: [],
        }),
        {
          status: 200,
          headers: {
            "Content-Type": "application/json",
            ETag: '"asset:list:v1"',
            "X-Trace-ID": "0".repeat(32),
          },
        },
      ),
    );
    const client = createControlPlaneClient({
      apiBasePath: "/api/v1",
      getAccessToken,
      fetcher,
    });

    const result = await client.execute("listAssets", {
      parameters: {
        path: {
          workspace_id: workspaceID,
          environment_id: environmentID,
        },
        query: {
          search: "payments",
          kinds: ["LINUX_VM"],
          limit: 50,
        },
      },
    });

    expect(result.data.items).toEqual([]);
    expect(result.etag).toBe('"asset:list:v1"');
    expect(getAccessToken).toHaveBeenCalledTimes(1);
    expect(fetcher).toHaveBeenCalledWith(
      `/api/v1/workspaces/${workspaceID}/environments/${environmentID}/assets?search=payments&kinds=LINUX_VM&limit=50`,
      expect.objectContaining({
        method: "GET",
        cache: "no-store",
        credentials: "omit",
        redirect: "error",
      }),
    );
    const request = fetcher.mock.calls[0]?.[1] as RequestInit | undefined;
    const headers = new Headers(request?.headers);
    expect(headers.get("Authorization")).toBe("Bearer ephemeral-token");
    expect(headers.get("Accept")).toBe("application/json");
  });

  it("passes the same AbortSignal to fetch and rejects when the caller aborts", async () => {
    const controller = new AbortController();
    const fetcher = vi.fn(
      (_input: RequestInfo | URL, init?: RequestInit) =>
        new Promise<Response>((_resolve, reject) => {
          init?.signal?.addEventListener(
            "abort",
            () => {
              reject(new DOMException("The operation was aborted", "AbortError"));
            },
            { once: true },
          );
        }),
    );
    const client = createControlPlaneClient({
      apiBasePath: "/api/v1",
      getAccessToken: vi.fn().mockResolvedValue("ephemeral-token"),
      fetcher,
    });

    const request = client.execute(
      "getSession",
      { parameters: {} },
      { signal: controller.signal },
    );
    await vi.waitFor(() => expect(fetcher).toHaveBeenCalledTimes(1));
    expect(fetcher.mock.calls[0]?.[1]?.signal).toBe(controller.signal);

    controller.abort();

    await expect(request).rejects.toMatchObject({ name: "AbortError" });
  });

  it("sends only generated declared mutation headers and a JSON body", async () => {
    const fetcher = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({
          asset: {},
          mutation_receipt: {},
        }),
        {
          status: 201,
          headers: { "Content-Type": "application/json" },
        },
      ),
    );
    const client = createControlPlaneClient({
      apiBasePath: "/api/v1",
      getAccessToken: vi.fn().mockResolvedValue("ephemeral-token"),
      fetcher,
    });

    await client.execute("createAsset", {
      parameters: {
        path: {
          workspace_id: workspaceID,
          environment_id: environmentID,
        },
        header: {
          "Idempotency-Key": "create-asset-1",
        },
      },
      requestBody: {
        content: {
          "application/json": {
            source_id: "55555555-5555-4555-8555-555555555555",
            kind: "LINUX_VM",
            external_id: "host-1",
            display_name: "payments-01",
            owner_group: null,
            criticality: "HIGH",
            data_classification: "INTERNAL",
            labels: [],
          },
        },
      },
    });

    const request = fetcher.mock.calls[0]?.[1] as RequestInit | undefined;
    const headers = new Headers(request?.headers);
    expect(headers.get("Idempotency-Key")).toBe("create-asset-1");
    expect(headers.get("If-Match")).toBeNull();
    expect(headers.get("Content-Type")).toBe("application/json");
    expect(request?.body).toBeTypeOf("string");
  });

  it("projects a validated Problem and never logs raw detail, body, query or token", async () => {
    const consoleError = vi.spyOn(console, "error").mockImplementation(() => undefined);
    const fetcher = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({
          type: "about:blank",
          title: "Forbidden",
          status: 403,
          code: "asset_scope_forbidden",
          detail: "private external_id and upstream payload",
          trace_id: "1".repeat(32),
        }),
        {
          status: 403,
          headers: {
            "Content-Type": "application/problem+json",
            "X-Trace-ID": "1".repeat(32),
          },
        },
      ),
    );
    const client = createControlPlaneClient({
      apiBasePath: "/api/v1",
      getAccessToken: vi.fn().mockResolvedValue("secret-token"),
      fetcher,
    });

    await expect(
      client.execute("getSession", { parameters: {} }),
    ).rejects.toMatchObject({
      problem: {
        code: "asset_scope_forbidden",
        trace_id: "1".repeat(32),
      },
    });
    expect(consoleError).not.toHaveBeenCalled();
  });

  it("turns malformed errors into an unexpected response using only the trace header", async () => {
    const fetcher = vi.fn().mockResolvedValue(
      new Response("upstream endpoint https://private.invalid token=secret", {
        status: 502,
        headers: {
          "Content-Type": "text/plain",
          "X-Trace-ID": "2".repeat(32),
        },
      }),
    );
    const client = createControlPlaneClient({
      apiBasePath: "/api/v1",
      getAccessToken: vi.fn().mockResolvedValue("secret-token"),
      fetcher,
    });

    await expect(
      client.execute("getSession", { parameters: {} }),
    ).rejects.toMatchObject({
      problem: {
        code: "unexpected_response",
        trace_id: "2".repeat(32),
      },
    });
  });

  it("rejects undeclared 2xx statuses and mismatched header/body trace IDs", async () => {
    const undeclared = createControlPlaneClient({
      apiBasePath: "/api/v1",
      getAccessToken: vi.fn().mockResolvedValue("secret-token"),
      fetcher: vi.fn().mockResolvedValue(
        new Response("{}", {
          status: 202,
          headers: {
            "Content-Type": "application/json",
            "X-Trace-ID": "3".repeat(32),
          },
        }),
      ),
    });
    await expect(
      undeclared.execute("getSession", { parameters: {} }),
    ).rejects.toMatchObject({
      problem: { code: "unexpected_response", trace_id: "3".repeat(32) },
    });

    const mismatchedTrace = createControlPlaneClient({
      apiBasePath: "/api/v1",
      getAccessToken: vi.fn().mockResolvedValue("secret-token"),
      fetcher: vi.fn().mockResolvedValue(
        new Response(
          JSON.stringify({
            type: "about:blank",
            title: "Forbidden",
            status: 403,
            code: "asset_scope_forbidden",
            detail: "Safe detail",
            trace_id: "4".repeat(32),
          }),
          {
            status: 403,
            headers: {
              "Content-Type": "application/problem+json",
              "X-Trace-ID": "5".repeat(32),
            },
          },
        ),
      ),
    });
    await expect(
      mismatchedTrace.execute("getSession", { parameters: {} }),
    ).rejects.toMatchObject({
      problem: { code: "unexpected_response", trace_id: "5".repeat(32) },
    });
  });
});

type ParsedOperation = {
  method: "GET" | "POST" | "PATCH" | "DELETE";
  path: string;
  successStatus: number;
};

function parseOpenAPIOperations(source: string): Map<string, ParsedOperation> {
  const result = new Map<string, ParsedOperation>();
  let currentPath: string | undefined;
  let currentMethod: ParsedOperation["method"] | undefined;
  let currentOperation: string | undefined;
  for (const line of source.split("\n")) {
    const pathMatch = /^ {2}(\/api\/v1\/.*):$/.exec(line);
    if (pathMatch?.[1] !== undefined) {
      currentPath = pathMatch[1];
      currentMethod = undefined;
      currentOperation = undefined;
      continue;
    }
    const methodMatch = /^ {4}(get|post|patch|delete):$/.exec(line);
    if (methodMatch?.[1] !== undefined) {
      currentMethod = methodMatch[1].toUpperCase() as ParsedOperation["method"];
      currentOperation = undefined;
      continue;
    }
    const operationMatch = /^ {6}operationId: ([A-Za-z0-9]+)$/.exec(line);
    if (
      operationMatch?.[1] !== undefined &&
      currentPath !== undefined &&
      currentMethod !== undefined
    ) {
      currentOperation = operationMatch[1];
      continue;
    }
    const statusMatch = /^ {8}"([0-9]{3})":$/.exec(line);
    if (
      statusMatch?.[1] !== undefined &&
      currentOperation !== undefined &&
      currentPath !== undefined &&
      currentMethod !== undefined
    ) {
      const status = Number(statusMatch[1]);
      if (status >= 200 && status <= 299 && !result.has(currentOperation)) {
        result.set(currentOperation, {
          method: currentMethod,
          path: currentPath,
          successStatus: status,
        });
      }
    }
  }
  return result;
}
