import { z } from "zod";

import type { components } from "@/shared/api/schema";

export const sourceStatuses = [
  "ACTIVE",
  "PAUSED",
  "DEGRADED",
  "DISABLED",
] as const satisfies readonly components["schemas"]["SourceStatus"][];

export const sourceKinds = [
  "MANUAL",
  "CSV_IMPORT",
  "CONTROL_PLANE_API",
  "EXTERNAL_CMDB",
  "VSPHERE",
  "PROXMOX",
  "OPENSTACK",
  "CLOUD_PROVIDER",
  "KUBERNETES_OPERATOR",
  "AWX_INVENTORY",
] as const satisfies readonly components["schemas"]["SourceKind"][];

export type SourceSearch = {
  workspace: string;
  status: components["schemas"]["SourceStatus"][];
  kind: components["schemas"]["SourceKind"][];
  cursor?: string;
  sourceId?: string;
  runId?: string;
};

export type SourceSearchFallback = Pick<SourceSearch, "workspace">;

export type SourceListSearch = Pick<
  SourceSearch,
  "status" | "kind" | "cursor"
>;

const uuidSchema = z.string().uuid();
const statusSchema = z.enum(sourceStatuses);
const kindSchema = z.enum(sourceKinds);

export function parseSourceSearch(
  input: unknown,
  fallback: SourceSearchFallback,
): SourceSearch {
  const record = isRecord(input) ? input : {};
  const workspace = validUUID(record.workspace) ?? fallback.workspace;
  const cursor = boundedString(record.cursor, 2_048);
  const sourceId = validUUID(record.sourceId);
  const runId = validUUID(record.runId);
  return {
    workspace,
    status: canonicalEnumArray(
      record.status,
      statusSchema,
      sourceStatuses.length,
    ),
    kind: canonicalEnumArray(
      record.kind,
      kindSchema,
      sourceKinds.length,
    ),
    ...(cursor === undefined ? {} : { cursor }),
    ...(sourceId === undefined ? {} : { sourceId }),
    ...(runId === undefined ? {} : { runId }),
  };
}

export function canonicalizeSourceSearch(
  search: SourceSearch,
): SourceSearch {
  return parseSourceSearch(search, { workspace: search.workspace });
}

export function sourceListSearch(
  search: SourceSearch,
): SourceListSearch {
  const canonical = canonicalizeSourceSearch(search);
  return {
    status: canonical.status,
    kind: canonical.kind,
    ...(canonical.cursor === undefined
      ? {}
      : { cursor: canonical.cursor }),
  };
}

export function changeSourceFilters(
  search: SourceSearch,
  patch: {
    status?: SourceSearch["status"] | undefined;
    kind?: SourceSearch["kind"] | undefined;
  },
): SourceSearch {
  return parseSourceSearch(
    {
      ...search,
      ...patch,
      cursor: undefined,
      sourceId: undefined,
      runId: undefined,
    },
    { workspace: search.workspace },
  );
}

export function selectSource(
  search: SourceSearch,
  sourceId: string | undefined,
): SourceSearch {
  return parseSourceSearch(
    {
      ...search,
      sourceId,
      runId: undefined,
    },
    { workspace: search.workspace },
  );
}

export function selectSourceRun(
  search: SourceSearch,
  sourceId: string,
  runId: string,
): SourceSearch {
  return parseSourceSearch(
    { ...search, sourceId, runId },
    { workspace: search.workspace },
  );
}

export function nextSourcePage(
  search: SourceSearch,
  cursor: string,
): SourceSearch {
  return parseSourceSearch(
    {
      ...search,
      cursor,
      sourceId: undefined,
      runId: undefined,
    },
    { workspace: search.workspace },
  );
}

function canonicalEnumArray<Value extends string>(
  input: unknown,
  schema: z.ZodEnum<Record<Value, Value>>,
  maximum: number,
): Value[] {
  const values: Value[] = [];
  for (const candidate of arrayInput(input)) {
    const parsed = schema.safeParse(candidate);
    if (parsed.success) {
      values.push(parsed.data);
    }
  }
  return [...new Set(values)].sort().slice(0, maximum);
}

function arrayInput(input: unknown): unknown[] {
  if (Array.isArray(input)) {
    return input;
  }
  if (typeof input !== "string") {
    return [];
  }
  const value = input.trim();
  if (value.startsWith("[")) {
    try {
      const parsed: unknown = JSON.parse(value);
      return Array.isArray(parsed) ? parsed : [];
    } catch {
      return [];
    }
  }
  return value === "" ? [] : value.split(",");
}

function validUUID(input: unknown): string | undefined {
  const parsed = uuidSchema.safeParse(input);
  return parsed.success ? parsed.data : undefined;
}

function boundedString(
  input: unknown,
  maximum: number,
): string | undefined {
  if (typeof input !== "string") {
    return undefined;
  }
  const value = input.trim();
  return value !== "" && value.length <= maximum ? value : undefined;
}

function isRecord(input: unknown): input is Record<string, unknown> {
  return typeof input === "object" && input !== null && !Array.isArray(input);
}
