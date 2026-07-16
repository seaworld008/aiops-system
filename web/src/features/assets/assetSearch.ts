import { z } from "zod";

import type { components } from "@/shared/api/schema";

export const assetKinds = [
  "SERVICE",
  "LINUX_VM",
  "WINDOWS_VM",
  "BARE_METAL_HOST",
  "KUBERNETES_CLUSTER",
  "KUBERNETES_NAMESPACE",
  "KUBERNETES_WORKLOAD",
  "DATABASE_INSTANCE",
  "DATABASE",
  "METRICS_SOURCE",
  "LOG_SOURCE",
  "TRACE_SOURCE",
  "AWX_INVENTORY",
  "ARGO_APPLICATION",
  "CI_PIPELINE",
  "GIT_REPOSITORY",
  "CLOUD_RESOURCE",
] as const satisfies readonly components["schemas"]["AssetKind"][];

export const mappingStatuses = [
  "EXACT",
  "AMBIGUOUS",
  "UNRESOLVED",
] as const satisfies readonly components["schemas"]["MappingStatus"][];

export const assetLifecycles = [
  "DISCOVERED",
  "ACTIVE",
  "STALE",
  "QUARANTINED",
  "RETIRED",
] as const satisfies readonly components["schemas"]["AssetLifecycle"][];

export const assetCriticalities = [
  "LOW",
  "MEDIUM",
  "HIGH",
  "CRITICAL",
] as const satisfies readonly components["schemas"]["Criticality"][];

export const assetDataClassifications = [
  "PUBLIC",
  "INTERNAL",
  "CONFIDENTIAL",
  "RESTRICTED",
] as const satisfies readonly components["schemas"]["DataClassification"][];

export const assetTabs = [
  "overview",
  "connections",
  "capabilities",
  "relations",
  "audit",
] as const;

export const assetSorts = [
  "display_name_asc",
  "last_observed_at_desc",
] as const satisfies readonly components["schemas"]["AssetSort"][];

export const assetKindLabels: Record<
  components["schemas"]["AssetKind"],
  string
> = {
  SERVICE: "服务",
  LINUX_VM: "Linux 虚拟机",
  WINDOWS_VM: "Windows 虚拟机",
  BARE_METAL_HOST: "裸金属主机",
  KUBERNETES_CLUSTER: "Kubernetes 集群",
  KUBERNETES_NAMESPACE: "Kubernetes 命名空间",
  KUBERNETES_WORKLOAD: "Kubernetes 工作负载",
  DATABASE_INSTANCE: "数据库实例",
  DATABASE: "数据库",
  METRICS_SOURCE: "指标数据源",
  LOG_SOURCE: "日志数据源",
  TRACE_SOURCE: "追踪数据源",
  AWX_INVENTORY: "AWX 清单",
  ARGO_APPLICATION: "Argo 应用",
  CI_PIPELINE: "CI 流水线",
  GIT_REPOSITORY: "Git 仓库",
  CLOUD_RESOURCE: "云资源",
};

const uuidSchema = z.string().uuid();
const assetKindSchema = z.enum(assetKinds);
const mappingStatusSchema = z.enum(mappingStatuses);
const assetLifecycleSchema = z.enum(assetLifecycles);
const assetCriticalitySchema = z.enum(assetCriticalities);
const assetDataClassificationSchema = z.enum(assetDataClassifications);
const assetTabSchema = z.enum(assetTabs);
const assetSortSchema = z.enum(assetSorts);

export type AssetSearch = {
  workspace: string;
  environment: string;
  q?: string;
  kind: components["schemas"]["AssetKind"][];
  source: string[];
  service?: string;
  mapping: components["schemas"]["MappingStatus"][];
  lifecycle: components["schemas"]["AssetLifecycle"][];
  criticality: components["schemas"]["Criticality"][];
  dataClassification: components["schemas"]["DataClassification"][];
  sort: components["schemas"]["AssetSort"];
  cursor?: string;
  trail: string[];
  assetId?: string;
  tab: (typeof assetTabs)[number];
};

export type AssetSearchFallback = Pick<
  AssetSearch,
  "workspace" | "environment"
>;

export type CanonicalAssetListSearch = Pick<
  AssetSearch,
  | "q"
  | "kind"
  | "source"
  | "service"
  | "mapping"
  | "lifecycle"
  | "criticality"
  | "dataClassification"
  | "sort"
  | "cursor"
>;

export function parseAssetSearch(
  input: unknown,
  fallback: AssetSearchFallback,
): AssetSearch {
  const record = isRecord(input) ? input : {};
  const workspace = validUUID(record.workspace) ?? fallback.workspace;
  const environment = validUUID(record.environment) ?? fallback.environment;
  const q = optionalBoundedString(record.q, 128, true);
  const service = validUUID(record.service);
  const cursor = optionalBoundedString(record.cursor, 2048, false);
  const assetId = validUUID(record.assetId);
  const sort = assetSortSchema.safeParse(record.sort);
  const tab = assetTabSchema.safeParse(record.tab);

  return {
    workspace,
    environment,
    ...(q === undefined ? {} : { q }),
    kind: canonicalEnumArray(record.kind, assetKindSchema, 17),
    source: canonicalUUIDArray(record.source, 20),
    ...(service === undefined ? {} : { service }),
    mapping: canonicalEnumArray(record.mapping, mappingStatusSchema, 3),
    lifecycle: canonicalEnumArray(record.lifecycle, assetLifecycleSchema, 5),
    criticality: canonicalEnumArray(
      record.criticality,
      assetCriticalitySchema,
      4,
    ),
    dataClassification: canonicalEnumArray(
      record.dataClassification,
      assetDataClassificationSchema,
      4,
    ),
    sort: sort.success ? sort.data : "display_name_asc",
    ...(cursor === undefined ? {} : { cursor }),
    trail: canonicalCursorTrail(record.trail),
    ...(assetId === undefined ? {} : { assetId }),
    tab: tab.success ? tab.data : "overview",
  };
}

export function canonicalizeAssetSearch(
  search: AssetSearch,
): AssetSearch {
  return parseAssetSearch(search, {
    workspace: search.workspace,
    environment: search.environment,
  });
}

export function canonicalAssetListSearch(
  search: AssetSearch,
): CanonicalAssetListSearch {
  const canonical = canonicalizeAssetSearch(search);
  return {
    ...(canonical.q === undefined ? {} : { q: canonical.q }),
    kind: canonical.kind,
    source: canonical.source,
    ...(canonical.service === undefined
      ? {}
      : { service: canonical.service }),
    mapping: canonical.mapping,
    lifecycle: canonical.lifecycle,
    criticality: canonical.criticality,
    dataClassification: canonical.dataClassification,
    sort: canonical.sort,
    ...(canonical.cursor === undefined
      ? {}
      : { cursor: canonical.cursor }),
  };
}

export function changeAssetFilters(
  search: AssetSearch,
  patch: {
    q?: string | undefined;
    kind?: AssetSearch["kind"] | undefined;
    source?: AssetSearch["source"] | undefined;
    service?: string | undefined;
    mapping?: AssetSearch["mapping"] | undefined;
    lifecycle?: AssetSearch["lifecycle"] | undefined;
    criticality?: AssetSearch["criticality"] | undefined;
    dataClassification?: AssetSearch["dataClassification"] | undefined;
    sort?: AssetSearch["sort"] | undefined;
  },
): AssetSearch {
  return parseAssetSearch(
    {
      ...search,
      ...patch,
      cursor: undefined,
      trail: [],
    },
    {
      workspace: search.workspace,
      environment: search.environment,
    },
  );
}

export function selectAsset(
  search: AssetSearch,
  assetId: string | undefined,
  tab: AssetSearch["tab"] = "overview",
): AssetSearch {
  const next: AssetSearch = {
    ...search,
    tab,
  };
  if (assetId === undefined) {
    delete next.assetId;
  } else {
    next.assetId = assetId;
  }
  return canonicalizeAssetSearch(next);
}

export function nextAssetPage(
  search: AssetSearch,
  nextCursor: string,
): AssetSearch {
  const next: AssetSearch = {
    ...search,
    cursor: nextCursor,
    trail: [...search.trail, search.cursor ?? ""],
    tab: "overview",
  };
  delete next.assetId;
  return canonicalizeAssetSearch(next);
}

export function previousAssetPage(search: AssetSearch): AssetSearch {
  const previous = search.trail.at(-1);
  const next: AssetSearch = {
    ...search,
    trail: search.trail.slice(0, -1),
    tab: "overview",
  };
  if (previous === "" || previous === undefined) {
    delete next.cursor;
  } else {
    next.cursor = previous;
  }
  delete next.assetId;
  return canonicalizeAssetSearch(next);
}

export function assetListHref(search: AssetSearch): string {
  const listSearch: AssetSearch = { ...search };
  delete listSearch.assetId;
  const canonical = canonicalizeAssetSearch(listSearch);
  const parameters = new URLSearchParams();
  parameters.set("workspace", canonical.workspace);
  parameters.set("environment", canonical.environment);
  setOptional(parameters, "q", canonical.q);
  setArray(parameters, "kind", canonical.kind);
  setArray(parameters, "source", canonical.source);
  setOptional(parameters, "service", canonical.service);
  setArray(parameters, "mapping", canonical.mapping);
  setArray(parameters, "lifecycle", canonical.lifecycle);
  setArray(parameters, "criticality", canonical.criticality);
  setArray(
    parameters,
    "dataClassification",
    canonical.dataClassification,
  );
  parameters.set("sort", canonical.sort);
  setOptional(parameters, "cursor", canonical.cursor);
  setArray(parameters, "trail", canonical.trail);
  parameters.set("tab", canonical.tab);
  return `/assets?${parameters.toString()}`;
}

export function isAssetUUID(value: string): boolean {
  return uuidSchema.safeParse(value).success;
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
  return uniqueSorted(values).slice(0, maximum);
}

function canonicalUUIDArray(input: unknown, maximum: number): string[] {
  const values = arrayInput(input)
    .map((candidate) => validUUID(candidate))
    .filter((candidate): candidate is string => candidate !== undefined);
  return uniqueSorted(values).slice(0, maximum);
}

function canonicalCursorTrail(input: unknown): string[] {
  const values = arrayInput(input)
    .map((candidate) =>
      typeof candidate === "string" && candidate.length <= 2048
        ? candidate
        : undefined,
    )
    .filter((candidate): candidate is string => candidate !== undefined);
  return values.slice(-20);
}

function arrayInput(input: unknown): unknown[] {
  if (Array.isArray(input)) {
    return input;
  }
  if (typeof input !== "string") {
    return [];
  }
  const trimmed = input.trim();
  if (trimmed.startsWith("[")) {
    try {
      const parsed: unknown = JSON.parse(trimmed);
      return Array.isArray(parsed) ? parsed : [];
    } catch {
      return [];
    }
  }
  return [input];
}

function optionalBoundedString(
  input: unknown,
  maximum: number,
  trim: boolean,
): string | undefined {
  if (typeof input !== "string") {
    return undefined;
  }
  const value = trim ? input.trim() : input;
  return value.length > 0 && value.length <= maximum ? value : undefined;
}

function validUUID(input: unknown): string | undefined {
  const parsed = uuidSchema.safeParse(input);
  return parsed.success ? parsed.data : undefined;
}

function uniqueSorted<Value extends string>(values: Value[]): Value[] {
  return [...new Set(values)].sort((left, right) =>
    left.localeCompare(right),
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return (
    typeof value === "object" &&
    value !== null &&
    !Array.isArray(value)
  );
}

function setOptional(
  parameters: URLSearchParams,
  name: string,
  value: string | undefined,
): void {
  if (value !== undefined) {
    parameters.set(name, value);
  }
}

function setArray(
  parameters: URLSearchParams,
  name: string,
  values: readonly string[],
): void {
  if (values.length > 0) {
    parameters.set(name, JSON.stringify(values));
  }
}
