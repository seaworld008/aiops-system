import { z } from "zod";

import type { components } from "@/shared/api/schema";

export const conflictStatuses = [
  "OPEN",
  "RESOLVED",
  "REJECTED",
] as const satisfies readonly components["schemas"]["ConflictStatus"][];

export const mappingRisks = [
  "LOW",
  "MEDIUM",
  "HIGH",
  "CRITICAL",
] as const;

export const mappingAges = [
  "ALL",
  "OVER_24H",
  "OVER_72H",
  "OVER_7D",
  "OVER_30D",
] as const;

export type MappingRisk = (typeof mappingRisks)[number];
export type MappingAge = (typeof mappingAges)[number];

export type MappingSearch = {
  workspace: string;
  environment: string;
  status: components["schemas"]["ConflictStatus"][];
  risk: MappingRisk[];
  source?: string;
  service?: string;
  age: MappingAge;
  cursor?: string;
  conflictId?: string;
};

export type MappingSearchFallback = Pick<
  MappingSearch,
  "workspace" | "environment"
>;

export type MappingListSearch = Pick<
  MappingSearch,
  "status" | "risk" | "source" | "service" | "age" | "cursor"
>;

type Conflict = components["schemas"]["AssetConflictDetail"];

const uuidSchema = z.string().uuid();
const statusSchema = z.enum(conflictStatuses);
const riskSchema = z.enum(mappingRisks);
const ageSchema = z.enum(mappingAges);

export function parseMappingSearch(
  input: unknown,
  fallback: MappingSearchFallback,
): MappingSearch {
  const record = isRecord(input) ? input : {};
  const workspace = validUUID(record.workspace) ?? fallback.workspace;
  const environment =
    validUUID(record.environment) ?? fallback.environment;
  const source = validUUID(record.source);
  const service = validUUID(record.service);
  const conflictId = validUUID(record.conflictId);
  const cursor = validCursor(record.cursor);
  const age = ageSchema.safeParse(record.age);
  return {
    workspace,
    environment,
    status: canonicalEnumArray(record.status, statusSchema, 3),
    risk: canonicalEnumArray(record.risk, riskSchema, 4),
    ...(source === undefined ? {} : { source }),
    ...(service === undefined ? {} : { service }),
    age: age.success ? age.data : "ALL",
    ...(cursor === undefined ? {} : { cursor }),
    ...(conflictId === undefined ? {} : { conflictId }),
  };
}

export function canonicalizeMappingSearch(
  search: MappingSearch,
): MappingSearch {
  return parseMappingSearch(search, {
    workspace: search.workspace,
    environment: search.environment,
  });
}

export function mappingListSearch(
  search: MappingSearch,
): MappingListSearch {
  const canonical = canonicalizeMappingSearch(search);
  return {
    status: canonical.status,
    risk: canonical.risk,
    ...(canonical.source === undefined
      ? {}
      : { source: canonical.source }),
    ...(canonical.service === undefined
      ? {}
      : { service: canonical.service }),
    age: canonical.age,
    ...(canonical.cursor === undefined
      ? {}
      : { cursor: canonical.cursor }),
  };
}

export function changeMappingFilters(
  search: MappingSearch,
  patch: {
    status?: MappingSearch["status"] | undefined;
    risk?: MappingSearch["risk"] | undefined;
    source?: string | undefined;
    service?: string | undefined;
    age?: MappingSearch["age"] | undefined;
  },
): MappingSearch {
  const next: Record<string, unknown> = {
    ...search,
    ...patch,
  };
  delete next.cursor;
  delete next.conflictId;
  return parseMappingSearch(next, {
    workspace: search.workspace,
    environment: search.environment,
  });
}

export function selectMappingConflict(
  search: MappingSearch,
  conflictId: string | undefined,
): MappingSearch {
  const next: Record<string, unknown> = { ...search };
  if (conflictId === undefined) {
    delete next.conflictId;
  } else {
    next.conflictId = conflictId;
  }
  return parseMappingSearch(next, {
    workspace: search.workspace,
    environment: search.environment,
  });
}

export function nextMappingPage(
  search: MappingSearch,
  cursor: string,
): MappingSearch {
  const next: Record<string, unknown> = {
    ...search,
    cursor,
  };
  delete next.conflictId;
  return parseMappingSearch(next, {
    workspace: search.workspace,
    environment: search.environment,
  });
}

export function conflictRisk(conflict: Conflict): MappingRisk {
  const counts = conflict.impact_counts;
  const affected =
    counts.asset_active_bindings +
    counts.asset_active_relationships +
    counts.candidate_asset_active_bindings +
    counts.candidate_asset_active_relationships +
    counts.candidate_service_active_bindings;
  if (affected >= 10) {
    return "CRITICAL";
  }
  if (affected >= 5) {
    return "HIGH";
  }
  return affected > 0 ? "MEDIUM" : "LOW";
}

export function conflictMatchesClientFilters(
  conflict: Conflict,
  search: MappingSearch,
  now = Date.now(),
): boolean {
  if (
    search.risk.length > 0 &&
    !search.risk.includes(conflictRisk(conflict))
  ) {
    return false;
  }
  if (
    search.service !== undefined &&
    conflict.candidate_service?.id !== search.service
  ) {
    return false;
  }
  if (search.age === "ALL") {
    return true;
  }
  const createdAt = Date.parse(conflict.created_at);
  if (!Number.isFinite(createdAt)) {
    return false;
  }
  return now - createdAt >= ageMilliseconds(search.age);
}

export function conflictComparisonKey(conflict: Conflict): string {
  return [
    conflict.type,
    conflict.field_name,
    conflict.existing_value_sha256,
    conflict.candidate_value_sha256,
  ].join("\u0000");
}

function ageMilliseconds(age: Exclude<MappingAge, "ALL">): number {
  switch (age) {
    case "OVER_24H":
      return 24 * 60 * 60 * 1_000;
    case "OVER_72H":
      return 72 * 60 * 60 * 1_000;
    case "OVER_7D":
      return 7 * 24 * 60 * 60 * 1_000;
    case "OVER_30D":
      return 30 * 24 * 60 * 60 * 1_000;
  }
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

function validUUID(input: unknown): string | undefined {
  const parsed = uuidSchema.safeParse(input);
  return parsed.success ? parsed.data : undefined;
}

function validCursor(input: unknown): string | undefined {
  return typeof input === "string" &&
    input.length > 0 &&
    input.length <= 2048 &&
    /^[A-Za-z0-9_-]+$/u.test(input)
    ? input
    : undefined;
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
