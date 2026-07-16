import {
  createContext,
  createElement,
  type PropsWithChildren,
  useContext,
  useEffect,
} from "react";

export type Scope = {
  workspaceId: string;
  environmentId: string;
};

export type ScopeKey = Scope;

export type DraftGuardRegistration = {
  isDirty: () => boolean;
  discard: () => void;
};

type ScopeRuntimeValue = {
  scope: Scope;
  requestScopeChange: (scope: Scope) => void;
  registerDraftGuard: (registration: DraftGuardRegistration) => () => void;
};

type ScopeRuntimeProviderProps = PropsWithChildren<ScopeRuntimeValue>;

const ScopeRuntimeContext = createContext<ScopeRuntimeValue | undefined>(
  undefined,
);

export function ScopeRuntimeProvider({
  scope,
  requestScopeChange,
  registerDraftGuard,
  children,
}: ScopeRuntimeProviderProps) {
  return createElement(
    ScopeRuntimeContext.Provider,
    {
      value: {
        scope,
        requestScopeChange,
        registerDraftGuard,
      },
    },
    children,
  );
}

export function useScope(): Pick<
  ScopeRuntimeValue,
  "scope" | "requestScopeChange"
> {
  const { scope, requestScopeChange } = useScopeRuntime();
  return { scope, requestScopeChange };
}

export function useDraftGuard(
  registration: DraftGuardRegistration,
): void {
  const { registerDraftGuard } = useScopeRuntime();
  useEffect(
    () => registerDraftGuard(registration),
    [registerDraftGuard, registration],
  );
}

function useScopeRuntime(): ScopeRuntimeValue {
  const value = useContext(ScopeRuntimeContext);
  if (value === undefined) {
    throw new Error("ScopeRuntimeProvider is required");
  }
  return value;
}

export const queryKeys = {
  session: () => ["session"] as const,
  scoped: <Domain extends string, Filters>(
    domain: Domain,
    scope: ScopeKey,
    filters: Filters,
  ) =>
    [
      domain,
      scope.workspaceId,
      scope.environmentId,
      normalizeFilter(filters),
    ] as const,
  operation: (
    scope: ScopeKey,
    kind: string,
    operationId: string,
  ) =>
    [
      "operation",
      scope.workspaceId,
      scope.environmentId,
      kind,
      operationId,
    ] as const,
};

function normalizeFilter(value: unknown): unknown {
  if (value === undefined || value === null) {
    return value;
  }
  if (Array.isArray(value)) {
    const normalized = value
      .map(normalizeFilter)
      .filter((item) => item !== undefined)
      .sort((left, right) =>
        stableFilterKey(left).localeCompare(stableFilterKey(right)),
      );
    const unique: unknown[] = [];
    let previousKey: string | undefined;
    for (const item of normalized) {
      const key = stableFilterKey(item);
      if (key !== previousKey) {
        unique.push(item);
        previousKey = key;
      }
    }
    return unique;
  }
  if (typeof value !== "object") {
    return value;
  }
  const prototype: unknown = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    return value;
  }
  const normalized: Record<string, unknown> = {};
  for (const key of Object.keys(value).sort()) {
    const item = normalizeFilter((value as Record<string, unknown>)[key]);
    if (item !== undefined) {
      normalized[key] = item;
    }
  }
  return normalized;
}

function stableFilterKey(value: unknown): string {
  if (value === null) {
    return "null";
  }
  if (typeof value === "number") {
    return `number:${Object.is(value, -0) ? "-0" : String(value)}`;
  }
  if (typeof value === "string") {
    return `string:${JSON.stringify(value)}`;
  }
  if (typeof value === "boolean") {
    return `boolean:${String(value)}`;
  }
  if (Array.isArray(value)) {
    return `array:${JSON.stringify(value)}`;
  }
  if (typeof value === "object") {
    return `object:${JSON.stringify(value)}`;
  }
  if (typeof value === "bigint") {
    return `bigint:${value.toString()}`;
  }
  if (typeof value === "symbol") {
    return `symbol:${value.description ?? ""}`;
  }
  return typeof value;
}
