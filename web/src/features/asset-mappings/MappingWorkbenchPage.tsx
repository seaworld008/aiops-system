import {
  useQuery,
} from "@tanstack/react-query";
import {
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";

import { useControlPlaneClient } from "@/shared/api/controlPlaneClient";
import { useScope } from "@/shared/api/queryKeys";
import { CursorPagination } from "@/shared/ui/CursorPagination";
import { FilterBar } from "@/shared/ui/FilterBar";
import { ProblemPanel } from "@/shared/ui/ProblemPanel";

import {
  type AssetConflict,
  type ConflictBatchResult,
  listAssetConflicts,
  mappingQueryKeys,
  problemFromError,
} from "./api";
import { ConflictQueue } from "./ConflictQueue";
import styles from "./MappingWorkbenchPage.module.css";
import {
  canonicalizeMappingSearch,
  changeMappingFilters,
  conflictComparisonKey,
  conflictMatchesClientFilters,
  conflictStatuses,
  mappingAges,
  mappingRisks,
  nextMappingPage,
  selectMappingConflict,
  type MappingSearch,
} from "./mappingSearch";
import { ProvenanceComparison } from "./ProvenanceComparison";
import {
  type ConflictDecision,
  ResolveConflictDialog,
} from "./ResolveConflictDialog";

export type MappingSearchChangeOptions = {
  replace?: boolean;
};

export type MappingWorkbenchPageProps = {
  search: MappingSearch;
  onSearchChange: (
    search: MappingSearch,
    options?: MappingSearchChangeOptions,
  ) => void;
};

type DialogState = {
  decision: ConflictDecision;
  conflicts: readonly AssetConflict[];
  mediaRevision: number;
  reviewIdentity: string;
};

export function MappingWorkbenchPage({
  search,
  onSearchChange,
}: MappingWorkbenchPageProps) {
  const client = useControlPlaneClient();
  const { scope } = useScope();
  const desktopMedia = useMediaQuery("(min-width: 768px)");
  const desktopGovernance = desktopMedia.matches;
  const [renderedAt] = useState(() => Date.now());
  const canonicalSearch = useMemo(
    () =>
      canonicalizeMappingSearch({
        ...search,
        workspace: scope.workspaceId,
        environment: scope.environmentId,
      }),
    [scope.environmentId, scope.workspaceId, search],
  );
  const canonicalIdentity = JSON.stringify(canonicalSearch);
  const canonicalReplace = useRef<string | undefined>(undefined);
  const [batchSelectedIds, setBatchSelectedIds] = useState(
    () => new Set<string>(),
  );
  const [scopeResolutionClosed, setScopeResolutionClosed] =
    useState(false);
  const [dialog, setDialog] = useState<DialogState | null>(null);
  const [navigationBlocked, setNavigationBlocked] = useState(false);
  const [navigationWarning, setNavigationWarning] = useState(false);
  const [results, setResults] = useState<
    readonly ConflictBatchResult[]
  >([]);
  const [resultExpectedCount, setResultExpectedCount] = useState(0);
  const scopeKey = `${scope.workspaceId}:${scope.environmentId}`;
  const previousScopeKey = useRef(scopeKey);
  const previousReviewContext = useRef(canonicalIdentity);

  useEffect(() => {
    if (canonicalReplace.current !== canonicalIdentity) {
      canonicalReplace.current = canonicalIdentity;
      onSearchChange(canonicalSearch, { replace: true });
    }
  }, [
    canonicalIdentity,
    canonicalSearch,
    onSearchChange,
  ]);

  useEffect(() => {
    if (previousScopeKey.current !== scopeKey) {
      previousScopeKey.current = scopeKey;
      setBatchSelectedIds(new Set());
      setScopeResolutionClosed(false);
      setDialog(null);
      setResults([]);
      setResultExpectedCount(0);
      setNavigationWarning(false);
    }
  }, [scopeKey]);

  useEffect(() => {
    if (previousReviewContext.current !== canonicalIdentity) {
      previousReviewContext.current = canonicalIdentity;
      setBatchSelectedIds(new Set());
      setDialog(null);
      setResults([]);
      setResultExpectedCount(0);
      setNavigationWarning(false);
    }
  }, [canonicalIdentity]);

  const conflictsQuery = useQuery({
    queryKey: mappingQueryKeys.list(scope, canonicalSearch),
    queryFn: ({ signal }) =>
      listAssetConflicts(
        client,
        scope,
        canonicalSearch,
        signal,
      ),
  });
  const visibleConflicts = useMemo(
    () =>
      (conflictsQuery.data?.items ?? []).filter((item) =>
        conflictMatchesClientFilters(
          item,
          canonicalSearch,
          renderedAt,
        ),
      ),
    [canonicalSearch, conflictsQuery.data?.items, renderedAt],
  );
  const selectedConflict =
    visibleConflicts.find(
      (item) => item.id === canonicalSearch.conflictId,
    ) ?? null;

  useEffect(() => {
    if (conflictsQuery.data === undefined) {
      return;
    }
    if (dialog !== null || results.length > 0) {
      return;
    }
    if (
      canonicalSearch.conflictId !== undefined &&
      selectedConflict === null
    ) {
      onSearchChange(
        selectMappingConflict(canonicalSearch, undefined),
        { replace: true },
      );
      return;
    }
    if (
      canonicalSearch.conflictId === undefined &&
      visibleConflicts[0] !== undefined
    ) {
      onSearchChange(
        selectMappingConflict(
          canonicalSearch,
          visibleConflicts[0].id,
        ),
        { replace: true },
      );
    }
  }, [
    canonicalSearch,
    conflictsQuery.data,
    dialog,
    onSearchChange,
    results.length,
    selectedConflict,
    visibleConflicts,
  ]);

  const visibleConflictIds = useMemo(
    () => new Set(visibleConflicts.map((item) => item.id)),
    [visibleConflicts],
  );
  const effectiveBatchSelectedIds = useMemo(
    () =>
      new Set(
        [...batchSelectedIds].filter((conflictId) =>
          visibleConflictIds.has(conflictId),
        ),
      ),
    [batchSelectedIds, visibleConflictIds],
  );
  const batchConflicts = visibleConflicts.filter((item) =>
    effectiveBatchSelectedIds.has(item.id),
  );
  const batchActionsAuthorized =
    batchConflicts.length >= 2 &&
    batchConflicts.every(
      (item) =>
        item.status === "OPEN" &&
        item.effective_actions.includes("RESOLVE_CONFLICT"),
    );
  const canResolveSelected =
    desktopGovernance &&
    !scopeResolutionClosed &&
    selectedConflict !== null &&
    selectedConflict.status === "OPEN" &&
    selectedConflict.effective_actions.includes(
      "RESOLVE_CONFLICT",
    );
  const openDialog = (
    decision: ConflictDecision,
    conflicts: readonly AssetConflict[],
  ) => {
    if (!desktopGovernance || scopeResolutionClosed) {
      return;
    }
    setResults([]);
    setResultExpectedCount(conflicts.length);
    setNavigationWarning(false);
    setDialog({
      decision,
      conflicts,
      mediaRevision: desktopMedia.revision,
      reviewIdentity: canonicalIdentity,
    });
  };
  const selectConflict = (conflictId: string) => {
    if (navigationBlocked) {
      setNavigationWarning(true);
      return;
    }
    setNavigationWarning(false);
    onSearchChange(
      selectMappingConflict(canonicalSearch, conflictId),
    );
  };

  return (
    <section className={styles.page}>
      <nav aria-label="面包屑" className={styles.breadcrumb}>
        资产与连接 / 映射工作台
      </nav>
      <header className={styles.pageHeader}>
        <div>
          <h1>映射工作台</h1>
          <p>
            显式审阅冲突、候选关系和字段来源；系统不会自动合并。
          </p>
        </div>
      </header>
      <MappingFilters
        key={`${canonicalSearch.source ?? ""}:${canonicalSearch.service ?? ""}`}
        search={canonicalSearch}
        onChange={(next) => {
          setBatchSelectedIds(new Set());
          onSearchChange(next);
        }}
      />
      {navigationWarning ? (
        <p role="alert" className={styles.warningNotice}>
          当前决定尚未由服务端确认，不能切换冲突或自动重放请求。
        </p>
      ) : null}
      <BatchResults
        results={results}
        expectedCount={resultExpectedCount}
      />
      {conflictsQuery.isPending ? (
        <section role="status" className={styles.loadingState}>
          正在读取冲突队列与安全比较…
        </section>
      ) : null}
      {conflictsQuery.error !== null ? (
        <ProblemPanel problem={problemFromError(conflictsQuery.error)} />
      ) : null}
      {conflictsQuery.data !== undefined ? (
        <>
          <section className={styles.batchActions}>
            <span>
              已选择 {batchConflicts.length} 项；batch
              逐项执行，不承诺原子性。
            </span>
            {!desktopGovernance ||
            scopeResolutionClosed ||
            !batchActionsAuthorized
              ? null
              : ([
                  "CONFIRM_EXACT",
                  "REJECT_CANDIDATE",
                  "KEEP_UNRESOLVED",
                  "QUARANTINE_ASSET",
                ] as const).map((decision) => (
                  <button
                    key={decision}
                    type="button"
                    disabled={
                      !batchCompatible(
                        batchConflicts,
                        decision,
                      )
                    }
                    onClick={() => {
                      openDialog(decision, batchConflicts);
                    }}
                  >
                    {batchDecisionLabel(decision)}
                  </button>
                ))}
          </section>
          <div className={styles.workbench}>
            <ConflictQueue
              conflicts={visibleConflicts}
              {...(canonicalSearch.conflictId === undefined
                ? {}
                : {
                    selectedConflictId:
                      canonicalSearch.conflictId,
                  })}
              batchSelectedIds={effectiveBatchSelectedIds}
              navigationBlocked={navigationBlocked}
              resolveControlsAvailable={
                desktopGovernance && !scopeResolutionClosed
              }
              onSelect={selectConflict}
              onBatchSelectionChange={(conflictId, selected) => {
                setBatchSelectedIds((current) => {
                  const next = new Set(current);
                  if (selected) {
                    next.add(conflictId);
                  } else {
                    next.delete(conflictId);
                  }
                  return next;
                });
              }}
            />
            <section className={styles.detailSurface}>
              {selectedConflict === null ? (
                <section role="status" className={styles.emptyState}>
                  <h2>选择一个冲突进行安全比较</h2>
                  <p>选择状态保存在 URL 的 conflictId 中。</p>
                </section>
              ) : (
                <>
                  <ProvenanceComparison
                    conflict={selectedConflict}
                  />
                  {canResolveSelected ? (
                    <section
                      className={styles.decisionActions}
                      aria-label="显式映射决定"
                    >
                      <button
                        type="button"
                        onClick={() => {
                          openDialog(
                            "CONFIRM_EXACT",
                            [selectedConflict],
                          );
                        }}
                      >
                        确认精确映射
                      </button>
                      <button
                        type="button"
                        onClick={() => {
                          openDialog(
                            "REJECT_CANDIDATE",
                            [selectedConflict],
                          );
                        }}
                      >
                        拒绝候选
                      </button>
                      <button
                        type="button"
                        onClick={() => {
                          openDialog(
                            "KEEP_UNRESOLVED",
                            [selectedConflict],
                          );
                        }}
                      >
                        保持未解析
                      </button>
                      <button
                        type="button"
                        className={styles.dangerAction}
                        onClick={() => {
                          openDialog(
                            "QUARANTINE_ASSET",
                            [selectedConflict],
                          );
                        }}
                      >
                        隔离资产
                      </button>
                    </section>
                  ) : (
                    <p role="status" className={styles.readOnly}>
                      {!desktopGovernance
                        ? "请在桌面完成映射治理操作。当前窄屏只提供安全比较。"
                        : scopeResolutionClosed
                          ? "当前 Scope 的映射治理授权已被服务端拒绝，所有 mutation 保持关闭。"
                          : "只读比较"}
                    </p>
                  )}
                </>
              )}
            </section>
          </div>
          <CursorPagination
            hasPrevious={false}
            hasNext={
              conflictsQuery.data.page.next_cursor !== null
            }
            onPrevious={() => undefined}
            onNext={() => {
              const cursor =
                conflictsQuery.data.page.next_cursor;
              if (cursor !== null) {
                onSearchChange(
                  nextMappingPage(canonicalSearch, cursor),
                );
              }
            }}
          />
        </>
      ) : null}
      {!desktopGovernance ||
      dialog === null ||
      dialog.mediaRevision !== desktopMedia.revision ||
      dialog.reviewIdentity !== canonicalIdentity ? null : (
        <ResolveConflictDialog
          open
          scope={scope}
          conflicts={dialog.conflicts}
          decision={dialog.decision}
          reviewIdentity={dialog.reviewIdentity}
          onOpenChange={(open) => {
            if (!open) {
              setDialog(null);
            }
          }}
          onResults={setResults}
          onPermissionDenied={() => {
            setScopeResolutionClosed(true);
            setBatchSelectedIds(new Set());
          }}
          onNavigationGuardChange={setNavigationBlocked}
        />
      )}
    </section>
  );
}

function MappingFilters({
  search,
  onChange,
}: {
  search: MappingSearch;
  onChange: (search: MappingSearch) => void;
}) {
  const [source, setSource] = useState(search.source ?? "");
  const [service, setService] = useState(search.service ?? "");
  const activeCount =
    search.status.length +
    search.risk.length +
    (search.source === undefined ? 0 : 1) +
    (search.service === undefined ? 0 : 1) +
    (search.age === "ALL" ? 0 : 1);
  return (
    <FilterBar
      activeCount={activeCount}
      onClearAll={() => {
        setSource("");
        setService("");
        onChange(
          changeMappingFilters(search, {
            status: [],
            risk: [],
            source: undefined,
            service: undefined,
            age: "ALL",
          }),
        );
      }}
    >
      <label>
        <span>状态</span>
        <select
          multiple
          aria-label="筛选冲突状态"
          value={search.status}
          onChange={(event) => {
            onChange(
              changeMappingFilters(search, {
                status: selectedValues(
                  event.currentTarget,
                ).filter(isConflictStatus),
              }),
            );
          }}
        >
          {conflictStatuses.map((status) => (
            <option key={status} value={status}>
              {status}
            </option>
          ))}
        </select>
      </label>
      <label>
        <span>风险</span>
        <select
          multiple
          aria-label="筛选风险"
          value={search.risk}
          onChange={(event) => {
            onChange(
              changeMappingFilters(search, {
                risk: selectedValues(
                  event.currentTarget,
                ).filter(isMappingRisk),
              }),
            );
          }}
        >
          {mappingRisks.map((risk) => (
            <option key={risk} value={risk}>
              {risk}
            </option>
          ))}
        </select>
      </label>
      <label>
        <span>Source ID</span>
        <input
          aria-label="筛选 Source ID"
          value={source}
          maxLength={36}
          onChange={(event) => {
            setSource(event.currentTarget.value);
          }}
          onBlur={() => {
            const next = changeMappingFilters(search, {
              source: source || undefined,
            });
            setSource(next.source ?? "");
            onChange(next);
          }}
        />
      </label>
      <label>
        <span>Service ID</span>
        <input
          aria-label="筛选 Service ID"
          value={service}
          maxLength={36}
          onChange={(event) => {
            setService(event.currentTarget.value);
          }}
          onBlur={() => {
            const next = changeMappingFilters(search, {
              service: service || undefined,
            });
            setService(next.service ?? "");
            onChange(next);
          }}
        />
      </label>
      <label>
        <span>等待时长</span>
        <select
          aria-label="筛选等待时长"
          value={search.age}
          onChange={(event) => {
            const age = mappingAges.find(
              (candidate) =>
                candidate === event.currentTarget.value,
            );
            if (age !== undefined) {
              onChange(changeMappingFilters(search, { age }));
            }
          }}
        >
          <option value="ALL">全部</option>
          <option value="OVER_24H">超过 24 小时</option>
          <option value="OVER_72H">超过 72 小时</option>
          <option value="OVER_7D">超过 7 天</option>
          <option value="OVER_30D">超过 30 天</option>
        </select>
      </label>
    </FilterBar>
  );
}

function BatchResults({
  results,
  expectedCount,
}: {
  results: readonly ConflictBatchResult[];
  expectedCount: number;
}) {
  if (results.length === 0) {
    return null;
  }
  const completed = results.length >= expectedCount;
  const allSucceeded =
    completed &&
    results.every((result) => result.status === "success");
  const failed = results.some(
    (result) => result.status === "failure",
  );
  return (
    <section
      role="status"
      className={
        allSucceeded
          ? styles.resultPanel
          : styles.partialResultPanel
      }
    >
      <strong>
        {allSucceeded
          ? "映射决定已记录"
          : failed
            ? "batch 已在首个失败处停止"
            : "batch 正在逐项执行"}
      </strong>
      <ul>
        {results.map((result) => (
          <li key={result.conflict.id}>
            {result.conflict.asset.display_name}：
            {result.status === "success"
              ? "成功"
              : result.status === "failure"
                ? "失败"
                : "已停止"}
            {result.status === "success" ? (
              <>
                <span data-monospace="true">
                  {result.response.result.mutation_receipt.audit_id}
                </span>
                <span data-monospace="true">
                  {result.response.result.mutation_receipt.trace_id}
                </span>
              </>
            ) : null}
          </li>
        ))}
      </ul>
    </section>
  );
}

function batchCompatible(
  conflicts: readonly AssetConflict[],
  decision: ConflictDecision,
): boolean {
  if (conflicts.length < 2) {
    return false;
  }
  const first = conflicts[0];
  if (first === undefined) {
    return false;
  }
  const comparisonKey = conflictComparisonKey(first);
  const serviceId = first.candidate_service?.id ?? null;
  if (decision === "CONFIRM_EXACT" && serviceId === null) {
    return false;
  }
  return conflicts.every(
    (item) =>
      item.status === "OPEN" &&
      item.effective_actions.includes("RESOLVE_CONFLICT") &&
      conflictComparisonKey(item) === comparisonKey &&
      (item.candidate_service?.id ?? null) === serviceId,
  );
}

function batchDecisionLabel(decision: ConflictDecision): string {
  switch (decision) {
    case "CONFIRM_EXACT":
      return "批量确认精确映射";
    case "REJECT_CANDIDATE":
      return "批量拒绝候选";
    case "KEEP_UNRESOLVED":
      return "批量保持未解析";
    case "QUARANTINE_ASSET":
      return "批量隔离资产";
  }
}

function selectedValues(select: HTMLSelectElement): string[] {
  return Array.from(select.selectedOptions, (option) => option.value);
}

function isConflictStatus(
  value: string,
): value is MappingSearch["status"][number] {
  return conflictStatuses.some((candidate) => candidate === value);
}

function isMappingRisk(
  value: string,
): value is MappingSearch["risk"][number] {
  return mappingRisks.some((candidate) => candidate === value);
}

function useMediaQuery(query: string): {
  matches: boolean;
  revision: number;
} {
  const [state, setState] = useState(() => ({
    matches: window.matchMedia(query).matches,
    revision: 0,
  }));
  useEffect(() => {
    const media = window.matchMedia(query);
    const handleChange = () => {
      setState((current) =>
        current.matches === media.matches
          ? current
          : {
              matches: media.matches,
              revision: current.revision + 1,
            },
      );
    };
    handleChange();
    media.addEventListener("change", handleChange);
    return () => {
      media.removeEventListener("change", handleChange);
    };
  }, [query]);
  return state;
}
