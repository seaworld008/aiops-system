import { useQuery } from "@tanstack/react-query";
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
  assetQueryKeys,
  listAssets,
  problemFromError,
  type AssetMutationResponse,
} from "./api";
import {
  assetCriticalities,
  assetDataClassifications,
  assetKinds,
  assetKindLabels,
  assetLifecycles,
  canonicalizeAssetSearch,
  changeAssetFilters,
  mappingStatuses,
  nextAssetPage,
  previousAssetPage,
  selectAsset,
  type AssetSearch,
} from "./assetSearch";
import { AssetDetailDrawer } from "./AssetDetailDrawer";
import styles from "./AssetCatalogPage.module.css";
import { AssetTable } from "./AssetTable";
import { CreateAssetDialog } from "./CreateAssetDialog";

export type AssetSearchChangeOptions = {
  replace?: boolean;
};

export type AssetCatalogPageProps = {
  search: AssetSearch;
  onSearchChange: (
    search: AssetSearch,
    options?: AssetSearchChangeOptions,
  ) => void;
  onOpenAsset: (assetId: string) => void;
};

export function AssetCatalogPage({
  search,
  onSearchChange,
  onOpenAsset,
}: AssetCatalogPageProps) {
  const client = useControlPlaneClient();
  const { scope } = useScope();
  const desktop = useMediaQuery("(min-width: 1024px)");
  const canonicalSearch = useMemo(
    () =>
      canonicalizeAssetSearch({
        ...search,
        workspace: scope.workspaceId,
        environment: scope.environmentId,
      }),
    [scope.environmentId, scope.workspaceId, search],
  );
  const canonicalReplace = useRef<string | undefined>(undefined);
  const [focusRequest, setFocusRequest] = useState<
    { assetId: string; sequence: number } | undefined
  >();
  const [createOpen, setCreateOpen] = useState(false);
  const [createResult, setCreateResult] = useState<
    | {
        scopeKey: string;
        response: AssetMutationResponse;
      }
    | undefined
  >();
  const scopeKey = `${scope.workspaceId}:${scope.environmentId}`;
  const createResultScope = useRef(scopeKey);
  const visibleCreateResult =
    createResult?.scopeKey === scopeKey
      ? createResult.response
      : undefined;

  useEffect(() => {
    if (createResultScope.current !== scopeKey) {
      createResultScope.current = scopeKey;
      setCreateResult(undefined);
    }
  }, [scopeKey]);

  useEffect(() => {
    const identity = JSON.stringify(canonicalSearch);
    if (canonicalReplace.current !== identity) {
      canonicalReplace.current = identity;
      onSearchChange(canonicalSearch, { replace: true });
    }
  }, [canonicalSearch, onSearchChange]);

  const assetsQuery = useQuery({
    queryKey: assetQueryKeys.list(scope, canonicalSearch),
    queryFn: ({ signal }) =>
      listAssets(client, scope, canonicalSearch, signal),
  });

  useEffect(() => {
    if (
      assetsQuery.data !== undefined &&
      canonicalSearch.assetId !== undefined &&
      !assetsQuery.data.items.some(
        (asset) => asset.id === canonicalSearch.assetId,
      )
    ) {
      onSearchChange(selectAsset(canonicalSearch, undefined), {
        replace: true,
      });
    }
  }, [assetsQuery.data, canonicalSearch, onSearchChange]);

  useEffect(() => {
    if (!desktop && canonicalSearch.assetId !== undefined) {
      onOpenAsset(canonicalSearch.assetId);
    }
  }, [canonicalSearch.assetId, desktop, onOpenAsset]);

  const selectedAssetId = canonicalSearch.assetId;
  const closeSelection = () => {
    if (selectedAssetId === undefined) {
      return;
    }
    const restoreAssetId = selectedAssetId;
    onSearchChange(selectAsset(canonicalSearch, undefined));
    setFocusRequest((current) => ({
      assetId: restoreAssetId,
      sequence: (current?.sequence ?? 0) + 1,
    }));
  };

  return (
    <section className={styles.page}>
      <nav aria-label="面包屑" className={styles.breadcrumb}>
        资产与连接 / 资产目录
      </nav>
      <header className={styles.pageHeader}>
        <div>
          <h1>资产目录</h1>
          <p>
            {assetsQuery.data === undefined
              ? "读取当前作用域的安全资产投影"
              : `${assetsQuery.data.items.length} 项资产`}
          </p>
        </div>
        {assetsQuery.data?.effective_actions.includes("CREATE_ASSET") ? (
          <button
            type="button"
            onClick={() => {
              setCreateOpen(true);
            }}
          >
            添加资产
          </button>
        ) : null}
      </header>
      {visibleCreateResult === undefined ? null : (
        <section role="status" className={styles.inlineResult}>
          <strong>资产登记已由服务端确认</strong>
          <span>
            Audit ID：{" "}
            <span data-monospace="true">
              {visibleCreateResult.result.mutation_receipt.audit_id}
            </span>
          </span>
          <span>
            Trace ID：{" "}
            <span data-monospace="true">
              {visibleCreateResult.result.mutation_receipt.trace_id}
            </span>
          </span>
        </section>
      )}
      <AssetFilters
        search={canonicalSearch}
        onChange={(next) => onSearchChange(next)}
      />
      {assetsQuery.isPending ? <AssetTableSkeleton /> : null}
      {assetsQuery.error !== null ? (
        <ProblemPanel problem={problemFromError(assetsQuery.error)} />
      ) : null}
      {assetsQuery.data !== undefined &&
      assetsQuery.data.items.length === 0 ? (
        <section role="status" className={styles.emptyState}>
          <h2>当前筛选没有资产</h2>
          <p>筛选条件保留在 URL 中，可清除或调整后继续查看。</p>
        </section>
      ) : null}
      {assetsQuery.data !== undefined &&
      assetsQuery.data.items.length > 0 ? (
        <>
          <AssetTable
            rows={assetsQuery.data.items}
            {...(selectedAssetId === undefined
              ? {}
              : { selectedAssetId })}
            {...(focusRequest === undefined ? {} : { focusRequest })}
            onSelect={(assetId) => {
              if (desktop) {
                onSearchChange(selectAsset(canonicalSearch, assetId));
              } else {
                onOpenAsset(assetId);
              }
            }}
            onOpen={onOpenAsset}
            onEscape={closeSelection}
          />
          <CursorPagination
            hasPrevious={canonicalSearch.trail.length > 0}
            hasNext={assetsQuery.data.page.next_cursor !== null}
            onPrevious={() => {
              onSearchChange(previousAssetPage(canonicalSearch));
            }}
            onNext={() => {
              const nextCursor = assetsQuery.data.page.next_cursor;
              if (nextCursor !== null) {
                onSearchChange(
                  nextAssetPage(canonicalSearch, nextCursor),
                );
              }
            }}
          />
        </>
      ) : null}
      {desktop && selectedAssetId !== undefined ? (
        <AssetDetailDrawer
          scope={scope}
          assetId={selectedAssetId}
          tab={canonicalSearch.tab}
          onTabChange={(tab) => {
            onSearchChange({
              ...canonicalSearch,
              tab,
            });
          }}
          onClose={closeSelection}
          onOpenFullPage={() => {
            onOpenAsset(selectedAssetId);
          }}
        />
      ) : null}
      <CreateAssetDialog
        open={createOpen}
        scope={scope}
        onOpenChange={setCreateOpen}
        onCreated={(response) => {
          setCreateResult({ scopeKey, response });
        }}
      />
    </section>
  );
}

function AssetFilters({
  search,
  onChange,
}: {
  search: AssetSearch;
  onChange: (search: AssetSearch) => void;
}) {
  const activeCount =
    (search.q === undefined ? 0 : 1) +
    search.kind.length +
    search.source.length +
    (search.service === undefined ? 0 : 1) +
    search.mapping.length +
    search.lifecycle.length +
    search.criticality.length +
    search.dataClassification.length;
  const clearAll = () => {
    onChange(
      changeAssetFilters(search, {
        q: undefined,
        kind: [],
        source: [],
        service: undefined,
        mapping: [],
        lifecycle: [],
        criticality: [],
        dataClassification: [],
        sort: "display_name_asc",
      }),
    );
  };
  return (
    <>
      <details className={styles.filterDisclosure} open>
        <summary className={styles.filterSummary}>筛选资产</summary>
        <FilterBar activeCount={activeCount} onClearAll={clearAll}>
          <label>
            <span>关键字</span>
            <input
              aria-label="关键字"
              value={search.q ?? ""}
              maxLength={128}
              onChange={(event) => {
                onChange(
                  changeAssetFilters(search, {
                    q: event.currentTarget.value || undefined,
                  }),
                );
              }}
            />
          </label>
        <label>
          <span>筛选资产类型</span>
          <select
            multiple
            aria-label="筛选资产类型"
            value={search.kind}
            onChange={(event) => {
              onChange(
                changeAssetFilters(search, {
                  kind: Array.from(
                    event.currentTarget.selectedOptions,
                    (option) => option.value,
                  ).filter((value): value is AssetSearch["kind"][number] =>
                    assetKinds.includes(
                      value as AssetSearch["kind"][number],
                    ),
                  ),
                }),
              );
            }}
          >
            {assetKinds.map((kind) => (
              <option key={kind} value={kind}>
                {assetKindLabels[kind]}
              </option>
            ))}
          </select>
        </label>
        <label>
          <span>映射</span>
          <select
            multiple
            aria-label="映射状态"
            value={search.mapping}
            onChange={(event) => {
              onChange(
                changeAssetFilters(search, {
                  mapping: Array.from(
                    event.currentTarget.selectedOptions,
                    (option) => option.value,
                  ).filter(
                    (value): value is AssetSearch["mapping"][number] =>
                      mappingStatuses.includes(
                        value as AssetSearch["mapping"][number],
                      ),
                  ),
                }),
              );
            }}
          >
            {mappingStatuses.map((status) => (
              <option key={status} value={status}>
                {status}
              </option>
            ))}
          </select>
        </label>
        <label>
          <span>生命周期</span>
          <select
            multiple
            aria-label="生命周期"
            value={search.lifecycle}
            onChange={(event) => {
              onChange(
                changeAssetFilters(search, {
                  lifecycle: Array.from(
                    event.currentTarget.selectedOptions,
                    (option) => option.value,
                  ).filter(
                    (value): value is AssetSearch["lifecycle"][number] =>
                      assetLifecycles.includes(
                        value as AssetSearch["lifecycle"][number],
                      ),
                  ),
                }),
              );
            }}
          >
            {assetLifecycles.map((lifecycle) => (
              <option key={lifecycle} value={lifecycle}>
                {lifecycle}
              </option>
            ))}
          </select>
        </label>
        <label>
          <span>Service ID</span>
          <input
            key={search.service ?? "no-service"}
            aria-label="Service ID"
            defaultValue={search.service ?? ""}
            onBlur={(event) => {
              onChange(
                changeAssetFilters(search, {
                  service: event.currentTarget.value || undefined,
                }),
              );
            }}
          />
        </label>
          <label>
            <span>Source IDs</span>
            <input
              key={search.source.join(",")}
              aria-label="Source IDs"
              defaultValue={search.source.join(",")}
              onBlur={(event) => {
                onChange(
                  changeAssetFilters(search, {
                    source: event.currentTarget.value
                      .split(",")
                      .map((value) => value.trim())
                      .filter((value) => value !== ""),
                  }),
                );
              }}
            />
          </label>
          <label>
            <span>关键度筛选</span>
            <select
              multiple
              aria-label="关键度筛选"
              value={search.criticality}
              onChange={(event) => {
                onChange(
                  changeAssetFilters(search, {
                    criticality: Array.from(
                      event.currentTarget.selectedOptions,
                      (option) => option.value,
                    ).filter(
                      (
                        value,
                      ): value is AssetSearch["criticality"][number] =>
                        assetCriticalities.includes(
                          value as AssetSearch["criticality"][number],
                        ),
                    ),
                  }),
                );
              }}
            >
              {assetCriticalities.map((criticality) => (
                <option key={criticality} value={criticality}>
                  {criticality}
                </option>
              ))}
            </select>
          </label>
          <label>
            <span>数据分类筛选</span>
            <select
              multiple
              aria-label="数据分类筛选"
              value={search.dataClassification}
              onChange={(event) => {
                onChange(
                  changeAssetFilters(search, {
                    dataClassification: Array.from(
                      event.currentTarget.selectedOptions,
                      (option) => option.value,
                    ).filter(
                      (
                        value,
                      ): value is AssetSearch["dataClassification"][number] =>
                        assetDataClassifications.includes(
                          value as AssetSearch["dataClassification"][number],
                        ),
                    ),
                  }),
                );
              }}
            >
              {assetDataClassifications.map((classification) => (
                <option key={classification} value={classification}>
                  {classification}
                </option>
              ))}
            </select>
          </label>
        <label>
          <span>排序</span>
          <select
            aria-label="排序"
            value={search.sort}
            onChange={(event) => {
              onChange(
                changeAssetFilters(search, {
                  sort: event.currentTarget.value as AssetSearch["sort"],
                }),
              );
            }}
          >
            <option value="display_name_asc">名称升序</option>
            <option value="last_observed_at_desc">最近观测降序</option>
          </select>
        </label>
        </FilterBar>
      </details>
      <div className={styles.chips} aria-label="当前筛选">
        {search.q === undefined ? null : (
          <FilterChip
            label={`关键字：${search.q}`}
            onRemove={() => {
              onChange(changeAssetFilters(search, { q: undefined }));
            }}
          />
        )}
        {search.kind.map((kind) => (
          <FilterChip
            key={kind}
            label={`类型：${assetKindLabels[kind]}`}
            onRemove={() => {
              onChange(
                changeAssetFilters(search, {
                  kind: search.kind.filter((item) => item !== kind),
                }),
              );
            }}
          />
        ))}
        {search.mapping.map((mapping) => (
          <FilterChip
            key={mapping}
            label={`映射：${mapping}`}
            onRemove={() => {
              onChange(
                changeAssetFilters(search, {
                  mapping: search.mapping.filter(
                    (item) => item !== mapping,
                  ),
                }),
              );
            }}
          />
        ))}
        {search.lifecycle.map((lifecycle) => (
          <FilterChip
            key={lifecycle}
            label={`生命周期：${lifecycle}`}
            onRemove={() => {
              onChange(
                changeAssetFilters(search, {
                  lifecycle: search.lifecycle.filter(
                    (item) => item !== lifecycle,
                  ),
                }),
              );
            }}
          />
        ))}
        {search.source.map((sourceId) => (
          <FilterChip
            key={sourceId}
            label={`来源：${sourceId}`}
            onRemove={() => {
              onChange(
                changeAssetFilters(search, {
                  source: search.source.filter(
                    (item) => item !== sourceId,
                  ),
                }),
              );
            }}
          />
        ))}
        {search.service === undefined ? null : (
          <FilterChip
            label={`Service：${search.service}`}
            onRemove={() => {
              onChange(
                changeAssetFilters(search, { service: undefined }),
              );
            }}
          />
        )}
        {search.criticality.map((criticality) => (
          <FilterChip
            key={criticality}
            label={`关键度：${criticality}`}
            onRemove={() => {
              onChange(
                changeAssetFilters(search, {
                  criticality: search.criticality.filter(
                    (item) => item !== criticality,
                  ),
                }),
              );
            }}
          />
        ))}
        {search.dataClassification.map((classification) => (
          <FilterChip
            key={classification}
            label={`数据分类：${classification}`}
            onRemove={() => {
              onChange(
                changeAssetFilters(search, {
                  dataClassification: search.dataClassification.filter(
                    (item) => item !== classification,
                  ),
                }),
              );
            }}
          />
        ))}
      </div>
    </>
  );
}

function FilterChip({
  label,
  onRemove,
}: {
  label: string;
  onRemove: () => void;
}) {
  return (
    <button type="button" className={styles.chip} onClick={onRemove}>
      {label}
    </button>
  );
}

function AssetTableSkeleton() {
  return (
    <div role="status" aria-label="正在加载资产目录" className={styles.tableScroll}>
      <table className={styles.table} aria-hidden="true">
        <thead>
          <tr>
            {[
              "名称 / 外部 ID",
              "类型",
              "Service / Environment",
              "权威来源",
              "映射",
              "生命周期",
              "连接健康",
              "Capability 门禁",
              "最近观测",
            ].map((heading) => (
              <th key={heading}>{heading}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {[0, 1, 2].map((row) => (
            <tr key={row}>
              {Array.from({ length: 9 }, (_, column) => (
                <td key={column}>
                  <span className={styles.skeleton} />
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function useMediaQuery(query: string): boolean {
  const [matches, setMatches] = useState(() =>
    window.matchMedia(query).matches,
  );
  useEffect(() => {
    const media = window.matchMedia(query);
    const handleChange = () => {
      setMatches(media.matches);
    };
    handleChange();
    media.addEventListener("change", handleChange);
    return () => {
      media.removeEventListener("change", handleChange);
    };
  }, [query]);
  return matches;
}
