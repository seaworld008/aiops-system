import { useQuery } from "@tanstack/react-query";
import {
  useEffect,
  useMemo,
  useRef,
} from "react";

import { useControlPlaneClient } from "@/shared/api/controlPlaneClient";
import { useScope } from "@/shared/api/queryKeys";
import type { components } from "@/shared/api/schema";
import { useOperation } from "@/shared/operations/useOperation";
import { AbsoluteTime } from "@/shared/ui/AbsoluteTime";
import { CursorPagination } from "@/shared/ui/CursorPagination";
import { FilterBar } from "@/shared/ui/FilterBar";
import { ProblemPanel } from "@/shared/ui/ProblemPanel";
import { StatusBadge } from "@/shared/ui/StatusBadge";

import {
  type AssetSourceSummary,
  getAssetSource,
  listAssetSources,
  sourceProblemFromError,
  sourceQueryKeys,
  sourceRunPollAdapter,
} from "./api";
import styles from "./AssetSourcesPage.module.css";
import {
  canonicalizeSourceSearch,
  changeSourceFilters,
  nextSourcePage,
  selectSource,
  sourceKinds,
  sourceStatuses,
  type SourceSearch,
} from "./sourceSearch";
import {
  CountGrid,
  SourceRunTimeline,
} from "./SourceRunTimeline";

export type SourceSearchChangeOptions = {
  replace?: boolean;
};

export type AssetSourcesPageProps = {
  search: SourceSearch;
  onSearchChange: (
    search: SourceSearch,
    options?: SourceSearchChangeOptions,
  ) => void;
};

export function AssetSourcesPage({
  search,
  onSearchChange,
}: AssetSourcesPageProps) {
  const client = useControlPlaneClient();
  const { scope } = useScope();
  const canonicalSearch = useMemo(
    () =>
      canonicalizeSourceSearch({
        ...search,
        workspace: scope.workspaceId,
        environment: scope.environmentId,
      }),
    [scope.environmentId, scope.workspaceId, search],
  );
  const canonicalIdentity = JSON.stringify(canonicalSearch);
  const canonicalReplace = useRef<string | undefined>(undefined);

  useEffect(() => {
    if (canonicalReplace.current !== canonicalIdentity) {
      canonicalReplace.current = canonicalIdentity;
      onSearchChange(canonicalSearch, { replace: true });
    }
  }, [canonicalIdentity, canonicalSearch, onSearchChange]);

  const sourcesQuery = useQuery({
    queryKey: sourceQueryKeys.list(scope, canonicalSearch),
    queryFn: ({ signal }) =>
      listAssetSources(
        client,
        scope.workspaceId,
        canonicalSearch,
        signal,
      ),
  });
  const selectedListSource =
    sourcesQuery.data?.items.find(
      (source) => source.id === canonicalSearch.sourceId,
    ) ?? null;
  const detailQuery = useQuery({
    queryKey: sourceQueryKeys.detail(
      scope,
      canonicalSearch.sourceId ?? "unselected",
    ),
    queryFn: ({ signal }) => {
      if (canonicalSearch.sourceId === undefined) {
        throw new Error("Source selection is required");
      }
      return getAssetSource(
        client,
        scope.workspaceId,
        canonicalSearch.sourceId,
        signal,
      );
    },
    enabled: canonicalSearch.sourceId !== undefined,
  });
  const selectedSource =
    detailQuery.data?.summary ?? selectedListSource;

  return (
    <section className={styles.page}>
      <nav aria-label="面包屑" className={styles.breadcrumb}>
        资产与连接 / 发现与同步
      </nav>
      <header className={styles.pageHeader}>
        <div>
          <h1>发现来源</h1>
          <p>
            只读查看来源库存、最近成功结果与所选 Source Run；运行能力继续关闭。
          </p>
        </div>
      </header>
      <SourceFilters
        search={canonicalSearch}
        onChange={onSearchChange}
      />
      {sourcesQuery.isPending ? (
        <section role="status" className={styles.statePanel}>
          正在读取来源安全投影…
        </section>
      ) : null}
      {sourcesQuery.error !== null ? (
        <ProblemPanel problem={sourceProblemFromError(sourcesQuery.error)} />
      ) : null}
      {sourcesQuery.data === undefined ? null : (
        <>
          <SourceInventory
            sources={sourcesQuery.data.items}
            selectedSourceId={canonicalSearch.sourceId}
            onSelect={(sourceId) => {
              onSearchChange(
                selectSource(canonicalSearch, sourceId),
              );
            }}
          />
          <CursorPagination
            hasPrevious={false}
            hasNext={sourcesQuery.data.page.next_cursor !== null}
            onPrevious={() => undefined}
            onNext={() => {
              const cursor = sourcesQuery.data?.page.next_cursor;
              if (cursor !== null && cursor !== undefined) {
                onSearchChange(
                  nextSourcePage(canonicalSearch, cursor),
                );
              }
            }}
          />
        </>
      )}
      {canonicalSearch.sourceId === undefined ? (
        <section role="status" className={styles.statePanel}>
          <h2>选择一个来源查看详情</h2>
          <p>来源选择保存在 URL 的 sourceId 中。</p>
        </section>
      ) : null}
      {detailQuery.isPending && canonicalSearch.sourceId !== undefined ? (
        <section role="status" className={styles.statePanel}>
          正在读取来源详情…
        </section>
      ) : null}
      {detailQuery.error !== null ? (
        <ProblemPanel problem={sourceProblemFromError(detailQuery.error)} />
      ) : null}
      {detailQuery.data === undefined ? null : (
        <SourceDetail
          detail={detailQuery.data}
          selectedSource={selectedSource}
        />
      )}
      {canonicalSearch.runId === undefined ? null : (
        <SelectedSourceRun
          runId={canonicalSearch.runId}
          expectedSourceId={canonicalSearch.sourceId}
          workspaceId={scope.workspaceId}
          environmentId={scope.environmentId}
        />
      )}
    </section>
  );
}

function SourceFilters({
  search,
  onChange,
}: {
  search: SourceSearch;
  onChange: AssetSourcesPageProps["onSearchChange"];
}) {
  const activeCount = search.status.length + search.kind.length;
  return (
    <FilterBar
      activeCount={activeCount}
      onClearAll={() => {
        onChange(
          changeSourceFilters(search, {
            status: [],
            kind: [],
          }),
        );
      }}
    >
      <label>
        <span>来源状态</span>
        <select
          aria-label="来源状态"
          multiple
          value={search.status}
          onChange={(event) => {
            onChange(
              changeSourceFilters(search, {
                status: selectedStatuses(event.currentTarget),
              }),
            );
          }}
        >
          {sourceStatuses.map((status) => (
            <option key={status} value={status}>
              {sourceStatusLabel(status)}
            </option>
          ))}
        </select>
      </label>
      <label>
        <span>来源类型</span>
        <select
          aria-label="来源类型"
          multiple
          value={search.kind}
          onChange={(event) => {
            onChange(
              changeSourceFilters(search, {
                kind: selectedKinds(event.currentTarget),
              }),
            );
          }}
        >
          {sourceKinds.map((kind) => (
            <option key={kind} value={kind}>
              {sourceKindLabel(kind)}
            </option>
          ))}
        </select>
      </label>
    </FilterBar>
  );
}

function SourceInventory({
  sources,
  selectedSourceId,
  onSelect,
}: {
  sources: readonly AssetSourceSummary[];
  selectedSourceId: string | undefined;
  onSelect: (sourceId: string) => void;
}) {
  if (sources.length === 0) {
    return (
      <section role="status" className={styles.statePanel}>
        <h2>没有匹配的来源</h2>
        <p>请清除筛选；本页面不提供创建来源或同步动作。</p>
      </section>
    );
  }
  return (
    <section
      aria-labelledby="source-inventory-title"
      className={styles.inventory}
    >
      <header className={styles.sectionHeader}>
        <div>
          <h2 id="source-inventory-title">来源库存</h2>
          <p>{sources.length} 个服务器安全投影</p>
        </div>
      </header>
      <div className={styles.tableScroller}>
        <table>
          <thead>
            <tr>
              <th scope="col">名称</th>
              <th scope="col">类型 / Provider</th>
              <th scope="col">来源状态</th>
              <th scope="col">Gate</th>
              <th scope="col">最近成功</th>
              <th scope="col">当前游标摘要</th>
            </tr>
          </thead>
          <tbody>
            {sources.map((source) => (
              <tr
                key={source.id}
                aria-selected={source.id === selectedSourceId}
              >
                <th scope="row">
                  <button
                    type="button"
                    onClick={() => {
                      onSelect(source.id);
                    }}
                  >
                    {source.name}
                  </button>
                  <span data-monospace="true">{source.id}</span>
                </th>
                <td>
                  {sourceKindLabel(source.kind)}
                  <span>{source.provider_kind}</span>
                </td>
                <td>
                  <StatusBadge tone={sourceStatusTone(source.status)}>
                    {sourceStatusLabel(source.status)}
                  </StatusBadge>
                </td>
                <td>
                  <StatusBadge tone={gateTone(source.gate_status)}>
                    {gateLabel(source.gate_status)}
                  </StatusBadge>
                </td>
                <td>
                  {source.last_success_at === null ? (
                    "尚无成功运行"
                  ) : (
                    <AbsoluteTime value={source.last_success_at} />
                  )}
                </td>
                <td data-monospace="true">
                  {source.checkpoint_sha256 ?? "尚无 checkpoint"}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}

function SourceDetail({
  detail,
  selectedSource,
}: {
  detail: components["schemas"]["AssetSourceDetail"];
  selectedSource: AssetSourceSummary | null;
}) {
  const source = selectedSource ?? detail.summary;
  return (
    <section
      aria-labelledby="source-detail-title"
      className={styles.detailPanel}
    >
      <header className={styles.sectionHeader}>
        <div>
          <h2 id="source-detail-title">{source.name}</h2>
          <p>来源详情仅显示服务端安全字段。</p>
        </div>
        <StatusBadge tone={sourceStatusTone(source.status)}>
          {sourceStatusLabel(source.status)}
        </StatusBadge>
      </header>
      <dl className={styles.definitionList}>
        <div>
          <dt>来源 ID</dt>
          <dd data-monospace="true">{source.id}</dd>
        </div>
        <div>
          <dt>来源类型</dt>
          <dd>{sourceKindLabel(source.kind)}</dd>
        </div>
        <div>
          <dt>Provider</dt>
          <dd>{source.provider_kind}</dd>
        </div>
        <div>
          <dt>同步方式</dt>
          <dd>{syncModeLabel(detail.latest_revision.sync_mode)}</dd>
        </div>
        <div>
          <dt>权威环境范围</dt>
          <dd>
            <ul className={styles.authorityList}>
              {detail.latest_revision.authority_environment_ids.map(
                (environmentId) => (
                  <li key={environmentId} data-monospace="true">
                    {environmentId}
                  </li>
                ),
              )}
            </ul>
          </dd>
        </div>
        <div>
          <dt>Gate 状态</dt>
          <dd>{gateLabel(source.gate_status)}</dd>
        </div>
        <div>
          <dt>最新修订</dt>
          <dd>
            {detail.latest_revision.revision} /{" "}
            {detail.latest_revision.status}
          </dd>
        </div>
        <div>
          <dt>已发布修订</dt>
          <dd>
            {detail.published_revision === null
              ? "尚未发布"
              : `${detail.published_revision.revision} / ${detail.published_revision.status}`}
          </dd>
        </div>
        <div>
          <dt>更新时间</dt>
          <dd>
            <AbsoluteTime value={source.updated_at} />
          </dd>
        </div>
      </dl>
      {source.last_success_run_id !== null &&
      source.last_run_counts !== null ? (
        <CountGrid
          counts={source.last_run_counts}
          label="最近成功运行计数"
        />
      ) : (
        <p className={styles.safeNote}>尚无最近成功运行计数。</p>
      )}
      {source.current_run_counts === null ? (
        <p className={styles.safeNote}>当前没有非终态运行。</p>
      ) : (
        <CountGrid
          counts={source.current_run_counts}
          label="当前非终态运行计数"
        />
      )}
    </section>
  );
}

function SelectedSourceRun({
  runId,
  expectedSourceId,
  workspaceId,
  environmentId,
}: {
  runId: string;
  expectedSourceId: string | undefined;
  workspaceId: string;
  environmentId: string;
}) {
  const client = useControlPlaneClient();
  const adapter = useMemo(
    () => sourceRunPollAdapter(client, expectedSourceId),
    [client, expectedSourceId],
  );
  const runQuery = useOperation({
    workspaceId,
    environmentId,
    kind: "asset-source-run",
    operationId: runId,
    adapter,
  });

  useEffect(() => {
    const url = new URL(window.location.href);
    if (url.searchParams.get("operationId") === runId) {
      url.searchParams.delete("operationId");
      window.history.replaceState(window.history.state, "", url);
    }
  }, [runId]);

  if (runQuery.isPending) {
    return (
      <section role="status" className={styles.statePanel}>
        正在恢复所选 Source Run…
      </section>
    );
  }
  if (runQuery.error !== null) {
    return (
      <ProblemPanel problem={sourceProblemFromError(runQuery.error)} />
    );
  }
  if (runQuery.data === undefined) {
    return null;
  }
  if (
    expectedSourceId !== undefined &&
    runQuery.data.source_id !== expectedSourceId
  ) {
    return (
      <section role="alert" className={styles.failurePanel}>
        <h2>所选运行不属于当前来源</h2>
        <p>已停止显示运行详情；不会跨来源猜测或重定向。</p>
      </section>
    );
  }
  return (
    <SourceRunTimeline
      run={runQuery.data}
      workspaceId={workspaceId}
      environmentId={environmentId}
    />
  );
}

function selectedStatuses(
  select: HTMLSelectElement,
): components["schemas"]["SourceStatus"][] {
  const selected = new Set(
    Array.from(select.selectedOptions, (option) => option.value),
  );
  return sourceStatuses.filter((status) => selected.has(status));
}

function selectedKinds(
  select: HTMLSelectElement,
): components["schemas"]["SourceKind"][] {
  const selected = new Set(
    Array.from(select.selectedOptions, (option) => option.value),
  );
  return sourceKinds.filter((kind) => selected.has(kind));
}

function sourceKindLabel(
  kind: components["schemas"]["SourceKind"],
): string {
  const labels: Record<components["schemas"]["SourceKind"], string> = {
    MANUAL: "手工来源",
    CSV_IMPORT: "CSV 导入",
    CONTROL_PLANE_API: "Control Plane API",
    EXTERNAL_CMDB: "外部 CMDB",
    VSPHERE: "vSphere",
    PROXMOX: "Proxmox",
    OPENSTACK: "OpenStack",
    CLOUD_PROVIDER: "云平台",
    KUBERNETES_OPERATOR: "Kubernetes Operator",
    AWX_INVENTORY: "AWX Inventory",
  };
  return labels[kind];
}

function sourceStatusLabel(
  status: components["schemas"]["SourceStatus"],
): string {
  const labels: Record<
    components["schemas"]["SourceStatus"],
    string
  > = {
    ACTIVE: "活动",
    PAUSED: "已暂停",
    DEGRADED: "已降级",
    DISABLED: "已禁用",
  };
  return labels[status];
}

function sourceStatusTone(
  status: components["schemas"]["SourceStatus"],
): "success" | "warning" | "danger" {
  switch (status) {
    case "ACTIVE":
      return "success";
    case "PAUSED":
    case "DEGRADED":
      return "warning";
    case "DISABLED":
      return "danger";
  }
}

function gateLabel(
  status: components["schemas"]["SourceGateStatus"],
): string {
  const labels: Record<
    components["schemas"]["SourceGateStatus"],
    string
  > = {
    UNAVAILABLE: "不可用",
    VALIDATING: "验证中",
    AVAILABLE: "可用",
    DEGRADED: "已降级",
    SUSPENDED: "已暂停",
  };
  return labels[status];
}

function gateTone(
  status: components["schemas"]["SourceGateStatus"],
): "neutral" | "success" | "warning" | "danger" {
  switch (status) {
    case "AVAILABLE":
      return "success";
    case "VALIDATING":
    case "DEGRADED":
      return "warning";
    case "SUSPENDED":
      return "danger";
    case "UNAVAILABLE":
      return "neutral";
  }
}

function syncModeLabel(
  mode: components["schemas"]["SourceSyncMode"],
): string {
  const labels: Record<
    components["schemas"]["SourceSyncMode"],
    string
  > = {
    MANUAL: "手工",
    ON_DEMAND: "按需",
    SCHEDULED: "计划调度",
  };
  return labels[mode];
}
