import { useQuery } from "@tanstack/react-query";
import { Dialog } from "radix-ui";

import { useControlPlaneClient } from "@/shared/api/controlPlaneClient";
import type { Scope } from "@/shared/api/queryKeys";
import { AbsoluteTime } from "@/shared/ui/AbsoluteTime";
import { ProblemPanel } from "@/shared/ui/ProblemPanel";
import { StatusBadge } from "@/shared/ui/StatusBadge";

import {
  assetQueryKeys,
  getAsset,
  listAssetRelations,
  problemFromError,
  type AssetDetailResult,
} from "./api";
import {
  assetKindLabels,
  type AssetSearch,
} from "./assetSearch";
import styles from "./AssetCatalogPage.module.css";
import { GovernanceForm } from "./GovernanceForm";

type AssetDetailDrawerProps = {
  scope: Scope;
  assetId: string;
  tab: AssetSearch["tab"];
  onTabChange: (tab: AssetSearch["tab"]) => void;
  onClose: () => void;
  onOpenFullPage: () => void;
};

type AssetDetailPanelProps = {
  scope: Scope;
  assetId: string;
  tab: AssetSearch["tab"];
  onTabChange: (tab: AssetSearch["tab"]) => void;
};

const detailTabs: ReadonlyArray<{
  id: AssetSearch["tab"];
  label: string;
}> = [
  { id: "overview", label: "概览" },
  { id: "connections", label: "连接" },
  { id: "capabilities", label: "能力" },
  { id: "relations", label: "关系" },
  { id: "audit", label: "审计" },
];

export function AssetDetailDrawer({
  scope,
  assetId,
  tab,
  onTabChange,
  onClose,
  onOpenFullPage,
}: AssetDetailDrawerProps) {
  const client = useControlPlaneClient();
  const detailQuery = useQuery({
    queryKey: assetQueryKeys.detail(scope, assetId),
    queryFn: ({ signal }) => getAsset(client, scope, assetId, signal),
  });
  const title =
    detailQuery.data === undefined
      ? "资产详情"
      : `${detailQuery.data.asset.display_name} 资产详情`;

  return (
    <Dialog.Root
      open
      modal={false}
      onOpenChange={(open) => {
        if (!open) {
          onClose();
        }
      }}
    >
      <Dialog.Portal>
        <Dialog.Content className="drawer-content">
          <div className="drawer-header">
            <Dialog.Title>{title}</Dialog.Title>
            <Dialog.Close asChild>
              <button type="button" aria-label={`关闭${title}`}>
                关闭
              </button>
            </Dialog.Close>
          </div>
          <button
            type="button"
            className={styles.fullPageButton}
            onClick={onOpenFullPage}
          >
            在完整页打开
          </button>
          <AssetDetailQueryState
            scope={scope}
            assetId={assetId}
            tab={tab}
            onTabChange={onTabChange}
            detail={detailQuery.data}
            loading={detailQuery.isPending}
            error={detailQuery.error}
          />
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

export function AssetDetailPanel({
  scope,
  assetId,
  tab,
  onTabChange,
}: AssetDetailPanelProps) {
  const client = useControlPlaneClient();
  const detailQuery = useQuery({
    queryKey: assetQueryKeys.detail(scope, assetId),
    queryFn: ({ signal }) => getAsset(client, scope, assetId, signal),
  });
  return (
    <AssetDetailQueryState
      scope={scope}
      assetId={assetId}
      tab={tab}
      onTabChange={onTabChange}
      detail={detailQuery.data}
      loading={detailQuery.isPending}
      error={detailQuery.error}
    />
  );
}

function AssetDetailQueryState({
  scope,
  assetId,
  tab,
  onTabChange,
  detail,
  loading,
  error,
}: AssetDetailPanelProps & {
  detail: AssetDetailResult | undefined;
  loading: boolean;
  error: unknown;
}) {
  if (loading) {
    return (
      <section role="status" className={styles.detailLoading}>
        正在加载资产安全投影…
      </section>
    );
  }
  if (error !== null || detail === undefined) {
    return <ProblemPanel problem={problemFromError(error)} />;
  }
  const asset = detail.asset;
  return (
    <article className={styles.detail}>
      <UnsafeAssetBanner asset={asset} onGovernance={() => onTabChange("overview")} />
      <header className={styles.detailIdentity}>
        <div>
          <h2>{asset.display_name}</h2>
          <p data-monospace="true">asset:{asset.id}</p>
        </div>
        <div className={styles.detailBadges}>
          <StatusBadge tone={asset.lifecycle === "ACTIVE" ? "success" : "warning"}>
            {asset.lifecycle}
          </StatusBadge>
          <StatusBadge tone={asset.mapping_status === "EXACT" ? "success" : "warning"}>
            {asset.mapping_status}
          </StatusBadge>
        </div>
      </header>
      <GovernanceForm
        key={`${scope.workspaceId}:${scope.environmentId}:${asset.id}`}
        scope={scope}
        detail={detail}
      />
      <div role="tablist" aria-label="资产详情标签" className={styles.tabs}>
        {detailTabs.map((item) => (
          <button
            key={item.id}
            type="button"
            role="tab"
            aria-selected={tab === item.id}
            onClick={() => onTabChange(item.id)}
          >
            {item.label}
          </button>
        ))}
      </div>
      <section role="tabpanel" className={styles.tabPanel}>
        {tab === "overview" ? <Overview detail={detail} /> : null}
        {tab === "connections" ? (
          <NeutralState
            title="连接未配置"
            status={asset.connection_summary.status}
            description="当前资产没有已发布的安全连接摘要。"
          />
        ) : null}
        {tab === "capabilities" ? (
          <NeutralState
            title="能力未配置"
            status={asset.capability_summary.status}
            description={`当前安全投影中的能力数量为 ${asset.capability_summary.count}。`}
          />
        ) : null}
        {tab === "relations" ? (
          <Relations scope={scope} assetId={assetId} />
        ) : null}
        {tab === "audit" ? (
          <NeutralState
            title="审计 API 后续接入"
            status="NOT_CONFIGURED"
            description="此处不会使用前端数据伪造审计记录。"
          />
        ) : null}
      </section>
    </article>
  );
}

function UnsafeAssetBanner({
  asset,
  onGovernance,
}: {
  asset: AssetDetailResult["asset"];
  onGovernance: () => void;
}) {
  const notices: Array<{ title: string; reason: string }> = [];
  if (asset.lifecycle === "QUARANTINED") {
    notices.push({
      title: "资产已隔离",
      reason: "原因：资产处于 QUARANTINED 生命周期。",
    });
  } else if (asset.lifecycle === "STALE") {
    notices.push({
      title: "资产观测已陈旧",
      reason: "原因：权威来源尚未恢复有效观测。",
    });
  }
  if (asset.mapping_status === "AMBIGUOUS") {
    notices.push({
      title: "资产映射存在歧义",
      reason: "原因：存在多个候选映射，尚未形成 EXACT 决策。",
    });
  } else if (asset.mapping_status === "UNRESOLVED") {
    notices.push({
      title: "资产映射尚未解析",
      reason: "原因：当前没有经过治理确认的精确映射。",
    });
  }
  if (notices.length === 0) {
    return null;
  }
  return (
    <section role="alert" className={styles.unsafeBanner}>
      {notices.map((notice) => (
        <div key={notice.title}>
          <h3>{notice.title}</h3>
          <p>{notice.reason}</p>
        </div>
      ))}
      <p>影响：禁止新建调查或运行诊断；必须先完成治理审阅。</p>
      <button type="button" onClick={onGovernance}>
        查看治理信息
      </button>
    </section>
  );
}

function Overview({ detail }: { detail: AssetDetailResult }) {
  const asset = detail.asset;
  return (
    <div className={styles.overview}>
      <DefinitionList
        values={[
          ["稳定资产 ID", `asset:${asset.id}`],
          ["外部 ID", asset.external_id],
          ["资产类型", assetKindLabels[asset.kind]],
          ["Environment", asset.environment_id],
          ["权威来源", `${asset.source.name} (${asset.source.id})`],
          ["Provider", asset.provider_kind],
          ["Owner 组", asset.owner_group ?? "未设置"],
          ["关键度", asset.criticality],
          ["数据分类", asset.data_classification],
          ["版本", String(asset.version)],
          ["ETag", detail.etag ?? "服务端未返回"],
        ]}
      />
      <section>
        <h3>绝对观测时间</h3>
        <p>
          <AbsoluteTime value={asset.last_observed_at} /> ·{" "}
          <time dateTime={asset.last_observed_at} data-monospace="true">
            {formatAbsolute(asset.last_observed_at)}
          </time>
        </p>
      </section>
      <section>
        <h3>Service 关系</h3>
        {asset.service_summaries.length === 0 ? (
          <p>未绑定 Service</p>
        ) : (
          <ul>
            {asset.service_summaries.map((service) => (
              <li key={service.id}>
                {service.name} · {service.role} ·{" "}
                <span data-monospace="true">{service.id}</span>
              </li>
            ))}
          </ul>
        )}
      </section>
      <section>
        <h3>安全标签</h3>
        {asset.labels.length === 0 ? (
          <p>未设置标签</p>
        ) : (
          <ul className={styles.labelList}>
            {asset.labels.map((label) => (
              <li key={`${label.key}:${label.value}`}>
                {label.key}={label.value}
              </li>
            ))}
          </ul>
        )}
      </section>
      <section>
        <h3>字段 Provenance</h3>
        <div className={styles.tableScroll}>
          <table className={styles.table}>
            <thead>
              <tr>
                <th scope="col">字段</th>
                <th scope="col">所有权</th>
                <th scope="col">来源 / 修订</th>
                <th scope="col">Provider path</th>
                <th scope="col">观测时间</th>
              </tr>
            </thead>
            <tbody>
              {asset.field_provenance.map((field) => (
                <tr key={field.field_code}>
                  <td>{field.field_code}</td>
                  <td>{field.ownership}</td>
                  <td>
                    <span data-monospace="true">{field.source_id}</span> /{" "}
                    {field.source_revision}
                  </td>
                  <td>{field.provider_path_code}</td>
                  <td data-monospace="true">{formatAbsolute(field.observed_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}

function Relations({ scope, assetId }: { scope: Scope; assetId: string }) {
  const client = useControlPlaneClient();
  const relationsQuery = useQuery({
    queryKey: assetQueryKeys.relations(scope, assetId),
    queryFn: ({ signal }) =>
      listAssetRelations(client, scope, assetId, signal),
  });
  if (relationsQuery.isPending) {
    return <p role="status">正在加载资产关系…</p>;
  }
  if (relationsQuery.error !== null || relationsQuery.data === undefined) {
    return <ProblemPanel problem={problemFromError(relationsQuery.error)} />;
  }
  if (relationsQuery.data.items.length === 0) {
    return <p>当前资产没有关系记录。</p>;
  }
  return (
    <div className={styles.tableScroll}>
      <table className={styles.table}>
        <thead>
          <tr>
            <th scope="col">方向</th>
            <th scope="col">关系类型</th>
            <th scope="col">对端资产</th>
            <th scope="col">状态</th>
            <th scope="col">Provenance</th>
          </tr>
        </thead>
        <tbody>
          {relationsQuery.data.items.map((relation) => {
            const outgoing = relation.source_asset_id === assetId;
            return (
              <tr key={relation.id}>
                <td>{outgoing ? "出向" : "入向"}</td>
                <td>{relation.type}</td>
                <td data-monospace="true">
                  {outgoing
                    ? relation.target_asset_id
                    : relation.source_asset_id}
                </td>
                <td>{relation.status}</td>
                <td>
                  {relation.provenance} · {relation.source_revision}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

function DefinitionList({
  values,
}: {
  values: ReadonlyArray<readonly [string, string]>;
}) {
  return (
    <dl className={styles.definitionList}>
      {values.map(([term, value]) => (
        <div key={term}>
          <dt>{term}</dt>
          <dd data-monospace={term.includes("ID") || term === "ETag" ? "true" : undefined}>
            {value}
          </dd>
        </div>
      ))}
    </dl>
  );
}

function NeutralState({
  title,
  status,
  description,
}: {
  title: string;
  status: string;
  description: string;
}) {
  return (
    <section className={styles.neutralState}>
      <h3>{title}</h3>
      <StatusBadge tone="neutral">{status}</StatusBadge>
      <p>{description}</p>
    </section>
  );
}

function formatAbsolute(value: string): string {
  const date = new Date(value);
  return Number.isNaN(date.getTime())
    ? "时间不可用"
    : date.toLocaleString(undefined, {
        dateStyle: "medium",
        timeStyle: "long",
      });
}
