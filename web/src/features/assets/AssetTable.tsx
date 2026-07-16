import {
  type KeyboardEvent,
  useEffect,
  useRef,
  useState,
} from "react";

import { AbsoluteTime } from "@/shared/ui/AbsoluteTime";
import { StatusBadge } from "@/shared/ui/StatusBadge";

import type { AssetPage } from "./api";
import styles from "./AssetCatalogPage.module.css";
import { assetKindLabels } from "./assetSearch";

type AssetSummary = AssetPage["items"][number];

type FocusRequest = {
  assetId: string;
  sequence: number;
};

type AssetTableProps = {
  rows: readonly AssetSummary[];
  selectedAssetId?: string;
  focusRequest?: FocusRequest;
  onSelect: (assetId: string) => void;
  onOpen: (assetId: string) => void;
  onEscape: () => void;
};

export function AssetTable({
  rows,
  selectedAssetId,
  focusRequest,
  onSelect,
  onOpen,
  onEscape,
}: AssetTableProps) {
  const [activeAssetId, setActiveAssetId] = useState(
    selectedAssetId ?? rows[0]?.id,
  );
  const rowRefs = useRef(new Map<string, HTMLTableRowElement>());

  const effectiveActiveAssetId = rows.some(
    (row) => row.id === activeAssetId,
  )
    ? activeAssetId
    : selectedAssetId ?? rows[0]?.id;

  useEffect(() => {
    if (focusRequest !== undefined) {
      rowRefs.current.get(focusRequest.assetId)?.focus();
    }
  }, [focusRequest]);

  const handleKeyDown = (
    event: KeyboardEvent<HTMLTableRowElement>,
    rowIndex: number,
    assetId: string,
  ) => {
    if (event.key === "ArrowDown" || event.key === "ArrowUp") {
      event.preventDefault();
      const offset = event.key === "ArrowDown" ? 1 : -1;
      const nextIndex = Math.min(
        rows.length - 1,
        Math.max(0, rowIndex + offset),
      );
      const next = rows[nextIndex];
      if (next !== undefined) {
        setActiveAssetId(next.id);
        rowRefs.current.get(next.id)?.focus();
      }
      return;
    }
    if (event.key === "Enter") {
      event.preventDefault();
      onSelect(assetId);
      return;
    }
    if (event.key === "Escape") {
      event.preventDefault();
      onEscape();
    }
  };

  return (
    <div className={styles.tableScroll}>
      <table className={styles.table} aria-label="资产目录">
        <thead>
          <tr>
            <th className={styles.identityCell} scope="col">
              名称 / 外部 ID
            </th>
            <th scope="col">类型</th>
            <th scope="col">Service / Environment</th>
            <th scope="col">权威来源</th>
            <th scope="col">映射</th>
            <th className={styles.lifecycleCell} scope="col">
              生命周期
            </th>
            <th scope="col">连接健康</th>
            <th scope="col">Capability 门禁</th>
            <th scope="col">最近观测</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row, rowIndex) => (
            <tr
              key={row.id}
              ref={(element) => {
                if (element === null) {
                  rowRefs.current.delete(row.id);
                } else {
                  rowRefs.current.set(row.id, element);
                }
              }}
              tabIndex={effectiveActiveAssetId === row.id ? 0 : -1}
              aria-selected={selectedAssetId === row.id}
              className={
                selectedAssetId === row.id ? styles.selectedRow : undefined
              }
              onFocus={() => {
                setActiveAssetId(row.id);
              }}
              onClick={() => {
                onSelect(row.id);
              }}
              onDoubleClick={() => {
                onOpen(row.id);
              }}
              onKeyDown={(event) => {
                handleKeyDown(event, rowIndex, row.id);
              }}
            >
              <td className={styles.identityCell}>
                <span className={styles.assetName}>{row.display_name}</span>
                <span className={styles.secondaryText}>
                  {row.external_id}
                </span>
                <button
                  type="button"
                  className={styles.inlineAction}
                  onClick={(event) => {
                    event.stopPropagation();
                    onOpen(row.id);
                  }}
                >
                  在完整页打开
                </button>
              </td>
              <td>{assetKindLabels[row.kind]}</td>
              <td>
                <span>
                  {row.service_summaries.map((service) => service.name).join(", ") ||
                    "未绑定 Service"}
                </span>
                <span className={styles.secondaryText}>
                  {row.environment_id}
                </span>
              </td>
              <td>
                <span>{row.source.name}</span>
                <span className={styles.secondaryText}>{row.source.kind}</span>
              </td>
              <td>
                <StatusBadge tone={mappingTone(row.mapping_status)}>
                  {row.mapping_status}
                </StatusBadge>
              </td>
              <td className={styles.lifecycleCell}>
                <StatusBadge tone={lifecycleTone(row.lifecycle)}>
                  {row.lifecycle}
                </StatusBadge>
              </td>
              <td>{row.connection_summary.status}</td>
              <td>
                {row.capability_summary.status} · {row.capability_summary.count}
              </td>
              <td>
                <AbsoluteTime value={row.last_observed_at} />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function mappingTone(
  status: AssetSummary["mapping_status"],
): "success" | "warning" | "danger" {
  if (status === "EXACT") {
    return "success";
  }
  return status === "AMBIGUOUS" ? "warning" : "danger";
}

function lifecycleTone(
  lifecycle: AssetSummary["lifecycle"],
): "neutral" | "success" | "warning" | "danger" {
  if (lifecycle === "ACTIVE") {
    return "success";
  }
  if (lifecycle === "STALE" || lifecycle === "DISCOVERED") {
    return "warning";
  }
  if (lifecycle === "QUARANTINED" || lifecycle === "RETIRED") {
    return "danger";
  }
  return "neutral";
}
