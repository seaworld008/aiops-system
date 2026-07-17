import {
  type KeyboardEvent,
  useId,
  useRef,
  useState,
} from "react";

import { AbsoluteTime } from "@/shared/ui/AbsoluteTime";
import { StatusBadge } from "@/shared/ui/StatusBadge";

import type { AssetConflict } from "./api";
import styles from "./MappingWorkbenchPage.module.css";
import { conflictRisk } from "./mappingSearch";

export type ConflictQueueProps = {
  conflicts: readonly AssetConflict[];
  selectedConflictId?: string;
  batchSelectedIds: ReadonlySet<string>;
  navigationBlocked: boolean;
  resolveControlsAvailable: boolean;
  currentPageFiltersActive: boolean;
  hasNextPage: boolean;
  onSelect: (conflictId: string) => void;
  onBatchSelectionChange: (
    conflictId: string,
    selected: boolean,
  ) => void;
};

export function ConflictQueue({
  conflicts,
  selectedConflictId,
  batchSelectedIds,
  navigationBlocked,
  resolveControlsAvailable,
  currentPageFiltersActive,
  hasNextPage,
  onSelect,
  onBatchSelectionChange,
}: ConflictQueueProps) {
  const titleId = useId();
  const [activeConflictId, setActiveConflictId] = useState(
    selectedConflictId ?? conflicts[0]?.id,
  );
  const rowRefs = useRef(new Map<string, HTMLButtonElement>());
  const effectiveActiveId = conflicts.some(
    (item) => item.id === activeConflictId,
  )
    ? activeConflictId
    : conflicts.some((item) => item.id === selectedConflictId)
      ? selectedConflictId
      : conflicts[0]?.id;

  const handleKeyDown = (
    event: KeyboardEvent<HTMLButtonElement>,
    index: number,
    conflictId: string,
  ) => {
    if (event.key === "ArrowDown" || event.key === "ArrowUp") {
      event.preventDefault();
      const nextIndex = Math.min(
        conflicts.length - 1,
        Math.max(0, index + (event.key === "ArrowDown" ? 1 : -1)),
      );
      const next = conflicts[nextIndex];
      if (next !== undefined) {
        setActiveConflictId(next.id);
        rowRefs.current.get(next.id)?.focus();
      }
      return;
    }
    if (event.key === "Enter") {
      event.preventDefault();
      onSelect(conflictId);
    }
  };

  return (
    <section className={styles.queue} aria-labelledby={titleId}>
      <header className={styles.sectionHeader}>
        <div>
          <h2 id={titleId}>冲突与未解析队列</h2>
          <p>{conflicts.length} 项安全投影</p>
        </div>
      </header>
      {conflicts.length === 0 ? (
        <p role="status" className={styles.emptyState}>
          {hasNextPage
            ? currentPageFiltersActive
              ? "当前服务端页没有匹配项；这不表示全部冲突均无匹配。后续 cursor 页可能仍有匹配，请继续下一页审阅。"
              : "当前服务端页没有冲突或未解析项；后续 cursor 页可能仍有匹配，请继续下一页审阅。"
            : currentPageFiltersActive
              ? "当前服务端页没有匹配项；风险、Service 和等待时长未执行跨页聚合。"
              : "当前服务端页没有冲突或未解析项。"}
        </p>
      ) : (
        <ul className={styles.queueList}>
          {conflicts.map((item, index) => (
            <li
              key={item.id}
              className={
                selectedConflictId === item.id
                  ? styles.queueItemSelected
                  : styles.queueItem
              }
            >
              {resolveControlsAvailable &&
              item.status === "OPEN" &&
              item.effective_actions.includes(
                "RESOLVE_CONFLICT",
              ) ? (
                <label className={styles.batchCheck}>
                  <input
                    type="checkbox"
                    aria-label={`选择冲突 ${item.asset.display_name}`}
                    checked={batchSelectedIds.has(item.id)}
                    disabled={navigationBlocked}
                    onChange={(event) => {
                      onBatchSelectionChange(
                        item.id,
                        event.currentTarget.checked,
                      );
                    }}
                  />
                </label>
              ) : (
                <span className={styles.batchCheck} aria-hidden="true" />
              )}
              <button
                type="button"
                ref={(element) => {
                  if (element === null) {
                    rowRefs.current.delete(item.id);
                  } else {
                    rowRefs.current.set(item.id, element);
                  }
                }}
                className={styles.queueButton}
                tabIndex={effectiveActiveId === item.id ? 0 : -1}
                aria-current={
                  selectedConflictId === item.id ? "true" : undefined
                }
                disabled={navigationBlocked}
                onFocus={() => {
                  setActiveConflictId(item.id);
                }}
                onClick={() => {
                  onSelect(item.id);
                }}
                onKeyDown={(event) => {
                  handleKeyDown(event, index, item.id);
                }}
              >
                <strong className={styles.queueIdentity}>
                  {item.asset.display_name}
                </strong>
                <span className={styles.queueMeta}>
                  {item.asset.kind} ·{" "}
                  {item.candidate_service?.name ?? "无候选 Service"}
                </span>
                <span className={styles.queueMeta}>
                  {item.type}/{item.field_name}
                </span>
                <span className={styles.queueMeta}>
                  来源 ID：{item.source_id}
                </span>
                <span className={styles.queueStatus}>
                  <StatusBadge tone={riskTone(conflictRisk(item))}>
                    风险 {conflictRisk(item)}
                  </StatusBadge>
                  <StatusBadge tone={item.status === "OPEN" ? "warning" : "neutral"}>
                    {mappingProjection(item)}
                  </StatusBadge>
                </span>
                <span className={styles.queueMeta}>
                  等待 <AbsoluteTime value={item.created_at} />
                </span>
              </button>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

function riskTone(
  risk: ReturnType<typeof conflictRisk>,
): "neutral" | "warning" | "danger" {
  if (risk === "LOW") {
    return "neutral";
  }
  return risk === "MEDIUM" ? "warning" : "danger";
}

function mappingProjection(conflict: AssetConflict): string {
  if (
    conflict.status === "RESOLVED" &&
    conflict.resolution === "CONFIRM_EXACT"
  ) {
    return "EXACT";
  }
  return conflict.status === "OPEN" ? "AMBIGUOUS" : "UNRESOLVED";
}
