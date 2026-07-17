import type { components } from "@/shared/api/schema";
import { AbsoluteTime } from "@/shared/ui/AbsoluteTime";
import {
  OperationTimeline,
  type OperationTimelineItem,
} from "@/shared/ui/OperationTimeline";
import { StatusBadge } from "@/shared/ui/StatusBadge";

import type {
  AssetSourceRun,
  SourceRunCounts,
} from "./api";
import styles from "./AssetSourcesPage.module.css";

type SourceRunTimelineProps = {
  run: AssetSourceRun;
  workspaceId: string;
  environmentId: string;
};

const stageOrder = [
  ["WAITING", "请求已接受 / 等待执行"],
  ["DELAYED", "延迟重试"],
  ["VALIDATING", "验证来源"],
  ["READING", "读取来源"],
  ["NORMALIZING", "规范化"],
  ["APPLYING", "合并投影"],
  ["CLEANING_UP", "清理凭据"],
  ["COMPLETED", "完成"],
] as const satisfies readonly [
  components["schemas"]["RunStage"],
  string,
][];

export function SourceRunTimeline({
  run,
  workspaceId,
  environmentId,
}: SourceRunTimelineProps) {
  const currentStageIndex = stageOrder.findIndex(
    ([stage]) => stage === run.stage,
  );
  const timelineItems = stageOrder.map(
    ([stage, label], index): OperationTimelineItem => ({
      id: stage,
      label,
      status: stageStatus(run, currentStageIndex, index),
      ...(index === currentStageIndex
        ? { timestamp: run.stage_changed_at }
        : {}),
    }),
  );
  const conflictHref = mappingWorkbenchHref(
    workspaceId,
    environmentId,
    run.source_id,
  );

  return (
    <section
      aria-labelledby="source-run-timeline-title"
      className={styles.runPanel}
    >
      <header className={styles.sectionHeader}>
        <div>
          <h2 id="source-run-timeline-title">Source Run 时间线</h2>
          <p>{runSummary(run.status)}</p>
        </div>
        <StatusBadge tone={runTone(run.status)}>
          {runStatusLabel(run.status)}
        </StatusBadge>
      </header>
      <dl className={styles.definitionList}>
        <div>
          <dt>Run ID</dt>
          <dd data-monospace="true">{run.id}</dd>
        </div>
        <div>
          <dt>运行类型</dt>
          <dd>{runKindLabel(run.kind)}</dd>
        </div>
        <div>
          <dt>来源修订</dt>
          <dd>{run.source_revision}</dd>
        </div>
        <div>
          <dt>触发方式</dt>
          <dd>{triggerLabel(run.trigger_type)}</dd>
        </div>
        <div>
          <dt>凭据清理</dt>
          <dd>{cleanupLabel(run.credential_cleanup_status)}</dd>
        </div>
        <div>
          <dt>阶段更新时间</dt>
          <dd>
            <AbsoluteTime value={run.stage_changed_at} />
          </dd>
        </div>
      </dl>
      <OperationTimeline items={timelineItems} />
      <CountGrid
        counts={run.counts}
        label="所选运行安全计数"
      />
      {run.status === "FAILED" ? (
        <section role="alert" className={styles.failurePanel}>
          <h3>发现运行失败</h3>
          <dl>
            <div>
              <dt>错误代码</dt>
              <dd data-monospace="true">
                {run.failure_code ?? "source_run_failed"}
              </dd>
            </div>
            {run.trace_id === null ? null : (
              <div>
                <dt>Trace ID</dt>
                <dd data-monospace="true">{run.trace_id}</dd>
              </div>
            )}
          </dl>
          <p>上游错误正文不会显示；请使用 Trace ID 联系平台管理员。</p>
        </section>
      ) : null}
      {run.counts.conflicts > 0 ? (
        <p className={styles.conflictLink}>
          <a href={conflictHref}>
            在映射工作台查看 {run.counts.conflicts} 个冲突
          </a>
        </p>
      ) : null}
    </section>
  );
}

export function CountGrid({
  counts,
  label,
}: {
  counts: SourceRunCounts;
  label: string;
}) {
  const items = [
    ["观测", counts.observed],
    ["已创建", counts.created],
    ["已变化", counts.changed],
    ["未变化", counts.unchanged],
    ["冲突", counts.conflicts],
    ["失联", counts.missing],
    ["已陈旧", counts.stale],
    ["已恢复", counts.restored],
    ["已墓碑", counts.tombstoned],
    ["已拒绝", counts.rejected],
  ] as const;
  return (
    <section aria-label={label} className={styles.countSection}>
      <h3>{label}</h3>
      <dl className={styles.countGrid}>
        {items.map(([name, value]) => (
          <div key={name}>
            <dt>{name}</dt>
            <dd>{value}</dd>
          </div>
        ))}
      </dl>
    </section>
  );
}

function stageStatus(
  run: AssetSourceRun,
  currentStageIndex: number,
  index: number,
): OperationTimelineItem["status"] {
  if (index < currentStageIndex) {
    return "complete";
  }
  if (index > currentStageIndex) {
    return "pending";
  }
  if (run.status === "FAILED" || run.status === "CANCELLED") {
    return "failed";
  }
  return run.stage === "COMPLETED" ? "complete" : "current";
}

function runStatusLabel(
  status: components["schemas"]["RunStatus"],
): string {
  const labels: Record<components["schemas"]["RunStatus"], string> = {
    QUEUED: "已排队（QUEUED）",
    DELAYED: "已延迟（DELAYED）",
    RUNNING: "运行中（RUNNING）",
    FINALIZING: "正在完成（FINALIZING）",
    SUCCEEDED: "成功（SUCCEEDED）",
    PARTIAL: "部分完成（PARTIAL）",
    FAILED: "失败（FAILED）",
    CANCELLED: "已取消（CANCELLED）",
  };
  return labels[status];
}

function runSummary(
  status: components["schemas"]["RunStatus"],
): string {
  switch (status) {
    case "SUCCEEDED":
      return "发现完成";
    case "PARTIAL":
      return "发现部分完成；最近成功计数保持独立。";
    case "FAILED":
      return "发现失败；仅显示稳定错误代码与 Trace ID。";
    case "CANCELLED":
      return "发现运行已取消。";
    case "FINALIZING":
      return "发现结果已封存，正在完成清理。";
    case "QUEUED":
    case "DELAYED":
    case "RUNNING":
      return "发现运行仍在进行；页面只轮询此所选运行。";
  }
}

function runTone(
  status: components["schemas"]["RunStatus"],
): "neutral" | "success" | "warning" | "danger" {
  switch (status) {
    case "SUCCEEDED":
      return "success";
    case "PARTIAL":
    case "DELAYED":
      return "warning";
    case "FAILED":
    case "CANCELLED":
      return "danger";
    case "QUEUED":
    case "RUNNING":
    case "FINALIZING":
      return "neutral";
  }
}

function runKindLabel(
  kind: components["schemas"]["RunKind"],
): string {
  const labels: Record<components["schemas"]["RunKind"], string> = {
    VALIDATION: "来源验证",
    DISCOVERY: "发现同步",
    CSV_IMPORT: "CSV 导入",
    API_INGESTION: "API 摄取",
    MANUAL_MUTATION: "手工登记",
  };
  return labels[kind];
}

function triggerLabel(
  trigger: components["schemas"]["TriggerType"],
): string {
  const labels: Record<components["schemas"]["TriggerType"], string> = {
    HUMAN: "人工",
    API: "API",
    SCHEDULED: "计划调度",
  };
  return labels[trigger];
}

function cleanupLabel(
  status: components["schemas"]["CredentialCleanupStatus"],
): string {
  const labels: Record<
    components["schemas"]["CredentialCleanupStatus"],
    string
  > = {
    NOT_OPENED: "未打开凭据",
    PENDING: "等待清理",
    REVOKED: "已吊销",
    NO_CREDENTIAL: "无需凭据",
    UNCERTAIN: "清理结果不确定",
  };
  return labels[status];
}

function mappingWorkbenchHref(
  workspaceId: string,
  environmentId: string,
  sourceId: string,
): string {
  const search = new URLSearchParams({
    workspace: workspaceId,
    environment: environmentId,
    source: sourceId,
    status: JSON.stringify(["OPEN"]),
  });
  return `/asset-mappings?${search.toString()}`;
}
