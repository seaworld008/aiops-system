import { AbsoluteTime } from "./AbsoluteTime";

export type OperationTimelineItem = {
  id: string;
  label: string;
  status: "pending" | "current" | "complete" | "failed";
  timestamp?: string;
};

type OperationTimelineProps = {
  items: readonly OperationTimelineItem[];
};

const statusText: Record<OperationTimelineItem["status"], string> = {
  pending: "等待",
  current: "进行中",
  complete: "完成",
  failed: "失败",
};

export function OperationTimeline({ items }: OperationTimelineProps) {
  return (
    <ol aria-label="Operation 时间线" className="operation-timeline">
      {items.map((item) => (
        <li key={item.id} data-status={item.status}>
          <span aria-hidden="true" className="operation-marker" />
          <span>{item.label}</span>
          <span className="operation-status">{statusText[item.status]}</span>
          {item.timestamp === undefined ? null : (
            <AbsoluteTime value={item.timestamp} />
          )}
        </li>
      ))}
    </ol>
  );
}
