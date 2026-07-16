import type { PropsWithChildren } from "react";

type StatusTone = "neutral" | "success" | "warning" | "danger";

const toneNames: Record<StatusTone, string> = {
  neutral: "状态",
  success: "成功",
  warning: "警告",
  danger: "危险",
};

type StatusBadgeProps = PropsWithChildren<{
  tone: StatusTone;
}>;

export function StatusBadge({ tone, children }: StatusBadgeProps) {
  const text = typeof children === "string" ? children : "状态";
  return (
    <span
      className={`status-badge status-badge-${tone}`}
      aria-label={`${toneNames[tone]}：${text}`}
    >
      {children}
    </span>
  );
}
