import type { PropsWithChildren } from "react";

type FilterBarProps = PropsWithChildren<{
  activeCount: number;
  onClearAll: () => void;
}>;

export function FilterBar({
  activeCount,
  onClearAll,
  children,
}: FilterBarProps) {
  return (
    <section aria-label="筛选" className="filter-bar">
      <div className="filter-bar-fields">{children}</div>
      <button
        type="button"
        disabled={activeCount === 0}
        aria-label={`清除全部 ${activeCount} 个筛选`}
        onClick={onClearAll}
      >
        清除全部
      </button>
    </section>
  );
}
