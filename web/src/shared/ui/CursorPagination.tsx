type CursorPaginationProps = {
  hasPrevious: boolean;
  hasNext: boolean;
  onPrevious: () => void;
  onNext: () => void;
};

export function CursorPagination({
  hasPrevious,
  hasNext,
  onPrevious,
  onNext,
}: CursorPaginationProps) {
  return (
    <nav aria-label="分页" className="cursor-pagination">
      <button type="button" disabled={!hasPrevious} onClick={onPrevious}>
        上一页
      </button>
      <button type="button" disabled={!hasNext} onClick={onNext}>
        下一页
      </button>
    </nav>
  );
}
