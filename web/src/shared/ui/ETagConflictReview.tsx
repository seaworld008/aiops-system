export type ETagConflictDiffRow = {
  field: string;
  submittedValue: string;
  serverValue: string;
};

type ETagConflictReviewProps = {
  clientVersion: string;
  serverVersion: string;
  diffRows: readonly ETagConflictDiffRow[];
  onReload: () => void;
};

export function ETagConflictReview({
  clientVersion,
  serverVersion,
  diffRows,
  onReload,
}: ETagConflictReviewProps) {
  return (
    <section role="status" className="etag-conflict-review">
      <h2>资源已被其他操作更新</h2>
      <dl>
        <div>
          <dt>提交时版本</dt>
          <dd data-monospace="true">{clientVersion}</dd>
        </div>
        <div>
          <dt>服务端版本</dt>
          <dd data-monospace="true">{serverVersion}</dd>
        </div>
      </dl>
      <div className="data-table-scroll">
        <table className="data-table">
          <caption className="sr-only">提交值与服务端值差异</caption>
          <thead>
            <tr>
              <th scope="col">字段</th>
              <th scope="col">提交值</th>
              <th scope="col">服务端值</th>
            </tr>
          </thead>
          <tbody>
            {diffRows.map((row) => (
              <tr key={row.field}>
                <td data-monospace="true">{row.field}</td>
                <td>{row.submittedValue}</td>
                <td>{row.serverValue}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <button type="button" onClick={onReload}>
        重新加载并审阅
      </button>
    </section>
  );
}
