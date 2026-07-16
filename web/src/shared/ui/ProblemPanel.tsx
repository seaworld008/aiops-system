import type { ClientProblem } from "@/shared/api/problem";

type ProblemPanelProps = {
  problem: ClientProblem;
};

export function ProblemPanel({ problem }: ProblemPanelProps) {
  return (
    <section role="alert" className="problem-panel">
      <h2>{problem.title}</h2>
      <p>{problem.detail}</p>
      <dl>
        <div>
          <dt>错误代码</dt>
          <dd data-monospace="true">{problem.code}</dd>
        </div>
        {problem.trace_id === undefined ? null : (
          <div>
            <dt>Trace ID</dt>
            <dd data-monospace="true">{problem.trace_id}</dd>
          </div>
        )}
      </dl>
    </section>
  );
}
