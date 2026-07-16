import { z } from "zod";

import type { components } from "./schema";

export const problemSchema = z
  .object({
    type: z.literal("about:blank"),
    title: z.string().min(1).max(128),
    status: z.number().int().min(400).max(599),
    code: z.string().regex(/^[a-z][a-z0-9_]{0,127}$/),
    detail: z.string().min(1).max(512),
    trace_id: z.string().regex(/^[a-f0-9]{32}$/),
  })
  .strict();

export type ServerProblem = components["schemas"]["Problem"];

export type ClientProblem = Omit<ServerProblem, "trace_id"> & {
  trace_id?: string;
};

export class ControlPlaneProblemError extends Error {
  readonly problem: ClientProblem;

  constructor(problem: ClientProblem) {
    super(`Control Plane request failed: ${problem.code}`);
    this.name = "ControlPlaneProblemError";
    this.problem = problem;
  }
}

export function unexpectedResponseProblem(
  status: number,
  traceID: string | undefined,
): ClientProblem {
  return {
    type: "about:blank",
    title: "Unexpected response",
    status: status >= 400 && status <= 599 ? status : 500,
    code: "unexpected_response",
    detail: "The Control Plane returned an unexpected response.",
    ...(traceID === undefined ? {} : { trace_id: traceID }),
  };
}

export function safeTraceID(headers: Headers): string | undefined {
  const value = headers.get("X-Trace-ID")?.toLowerCase();
  return value !== undefined && /^[a-f0-9]{32}$/.test(value) ? value : undefined;
}
