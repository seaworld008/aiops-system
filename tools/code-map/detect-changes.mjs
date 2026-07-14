import fs from "node:fs";
import path from "node:path";

import { LocalBackend } from "./node_modules/gitnexus/dist/mcp/local/local-backend.js";

const [scope, baseRef, repoRoot, expectedFilesRaw] = process.argv.slice(2);
const expectedFiles = Number(expectedFilesRaw);
const allowedScopes = new Set(["unstaged", "staged", "all", "compare"]);

function fail(message) {
  console.error("code-map change validator: " + message);
  process.exit(1);
}

if (
  !allowedScopes.has(scope) ||
  !repoRoot ||
  !path.isAbsolute(repoRoot) ||
  !Number.isInteger(expectedFiles) ||
  expectedFiles < 0 ||
  (scope === "compare" && !baseRef)
) {
  fail("invalid scope, repository root, base ref, or expected file count");
}

const incomplete = (value) => {
  if (!value || typeof value !== "object") return false;
  if (
    value.partial === true ||
    value.partialProbe === true ||
    value.truncated === true ||
    value.status === "error"
  ) {
    return true;
  }
  return Object.values(value).some(incomplete);
};

let result;
try {
  const backend = new LocalBackend();
  if (!(await backend.init())) fail("GitNexus backend could not initialize");
  result = await backend.callTool("detect_changes", {
    scope,
    ...(scope === "compare" ? { base_ref: baseRef } : {}),
    repo: repoRoot,
    worktree: repoRoot,
  });
} catch (error) {
  fail(error instanceof Error ? error.message : String(error));
}

if (!result || typeof result !== "object" || result.error || incomplete(result)) {
  fail("GitNexus returned an error, partial, truncated, or otherwise incomplete result");
}

const summary = result.summary;
const changed = result.changed_symbols;
const affected = result.affected_processes;
if (
  !summary ||
  !Number.isInteger(summary.changed_count) ||
  summary.changed_count < 0 ||
  !Number.isInteger(summary.affected_count) ||
  summary.affected_count < 0 ||
  !Array.isArray(changed) ||
  changed.length !== summary.changed_count ||
  !Array.isArray(affected) ||
  affected.length !== summary.affected_count
) {
  fail("GitNexus returned an invalid change summary schema");
}

const reportedFiles = summary.changed_files ?? 0;
if (!Number.isInteger(reportedFiles) || reportedFiles !== expectedFiles) {
  fail("GitNexus did not account for every A/M path in the requested scope");
}

if (expectedFiles === 0) {
  if (
    summary.changed_count !== 0 ||
    summary.affected_count !== 0 ||
    summary.risk_level !== "none"
  ) {
    fail("an empty diff did not produce the exact empty result");
  }
} else if (
  summary.changed_count === 0 ||
  !["low", "medium", "high", "critical"].includes(summary.risk_level)
) {
  fail("a non-empty diff produced zero mapped symbols or an unknown risk level");
}

fs.writeSync(1, JSON.stringify(result, null, 2) + "\n");
