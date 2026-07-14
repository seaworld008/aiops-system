import fs from "node:fs";
import path from "node:path";

const [directory, expectedHead, expectedFingerprint, expectedClean] =
  process.argv.slice(2);
if (!directory || !expectedHead || !expectedFingerprint || !expectedClean) {
  console.error(
    "code-map snapshot validator: usage <directory> <head> <fingerprint> <clean>",
  );
  process.exit(2);
}

const expectedNames = [
  "community-count.txt",
  "file-count.txt",
  "manifest.txt",
  "node-count.txt",
  "process-count.txt",
  "relationship-count.txt",
  "structural-check.json",
];

function fail(message) {
  console.error("code-map snapshot validator: " + message);
  process.exit(1);
}

const names = fs.readdirSync(directory).sort();
if (JSON.stringify(names) !== JSON.stringify(expectedNames)) {
  fail("snapshot does not contain the exact report whitelist");
}

for (const name of names) {
  const reportPath = path.join(directory, name);
  const stats = fs.lstatSync(reportPath);
  if (
    !stats.isFile() ||
    stats.isSymbolicLink() ||
    stats.nlink !== 1 ||
    (typeof process.getuid === "function" && stats.uid !== process.getuid()) ||
    (stats.mode & 0o077) !== 0 ||
    stats.size < 1 ||
    stats.size > 1024 * 1024
  ) {
    fail("unsafe report metadata for " + JSON.stringify(name));
  }
}

const manifestEntries = fs
  .readFileSync(path.join(directory, "manifest.txt"), "utf8")
  .trimEnd()
  .split("\n")
  .map((line) => {
    const separator = line.indexOf("=");
    if (separator < 1) fail("invalid manifest line");
    return [line.slice(0, separator), line.slice(separator + 1)];
  });
const manifest = Object.fromEntries(manifestEntries);
if (
  manifestEntries.length !== 7 ||
  Object.keys(manifest).length !== 7 ||
  manifest.git_head !== expectedHead ||
  manifest.worktree_fingerprint !== expectedFingerprint ||
  manifest.worktree_clean !== expectedClean ||
  manifest.authoritative !== "false" ||
  manifest.pnpm !== "10.34.0" ||
  manifest.gitnexus !== "1.6.9" ||
  !/^v24\.[0-9]+\.[0-9]+$/.test(manifest.node)
) {
  fail("manifest schema or binding is invalid");
}

const countReports = new Map([
  ["community-count.txt", "communities"],
  ["file-count.txt", "files"],
  ["node-count.txt", "nodes"],
  ["process-count.txt", "processes"],
  ["relationship-count.txt", "relationships"],
]);
for (const [name, column] of countReports) {
  let report;
  try {
    report = JSON.parse(fs.readFileSync(path.join(directory, name), "utf8"));
  } catch {
    fail("invalid JSON in " + name);
  }
  const table = new RegExp(
    "^\\| " +
      column +
      " \\|\\n\\| --- \\|\\n\\| [0-9]+ \\|$",
  );
  if (
    Object.keys(report).sort().join(",") !== "markdown,row_count" ||
    report.row_count !== 1 ||
    typeof report.markdown !== "string" ||
    !table.test(report.markdown)
  ) {
    fail("invalid count report schema in " + name);
  }
}

let structural;
try {
  structural = JSON.parse(
    fs.readFileSync(path.join(directory, "structural-check.json"), "utf8"),
  );
} catch {
  fail("invalid structural-check JSON");
}
if (
  structural.status !== "clean" ||
  structural.cycleCount !== 0 ||
  !Array.isArray(structural.cycles) ||
  structural.cycles.length !== 0
) {
  fail("structural check is not clean and cycle-free");
}
