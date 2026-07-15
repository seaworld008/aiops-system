import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";

const repoRoot = process.argv[2];
if (!repoRoot) {
  console.error("code-map secret scan: repository root is required");
  process.exit(2);
}

const input = fs.readFileSync(0);
const relativePaths = input.toString("utf8").split("\0").filter(Boolean);
const allowedFixtureDigests = new Map([
  [
    "internal/credential/vault/client_test.go",
    new Set([
      "955789569eaa98e1fd408c774636738acae959a93f2d074c7dd7f1a88f767010",
      "44537eb9dceb926215c62e032e36ace6907f5c597fa0815f5d7fc7c123955ead",
    ]),
  ],
]);

function decodedBase64(value) {
  const compact = value.replace(/\s+/g, "");
  if (
    compact.length < 80 ||
    !/^[A-Za-z0-9+/]+={0,2}$/.test(compact) ||
    compact.length % 4 === 1
  ) {
    return null;
  }
  try {
    return Buffer.from(compact, "base64");
  } catch {
    return null;
  }
}

function containsPrivatePem(text) {
  const pattern =
    /-----BEGIN (PRIVATE KEY|ENCRYPTED PRIVATE KEY|RSA PRIVATE KEY|EC PRIVATE KEY|DSA PRIVATE KEY|OPENSSH PRIVATE KEY)-----([\s\S]*?)-----END \1-----/g;
  for (const match of text.matchAll(pattern)) {
    const lines = match[2].replace(/\r/g, "").split("\n");
    const headers = [];
    while (lines.length > 0 && lines[0].trim() === "") lines.shift();
    while (lines.length > 0 && /^[A-Za-z0-9-]+:\s*.+$/.test(lines[0])) {
      headers.push(lines.shift().trim());
    }
    if (headers.length > 0) {
      if (lines.length === 0 || lines[0].trim() !== "") continue;
      while (lines.length > 0 && lines[0].trim() === "") lines.shift();
    }
    const decoded = decodedBase64(lines.join(""));
    if (!decoded || decoded.length < 64) continue;
    if (match[1] === "OPENSSH PRIVATE KEY") {
      if (decoded.subarray(0, 15).toString("binary") === "openssh-key-v1\0") return true;
      continue;
    }
    if (
      /^(RSA|EC|DSA) PRIVATE KEY$/.test(match[1]) &&
      headers.some((line) => /^Proc-Type:\s*4,ENCRYPTED$/i.test(line)) &&
      headers.some((line) => /^DEK-Info:\s*[A-Z0-9-]+,[0-9A-F]+$/i.test(line))
    ) {
      return true;
    }
    if (decoded[0] === 0x30) return true;
  }
  return false;
}

function containsPgpPrivateBlock(text) {
  const pattern =
    /-----BEGIN PGP PRIVATE KEY BLOCK-----([\s\S]*?)-----END PGP PRIVATE KEY BLOCK-----/g;
  for (const match of text.matchAll(pattern)) {
    const encoded = match[1]
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter((line) => line && !line.includes(":") && !line.startsWith("="))
      .join("");
    const decoded = decodedBase64(encoded);
    if (decoded && decoded.length >= 64 && (decoded[0] & 0x80) !== 0) return true;
  }
  return false;
}

function privateMaterialReason(text) {
  if (containsPrivatePem(text)) return "decodable private-key PEM block";
  if (containsPgpPrivateBlock(text)) return "decodable PGP private-key block";
  if (
    /^PuTTY-User-Key-File-[23]: .+$/m.test(text) &&
    /^Private-Lines: [1-9][0-9]*$/m.test(text) &&
    /^Private-MAC: [0-9a-f]+$/im.test(text)
  ) {
    return "PuTTY private-key block";
  }
  if (/AGE-SECRET-KEY-1[0-9A-Z]{20,}/.test(text)) return "age secret key";
  if (
    /minisign encrypted secret key/i.test(text) &&
    /\n[A-Za-z0-9+/]{80,}={0,2}(?:\r?\n|$)/.test(text)
  ) {
    return "minisign encrypted secret key";
  }
  return "";
}

function tokenMaterialReason(relativePath, text) {
  const allowed = allowedFixtureDigests.get(relativePath) ?? new Set();
  for (const match of text.matchAll(/\bhv[sbpr]\.[A-Za-z0-9_-]{20,}/g)) {
    const digest = crypto.createHash("sha256").update(match[0]).digest("hex");
    if (!allowed.has(digest)) return "unapproved Vault token";
  }
  const highConfidencePatterns = [
    /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g,
    /\bgh[pousr]_[A-Za-z0-9_]{20,}\b/g,
    /\bgithub_pat_[A-Za-z0-9_]{20,}\b/g,
    /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g,
    /\bnpm_[A-Za-z0-9_-]{20,}\b/g,
    /\bsk-[A-Za-z0-9_-]{20,}\b/g,
    /\bAIza[0-9A-Za-z_-]{35}\b/g,
    /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g,
  ];
  for (const pattern of highConfidencePatterns) {
    if (pattern.test(text)) return "high-confidence credential material";
  }
  return "";
}

for (const relativePath of relativePaths) {
  const absolutePath = path.resolve(repoRoot, relativePath);
  if (
    absolutePath !== repoRoot &&
    !absolutePath.startsWith(repoRoot + path.sep)
  ) {
    console.error(
      "code-map secret scan: input escaped repository root: " +
        JSON.stringify(relativePath),
    );
    process.exit(2);
  }

  let contents;
  try {
    contents = fs.readFileSync(absolutePath);
  } catch (error) {
    console.error(
      "code-map secret scan: failed to read " +
        JSON.stringify(relativePath) +
        ": " +
        error.message,
    );
    process.exit(2);
  }
  const text = contents.toString("utf8");
  const reason = privateMaterialReason(text) || tokenMaterialReason(relativePath, text);
  if (reason) {
    console.error(
      "code-map secret scan: " +
        reason +
        " detected in " +
        JSON.stringify(relativePath),
    );
    process.exit(1);
  }
}
