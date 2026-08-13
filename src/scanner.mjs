import { createHash } from "node:crypto";
import { lstat, readFile, readdir } from "node:fs/promises";
import path from "node:path";
import { findHighEntropyAssignments } from "./entropy.mjs";
import { createIgnoreMatcher, parseIgnoreFile } from "./ignore.mjs";
import {
  PERSONAL_DATA_PATTERNS,
  SECRET_PATTERNS,
  SENSITIVE_FILE_PATTERNS,
  isAtLeastSeverity,
} from "./patterns.mjs";

const DEFAULT_MAX_FILE_SIZE = 1024 * 1024;
const DEFAULT_MAX_FINDINGS = 200;

function normalize(value) {
  return value.split(path.sep).join("/");
}

function lineAndColumn(text, index) {
  const before = text.slice(0, index);
  const lines = before.split("\n");
  return { line: lines.length, column: lines.at(-1).length + 1 };
}

function fingerprint(ruleId, file, matchedValue) {
  return createHash("sha256")
    .update(`${ruleId}\0${file}\0${matchedValue}`)
    .digest("hex")
    .slice(0, 16);
}

function findingFromMatch({ rule, file, text, index, matchedValue, length }) {
  const position = lineAndColumn(text, index);
  return {
    ruleId: rule.id,
    severity: rule.severity,
    message: rule.message,
    file,
    line: position.line,
    column: position.column,
    fingerprint: fingerprint(rule.id, file, matchedValue),
    redacted: `<redacted:${length}>`,
  };
}

function containsNullByte(buffer) {
  const sampleLength = Math.min(buffer.length, 8192);
  for (let index = 0; index < sampleLength; index += 1) {
    if (buffer[index] === 0) return true;
  }
  return false;
}

function isAllowedLine(text, index) {
  const start = text.lastIndexOf("\n", index - 1) + 1;
  const end = text.indexOf("\n", index);
  const line = text.slice(start, end === -1 ? undefined : end);
  return line.includes("repoguard:allow");
}

function inspectText(text, file, options) {
  const findings = [];
  const rules = options.personalData
    ? [...SECRET_PATTERNS, ...PERSONAL_DATA_PATTERNS]
    : SECRET_PATTERNS;

  for (const rule of rules) {
    const pattern = new RegExp(rule.source, rule.flags);
    for (const match of text.matchAll(pattern)) {
      if (isAllowedLine(text, match.index ?? 0)) continue;
      findings.push(
        findingFromMatch({
          rule,
          file,
          text,
          index: match.index ?? 0,
          matchedValue: match[0],
          length: match[0].length,
        }),
      );
    }
  }

  if (options.entropy !== false) {
    for (const match of findHighEntropyAssignments(text, options.minimumEntropy)) {
      if (isAllowedLine(text, match.index)) continue;
      findings.push(
        findingFromMatch({
          rule: match,
          file,
          text,
          index: match.index,
          matchedValue: text.slice(match.index, match.index + match.length),
          length: match.length,
        }),
      );
    }
  }

  return findings;
}

function sensitiveFilenameFinding(relativePath) {
  if (/\.example$/i.test(relativePath)) return null;
  const rule = SENSITIVE_FILE_PATTERNS.find(({ pattern }) => pattern.test(relativePath));
  if (!rule) return null;
  return {
    ruleId: rule.id,
    severity: rule.severity,
    message: "Sensitive filename should be reviewed before publishing",
    file: relativePath,
    line: 1,
    column: 1,
    fingerprint: fingerprint(rule.id, relativePath, relativePath),
    redacted: "<filename-only>",
  };
}

async function readIgnorePatterns(root) {
  try {
    return parseIgnoreFile(await readFile(path.join(root, ".repoguardignore"), "utf8"));
  } catch (error) {
    if (error.code === "ENOENT") return [];
    throw error;
  }
}

async function collectFiles(target, root, isIgnored, files, skipped) {
  const info = await lstat(target);
  const relativePath = normalize(path.relative(root, target)) || path.basename(target);
  if (isIgnored(relativePath) && target !== root) {
    skipped.ignored += 1;
    return;
  }

  if (info.isSymbolicLink()) {
    skipped.symlink += 1;
    return;
  }

  if (info.isDirectory()) {
    const entries = await readdir(target, { withFileTypes: true });
    for (const entry of entries) {
      await collectFiles(path.join(target, entry.name), root, isIgnored, files, skipped);
    }
  } else if (info.isFile()) {
    files.push({ absolutePath: target, relativePath, size: info.size });
  }
}

export async function scanPath(targetPath = ".", options = {}) {
  const target = path.resolve(targetPath);
  const targetInfo = await lstat(target);
  if (targetInfo.isSymbolicLink()) {
    throw new Error("Refusing to scan a symbolic-link target");
  }
  const root = targetInfo.isDirectory() ? target : path.dirname(target);
  const ignorePatterns = await readIgnorePatterns(root);
  const isIgnored = createIgnoreMatcher([...ignorePatterns, ...(options.ignore ?? [])]);
  const files = [];
  const skipped = { ignored: 0, large: 0, binary: 0, symlink: 0 };
  await collectFiles(target, root, isIgnored, files, skipped);

  const findings = [];
  const maxFileSize = options.maxFileSize ?? DEFAULT_MAX_FILE_SIZE;
  const maxFindings = options.maxFindings ?? DEFAULT_MAX_FINDINGS;
  let scannedFiles = 0;
  let truncated = false;

  for (let fileIndex = 0; fileIndex < files.length; fileIndex += 1) {
    if (findings.length >= maxFindings) {
      truncated = true;
      break;
    }

    const file = files[fileIndex];
    const filenameFinding = sensitiveFilenameFinding(file.relativePath);
    if (filenameFinding) findings.push(filenameFinding);
    if (file.size > maxFileSize) {
      skipped.large += 1;
      continue;
    }

    const buffer = await readFile(file.absolutePath);
    if (containsNullByte(buffer)) {
      skipped.binary += 1;
      continue;
    }

    scannedFiles += 1;
    const fileFindings = inspectText(buffer.toString("utf8"), file.relativePath, {
      personalData: options.personalData === true,
      entropy: options.entropy,
      minimumEntropy: options.minimumEntropy ?? 4.1,
    });
    const remainingCapacity = Math.max(0, maxFindings - findings.length);
    if (fileFindings.length > remainingCapacity) truncated = true;
    findings.push(...fileFindings.slice(0, remainingCapacity));

    if (findings.length >= maxFindings && fileIndex < files.length - 1) {
      truncated = true;
      break;
    }
  }

  const limitedFindings = findings.sort((left, right) =>
    left.file.localeCompare(right.file) || left.line - right.line || left.ruleId.localeCompare(right.ruleId),
  );
  const minimumSeverity = options.minimumSeverity ?? "high";

  return {
    version: 1,
    target,
    scannedFiles,
    skipped,
    truncated,
    minimumSeverity,
    findings: limitedFindings,
    blockingFindings: limitedFindings.filter((finding) =>
      isAtLeastSeverity(finding.severity, minimumSeverity),
    ).length,
  };
}

export { isAtLeastSeverity } from "./patterns.mjs";
