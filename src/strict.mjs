import { constants } from "node:fs";
import { lstat, open, opendir } from "node:fs/promises";
import path from "node:path";
import { isAtLeastSeverity } from "./patterns.mjs";

const CEILINGS = Object.freeze({
  maxFileSize: 1024 * 1024, maxFindings: 10000, maxFiles: 5000,
  maxEntries: 10000, maxTotalBytes: 64 * 1024 * 1024, maxDepth: 64,
});

function policy(options) {
  if ((options.ignore?.length ?? 0) !== 0 || options.entropy === false ||
      (options.minimumEntropy !== undefined && options.minimumEntropy !== 4.1) ||
      !["low", "medium", "high"].includes(options.minimumSeverity ?? "high")) {
    throw new Error("Strict gate options cannot weaken the detection policy");
  }
  const limits = {};
  for (const [name, ceiling] of Object.entries(CEILINGS)) {
    const value = options[name] ?? (name === "maxFindings" ? 200 : ceiling);
    if (!Number.isSafeInteger(value) || value <= 0 || value > ceiling) {
      throw new Error("Strict gate limits must be positive integers within policy ceilings");
    }
    limits[name] = value;
  }
  return limits;
}

function stamp(info) {
  return [info.dev, info.ino, info.mode, info.size, info.mtimeMs, info.ctimeMs].join(":");
}

export function isSafePathComponent(name) {
  return name.length > 0 && name === name.normalize("NFC") &&
    !/[\p{Cc}\p{Cf}<>:"/\\|?*]/u.test(name) && !/[. ]$/.test(name) &&
    !/^(con|prn|aux|nul|conin\$|conout\$|com[1-9¹²³]|lpt[1-9¹²³])(?:\.|$)/i.test(name);
}

/** Static bounded filesystem observation; not an atomic snapshot or an OS sandbox. */
export async function scanStrictPath(targetPath, options, detectors) {
  const limits = policy(options);
  const target = path.resolve(targetPath);
  const minimumSeverity = options.minimumSeverity ?? "high";
  const reasons = new Set();
  const findings = [];
  const skipped = { ignored: 0, large: 0, binary: 0, symlink: 0, unreadable: 0, unsupported: 0 };
  const observed = new Map();
  const files = [];
  let scope = "target-tree-excluding-root-git-metadata-v1";
  let excludedGitMetadata = 0;
  let entries = 0;
  let totalBytes = 0;
  let scannedFiles = 0;
  let truncated = false;
  let blockingObserved = false;

  const finish = () => {
    findings.sort((a, b) => a.file < b.file ? -1 : a.file > b.file ? 1 :
      a.line - b.line || a.column - b.column || a.ruleId.localeCompare(b.ruleId));
    const blockingFindings = findings.filter((f) => isAtLeastSeverity(f.severity, minimumSeverity)).length;
    const complete = reasons.size === 0;
    return {
      version: 1, target: targetPath.split(path.sep).join("/"), staged: Boolean(options.staged),
      scannedFiles, skipped, truncated, minimumSeverity, findings, blockingFindings,
      gate: {
        schemaVersion: 1, policyVersion: "strict-gate-v1", scope,
        decision: blockingObserved ? "fail" : complete ? "pass" : "unknown",
        complete, blockingObserved, reasons: [...reasons].sort(), excludedGitMetadata,
        entries, discoveredFiles: files.length, totalBytes, limits,
      },
    };
  };
  const add = (items) => {
    if (items.some((item) => isAtLeastSeverity(item.severity, minimumSeverity))) blockingObserved = true;
    const remaining = limits.maxFindings - findings.length;
    if (items.length > remaining) { truncated = true; reasons.add("findings_limit"); }
    findings.push(...items.slice(0, remaining));
  };
  const readInfo = async (absolute) => {
    try { return await lstat(absolute); }
    catch { skipped.unreadable += 1; reasons.add("read_error"); return null; }
  };

  // Strict staged scanning is unsupported: no Git subprocess is started.
  if (options.staged) {
    scope = "unsupported-staged-v1";
    reasons.add("unsupported_staged_scope");
    return finish();
  }
  // Refuse symlinks/junctions in ancestors as well as the target itself.
  const ancestors = new Map();
  let ancestor = target;
  while (true) {
    const info = await readInfo(ancestor);
    if (!info) return finish();
    if (info.isSymbolicLink()) { skipped.symlink += 1; reasons.add("symlink"); return finish(); }
    ancestors.set(ancestor, `${info.dev}:${info.ino}:${info.mode}`);
    const parent = path.dirname(ancestor);
    if (parent === ancestor) break;
    ancestor = parent;
  }
  const rootInfo = await readInfo(target);
  if (!rootInfo) return finish();
  if (!rootInfo.isDirectory() && !rootInfo.isFile()) {
    skipped.unsupported += 1; reasons.add("unsupported_file"); return finish();
  }
  const isTree = rootInfo.isDirectory();
  if (!isTree) scope = "single-file-v1";
  if (!isTree && !isSafePathComponent(path.basename(target))) {
    reasons.add("unsupported_path"); return finish();
  }
  const stack = [{ absolute: target, relative: isTree ? "" : path.basename(target), depth: 0 }];
  const identities = new Set();
  while (stack.length) {
    const item = stack.pop();
    const info = await readInfo(item.absolute);
    if (!info) continue;
    observed.set(item.absolute, stamp(info));
    if (info.isSymbolicLink()) { skipped.symlink += 1; reasons.add("symlink"); continue; }
    if (info.isFile()) {
      if (files.length >= limits.maxFiles) { reasons.add("file_limit"); continue; }
      files.push({ ...item, info });
      continue;
    }
    if (!info.isDirectory()) { skipped.unsupported += 1; reasons.add("unsupported_file"); continue; }
    if (item.depth >= limits.maxDepth) { reasons.add("depth_limit"); continue; }
    try {
      const directory = await opendir(item.absolute);
      for await (const entry of directory) {
        entries += 1;
        if (entries > limits.maxEntries) { reasons.add("entry_limit"); break; }
        const absolute = path.join(item.absolute, entry.name);
        const relative = item.relative ? `${item.relative}/${entry.name}` : entry.name;
        if (isTree && item.absolute === target && entry.name === ".git") {
          const gitInfo = await readInfo(absolute);
          if (gitInfo?.isSymbolicLink()) { skipped.symlink += 1; reasons.add("symlink"); }
          else if (gitInfo?.isDirectory() || gitInfo?.isFile()) excludedGitMetadata += 1;
          else if (gitInfo) { skipped.unsupported += 1; reasons.add("unsupported_file"); }
          continue;
        }
        if (!isSafePathComponent(entry.name) || entry.name.toLowerCase() === ".git") {
          reasons.add("unsupported_path"); continue;
        }
        const identity = relative.toLowerCase();
        if (identities.has(identity)) { reasons.add("path_collision"); continue; }
        identities.add(identity);
        stack.push({ absolute, relative, depth: item.depth + 1 });
      }
    } catch { skipped.unreadable += 1; reasons.add("read_error"); }
    if (reasons.has("entry_limit")) break;
  }

  files.sort((a, b) => a.relative < b.relative ? -1 : a.relative > b.relative ? 1 : 0);
  const scratch = Buffer.alloc(limits.maxFileSize + 1);
  for (const file of files) {
    const filenameFinding = detectors.sensitiveFilenameFinding(file.relative);
    if (filenameFinding) add([filenameFinding]);
    if (file.info.size > limits.maxFileSize) { skipped.large += 1; reasons.add("large_file"); continue; }
    if (totalBytes >= limits.maxTotalBytes && file.info.size > 0) { reasons.add("total_bytes_limit"); continue; }
    let handle;
    try {
      const before = await lstat(file.absolute);
      if (before.isSymbolicLink() || !before.isFile() || stamp(before) !== stamp(file.info)) {
        reasons.add("metadata_changed"); continue;
      }
      handle = await open(file.absolute, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
      const opened = await handle.stat();
      if (!opened.isFile() || stamp(opened) !== stamp(before)) { reasons.add("metadata_changed"); continue; }
      let used = 0;
      const readLimit = Math.min(scratch.length, limits.maxTotalBytes - totalBytes);
      while (used < readLimit) {
        const { bytesRead } = await handle.read(scratch, used, readLimit - used, used);
        if (!bytesRead) break;
        used += bytesRead;
      }
      totalBytes += used;
      if (stamp(await handle.stat()) !== stamp(opened) || stamp(await lstat(file.absolute)) !== stamp(opened)) {
        reasons.add("metadata_changed"); continue;
      }
      if (used > limits.maxFileSize) { skipped.large += 1; reasons.add("large_file"); continue; }
      if (used !== opened.size) { reasons.add(used === readLimit ? "total_bytes_limit" : "metadata_changed"); continue; }
      const buffer = scratch.subarray(0, used);
      if (buffer.includes(0)) { skipped.binary += 1; reasons.add("binary_file"); continue; }
      let text;
      try { text = new TextDecoder("utf-8", { fatal: true }).decode(buffer); }
      catch { skipped.binary += 1; reasons.add("invalid_utf8"); continue; }
      scannedFiles += 1;
      add(detectors.inspectText(text, file.relative, {
        strictGate: true, personalData: options.personalData === true,
        entropy: true, minimumEntropy: 4.1, maxFindings: limits.maxFindings - findings.length + 1,
      }));
    } catch { skipped.unreadable += 1; reasons.add("read_error"); }
    finally {
      if (handle) {
        try { await handle.close(); }
        catch { reasons.add("read_error"); }
      }
    }
  }
  for (const [absolute, expected] of observed) {
    const info = await readInfo(absolute);
    if (info && stamp(info) !== expected) reasons.add("metadata_changed");
  }
  for (const [absolute, expected] of ancestors) {
    const info = await readInfo(absolute);
    if (info && `${info.dev}:${info.ino}:${info.mode}` !== expected) reasons.add("metadata_changed");
  }
  return finish();
}
