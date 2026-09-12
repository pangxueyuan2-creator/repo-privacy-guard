import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { existsSync, unlinkSync, writeFileSync } from "node:fs";
import { mkdtemp, mkdir, rm, symlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { scanPath } from "../src/scanner.mjs";
import { isSafePathComponent, scanStrictPath } from "../src/strict.mjs";
import { formatJson, formatSarif, formatText } from "../src/reporters.mjs";

const TOKEN = ["ghp", "A".repeat(30)].join("_");
const cliPath = fileURLToPath(new URL("../src/cli.mjs", import.meta.url));
async function fixture(t) {
  const root = await mkdtemp(path.join(os.tmpdir(), "repoguard-strict-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  return root;
}
const scan = (target, options = {}) => scanPath(target, { strictGate: true, ...options });
const cli = (target, ...args) => new Promise((resolve, reject) => {
  execFile(process.execPath, [cliPath, "scan", target, "--strict-gate", "--format", "json", ...args],
    { timeout: 15000, maxBuffer: 2 * 1024 * 1024 }, (error, stdout, stderr) => {
      if (error && typeof error.code !== "number") reject(error);
      else resolve({ code: error?.code ?? 0, stdout, stderr });
    });
});

test("strict gate complete clean target passes with explicit bounded scope", async (t) => {
  const root = await fixture(t);
  await writeFile(path.join(root, "safe.txt"), "safe content");
  const result = await scan(root);
  assert.equal(result.gate.decision, "pass");
  assert.equal(result.gate.complete, true);
  assert.deepEqual(result.gate.reasons, []);
  assert.equal(result.scannedFiles, 1);
  assert.equal(result.gate.policyVersion, "strict-gate-v1");
  assert.equal(result.gate.scope, "target-tree-excluding-root-git-metadata-v1");
  assert.equal(result.gate.totalBytes, 12);
});

test("strict gate ignores target .repoguardignore and inline repoguard:allow bypasses", async (t) => {
  const root = await fixture(t);
  await writeFile(path.join(root, ".repoguardignore"), "*\n");
  await writeFile(path.join(root, "secret.txt"), `${TOKEN} // repoguard:allow`);
  assert.equal((await scanPath(root)).blockingFindings, 0);
  const result = await scan(root);
  assert.equal(result.gate.decision, "fail");
  assert.equal(result.gate.complete, true);
  assert.deepEqual(result.findings.map((f) => f.ruleId), ["github-token"]);
  assert.equal(result.skipped.ignored, 0);
});

for (const directory of ["node_modules", "dist", "build", "vendor", "coverage", ".cache", ".next"]) {
  test(`strict gate detects secret in default ignored ${directory}`, async (t) => {
    const root = await fixture(t);
    await mkdir(path.join(root, directory));
    await writeFile(path.join(root, directory, "secret.txt"), `${TOKEN} # repoguard:allow`);
    const result = await scan(root);
    assert.equal(result.gate.decision, "fail");
    assert.equal(result.findings[0].ruleId, "github-token");
  });
}

test("strict gate entropy checks cannot be suppressed inline", async (t) => {
  const root = await fixture(t);
  const value = "A1b2C3d4E5f6G7h8I9j0KLMnopQRstuVWxyz";
  await writeFile(path.join(root, "settings.txt"), `password = '${value}' # repoguard:allow`);
  const result = await scan(root);
  assert.equal(result.gate.decision, "fail");
  assert.ok(result.findings.some((f) => f.ruleId === "high-entropy-secret"));
  assert.ok(!formatJson(result).includes(value));
});

test("strict gate reports secrets inside example files", async (t) => {
  const root = await fixture(t);
  await writeFile(path.join(root, ".env.example"), TOKEN);
  assert.equal((await scan(root)).gate.decision, "fail");
});

for (const [name, content, options, reason] of [
  ["binary", Buffer.from([97, 0, 98]), {}, "binary_file"],
  ["null past legacy sample", Buffer.concat([Buffer.alloc(9000, 97), Buffer.from([0])]), {}, "binary_file"],
  ["invalid UTF-8", Buffer.from([0xc3, 0x28]), {}, "invalid_utf8"],
  ["oversized", "long text", { maxFileSize: 2 }, "large_file"],
  ["total bytes", "long text", { maxTotalBytes: 2 }, "total_bytes_limit"],
]) {
  test(`strict gate ${name} cannot pass`, async (t) => {
    const root = await fixture(t);
    await writeFile(path.join(root, "data.txt"), content);
    const result = await scan(root, options);
    assert.equal(result.gate.decision, "unknown");
    assert.equal(result.gate.complete, false);
    assert.ok(result.gate.reasons.includes(reason));
  });
}

test("strict gate byte budget exact boundary remains complete", async (t) => {
  const root = await fixture(t);
  await writeFile(path.join(root, "data.txt"), "safe");
  const result = await scan(root, { maxTotalBytes: 4, maxFileSize: 4 });
  assert.equal(result.gate.decision, "pass");
  assert.equal(result.gate.totalBytes, 4);
});

test("strict gate finding truncation retains failure and signals incompleteness", async (t) => {
  const root = await fixture(t);
  await writeFile(path.join(root, "tokens.txt"), `${TOKEN}\n${TOKEN}\n${TOKEN}`);
  const result = await scan(root, { maxFindings: 1 });
  assert.equal(result.gate.decision, "fail");
  assert.equal(result.gate.complete, false);
  assert.equal(result.truncated, true);
  assert.equal(result.findings.length, 1);
  assert.ok(result.gate.reasons.includes("findings_limit"));
});

test("strict gate exact finding limit is not itself incomplete", async (t) => {
  const root = await fixture(t);
  await writeFile(path.join(root, "a.txt"), TOKEN);
  await writeFile(path.join(root, "b.txt"), "safe");
  const result = await scan(root, { maxFindings: 1 });
  assert.equal(result.gate.complete, true);
  assert.equal(result.truncated, false);
  assert.equal(result.scannedFiles, 2);
});

for (const [options, reason] of [[{ maxFiles: 1 }, "file_limit"], [{ maxEntries: 1 }, "entry_limit"]]) {
  test(`strict gate ${reason} cannot pass`, async (t) => {
    const root = await fixture(t);
    await writeFile(path.join(root, "a.txt"), "safe");
    await writeFile(path.join(root, "b.txt"), "safe");
    const result = await scan(root, options);
    assert.equal(result.gate.decision, "unknown");
    assert.ok(result.gate.reasons.includes(reason));
  });
}

test("strict gate depth limit cannot pass", async (t) => {
  const root = await fixture(t);
  await mkdir(path.join(root, "a"));
  await writeFile(path.join(root, "a", "data.txt"), "safe");
  const result = await scan(root, { maxDepth: 1 });
  assert.equal(result.gate.decision, "unknown");
  assert.ok(result.gate.reasons.includes("depth_limit"));
});

test("strict gate excludes only root git metadata and counts scope exclusion", async (t) => {
  const root = await fixture(t);
  await mkdir(path.join(root, ".git"));
  await writeFile(path.join(root, ".git", "objects"), Buffer.from([0, 1, 2]));
  await writeFile(path.join(root, "safe.txt"), "safe");
  const result = await scan(root);
  assert.equal(result.gate.decision, "pass");
  assert.equal(result.gate.excludedGitMetadata, 1);
  assert.equal(result.scannedFiles, 1);
});

test("strict gate nested git metadata cannot pass", async (t) => {
  const root = await fixture(t);
  await mkdir(path.join(root, "nested", ".git"), { recursive: true });
  const result = await scan(root);
  assert.equal(result.gate.decision, "unknown");
  assert.ok(result.gate.reasons.includes("unsupported_path"));
});

test("strict gate symlink target and ancestor cannot pass", async (t) => {
  const root = await fixture(t);
  const outside = await fixture(t);
  await writeFile(path.join(outside, "safe.txt"), "safe");
  const linked = path.join(root, "linked");
  await symlink(outside, linked, process.platform === "win32" ? "junction" : "dir");
  for (const target of [root, linked, path.join(linked, "safe.txt")]) {
    const result = await scan(target);
    assert.equal(result.gate.decision, "unknown");
    assert.ok(result.gate.reasons.includes("symlink"));
  }
});

test("strict gate root git symlink is not excluded silently", async (t) => {
  const root = await fixture(t);
  const outside = await fixture(t);
  await symlink(outside, path.join(root, ".git"), process.platform === "win32" ? "junction" : "dir");
  const result = await scan(root);
  assert.equal(result.gate.decision, "unknown");
  assert.equal(result.gate.excludedGitMetadata, 0);
});

test("strict gate missing target returns structured unknown without path errors", async (t) => {
  const root = await fixture(t);
  const result = await scan(path.join(root, "missing"));
  assert.equal(result.gate.decision, "unknown");
  assert.deepEqual(result.gate.reasons, ["read_error"]);
  assert.ok(!JSON.stringify(result).includes("ENOENT"));
});

test("strict gate staged scope returns unknown without invoking git", async (t) => {
  const root = await fixture(t);
  const result = await scan(root, { staged: true });
  assert.equal(result.gate.decision, "unknown");
  assert.deepEqual(result.gate.reasons, ["unsupported_staged_scope"]);
  assert.equal(result.gate.scope, "unsupported-staged-v1");
});

test("strict gate rejects weakening policies and invalid budgets", async (t) => {
  const root = await fixture(t);
  for (const options of [
    { ignore: ["*"] }, { entropy: false }, { minimumEntropy: 9 }, { minimumSeverity: "critical" },
    { maxFileSize: 1048577 }, { maxFindings: 10001 }, { maxFiles: 0 }, { maxEntries: 0.5 },
    { maxTotalBytes: Infinity }, { maxDepth: -1 },
  ]) await assert.rejects(scan(root, options), /Strict gate/);
});

test("strict gate rejects unsafe and Windows device path aliases", () => {
  for (const name of ["", "a/b", "CONIN$", "CONOUT$.txt", "COM¹", "LPT².txt", "COM³.log", "aux.txt", "trailing.", "a\u200bb", "e\u0301", "bad:name"]) {
    assert.equal(isSafePathComponent(name), false, name);
  }
  for (const name of ["config.txt", "CONNECTION", "common.py", "COM0.txt"]) assert.equal(isSafePathComponent(name), true, name);
});

test("strict gate blocking finding beyond retained low-severity cap still fails", async (t) => {
  const root = await fixture(t);
  await writeFile(path.join(root, "a.txt"), "Contact maintainer@example.com");
  await writeFile(path.join(root, "b.txt"), TOKEN);
  const result = await scan(root, { personalData: true, maxFindings: 1 });
  assert.equal(result.findings[0].ruleId, "email-address");
  assert.equal(result.blockingFindings, 0);
  assert.equal(result.gate.blockingObserved, true);
  assert.equal(result.gate.decision, "fail");
  assert.equal(result.gate.complete, false);
  assert.equal((await cli(root, "--personal-data", "--max-findings", "1")).code, 1);
});

test("strict gate nonblocking finding truncation cannot pass", async (t) => {
  const root = await fixture(t);
  await writeFile(path.join(root, "a.txt"), "Contact maintainer@example.com and admin@example.com");
  const result = await scan(root, { personalData: true, maxFindings: 1 });
  assert.equal(result.gate.decision, "unknown");
  assert.equal(result.gate.blockingObserved, false);
  assert.ok(result.gate.reasons.includes("findings_limit"));
});

test("strict gate catches file mutation during scan", async (t) => {
  const root = await fixture(t);
  const source = path.join(root, "safe.txt");
  await writeFile(source, "original");
  const result = await scanStrictPath(root, {}, {
    sensitiveFilenameFinding: () => null,
    inspectText: () => { writeFileSync(source, "changed and longer"); return []; },
  });
  assert.equal(result.gate.decision, "unknown");
  assert.ok(result.gate.reasons.includes("metadata_changed"));
});

test("strict gate catches disappearing file without raw OS errors", async (t) => {
  const root = await fixture(t);
  const source = path.join(root, "safe.txt");
  await writeFile(source, "original");
  const result = await scanStrictPath(root, {}, {
    sensitiveFilenameFinding: () => { unlinkSync(source); return null; }, inspectText: () => [],
  });
  assert.equal(result.gate.decision, "unknown");
  assert.ok(result.gate.reasons.includes("read_error"));
  assert.ok(!JSON.stringify(result).includes("ENOENT"));
});

test("strict gate scans code statically without executing target files", async (t) => {
  const root = await fixture(t);
  const marker = path.join(root, "executed.txt");
  await writeFile(path.join(root, "evil.mjs"), `import fs from 'node:fs'; fs.writeFileSync(${JSON.stringify(marker)}, 'executed');`);
  assert.equal((await scan(root)).gate.decision, "pass");
  assert.equal(existsSync(marker), false);
});

test("strict gate known fail dominates unknown and all reports redact values", async (t) => {
  const root = await fixture(t);
  await writeFile(path.join(root, "secret.txt"), TOKEN);
  await writeFile(path.join(root, "binary.dat"), Buffer.from([0]));
  const result = await scan(root);
  assert.equal(result.gate.decision, "fail");
  assert.equal(result.gate.complete, false);
  for (const report of [formatJson(result), formatSarif(result), formatText(result)]) assert.ok(!report.includes(TOKEN));
  const run = JSON.parse(formatSarif(result)).runs[0];
  assert.equal(run.invocations[0].executionSuccessful, false);
  assert.equal(run.properties.strictGate.decision, "fail");
  assert.equal(run.invocations[0].toolExecutionNotifications[0].descriptor.id, "binary_file");
});

test("strict gate CLI exits 0 pass, 1 fail, 2 invalid, 3 unknown", async (t) => {
  const root = await fixture(t);
  await writeFile(path.join(root, "safe.txt"), "safe");
  assert.equal((await cli(root)).code, 0);
  await writeFile(path.join(root, "secret.txt"), `${TOKEN} // repoguard:allow`);
  const fail = await cli(root);
  assert.equal(fail.code, 1);
  assert.equal(JSON.parse(fail.stdout).gate.decision, "fail");
  assert.equal((await cli(root, "--ignore", "*")).code, 2);
  await rm(path.join(root, "secret.txt"));
  await writeFile(path.join(root, "binary.dat"), Buffer.from([0]));
  const unknown = await cli(root);
  assert.equal(unknown.code, 3);
  assert.equal(JSON.parse(unknown.stdout).gate.decision, "unknown");
  assert.equal((await cli(root, "--staged")).code, 3);
});
