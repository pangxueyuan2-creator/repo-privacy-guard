import assert from "node:assert/strict";
import { mkdtemp, mkdir, symlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { scanPath } from "../src/scanner.mjs";

async function fixture() {
  return mkdtemp(path.join(os.tmpdir(), "repo-privacy-guard-"));
}

test("reports provider keys without returning their values", async () => {
  const root = await fixture();
  const secret = ["sk", "proj", "A1b2C3d4E5f6G7h8I9j0K1l2M3n4"].join("-");
  await writeFile(path.join(root, "config.js"), `export const value = "${secret}";\n`);

  const result = await scanPath(root);
  assert.equal(result.blockingFindings, 1);
  assert.equal(result.findings[0].ruleId, "openai-api-key");
  assert.equal(JSON.stringify(result).includes(secret), false);
});

test("flags sensitive filenames and honors example files", async () => {
  const root = await fixture();
  await writeFile(path.join(root, ".env"), "SAFE_PLACEHOLDER=true\n");
  await writeFile(path.join(root, ".env.example"), "SAFE_PLACEHOLDER=true\n");
  const result = await scanPath(root);
  assert.deepEqual(result.findings.map((finding) => finding.file), [".env"]);
});

test("supports ignore files and inline allow comments", async () => {
  const root = await fixture();
  const token = ["ghp", "A".repeat(30)].join("_");
  await writeFile(path.join(root, ".repoguardignore"), "ignored.txt\n");
  await writeFile(path.join(root, "ignored.txt"), token);
  await writeFile(path.join(root, "allowed.txt"), `${token} # repoguard:allow\n`);
  const result = await scanPath(root);
  assert.equal(result.findings.length, 0);
  assert.equal(result.skipped.ignored, 1);
});

test("personal data checks are opt-in", async () => {
  const root = await fixture();
  await writeFile(path.join(root, "contact.txt"), "Contact maintainer@example.com\n");
  assert.equal((await scanPath(root)).findings.length, 0);
  const result = await scanPath(root, { personalData: true, minimumSeverity: "low" });
  assert.equal(result.findings[0].ruleId, "email-address");
});

test("skips binary, large, and default ignored files", async () => {
  const root = await fixture();
  await mkdir(path.join(root, "node_modules"));
  await writeFile(path.join(root, "node_modules", "ignored.js"), "ignored");
  await writeFile(path.join(root, "binary.dat"), Buffer.from([0, 1, 2]));
  await writeFile(path.join(root, "large.txt"), "x".repeat(100));
  const result = await scanPath(root, { maxFileSize: 50 });
  assert.equal(result.skipped.ignored, 1);
  assert.equal(result.skipped.binary, 1);
  assert.equal(result.skipped.large, 1);
});

test("does not follow symbolic links outside the scan root", async (context) => {
  const root = await fixture();
  const outside = await fixture();
  const token = ["ghp", "A".repeat(30)].join("_");
  await writeFile(path.join(outside, "secret.txt"), token);

  try {
    await symlink(outside, path.join(root, "linked"), process.platform === "win32" ? "junction" : "dir");
  } catch (error) {
    if (error.code === "EPERM") {
      context.skip("Creating symbolic links is not permitted in this environment");
      return;
    }
    throw error;
  }

  const result = await scanPath(root);
  assert.equal(result.findings.length, 0);
  assert.equal(result.scannedFiles, 0);
  assert.equal(result.skipped.symlink, 1);
});

test("reports truncation and only counts files that were scanned", async () => {
  const root = await fixture();
  const token = ["ghp", "A".repeat(30)].join("_");
  await writeFile(path.join(root, "a.txt"), token);
  await writeFile(path.join(root, "b.txt"), token);

  const result = await scanPath(root, { maxFindings: 1 });
  assert.equal(result.findings.length, 1);
  assert.equal(result.scannedFiles, 1);
  assert.equal(result.truncated, true);
});

test("does not report truncation when the exact limit covers the full scan", async () => {
  const root = await fixture();
  const token = ["ghp", "A".repeat(30)].join("_");
  await writeFile(path.join(root, "only.txt"), token);

  const result = await scanPath(root, { maxFindings: 1 });
  assert.equal(result.findings.length, 1);
  assert.equal(result.scannedFiles, 1);
  assert.equal(result.truncated, false);
});
