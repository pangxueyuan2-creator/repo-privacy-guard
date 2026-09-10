import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import test from "node:test";
import { scanPath } from "../src/scanner.mjs";

const execFileAsync = promisify(execFile);

async function fixture() {
  const root = await mkdtemp(path.join(os.tmpdir(), "repo-privacy-guard-staged-ignore-"));
  await execFileAsync("git", ["-C", root, "init", "-b", "main"]);
  await execFileAsync("git", ["-C", root, "config", "user.email", "test@example.invalid"]);
  await execFileAsync("git", ["-C", root, "config", "user.name", "Test"]);
  await writeFile(path.join(root, ".repoguardignore"), "");
  await writeFile(path.join(root, "secret.txt"), "safe\n");
  await execFileAsync("git", ["-C", root, "add", "."]);
  await execFileAsync("git", ["-C", root, "commit", "-m", "base"]);
  return root;
}

test("staged scan cannot be hidden by unstaged ignore-file changes", async () => {
  const root = await fixture();
  const token = ["ghp", "A".repeat(30)].join("_");

  await writeFile(path.join(root, "secret.txt"), `${token}\n`);
  await execFileAsync("git", ["-C", root, "add", "secret.txt"]);
  await writeFile(path.join(root, ".repoguardignore"), "secret.txt\n");

  const result = await scanPath(root, { staged: true });

  assert.equal(result.findings.some((finding) => finding.file === "secret.txt"), true);
});

test("staged scan honors the index copy of the ignore file", async () => {
  const root = await fixture();
  const token = ["ghp", "A".repeat(30)].join("_");

  await writeFile(path.join(root, "secret.txt"), `${token}\n`);
  await writeFile(path.join(root, ".repoguardignore"), "secret.txt\n");
  await execFileAsync("git", ["-C", root, "add", "secret.txt", ".repoguardignore"]);

  // Change only the worktree copy after staging. The staged policy remains authoritative.
  await writeFile(path.join(root, ".repoguardignore"), "");

  const result = await scanPath(root, { staged: true });

  assert.equal(result.findings.some((finding) => finding.file === "secret.txt"), false);
  assert.equal(result.skipped.ignored, 1);
});
