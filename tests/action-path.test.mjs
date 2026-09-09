import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const actionPath = path.join(repoRoot, "action", "index.mjs");

test("GitHub Action rejects scan paths outside GITHUB_WORKSPACE", async () => {
  const workspace = await mkdtemp(path.join(tmpdir(), "repo-privacy-guard-"));
  try {
    const result = spawnSync(process.execPath, [actionPath], {
      cwd: repoRoot,
      encoding: "utf8",
      env: {
        ...process.env,
        GITHUB_WORKSPACE: workspace,
        INPUT_PATH: "..",
      },
    });

    assert.equal(result.status, 2);
    assert.match(result.stderr, /Input path must stay within GITHUB_WORKSPACE/);
  } finally {
    await rm(workspace, { recursive: true, force: true });
  }
});
