import assert from "node:assert/strict";
import { mkdtemp, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { scanPath } from "../src/scanner.mjs";

async function fixture() {
  return mkdtemp(path.join(os.tmpdir(), "repo-privacy-guard-"));
}

test("detects Anthropic and xAI keys without returning their values", async () => {
  const root = await fixture();
  // Values are assembled from fragments so this file never contains a
  // literal secret shape (push protection and self-scan stay quiet).
  const anthropic = ["sk", "ant", "api03", "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"].join("-");
  const xai = ["xai", "Z9y8X7w6V5u4T3s2R1q0P9o8N7m6L5k4J3h2"].join("-");
  await writeFile(
    path.join(root, "config.js"),
    'anthropicKey = "' + anthropic + '";\nxaiKey = "' + xai + '";\n',
  );
  const result = await scanPath(root);
  const ids = result.findings.map((finding) => finding.ruleId);
  assert.ok(ids.includes("anthropic-api-key"), JSON.stringify(ids));
  assert.ok(ids.includes("xai-api-key"), JSON.stringify(ids));
  assert.equal(JSON.stringify(result).includes(anthropic), false);
  assert.equal(JSON.stringify(result).includes(xai), false);
});

test("detects Slack webhook URLs without returning their values", async () => {
  const root = await fixture();
  const hook = [
    "https://hooks.slack.com",
    "services",
    "T00000000",
    "B00000000",
    "XXXXXXXXXXXXXXXXXXXXXXXX",
  ].join("/");
  await writeFile(path.join(root, "notify.js"), 'const hook = "' + hook + '";\n');
  const result = await scanPath(root);
  assert.ok(
    result.findings.some((finding) => finding.ruleId === "slack-webhook"),
  );
  assert.equal(JSON.stringify(result).includes(hook), false);
});
