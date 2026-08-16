import assert from "node:assert/strict";
import { mkdtemp, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { scanPath } from "../src/scanner.mjs";

async function fixture() {
  return mkdtemp(path.join(os.tmpdir(), "repo-privacy-guard-"));
}

// Regression: AWS secret access keys were never detected (only AKIA/ASIA key IDs).
// Values are assembled at runtime so the test source itself stays clean under scan:self.
test("detects AWS secret access keys and keeps the value out of reports", async () => {
  const root = await fixture();
  const accessKey = ["AKIA", "IOSFODNN7EXAMPLE"].join("");
  const secretKey = ["wJalrXUtnFEMI", "K7MDENG", "bPxRfiCYEXAMPLEKEY"].join("/");
  await writeFile(
    path.join(root, "aws.env"),
    ["aws_access_key_id=", accessKey, "\naws_secret_access_key=", secretKey, "\n"].join(""),
  );

  const result = await scanPath(root, { minimumSeverity: "critical" });
  assert.equal(result.findings.some((f) => f.ruleId === "aws-secret-key"), true);
  assert.equal(JSON.stringify(result).includes(secretKey), false);
});

// Regression: high-entropy assignments with special characters or no quotes were missed.
test("detects special-character and unquoted password assignments", async () => {
  const root = await fixture();
  const specialPassword = ["S3cr3t!P", "@ssw0rd#2026", "_ExtraLong"].join("");
  const plainPassword = ["plainTextButLongEnough", "123456789"].join("");
  await writeFile(
    path.join(root, "config.sh"),
    ["export password=", specialPassword, "\nexport passwd=", plainPassword, "\n"].join(""),
  );

  const result = await scanPath(root, { minimumSeverity: "high" });
  assert.equal(result.findings.filter((f) => f.ruleId === "high-entropy-secret").length, 2);
  assert.equal(JSON.stringify(result).includes(specialPassword), false);
});

// Regression: reports embedded the absolute local scan path (home directory leak).
test("reports the target path as given, not the resolved absolute path", async () => {
  const root = await fixture();
  await writeFile(path.join(root, "ok.txt"), "nothing here\n");
  const relative = path.relative(process.cwd(), root);
  const result = await scanPath(relative, {});
  assert.equal(result.target, relative.split(path.sep).join("/"));
  assert.equal(result.target.includes(os.homedir()), false);
});

// Regression: redacted markers disclosed the matched secret's length.
test("redacted markers do not disclose matched value length", async () => {
  const root = await fixture();
  const token = ["ghp", "A".repeat(30)].join("_");
  await writeFile(path.join(root, "config.js"), `export const value = "${token}";
`);
  const result = await scanPath(root, {});
  assert.equal(result.findings[0].redacted, "<redacted>");
  assert.equal(JSON.stringify(result).includes(token), false);
});
