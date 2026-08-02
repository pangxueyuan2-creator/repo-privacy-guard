import assert from "node:assert/strict";
import test from "node:test";
import { formatJson, formatSarif, formatText } from "../src/reporters.mjs";

const result = {
  version: 1,
  target: "/repo",
  scannedFiles: 2,
  skipped: { ignored: 0, large: 0, binary: 0 },
  truncated: false,
  minimumSeverity: "high",
  blockingFindings: 1,
  findings: [{
    ruleId: "github-token",
    severity: "critical",
    message: "Possible GitHub access token",
    file: "config.js",
    line: 2,
    column: 4,
    fingerprint: "0123456789abcdef",
    redacted: "<redacted:40>",
  }],
};

test("text output is concise and redacted", () => {
  const output = formatText(result);
  assert.match(output, /config\.js:2:4/);
  assert.match(output, /intentionally redacted/);
});

test("JSON output is machine readable", () => {
  assert.deepEqual(JSON.parse(formatJson(result)).findings, result.findings);
});

test("SARIF output carries locations and fingerprints", () => {
  const sarif = JSON.parse(formatSarif(result));
  assert.equal(sarif.version, "2.1.0");
  assert.equal(sarif.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri, "config.js");
});
