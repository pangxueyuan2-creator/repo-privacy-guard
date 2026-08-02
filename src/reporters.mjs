const SARIF_LEVEL = Object.freeze({
  low: "note",
  medium: "warning",
  high: "error",
  critical: "error",
});

export function formatText(result) {
  const lines = [
    `Repo Privacy Guard scanned ${result.scannedFiles} file(s).`,
    `Findings: ${result.findings.length}; blocking at ${result.minimumSeverity}+: ${result.blockingFindings}.`,
  ];

  for (const finding of result.findings) {
    lines.push(
      `${finding.severity.toUpperCase()} ${finding.ruleId} ${finding.file}:${finding.line}:${finding.column} — ${finding.message} [${finding.fingerprint}]`,
    );
  }

  if (result.findings.length === 0) {
    lines.push("No likely secrets or sensitive filenames were found.");
  }
  if (result.truncated) lines.push("Results were truncated at the configured limit.");
  lines.push("Matched values are intentionally redacted.");
  return lines.join("\n");
}

export function formatJson(result) {
  return JSON.stringify(result, null, 2);
}

export function formatSarif(result) {
  const rules = [...new Map(result.findings.map((finding) => [finding.ruleId, finding])).values()]
    .map((finding) => ({
      id: finding.ruleId,
      shortDescription: { text: finding.message },
      defaultConfiguration: { level: SARIF_LEVEL[finding.severity] },
      properties: { severity: finding.severity },
    }));

  return JSON.stringify({
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [{
      tool: { driver: { name: "Repo Privacy Guard", version: "0.1.0", rules } },
      results: result.findings.map((finding) => ({
        ruleId: finding.ruleId,
        level: SARIF_LEVEL[finding.severity],
        message: { text: finding.message },
        partialFingerprints: { primaryLocationLineHash: finding.fingerprint },
        locations: [{
          physicalLocation: {
            artifactLocation: { uri: finding.file },
            region: { startLine: finding.line, startColumn: finding.column },
          },
        }],
      })),
    }],
  }, null, 2);
}

export function formatResult(result, format = "text") {
  if (format === "json") return formatJson(result);
  if (format === "sarif") return formatSarif(result);
  if (format === "text") return formatText(result);
  throw new Error(`Unsupported format: ${format}`);
}
