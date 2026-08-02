import { appendFile } from "node:fs/promises";
import path from "node:path";
import { scanPath } from "../src/scanner.mjs";

function escapeProperty(value) {
  return String(value).replace(/%/g, "%25").replace(/\r/g, "%0D").replace(/\n/g, "%0A").replace(/:/g, "%3A").replace(/,/g, "%2C");
}

function escapeMessage(value) {
  return String(value).replace(/%/g, "%25").replace(/\r/g, "%0D").replace(/\n/g, "%0A");
}

async function setOutput(name, value) {
  if (process.env.GITHUB_OUTPUT) {
    await appendFile(process.env.GITHUB_OUTPUT, `${name}=${value}\n`, "utf8");
  }
}

try {
  const configuredPath = process.env.INPUT_PATH || ".";
  const minimumSeverity = process.env["INPUT_MINIMUM-SEVERITY"] || "high";
  const personalData = (process.env["INPUT_PERSONAL-DATA"] || "false").toLowerCase() === "true";
  const target = path.resolve(process.env.GITHUB_WORKSPACE || process.cwd(), configuredPath);
  const result = await scanPath(target, { minimumSeverity, personalData });

  for (const finding of result.findings) {
    const command = finding.severity === "critical" || finding.severity === "high" ? "error" : "warning";
    console.log(`::${command} file=${escapeProperty(finding.file)},line=${finding.line},col=${finding.column},title=${escapeProperty(finding.ruleId)}::${escapeMessage(`${finding.message}; value redacted; fingerprint ${finding.fingerprint}`)}`);
  }

  await setOutput("findings", result.blockingFindings);
  console.log(`Repo Privacy Guard scanned ${result.scannedFiles} file(s); ${result.blockingFindings} blocking finding(s).`);
  if (result.blockingFindings > 0) process.exitCode = 1;
} catch (error) {
  console.error(`::error title=Repo Privacy Guard failed::${escapeMessage(error.message)}`);
  process.exitCode = 2;
}
