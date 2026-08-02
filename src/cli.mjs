#!/usr/bin/env node
import { writeFile } from "node:fs/promises";
import { scanPath } from "./scanner.mjs";
import { formatResult } from "./reporters.mjs";
import { SEVERITY_ORDER } from "./patterns.mjs";

const VERSION = "0.1.0";

function help() {
  return `Repo Privacy Guard ${VERSION}

Usage:
  repo-privacy-guard scan [path] [options]

Options:
  --format <text|json|sarif>  Report format (default: text)
  --output <file>             Write the report to a file
  --min-severity <level>      Exit 1 at low, medium, high, or critical (default: high)
  --personal-data             Also flag email addresses and international phone numbers
  --ignore <glob>             Add an ignore pattern (repeatable)
  --max-file-size <bytes>     Skip larger files (default: 1048576)
  --max-findings <number>     Stop reporting after this many findings (default: 200)
  --no-entropy                Disable contextual high-entropy checks
  --version                   Print the version
  --help                      Show this help

Use .repoguardignore for persistent ignore patterns. Add "repoguard:allow" to
an intentionally safe line to suppress findings on that line.`;
}

function valueAfter(args, index, option) {
  const value = args[index + 1];
  if (!value || value.startsWith("--")) throw new Error(`${option} requires a value`);
  return value;
}

function parseArgs(argv) {
  const args = [...argv];
  if (args[0] === "scan") args.shift();
  const options = { format: "text", minimumSeverity: "high", ignore: [], entropy: true };
  let target = ".";

  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index];
    if (argument === "--help" || argument === "-h") return { help: true };
    if (argument === "--version" || argument === "-v") return { version: true };
    if (argument === "--personal-data") options.personalData = true;
    else if (argument === "--no-entropy") options.entropy = false;
    else if (argument === "--format") options.format = valueAfter(args, index++, argument);
    else if (argument === "--output") options.output = valueAfter(args, index++, argument);
    else if (argument === "--min-severity") options.minimumSeverity = valueAfter(args, index++, argument);
    else if (argument === "--ignore") options.ignore.push(valueAfter(args, index++, argument));
    else if (argument === "--max-file-size") options.maxFileSize = Number(valueAfter(args, index++, argument));
    else if (argument === "--max-findings") options.maxFindings = Number(valueAfter(args, index++, argument));
    else if (argument.startsWith("--")) throw new Error(`Unknown option: ${argument}`);
    else if (target === ".") target = argument;
    else throw new Error(`Unexpected argument: ${argument}`);
  }

  if (!["text", "json", "sarif"].includes(options.format)) {
    throw new Error("--format must be text, json, or sarif");
  }
  if (!(options.minimumSeverity in SEVERITY_ORDER)) {
    throw new Error("--min-severity must be low, medium, high, or critical");
  }
  if (!Number.isFinite(options.maxFileSize ?? 1) || (options.maxFileSize ?? 1) <= 0) {
    throw new Error("--max-file-size must be a positive number");
  }
  if (!Number.isInteger(options.maxFindings ?? 1) || (options.maxFindings ?? 1) <= 0) {
    throw new Error("--max-findings must be a positive integer");
  }
  return { target, options };
}

async function main() {
  try {
    const parsed = parseArgs(process.argv.slice(2));
    if (parsed.help) {
      console.log(help());
      return;
    }
    if (parsed.version) {
      console.log(VERSION);
      return;
    }

    const { format, output, ...scanOptions } = parsed.options;
    const result = await scanPath(parsed.target, scanOptions);
    const report = formatResult(result, format);
    if (output) await writeFile(output, `${report}\n`, "utf8");
    else console.log(report);
    if (result.blockingFindings > 0) process.exitCode = 1;
  } catch (error) {
    console.error(`Repo Privacy Guard: ${error.message}`);
    console.error("Run with --help for usage.");
    process.exitCode = 2;
  }
}

await main();
