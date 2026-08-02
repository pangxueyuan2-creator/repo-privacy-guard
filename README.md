# Repo Privacy Guard

[![CI](https://github.com/pangxueyuan2-creator/repo-privacy-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/pangxueyuan2-creator/repo-privacy-guard/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Zero runtime dependencies](https://img.shields.io/badge/runtime%20dependencies-0-blue.svg)](package.json)

**Find likely secrets and privacy risks before a repository becomes public.**

Repo Privacy Guard is an offline-first command-line scanner and GitHub Action.
It detects common provider credentials, private keys, credentialed database URLs,
high-entropy values in secret-like assignments, and sensitive filenames. It
reports locations and irreversible fingerprints while intentionally redacting
the matched values.

> Security tools reduce risk; they do not prove that a repository is safe. Use
> provider-side secret scanning and code review alongside this project.

[简体中文说明](README.zh-CN.md)

## Why it is useful

It is easy to publish a `.env` file, a private key, or a copied token while
making a repository public. Reviewing every file and every build artifact by
hand is slow, and printing a discovered secret into a CI log creates a second
exposure. Repo Privacy Guard provides a fast local check with redacted output.

## Features

- Runs locally with zero runtime dependencies and no network requests.
- Detects likely OpenAI, GitHub, AWS, Google, and Slack credentials.
- Detects private-key headers, credentialed database URLs, and JWT-like values.
- Flags `.env`, key, credential, and authentication configuration filenames.
- Adds contextual entropy checks for values assigned to secret-like names.
- Optionally checks email addresses and international phone numbers.
- Supports text, JSON, and SARIF 2.1.0 reports.
- Supports `.repoguardignore` and line-level `repoguard:allow` exceptions.
- Works as a CLI, JavaScript library, or reusable GitHub Action.
- Never includes a matched secret value in its result object or normal output.

## Quick start

Requirements: Node.js 20 or newer.

Run directly from GitHub:

```bash
npx --yes github:pangxueyuan2-creator/repo-privacy-guard scan .
```

Or clone the project:

```bash
git clone https://github.com/pangxueyuan2-creator/repo-privacy-guard.git
cd repo-privacy-guard
npm install
npm test
node src/cli.mjs scan /path/to/project
```

Exit codes:

| Code | Meaning |
| --- | --- |
| `0` | Scan completed with no findings at or above the configured severity |
| `1` | One or more blocking findings were reported |
| `2` | Invalid options, unreadable path, or another scanner error |

## Examples

Scan the current directory and fail on high or critical findings:

```bash
repo-privacy-guard scan .
```

Include possible personal data and fail on any finding:

```bash
repo-privacy-guard scan . --personal-data --min-severity low
```

Create a SARIF report for another security tool:

```bash
repo-privacy-guard scan . --format sarif --output repo-privacy-guard.sarif
```

Add project-specific exclusions in `.repoguardignore`:

```gitignore
fixtures/generated/
docs/example-output.json
*.min.js
```

For an intentionally safe synthetic value, add `repoguard:allow` on that line.
Never use an exception to hide a real credential.

## GitHub Action

```yaml
name: Privacy guard

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - uses: pangxueyuan2-creator/repo-privacy-guard@v0.1.0
        with:
          path: .
          minimum-severity: high
```

Findings appear as redacted file and line annotations. The action never uploads
repository contents and needs only read access to the checked-out files.

## JavaScript API

```js
import { scanPath } from "repo-privacy-guard";

const result = await scanPath(".", {
  minimumSeverity: "high",
  personalData: false,
});

console.log(result.blockingFindings);
```

## Detection and privacy model

The scanner reads files from the selected path, skips common dependency/build
directories, avoids large and binary files, and evaluates text locally. A
finding contains the rule, severity, file, line, column, redacted length, and a
short SHA-256-derived fingerprint. It does not contain the matched value.

The fingerprint helps identify repeat findings without making the original
value recoverable. No telemetry, analytics, API key, or account is required.

See [docs/threat-model.md](docs/threat-model.md) for security boundaries and
known limitations.

## Project status

The initial release is usable and tested, but the detection engine is young.
False positives and false negatives are expected. The public roadmap is in
[ROADMAP.md](ROADMAP.md), and focused rule improvements are welcome.

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md). Use synthetic fixtures only—never place
a live credential in a test, issue, pull request, or discussion.

## License

[MIT](LICENSE)
