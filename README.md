# Repo Privacy Guard

**Find likely secrets and privacy risks before a repository becomes public.**

Offline-first CLI and GitHub Action. Detects common credentials, private keys, credentialed URLs, high-entropy values, and sensitive filenames. Output is redacted — matched values never appear in results.

It reduces risk; it does not prove a repo is safe.

[简体中文](README.zh-CN.md)

## Quick start

Node 20+.

```bash
npx --yes github:pangxueyuan2-creator/repo-privacy-guard scan .
```

Or from source:

```bash
git clone https://github.com/pangxueyuan2-creator/repo-privacy-guard.git
cd repo-privacy-guard
npm install && npm test
node src/cli.mjs scan /path/to/project
```

Exit codes: `0` clean, `1` findings, `2` error.

## Useful options

```bash
repo-privacy-guard scan . --personal-data --min-severity low
repo-privacy-guard scan . --format sarif --output report.sarif
```

Supports `.repoguardignore` and line-level `repoguard:allow`.

## GitHub Action

```yaml
- uses: pangxueyuan2-creator/repo-privacy-guard@v0.1.0
  with:
    path: .
    minimum-severity: high
```

## Status

Early version. Expect false positives and misses. MIT License.
