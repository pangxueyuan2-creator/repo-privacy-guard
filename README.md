# Repo Privacy Guard

Offline scanner that looks for likely secrets and privacy risks before you make a repository public.

It checks for common credentials, private keys, credentialed URLs, high-entropy values, and sensitive filenames. Output is redacted — matched values never show up in the results.

It reduces risk. It does not prove a repo is safe.

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
repo-privacy-guard scan . --staged   # only what is staged for the next commit
```

`--staged` reads file content from the Git index (what will be committed), skips deleted paths, and never executes repository code. Supports `.repoguardignore` and line-level `repoguard:allow`.

## GitHub Action

```yaml
- uses: pangxueyuan2-creator/repo-privacy-guard@v0.1.0
  with:
    path: .
    minimum-severity: high
```

## Status

Early version. Expect false positives and misses. MIT.
