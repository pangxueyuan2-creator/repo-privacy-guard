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

## Strict automated gate

```bash
repo-privacy-guard scan /immutable/source-snapshot --strict-gate --format json
```

Strict mode disables `.repoguardignore`, inline `repoguard:allow`, and default
ignored directories such as `dist`, `vendor`, and `node_modules`. The only tree
exclusion is the target root's `.git` directory or metadata file; its presence is
counted in `gate.excludedGitMetadata`. Git history and metadata are outside this
scope. A nested `.git`, symbolic link, unreadable file, binary content, invalid
UTF-8, changed metadata, or an exhausted budget makes the scan incomplete.

| Decision | Exit | Meaning |
| --- | --- | --- |
| `pass` | 0 | Complete observation of the declared scope with no blocking finding |
| `fail` | 1 | A blocking finding was observed, including during an incomplete scan |
| invalid request / operational error | 2 | No usable gate result; never treat as pass |
| `unknown` | 3 | Incomplete observation with no known blocking finding |

`--staged --strict-gate` returns `unknown` without invoking Git. `--ignore`,
`--no-entropy`, and `--min-severity critical` are rejected in strict mode. The
default threshold is `high`; callers may lower it to `medium` or `low`.
Personal-data checks remain opt-in. The existing GitHub Action retains its
advisory scanning interface; invoke the CLI explicitly to use this gate.

```js
import { scanPath } from "repo-privacy-guard";
const report = await scanPath(snapshotPath, { strictGate: true });
if (report.gate.decision !== "pass") {
  // Reject delivery. Findings contain rule IDs and positions, never matched values.
}
```

JSON preserves the existing `version: 1` fields and adds `gate`:
`schemaVersion`, `policyVersion`, `scope`, `decision`, `complete`,
`blockingObserved`, `reasons`, `excludedGitMetadata`, `entries`,
`discoveredFiles`, `totalBytes`, and `limits`. Decisions are lowercase. Scope is
`target-tree-excluding-root-git-metadata-v1` for a directory, `single-file-v1`
for a file, or `unsupported-staged-v1`. `blockingFindings` counts retained
findings; `gate.blockingObserved` also covers blocking findings omitted by the
report cap. Always consume `gate.decision`, rather than infer pass from an empty
findings array. SARIF 2.1.0 includes the same gate in
`runs[0].properties.strictGate` and reports incomplete execution in `invocations`.

The default limits are 1 MiB per file, 200 retained findings, 5,000 files,
10,000 directory entries, 64 MiB total bytes read, and directory depth 64.
The JavaScript options `maxFileSize`, `maxFindings`, `maxFiles`, `maxEntries`,
`maxTotalBytes`, and `maxDepth` may reduce these limits. `maxFindings` may be
increased to 10,000; other defaults are ceilings. Directory enumeration reads at
most one extra entry to detect exhaustion. Content is read with a bounded buffer,
never imported or executed. Invalid limits throw an error.

Stable incomplete reason codes are `binary_file`, `invalid_utf8`, `large_file`,
`read_error`, `symlink`, `unsupported_file`, `unsupported_path`, `path_collision`,
`metadata_changed`, `file_limit`, `entry_limit`, `depth_limit`,
`total_bytes_limit`, `findings_limit`, and `unsupported_staged_scope`.

Strict mode is a filesystem observation, not an atomic snapshot or a proof that
all credentials were found. Callers should provide an immutable source snapshot,
bind its digest and the scanner revision externally, and impose an external
wall-clock deadline. Individual filesystem operations can block; metadata checks
cannot exclude concurrent change-and-restore attacks or every path race.

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
