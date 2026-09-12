# Threat model

## Assets protected

- Provider API keys and access tokens accidentally stored in text files.
- Private keys and credential-bearing connection strings.
- Sensitive configuration files that should be reviewed before publication.
- Optional basic personal identifiers such as email addresses and phone numbers.

## Trust boundaries

The scanner is designed to run on a trusted local checkout or GitHub Actions
runner. It reads the target path and writes only when `--output` is supplied.
It does not make network requests or execute scanned files. Stable symbolic links
are rejected or skipped. This is an observed-filesystem boundary, not a sandbox:
concurrent directory replacement can race filesystem operations.

Finding objects and normal reports do not include matched values. A truncated
SHA-256-derived fingerprint is provided for correlation and is not intended as
an authentication or integrity primitive.

## Known limitations

Strict mode (`--strict-gate`) rejects target-controlled suppressions and surfaces
all observed content exclusions as incomplete, except the explicitly declared
root `.git` metadata exclusion. Nested Git metadata is unsupported. Strict mode
does not execute Git; staged strict scanning returns unknown. It checks metadata
before/after reads and at the end of scanning, but does not provide an atomic
snapshot or prevent concurrent change-and-restore attacks. Use an immutable source
snapshot and externally bind the scanner revision and source digest for delivery
receipts. Resource ceilings bound content and inventory work, while individual
filesystem calls still require an external wall-clock watchdog. Names must be
portable NFC path components without control characters or Windows device aliases.
Strict pass attests only that this declared observation completed and no configured
blocking detector fired; it does not attest credential absence or Git history safety.

- Pattern matching cannot detect every credential format.
- Entropy is a heuristic and can produce false positives or false negatives.
- Files larger than the configured limit and files detected as binary are skipped.
- Symbolic links are skipped and their targets are not scanned.
- Ignore rules and inline exceptions can hide real risks if misused.
- Previously committed secrets remain compromised even after removal from HEAD.
- The scanner does not validate whether a credential is active.
- Personal-data checks cover only simple email and international phone formats.

## Recommended response to a real exposure

1. Revoke or rotate the credential at its provider immediately.
2. Review provider logs for unauthorized use.
3. Remove the value from the current tree and, when appropriate, Git history.
4. Notify affected collaborators without posting the credential again.
5. Add a regression test or scanning rule using a synthetic value.
