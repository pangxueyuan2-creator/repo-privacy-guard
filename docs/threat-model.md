# Threat model

## Assets protected

- Provider API keys and access tokens accidentally stored in text files.
- Private keys and credential-bearing connection strings.
- Sensitive configuration files that should be reviewed before publication.
- Optional basic personal identifiers such as email addresses and phone numbers.

## Trust boundaries

The scanner is designed to run on a trusted local checkout or GitHub Actions
runner. It reads the target path and writes only when `--output` is supplied.
It does not make network requests or execute scanned files.

Finding objects and normal reports do not include matched values. A truncated
SHA-256-derived fingerprint is provided for correlation and is not intended as
an authentication or integrity primitive.

## Known limitations

- Pattern matching cannot detect every credential format.
- Entropy is a heuristic and can produce false positives or false negatives.
- Files larger than the configured limit and files detected as binary are skipped.
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
