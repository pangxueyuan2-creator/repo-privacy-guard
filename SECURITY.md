# Security policy

## Supported version

Security fixes are applied to the latest release and the `main` branch.

## Reporting a vulnerability

Use [GitHub private vulnerability reporting](https://github.com/pangxueyuan2-creator/repo-privacy-guard/security/advisories/new).
Do not open a public issue containing a real secret, exploit, private repository
content, or personal information.

Include a redacted description, affected version, impact, and reproduction steps
that use synthetic data. The maintainer will acknowledge a complete report within
seven days and coordinate disclosure after a fix is available.

## Important limitation

If the scanner misses a live credential, revoke or rotate that credential before
reporting the detection gap. Removing it from a file does not make it safe again.
