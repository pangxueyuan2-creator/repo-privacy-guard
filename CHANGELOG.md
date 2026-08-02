# Changelog

All notable changes are documented here.

## [Unreleased]

### Fixed

- Prevent scans from following symbolic links outside the selected path.
- Match double-star ignore patterns across nested directories correctly.
- Report result truncation and the number of actually scanned files accurately.

## [0.1.0] - 2026-08-02

### Added

- Offline scanning for common provider credentials and private-key material.
- Sensitive filename and contextual entropy checks.
- Optional email and international phone detection.
- Text, JSON, and SARIF reporters with redacted findings.
- CLI, JavaScript API, and reusable GitHub Action.
- Tests, bilingual documentation, threat model, and community files.

[Unreleased]: https://github.com/pangxueyuan2-creator/repo-privacy-guard/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/pangxueyuan2-creator/repo-privacy-guard/releases/tag/v0.1.0
