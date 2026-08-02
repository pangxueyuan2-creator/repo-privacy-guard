# Contributing

Thanks for helping improve Repo Privacy Guard.

## Before opening a change

- Search existing issues and pull requests.
- Open an issue for a new provider rule or behavior change.
- Never include a live credential, private key, personal record, or customer file.
- Build fixtures from synthetic segments so they cannot authenticate anywhere.

## Development

```bash
npm install
npm run verify
```

Changes to a detection rule should include:

- a positive synthetic example;
- a nearby negative example that must not match;
- confirmation that JSON, text, and SARIF output remain redacted;
- a short note about expected false positives.

Pull requests should be focused and explain security impact. By contributing,
you agree that your contribution is licensed under the MIT License.
