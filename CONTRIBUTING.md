# Contributing to EasyEAP

Thanks for helping. Bug reports, controller compatibility notes and pull requests are all welcome.

## Before you start

- **Security issues:** don't open a public issue. Use
  [private vulnerability reporting](https://github.com/paulmataruso/EasyEAP/security/advisories/new). See
  [SECURITY.md](SECURITY.md).
- **Larger changes:** open an issue first so we can agree on the approach before you spend time on it.
- **Controller reports:** if you've run EasyEAP with a controller that isn't in
  [docs/controllers/](docs/controllers/README.md), an issue with the model, firmware version and what worked is
  very useful.

## Licensing of contributions

EasyEAP is licensed under the [Business Source License 1.1](LICENSE), and the maintainer also offers commercial
licenses. For that to stay possible, contributions must be licensable on the same terms.

By submitting a pull request, you agree that:

1. you wrote the contribution, or otherwise have the right to submit it;
2. you license it to the maintainer under the Apache License 2.0, and you grant the maintainer the right to
   distribute it as part of EasyEAP under the Business Source License, under commercial licenses, and under any later
   license that EasyEAP uses;
3. you sign off each commit (`git commit -s`), which certifies the
   [Developer Certificate of Origin](https://developercertificate.org).

If you can't agree to these terms, please open an issue describing the change instead of a pull request.

## Development

[DEVELOPMENT.md](DEVELOPMENT.md) describes the repository layout, the development stack and conventions. The short
version:

```sh
# Backend (Python 3.13)
cd backend && pip install -e '.[dev]'
ruff check app tests && pytest

# Frontend (Node 24, pnpm)
cd frontend && pnpm install
pnpm typecheck && pnpm lint && pnpm test

# Full stack, including real EAP-TLS against a lab domain controller
cd deploy && ./install.sh --lab && bash ../tests/e2e/run.sh
```

## What a good pull request looks like

- **It fails securely.** Missing or stale data, and any error, must deny access. Never log private keys, passwords,
  shared secrets, enrollment tokens or PKCS#12 passwords.
- **It doesn't add custom cryptography.** Use the established libraries the project already relies on.
- **It's tested.** Add or update tests next to the code you change. CI runs the backend and frontend suites and
  builds every image.
- **It keeps the console honest.** Status labels must state what's actually true. For example, don't call
  revocation immediate when a cache or controller delays it.
- **It documents user-visible changes** in [CHANGELOG.md](CHANGELOG.md) under *Unreleased*.

## Conduct

Everyone taking part is expected to follow the [Code of Conduct](CODE_OF_CONDUCT.md).
