# Contributing

Thanks for helping. Postern is small on purpose; changes that widen what it can reach or do need a strong reason.

## Build and test

```sh
make build
make test     # offline, no keychain, no Docker
make race
make vet
```

The bridge needs macOS (keychain via cgo). `make keychain-test` exercises the real login keychain with throwaway items.

## Rules

- **Security properties need tests.** Anything in the "Security musts" of [CLAUDE.md](CLAUDE.md) or the acceptance list in [PLAN.md](PLAN.md) that you touch must stay covered by a test that would fail if the property broke.
- **Keep it generic.** No real names, company or product names, hostnames, domains, account ids or personal paths in code, docs, tests or commit messages. Use `peer-a`/`peer-b`, `machine A/B`, `operator`, `postern.example.com`.
- **No secrets.** Never commit keys, certificates, tunnel credentials or tokens, and never write realistic-looking secrets into test fixtures; build them at runtime.
- **Logs never contain message subjects, bodies, keys or query strings.**
- **Stdlib first.** New dependencies need a reason in the PR.

## Pull requests

- One concern per PR, small commits, each commit builds.
- Commits are signed.
- Describe the security impact (or "none") and how you tested it.

Report vulnerabilities privately; see [SECURITY.md](SECURITY.md).
