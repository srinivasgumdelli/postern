# Security policy

Postern's job is to keep a narrow, encrypted door between agent sessions closed to everything else, so security reports are very welcome.

## Reporting a vulnerability

Please report privately through GitHub: **Security → Report a vulnerability** on this repository. Do not open a public issue for anything exploitable.

Include what you can: affected component (bridge, relay, edge setup, session guard, scanner), steps or a proof of concept, and the impact you see. Please do not include real keys, tokens or message contents.

You should get an acknowledgement within a few days. Fixes land on `main`; there are no maintained release branches yet.

## Scope

In scope:

- Reading or forging message content anywhere outside the two bridges (relay, edge, tunnel, logs, disk).
- Impersonating a peer, replaying or dropping messages at the relay beyond what the threat model in [DESIGN.md](DESIGN.md) allows.
- Inbound content triggering a tool call without the human's approval, or the session guard failing open.
- Keys or secrets reaching files, env vars, logs, argv or MCP output.
- Bypassing the config pin or the user-presence check for trust changes.

Known residual risks, documented and out of scope unless you find a cheaper path than described:

- A process running as the same OS user as the bridge can run the `postern` binary or rewrite keychain items (see [docs/operations.md](docs/operations.md#residual-risks-v0)).
- The secret scanner is a best-effort filter, not a boundary.
- Agent clients without per-call approval are unsupported for receiving messages (see [docs/session-guard.md](docs/session-guard.md)).
