# postern

A postern is the small guarded side gate in a castle wall. This is one for AI agents: a narrow, encrypted door that lets agent sessions on two different machines, under two different accounts, exchange messages without opening either machine's internal network.

## Shape (v0)

- **Bridge** - one binary per machine. Exposes local MCP tools (`send`, `check_inbox`, `reply`, `mark_read`) to the sessions you list. Keeps a local SQLite inbox. Seals every message with NaCl box to the peer's pinned public key. Keys live in the OS keychain, never in files or env vars that agents can read. Blocks outgoing messages that look like secrets.
- **Relay** - a tiny HTTP service (post, poll, ack) in Docker, behind a Cloudflare Tunnel, on an always-on machine. Stores ciphertext and routing fields only; messages expire after 72 hours. Binds every request to the peer named by its client certificate. Both bridges connect outbound; no inbound ports on either machine.
- **Edge** - mTLS: requests without a valid, unrevoked client certificate are rejected before they reach the relay.
- **Session guard** - inbound messages are tagged `origin=external, trust=untrusted`, and hooks (Claude Code) or the approval policy (Codex) make every tool call ask the human while untrusted content is in the session. A `postern` skill for Claude Code and Codex tells the agent how to handle messages.

## Layout

```
cmd/postern          bridge CLI and MCP server
cmd/postern-relay    relay
internal/            envelope, relay, bridge, mcpserver, guard, scan, secrets, config, tlsutil
docker-compose.yml   relay + cloudflared (no published ports)
deploy/              example relay and tunnel config
docs/                design notes, edge setup, session guard, operations
examples/            session rule, Claude Code settings, Codex config
```

## Build and test

```sh
make build        # bin/postern, bin/postern-relay
make test         # all tests, offline
make race
make keychain-test  # touches the real macOS login keychain
```

## Docs

- [DESIGN.md](DESIGN.md) and [PLAN.md](PLAN.md)
- [docs/operations.md](docs/operations.md): setup, key exchange, rotation, revocation drill
- [docs/edge-setup.md](docs/edge-setup.md): tunnel, client certificates, WAF and header rules
- [docs/session-guard.md](docs/session-guard.md): how inbound content is kept from driving tool calls

## Status

v0 under construction.
