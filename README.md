# postern

A postern is the small guarded side gate in a castle wall. This is one for AI agents: a narrow, encrypted door that lets agent sessions on two different machines, under two different accounts, exchange messages without opening either machine's internal network.

## Shape (v0)

- **Bridge** - one binary per machine. Exposes local MCP tools (`send`, `check_inbox`, `reply`) to the sessions you configure. Keeps a local SQLite inbox. Seals every message with NaCl box to the peer's pinned public key. Keys live in the OS keychain, never in files or env vars that agents can read.
- **Relay** - a tiny HTTP service (post, poll, ack) in Docker, behind a Cloudflare Tunnel. Stores ciphertext and routing fields only; messages expire after 72 hours. Both bridges connect outbound; no inbound ports on either machine.
- **Edge** - mTLS: requests without a valid, unrevoked client certificate are rejected before they reach the relay.
- **Agent posture** - inbound messages are tagged `origin=external, trust=untrusted`: information for the agent, never instructions with authority.

## Status

Design stage. Nothing built yet.
