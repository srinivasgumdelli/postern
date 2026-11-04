# Postern build plan

## v0 (target 2-3 days, one session)

Nothing security-relevant is deferred from v0. Each item has a test. Identity binding and the 10 minute replay window moved here from v1 so that statement holds. Detailed task plan: `docs/plans/2026-11-05-v0-implementation.md`.

1. **Repo skeleton**: Go module, `cmd/postern` (bridge + CLI), `cmd/postern-relay`, `internal/...`, Makefile, `docker-compose.yml` for relay + cloudflared. Go stdlib + `golang.org/x/crypto`, a pure-Go SQLite driver (e.g. `modernc.org/sqlite`), an MCP Go SDK.
2. **Envelope + crypto** (`internal/envelope`): build/parse, NaCl box seal/open, ULID ids. Tests: round trip; wrong key fails; tampered box fails; wrong recipient fails.
3. **Relay** (`cmd/postern-relay`): POST/poll/ack/healthz, SQLite store, 72h expiry job, body size cap, no body logging, identity binding (cert fingerprint to peer), 10 minute timestamp window. Tests: long-poll returns on new message; timeout returns empty; duplicate id 409; oversize 413; expiry deletes; foreign `from`/`to` 403; stale 422.
4. **Bridge sender + poller**: outbound HTTPS with client cert; retry with backoff; dedup on receive; local SQLite inbox. Tests against a local relay (mTLS mocked with a test CA).
5. **Keychain**: store/load private key and client cert from macOS Keychain (e.g. via `keybase/go-keychain` or `security` CLI). `postern init` generates the key pair and prints the public key + fingerprint. No secrets ever written to disk in plaintext.
6. **MCP server**: `send`, `check_inbox`, `reply`, `mark_read` over stdio, with untrusted tagging in outputs and in tool descriptions.
7. **Limits**: 32 KB body, per-session and global rate limits, per-thread cap with circuit breaker.
8. **Edge setup doc** (generic): create subdomain, issue client certs, WAF rule, tunnel; checklist to verify that a request without a cert is blocked.
9. **Session-side guard**: ship (a) the session rule snippet, (b) a Claude Code `PreToolUse` + `UserPromptSubmit` hook pair with per-session taint marker, (c) Codex approval-policy config, (d) `untrusted_content` framing and `readOnlyHint` annotations. Tests: hook returns `ask` for any tool other than `check_inbox`/`mark_read` while tainted (`deny` in bypass mode); clears only on the explicit `postern clear` prompt; injection fixture (message asking to run a command, edit a file, push code) produces zero unapproved tool calls in a scripted session.
10. **End-to-end test**: two bridges on one machine with separate keychains/configs through a local relay; message out and reply back.

Acceptance for v0:
- Request without a valid client cert never reaches the relay (verified against the real edge).
- Relay DB contains no plaintext subject/body (grep test).
- Tampered or wrongly-addressed envelopes are dropped.
- An agent session without the MCP config cannot send.
- Inbound messages show `origin=external, trust=untrusted`.
- An inbound message never triggers a tool call without the human's approval (hook/approval policy enforced, injection fixture passes).

## v1 (+1-2 days)

- Secret scanner on outgoing messages (block, not redact).
- Audit log (JSONL, metadata only, no bodies).
- Bridge under a separate OS user (closes the same-user residual risk).
- Hardware-bound keys option.
- `postern wait` helper.
- Setup scripts and docs.

## Before the first real peer connects

One security review covering: key storage, no-secrets-in-logs, edge rule verification, relay has no published ports, tool descriptions, limits, revocation drill (revoke a cert and confirm the bridge is cut off).
