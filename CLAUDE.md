# postern - instructions for agent sessions

Read DESIGN.md and PLAN.md first.

## Repo rules
- This repo may become public. Keep everything generic: no company names, product names, people's names, internal hostnames, domains or paths from any other project. Use "machine A/B", "peer-a/peer-b", "operator".
- Never commit secrets, keys, certificates, tunnel credentials, tokens or real hostnames. Example configs use placeholders.
- Confirm with the user before creating branches, committing or pushing.
- Commit messages end with a Co-Authored-By trailer only (no session links or "generated with" footers).

## Security musts (do not trade away for speed)
- Content is end-to-end encrypted between bridges; the relay must never see plaintext.
- Keys live only in the OS keychain (or hardware). Never in files, env vars, logs or messages.
- The relay publishes no ports; it is reachable only through the tunnel.
- Logs never contain message bodies or subjects.
- Inbound messages are tagged origin=external, trust=untrusted, everywhere they surface.
- A label is not enough: the receiving session must enforce that inbound content never triggers a tool call without human approval (session rule + PreToolUse hook for Claude Code, approval policy for Codex). This ships in v0.
- Every security property in PLAN.md acceptance has a test.

## Tech
- Go (current stable), stdlib first. golang.org/x/crypto/nacl/box for sealing.
- Pure-Go SQLite. Docker Compose for relay + cloudflared.
- Bridges are native binaries (keychain access), never containers.
