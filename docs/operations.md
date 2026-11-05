# Operations

Setup, key exchange, certificate rotation and the revocation drill. Edge and relay deployment are in [edge-setup.md](edge-setup.md); the session guard is in [session-guard.md](session-guard.md).

All examples use placeholders: `peer-a` (machine A), `peer-b` (machine B), `postern.example.com` (relay hostname). Run every command yourself in a terminal, not through an agent session. Commands that change trust need Touch ID or your login password, so run them on the machine itself, in a logged-in macOS GUI session (not over SSH).

## 1. Install the bridge (each machine)

```sh
make build
sudo install -m 0755 bin/postern /usr/local/bin/postern
```

The bridge must run natively (not in a container) so it can use the OS keychain. v0 supports the macOS login keychain.

When the binary changes (rebuild or upgrade), macOS asks once per keychain item whether the new binary may use it. Choose **Always Allow** only for the `postern` binary you just installed. If any other program triggers a Postern keychain prompt, deny it and investigate.

## 2. Initialise

```sh
postern init --peer-name peer-a --relay-url https://postern.example.com --session build
```

This:

- generates the X25519 key pair and the mTLS client key, and stores both in the keychain (never on disk);
- writes the config (`~/Library/Application Support/postern/config.json`, or `$POSTERN_CONFIG`), which holds no secrets;
- generates a key that encrypts the local inbox at rest;
- pins the config: an HMAC-SHA256 of its path and contents, keyed by a pin key that postern creates in the keychain on first use, goes into the keychain under the fixed `postern-pin` service, and the bridge refuses to start if the file changes without a re-pin;
- prints the public key, its fingerprint, and a certificate signing request (CSR) for the edge.

Add more sessions later with `postern session add NAME`. Only listed sessions can start the MCP server.

Commands that change what the bridge trusts (`init`, `peer add/remove`, `session add/remove`, `config pin`, and `cert import` when it switches to a rotated key) print the full change on your terminal, then macOS shows a system dialog asking for Touch ID or your login password. Read the change on the terminal before you approve. The dialog is drawn by the operating system, so an agent cannot read or answer it, even by running the command inside a pseudo-terminal. Without a logged-in GUI session (for example over SSH) the change is refused; there is no fallback.

## 3. Exchange public keys

Each side sends the other its public key and fingerprint (`postern show`). Then compare fingerprints **out of band**: read them aloud on a call or compare in person. Do not trust a fingerprint that arrived in the same channel as the key.

```sh
postern peer add --name peer-b --public-key '<BASE64_PUBLIC_KEY>' --fingerprint '<FINGERPRINT>'
```

`peer add` refuses a fingerprint that does not match the key, then saves and re-pins the config.

## 4. Client certificate

1. Give the CSR printed by `init` (or `postern cert csr`) to the operator. It contains only the public key.
2. The operator issues a client certificate from it ([edge-setup.md](edge-setup.md)) and returns the certificate PEM.
3. Import it:

   ```sh
   postern cert import peer-a.pem
   ```

   This checks that the certificate matches the key in the keychain, stores it, and prints its SHA-256 fingerprint.
4. The operator adds that fingerprint under `peer-a` in the relay's `relay.json` and restarts the relay (in Worker mode: adds it to `PEERS` in `wrangler.toml` and redeploys, see [relay-modes.md](relay-modes.md#worker-deploy)).
5. Verify: `postern edge-check`.

## 5. Connect sessions

Claude Code, in the project of a session listed in the config:

```sh
claude mcp add postern -- /usr/local/bin/postern mcp --session build
postern guard install --project /path/to/project
```

This installs the guard hooks, the `/postern-clear` command and the `postern` skill. Then add the session rule from [`examples/session-rule.md`](../examples/session-rule.md) to that project's `CLAUDE.md`.

Codex: `postern guard install-codex` installs the skill; then follow [`examples/codex/config.toml`](../examples/codex/config.toml) in the user-level `~/.codex/config.toml` (project marked untrusted, `read-only` sandbox; never `on-request` or `never`), install [`examples/codex/rules/postern.rules`](../examples/codex/rules/postern.rules) as `~/.codex/rules/postern.rules`, and add the session rule to the project's `AGENTS.md`. Details: [session-guard.md](session-guard.md#codex).

Do not run these sessions in bypass or auto-approve modes.

## Local inbox retention

Each bridge prunes its local inbox hourly: sent and received messages after 30 days, failed outgoing messages after 7 days. Change the period with `"limits": {"message_retention_days": N}` in the config (then `postern config pin`). Upgrade all Postern processes on a machine together: once a newer binary migrates the inbox database, older binaries refuse to open it.

## Audit log

Each machine keeps a local, append-only audit log of what went through its bridge and of every trust change made with the CLI. It is metadata only, and it is on by default.

**Where it lives.** `<data dir>/audit/audit.jsonl`, where the data directory is `data_dir` from the config or, by default, the config file's directory (`~/Library/Application Support/postern/audit/`). The directory is mode 0700 and the files 0600; Postern refuses to use them if group or others can access them, or if the file is a symlink. Every `postern mcp` process and the CLI on the machine append to the same file, one at a time, under a lock on `audit.lock` in that directory.

**What it records.** One JSON line per event, with `ts` (UTC), `seq`, `event`, `actor` (`bridge` or `cli`) and, where they apply, `peer`, `session`, `thread`, `id`, `size_bytes` (body size), `status` (relay HTTP status), `reason` (a short code), and `prev`.

- Bridge: `sent`, `queued`, `delivered` (a queued message accepted on a retry), `rejected` (the relay refused it, or it `expired` after 72 hours), `blocked_by_scanner` (`reason` is the rule name and line, for example `rule=private-key,line=3`), `rate_limited` (`session` or `global`), `thread_tripped` (`cap` or `burst`), `received`, `dropped` (the drop reason code, for example `wrong_recipient` or `decrypt`), `relay_auth_failed`, `relay_unreachable`, `relay_recovered` (each once per change of state, not per retry).
- CLI, after the change succeeded: `init`, `peer_add`, `peer_remove`, `session_add`, `session_remove`, `config_pin`, `cert_import`, `cert_rotate`, `thread_reset`, `guard_install`.

It never records subjects, bodies, keys, certificates, fingerprints, query strings or file paths, and never the sending session of an inbound message (that name comes from the other machine, inside the sealed message). Every field is checked against a strict pattern before it is written; anything else is written as `!invalid`.

**Reading it.**

```sh
postern audit tail            # last 20 events
postern audit tail -n 200 --json
```

`tail` re-checks every field it prints, so a hand-edited line cannot put arbitrary text (or terminal escapes) on your screen or into an agent's context. Neither `tail` nor `verify` opens the bridge's keys; both refuse a config that no longer matches its pin, so an edited `data_dir` cannot point them at another log.

**Verifying it.**

```sh
postern audit verify
postern audit verify --hash <LAST_HASH_NOTED_EARLIER>
```

Every line's `prev` is the SHA-256 of the line before it (the first line ever has 64 zeros), and `seq` goes up by one. `verify` walks the rotated files and the active file in order and exits non-zero at the first entry that does not parse, skips a `seq`, or whose `prev` does not match, naming that `seq` and the file. An edit to an entry shows up at the entry after it. On success it prints the last hash: write it down somewhere the machine's user cannot change (a note on another device, a ticket), and later run `verify --hash` with it to check that every entry up to that point is still there and unchanged.

**Rotation.** At 10 MiB the active file is renamed to `audit-YYYYMMDD-HHMMSS.jsonl` (UTC) and a new one starts whose first line chains to the old file's last line. At most 10 rotated files are kept; once the oldest are removed, `verify` says the chain starts at a later `seq` and takes that first entry as given.

**What it does not prove.** It is tamper evidence, not prevention. Anything running as your OS user (including an agent with shell access) can rewrite the whole log and recompute every hash, or delete it. Cutting entries off the end, or editing only the last entry, leaves a chain that still verifies; only a hash you kept elsewhere catches that. A crash or a full disk mid-write can leave one broken line, which `verify` reports like an edit. A clean `verify` shows the entries are consistent with each other; it does not show that nothing happened that is not in the log. Running the bridge as a separate OS user (v1) is what would put the log out of an agent's reach.

**Turning it off.** Set `"audit": {"enabled": false}` in the config and run `postern config pin`. That pin is still recorded (`config_pin` with `reason=audit_off`), so the log shows when it stopped. If the audit log cannot be opened (for example wrong permissions), `postern mcp` refuses to start and says why; if a single write fails later, the bridge logs it and keeps working.

Upgrade note: a config saved by this version states `"audit"`, which older binaries reject as an unknown field. Upgrade every Postern binary on a machine together.

## Weekly certificate rotation

Client certificates are short-lived (about 14 days) and rotate weekly.

1. `postern cert csr --new-key` generates a new key, keeps it as the *next* key in the keychain (the current certificate keeps working), and prints a CSR.
2. The operator issues a certificate for it and notes its SHA-256 fingerprint ([edge-setup.md](edge-setup.md) step 5).
3. The operator adds the new fingerprint next to the old one in `relay.json` (both are accepted during the overlap) and restarts the relay. In Worker mode: add it to `PEERS` and redeploy ([relay-modes.md](relay-modes.md#rotation)). Do this before the import, so the bridge is never presenting a certificate the relay does not know.
4. `postern cert import new.pem` sees that the certificate matches the next key, asks you to approve the switch (Touch ID or password), promotes it, and prints the new fingerprint. Check that it matches the one the operator added.
5. Once `postern edge-check` passes with the new certificate, the operator removes the old fingerprint and revokes the old certificate at the edge.

## Revocation drill (before the first real peer connects)

Do this once, on the same day, with both operators present.

1. The operator revokes peer-b's current certificate at the edge.
2. On machine B, `postern edge-check` must fail: requests with that certificate are blocked at the edge.
3. A peer-b session's `send` reports the message as queued with `relay_status: relay_auth_failed`, and its `check_inbox` reports the same; peer-a receives nothing new.
4. The operator takes the revoked fingerprint out of `relay.json` as well and restarts the relay (in Worker mode: out of `PEERS`, then redeploys). Every peer must keep at least one fingerprint: the Docker relay refuses to start, and the Worker answers 500 to everyone, when a peer has none. If the replacement certificate is not issued yet, put a fingerprint that matches no certificate in its place (`openssl rand -hex 32`).
5. Re-issue: peer-b runs `postern cert csr --new-key`, the operator issues and registers the new certificate, `postern cert import`, `postern edge-check` passes, and queued messages deliver.

Record the date and outcome. Repeat after any change to the edge rules.

## Incidents

| Event | Action |
|---|---|
| Client certificate leaked | Revoke it at the edge, take its fingerprint out of `relay.json` (or `PEERS` in Worker mode; replace it with `openssl rand -hex 32` if it was the peer's only one) and restart or redeploy the relay, rotate (`cert csr --new-key`). |
| Machine lost or stolen | Revoke its certificate, remove its fingerprint, and have every peer remove its public key (`postern peer remove`, re-pin). Re-run `init --force` on the replacement machine and exchange fingerprints again. |
| Bridge refuses to start: config pin mismatch | Something changed the config. Inspect it (relay URL, keychain service, peer keys, sessions). If you made the change, `postern config pin` (it asks for Touch ID or your password); if not, treat it as tampering. |
| Bridge refuses a keychain item as "not created by postern" | A pin key or pin in the `postern-pin` service lets any application read it, so something other than postern made it. Treat it as tampering: delete that item (Keychain Access, or `security delete-generic-password -s postern-pin -a <account>`), review the config, then `postern config pin`. |
| A Touch ID or password dialog for `postern` appears that you did not expect | Something tried to change what the bridge trusts. Cancel it, then find out what ran it. |
| `postern audit verify` reports a break | Something edited, removed or reordered audit entries (or a write was interrupted by a crash or full disk). Note the `seq` and file it names; entries before it still verify. Copy the audit directory somewhere safe, then find out what ran as your user around that time. Do not edit the log to make it verify again. |
| Thread circuit breaker tripped | Read the thread first. If the loop is understood, `postern thread reset <thread>`. |
| Relay host or edge account compromised | Content stays sealed. Rotate the edge API token, tunnel credentials and edge secret ([edge-setup.md](edge-setup.md#edge-secret-rotation)), redeploy the relay, rotate client certificates. |
| Relay logs show `edge secret rejected` | Something reached the relay without going through the edge (or the transform rule's secret is out of date). The `reason` says whether the header was missing, wrong or repeated. Find what on the relay host or internal network sent it; if the rule was just changed, re-check it against `deploy/secrets/edge-secret`. |

## Residual risks (v0)

- A process running as your OS user can delete the pin key and re-create it with an access list that names the `postern` binary, then write a matching pin for a config of its choosing. The access-list check cannot tell that item from a real one. Postern itself never re-pins without your Touch ID or password; closing this fully needs the v1 separate-OS-user bridge. See DESIGN.md.
- The dialog proves you approved, not that you started the command: an agent can run a trust-changing command and the dialog still appears. Approve only changes you started.

- Any process running as the same OS user can run the `postern` binary, which the keychain trusts. Sessions with untrusted content in context must approve every tool call, but other agents on the machine are not covered. v1 option: run the bridge as a separate OS user.
- A human approving a long outgoing reply may not read all of it. The secret scanner blocks messages that look like keys or tokens; it cannot catch every sensitive detail.
