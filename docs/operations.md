# Operations

Setup, key exchange, certificate rotation and the revocation drill. Edge and relay deployment are in [edge-setup.md](edge-setup.md); the session guard is in [session-guard.md](session-guard.md).

All examples use placeholders: `peer-a` (machine A), `peer-b` (machine B), `postern.example.com` (relay hostname). Run every command yourself in a terminal, not through an agent session.

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
- pins the config: the SHA-256 of its path and contents goes into the keychain under the fixed `postern-pin` service, and the bridge refuses to start if the file changes without a re-pin;
- prints the public key, its fingerprint, and a certificate signing request (CSR) for the edge.

Add more sessions later with `postern session add NAME`. Only listed sessions can start the MCP server.

Commands that change what the bridge trusts (`init`, `peer add/remove`, `session add/remove`, `config pin`) print the change on your terminal and ask you to type a one-time code shown there. They refuse to run without a terminal, so an agent cannot run them for you.

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
4. The operator adds that fingerprint under `peer-a` in the relay's `relay.json` and restarts the relay.
5. Verify: `postern edge-check`.

## 5. Connect sessions

Claude Code, in the project of a session listed in the config:

```sh
claude mcp add postern -- /usr/local/bin/postern mcp --session build
postern guard install --project /path/to/project
```

This installs the guard hooks, the `/postern-clear` command and the `postern` skill. Then add the session rule from [`examples/session-rule.md`](../examples/session-rule.md) to that project's `CLAUDE.md`.

Codex: `postern guard install-codex` installs the skill; then follow [`examples/codex/config.toml`](../examples/codex/config.toml) (project marked untrusted; never `on-request` or `never`).

Do not run these sessions in bypass or auto-approve modes.

## Weekly certificate rotation

Client certificates are short-lived (about 14 days) and rotate weekly.

1. `postern cert csr --new-key` generates a new key, keeps it as the *next* key in the keychain (the current certificate keeps working), and prints a CSR.
2. The operator issues a certificate for it.
3. `postern cert import new.pem` sees that the certificate matches the next key, promotes it, and prints the new fingerprint.
4. The operator adds the new fingerprint next to the old one in `relay.json` (both are accepted during the overlap) and restarts the relay.
5. Once `postern edge-check` passes with the new certificate, the operator removes the old fingerprint and revokes the old certificate at the edge.

## Revocation drill (before the first real peer connects)

Do this once, on the same day, with both operators present.

1. The operator revokes peer-b's current certificate at the edge.
2. On machine B, `postern edge-check` must fail: requests with that certificate are blocked at the edge.
3. A peer-b session's `send` reports the message as queued with `relay_status: relay_auth_failed`, and its `check_inbox` reports the same; peer-a receives nothing new.
4. The operator removes the revoked fingerprint from `relay.json` as well.
5. Re-issue: peer-b runs `postern cert csr --new-key`, the operator issues and registers the new certificate, `postern cert import`, `postern edge-check` passes, and queued messages deliver.

Record the date and outcome. Repeat after any change to the edge rules.

## Incidents

| Event | Action |
|---|---|
| Client certificate leaked | Revoke it at the edge, remove its fingerprint from `relay.json`, rotate (`cert csr --new-key`). |
| Machine lost or stolen | Revoke its certificate, remove its fingerprint, and have every peer remove its public key (`postern peer remove`, re-pin). Re-run `init --force` on the replacement machine and exchange fingerprints again. |
| Bridge refuses to start: config pin mismatch | Something changed the config. Inspect it (relay URL, keychain service, peer keys, sessions). If you made the change, `postern config pin` (it asks you to type a code shown on your terminal); if not, treat it as tampering. |
| A `postern` command asks for a confirmation code you did not expect | Something tried to change what the bridge trusts. Do not type the code; press Enter to refuse, then find out what ran it. |
| Thread circuit breaker tripped | Read the thread first. If the loop is understood, `postern thread reset <thread>`. |
| Relay host or edge account compromised | Content stays sealed. Rotate the edge API token and tunnel credentials, redeploy the relay, rotate client certificates. |

## Residual risks (v0)

- Any process running as the same OS user can run the `postern` binary, which the keychain trusts. Sessions with untrusted content in context must approve every tool call, but other agents on the machine are not covered. v1 option: run the bridge as a separate OS user.
- A human approving a long outgoing reply may not read all of it. The secret scanner blocks messages that look like keys or tokens; it cannot catch every sensitive detail.
