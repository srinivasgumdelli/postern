# Deployment guide

One ordered path from nothing to two connected machines: a relay, the edge in front of it, a bridge on each machine, and agent sessions that can send and receive. Each step links to the detailed page for it; this page gives the order and the commands.

Placeholders used throughout. Replace them at deploy time and never commit real values.

| Placeholder | Meaning |
|---|---|
| machine A, machine B | the two machines; machine A also hosts the Docker relay if you use one |
| `peer-a`, `peer-b` | the bridge (peer) names of machine A and machine B |
| `build`, `review` | example session names on machine A and machine B |
| `postern.example.com` | the dedicated relay hostname, a subdomain of a zone you own |
| `<ZONE_ID>`, `<ACCOUNT_ID>` | that zone's id, and the Cloudflare account id (Worker mode only) |
| `<TUNNEL_UUID>` | the tunnel id printed by `cloudflared tunnel create` (Docker mode only) |
| `<PEER_A_CERT_SHA256>`, `<PEER_B_CERT_SHA256>` | SHA-256 fingerprints of each bridge's client certificate |
| `/path/to/project` | the project directory of an agent session that gets the bridge |

Who does what:

- The **operator** owns the Cloudflare zone, runs the relay and issues client certificates. One person can be operator and the human on machine A.
- The **human on each machine** runs the bridge commands in a terminal on that machine, never through an agent session.

Items marked **(unverified)** are Cloudflare behaviour that the detailed docs could not confirm against Cloudflare's documentation. Check them before relying on them; the checks in step 8 test the parts that matter.

## 0. Overview and prerequisites

```
machine A                             edge (Cloudflare)                     machine B
agent sessions --MCP--> bridge  --HTTPS + client cert-->  mTLS + WAF  <--HTTPS + client cert--  bridge <--MCP-- agent sessions
                                                              |
                                          relay: Docker + tunnel on machine A,
                                          or a Worker + Durable Object
```

Both bridges dial out; nothing listens on either machine. The relay sees only ciphertext and routing fields. See [DESIGN.md](../DESIGN.md) for the threat model.

You need:

- **Two machines running macOS** for the bridges, each with a logged-in GUI session and Touch ID or a login password. Trust changes ask for Touch ID or the password in a system dialog, which does not work over SSH.
- **Go 1.26** and the Xcode Command Line Tools on each machine (the bridge uses cgo for the keychain and the approval dialog).
- **A Cloudflare zone you own**, with a dedicated subdomain for the relay (`postern.example.com`) that has no other use.
- For the relay, one of:
  - **Docker mode:** an always-on host (machine A here) with Docker Compose and `cloudflared` for the tunnel login.
  - **Worker mode:** a Cloudflare Workers account and Node 24 (to run the tests and Wrangler).
- **`jq`, `curl` (7.55 or later) and `openssl`** on the operator's machine, for issuing certificates.
- For the agent sessions: **Claude Code 2.1.295 or later** and/or **Codex**.

## 1. Choose a relay mode

Both modes serve the same API, so the bridges only see `relay_url`. Full comparison and threat-model differences: [relay-modes.md](relay-modes.md).

| | Docker + tunnel | Worker + Durable Object |
|---|---|---|
| Runs on | an always-on host you run (relay + `cloudflared` in Compose) | Cloudflare, no host |
| Ciphertext at rest | SQLite on your host | Durable Object storage in your Cloudflare account |
| Identity | edge forwards the certificate fingerprint in a header, plus an edge secret header | the Worker reads the edge's mTLS result itself |
| Edge rules | mTLS, WAF rule, transform rule | mTLS, WAF rule (no transform rule, no edge secret) |
| Fingerprint changes | edit `deploy/relay.json`, restart the relay | edit `PEERS` in `wrangler.toml`, redeploy |
| You patch | host, Docker, pinned images | Worker dev dependencies and compatibility date |

Pick one, then follow **2a** or **2b**, not both.

## 2a. Deploy the Docker relay

Detail: [edge-setup.md](edge-setup.md) steps 1, 2 and 9. On the relay host, in a checkout of this repo:

1. Copy the example files (the real ones are gitignored) and make the secrets directory:

   ```sh
   cp deploy/relay.example.json deploy/relay.json
   cp deploy/cloudflared/config.example.yml deploy/cloudflared/config.yml
   mkdir -m 0700 -p deploy/secrets
   ```

2. Generate the edge secret. It never appears on the terminal, in argv or in shell history:

   ```sh
   (umask 077 && openssl rand -hex 32 > deploy/secrets/edge-secret)
   chmod 0400 deploy/secrets/edge-secret
   ```

3. Create the tunnel and move its credentials into the secrets directory:

   ```sh
   cloudflared tunnel login
   cloudflared tunnel create postern          # prints <TUNNEL_UUID>
   cloudflared tunnel route dns postern postern.example.com
   mv ~/.cloudflared/<TUNNEL_UUID>.json deploy/secrets/tunnel-credentials.json
   chmod 0400 deploy/secrets/tunnel-credentials.json
   ```

   Set `tunnel: <TUNNEL_UUID>` and the hostname in `deploy/cloudflared/config.yml`; keep its two ingress rules as they are. Remove `~/.cloudflared/cert.pem` once the tunnel exists: it can manage every tunnel in the account. (That a credentials-file tunnel runs without it is **unverified**.) Make sure the hostname's only DNS record is the proxied tunnel CNAME.

4. On a Linux host, the relay and `cloudflared` run as `65532:65532` and need to read their secret files. See the ownership notes in [edge-setup.md](edge-setup.md#1-relay-host-files) and [step 2](edge-setup.md#2-tunnel). Change the edge secret's owner only after you have copied it into the transform rule (step 3 below).

5. Leave `deploy/relay.json` with its placeholders for now. Its settings (`"identity": "header"`, `edge_secret_file`, the fingerprint header) are already right for this layout. You fill in the fingerprints in step 7.

6. Optionally build the image now, to catch build problems early:

   ```sh
   docker compose build relay
   ```

**Do not start the stack yet.** The relay refuses to start while `relay.json` still holds placeholder fingerprints, and it must not be reachable before the WAF and transform rules exist (step 3). You start it in step 7, and check its healthcheck there.

## 2b. Deploy the Worker relay

Detail: [relay-modes.md](relay-modes.md#worker-deploy). On the operator's machine, in a checkout of this repo:

1. Test locally:

   ```sh
   cd relay-worker
   npm ci
   npm test
   ```

2. Create `wrangler.toml` from the example (gitignored) and fill it in:

   ```sh
   cp wrangler.toml.example wrangler.toml
   ```

   - `account_id = "<ACCOUNT_ID>"`
   - the route `{ pattern = "postern.example.com", custom_domain = true }`
   - `RELAY_HOSTNAME = "postern.example.com"`
   - leave `PEERS` with its placeholders for now; you fill it in at step 7:

     ```toml
     PEERS = '{"peer-a":["<PEER_A_CERT_SHA256>"],"peer-b":["<PEER_B_CERT_SHA256>"]}'
     ```

   Keep `workers_dev = false`, `preview_urls = false` and `invocation_logs = false`.

3. Authenticate Wrangler with the operator's own Cloudflare login, then deploy:

   ```sh
   npx wrangler login
   npx wrangler deploy
   ```

   The deploy creates the custom domain for `postern.example.com`. A custom domain needs the hostname to have no other DNS record, for example an old tunnel CNAME; remove it first (**unverified**). While `PEERS` holds placeholders the Worker answers 500 `internal` to every request, `/healthz` included, so this first deploy exposes nothing.

## 3. Configure the edge

Detail: [edge-setup.md](edge-setup.md) steps 3, 4, 7 and 8. Do all of this before the relay serves real traffic.

1. **API token, scoped to the one zone.** Dashboard: My Profile, API Tokens, Create Custom Token. Permission **Zone, SSL and Certificates, Edit**; zone resources **Include, Specific zone**, the zone that holds `postern.example.com`; no other zones and no account permissions. Store it in the operator's keychain (`-w` last makes `security` prompt for it):

   ```sh
   security add-generic-password -a operator -s postern-edge-token -w
   ```

   Then define the `cfapi` helper from [edge-setup.md step 3](edge-setup.md#3-edge-api-token-kept-in-the-keychain), which reads the token from the keychain and passes it to `curl` on stdin. It is used for issuing and revoking certificates and for the mTLS host list. It cannot read or change WAF or transform rules.

2. **mTLS for the one hostname.** Dashboard: SSL/TLS, Client Certificates, Hosts, add `postern.example.com`. Or with the API, as in [edge-setup.md step 4](edge-setup.md#4-enable-mtls-for-the-one-hostname) (the `PUT` replaces the whole host list). Set the minimum TLS version to 1.2 or later. Whether mTLS with the Cloudflare-managed CA works on a Free zone and on a Worker custom domain is **unverified**.

3. **WAF custom rule**, both modes. Security, WAF, Custom rules, Create rule, action **Block**:

   ```
   (http.host eq "postern.example.com" and (not cf.tls_client_auth.cert_verified or cf.tls_client_auth.cert_revoked))
   ```

   Both conditions are needed: a revoked certificate still counts as verified.

4. **Transform rule, Docker mode only.** Rules, Transform Rules, Modify Request Header, Create rule, when `http.host eq "postern.example.com"`, with two operations:
   1. **Set dynamic** `X-Postern-Client-Cert-Sha256` to `cf.tls_client_auth.cert_fingerprint_sha256`.
   2. **Set static** `X-Postern-Edge-Secret` to the content of `deploy/secrets/edge-secret`. Paste it from the clipboard (`pbcopy < deploy/secrets/edge-secret` on macOS, `xclip -selection clipboard < deploy/secrets/edge-secret` on Linux) and clear the clipboard afterwards.

   Use **Set**, not Add: Set overwrites whatever a client sends. Whether the `cf.tls_client_auth.*` fields are usable in transform rules on your plan is **unverified**; `postern edge-check` in step 8 proves it. Worker mode needs no transform rule and no edge secret.

## 4. Install the bridge on each machine

On machine A and on machine B, in a checkout of this repo:

```sh
make build
sudo install -m 0755 bin/postern /usr/local/bin/postern
postern version
```

Keep the binary at one fixed path. The Claude Code hooks and the Codex config name it by absolute path, and the keychain trusts that binary. The bridge runs natively, never in a container. Detail: [operations.md](operations.md#1-install-the-bridge-each-machine).

## 5. Initialise each bridge

On machine A, in a terminal on the machine itself (not over SSH, not through an agent):

```sh
postern init --peer-name peer-a --relay-url https://postern.example.com --session build
```

On machine B:

```sh
postern init --peer-name peer-b --relay-url https://postern.example.com --session review
```

`--session` is repeatable; list every session on that machine that should get the bridge, and add more later with `postern session add NAME`. Names are lowercase letters, digits and hyphens. Other flags: `--keychain-service` (default `postern`) and `--config PATH` (default `$POSTERN_CONFIG`, or `~/Library/Application Support/postern/config.json`).

`init` first prints the change it is about to make:

```
Initialise this bridge: generate new keys and trust this config.

Config:    /Users/<you>/Library/Application Support/postern/config.json
Peer name: peer-a
Relay:     https://postern.example.com
Keychain:  postern
Sessions:  build

Approve this change with Touch ID or your login password in the system dialog.
```

Read it, then approve the system dialog with Touch ID or your login password. The dialog is drawn by macOS, so an agent cannot answer it; over SSH or without a GUI session the change is refused. On approval it stores the keys in the keychain, writes and pins the config, and prints:

```
Initialised peer-a (config /Users/<you>/Library/Application Support/postern/config.json, pinned).

Public key:  <BASE64_PUBLIC_KEY>
Fingerprint: <8 groups of 4 hex characters>

Send the public key to your peer and compare fingerprints out of band.
Give this certificate signing request to the edge operator:

-----BEGIN CERTIFICATE REQUEST-----
...
-----END CERTIFICATE REQUEST-----
```

To get the CSR into a file for the operator (this needs no approval and makes no new key):

```sh
postern cert csr --out peer-a.csr       # on machine B: peer-b.csr
```

The CSR holds only the public key. The private keys never leave the keychain. Detail: [operations.md](operations.md#2-initialise).

## 6. Exchange keys

1. Each human runs `postern show` and sends the other side the `Public key` and `Fingerprint` lines. Any channel will do for the key.
2. Compare the fingerprints **out of band**: read them aloud on a call, or compare in person. Do not trust a fingerprint that arrived in the same channel as the key.
3. Add the other side. On machine A:

   ```sh
   postern peer add --name peer-b --public-key '<PEER_B_PUBLIC_KEY>' --fingerprint '<PEER_B_FINGERPRINT>'
   ```

   On machine B:

   ```sh
   postern peer add --name peer-a --public-key '<PEER_A_PUBLIC_KEY>' --fingerprint '<PEER_A_FINGERPRINT>'
   ```

   Quote the fingerprint: it contains spaces. `peer add` refuses a fingerprint that does not match the key, prints the change, asks for Touch ID or your password, then saves and re-pins the config (`Added peer peer-b (...). Config re-pinned.`). Approve only if you compared the fingerprint yourself.

## 7. Issue client certificates

Detail: [edge-setup.md step 5](edge-setup.md#5-issue-a-client-certificate-per-bridge) and [operations.md](operations.md#4-client-certificate).

1. **CSR to the operator.** Each human gives the operator its `peer-a.csr` or `peer-b.csr` from step 5. It is public.

2. **The operator issues each certificate via the API.** Work in a scratch directory outside the repo, with `cfapi` defined as in step 3:

   ```sh
   jq -n --rawfile csr peer-a.csr '{csr: $csr, validity_days: 14}' > peer-a-req.json
   cfapi -X POST "https://api.cloudflare.com/client/v4/zones/<ZONE_ID>/client_certificates" \
     -H 'Content-Type: application/json' --data-binary @peer-a-req.json > peer-a-resp.json
   jq -r '.result.certificate' peer-a-resp.json > peer-a.pem
   jq -r '.result.id, .result.fingerprint_sha256, .result.expires_on' peer-a-resp.json
   openssl x509 -in peer-a.pem -outform DER | shasum -a 256 | cut -d' ' -f1
   ```

   Keep the certificate id (needed to revoke it), check that the two fingerprints agree, return `peer-a.pem` to machine A, and delete the request and response files. Repeat for `peer-b`. Whether the API enforces limits on `validity_days` is **unverified**.

3. **Each bridge imports its certificate:**

   ```sh
   postern cert import peer-a.pem        # on machine B: peer-b.pem
   ```

   It checks that the certificate matches the client key in the keychain, stores it there, and prints:

   ```
   Imported client certificate for peer-a.
   SHA-256: <PEER_A_CERT_SHA256>
   Expires: <date>
   Add the SHA-256 under this peer in the relay's relay.json, then run `postern edge-check`.
   ```

   The first import needs no approval. Check that the SHA-256 matches what the operator computed.

4. **The fingerprints go into the relay config.**
   - Docker mode: in `deploy/relay.json`, replace the placeholders:

     ```json
     "peers": {
       "peer-a": ["<PEER_A_CERT_SHA256>"],
       "peer-b": ["<PEER_B_CERT_SHA256>"]
     },
     ```

   - Worker mode: in `relay-worker/wrangler.toml`:

     ```toml
     PEERS = '{"peer-a":["<PEER_A_CERT_SHA256>"],"peer-b":["<PEER_B_CERT_SHA256>"]}'
     ```

   Fingerprints are 64 hex characters (case, colons and spaces are normalised), each belongs to one peer only, and every peer needs at least one. They are public, not secrets.

5. **Start, restart or redeploy the relay.**
   - Docker mode, the first time (only once the WAF and transform rules from step 3 are live):

     ```sh
     docker compose up -d --build
     docker compose ps            # relay "healthy", cloudflared running, PORTS empty for both
     ```

     `cloudflared` starts only after the relay's healthcheck (`postern-relay healthcheck`) passes. If the relay exits, `docker compose logs relay` says why (for example a placeholder fingerprint or a missing edge secret file). After any later change to `relay.json`: `docker compose restart relay`.
   - Worker mode, after every change to `PEERS`:

     ```sh
     npx wrangler deploy
     ```

## 8. Verify

On each machine:

```sh
postern edge-check
```

It runs these checks against the live hostname and prints `PASS` or `FAIL` for each, with the HTTP status (or `connection refused or TLS rejected`). All must pass:

| Check | What a FAIL means |
|---|---|
| `request without a client certificate is blocked` | A request with no certificate got past the edge. mTLS is not enabled for the hostname, or the WAF rule is missing, disabled or scoped to another host. (A TLS refusal or a 403 HTML page both count as blocked.) |
| `forged fingerprint header without a certificate is blocked` | Same cause as above, and more serious in Docker mode: a client-chosen identity header reached the relay. Stop the relay until the WAF rule is fixed. |
| `request with this bridge's certificate reaches the relay` | The bridge's own certificate does not get through. A 403 HTML page: the certificate is revoked, or not issued from this zone's managed CA. A TLS error: the hostname or DNS is wrong. A 5xx: the tunnel or the relay is down (Docker), or `PEERS` is invalid (Worker, 500). |
| `relay binds this certificate to peer-a` | The relay does not map this certificate to this peer. 403: the fingerprint is not in `relay.json` or `PEERS`, is under the wrong peer, or the relay was not restarted or redeployed. 401 in Docker mode: the edge secret or the fingerprint header did not arrive; check both operations of the transform rule and `docker compose logs relay` for `edge secret rejected`. 401 in Worker mode: the edge did not report a verified, unrevoked certificate. |
| `a forged fingerprint header cannot override this certificate` | Docker mode: the transform rule does not overwrite a client-sent header (an Add instead of a Set, or the rule is missing). Stop and fix it. |
| `this certificate cannot read peer-b's mailbox` | This certificate can poll the other peer's mailbox: its fingerprint is listed under the wrong peer, or both peers share one. Fix the relay config immediately. (Shown only once a peer has been added.) |

Then the operator runs the full [edge-setup.md verification checklist](edge-setup.md#verification-checklist) with a throwaway certificate: items 1 to 10 in Docker mode, items 1 to 6 in Worker mode. It also covers what `edge-check` cannot see from a bridge, such as published ports and requests that skip the edge.

## 9. Connect agent sessions

Give the bridge only to the sessions listed in step 5, and never run them in a bypass or auto-approve mode. Why and how the guard works: [session-guard.md](session-guard.md).

### Claude Code

In each project whose session gets the bridge (here the `build` session on machine A; use `review` on machine B):

1. Add the MCP server in local scope, so it is not committed and other projects do not get it:

   ```sh
   cd /path/to/project
   claude mcp add --transport stdio --scope local postern -- /usr/local/bin/postern mcp --session build
   ```

   Keep the server name `postern`; if you use another, pass it to the guard with `--server`.

2. Install the guard:

   ```sh
   postern guard install --project /path/to/project
   ```

   This merges four hooks (`PreToolUse`, `PostToolUse`, `UserPromptSubmit`, `SessionStart`) into `/path/to/project/.claude/settings.json`, writes the `/postern-clear` command and the `postern` skill. It first runs `claude --version` and refuses a Claude Code release older than 2.1.295, or one whose version it cannot read, because older releases run the tool call when a hook fails. Use `--skip-claude-version-check` only after checking the version yourself.

3. Add the session rule from [examples/session-rule.md](../examples/session-rule.md) to the project's `CLAUDE.md`.

4. Start Claude Code **from the project directory** (hooks load from the start directory only), run `/hooks`, and confirm the four Postern hooks are listed (the commands are `'/usr/local/bin/postern' hook <event> --server postern`). If they are missing, check that no settings file sets `disableAllHooks` and that managed settings do not set `allowManagedHooksOnly`; until they show, do not use the bridge in that session.

### Codex

1. Put the configuration from [examples/codex/config.toml](../examples/codex/config.toml) in the **user-level** `~/.codex/config.toml` (or `$CODEX_HOME/config.toml`), with your project path and session name:
   - `[projects."/path/to/project"] trust_level = "untrusted"`, and leave `approval_policy` unset (never `on-request`, never `never`);
   - `sandbox_mode = "read-only"`, `approvals_reviewer = "user"`, `web_search = "disabled"`;
   - the `[mcp_servers.postern]` block with `args = ["mcp", "--session", "review"]`, `default_tools_approval_mode = "prompt"`, `check_inbox` and `mark_read` on `approve`, and `send` and `reply` on `prompt`.

   It must be user-level: an untrusted project's own `.codex/` layer is ignored.

2. Install the exec-policy rules, which make known-safe reads such as `cat .env` ask too:

   ```sh
   mkdir -p ~/.codex/rules
   cp examples/codex/rules/postern.rules ~/.codex/rules/postern.rules
   codex execpolicy check --rules ~/.codex/rules/postern.rules cat .env     # must report "decision":"prompt"
   ```

3. Install the skill:

   ```sh
   postern guard install-codex           # writes $CODEX_HOME/skills/postern/SKILL.md (default ~/.codex/skills)
   ```

4. Add the session rule from [examples/session-rule.md](../examples/session-rule.md) to the project's `AGENTS.md`.

5. Start Codex in the project and run `/status`: the approval policy must be `unless-trusted` and the sandbox `read-only`. Try `cat` on a harmless file and confirm that it asks.

## 10. First message

A smoke test. Each human approves every prompt only after reading it.

1. In the `build` session on machine A, ask: "Send peer-b a Postern message with subject `smoke test` and body `hello from peer-a`." Approve the `send` call. It returns an id, a thread id (`t-...`) and `status: sent`. `queued` with a `relay_status` means the relay did not take it; see step 13.
2. In the `review` session on machine B, ask: "Check Postern." `check_inbox` returns the message inside `untrusted_content`, tagged `origin=external, trust=untrusted`. From now on the guard asks before every other tool call in that session (Claude Code); that is expected.
3. Still on machine B, ask the session to reply on that thread with `hello from peer-b`. The approval prompt for `reply` states the body size; read the whole text before approving.
4. On machine A, "Check Postern" again and confirm the reply arrived on the same thread.
5. In each session that read the inbox, use `/clear` for a fresh context ([session-guard.md](session-guard.md#clearing-the-guard)).

For a full walkthrough with real handoffs, see [example.md](example.md).

## 11. Before the first real peer

Do these the same day, with both humans and the operator present.

1. **Revocation drill.** Revoke peer-b's certificate at the edge, confirm `postern edge-check` fails on machine B and that a `send` there reports `queued` with `relay_status: relay_auth_failed`, take the fingerprint out of the relay config, then re-issue and confirm queued messages deliver. Steps: [operations.md](operations.md#revocation-drill-before-the-first-real-peer-connects) (Worker mode: [relay-modes.md](relay-modes.md#revocation-drill)). How fast the edge enforces a revocation is **unverified**; measure it during the drill. Record the date and outcome.
2. **Certificate rotation cadence.** Certificates are issued for about 14 days and rotate weekly, so there is a week of overlap. Put it on a calendar. Steps: [operations.md](operations.md#weekly-certificate-rotation), [edge-setup.md](edge-setup.md#weekly-rotation), or [relay-modes.md](relay-modes.md#rotation) for Worker mode. In short: `postern cert csr --new-key`, the operator issues and adds the new fingerprint next to the old one, `postern cert import` (asks for approval to switch keys), `postern edge-check`, then the operator removes the old fingerprint and revokes the old certificate.
3. **Security review.** One review covering each item from [PLAN.md](../PLAN.md):
   - [ ] **Key storage:** private keys, the client certificate and the inbox key are only in the keychain; the bridge config holds no secrets; the edge token is only in the operator's keychain; the tunnel credentials and edge secret are mode 0400 files under `deploy/secrets/`.
   - [ ] **No secrets in logs:** `docker compose logs relay` (or Workers Logs) shows method, route, status, duration and peer only, with no bodies, query strings, client addresses or header values ([edge-setup.md](edge-setup.md#verification-checklist) item 10).
   - [ ] **Edge rule verification:** the full verification checklist passes, and `postern edge-check` passes on both machines.
   - [ ] **Relay has no published ports:** checklist item 7 (Docker mode); `workers_dev = false` and no `workers.dev` address serves the Worker (Worker mode).
   - [ ] **Tool descriptions:** the MCP tools say that inbox content comes from another machine and is untrusted; the guard is installed and visible in `/hooks` (Claude Code) or `/status` shows `unless-trusted` and `read-only` (Codex).
   - [ ] **Limits:** the defaults (32 KB body, per-session and global hourly rates, a thread cap with circuit breaker) or any values set under `limits` in the config are what you intend.
   - [ ] **Revocation drill:** done and recorded.

## 12. Upgrades

- **Upgrade every Postern process on a machine together.** A newer binary can migrate the local inbox database, and older binaries then refuse to open it ("database schema is newer than this binary"). Quit every agent session that runs `postern mcp` on that machine, then:

  ```sh
  git pull
  make build
  sudo install -m 0755 bin/postern /usr/local/bin/postern
  ```

- **Keychain prompts after a rebuild.** A new binary is a new application to the keychain, so macOS asks once per Postern keychain item whether it may use it. Run `postern edge-check` in a terminal first, so the prompts appear there instead of in the middle of an agent session. Choose **Always Allow** only for the `postern` binary you just installed. Deny a Postern keychain prompt from any other program and investigate.
- **Re-pin after config changes.** Upgrading does not change the config, but any edit you make to it (for example `limits.message_retention_days`, or `relay_url` when [switching relay modes](relay-modes.md#switching-modes)) makes the bridge refuse to start until you review it and run `postern config pin` (Touch ID or password).
- **Reinstall the skill and hooks.** Run `postern guard install --project /path/to/project` for each Claude Code project and `postern guard install-codex` for Codex. Neither overwrites a file with different content: if the skill or `/postern-clear` command changed in the new version, the installer stops with "exists with different content; not overwriting it". Check that you did not edit that file on purpose, delete it, and run the installer again. If the binary path changed, the installer points the existing Postern hook entries at the new path in place, keeping their matchers and other keys; it refuses, and changes nothing, if one of them was narrowed by hand (a matcher, `if` or async). Check `/hooks` afterwards.
- **Relay.** Docker mode: `git pull`, then `docker compose up -d --build`. Worker mode: `npm ci && npm test`, then `npx wrangler deploy`. Run `postern edge-check` on both machines afterwards.

## 13. Troubleshooting

More incidents (leaked certificate, lost machine, compromised relay): [operations.md](operations.md#incidents).

| Symptom | Likely cause | Fix |
|---|---|---|
| `config changed since it was pinned; review it (...), then run postern config pin if the change is yours` (or `config is not pinned`) | The config file differs from what you last approved: your own edit, or tampering. | Read the file (relay URL, keychain service, peer keys, sessions). If every change is yours, `postern config pin`. If not, treat it as tampering. |
| `send` returns `status: queued` and `relay_status: relay_auth_failed`, or `check_inbox` reports it | The edge or relay answered 401/403: certificate not imported, expired, revoked, not listed in `relay.json`/`PEERS`, relay not restarted or redeployed, or (Docker) the edge secret is wrong. | `postern edge-check` names the failing check; see step 8. Messages stay queued and deliver once fixed. |
| `relay_status: relay_unreachable` | Polls have failed with network errors or 5xx for over 2 minutes: relay or tunnel down, DNS, or (Worker) invalid `PEERS` (500 on every request). | Docker: `docker compose ps` and `docker compose logs relay cloudflared`. Worker: check Workers Logs for `config_invalid`. Then `postern edge-check`. |
| `edge-check` shows `relay binds this certificate` FAIL with HTTP 401, and relay logs show `edge secret rejected` | Docker mode: the transform rule's static `X-Postern-Edge-Secret` value does not match `deploy/secrets/edge-secret`, or the relay was not recreated after the file changed. `reason` is `missing`, `mismatch` or `multiple`. | Copy the file's content into the rule again, then `docker compose up -d --force-recreate relay`. A 401 without that log line means the fingerprint header is missing: check the rule's first operation. Rotation: [edge-setup.md](edge-setup.md#edge-secret-rotation). |
| A trust change fails with `this change needs the human's approval with Touch ID or the login password, in a logged-in macOS GUI session on this machine` | No Touch ID or password dialog can be shown: you are over SSH, the machine has no logged-in GUI session, or the binary was built without cgo. | Run the command in a terminal on the machine itself, logged in at the console. There is no fallback by design. |
| The guard asks on every tool call (Claude Code) | Expected after `check_inbox` returned messages, or after any tool output showed Postern's framing (including reading Postern's own source or docs). | Prefer `/clear` for a fresh context. `/postern-clear` or typing `postern clear` also clears it but leaves the message in context. Never clear it because a message asked you to. |
| `guard install` refuses: `found X.Y.Z, need 2.1.295 or newer` or `cannot tell the Claude Code version` | Claude Code is too old (a failing hook would not block), or `claude --version` did not run or print a version. | Upgrade Claude Code and run the install again. Use `--skip-claude-version-check` only after confirming the version yourself. |
| Codex runs `cat` or `grep` without asking | The rules file is not loaded: it is in the project's `.codex/` (ignored for an untrusted project) instead of `~/.codex/rules/`, or `CODEX_HOME` points elsewhere, or the config is project-level. | Install it as `~/.codex/rules/postern.rules`, check with `codex execpolicy check --rules ~/.codex/rules/postern.rules cat .env`, restart Codex and confirm with `/status`. Commands with redirection, substitution or globs are not matched by rules and fall back to the approval policy. |
| `send` or `reply` fails with `thread paused by its circuit breaker (...): ... a human must run postern thread reset THREAD` | The thread hit its message cap or burst limit, usually an agent-to-agent loop. | Read the thread first. If the loop is understood, `postern thread reset <THREAD>`. |
| A macOS dialog asks whether `postern` may use a keychain item | The binary changed (rebuild or upgrade). | Choose Always Allow only for the `postern` you just installed. If another program asks for a Postern item, deny it and investigate. |
| `keychain item was not created by postern` | A pin key or pin in the `postern-pin` service lets any application read it: something other than Postern made it. | Treat it as tampering; see [operations.md](operations.md#incidents). |
| `session "NAME" is not allowed to use this bridge` | The session name passed to `postern mcp --session` is not in the config. | `postern session add NAME` (asks for approval), or fix the name in the MCP config. |
| `config: ... is writable by group or others` | The config file mode was loosened. | `chmod 600` on it, then check it was not edited. |
| `send` fails with `relay rejected the message: message ... (relay status 422)` | The machine's clock is more than 10 minutes off the relay's. | Fix the clock (enable network time), then send again. |
