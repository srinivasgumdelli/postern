# Design: the bridge under a separate OS user (macOS)

Status: proposal for v1. Nothing here is implemented. No code changes come with this document.

Placeholders: `_postern` (the dedicated role user and its group), "operator" (the human's own macOS account, which also runs the agent sessions), `postern.bridge` (launchd label), `peer-a`/`peer-b`, `build`/`review` (session names).

Every macOS fact this design depends on is tagged with an id such as [F12]. The [fact register](#fact-register) at the end says for each one whether it was **verified** (and how: man page, SDK header, or a throwaway probe run on macOS 26.5, Apple silicon, Go 1.26) or is **unverified**. Unverified facts are the first things to test (Phase 0).

## Summary

Today every `postern mcp` process runs as the operator, reads its keys from the operator's login keychain, and shares an inbox file in the operator's home. Any other process running as the operator can run the same binary, so it can use the bridge's identity, and with some deliberate work it can forge the config pin (DESIGN.md, "Residual risk: forging the pin as the same OS user").

The proposal: one long-running bridge daemon, started by launchd in the system domain as a hidden role user `_postern`. The keys, config, pin, inbox and relay connection all move into that daemon and into files only `_postern` can open. Agent sessions keep launching `postern mcp --session NAME`, but that process becomes a thin client. It connects to a unix socket, and the daemon checks the caller's uid and code signature through the kernel's audit token before it answers. Trust changes still need Touch ID or the login password. The client shows that dialog in the operator's GUI session, and the daemon applies a change only on the same verified connection, against a single-use challenge bound to the exact change.

What this buys: an operator-uid process can no longer **steal** the keys, **rewrite** what the bridge trusts, or **read or corrupt** the inbox. What it does not buy by itself: an operator-uid process can still **use** the bridge as a listed session by running the genuine client. An optional "attach approval" (a Touch ID dialog whenever a session connects) narrows that, at the cost of one dialog per session start. Root, and an admin whose sudo can be reached, are out of scope.

Recommendation: build it (alternative (a) below), with ad-hoc signing plus the hardened runtime and a client check that pins the daemon's own cdhash. Developer ID signing stays optional. Separately, as a cheap fix that does not wait for the daemon: sign the v0 binary with the hardened runtime now [F22]. Estimated effort for Phases 0 to 3 is 7 to 10 working days, well over PLAN.md's "+1-2 days" for all of v1.

## 1. Background: the v0 process model and its residual risk

- There is no daemon. Each configured session starts its own `postern mcp --session NAME`, which loads keys from the login keychain and polls the relay. All such processes share one SQLite inbox (WAL) under `~/Library/Application Support/postern/`.
- Keychain items are created in-process, so their access lists name the postern binary. The bridge refuses items whose access list lets any application read them (`CheckOwnedACL`).
- The config is pinned with an HMAC under a keychain-held pin key. Trust changes ask for user presence through LocalAuthentication.
- Residual risk, as documented: a process running as the operator can run the `postern` binary, which the keychain trusts, and so use the bridge's identity. It can also delete the pin key and re-create it with an access list that names the binary (`security add-generic-password -T`), then write a matching pin for a config of its choice. A process running as the operator can also inject code into the non-hardened v0 binary with `DYLD_*` environment variables, which dyld honours for a plain ad-hoc signature [F22]. That is a route to the key bytes themselves.

The session guard (docs/session-guard.md) limits what the *agent in a guarded session* does with inbound content. It is not a boundary against other processes running as the operator.

## 2. Goal and threat model delta

### Attackers considered

| Id | Attacker | Examples |
|---|---|---|
| A1 | Any process running as the operator, without root | an agent with a shell tool (guarded or not), another agent framework, a malicious package install script, a compromised editor extension |
| A2 | Another local non-admin account | a separate account the operator made for untrusted agents |
| A3 | An operator-uid process that can reach root | the operator is an admin and a sudo timestamp is live in a reachable tty, sudo is `NOPASSWD`, or sudo uses Touch ID and the human approves a dialog the process triggered |
| A4 | root, or the kernel | |
| A5 | relay host, edge, network | unchanged by this design (DESIGN.md threat model) |

### What changes

| What the attacker can do | v0 (A1) | Daemon as `_postern` (A1) |
|---|---|---|
| Extract the box or TLS private key, inbox key or pin key | Yes, with effort: by injecting into the trusted binary [F22], or by getting the human to click "Always Allow" on a keychain prompt | **No.** The keys are in a keychain file only `_postern` can open [§3.4]. The client never holds them |
| Rewrite trust (peers, relay URL, sessions, keys) without the human | Yes, with effort: by forging the pin (DESIGN.md) | **No.** The config and pin key are `_postern`-owned. A change goes only through the daemon's approval handoff [§5] |
| Read the inbox (plaintext) | Yes, with effort: read the database file and extract the inbox key | **No.** The database is mode 0600, owned by `_postern` |
| Delete or corrupt the inbox, outbox, config or cursor (denial of service, or replayed rows) | Yes | **No** |
| Stop or replace the bridge process | Yes (kill it, or edit the MCP config) | It cannot stop the daemon: changing the system domain needs root [F7]. It can still edit its own sessions' MCP configs, as before |
| Use the bridge as a listed session (send, reply, read the inbox through the tools) | Yes, silently: `postern mcp --session NAME` | **Still yes**, through the genuine client [§4.4]. With attach approval on, every new connection shows a Touch ID dialog the human did not expect |
| Use a copied, rebuilt or patched postern binary | Yes, if it gets through the keychain prompt | **No.** The daemon refuses any client whose cdhash differs from its own, or that runs without the hardened runtime [§4.2] |
| Tamper with the session guard's taint markers | Yes | Yes (unchanged: the guard runs inside the agent's process tree, as the operator) |
| Read logs | metadata only | metadata only. A daemon-held audit log cannot be edited by A1 |

For A2 (another local account), v0 already keeps it out of the operator's keychain. The daemon adds that the socket refuses it twice: by file mode, and by the peer uid check.

### What it still does not protect

- **Use, as opposed to theft.** "This connection comes from the genuine postern client" is provable [F16]. "That client was started by the listed Claude Code or Codex session, on behalf of the human" is not. Anyone who can run programs as the operator can start the genuine client and type JSON-RPC into its stdin. §4.4 says exactly what can be proven.
- **The approval dialog proves approval, not intent.** This is the same as v0. An A1 process can start a genuine `postern peer add` and the dialog appears. The human must approve only changes they started.
- **A3 and A4.** Root reads every file, can run anything as `_postern`, and can replace the binary and the launchd plist. An admin operator with a sudo path that a process can reach is root. Mitigations are operational: no `NOPASSWD`, keep sudo timestamps per tty (the macOS default; unverified on every release), do not use Touch ID for sudo on machines that run agents, and do not run agents in a terminal where sudo was just used.
- **Compromise of the genuine client's process.** The design assumes the hardened runtime stops a same-uid process from injecting code (dyld environment variables: verified [F22]; debugger attach: unverified [F23]).
- **Content the human lets in.** The session guard is still the control for what a guarded agent does with a message.
- **A stolen machine** without FileVault. Disk encryption is outside this design.

## 3. Architecture

```
operator's GUI session (uid = operator)                       system domain (uid = _postern)
---------------------------------------                       ------------------------------
Claude Code / Codex session
  | MCP over stdio
  v
postern mcp --session build  ---- unix socket ---->  postern daemon run
(thin client: MCP server,       /var/db/postern-run/    keys: dedicated keychain file
 LocalAuthentication dialog)    bridge.sock (0660)      config + pin, inbox.db, audit log
                                peer uid + audit token  one poller, one outbox loop
postern peer add ... (CLI) ----> code check  ---->      relay client: HTTPS + mTLS --> edge --> relay
hooks: postern hook ...  (local only, no socket)
```

### 3.1 launchd: a system LaunchDaemon with `UserName`, not a per-user agent

- **LaunchDaemon in `/Library/LaunchDaemons/postern.bridge.plist`, with `UserName = _postern`.** `UserName` and `GroupName` apply only to jobs in the privileged system domain [F1]. Agents ignore `UserName` [F2], so a per-user LaunchAgent always runs as the logged-in user. A LaunchAgent would therefore change nothing about the threat: it is the v0 process model with a longer lifetime. A user domain for `_postern` "may exist independently of a logged-in user" [F7], but a role account never logs in. Using that domain would need extra work (bootstrapping it by hand) for no gain over the system domain.
- **Changing the system domain needs root** [F7], so an operator-uid process can neither unload the daemon nor load a fake one. `launchctl disable` state persists across boots [F8]. A disabled daemon fails closed: clients cannot connect, and nothing falls back to v0 mode (§6.5).
- **There is no GUI session in the system domain** [F3]. So the daemon cannot show LocalAuthentication, keychain or any other dialog [F33]. Every user-facing prompt has to happen in a client process (§5), and the daemon's keychain must work with user interaction disabled (§3.4).
- Plist keys (all verified as documented [F1, F2, F4, F5]):

  | Key | Value | Why |
  |---|---|---|
  | `Label` | `postern.bridge` | |
  | `ProgramArguments` | `/usr/local/libexec/postern/postern`, `daemon`, `run` | root-owned path (§6.1) |
  | `UserName` / `GroupName` | `_postern` / `_postern` | |
  | `InitGroups` | default (true) | |
  | `RunAtLoad`, `KeepAlive` | true | always on, like the relay host |
  | `Umask` | `63` (decimal for 0077) | plists have no octal [F1] |
  | `WorkingDirectory` | `/var/db/postern` | |
  | `StandardErrorPath` | `/var/log/postern/bridge.log` | launchd opens it as `UserName`/`GroupName` [F5]. Metadata-only logs, as today |
  | `ProcessType` | unset (Standard) | `Background` throttles CPU and I/O [F1]. It is probably fine for long-polls, but leave it unset until measured |
  | `SessionCreate` | unset, unless Phase 0 shows keychain access needs it [F6] | creates a new security audit session [F6]. Some older daemons needed it for keychain use (unverified) |
  | `Sockets` | not used (see §4.1) | |

- macOS shows a "background item added" notice when a launch daemon is installed, and lets the user switch it off in System Settings (unverified [F35]). Document this, so the operator recognises the notice and so a disabled daemon is easy to diagnose.
- Keep the state out of privacy-protected folders. launchd jobs are subject to TCC, and paths in protected folders "may prevent the job from running" [F36]. Everything lives under `/var/db` and `/var/log`.

### 3.2 The `_postern` account and group

- **User** `_postern`: a role account with a UID in 450-499. `sysadminctl -roleAccount` requires a name starting with `_` and a UID in that range [F9]. On the probe machine no account used that range, while Apple's own role accounts sat lower [F9]. Shell `/usr/bin/false`, home `/var/empty`, password `*` (no login), hidden. The installer creates it with `dscl . -create` [F10]. It does not use `sysadminctl`, whose usage text asks for interactive admin authentication or an admin password on the command line [F9].
- **Group** `_postern`: the user's primary group. Its only other member is the operator account (`dseditgroup -o edit -a <operator> -t user _postern` [F10]). The group exists only to let the operator reach the socket (§4.1). It grants nothing else, because every state file is mode 0600 or 0700.
- A new group membership may only take effect in processes started after the operator logs in again (unverified [F40]). The installer says so.

### 3.3 Filesystem layout

| Path | Owner:group | Mode | Contents |
|---|---|---|---|
| `/usr/local/libexec/postern/` | root:wheel | 0755 | install dir; every parent is root-owned and not group- or world-writable (checked) [F32] |
| `/usr/local/libexec/postern/postern` | root:wheel | 0755 | the one binary: daemon, client and CLI. Ad-hoc signed with the hardened runtime (§7) |
| `/usr/local/bin/postern` | root:wheel | symlink | -> the libexec binary. MCP configs and hooks keep using this path |
| `/Library/LaunchDaemons/postern.bridge.plist` | root:wheel | 0644 | the launchd job |
| `/var/db/postern/` | _postern:_postern | 0700 | daemon state |
| `/var/db/postern/bridge.keychain-db` | _postern:_postern | 0600 | dedicated keychain (§3.4) |
| `/var/db/postern/config.json` | _postern:_postern | 0600 | config. Pinned as today, with the pin key in the dedicated keychain |
| `/var/db/postern/inbox.db` (+ `-wal`, `-shm`) | _postern:_postern | 0600 | inbox and outbox, sealed at rest as today |
| `/var/db/postern/audit.jsonl` | _postern:_postern | 0600 | the v1 audit log (metadata only). The operator reads it through `postern audit` |
| `/var/db/postern-run/` | _postern:_postern | 0750 | socket directory. The group can traverse it but not create files in it |
| `/var/db/postern-run/bridge.sock` | _postern:_postern | 0660 | the socket (§4.1) |
| `/var/log/postern/` | _postern:_postern | 0750 | daemon log |

The socket path is 31 bytes, well under the 104-byte `sun_path` limit [F14].

### 3.4 Where the keys live

The design rule stands: keys live only in the OS keychain (or hardware), never in plain files, env vars or logs. The question is which keychain a daemon user can actually use without a GUI session.

| Option | What happens for a `_postern` daemon | Verdict |
|---|---|---|
| K1. `_postern`'s login keychain | A role account never logs in, so nothing creates or unlocks a login keychain for it. A keychain the daemon creates and unlocks with its own password is just K3 under a misleading name | No |
| K2. The System keychain (`/Library/Keychains/System.keychain`) | The file is root:wheel 0644, and its unlock key `/var/db/SystemKey` is root-only 0400 [F31]. Writing needs root (inferred from the file mode). Item access lists are per application, not per user, so any uid running a trusted binary could read an item (unverified [F31]). The operator can run the postern binary, so the key's safety would rest only on code behaviour | Not for the keys. Used only to hold K3's unlock secret, below |
| K3. A dedicated file-based keychain owned by `_postern` | Created by the daemon with `SecKeychainCreate` and unlocked with `SecKeychainUnlock`. Every item call passes the keychain explicitly (`kSecUseKeychain` to add, `kSecMatchSearchList` to query), so the search list and default keychain never matter [F25, F27]. Interaction is disabled (`SecKeychainSetUserInteractionAllowed(false)`), so an access check that would need a dialog fails instead of hanging (expected, unverified [F30]). The file is 0600 inside a 0700 directory, so the uid boundary applies before the keychain does | **Yes** |
| K4. The data protection keychain | Needs a login keybag. A daemon user has none (unverified [F29]). Access groups need entitlements (see alternative (b)) | No |

The APIs K3 needs (`SecKeychainCreate`, `SecKeychainOpen`, `SecKeychainUnlock`, `SecKeychainSetSettings`, `SecKeychainSetUserInteractionAllowed`, `SecAccessCreate`, `SecTrustedApplicationCreateFromPath`) are in the macOS 26.5 SDK but deprecated since 10.10 [F25]. v0 already depends on deprecated `SecKeychainItem`/`SecAccess` calls for its ACL check. That is an accepted, tracked risk: if Apple removes them, the fallback is (b) or hardware keys.

**K3's unlock secret.** K3 needs a password. Options:

1. **Recommended, if Phase 0 confirms it:** a random 32-byte password, kept as one generic-password item in the System keychain. `sudo postern daemon install` creates it in-process as root, with an access list that trusts only the installed binary. The daemon reads it at start-up. Only the `daemon run` code path reads it, and that path refuses to run unless `getuid()` is `_postern`'s uid and its parent is launchd (pid 1). An operator who runs the same binary cannot reach it. This layers a code check (the System keychain access list) on top of the uid check (K3's file mode). Two points are unverified: that a non-root process can read a System keychain item whose access list names it, without any dialog, and that the partition list does not get in the way [F31]. Phase 0 tests both. Upgrades must re-bless the item (§6.2).
2. **Fallback, if (1) does not work:** the password sits in a `_postern`-owned 0400 file next to the keychain. Be honest about what that means. Against A1 and A2 the protection is identical, because the uid boundary is what stops them. Against offline copies (backups, disk images) the keychain then adds nothing, and protection rests on FileVault and on backup handling. This bends the "never in files" rule in letter, so it needs the human's sign-off (open question 2).

**Item access lists inside K3.** Items in K3 are created in-process by the daemon. With an ad-hoc signature, the trusted-application entry is the cdhash [F20], so after an upgrade the new binary would need a dialog that cannot appear [F33]. The SDK has no public call to rewrite an item's access with the keychain password [F26]. So K3 items get an access list with no application restriction, and the boundary is the file mode plus the keychain password. The v0 `CheckOwnedACL` test ("refuse items any application can read") does not apply to this store. It is replaced by checks at start-up that `/var/db/postern` is 0700, the keychain file 0600, both owned by `_postern`, and that no ancestor directory is writable by anyone but root. With Developer ID signing (§7), items could trust a stable designated requirement instead.

Items stored in K3 are the same as today: `box-private-key`, `tls-private-key`, `tls-certificate`, the next TLS key during rotation, `inbox-key`, `pin-key` and the config pins.

### 3.5 Inbox database

- `/var/db/postern/inbox.db`, 0600 `_postern`, still sealed at rest with the inbox key. Sealing now also protects against offline copies of the state directory.
- There is now one writer process. The cross-process machinery (WAL, BEGIN IMMEDIATE, outbox leases, id tombstones) stays as it is: it is correct for one process too, and it keeps the store package unchanged.
- "Upgrade every Postern process together" (docs/deployment.md) becomes "upgrade the daemon". Clients must match the daemon's cdhash anyway (§4.2), so a version mismatch shows up as a clear "restart this session" error, not as a schema error.

### 3.6 Relay client

- The daemon runs one poll loop and one outbox loop for the machine, replacing N poll loops. A 401/403 still keeps messages queued and re-reads the certificate from K3.
- Go's HTTP client uses proxy settings from the environment, not per-user system settings. The daemon's environment comes from the plist, so if a proxy is ever needed it is set there. Today there is none.
- `RelayCAFile` (dev and tests only) must be readable by `_postern`. The daemon refuses a CA file that is writable by anyone but root or `_postern`.
- `postern edge-check` becomes a daemon request, since only the daemon holds the certificate.

### 3.7 What stays in the operator's processes

- `postern mcp --session NAME` stays an MCP stdio server, so the Claude Code and Codex configs do not change. It holds no keys, opens no files under `/var/db/postern`, and forwards the four tools to the daemon.
- The session guard hooks (`postern hook ...`) never touch the socket. Their markers stay in the operator's config directory. Moving taint into the daemon is a possible later step (Phase 4). It would stop A1 from simply deleting marker files, but A1 could still feed the genuine hook binary a fake clear event, so the gain is small.

## 4. Session to daemon channel

### 4.1 The socket

- **The daemon binds the socket itself**, at `/var/db/postern-run/bridge.sock`. It does not use launchd's `Sockets` key. With launchd activation, launchd (root) calls `listen()`, so a client checking the server's peer credentials would see root, not `_postern` [F11, F12]. A daemon-bound socket lets the client require that the listener is `_postern`. The daemon sets its umask before `bind()` so the socket comes out 0660, then checks the result.
- **File permissions are enforced on connect.** `connect()` needs write permission on the socket file [F13]. A probe confirmed it: a mode 0000 socket refused its own owner with `EACCES`, and 0600 accepted [F13]. With 0660 `_postern:_postern` inside a 0750 directory, only root, `_postern` and members of group `_postern` (the operator) can connect. A new file takes the group of its directory [F15], which the probe also showed, so the socket's group is right without a `chown`.
- **The daemon also checks the peer uid**, because permissions alone do not distinguish the operator from `_postern` or root. It reads `LOCAL_PEERCRED` (or `getpeereid`) on every accepted connection, and accepts only the operator uid recorded at install [F11, F12]. Root and `_postern` are refused too: admin commands run as root act on files directly, with the daemon stopped (§6).
- **The client checks the server.** It reads the listener's credentials (`LOCAL_PEERCRED` on the client side returns the server's credentials from `listen()` time [F12]), and requires `_postern`'s uid. It also checks that the socket and its directory are owned by `_postern` and not writable by others. A fake daemon could otherwise collect outgoing messages, or get the human to approve dialogs. The socket path is fixed. A `--socket` flag exists only in test builds.

### 4.2 Authenticating the calling process

On accept, before reading a single request byte:

1. `getsockopt(fd, SOL_LOCAL, LOCAL_PEERTOKEN, &token)` gives the connecting process's audit token [F12]. The credentials are the ones the client had when it called `connect()` [F11, F18].
2. `SecCodeCopyGuestWithAttributes(NULL, {kSecGuestAttributeAudit: token})` gives a `SecCodeRef` for that exact process. The audit token carries the pid version, so pid reuse cannot fool it [F38]. Probe: a client that connected and then `exec`ed another program failed with `errSecCSNoSuchCode` (-67065). One that had already exited failed too [F17].
3. `SecCodeCheckValidity(code, kSecCSDefaultFlags, req)` with `req = cdhash H"<daemon's own cdhash>"`. The daemon gets its own cdhash once at start (`SecCodeCopySelf`, `kSecCodeInfoUnique`). Probe: the matching binary passed; the same binary checked against another cdhash failed with `errSecCSReqFailed` (-67050) [F16]. The lookup also works when the checker is a different uid (verified for lookup by pid; by audit token, unverified [F24]).
4. `SecCodeCopySigningInformation(code, kSecCSSigningInformation | kSecCSDynamicInformation)`: require the hardened-runtime flag (`kSecCodeSignatureRuntime`, 0x10000) in the static flags. Require no `com.apple.security.get-task-allow` entitlement. Require that the dynamic status shows the process valid and not debugged (`CS_VALID` set, `CS_DEBUGGED` clear; these are xnu constants from `cs_blobs.h`, which is not in the public SDK [F22]).
5. Repeat step 2 and 3 just before applying any trust change (§5). This catches a client that `exec`ed after connecting [F17].

Sketch (the probe's server, in C; the Go version is cgo in `internal/secrets` or a new `internal/peer` package):

```c
audit_token_t tok; socklen_t l = sizeof tok;
getsockopt(c, SOL_LOCAL, LOCAL_PEERTOKEN, &tok, &l);
CFDataRef td = CFDataCreate(NULL, (const UInt8 *)&tok, sizeof tok);
CFDictionaryRef attrs = /* { kSecGuestAttributeAudit: td } */;
SecCodeRef code; SecCodeCopyGuestWithAttributes(NULL, attrs, kSecCSDefaultFlags, &code);
SecRequirementRef req; SecRequirementCreateWithString(CFSTR("cdhash H\"...\""), kSecCSDefaultFlags, &req);
OSStatus st = SecCodeCheckValidity(code, kSecCSDefaultFlags, req);   /* 0, or -67050 */
```

### 4.3 What the code check proves, and what it does not

It proves: the process at the other end is running exactly the binary the admin installed, it was not started with injected libraries (hardened runtime: dyld ignores `DYLD_*` variables [F22]), it is not being debugged (if [F23] holds), and it has not been replaced by `exec` since it connected [F17].

It does not prove who is driving that process. The genuine client is a pipe: it forwards whatever MCP requests arrive on its stdin. Any operator-uid process can start it.

So the code check matters for two things:

- **The approval handoff.** Only genuine code can submit an approval, and genuine code always runs the LocalAuthentication dialog first (§5).
- **No raw access.** Nothing but the genuine client speaks the daemon protocol, and the daemon frames inbound content itself before it leaves (§4.6). There is no unframed path for a shell to scrape, unlike v0's `postern mcp` piped from a shell.

### 4.4 Proving a session is a listed session

What the daemon can know about a connecting client:

| Claim | Provable? | How / why not |
|---|---|---|
| The caller runs as the operator | **Yes** | peer uid [F11] |
| The caller is the genuine, unmodified postern binary | **Yes** (given [F23]) | audit token and cdhash [F16, F17, F22] |
| The caller says it is session `build` | It *claims* so | the `--session` argument, as in v0 |
| The caller was started by a Claude Code or Codex process | **Weak** | Parent pid via `proc_pidinfo`, and the parent's signature by pid. This is racy: the parent can exit and the pid be reused (there is no audit token for the parent). And an attacker can start a real `claude -p` or `codex exec` with an MCP config of its own. A speed bump at most |
| That agent process is the listed session the human configured | **No** | Nothing binds a Claude Code session to a postern session name except a config file the operator, and so A1, can write |
| A human wants this session connected now | **Yes**, with attach approval | a LocalAuthentication dialog in the genuine client, handed off as in §5 |

Options:

- **Session names only (v0 behaviour).** Any operator-uid process that knows a listed name can connect as that session.
- **Per-session capability tokens.** At `postern session add`, the daemon mints a 32-byte random token and stores only its hash. The client must present the token in `hello`. The token has to reach the MCP client, so it sits in a place the operator can read: the MCP config, an env var in that config, or a login keychain item whose access list trusts the client binary. A1 can read any of these, or simply run the genuine client, which reads it for them. Tokens add per-session revocation and stop one session from claiming to be another *by accident*. Against A1 they add almost nothing, and they put a long-lived secret in agent-readable files, which the repo rules discourage. **Not recommended for v1.**
- **Attach approval (recommended, policy `attach: presence`).** When a client sends `hello{session}`, the daemon starts an approval exchange (§5) with the summary "Connect agent session `build` (client pid 1234, parent: `claude`, pid 1200)". The genuine client shows the Touch ID or password dialog. The connection is bound to that session until it closes. The daemon refuses a second live connection for the same session unless the policy allows it. Effect: a background process that wants the bridge has to trigger a dialog the human did not expect. An injected agent that runs `postern mcp` from its shell triggers one in the middle of a session. Cost: one dialog per session start, and per MCP server restart. Residual: the human approves an attach they did not start, for example one raced against their own session start. The dialog text names the parent process to help. Policy `attach: open` keeps v0 behaviour, for operators who decide the friction is not worth it (open question 1).
- **Optional `send: presence`.** A dialog for every `send`/`reply`, with the body size in the reason. This is the strongest guard against silent exfiltration through the bridge, and the friction is high. Offer it as a per-session policy (open question 7).

### 4.5 Does the same-user problem just move?

Partly, and it becomes much smaller. "Anyone as the operator can connect" stays true for **use**: without attach approval, A1 can send and read as a listed session, through the genuine client, exactly as in v0. What moves out of A1's reach is everything that persists or spreads:

- the keys (no theft, so no impersonation from elsewhere and none that outlives a revoked certificate);
- the trust state (no pin forgery, no swapped peer key or relay URL);
- the stored inbox and outbox (no reading, planting or deleting);
- the audit log.

With attach approval, use also needs a human-visible dialog. Root and a reachable sudo remain out of scope.

### 4.6 Protocol

- Length-prefixed JSON frames, at most 64 KiB (the 32 KB body cap plus headers). A versioned `hello` comes first. Requests on a connection run in order.
- Methods: `hello`, `send`, `reply`, `check_inbox`, `mark_read`, `status`, `show`, `edge_check`, `cert_csr`, `thread_reset`, `audit_tail`, and the two approval methods `change_request` and `change_approve` (§5). Trust changes have no direct method: they always go through the approval pair.
- The daemon builds the `untrusted_content` framing, the `origin`/`trust` tags and the delimiters itself. The client cannot get an inbound body any other way.
- The daemon is now a privilege boundary that parses input from the operator's uid. So: a small hand-written decoder (not the full MCP SDK), strict size and field limits, at most 32 connections, idle timeouts, per-connection rate limits on top of the existing per-session ones, and a fuzz test for the decoder.
- Errors are as safe to show an agent as today's bridge errors (no paths, SQL, subjects or bodies).

## 5. Trust-change UX: approval in the GUI session, applied by the daemon

Trust changes (`init`, `peer add/remove`, `session add/remove`, `config pin`, `cert import` when it promotes a key, the attach approvals, and any change to daemon policy) still need Touch ID or the login password.

Ways to do it:

| Option | Works? | Notes |
|---|---|---|
| The daemon shows the dialog | **No** | no GUI session in the system domain [F3, F33] |
| The CLI shows the dialog and the daemon trusts the verified CLI (chosen) | **Yes** | security rests on the code check [§4.2] plus a single-use challenge bound to the change and to the connection |
| A GUI approver LaunchAgent in the operator's Aqua session, which the daemon asks for approvals | Yes | Same trust root (the approver's code check). It adds a second always-on component and changes nothing about forgery. Possible later, if the CLI-side flow proves awkward |
| A presence-gated signature: an `LAPersistedRight` private key [F34], registered with the daemon at install, signs the challenge after Touch ID | Maybe | The daemon would get a cryptographic proof that a presence check gated the key, not just a well-behaved client. Unverified: whether an unbundled ad-hoc CLI can use `LARightStore`, and which processes can use the right. Even if it works, an attacker using the right chooses the dialog text, so it complements the code check and does not replace it. Phase 4 |
| `LAContext` external context handed to the daemon | No | its consumer is the keychain's access-control layer, which the daemon's file keychain does not use |
| Use `sudo` for trust changes | Possible, but weaker | It is a terminal password prompt. A pty-driving agent can wait for, or ride on, a live sudo timestamp. The OS-drawn LocalAuthentication dialog is the stronger UX (DESIGN.md) |

### The handoff protocol

1. The CLI (a genuine client, checked at accept) sends `change_request{op, args}`, for example `peer.add{name, public_key, fingerprint}`.
2. The daemon validates the request exactly as v0 does (the fingerprint must match the key, names must be valid, and so on). It then builds:
   - the canonical summary text `S` (the same text v0 prints);
   - `H = SHA-256(op || canonical args || digest of the current config)`;
   - a challenge `{id: 128 random bits, H, connection, expires: now + 120 s, used: false}`.
   It returns `{id, S, reason}`.
3. The CLI prints `S` on the terminal and runs `LAContext evaluatePolicy:LAPolicyDeviceOwnerAuthentication` with the short reason. This is the existing `internal/presence` code, unchanged.
4. On success the CLI sends `change_approve{id}` on **the same connection**. On failure or cancel, it sends `change_cancel{id}`, or simply closes.
5. The daemon applies the change only if all of these hold:
   - the challenge exists, is not expired, is unused, and belongs to this connection;
   - the config digest still equals the one inside `H`, so no other change slipped in between;
   - the peer audit token still resolves to valid code with the pinned cdhash [F17].
   It then applies the change, re-pins the config, writes an audit record (op, digest, time, client pid; no secrets), marks the challenge used and replies. Any failure discards the challenge.

### Why a forged request cannot skip approval

| Attempt | Result |
|---|---|
| A non-genuine program (script, rebuilt or patched binary) connects and sends `change_request`/`change_approve` | refused at accept: cdhash or hardened-runtime check fails [F16, F22] |
| The genuine CLI, driven by A1 through a pty | the dialog appears. The human must approve. This is the same residual as v0 (approval, not intent) |
| A1 injects into the genuine client so it skips the dialog | blocked by the hardened runtime: dyld variables are ignored [F22]. Debugger attach is believed blocked (unverified [F23]). The dynamic `CS_DEBUGGED` check is a second line |
| The genuine client connects and passes its connected socket to another process (`SCM_RIGHTS`), or another process inherits it | the genuine code never does this. Go sets close-on-exec on its descriptors (unverified here [F39]). The daemon re-checks the token before applying [F17, F18] |
| An approval replayed, or sent on another connection | refused: challenges are single-use and bound to a connection |
| Request change X, get the human to approve, then apply change Y | impossible: the daemon applies only the change hashed in `H`, which it computed itself, and the terminal shows that change's summary |
| Two changes race | the second fails the config-digest check and must be requested again |
| The daemon is down or disabled | nothing applies. There is no fallback to v0 mode |

## 6. Install, upgrade, uninstall and key migration

All of these run as root via `sudo` in a terminal on the machine, never through an agent. They act on files directly, with the daemon stopped where needed. They do not use the socket.

### 6.1 `sudo postern daemon install [--operator USER]`

1. Refuse unless the effective uid is 0. The operator defaults to `SUDO_USER`/`SUDO_UID`. Refuse root, or a uid below 501, as the operator.
2. Check the source binary: arm64 or x86_64 to match the host, and a valid signature. Copy it to `/usr/local/libexec/postern/postern` (root:wheel 0755), using a temporary file and `rename`. Re-sign the installed copy ad-hoc with the hardened runtime and a fixed identifier (`codesign -s - -o runtime -i postern`; probe-verified to run [F22]), unless it already has a Developer ID signature (§7). Point the `/usr/local/bin/postern` symlink at it. Check that every directory from `/` down is root-owned and not group- or world-writable. On some machines `/usr/local/bin` is user-owned; if so, refuse or use another path (verified root-owned only on the probe machine [F32]).
3. Pick a free UID and GID in 450-499 [F9]. Create group `_postern` and user `_postern` with `dscl`. Add the operator to the group [F10]. If an account by that name exists, refuse unless it matches what an earlier install made (same ids, same shell and home).
4. Create the directories from §3.3 with exact owners and modes.
5. Generate the K3 password and store it in the System keychain, in-process, with an access list that trusts the installed binary (§3.4 option 1, or the fallback).
6. Write the plist (root:wheel 0644) and `launchctl bootstrap system /Library/LaunchDaemons/postern.bridge.plist` [F7].
7. At first start the daemon creates K3: no auto-lock and no lock on sleep (`SecKeychainSetSettings`), interaction disabled. It then waits for `init` or `migrate`.
8. Print the next steps: log out and in again for the group to take effect (if needed [F40]); then `postern daemon migrate` or `postern init`, both as the operator, in the GUI session.

### 6.2 `sudo postern daemon upgrade --from PATH`

The **installed** (old) binary runs this, so that the trusted code blesses its successor:

1. Check the new binary as in 6.1 step 2, staged in the root-owned install dir.
2. Read the K3 password from the System keychain. The old binary is trusted, so this needs no dialog (Phase 0 confirms this works as root [F31]).
3. `launchctl bootout system/postern.bridge`.
4. Rename the new binary into place. Delete the System keychain item and re-add it with an access list trusting the new binary at that path (`SecTrustedApplicationCreateFromPath` [F25]). Delete-and-add sidesteps the partition list as well (unverified [F31]).
5. Bootstrap. Wait until the daemon answers `status` on the socket, then print the new cdhash.
6. Every running agent session must restart its MCP server. Old clients now have a different cdhash and get a clear error. The inbox schema migrates inside the one daemon.

With a Developer ID signature, the designated requirement stays the same across versions, so steps 2 and 4 are not needed.

A rebuilt binary copied over the installed one by hand, without `upgrade`, fails closed: the daemon cannot read its keychain password. Clients of the new build cannot connect to a still-running old daemon. Neither silently "works".

### 6.3 `sudo postern daemon uninstall [--keep-state]`

`launchctl bootout`. Remove the plist. Delete the System keychain item. Delete `/var/db/postern`, `/var/db/postern-run` and `/var/log/postern`, unless `--keep-state`; then they are left owned by root with mode 0700. Delete user and group `_postern` (`dscl . -delete`, `dseditgroup -o delete` [F10]). Leave the binary in place. Remind the operator to revoke the client certificate at the edge if this machine is leaving the network.

### 6.4 `postern daemon migrate` (operator, GUI session): moving off the login keychain

The point of v1 is keys that no operator-uid process could ever read. Keys from the login keychain may already have been copied by an A1 process, so migration **rotates by default**:

1. Drain v0: read the inbox one last time and make sure nothing is still queued to send. v0 has no outbox status command, so `migrate` itself opens the v0 database (as the operator, read-only) and refuses while any outgoing message is queued. Then quit all agent sessions.
2. `postern daemon migrate` connects to the daemon, which is in an uninitialised state. It sends the v0 config's non-secret fields (peer name, relay URL, sessions, peers with their fingerprints, limits). The daemon builds the summary. One approval (§5) covers "initialise the daemon bridge as peer-a with these peers and sessions, and generate new keys".
3. The daemon generates a new box key, TLS key and inbox key in K3, writes and pins its config, and returns the new public key, fingerprint and CSR.
4. The operator does the normal rotation steps: issue a certificate, add its fingerprint to `relay.json`/`PEERS`, `postern cert import`. Each peer re-adds the new public key after comparing fingerprints out of band (operations.md, step 3).
5. On success, the client deletes the v0 login keychain items (box key, TLS keys, certificate, inbox key, pin key, pins) and renames the v0 config to `config.json.migrated` so v0 mode cannot start again.

Options:

- `--keep-box-key` copies the v0 box key instead, to avoid a fingerprint re-exchange. The client reads it from the login keychain (this may cause one keychain prompt for the hardened build) and sends it over the socket after the approval. It never touches disk. A warning says any earlier copy of that key stays valid.
- `--import-inbox` is **not** offered. The v0 database and its inbox key were writable and readable by the operator, so its rows could have been planted. The old file is left for the human to read in v0 mode, or to delete. Envelopes still at the relay wait up to 72 hours and are fetched by the daemon once its certificate is registered.

### 6.5 v0 mode after install

Once the daemon is installed, `postern mcp` and the CLI use only the socket. They refuse to open login keychain items or a v0 config while `/Library/LaunchDaemons/postern.bridge.plist` exists. v0 mode stays for development, for the existing tests, and for platforms without the daemon.

## 7. Code signing

**Ad-hoc (the default for an open-source build).** The Go linker already ad-hoc signs (`linker-signed`, identifier `a.out`), and the designated requirement is just the cdhash [F20]. Ad-hoc signatures can carry the hardened runtime [F22]. The identity of an ad-hoc binary is its cdhash and nothing else.

**Does the socket check need a stable identity?** No. The daemon and the client are the same installed file, so "the client's cdhash equals mine" is a complete check that needs no stored state, and an upgrade keeps it consistent by construction. **The System keychain access list does need one**, which is why ad-hoc upgrades must re-bless the item (§6.2).

**What "this is the postern binary" means for an open-source project.** Anyone can build postern, including an attacker, so "signed as postern" cannot mean "made by the project". In this design it means: **the exact bytes an admin installed with sudo on this machine.** That is the property the threat model needs, because an A1 process cannot write to the install path. Whether those bytes came from a given commit is a separate supply-chain question. Go builds with `-trimpath` were reproducible on the probe machine: two builds, one forced with `-a`, gave the same cdhash. Across machines, with a different SDK or toolchain under cgo, this is unverified [F21]. A future `postern daemon verify --commit X` could compare a local rebuild.

**Developer ID (optional, later).** It gives a stable designated requirement (identifier plus team id), keychain access lists that survive upgrades, and notarization. It is a prerequisite for alternative (b) and for `SMAppService`-style install. Costs: a paid developer account, a signing key in CI (it must live in the CI's secret store, never in the repo), and the requirement "built by the project's team". Self-builders cannot meet that requirement, so they would stay on the ad-hoc path. If the project ships signed releases, the daemon's client check can accept "same cdhash as me" or "same team and identifier as me". Never accept the team alone: that trusts every binary the team ever signs.

## 8. Alternatives considered

### (a) Separate user plus LaunchDaemon (this design)

- **Pros:** a real kernel boundary (uid) for keys, trust state and stored messages. It works with ad-hoc builds. It is opt-in, and v0 mode remains. One poller per machine instead of N. The audit log gets a home A1 cannot edit.
- **Cons:** needs sudo to install and upgrade, a role account, a launchd job, deprecated keychain APIs [F25], and a new privilege boundary to harden (the socket protocol). Moderate effort. It adds a "service" to machines that wanted "just one binary".
- **Residual:** A1 can use the bridge as a listed session (narrowed by attach approval). The human can approve a change they did not start. A3 and A4 are out of scope.

### (b) Same user, keys in the data protection keychain with an access group

- **Pros:** no new account or daemon. Items in an access group are readable only by binaries whose entitlements carry that group, so other operator-uid binaries, including an attacker's rebuild, cannot read or write them. That closes key theft and pin forgery.
- **Cons:** needs a Developer ID-signed, notarized binary with a `keychain-access-groups` entitlement. On macOS that entitlement probably needs a provisioning profile (unverified). Self-builders of an open-source repo cannot get it. The config file and inbox database stay operator-writable (tampering, deletion, denial of service), unless they too move into keychain-protected storage. A read-only query from an unentitled binary returned "not found", not an entitlement error [F28], so add semantics need testing.
- **Residual:** A1 can still **use** the identity by running the genuine signed binary (the same as (a) without attach approval). A1 can still delete or corrupt local state.

### (c) Hardware-bound keys with per-use user presence

- **Pros:** keys cannot be extracted at all, even by root. Per-use presence makes silent use impossible.
- **Cons:** the Secure Enclave does only P-256. The box layer is X25519 (NaCl), so this is a protocol change, or it needs an external token that supports X25519 (unverified). Presence on every decrypt makes unattended receiving impossible: every poll result would need Touch ID. Presence on send only is plausible, and is what `send: presence` in (a) offers, without new hardware. The TLS key on a token needs a crypto.Signer bridge for each handshake.
- **Residual:** use while presence is being granted. A1 can trigger prompts with text it chooses. Without (a), the trust state is still forgeable. Best as a later layer on top of (a) (DESIGN.md's v1 hardware-key option).

### (d) Run the bridge in a lightweight VM or container

- **Pros:** a strong isolation boundary in principle.
- **Cons:** no macOS keychain, so keys would sit in files on a VM disk image. That image is a file owned by whoever runs the VM: the operator, unless the VM runs as another user, which brings back (a) with more parts. No Touch ID or LocalAuthentication inside the VM, so approvals need a host helper and the same handoff problem. The socket would cross vsock or a shared directory. It contradicts the repo rule "bridges are native binaries, never containers".
- **Residual:** whatever the host user can do to the VM image and its control socket. **Rejected.**

### (e) Leave it documented

- **Pros:** no effort. The session guard already makes a guarded session ask before shell commands while tainted.
- **Cons:** the risk stays as written in DESIGN.md: identity use, pin forgery, key extraction through injection (until the binary is hardened [F22]).
- **Residual:** unchanged. Two cheap improvements are worth doing either way: (1) sign with the hardened runtime in `make build`, and add a check to `postern version`/`edge-check`; (2) document running other, unguarded agents under a separate macOS account, so they are A2, not A1.

### (f) Inverse: run the agents under a separate user, keep the bridge as the operator

Not a substitute: the listed sessions themselves need the bridge, so they would reach it across a uid boundary. That is (a) with the roles named differently. Running *other* agents under their own account is good practice in every option, and docs should say so.

## 9. Recommendation

Build (a), in the phases below:

- ad-hoc signing with the hardened runtime, and a cdhash-equals-self client check;
- K3 for keys, with the System keychain holding the unlock secret if Phase 0 confirms it works;
- the CLI-side LocalAuthentication handoff with single-use, connection-bound, change-bound challenges;
- `attach: presence` on by default (pending open question 1);
- migration that rotates keys by default and does not import the old inbox.

Ship the hardened-runtime signing for v0 builds now, independently. Keep (b) and Developer ID as an optional later track for signed releases, and (c) as a later layer.

## 10. Phased plan and effort

| Phase | Content | Effort |
|---|---|---|
| 0. Feasibility, on a disposable macOS VM (it needs sudo, a role user and launchd) | Confirm every **unverified** fact the design depends on: K3 create, unlock and read as `_postern` under launchd with no GUI session and interaction disabled, across sleep and reboot [F30]; `_postern` reads a System keychain item that trusts it, with no dialog, and a replaced binary fails closed; old-blesses-new upgrade [F31]; audit-token code lookup from `_postern` of an operator process [F24]; LocalAuthentication from a hardened ad-hoc client [F37]; debugger attach to a hardened client refused [F23]; group membership timing [F40]; the background-items notice [F35]; whether `SessionCreate` is needed [F6] | 1-1.5 days |
| 0b. Quick win, independent | hardened-runtime ad-hoc signing in `make build`; `postern version` reports the signature flags; docs | 0.5 day |
| 1. Daemon core | `postern daemon run` (uid and launchd gate); socket server with peer uid, audit-token and code checks; framed protocol; `postern mcp` as a thin client; daemon-side framing; status, show, edge-check; configurable socket and state dir for tests | 2-3 days |
| 2. Keys and trust | K3-backed `secrets.Store`; System keychain unlock secret; config and pin in the state dir; the approval handoff for every trust change; `cert csr`/`import`, thread reset and audit log through the daemon | 2-3 days |
| 3. Lifecycle and policy | `daemon install/upgrade/uninstall/migrate`; attach approval; the v0-mode lockout; DESIGN.md, operations.md, deployment.md, session-guard.md and threat model updates; end-to-end runs on the VM | 2 days |
| 4. Optional | Developer ID release signing; `LAPersistedRight` approval signatures [F34]; daemon-held taint ledger; `send: presence`; `daemon verify --commit` | later |

Phases 0-3: about 7.5-10 working days.

## 11. Tests

Every security property gets a test (repo rule). Unit and integration tests run as the test user, with the daemon on a temporary socket and state directory, and with the code check pointed at a test cdhash. The tests that need a real role user run in the Phase 0 VM, as a gated suite (`POSTERN_TEST_DAEMON=1`), in the same way as today's keychain and presence tests.

Channel and peer authentication:

- A connection from a uid other than the recorded operator (including root and `_postern`) is refused before any request is read.
- A client with a different cdhash (a re-signed copy of the same binary) is refused. So is a binary without the hardened runtime, one with `get-task-allow`, and a client that `exec`s after connecting: the token check fails [F17].
- The client refuses a server whose listener uid is not `_postern`, or whose socket or directory is writable by others.
- Socket and directory modes are exact after start, and the daemon refuses to start if they are looser.
- A protocol fuzz test: frames that are oversized, truncated, have wrong types, or arrive before `hello`. No panic, a bounded allocation, and a safe error.
- Connection and rate limits hold.

Approval handoff:

- `change_approve` with an unknown id, an expired id, a used id, or on another connection: refused, nothing changed.
- A config change between request and approve: refused.
- An approval when the presence stub denies, or is unavailable: nothing changed, and the challenge is discarded.
- No code path applies a trust change without a used challenge. A table test covers every op.
- Attach approval: a session cannot send or read before approval. A second connection for a live session is refused by default.

Keys, state and logs:

- After `migrate`, no Postern items remain in the login keychain, and the v0 config cannot start.
- A rotate-by-default migration yields new box and TLS public keys.
- The state directory and files are owned by `_postern` with the modes in §3.3. The daemon refuses to start when they are not.
- (VM) An operator-uid process gets `EACCES` on the keychain, the database and the config. It can run neither `daemon run` (uid gate) nor a copied binary against the socket.
- Daemon logs and the audit log never contain subjects, bodies, keys or session tokens (grep test, as today).
- Every existing v0 acceptance test passes in daemon mode: no plaintext at the relay, tampered envelopes dropped, the `origin`/`trust` tags, injection fixture.

Lifecycle (VM):

- Install from scratch, upgrade (old blesses new), a hand-copied binary fails closed, uninstall removes the account, group, plist, keychain item and state.
- The daemon survives reboot and sleep with the keychain still usable.
- A disabled daemon makes clients fail with a clear error and no fallback.

## 12. Open questions for the human

1. **Attach approval by default?** It means one Touch ID or password dialog per agent session start, and per MCP server restart. Without it, an operator-uid process can still use the bridge silently (but not steal from it or rewrite it).
2. **If the System keychain cannot hold the unlock secret for a non-root daemon (Phase 0),** is a `_postern`-only 0400 password file acceptable? Against other processes the protection is the same; against offline copies it is weaker. Or should that case wait for Developer ID?
3. **Developer ID signing for releases:** worth the account, CI signing-secret handling and notarization for a public repo? It is required for alternative (b) and for upgrades without re-blessing.
4. **One binary or two?** A separate daemon binary, executable only by root and `_postern`, would mean the operator cannot even start the daemon code path. It costs a second group and install complexity.
5. **Migration default:** rotate both keys, which means peers re-compare fingerprints out of band, or keep the box key?
6. **Some deployments want "one binary, no services" on a machine.** Is a LaunchDaemon plus a role account acceptable there, or does that machine stay on v0 mode plus (e)?
7. **`send: presence`** (a dialog per outgoing message) as an available policy, and for which sessions?
8. **Should `thread reset` become an approved change** in daemon mode? Today it needs no approval.
9. **Admin operators:** should install refuse, or warn, when the operator is an admin with Touch ID enabled for sudo, since an A1 process could then trigger a root dialog?

## Fact register

How things were checked: man pages and `sysadminctl` usage on macOS 26.5.1 (build 25F80); SDK headers from the macOS 26.5 SDK (Security.framework, LocalAuthentication.framework, `sys/un.h`); and throwaway C and Go probes run as an ordinary user, in a scratch directory, without sudo, without new accounts and without keychain writes. Nothing was installed and no system setting was changed.

| Id | Fact | Status |
|---|---|---|
| F1 | `UserName` and `GroupName` apply only to services in the privileged system domain. `GroupName` defaults to the user's primary group. `Umask` takes decimal (no octal in plists). `ProcessType` unset means light throttling and `Background` throttles more | verified: `man launchd.plist` |
| F2 | `InitGroups` defaults to true and is ignored without `UserName`. Agents ignore `UserName` | verified: `man launchd.plist` |
| F3 | `LimitLoadToSessionType` applies only to agents: "There are no distinct sessions in the privileged system context" | verified: `man launchd.plist` |
| F4 | The `Sockets` key supports `SockPathName`, `SockPathOwner`, `SockPathGroup` and `SockPathMode`. The job checks in with `launch_activate_socket` | verified: `man launchd.plist` |
| F5 | `StandardErrorPath`/`StandardOutPath` files are created owned by `UserName`/`GroupName`, with the job's umask | verified: `man launchd.plist` |
| F6 | `SessionCreate` spawns the job in a new security audit session. Whether keychain use needs it | key documented: `man launchd.plist`. Effect on keychain use: **unverified** |
| F7 | Anyone may read the system domain; modifying it needs root. `gui/<uid>` and login domains exist for GUI logins. A `user/<uid>` domain may exist without a login | verified: `man launchctl` |
| F8 | `launchctl enable`/`disable` state persists across boots | verified: `man launchctl` |
| F9 | Role accounts need a name starting with `_` and a UID in 450-499. `sysadminctl -addUser` asks for interactive admin authentication or `-adminUser`/`-adminPassword`. On the probe machine no account used 450-499 (Apple's role accounts are lower) | verified: `sysadminctl` usage text; `dscl . -list /Users UniqueID` |
| F10 | `dscl . -create` sets user attributes such as `UserShell /usr/bin/false`. `dseditgroup -o create` / `-o edit -a USER -t user` / `-o delete` manage groups | verified: `man dscl`, `man dseditgroup` |
| F11 | `getpeereid` returns the peer's effective uid and gid "at the time it called connect(2)". It is reliable; the peer cannot influence it | verified: `man getpeereid` |
| F12 | `LOCAL_PEERCRED` (`struct xucred`), `LOCAL_PEERPID`, `LOCAL_PEEREPID`, `LOCAL_PEERUUID`, `LOCAL_PEEREUUID` and `LOCAL_PEERTOKEN` exist. The client side gets the server's credentials from `listen()` time. All returned consistent values for a test client (the token's pid matched `LOCAL_PEERPID`) | verified: `man 4 unix`, `sys/un.h`, probe |
| F13 | `connect()` to a unix socket needs write permission on the socket file. A mode 0000 socket refused its own owner with `EACCES`; 0600 accepted | verified: `man 4 unix`, probe |
| F14 | `sun_path` is 104 bytes. A longer path is silently truncated by careless code (it happened in the probe) | verified: `man 4 unix`, probe |
| F15 | A new file gets the group of its directory. The probe's socket file had the directory's group, not the process's egid | verified: `man 2 open`, probe |
| F16 | `SecCodeCopyGuestWithAttributes` with `kSecGuestAttributeAudit` resolves the connecting process. `SecCodeCheckValidity` with `cdhash H"<its hash>"` returns 0. With another cdhash it returns -67050 (`errSecCSReqFailed`) | verified: SDK `SecCode.h`/`CSCommon.h`, probe |
| F17 | If the client `exec`s another program after connecting, the lookup by the saved audit token fails with -67065 (`errSecCSNoSuchCode`). If the client has exited, the lookup fails | verified: probe |
| F18 | A connected descriptor passed with `SCM_RIGHTS`, or inherited, keeps the connector's credentials. The daemon sees the original connector | credentials at connect time: verified (`man 4 unix`). The consequence for passed descriptors is inference, **unverified** by probe |
| F19 | An Apple platform binary connecting to the socket (`nc -U`) resolved through its audit token with designated requirement `identifier "com.apple.nc" and anchor apple`. So the same check can tell an Apple tool from the postern client | verified: probe |
| F20 | Go 1.26 linker output is ad-hoc `linker-signed`, identifier `a.out`, no team id, and its designated requirement is `cdhash H"..."` | verified: probe (`codesign -dvvv`, `codesign -d -r-`) |
| F21 | Two `go build -trimpath` builds of postern on one machine (one with `-a`) gave the same cdhash. Reproducibility across machines and toolchains (cgo, SDK) | same machine: verified, probe. Across machines: **unverified** |
| F22 | `codesign -s - -o runtime` gives flags `0x10002 (adhoc,runtime)`. The re-signed postern binary runs. dyld ignored `DYLD_PRINT_LIBRARIES` for the hardened copy and honoured it for the plain ad-hoc copy. The hardened client's dynamic status had the runtime bit set and the debugged bit clear. `CS_*` names come from xnu's `cs_blobs.h`, which is not in the public SDK | verified: probe. That `DYLD_INSERT_LIBRARIES` is likewise ignored is inference, **unverified** directly |
| F23 | The hardened runtime without `get-task-allow` stops same-uid debuggers (`task_for_pid`) from attaching | **unverified** (Apple documentation, from memory) |
| F24 | Code-identity lookup works across uids: an ordinary user resolved and validated a root daemon's code by pid. Lookup by audit token from a different uid | by pid: verified, probe (`codesign -dvvv PID`, `codesign -v PID`). By audit token: **unverified** (same kernel interface) |
| F25 | `SecKeychainCreate/Open/Unlock/SetSettings/SetUserInteractionAllowed`, `SecAccessCreate`, `SecTrustedApplicationCreateFromPath` and `SecKeychainItemSetAccess` are in the SDK but deprecated since 10.10. `kSecUseKeychain` and `kSecMatchSearchList` exist (macOS only) | verified: SDK headers |
| F26 | The SDK has no public `SecKeychainItemSetAccessWithPassword`. `security set-generic-password-partition-list` exists and needs the keychain password | verified: SDK header grep, `man security` |
| F27 | `security create-keychain` adds keychains to the search list | verified: `man security` |
| F28 | `kSecAttrAccessGroup` applies on macOS only with the data protection keychain (or synchronizable items). A read-only query from an unentitled ad-hoc binary returned -25300 (not found), not an entitlement error. Whether `SecItemAdd` works without `keychain-access-groups`, and whether that entitlement needs a provisioning profile | header text and query result: verified (SDK `SecItem.h`, probe). Add semantics and profile: **unverified** |
| F29 | The data protection keychain is unavailable to a user that never logs in | **unverified** |
| F30 | A file keychain created and unlocked by a launchd daemon with no GUI session stays usable. With interaction disabled, an access check that would need a dialog returns an error instead of prompting | **unverified** (common practice on headless build machines) |
| F31 | `/Library/Keychains/System.keychain` is root:wheel 0644 and `/var/db/SystemKey` is root:wheel 0400. A non-root process can read a System keychain item whose access list names it, with no dialog. Partition lists do not block a delete-and-re-add by root | file modes: verified (`ls -l`). The rest: **unverified** |
| F32 | On the probe machine (fresh macOS 26.5, Apple silicon), `/usr/local/bin`, `/usr/local/libexec` and `/Library/LaunchDaemons` are root:wheel 0755 and `/var/run` is root:daemon 0775. Other machines (for example older package-manager setups that chown `/usr/local/bin`) | probe machine: verified (`ls -ld`). In general: **unverified**, so the installer checks |
| F33 | A system-domain daemon cannot show LocalAuthentication or keychain dialogs | inference from F3 and F7, and v0's refusal without a GUI session; **unverified** directly |
| F34 | `LAPersistedRight`, `LARightStore` and `LAPrivateKey` (macOS 13+) give an authorization-gated private key with `signData`. Usable from an unbundled ad-hoc CLI, and its scoping across processes | API: verified (SDK headers). Usability and scoping: **unverified** |
| F35 | macOS shows a background-item notice when a launch daemon is added and lets the user disable it in System Settings | `AssociatedBundleIdentifiers` and the Login Items UI: verified (`man launchd.plist`). The notice and toggle for a plist installed by hand: **unverified** |
| F36 | launchd jobs are subject to privacy protections. Paths in protected folders may stop a job from running | verified: `man launchd.plist` (CAVEATS) |
| F37 | LocalAuthentication and login keychain access work from a hardened-runtime ad-hoc binary with no entitlements | **unverified** |
| F38 | The audit token includes a pid version, so a reused pid does not match an old token. That `exec` also changes it is inferred from F17 | pid version field: verified (`audit_token_to_pidversion` in the probe). The `exec` behaviour: inferred from probe F17 |
| F39 | Go sets close-on-exec on the descriptors it opens | Go behaviour, **unverified** here |
| F40 | A new group membership reaches processes that were already running | **unverified** |
