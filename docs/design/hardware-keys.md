# Hardware-bound keys: feasibility and design

Status: proposal, for review. No code changes yet.
Scope: the v1 PLAN item "hardware-bound keys option" and the DESIGN.md note "v1 option: hardware-bound keys via `age-plugin-se` (Secure Enclave) or `age-plugin-yubikey`".

## Summary

The v1 goal is that the bridge's private keys cannot be copied off the machine, even by someone with full access to the machine as the user: Secure Enclave (SE) on a Mac, or a YubiKey.

Probes on an Apple silicon Mac with an ad-hoc signed Go binary (Go's default linker signature) show:

- **The SE works from a plain `go build` binary for non-permanent keys.** Permanent SE keys fail with `-34018` (`errSecMissingEntitlement`). An ad-hoc binary cannot claim the entitlement that permanent keys need; macOS kills it at launch. Saving the key's SE-encrypted token blob in the login keychain and re-importing it in a later process works. Import must pass the blob in the private `toid` attribute. Passing it only as key data silently creates a **new** random key.
- **Silent-downgrade trap:** with `kSecUseDataProtectionKeychain = false`, `SecKeyCreateRandomKey` ignores `kSecAttrTokenIDSecureEnclave` and returns an exportable **software** key with no error. The current keychain code sets that flag on every query. Every SE key must be checked after it is created or loaded.
- **The mTLS client key fits the SE natively.** A Go `crypto.Signer` backed by `SecKeyCreateSignature` signs a CSR and completes TLS 1.3 and TLS 1.2 client-certificate handshakes against a Go server.
- **The X25519 box key cannot live in the SE** (P-256 only). It can be wrapped at rest, or the envelope can move to P-256 so that the SE does the key agreement. The Go 1.26 stdlib has `crypto/hpke` and `crypto/ecdh.KeyExchanger`. An SE-backed `KeyExchanger` opens an HPKE message with one SE ECDH call, about 8 ms.
- **SE operations take about 7 ms each** (sign, ECDH, ECIES decrypt) against about 0.04 ms in software. That is fine for a per-message operation at Postern's message rates.
- **"Non-exportable" is not "unusable by an attacker on the machine".** A token blob read by another binary of the same user works there too. The SE stops keys leaving the machine. It does not stop a same-user process using them while it is on the machine, and it does not close the same-user pin-forging residual (DESIGN.md). Only the separate-OS-user design closes that.

**Recommendation:** two phases. **Phase 1** (about 5 to 6 days): put the mTLS client key in the SE, and wrap the box, inbox and pin keys at rest with an SE P-256 key. Use HPKE from the stdlib for the wrap, rather than Apple's ECIES; both are verified. Key storage becomes an explicit, pinned config field, with no fallback. **Phase 2** (about 5 to 7 days): envelope v2, with HPKE (DHKEM P-256) to an SE recipient key plus an SE ECDSA sender signature, replacing NaCl box. This makes the message-encryption key non-exportable too. YubiKey support comes after phase 2.

Evidence tags used below:

- **[P#]**: verified by a throwaway probe in this session (see [Probe results](#probe-results)).
- **[D]**: from vendor documentation. The URL is given in [Sources](#sources). The docs were not re-fetched in this session.
- **[U]**: unverified: inference, memory, or not testable here.

---

## 1. What we are protecting, and what hardware can and cannot buy

Current keys (DESIGN.md "Keys and secrets"; `internal/secrets`):

| Item | Type | Use | Frequency |
|---|---|---|---|
| `box-private-key` | X25519, 32 bytes | `envelope.Seal` and `Open` (NaCl box, static-static) | per send, per resend, per received message |
| `tls-private-key` (+ `-next` during rotation) | P-256, PKCS#8 | mTLS client authentication to the edge | per TLS handshake (new connection) |
| `inbox-key` | 32 random bytes | root of the secretbox and tag keys for the local inbox | derived once at start, then per row in memory |
| `pin-key` (service `postern-pin`) | 32 random bytes | HMAC-SHA256 config pin | at every start, and when pinning |

All four are generic-password items in the login keychain, created in-process so that the item's access list names the postern binary.

What an SE key gives, with evidence:

| Property | SE key | Today (login keychain) |
|---|---|---|
| Private key bits can be read out | No. `SecKeyCopyExternalRepresentation` returns `-4` [P3] | Yes, by the postern binary, or by anyone with the keychain file and the login password |
| Copy of the keychain file, a backup or a disk image is enough off-machine | No. The blob works only with this SE [D] (cross-machine use not testable here [U]) | Yes, with the login password |
| Any same-user process holding the blob can use the key on this machine | **Yes.** A second binary with a different code hash imported the blob and signed [P10] | Yes, by running the postern binary |
| Blob bound to the creating binary | **No** [P10]. Only the login-keychain access list on the blob item protects it, as today | n/a |
| Key usable after the machine is gone (logic board, SE reset, erase) | No [D] | Yes, if the keychain was backed up |

So the SE closes **theft and extraction**: copying keys off the machine, keychain backups, memory dumps of the mTLS key. It does not close **online misuse by a same-user process**. That is the same-user residual DESIGN.md already documents. It needs the v1 separate-OS-user bridge (and hardened runtime, section 9). Hardware keys and the separate user are complementary, and the strongest v1 has both.

The goal statement should therefore read: *"keys cannot be copied off the machine, even with full access as the user; while on the machine they can be used only through the bridge's own access controls."*

---

## 2. Q1: the Secure Enclave from an ad-hoc signed Go CLI

### Results

The probe binary was built with `go build`: `flags=0x20002(adhoc,linker-signed)`, no team id, no entitlements [P0].

| Case | Result |
|---|---|
| Permanent SE key, `kSecUseDataProtectionKeychain` unset | **Fails**: `-34018` (`errSecMissingEntitlement`), "failed to add key to keychain: <SecKeyRef:('com.apple.setoken')>" [P1] |
| Permanent SE key, `kSecUseDataProtectionKeychain = true` | **Fails**: `-34018` [P1] |
| Permanent SE key, `kSecUseDataProtectionKeychain = false` | "Succeeds", but the key is a **software key** in the login keychain: no `toid`, exportable (97-byte external representation) [P1, P2]. The probe deleted it at once (`SecItemDelete` = 0) and confirmed nothing was left |
| Non-permanent SE key (`kSecAttrIsPermanent = false`, flag unset) | **Works**: `kSecAttrTokenID = com.apple.setoken`, 324-byte token blob, private key not exportable (`-4`) [P1, P3] |
| Non-permanent, `kSecUseDataProtectionKeychain = false` | Software key again, silently [P2] |
| Non-permanent with `.userPresence` or `.biometryCurrentSet` added to the access control | Creation works (427 and 569-byte blobs) without any dialog. The probes never used these keys [P1] |
| Ad-hoc signature that claims `keychain-access-groups` and `com.apple.application-identifier` | **Killed at launch** (exit 137, SIGKILL), so the entitlement route needs a real signing identity and provisioning profile [P13]; that this is AMFI's restricted-entitlement check is [U] |
| Ad-hoc plus hardened runtime (`codesign -s - -o runtime`) | SE create, sign and HPKE all still work [P12] |

So permanent SE keys need the data-protection keychain, and that needs `keychain-access-groups`. For a binary outside an app bundle, that means a Developer ID signature and an embedded provisioning profile [D, U for the CLI-specific packaging]. That conflicts with "build from source with `go build`". **Non-permanent keys need no entitlement.**

### The wrap pattern: store the token blob, re-import later

For an SE key, `SecKeyCopyAttributes` returns the token object data under the attribute key `"toid"` (`kSecAttrTokenOID`). That key is in Apple's private headers, not the public SDK [P0: not in the SDK 26.5 headers]. The blob is the SE-encrypted private key plus its access control. It is the same format as CryptoKit's public `SecureEnclave.P256.*.PrivateKey.dataRepresentation`. A blob made by a 10-line Swift CryptoKit program imported in the Go probe, and the public keys matched [P16].

| Step | Result |
|---|---|
| Store the 324-byte blob as a login-keychain generic password, then read it in a **new process** of the same binary | `SecItemAdd` = 0, `SecItemCopyMatching` = 0, no prompt [P8] |
| `SecKeyCreateWithData(blob, {type EC, class private, tokenID SE})`, blob passed **only as key data** | **Trap**: returns a valid **new random** SE key. Its public key differs, and 324 bytes of `0x41` or empty data also "succeed". The wrapped test secret then fails to decrypt (`-50`) [P8, P9] |
| Same call with the blob in the `"toid"` attribute (key data empty, or the blob) | **Works**: same public key, same `toid`. Decrypting the secret wrapped by the earlier process succeeds, and so does signing [P8, P9] |
| Junk blob in `"toid"` | Import fails: `-3` "corrupted objectID detected" [P9] |
| One bit flipped in the blob | Import **succeeds** lazily. The first operation fails with `-3`, domain `CryptoTokenKit` [P9] |
| Blob used by a **different binary** (different code hash) | Works: public key matches, signature verifies [P10] |

Implementation rules that follow:

1. Never set `kSecUseDataProtectionKeychain = false` on SE key creation. Set nothing, as the probe did.
2. After every create **and** every load, check that `kSecAttrTokenID == com.apple.setoken`, that `SecKeyCopyExternalRepresentation` fails, and that the public key equals the one stored next to the blob. Then do one test operation (sign a fixed digest and verify it in Go) before using the key.
3. Import only through the `"toid"` attribute. Pin the behaviour with a test that a wrong blob fails, because the key-data-only path silently makes a fresh key.
4. Relying on the private `"toid"` string is a maintenance risk (Apple could rename it) [U]. It is the C-level equivalent of a public CryptoKit API, and the probe would catch a change. The fallback is a small Swift/CryptoKit shim, which conflicts with the stdlib-first rule.

The blob item gets the same in-process access list as today's items, so only the postern binary reads it silently.

---

## 3. Q2: the X25519 box key

NaCl box is static-static X25519 plus XSalsa20-Poly1305. Both the sender's and the recipient's long-term keys enter every message, and there is no forward secrecy. The SE supports only P-256 key agreement [D]. Newer CryptoKit releases also list SE post-quantum keys, Swift only [U].

### Options

**(a) Wrap the X25519 key at rest with an SE P-256 key.** At start the bridge does one SE decrypt to unwrap, then keeps the key in memory as today.

- Both wrap mechanisms are verified:
  - Apple ECIES (`kSecKeyAlgorithmECIESEncryptionCofactorX963SHA256AESGCM` and the `...VariableIV...` variant): 32-byte secret to 113 bytes. Round trip OK, a tampered ciphertext gives `-50`, a different SE key gives `-50` [P6].
  - HPKE from the stdlib with an SE-backed `ecdh.KeyExchanger` [P14]. **Prefer HPKE**: it is RFC 9180, it lets the wrap bind context through `info` (service and item name), and it can be tested in software with a plain `crypto/ecdh` key. ECIES has no associated-data parameter in the public API [U], so it would need the name inside the plaintext.
- Protects against keychain-file or backup theft. Does **not** make the key non-exportable: it is in process memory while the bridge runs, and the postern binary (or an attacker who can get code into it) can unwrap it on this machine.
- No protocol change and no peer re-pin.

**(b) Move the envelope to P-256 with key agreement in the SE (envelope v2).**

- Stdlib only: `crypto/hpke` (Go 1.26) with `NewDHKEMPrivateKey(ecdh.KeyExchanger)`, documented as meant for "a hardware key" [P15]. The probe opened a 32 KB HPKE message with an SE-backed key exchanger: **1 SE ECDH per open**, 81 bytes of overhead with ChaCha20-Poly1305, 7.9 ms p50 including the seal [P14].
- Go's `crypto/hpke` has **base mode only**: no `auth` or `psk` API [P15]. NaCl box authenticates the sender implicitly, so v2 needs explicit sender authentication. Candidates:
  1. **HPKE base plus an ECDSA P-256 signature by the sender's SE signing key** over the canonical outer envelope, including `enc` and the ciphertext. Stdlib primitives only, and the receiver checks the signature in software before spending an SE operation. The signature is transferable: the recipient can prove to a third party that the sender sent it. Deniability is not a Postern goal [U: confirm].
  2. HPKE `mode_auth` (AuthEncap) written by hand over `crypto/ecdh` and `crypto/hkdf`, about 150 lines checked against the RFC 9180 test vectors. It costs 2 SE ECDH operations on receive and 1 on send, and it is hand-rolled crypto.
  3. A static-static P-256 "box" (SE ECDH per message, then HKDF and an AEAD). Simplest, and it mirrors today's semantics, but it invites caching the shared secret, and a cached secret defeats the SE.
  - **Pick (1).** It also adds per-message **sender forward secrecy**: an ephemeral key is used per message, so a sender's leaked key does not open its sent messages. Today, either side's key opens everything in both directions.
- Per-message cost: one SE operation per send (sign), one per resend (resealed with a fresh `ts`), and one per receive (ECDH). About 7 to 10 ms each [P7, P14]. Long-polling decrypts each message once, not per poll, so the cost scales with messages, not with time.
- Protocol impact: a new envelope version, a new peer key format, new fingerprints, relay validation (Go relay **and** Worker), and conformance cases. See section 8 for the migration.

**(c) Keep software X25519 and gate its use with user presence.**

- Presence enforced by the app (LocalAuthentication before loading the key) adds nothing against extraction. The keychain item and the login password are still enough off the machine.
- Presence enforced by hardware is only possible through an SE key, so (c) only makes sense as **(a) with `.userPresence` on the wrap key**: one Touch ID per bridge start (section 6).

### Comparison

| | (a) SE-wrapped X25519 | (b) envelope v2, HPKE P-256 + SE | (c) presence-gated software key |
|---|---|---|---|
| Key non-exportable | No (in memory while running) | **Yes** | No |
| Keychain or backup theft | Protected | Protected | Not protected (unless combined with a) |
| Same-user online misuse | Possible | Possible (but the key cannot leave) | Possible after the human unlocks |
| Forward secrecy | None (as today) | Sender-side, per message | None |
| Protocol change | None | v2 envelope, relay, Worker, conformance, peer re-pin | None |
| Per-message SE cost | None | 1 operation (~7 to 10 ms) | None |
| Start cost | 1 SE operation (~7 ms) plus import (~6 ms) | Imports only | One dialog |
| UX | Invisible (or one Touch ID per start if opted in) | Invisible | One Touch ID per start |
| Effort | Small (phase 1) | Medium (phase 2) | Small, but weak on its own |

---

## 4. Q3: the mTLS client key in the SE

Verified end to end [P11]:

- A `crypto.Signer` whose `Sign(rand, digest, opts)` maps `opts.HashFunc()` to `kSecKeyAlgorithmECDSASignatureDigestX962SHA{1,256,384,512}` and calls `SecKeyCreateSignature`. The output is DER (X9.62), which is what Go expects. A SHA-256 digest signature verifies with `ecdsa.VerifyASN1` [P4].
- `x509.CreateCertificateRequest(rand, tmpl, seSigner)` gives a valid CSR (`CheckSignature` nil, matching public key) [P11]. The CSR has the same form as today's (P-256, ECDSA with SHA-256), so the edge's CSR handling should not change [U: not tried against the real edge].
- `tls.Certificate{Certificate: [][]byte{leaf}, PrivateKey: seSigner, Leaf: leaf}` against an `httptest` server with `RequireAndVerifyClientCert`: **TLS 1.3 200 OK** (first request including the handshake, 12.6 ms) and **TLS 1.2 200 OK** (9.6 ms). The same certificate with a different key is rejected by the server ("ECDSA verification failure") [P11].
- Cost: one SE signature (~7 ms) per handshake. The bridge reuses connections for long-polls, so handshakes are rare.
- The key never exists in process memory, so `tlsutil.ClientCertificate` and `loadClientCert` take a signer instead of PKCS#8 bytes. `tlsutil.CertMatchesKey` compares against `signer.Public()`.

Rotation (`cert csr --new-key`, then `cert import`): `--new-key` makes a new SE key and stores its blob as the pending item. Promotion moves the blob. Deleting the old blob destroys the old key for good, since no other copy can exist. The weekly rotation cadence is unaffected.

---

## 5. Q4: the inbox key and the pin key

Both are symmetric and are used in software, by the secretbox per inbox row and by the HMAC at start, so they cannot be non-exportable unless every use goes through the SE.

- **Wrap both with the SE wrap key** (HPKE as in 3a, or ECIES [P6]). At start: one SE operation per wrapped item, or one for a bundle.
- **Inbox key:** at-rest protection is the right level. Its job is framing (a session that reads the database directly sees ciphertext), not secrecy against the bridge's own user. An SE operation per row (~7 ms) is possible but not worth it: `check_inbox` with 20 rows would take about 140 ms.
- **Pin key:** wrapping protects it from keychain and backup theft, but **does not close the same-user forging residual**. A same-user attacker can make its own SE key with no entitlement [P1] and swap in a new wrap-key blob, wrapped pin key and pin. The bridge cannot attest that a blob was made by postern: macOS gives no SE key attestation for this use [U]. The fix stays the separate OS user. Do not claim more in the docs.
- Keep each wrap key in the same keychain service as the items it wraps. The pin service is fixed and is read before the config is trusted, so it gets its own wrap key.

---

## 6. Q5: access control and user presence

SE key access control is set at creation: `SecAccessControlCreateWithFlags(kSecAttrAccessibleWhenUnlockedThisDeviceOnly, kSecAccessControlPrivateKeyUsage [| .userPresence | .biometryCurrentSet])`. The presence variants were created without a prompt [P1]. Using them was **not probed**, by rule, so their runtime behaviour below is [D/U].

| Key | Presence policy | Why |
|---|---|---|
| mTLS key | `.privateKeyUsage` only | Handshakes happen whenever the network reconnects (sleep, wake, overnight). Presence here would stall the poller with nobody at the machine |
| Envelope v2 recipient (ECDH) key | `.privateKeyUsage` only | Long-poll decrypts arrive unattended. Presence per message is unusable |
| Wrap key for box and inbox (phase 1) | `.privateKeyUsage` by default; **opt-in `.userPresence`** = one Touch ID or password per bridge start | Each `postern mcp` process starts with a session the human just opened, so the human is there. Wrap box and inbox into **one bundle** so a start costs one SE operation and one dialog |
| Wrap key for the pin | `.privateKeyUsage` only | Presence would add a second dialog at start and does not close the residual (section 5) |
| Envelope v2 sender signing key (phase 2) | Opt-in `.userPresence` = **hardware-enforced approval of every outgoing message** | Today the human approves `send` and `reply` through the session guard (a hook, which the model or a same-user process could get around). An SE key that needs presence makes the hardware enforce the exfiltration control. Cost: one Touch ID per send. An open question for the human |

Notes:

- Prefer `.userPresence` (Touch ID **or** the login password) over `.biometryCurrentSet`. The latter invalidates the key when enrolled fingerprints change, which means a forced re-init [D].
- A dialog triggered by an SE operation is drawn by the system, outside the terminal, which is the same property `internal/presence` relies on today [D].
- To avoid one dialog per key, evaluate one `LAContext` and pass it as `kSecUseAuthenticationContext` [D/U], or use one bundled wrap (above).
- MCP clients may time out a server that waits on a dialog at start [U: check the client startup timeouts]. The bridge should start serving tools at once and report "waiting for approval" until the unwrap finishes, rather than block the MCP handshake.
- Over SSH or headless, presence-gated keys are unusable, and the bridge refuses with no fallback, as `internal/presence` does. Whether `.privateKeyUsage`-only SE keys work in a session with no GUI login (SSH only, or a locked screen) is **[U]**. Test it before claiming headless support.

---

## 7. Q6: YubiKey (PIV)

| Route | Dependencies | Works for | Notes |
|---|---|---|---|
| macOS CryptoTokenKit PIV token (`com.apple.pivtoken`): YubiKey PIV keys show up as `SecKey`s with a token id | None beyond Security.framework | Sign (mTLS, v2 sender signature) and ECDH (v2 recipient), through the **same cgo code** as the SE | [U]: no YubiKey here. Keys must be generated on the token with vendor tooling first. The PIN dialog is drawn by the system |
| `go-piv/piv-go` | One Go module; cgo to PCSC.framework (macOS) or pcsclite (Linux) | P-256 sign and ECDH, PIN and touch policies, generation on the device, **attestation** | Breaks "stdlib first", but it is narrow and well known [D]. Attestation lets a peer verify that the other side's key was made on a YubiKey: the SE has nothing like it here [U] |
| PKCS#11 (`ykcs11`, `miekg/pkcs11`) | Vendor library installed system-wide plus cgo | Everything | No: an install step and a large surface |
| `age-plugin-yubikey` / `age-plugin-se` | External plugin binaries (Rust or Swift), age plugin protocol | age file encryption only | No: neither does mTLS or NaCl box, and `age-plugin-se` uses P-256 recipients. **Recommend dropping both from DESIGN.md** |

YubiKey firmware 5.7 is said to add X25519 and Ed25519 to PIV [U]. That could keep NaCl box on hardware: `box.Precompute` is X25519 followed by HSalsa20, so the token's X25519 output could feed `salsa.HSalsa20`. That depends on firmware and touches every message, so it is not recommended over v2.

**Verdict:** a later option (phase 3). Envelope v2 (P-256) is what makes YubiKey support cheap. The CryptoTokenKit route reuses the phase-1 code on macOS, and `piv-go` is the cross-platform route if Linux bridges arrive.

---

## 8. Q7 and Q8: no-SE machines, other platforms, recovery and migration

### Machines without an SE, and other platforms

- Apple silicon Macs and Intel Macs with a T2 chip have an SE [D]. Intel Macs without a T2, macOS virtual machines [U] and CI runners [U] do not.
- **Key storage is an explicit, pinned config field**: `key_storage: "secure-enclave" | "keychain"` (and later `"yubikey"`). It is shown in `postern show` and in the presence-confirmed summary for `init` and `config pin`.
- `postern init` defaults to `secure-enclave`. If the SE is unavailable it **fails** with a message telling the operator to choose `--key-storage keychain` explicitly. It never falls back. Detect availability by creating and checking a throwaway non-permanent key (the section 2 checks). Do not trust "no error" alone: see the downgrade trap [P2].
- At run time, if the config says `secure-enclave` the bridge refuses to start when: a blob is missing or fails its checks, a plaintext `box-private-key`, `tls-private-key` or `inbox-key` item also exists (an unfinished or reverted migration), or any SE operation fails. The error names the item and the OSStatus or CryptoTokenKit code, never a value.
- Linux has no keychain support today (`keychain_other.go` returns `ErrUnsupported`). A later Linux bridge could use a TPM 2.0 through `google/go-tpm` (pure Go, one module) [U], or a YubiKey through `piv-go`. Windows: not planned.

### Recovery: the SE dies with the machine

SE keys cannot be backed up, by design. The token blob is useless anywhere else [D], and there is deliberately no escrow. Losing the machine, replacing the logic board or erasing the SE (and possibly deleting the macOS user or reinstalling [U]) means re-initialising. Runbook:

1. On the new or reset machine: `postern init --force --key-storage secure-enclave` (presence-confirmed). This makes new SE keys, a new box public key and fingerprint, a new CSR, and new wrap and pin keys. The config is re-pinned.
2. The edge operator issues a certificate for the new CSR **and revokes the old certificate**. The relay operator replaces the peer's fingerprint in `relay.json`.
3. The peer runs `peer remove` and then `peer add` with the new public key, **after comparing fingerprints out of band**. Both steps are presence-confirmed.
4. Messages queued at the relay for the old key cannot be decrypted. The peer resends anything unacknowledged. With envelope v2 the receiver drops undecryptable envelopes after acking them, and reports a count without content.
5. The local inbox (encrypted under the lost inbox key) cannot be read. Start a new database, and keep or delete the old file.

Document this in `docs/operations.md`. With two peers it costs one out-of-band fingerprint comparison and one certificate re-issue.

### Migrating an existing bridge (`postern keys migrate --to secure-enclave`, presence-confirmed)

Phase 1:

1. Create the SE wrap keys (bridge service and pin service). Store their blobs and public keys.
2. Wrap the existing box key and inbox key (as one bundle) and the pin key. Store the wrapped items. Read them back, unwrap and compare with the originals before deleting anything.
3. Make a new SE mTLS key, using the `cert csr --new-key` pending-key path, so the current certificate keeps working until the new one is imported. The edge issues a certificate and the relay fingerprint is updated, then `cert import` promotes it.
4. Re-pin the config with `key_storage: secure-enclave`.
5. Delete the plaintext items.
6. **Recommend rotating the box key as well** (peer re-pin). The old X25519 key was born in software and may already exist in Time Machine copies of `login.keychain-db` [U, depends on backup settings]. Wrapping a key that already leaked does not un-leak it. The same goes for the inbox key: rotating it means re-encrypting the inbox, which is cheap.

Phase 2 (envelope v2):

- Peer config gains `envelope: 1 | 2` and v2 keys (recipient ECDH public key plus signing public key, one fingerprint over both). It is pinned like everything else.
- The relay (Go and Worker) accepts **both** v1 and v2 for a transition window. Conformance cases cover both, and v1 is removed in a later release.
- A bridge sends v2 only to peers pinned as v2, receives both while it still holds the X25519 key, and drops it after cut-over.
- The two peers cut over together: both run `keys migrate --envelope 2`, exchange new fingerprints out of band and re-pin. With two peers that is one call.

---

## 9. Proposed phase-1 design (for review)

New package `internal/hwkey` (`darwin && cgo`; other builds return `ErrUnsupported`). It is a small cgo surface over Security.framework, with no Objective-C needed:

```go
// Key is a P-256 private key held by the Secure Enclave (later: a PIV token).
type Key interface {
    crypto.Signer                         // ECDSA, DER, digest-based (mTLS, CSR, v2 sender signature)
    ECDH(*ecdh.PublicKey) ([]byte, error) // so *Key satisfies ecdh.KeyExchanger
    ECDHPublic() *ecdh.PublicKey
    Close()
}
func Available() error                     // creates and checks a throwaway non-permanent key
func Generate(p Policy) (blob []byte, k Key, err error) // Policy: PrivateKeyUsage | UserPresence
func Load(blob []byte, wantPub []byte) (Key, error)     // via "toid"; runs every section-2 check
```

- **Storage**: items in the existing `secrets.Store` services, created in-process as today:
  - `se-tls-key`, `se-tls-key-next`: `ver || 65-byte public key || blob`.
  - `se-wrap-key`: in each service.
  - `wrapped-runtime-keys`: an HPKE bundle of the box and inbox keys, `info = "postern wrap v1\x00" || service || "\x00" || item`.
  - `wrapped-pin-key`: in `postern-pin`.
  - The existing `CheckOwnedACL` check applies to every one of them.
- **Wrap**: `crypto/hpke` with DHKEM(P-256, HKDF-SHA256), HKDF-SHA256 and AES-256-GCM, to the SE wrap key, opened through `hwkey.Key` as the `ecdh.KeyExchanger`. Apple ECIES stays a fallback, verified in [P6].
- **TLS**: `tlsutil.ClientCertificate(certPEM, crypto.Signer)`, `CreateCSR(crypto.Signer, cn)` and `CertMatchesKey(cert, crypto.PublicKey)`. The software path wraps an `*ecdsa.PrivateKey`, which is already a `crypto.Signer`.
- **Config**: `key_storage`, validated, pinned and displayed.
- **CLI**: `init --key-storage`, `keys migrate`, `show` (prints the storage kind, and `secure-enclave (non-exportable)`).
- **Hardened runtime**: ship and document `codesign -s - -o runtime` for the installed binary. The probe shows the SE still works with it [P12]. Under hardened runtime a same-user process cannot attach a debugger or inject a dylib to read unwrapped keys from memory [D, U for the exact same-user guarantees]. This also helps the phase-1 in-memory keys.
- **Docs**: DESIGN.md keys table and threat model (the "Machine stolen" and "Agent reads bridge keys" rows), SECURITY.md, operations runbook.

---

## 10. Phased plan and effort

| Phase | Scope | Estimate |
|---|---|---|
| 0 | This spike (done): probes and this document | done |
| **1** | `internal/hwkey` (create, load, checks, signer, ECDH): 1.5 days. TLS and CSR on a signer, plus rotation: 1 day. HPKE wrap of box, inbox and pin keys, plus the bundle: 1 day. `key_storage` config, `init`, `keys migrate`, `show`, refuse-on-mismatch: 1 day. Tests and docs: 1 to 1.5 days | **5 to 6 days** |
| **2** | Envelope v2 (HPKE base plus SE ECDSA sender signature, canonical signing input, size budget): 2 days. Go relay, Worker and conformance for v1 plus v2: 1.5 days. Peer key format, fingerprints, config, migration and cut-over: 1.5 days. E2E and docs: 1 day. Optional presence-per-send: 0.5 days | **5 to 7 days** |
| 3 | YubiKey: CryptoTokenKit PIV token on macOS (reuses `hwkey`), then `piv-go` with attestation if needed | 3 to 5 days |
| 3+ | Linux TPM 2.0 or PIV, with Linux bridge support | separate plan |

The size budget for v2 is [U]: about 88 base64 bytes of `enc` plus about 96 of signature against today's margin under the 48 KB cap with a 32 KB body. Prove it with a test at the maximum body and subject.

---

## 11. Tests needed

The hardware tests run only on a machine with an SE, behind a build tag or `POSTERN_HW_TESTS=1`. CI uses a software fake of `hwkey.Key` (a `crypto/ecdh` plus `ecdsa` key), kept in a `hwkeytest` package like `secretstest`, so production code cannot select it. Every security property below has a test, per CLAUDE.md.

Phase 1:

1. `Generate` returns a key with `tokenID == com.apple.setoken` whose external representation fails (non-exportable). A test asserts the creation dictionary never contains `kSecUseDataProtectionKeychain = false` (the downgrade trap).
2. `Load` with a blob of another SE key, junk, empty or a bit-flipped blob fails (no silent new key). `Load` with a mismatched stored public key fails.
3. Round trip across processes: generate, store, then a subprocess loads, signs and unwraps.
4. TLS: a handshake with an SE signer against an `httptest` server requiring client certificates (TLS 1.2 and 1.3). The wrong key is rejected. A CSR from an SE key passes `CheckSignature`.
5. Rotation: `cert csr --new-key` makes an SE key, promotion moves the blob, and the old blob is deleted.
6. Wrap: HPKE wrap and unwrap round trip. A wrong `info` (item swapped with another item) fails, a tampered ciphertext fails, and a different wrap key fails.
7. No fallback: with `key_storage: secure-enclave`, a missing or invalid blob, a leftover plaintext item, or a fake "SE unavailable" refuses to start. `init` on a machine without an SE fails unless `--key-storage keychain` is given.
8. `key_storage` is part of the pinned config: changing it without re-pinning is refused, like any edit.
9. Logs and errors carry no key bytes, blobs or plaintext. This extends the existing no-secrets-in-logs test.
10. `keys migrate`: verify-before-delete (a failure halfway leaves the old items usable), then the plaintext items are gone.

Phase 2:

11. v2 seal and open with the SE recipient and sender. Tampering with any outer field, `enc`, the ciphertext or the signature fails. The wrong recipient fails. A signature by an unpinned key fails. A replayed envelope with a changed `ts` fails.
12. Sender forward secrecy: with the sender's keys revealed, a test cannot open a captured v2 envelope.
13. Conformance: the shared v1 and v2 cases pass in the Go relay and the Worker. A maximum-size v2 envelope fits the 48 KB cap.
14. Mixed mode: a v1 peer and a v2 peer during the transition, and v1 refused after cut-over.
15. Presence-per-send (if adopted): a hardware test run by hand, documented as such (a probe must not raise dialogs automatically).

---

## 12. Open questions for the human

1. **Goal wording.** Accept "cannot be copied off the machine" (SE) as the v1 goal, with "cannot be used by a same-user process" left to the separate-OS-user item? Or block hardware keys on the separate user?
2. **Phase 1 only, or 1 + 2?** Phase 1 makes only the mTLS key truly non-exportable. Phase 2 is a protocol change, a re-pin and relay plus Worker work.
3. **Rotate the box key during migration** (recommended: one out-of-band fingerprint call), or wrap the existing key to avoid a re-pin?
4. **Presence:** opt-in Touch ID per bridge start (wrap key)? Opt-in Touch ID per outgoing message (phase-2 signing key)? Both are hardware-enforced.
5. **Sender authentication in v2:** ECDSA signature (recommended, transferable), or hand-written HPKE auth mode (deniable, more code)?
6. **Undocumented `toid` attribute:** acceptable, with a test that catches changes? The alternative is a Developer ID-signed, provisioned build (permanent keys, documented API), which would end "build from source with `go build`".
7. **YubiKey:** is it needed at all? If so, macOS-only through CryptoTokenKit, or `piv-go` (a dependency, but cross-platform with attestation)?
8. **Headless use:** must the bridge work over SSH or with the screen locked? This needs a probe on a real headless session before phase 1 promises it.
9. **DESIGN.md:** replace the `age-plugin-se` / `age-plugin-yubikey` note with a link to this document?

---

## Probe results

Environment: Apple silicon (M1-class) Mac, macOS 26.5.1, Xcode SDK 26.5, Go 1.26.3 darwin/arm64, a logged-in GUI user, probes run from a non-interactive shell. Throwaway cgo probes (Security.framework through cgo, as in `internal/secrets`) lived in a scratch directory outside the repo.

- Every SE key was non-permanent.
- Two permanent-creation attempts failed (`-34018`). A third, the downgrade case, made a **software** key that was deleted at once; `security find-key` confirmed nothing was left.
- The one login-keychain test item was deleted (`SecItemDelete` = 0), and the scratch blob files were removed.
- No probe used a presence-gated key, and no dialog appeared.

| # | Probe | Result (exact codes) |
|---|---|---|
| P0 | `codesign -dv` on the `go build` binary | `flags=0x20002(adhoc,linker-signed)`, `TeamIdentifier=not set`, no entitlements. `kSecAttrTokenOID` is not in the public SDK headers (the build fails), so the probe used `CFSTR("toid")` |
| P1 | `SecKeyCreateRandomKey`, `kSecAttrTokenIDSecureEnclave`, `kSecAttrKeyTypeECSECPrimeRandom` 256, access control `WhenUnlockedThisDeviceOnly` + `PrivateKeyUsage` | Permanent: `-34018` (data-protection flag unset or true). Non-permanent: OK, `toid` 324 bytes. With `+userPresence`: OK, 427 bytes. With `+biometryCurrentSet`: OK, 569 bytes (created only) |
| P2 | The same with `kSecUseDataProtectionKeychain = false` | Permanent and non-permanent both "OK", but `kSecAttrTokenID` is empty, there is no `toid`, and the external representation is 97 bytes: a **software key** |
| P3 | `SecKeyCopyExternalRepresentation` on an SE key | Fails, `-4` (`NSOSStatusErrorDomain`, `errSecUnimplemented`) |
| P4 | `SecKeyCreateSignature`, `ECDSASignatureDigestX962SHA256` | 70 to 71-byte DER signature, code 0. Go `ecdsa.VerifyASN1` = true |
| P5 | `SecKeyCopyKeyExchangeResult`, `ECDHKeyExchangeStandard` | 32 bytes, code 0, equal to Go `crypto/ecdh` P-256 on the other side |
| P6 | ECIES `CofactorX963SHA256AESGCM` and `CofactorVariableIVX963SHA256AESGCM` (32-byte secret) | 113-byte ciphertext, decrypt code 0, round trip OK. Tampered: `-50`. A different SE key: `-50` |
| P7 | Latency (p50 / p95) | Create 5.8 / 21.4 ms. Re-import 6.0 / 8.6 ms. Sign 7.3 / 8.8 ms. ECDH 7.1 / 7.7 ms. ECIES decrypt (32 B) 7.0 / 8.0 ms. ECIES decrypt (32 KB) 7.1 / 8.0 ms. Software P-256 ECDH 0.045 ms. Software X25519 0.040 ms |
| P8 | Blob stored as a login-keychain generic password; a new process of the same binary reads it, re-imports, unwraps and signs | Add 0, read 0, no prompt. **Key data only: a different public key, unwrap `-50`.** Through `toid`: same public key, unwrap code 0, sign verifies |
| P9 | In-process import variants | Key data only: a fresh random key each time, and 324 bytes of junk or empty data "succeed". `toid`: same key. Junk `toid`: `-3` "corrupted objectID detected". Bit-flipped `toid`: import succeeds, then sign fails `-3` (`CryptoTokenKit`) |
| P10 | Blob written by binary A, used by binary B (different code hash) | Public key matches, sign code 0, verifies |
| P11 | Go `crypto.Signer` over the SE: CSR, then TLS against an `httptest` server with `RequireAndVerifyClientCert` | CSR 205 bytes, `CheckSignature` nil. TLS 1.3: 200 OK (12.6 ms first request). TLS 1.2: 200 OK (9.6 ms). Wrong key: rejected ("ECDSA verification failure") |
| P12 | Re-signed `codesign -s - -o runtime` | `flags=0x10002(adhoc,runtime)`. SE create, toid import, sign and HPKE all OK. Permanent still `-34018` |
| P13 | Ad-hoc signed with `keychain-access-groups` + `com.apple.application-identifier` entitlements | Process killed at launch, exit status 137 (SIGKILL) |
| P14 | `crypto/hpke` Seal and Open, DHKEM(P-256) + HKDF-SHA256 + ChaCha20-Poly1305, recipient = SE key via an `ecdh.KeyExchanger` wrapper, 32 KB plaintext | Open OK, **1 SE ECDH call**, 81 bytes of overhead. Tampered: "chacha20poly1305: message authentication failed". Seal + Open p50 7.9 ms, p95 9.5 ms |
| P15 | `go doc crypto/hpke`, `go doc crypto/ecdh.KeyExchanger` (Go 1.26.3) | `NewDHKEMPrivateKey(priv ecdh.KeyExchanger)` ("e.g. a hardware key"). Seal, Open, Sender and Recipient in base mode only; no auth or PSK API |
| P16 | Swift CryptoKit `SecureEnclave.P256.Signing.PrivateKey().dataRepresentation` (284 bytes), imported by the Go probe through `toid` | Public key matches, sign code 0, verifies: the `toid` blob **is** CryptoKit's `dataRepresentation` format |

Core calls, for reproduction (C inside cgo):

```c
// create (non-permanent; NEVER set kSecUseDataProtectionKeychain=false)
SecAccessControlRef ac = SecAccessControlCreateWithFlags(NULL,
    kSecAttrAccessibleWhenUnlockedThisDeviceOnly, kSecAccessControlPrivateKeyUsage, &err);
// attrs: kSecAttrKeyType=kSecAttrKeyTypeECSECPrimeRandom, kSecAttrKeySizeInBits=256,
//        kSecAttrTokenID=kSecAttrTokenIDSecureEnclave,
//        kSecPrivateKeyAttrs={kSecAttrIsPermanent=false, kSecAttrAccessControl=ac}
SecKeyRef k = SecKeyCreateRandomKey(attrs, &err);
CFDataRef blob = CFDictionaryGetValue(SecKeyCopyAttributes(k), CFSTR("toid"));

// re-import in a later process: the blob MUST go in the "toid" attribute
// attrs: kSecAttrKeyType=EC, kSecAttrKeyClass=kSecAttrKeyClassPrivate,
//        kSecAttrTokenID=kSecAttrTokenIDSecureEnclave, CFSTR("toid")=blob
SecKeyRef k2 = SecKeyCreateWithData(emptyData, attrs, &err);
```

## Sources

[D] references are cited from documentation and were **not re-fetched in this session**. Check them before relying on exact wording.

- Apple, Protecting keys with the Secure Enclave: https://developer.apple.com/documentation/security/protecting-keys-with-the-secure-enclave
- Apple, `kSecAttrTokenIDSecureEnclave`: https://developer.apple.com/documentation/security/ksecattrtokenidsecureenclave
- Apple, `kSecUseDataProtectionKeychain`: https://developer.apple.com/documentation/security/ksecusedataprotectionkeychain
- Apple, `errSecMissingEntitlement`: https://developer.apple.com/documentation/security/errsecmissingentitlement
- Apple, `SecAccessControlCreateFlags`: https://developer.apple.com/documentation/security/secaccesscontrolcreateflags
- Apple, `kSecUseAuthenticationContext`: https://developer.apple.com/documentation/security/ksecuseauthenticationcontext
- Apple, CryptoKit `SecureEnclave.P256.Signing.PrivateKey.dataRepresentation`: https://developer.apple.com/documentation/cryptokit/secureenclave/p256/signing/privatekey/datarepresentation
- Apple Platform Security, Secure Enclave: https://support.apple.com/guide/security/secure-enclave-sec59b0b31ff/web
- Apple, Mac computers with the Apple T2 Security Chip: https://support.apple.com/en-us/103265
- Apple, Hardened Runtime: https://developer.apple.com/documentation/security/hardened-runtime
- Go `crypto/hpke`: https://pkg.go.dev/crypto/hpke ; Go `crypto/ecdh.KeyExchanger`: https://pkg.go.dev/crypto/ecdh#KeyExchanger (also checked locally, [P15])
- RFC 9180, Hybrid Public Key Encryption: https://www.rfc-editor.org/rfc/rfc9180
- `go-piv/piv-go`: https://github.com/go-piv/piv-go
- Yubico, PIV attestation: https://developers.yubico.com/PIV/Introduction/PIV_attestation.html
- `google/go-tpm`: https://github.com/google/go-tpm
