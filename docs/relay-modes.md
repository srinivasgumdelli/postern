# Relay modes

The relay can run two ways. Both serve the same HTTP API (`POST /v1/msg`, `GET /v1/poll`, `POST /v1/ack/{id}`, `GET /healthz`) with the same status codes and error bodies, so a bridge works against either without code changes.

| | Docker + tunnel | Worker + Durable Object |
|---|---|---|
| Code | `cmd/postern-relay`, `internal/relay` (Go) | `relay-worker/` (TypeScript) |
| Runs on | an always-on host you run (Docker Compose: relay + `cloudflared`) | Cloudflare: a Worker on a custom domain plus one SQLite-backed Durable Object |
| Ciphertext at rest | SQLite on your host, no backups | Durable Object storage in your Cloudflare account |
| Availability | as good as the host; it must stay on | always on, no host |
| Identity | the edge verifies the client certificate and a transform rule forwards its fingerprint in a header (plus an edge-secret header where configured, see [edge-setup.md](edge-setup.md)); the relay trusts the header only because it is reachable solely through the tunnel | the Worker reads the edge's mTLS result from `request.cf.tlsClientAuth` itself; no header is trusted, no edge secret, no tunnel |
| You patch | host OS, Docker, the pinned `cloudflared` and relay images | `relay-worker` dev dependencies and the compatibility date; Cloudflare patches the runtime |
| Logs | `docker compose logs relay` | Workers Logs (the Worker's own lines only; invocation logs off) |
| Cost | the host you already run; the edge features used are on the Free plan | Workers Free within its limits (below), or Workers Paid from $5 a month |

In both modes content is end-to-end encrypted between bridges. The relay, the edge and the Cloudflare account see routing fields (`from`, `to`, `thread`, `ts`, `id`, sizes and timing) and ciphertext, never plaintext, and hold no key that could open or forge a message.

## What changes in the threat model

Worker mode moves ciphertext at rest from your host to Cloudflare's Durable Object storage. Someone who controls the Cloudflare account (or Cloudflare itself) can read the stored ciphertext and routing fields, delete, delay or withhold messages, and change the Worker code or `PEERS`. They still cannot read or forge messages: the box is sealed to the recipient's key, every routing field is authenticated inside it, and bridges check the sender's pinned key. A changed `PEERS` lets an attacker-issued certificate post as a peer, but the receiving bridge drops anything not sealed by that peer's pinned key.

In Docker mode the same holds for whoever controls the relay host; the Cloudflare account carries traffic but stores nothing.

Deleted rows: the Docker relay sets SQLite `secure_delete` so acked and expired ciphertext is overwritten. Durable Object SQL does not expose that pragma; how long deleted data lingers in Cloudflare's storage layer is Cloudflare's (unverified).

## Durable Object design

One Durable Object (`idFromName("relay")`) holds every mailbox. One object per mailbox was considered and rejected:

- **Seen ids must be global.** The Go relay refuses a replayed id whichever mailbox it is posted to, and checks and records the id in the same transaction as the insert. With one object per mailbox, the check would span objects and could not be atomic.
- **Cursor semantics stay identical.** Like the Go relay, one `AUTOINCREMENT` sequence numbers every envelope. Per mailbox it is strictly increasing, which is all a cursor needs, and the same code answers `after` the same way.
- **The rate limit is per sender, across recipients.** One object keeps the sender's sliding window in one place.
- **Ordering and atomicity are free.** Each post runs dedup, rate limit, queue cap and insert synchronously in one `transactionSync`, the equivalent of the Go relay's `postMu`.
- **It fits the Free plan.** A Durable Object is billed for wall-clock duration at 128 MB while a request (a long-poll) keeps it active. One object polled around the clock is 86,400 s x 0.128 GB = 11,059 GB-s a day, under the Free plan's 13,000 GB-s. Two objects polled around the clock would be about 22,118 GB-s and exceed it.
- **Load is tiny.** Two peers come nowhere near the soft limit of about 1,000 requests a second per object, and a full queue (2 x 1,000 envelopes x 48 KB, about 96 MB) is well under the 1 GB per-object storage on Free.

The cost is a single point of contention: if that object is overloaded or restarting, every mailbox waits. For two peers that is the right trade.

Long-poll: the object holds the poll in memory and resolves it when a post for that mailbox commits, or at the timeout (at most 25 s). It takes the wake-up promise before it queries, so a message committed after the query always wakes the poller. At most 16 polls per peer wait at once (429 beyond that).

Expiry: an alarm fires when the oldest envelope or seen id passes 72 hours and deletes everything past retention, then re-arms. Polls also filter out anything past retention, so a late alarm never serves an expired envelope.

Envelopes are stored re-encoded canonically (Go's `json.Marshal` form), as the Go relay does, so the recipient sees exactly what the routing columns say. `testdata/conformance/envelopes.json`, generated from real sealed envelopes by `internal/conformance`, holds the cases both implementations must agree on; both test suites run every case.

## Free-plan limits

Checked against Cloudflare's documentation on 2026-11-05. "Verified" means the docs state it; "unverified" means they did not, or not clearly. Plans change: check again before relying on them.

| Limit | Value | Status |
|---|---|---|
| Worker requests | 100,000 a day, reset at 00:00 UTC; over it, requests fail (error 1027) | verified |
| Worker CPU time | 10 ms per request (waiting on the Durable Object does not count) | verified |
| Worker duration | no hard limit while the client stays connected | verified |
| Durable Object requests | 100,000 a day | verified |
| Durable Object duration | 13,000 GB-s a day, billed at 128 MB per active object | verified |
| SQLite rows read / written | 5 million / 100,000 a day | verified |
| SQLite storage | 5 GB per account, 1 GB per object on Free | verified |
| Durable Object backend on Free | SQLite only (`new_sqlite_classes`) | verified |
| Requests per object | soft limit about 1,000 a second | verified |
| Whether Durable Object requests also count against the 100,000 Worker requests | not stated | unverified |
| WAF custom rules | 5 on Free | verified |
| Client certificates (Cloudflare-managed CA) | 100 active per zone | verified |
| mTLS with the Cloudflare-managed CA on a Free zone, and on a Worker custom domain | not stated on the client certificates page | unverified |
| WAF custom rules run before the Worker | not stated in the pages checked | unverified (the Worker checks the certificate itself, so the order does not affect security) |

Budget for one deployment: every bridge process holds one long-poll of up to 25 s, so each costs about 3,500 Worker requests and 3,500 Durable Object requests a day, plus one of each per message sent and per ack. A handful of sessions stays far inside the Free limits; the duration figure above is the one to watch.

On Workers Paid ($5 a month minimum) the included amounts are 10 million Worker requests, 1 million Durable Object requests and 400,000 GB-s of duration a month (verified), so one always-polled object (about 332,000 GB-s a month) still costs nothing extra.

## Behaviour differences from the Go relay

The API, status codes, error codes, limits and envelope rules match. These details differ, none of them on the path a bridge uses:

- **Ack body keys.** Go decodes `{"to": ...}` with `encoding/json`, which also accepts `"TO"` and a repeated key. The Worker accepts exactly `"to"`, once, and answers 400 otherwise. (Envelopes are strict in both: `envelope.ParseEnvelope` rejects duplicate and case-folded keys.)
- **Dot segments.** The URL parser in front of the Worker resolves `/./` and `/../` (including `%2e`) before the Worker sees the path, so such a path is routed by its resolved form instead of answering 404. Double and trailing slashes still get 404, and nothing redirects.
- **A disconnected poller** keeps its slot until its timeout (at most 25 s); the Go relay frees it at once.
- **Body size.** An ack body over 1 KB is 413 even if it starts with valid JSON; Go can answer 400 for valid JSON followed by more than 1 KB of whitespace.
- **Bad configuration.** The Go relay refuses to start. A Worker cannot refuse to deploy, so it answers 500 `internal` to every request, `/healthz` included, and logs `config_invalid`.
- **Hostname.** The Worker answers 404 for any host but `RELAY_HOSTNAME`, and for plain HTTP. In Docker mode the tunnel's ingress does this.
- **Certificate states.** A certificate that is presented but not verified, or revoked, is 401 `no_identity` in the Worker. In Docker mode the edge's WAF rule blocks those before the relay.
- **Rate limit state** is stored in the Durable Object and survives restarts; the Go relay's is in memory.
- **Logs** are JSON lines with `event`, `method`, `route`, `status`, `duration_ms` and `peer` (no byte count).

## Worker deploy

The operator does this, with their own Cloudflare login. Nothing in the repo deploys automatically, and CI only runs local tests.

Placeholders: `postern.example.com`, `<ZONE_ID>`, `<ACCOUNT_ID>`, `<PEER_A_CERT_SHA256>`, `<PEER_B_CERT_SHA256>`, `<CERT_ID>` (see [edge-setup.md](edge-setup.md)).

1. **Test locally.** `cd relay-worker && npm ci && npm test` (Node 24).
2. **Edge API token and mTLS.** As in [edge-setup.md](edge-setup.md) steps 3 and 4: a token scoped to the one zone, kept in the keychain, and mTLS enabled for `postern.example.com` only. Minimum TLS 1.2.
3. **Client certificates.** Issue one per bridge as in [edge-setup.md](edge-setup.md) step 5. Each bridge runs `postern cert import peer-a.pem`, which prints the certificate's SHA-256; check it with `openssl x509 -in peer-a.pem -outform DER | shasum -a 256`.
4. **WAF rule, as defence in depth.** The same custom rule as [edge-setup.md](edge-setup.md) step 7, scoped to the hostname, action Block:

   ```
   (http.host eq "postern.example.com" and (not cf.tls_client_auth.cert_verified or cf.tls_client_auth.cert_revoked))
   ```

   The Worker refuses those requests itself (401), but with the rule they never reach it, and `postern edge-check` expects the edge to block them. The transform rule of step 8 is not needed in Worker mode, and there is no tunnel.
5. **Configure.** `cp wrangler.toml.example wrangler.toml` (gitignored). Set `account_id = "<ACCOUNT_ID>"`, the custom domain route and `RELAY_HOSTNAME` to `postern.example.com`, and `PEERS` to the fingerprints from step 3:

   ```toml
   PEERS = '{"peer-a":["<PEER_A_CERT_SHA256>"],"peer-b":["<PEER_B_CERT_SHA256>"]}'
   ```

   Fingerprints are public; they are not secrets. The file keeps `workers_dev = false`, `preview_urls = false` and invocation logs off. A custom domain needs the hostname to have no other DNS record (for example an old tunnel CNAME); remove it first (verify against current Cloudflare docs).
6. **Deploy.** The operator authenticates Wrangler with their own account and runs:

   ```sh
   npx wrangler deploy
   ```

7. **Verify.** On each machine, `postern edge-check`. Then the checklist in [edge-setup.md](edge-setup.md), items 1 to 6 (item 5 now proves the Worker ignores the header; item 7 does not apply). Check that the Worker's `workers.dev` address does not serve it (with `workers_dev = false` it should not; if it does, the Worker still answers 404 for that host).

Do not run `wrangler tail` against the production Worker as a habit: a tail streams request metadata that can include the URL with its query string, headers, the client address and certificate details (unverified exactly which). The Worker's own log lines never contain them.

### Rotation

1. The bridge makes a new key and CSR (`postern cert csr --new-key`) and the operator issues a certificate.
2. Add the new fingerprint next to the old one in `PEERS` and `npx wrangler deploy`. Vars change only with a deploy.
3. The bridge imports the certificate (`postern cert import`) and runs `postern edge-check`.
4. Remove the old fingerprint from `PEERS`, deploy again, and revoke the old certificate at the edge.

### Revocation drill

As in [operations.md](operations.md#revocation-drill-before-the-first-real-peer-connects), with one change: in step 4 remove the revoked fingerprint from `PEERS` and deploy, instead of editing `relay.json`. Once the edge marks the certificate revoked, the WAF rule blocks it, and the Worker refuses it on its own (`certRevoked` is `"1"`) even if the rule were missing.

## Switching modes

Bridges only need the relay's URL. If the hostname stays the same, nothing changes on the bridges. If it changes:

1. Update `relay_url` in each bridge config and re-pin it (`postern config pin`, which asks for the terminal code).
2. Run `postern edge-check` on each machine.

Messages are not migrated. Envelopes accepted by the old relay but not yet polled stay there, so let both inboxes drain (no sends, recipients poll) before switching. Seen ids are not migrated either; that is safe, because a replayed envelope is more than 10 minutes old within minutes of the switch, and posting it would still need the sender's client certificate.
