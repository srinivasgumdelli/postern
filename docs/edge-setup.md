# Edge and relay setup

How the operator puts the relay on the internet: a Cloudflare Tunnel to a relay that publishes no ports, with client certificates (mTLS) enforced at the edge for one dedicated hostname. Bridge-side steps (CSR, `cert import`, `edge-check`) are in [operations.md](operations.md). To run the relay as a Cloudflare Worker instead (no tunnel, no relay host), see [relay-modes.md](relay-modes.md); it reuses steps 3 to 5 and 7 below.

Placeholders used throughout. Replace them at deploy time; never commit real values.

| Placeholder | Meaning |
|---|---|
| `postern.example.com` | the dedicated relay hostname, a subdomain of a zone you own |
| `<ZONE_ID>` | that zone's id (dashboard, zone overview) |
| `<TUNNEL_UUID>` | the tunnel id printed by `cloudflared tunnel create` |
| `<PEER_A_CERT_SHA256>`, `<PEER_B_CERT_SHA256>` | SHA-256 fingerprints of each bridge's client certificate |
| `<CERT_ID>` | the edge's id for an issued client certificate (needed to revoke it) |
| `<EDGE_SECRET>` | the content of `deploy/secrets/edge-secret` (never paste it anywhere but the transform rule) |

Items marked **(verify against current Cloudflare docs)** could not be confirmed against Cloudflare's documentation when this was written. Check them before relying on them. The verification checklist at the end tests the parts that matter on the real edge.

## How the pieces fit

```
bridge --HTTPS + client cert--> edge (postern.example.com)
                                  1. mTLS handshake against the Cloudflare-managed CA
                                  2. WAF: block unless cert verified and not revoked
                                  3. transform: SET X-Postern-Client-Cert-Sha256 = cert fingerprint
                                                SET X-Postern-Edge-Secret       = <EDGE_SECRET>
                                  |
                          tunnel (cloudflared dials out from the relay host)
                                  |
                          relay (Docker, internal network only, no published ports)
                                  checks the edge secret (constant time); 401 if missing or wrong
                                  maps the fingerprint to a peer name; 401/403 otherwise
```

The relay runs in `identity: "header"` mode: it trusts the `X-Postern-Client-Cert-Sha256` header, but only on a request that also carries the edge secret. **That is safe only because the relay is reachable solely through the tunnel.** `docker-compose.yml` publishes no ports, puts the relay on an `internal: true` network shared only with `cloudflared`, and `cmd/postern-relay/compose_test.go` fails if that changes. Never publish the relay's port, never attach it to another network, never add a second ingress route to it.

The edge secret covers what that layout cannot: a process on the relay host, or any container joined to the internal network, can still reach the relay. Without the secret it gets 401 for every `/v1` request, so it cannot poll a peer's mailbox or ack (delete) its messages. Anyone who can read the secret (the file on the relay host, or the transform rule in the dashboard) and reach the relay can still claim any identity. That gets them ciphertext only, but they could drop or ack messages. Keep both as tightly held as the tunnel credentials.

## 1. Relay host files

On the relay host (machine A), in the repo checkout:

```sh
cp deploy/relay.example.json deploy/relay.json
cp deploy/cloudflared/config.example.yml deploy/cloudflared/config.yml
mkdir -m 0700 -p deploy/secrets
```

These real files are gitignored. `deploy/relay.json` holds certificate fingerprints, which are not secret. The relay refuses to start while it still contains the `<PEER_..._CERT_SHA256>` placeholders; you fill them in at step 6.

Generate the edge secret. It never appears on the terminal, in argv or in shell history:

```sh
(umask 077 && openssl rand -hex 32 > deploy/secrets/edge-secret)
chmod 0400 deploy/secrets/edge-secret
```

- Compose mounts it into the relay at `/run/secrets/edge_secret` (`edge_secret_file` in `relay.json`). `cloudflared` does not get it.
- The relay refuses to start in header mode without it, if it is shorter than 32 bytes, or if it looks like a placeholder. It reads the file once at start, trims one trailing newline, keeps only a SHA-256 digest and never logs the value.
- The relay runs as `65532:65532`, and Compose bind-mounts file secrets with the host file's owner and mode. On a Linux host, after you have copied the value into the transform rule (step 8): `sudo chown 65532:65532 deploy/secrets/edge-secret`. Docker Desktop maps file ownership differently; check that the relay starts.

## 2. Tunnel

Use a locally managed tunnel with a credentials file (the compose file mounts it as a secret).

```sh
cloudflared tunnel login                 # browser login; writes an account certificate to ~/.cloudflared/cert.pem
cloudflared tunnel create postern        # prints <TUNNEL_UUID>; writes ~/.cloudflared/<TUNNEL_UUID>.json
cloudflared tunnel route dns postern postern.example.com
```

Then:

```sh
mv ~/.cloudflared/<TUNNEL_UUID>.json deploy/secrets/tunnel-credentials.json
chmod 0400 deploy/secrets/tunnel-credentials.json
```

- Edit `deploy/cloudflared/config.yml`: set `tunnel: <TUNNEL_UUID>` and the hostname. The ingress has exactly two rules: the hostname to `http://relay:8080`, then `http_status:404`.
- The pinned `cloudflared` image runs as `65532:65532` (check with `docker image inspect -f '{{.Config.User}}'` after an upgrade). On a Linux host the credentials file must be readable by that user and nobody else: `sudo chown 65532:65532 deploy/secrets/tunnel-credentials.json`. Docker Desktop maps file ownership differently; check that the tunnel starts.
- `~/.cloudflared/cert.pem` can create and delete tunnels for the whole account. Remove it once the tunnel exists, and log in again only when you need to change tunnels (verify against current Cloudflare docs that a credentials-file tunnel runs without it).
- Make sure the hostname's only DNS record is the tunnel CNAME (`<TUNNEL_UUID>.cfargotunnel.com`, proxied). No A/AAAA records pointing at the relay host.

## 3. Edge API token, kept in the keychain

Create an API token in the dashboard (My Profile, API Tokens, Create Custom Token):

- Permission: **Zone, SSL and Certificates, Edit** (the API reference calls it "SSL and Certificates Write").
- Zone resources: **Include, Specific zone**, the one zone that holds `postern.example.com`. No other zones, no account permissions.
- Optionally restrict client IP addresses and set an expiry.

Store it in the operator's login keychain. With `-w` last, `security` prompts for the value, so the token never appears in argv, shell history or the environment:

```sh
security add-generic-password -a operator -s postern-edge-token -w
```

Every API call below reads the token from the keychain and pipes the `Authorization` header into `curl` on stdin (`-H @-`, curl 7.55 or later). The token is never an argument, never an environment variable, never in a file:

```sh
cfapi() {
  security find-generic-password -s postern-edge-token -w \
    | sed 's/^/Authorization: Bearer /' \
    | curl -sS --fail-with-body -H @- "$@"
}
```

Because stdin carries the header, request bodies are passed as files (`--data-binary @file`). They contain only CSRs and hostnames, nothing secret.

## 4. Enable mTLS for the one hostname

Dashboard: SSL/TLS, Client Certificates, Hosts, Edit, add `postern.example.com`.

Or the API (no `mtls_certificate_id` means the Cloudflare-managed CA). Note that `PUT` replaces the whole list, so include every hostname that should keep mTLS:

```sh
printf '{"hostnames":["postern.example.com"]}' > hosts.json
cfapi -X PUT "https://api.cloudflare.com/client/v4/zones/<ZONE_ID>/certificate_authorities/hostname_associations" \
  -H 'Content-Type: application/json' --data-binary @hosts.json
```

Also, for the zone or hostname: minimum TLS version 1.2 or later. Enabling mTLS for the host only makes the edge *ask* for a certificate. The WAF rule in step 7 is what blocks requests without one.

## 5. Issue a client certificate per bridge

Each bridge prints a CSR (`postern init` or `postern cert csr`); the private key never leaves that machine's keychain. Copy the CSR to the operator, for example as `peer-a.csr`. Then:

```sh
jq -n --rawfile csr peer-a.csr '{csr: $csr, validity_days: 14}' > peer-a-req.json
cfapi -X POST "https://api.cloudflare.com/client/v4/zones/<ZONE_ID>/client_certificates" \
  -H 'Content-Type: application/json' --data-binary @peer-a-req.json > peer-a-resp.json
jq -r '.result.certificate' peer-a-resp.json > peer-a.pem
jq -r '.result.id, .result.fingerprint_sha256, .result.expires_on' peer-a-resp.json   # note <CERT_ID>
```

- Validity is about 14 days and certificates rotate weekly (one week of overlap). Whether the API enforces a minimum or maximum `validity_days`: verify against current Cloudflare docs.
- A zone can hold up to 100 active certificates from the Cloudflare-managed CA. Revoked ones do not count.
- Compute the fingerprint yourself; it must match what `postern cert import peer-a.pem` prints on the bridge:

  ```sh
  openssl x509 -in peer-a.pem -outform DER | shasum -a 256 | cut -d' ' -f1
  ```

- Return `peer-a.pem` to the bridge's operator (it is public), keep `<CERT_ID>` for revocation, and delete the request and response files.

Repeat for `peer-b`.

### Revoke

```sh
cfapi -X DELETE "https://api.cloudflare.com/client/v4/zones/<ZONE_ID>/client_certificates/<CERT_ID>"
```

Revocation is asynchronous: the status moves from `pending_revocation` to `revoked`. How quickly the edge enforces it: verify against current Cloudflare docs, and measure it during the revocation drill ([operations.md](operations.md)). Then remove that fingerprint from `relay.json` and restart the relay, so the relay rejects it too. If it was the peer's only fingerprint, replace it instead (step 6): the relay refuses to start with a peer that has none.

List certificates (to audit, or to find a `<CERT_ID>`):

```sh
cfapi "https://api.cloudflare.com/client/v4/zones/<ZONE_ID>/client_certificates" \
  | jq -r '.result[] | [.id, .status, .common_name, .expires_on, .fingerprint_sha256] | @tsv'
```

(Filter and pagination parameters: verify against current Cloudflare docs.)

## 6. Put the fingerprints in relay.json

```json
{
  "listen": ":8080",
  "db": "/data/relay.db",
  "identity": "header",
  "fingerprint_header": "X-Postern-Client-Cert-Sha256",
  "edge_secret_file": "/run/secrets/edge_secret",
  "peers": {
    "peer-a": ["<PEER_A_CERT_SHA256>"],
    "peer-b": ["<PEER_B_CERT_SHA256>"]
  },
  "posts_per_hour": 120,
  "max_queued_per_peer": 1000
}
```

- `edge_secret_file` is the path inside the container; leave it as is. It is required in header mode and ignored in `mtls` mode. `edge_secret_next_file` is set only during an [edge secret rotation](#edge-secret-rotation).
- Fingerprints are 64 hex characters. Case, colons and spaces are normalized. A fingerprint may belong to only one peer.
- During rotation a peer lists two fingerprints (old and new); remove the old one once the bridge has switched.
- Every peer needs at least one fingerprint, and the file needs at least two peers; otherwise the relay refuses to start. To cut a peer off before its replacement certificate exists, replace its fingerprint with one that matches no certificate (`openssl rand -hex 32`) rather than leaving the list empty.
- The relay reads the file only at start: `docker compose restart relay` after every change.

Do not start the stack yet. Until the WAF rule and the transform rule (steps 7 and 8) are live, a request without a certificate, or with a client-chosen fingerprint header, would reach the relay.

## 7. WAF custom rule

Security, WAF, Custom rules, Create rule:

- Expression:

  ```
  (http.host eq "postern.example.com" and (not cf.tls_client_auth.cert_verified or cf.tls_client_auth.cert_revoked))
  ```

- Action: **Block**.

Both conditions are needed: `cert_verified` is still true for a valid certificate that has been revoked. The Free plan allows 5 custom rules (checked 2026-11-05, see the limits table in [relay-modes.md](relay-modes.md#free-plan-limits); plans change). This rule must stay enabled and scoped to this hostname.

## 8. Transform rule: set the fingerprint and edge secret headers

Rules, Transform Rules, Modify Request Header, Create rule:

- When: custom filter expression `http.host eq "postern.example.com"`.
- Then, two operations in the same rule:
  1. **Set dynamic**, header name `X-Postern-Client-Cert-Sha256`, value `cf.tls_client_auth.cert_fingerprint_sha256`.
  2. **Set static**, header name `X-Postern-Edge-Secret`, value `<EDGE_SECRET>`.

To paste the secret without printing it, copy it to the clipboard on the relay host (`pbcopy < deploy/secrets/edge-secret` on macOS, `xclip -selection clipboard < deploy/secrets/edge-secret` on Linux) and clear the clipboard afterwards. Anyone who can view this rule in the dashboard can read the secret. The API token from step 3 cannot: it has only the SSL and Certificates permission.

"Set" overwrites any value the client sent, so a client cannot choose its own identity or learn anything by sending its own edge secret. When there is no client certificate the field is empty, and a header set to an empty value is removed, so the relay sees no identity (401). The field holds 64 lowercase hex characters. Whether the `cf.tls_client_auth.*` fields are usable in transform rules on your plan: verify against current Cloudflare docs. Checklist items 4 and 5 below prove it works.

Request header transform rules run in the `http_request_late_transform` phase. Where that sits relative to WAF custom rules does not matter here: the WAF blocks no-certificate requests either way, and the header always comes from the edge.

## 9. Start

Only after steps 7 and 8 are deployed:

```sh
docker compose up -d --build
docker compose ps
```

Then run the verification checklist below.

## Weekly rotation

1. The bridge makes a new key and CSR (`postern cert csr --new-key`).
2. Issue a certificate from it (step 5).
3. Add the new fingerprint next to the old one in `relay.json`, then `docker compose restart relay`.
4. The bridge imports the certificate and checks it (`postern cert import`, `postern edge-check`).
5. Remove the old fingerprint, restart the relay, and revoke the old certificate.

## Edge secret rotation

Rotate the edge secret when someone who could read it (the file, or the transform rule) no longer should, when you suspect it leaked, when the relay host or edge account may be compromised, and whenever you rotate the tunnel credentials.

The relay accepts a second, *next* secret alongside the current one (`edge_secret_next_file`), so there is no window in which the edge sends a secret the relay does not know. A request passes if its secret matches either; both are compared in constant time, and the access log names the slot that matched only as `"edge_secret_slot":"current"` or `"next"`. The two relay restarts below take a few seconds each, and bridges retry with backoff. Order matters: change the transform rule only after the relay has loaded the next secret (step 2), and drop the old one only after the edge sends the new one (step 3).

1. **Generate the next secret** on the relay host, next to the current one. It never appears on the terminal, in argv or in shell history:

   ```sh
   (umask 077 && openssl rand -hex 32 > deploy/secrets/edge-secret-next)
   chmod 0400 deploy/secrets/edge-secret-next
   ```

   On a Linux host the relay (`65532:65532`) must be able to read it: `sudo chown 65532:65532 deploy/secrets/edge-secret-next`. Then step 3 needs `sudo cat` to copy it.

2. **Restart the relay with both secrets.** Add this line to `deploy/relay.json`, next to `edge_secret_file`:

   ```json
   "edge_secret_next_file": "/run/secrets/edge_secret_next",
   ```

   and recreate the relay with the rotation overlay, which mounts the file as a second compose secret (the relay only; `cloudflared` never gets it):

   ```sh
   docker compose -f docker-compose.yml -f deploy/compose.edge-secret-next.yml up -d --force-recreate relay
   docker compose logs relay | grep 'relay listening'      # "edge_secrets":2
   ```

   The next file gets the same checks as the current one (at least 32 bytes, printable, not a placeholder, at most 4 KB), and must differ from it; otherwise the relay refuses to start and says which file is wrong, never its content. Requests still carry the current secret: their access log lines show `"edge_secret_slot":"current"`.

3. **Switch the edge.** Edit the transform rule (step 8): replace the static `X-Postern-Edge-Secret` value with the content of `edge-secret-next` (`pbcopy < deploy/secrets/edge-secret-next` on macOS, `sudo cat deploy/secrets/edge-secret-next | xclip -selection clipboard` on Linux), deploy the rule, and clear the clipboard. Then wait until requests arrive with the next secret only. Bridges poll at least every 25 seconds, so a couple of minutes is plenty:

   ```sh
   docker compose logs --since 2m relay | grep -c '"edge_secret_slot":"current"'   # 0 once the edge has switched
   docker compose logs --since 2m relay | grep -c '"edge_secret_slot":"next"'      # more than 0
   ```

4. **Promote the next secret and drop the old one.** Move the new value into the current file, remove the `edge_secret_next_file` line from `deploy/relay.json`, and recreate the relay **without** the overlay. Replacing the file creates a new inode, so recreate the container rather than restarting it:

   ```sh
   mv deploy/secrets/edge-secret-next deploy/secrets/edge-secret     # sudo mv if the files are owned by 65532
   docker compose up -d --force-recreate relay
   docker compose logs relay | grep 'relay listening'      # "edge_secrets":1
   ```

   `mv` keeps the next file's mode (0400) and owner. If the relay does not start, `docker compose logs relay` says why; a `cannot open edge_secret_next_file` means the line is still in `relay.json`.

5. **Check:** the access log shows `"edge_secret_slot":"current"` again, `postern edge-check` passes on each bridge, verification item 8 below still gets 401, and `docker compose logs relay` shows no `edge secret rejected` events after the restart.

To abandon a rotation before step 4, put the old value back in the transform rule (if you changed it), remove the `edge_secret_next_file` line, recreate the relay without the overlay, and delete `deploy/secrets/edge-secret-next`. The current secret works throughout.

## Verification checklist

Run all of it before the first real peer connects, and again after any edge change. Use a throwaway certificate, so no bridge key has to leave a keychain:

```sh
openssl ecparam -genkey -name prime256v1 -noout -out edge-test-key.pem
openssl req -new -key edge-test-key.pem -subj /CN=edge-test -out edge-test.csr
# issue it as in step 5 -> edge-test.pem, and note its <CERT_ID>
```

An edge rejection is Cloudflare's HTML block page. A relay rejection is JSON like `{"error":"forbidden"}`.

1. **No certificate is blocked at the edge.** Expect 403 with the HTML block page:

   ```sh
   curl -sS -o /dev/null -w '%{http_code}\n' https://postern.example.com/healthz
   ```

2. **A forged header without a certificate is still blocked at the edge.** Expect 403 HTML:

   ```sh
   curl -sS -w '\n%{http_code}\n' -H 'X-Postern-Client-Cert-Sha256: <PEER_A_CERT_SHA256>' \
     'https://postern.example.com/v1/poll?to=peer-a&timeout=0'
   ```

3. **With a certificate, `/healthz` is 200.** Expect `ok`:

   ```sh
   curl -sS --cert edge-test.pem --key edge-test-key.pem https://postern.example.com/healthz
   ```

4. **The relay enforces the fingerprint.** The test certificate is not in `relay.json`. Expect `{"error":"forbidden"}` (403 from the relay):

   ```sh
   curl -sS --cert edge-test.pem --key edge-test-key.pem 'https://postern.example.com/v1/poll?to=peer-a&timeout=0'
   ```

   `{"error":"no_identity"}` (401) instead means the edge secret did not arrive or does not match `deploy/secrets/edge-secret`: check the second operation of the transform rule, and `docker compose logs relay` for the `edge secret rejected` reason.

5. **The edge overwrites a client-sent header.** Same certificate, now also claiming peer-a's fingerprint. Expect `{"error":"forbidden"}` again. A 200 here means the transform rule is not overwriting the header: stop and fix it.

   ```sh
   curl -sS --cert edge-test.pem --key edge-test-key.pem -H 'X-Postern-Client-Cert-Sha256: <PEER_A_CERT_SHA256>' \
     'https://postern.example.com/v1/poll?to=peer-a&timeout=0'
   ```

6. **Revocation cuts the certificate off at the edge.** Revoke the test certificate (step 5, Revoke), wait for `revoked`, and repeat item 3. Expect 403 HTML. Then delete `edge-test-key.pem`, `edge-test.csr` and `edge-test.pem`.

7. **The relay container publishes no ports.** On the relay host:

   ```sh
   docker compose ps                                   # PORTS column empty for relay and cloudflared
   docker port postern-relay-1                         # prints nothing
   docker inspect -f '{{json .NetworkSettings.Ports}}' postern-relay-1    # {} or only unpublished entries
   docker network inspect -f '{{.Internal}}' postern_relay-internal       # true
   curl -m 3 http://127.0.0.1:8080/healthz             # must fail: nothing listens on the host
   ```

8. **A request that skips the edge cannot claim an identity.** This is what a process on the relay host or the internal network would try: go straight to the relay's internal address with a peer's fingerprint and no edge secret. **Verification step only:** it attaches a throwaway container to the internal network for one request and removes it (`--rm`). Never leave a container attached to `postern_relay-internal`.

   ```sh
   # healthz needs no identity: proves the request reached the relay. Expect "ok".
   docker run --rm --network postern_relay-internal curlimages/curl:8.11.1 \
     -sS -m 5 http://relay:8080/healthz
   # No edge secret. Expect {"error":"no_identity"} and 401.
   docker run --rm --network postern_relay-internal curlimages/curl:8.11.1 \
     -sS -m 5 -w '\n%{http_code}\n' -H 'X-Postern-Client-Cert-Sha256: <PEER_A_CERT_SHA256>' \
     'http://relay:8080/v1/poll?to=peer-a&timeout=0'
   # A wrong edge secret. Expect {"error":"no_identity"} and 401.
   docker run --rm --network postern_relay-internal curlimages/curl:8.11.1 \
     -sS -m 5 -w '\n%{http_code}\n' -H 'X-Postern-Client-Cert-Sha256: <PEER_A_CERT_SHA256>' \
     -H 'X-Postern-Edge-Secret: 0000000000000000000000000000000000000000000000000000000000000000' \
     'http://relay:8080/v1/poll?to=peer-a&timeout=0'
   ```

   A 200 on either `/v1/poll` request means the relay is not checking the edge secret: stop the stack and fix it. `<PEER_A_CERT_SHA256>` is a fingerprint, not a secret; never put the real edge secret on a command line. (`curlimages/curl` is just a small image with curl; pin whichever current tag you trust.)

9. **Real bridges work end to end.** On each machine, `postern edge-check` succeeds. It goes through the edge, which adds the edge secret, so it needs no access to the secret.

10. **Logs carry no content or secrets.** `docker compose logs relay` shows method, route, status, bytes, duration and peer only, plus `edge_secret_slot` (`current`, or `next` during a rotation) on requests that carried a valid edge secret. No query strings, no bodies, no client addresses, no header values. Item 8 adds `edge secret rejected` events with a `reason` (`missing`, `mismatch` or `multiple`) and nothing else.
