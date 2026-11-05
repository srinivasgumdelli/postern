// Identity: the client certificate the edge verified, mapped through
// PEERS, bound to "from" on post and "to" on poll and ack.

import { beforeEach, describe, expect, it } from "vitest";
import { ack, call, counts, encode, envelope, expectError, FP, goodCert, mustPost, poll, post, resetRelay } from "./helpers";

beforeEach(resetRelay);

const FINGERPRINT_HEADER = "X-Postern-Client-Cert-Sha256";

function endpoints(): { method: string; path: string; body?: string }[] {
  const e = envelope("peer-a", "peer-b");
  return [
    { method: "POST", path: "/v1/msg", body: encode(e) },
    { method: "GET", path: "/v1/poll?to=peer-a&timeout=0" },
    { method: "POST", path: "/v1/ack/" + e.id, body: '{"to":"peer-a"}' },
  ];
}

describe("client certificate", () => {
  it("is required: none, unverified or revoked is 401", async () => {
    const good = goodCert(FP["peer-a"]);
    const noIdentity: (Record<string, string> | null)[] = [
      null, // no tlsClientAuth at all (mTLS not enabled for the hostname)
      { ...good, certPresented: "0" },
      { ...good, certPresented: "0", certVerified: "NONE", certFingerprintSHA256: "" },
      { ...good, certVerified: "NONE" },
      { ...good, certVerified: "FAILED:unable to get local issuer certificate" },
      { ...good, certVerified: "FAILED:certificate has expired" },
      { ...good, certVerified: "success" },
      { ...good, certRevoked: "1" },
      { ...good, certRevoked: "" },
      { ...good, certPresented: "" },
    ];
    for (const ep of endpoints()) {
      for (const tls of noIdentity) {
        expectError(await call(ep.method, ep.path, { tls, body: ep.body }), 401, "no_identity");
      }
    }
    expect(await counts()).toEqual({ envelopes: 0, ids: 0 });
  });

  it("must belong to a configured peer: otherwise 403", async () => {
    for (const ep of endpoints()) {
      for (const fp of [FP.stranger, "not-a-fingerprint", "", "a".repeat(63)]) {
        expectError(await call(ep.method, ep.path, { tls: goodCert(fp), body: ep.body }), 403, "forbidden");
      }
    }
  });

  it("normalizes upper case and colon-separated fingerprints", async () => {
    const colon = FP["peer-a"].toUpperCase().match(/../g)!.join(":");
    const e = envelope("peer-a", "peer-b");
    const r = await call("POST", "/v1/msg", { tls: goodCert(colon), body: encode(e) });
    expect(r.status).toBe(201);
    expect((await counts()).envelopes).toBe(1);
  });

  it("allows several fingerprints per peer (rotation overlap)", async () => {
    await mustPost("peer-a", encode(envelope("peer-a", "peer-b")));
    const r = await call("GET", "/v1/poll?to=peer-b&timeout=0", { tls: goodCert(FP["peer-b-rotated"]) });
    expect(r.status).toBe(200);
    expect(r.body).toContain('"from":"peer-a"');
  });

  it("ignores any client-sent identity header", async () => {
    // No certificate, but a forged fingerprint header: still no identity.
    for (const ep of endpoints()) {
      const r = await call(ep.method, ep.path, { tls: null, body: ep.body, headers: { [FINGERPRINT_HEADER]: FP["peer-a"] } });
      expectError(r, 401, "no_identity");
    }
    // peer-a's certificate claiming peer-b's fingerprint stays peer-a.
    await mustPost("peer-a", encode(envelope("peer-a", "peer-b")));
    const r = await call("GET", "/v1/poll?to=peer-b&timeout=0", { as: "peer-a", headers: { [FINGERPRINT_HEADER]: FP["peer-b"] } });
    expectError(r, 403, "forbidden");
    const own = await call("GET", "/v1/poll?to=peer-a&timeout=0", { as: "peer-a", headers: { [FINGERPRINT_HEADER]: FP.stranger } });
    expect(own.status).toBe(200);
  });
});

describe("identity binding", () => {
  it("rejects a post whose from is not the caller", async () => {
    const forged = envelope("peer-b", "peer-a"); // claims to come from peer-b
    expectError(await post("peer-a", encode(forged)), 403, "forbidden");
    expect(await counts()).toEqual({ envelopes: 0, ids: 0 });
  });

  it("rejects poll and ack of another peer's mailbox", async () => {
    const e = envelope("peer-a", "peer-b");
    await mustPost("peer-a", encode(e));
    expectError(await call("GET", "/v1/poll?to=peer-b&timeout=0", { as: "peer-a" }), 403, "forbidden");
    expectError(await call("GET", "/v1/poll?timeout=0", { as: "peer-a" }), 403, "forbidden");
    expectError(await ack("peer-a", e.id, "peer-b"), 403, "forbidden");
    // Acking another peer's envelope through one's own mailbox finds nothing.
    expectError(await ack("peer-a", e.id, "peer-a"), 404, "not_found");
    expect((await poll("peer-b", "peer-b")).envelopes).toHaveLength(1);
  });
});
