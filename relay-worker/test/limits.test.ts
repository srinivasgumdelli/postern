// Replay window, dedup, size, rate and queue limits, poll concurrency and
// expiry, matched against internal/relay/server_test.go.

import { runDurableObjectAlarm } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";
import {
  ack,
  advance,
  call,
  counts,
  encode,
  envelope,
  expectError,
  mustPost,
  poll,
  post,
  relayNow,
  relayStub,
  resetRelay,
  sleep,
} from "./helpers";

beforeEach(resetRelay);

const MINUTE = 60_000;
const HOUR = 60 * MINUTE;
const RETENTION = 72 * HOUR;
const MAX_ENVELOPE_BYTES = 48 * 1024;

/** An envelope stamped with the relay's (possibly shifted) clock. */
async function fresh(from: string, to: string, offsetMs = 0) {
  return envelope(from, to, {}, (await relayNow()) + offsetMs);
}

describe("replay window", () => {
  it("rejects ts more than 10 minutes off with 422", async () => {
    for (const off of [-11 * MINUTE, 11 * MINUTE, -RETENTION, 365 * 24 * HOUR]) {
      expectError(await post("peer-a", encode(await fresh("peer-a", "peer-b", off))), 422, "stale");
    }
    for (const off of [-9 * MINUTE, 9 * MINUTE]) {
      expect((await post("peer-a", encode(await fresh("peer-a", "peer-b", off)))).status).toBe(201);
    }
    expectError(await post("peer-a", encode({ ...(await fresh("peer-a", "peer-b")), ts: 1 })), 422, "stale");
  });

  it("does not burn the id of a stale envelope", async () => {
    const e = await fresh("peer-a", "peer-b", -HOUR);
    expectError(await post("peer-a", encode(e)), 422, "stale");
    e.ts = Math.floor((await relayNow()) / 1000);
    expect((await post("peer-a", encode(e))).status).toBe(201);
  });

  it("rejects a duplicate id with 409, including after ack", async () => {
    const e = await fresh("peer-a", "peer-b");
    await mustPost("peer-a", encode(e));
    expectError(await post("peer-a", encode(e)), 409, "duplicate");

    // A reseal with a fresh ts and new ciphertext but the same id is still a duplicate.
    await advance(MINUTE);
    const resealed = { ...(await fresh("peer-a", "peer-b")), id: e.id };
    expectError(await post("peer-a", encode(resealed)), 409, "duplicate");

    expect((await ack("peer-b", e.id, "peer-b")).status).toBe(200);
    expectError(await post("peer-a", encode(e)), 409, "duplicate");
    expectError(await post("peer-a", encode(resealed)), 409, "duplicate");
    expect((await poll("peer-b", "peer-b")).envelopes).toHaveLength(0);
  });

  it("remembers ids across mailboxes", async () => {
    const e = await fresh("peer-a", "peer-b");
    await mustPost("peer-a", encode(e));
    // The same id sent the other way is a replay too.
    const back = { ...(await fresh("peer-b", "peer-a")), id: e.id };
    expectError(await post("peer-b", encode(back)), 409, "duplicate");
  });

  it("stores a racing duplicate once", async () => {
    const raw = encode(await fresh("peer-a", "peer-b"));
    const statuses = await Promise.all(Array.from({ length: 8 }, () => post("peer-a", raw).then((r) => r.status)));
    expect(statuses.filter((s) => s === 201)).toHaveLength(1);
    expect(statuses.filter((s) => s === 409)).toHaveLength(7);
  });
});

describe("size", () => {
  it("rejects an oversize envelope with 413", async () => {
    expectError(await post("peer-a", "A".repeat(MAX_ENVELOPE_BYTES + 1)), 413, "too_large");
    const big = { ...(await fresh("peer-a", "peer-b")), box: "A".repeat(MAX_ENVELOPE_BYTES) };
    expectError(await post("peer-a", encode(big)), 413, "too_large");
    // A declared length over the cap is refused before reading.
    const r = await call("POST", "/v1/msg", {
      as: "peer-a",
      body: "{}",
      headers: { "Content-Length": String(MAX_ENVELOPE_BYTES + 1) },
    });
    expect([400, 413]).toContain(r.status);
    expect(await counts()).toEqual({ envelopes: 0, ids: 0 });
  });

  it("accepts an envelope of exactly the cap", async () => {
    const raw = encode(await fresh("peer-a", "peer-b"));
    const padded = "{" + " ".repeat(MAX_ENVELOPE_BYTES - raw.length) + raw.slice(1);
    expect(new TextEncoder().encode(padded).length).toBe(MAX_ENVELOPE_BYTES);
    expect((await post("peer-a", padded)).status).toBe(201);
  });
});

describe("invalid envelopes", () => {
  it("are 400 and store nothing", async () => {
    const e = await fresh("peer-a", "peer-b");
    const good = encode(e);
    const cases: Record<string, string> = {
      "not json": "hello",
      empty: "",
      "unknown field": good.slice(0, -1) + ',"extra":1}',
      "trailing data": good + "{}",
      "wrong version": encode({ ...e, v: 2 }),
      "bad id": encode({ ...e, id: "nope" }),
      "bad thread": encode({ ...e, thread: "free text" }),
      "bad nonce": encode({ ...e, nonce: "AAAA" }),
      "unknown peer": encode({ ...e, to: "peer-c" }),
      "to self": encode({ ...e, to: "peer-a" }),
      "bad peer name": encode({ ...e, to: "Peer B" }),
      "missing ts": encode({ ...e, ts: 0 }),
      "box not base64": encode({ ...e, box: "!!!" }),
    };
    for (const [name, body] of Object.entries(cases)) {
      const r = await post("peer-a", body);
      expect(`${name}: ${r.status} ${r.body.trim()}`).toBe(`${name}: 400 {"error":"invalid"}`);
    }
    expect(await counts()).toEqual({ envelopes: 0, ids: 0 });
  });
});

describe("rate and queue limits", () => {
  it("limits posts per sender per hour (429)", async () => {
    const limited = { env: { POSTS_PER_HOUR: "3" } };
    for (let i = 0; i < 3; i++) await mustPost("peer-a", encode(await fresh("peer-a", "peer-b")), limited);
    const rejected = await fresh("peer-a", "peer-b");
    expectError(await post("peer-a", encode(rejected), limited), 429, "rate_limited");

    // Other senders are unaffected.
    await mustPost("peer-b", encode(await fresh("peer-b", "peer-a")), limited);

    // A rejected post does not burn its id; it goes through once the window
    // has moved on (resealed with a fresh ts, as a bridge would).
    await advance(HOUR + 1000);
    const again = { ...(await fresh("peer-a", "peer-b")), id: rejected.id };
    await mustPost("peer-a", encode(again), limited);
  });

  it("caps each recipient's queue (429 queue_full)", async () => {
    const capped = { env: { MAX_QUEUED_PER_PEER: "2" } };
    const first = await fresh("peer-a", "peer-b");
    await mustPost("peer-a", encode(first), capped);
    await mustPost("peer-a", encode(await fresh("peer-a", "peer-b")), capped);
    const third = encode(await fresh("peer-a", "peer-b"));
    expectError(await post("peer-a", third, capped), 429, "queue_full");
    // peer-a's own queue is separate.
    await mustPost("peer-b", encode(await fresh("peer-b", "peer-a")), capped);
    // Acking frees a slot.
    expect((await ack("peer-b", first.id, "peer-b")).status).toBe(200);
    await mustPost("peer-a", third, capped);
  });

  it("caps concurrent long-polls per peer (429)", async () => {
    const polls = Array.from({ length: 16 }, () => poll("peer-b", "peer-b", 0, 20));
    await sleep(500);
    expectError(await call("GET", "/v1/poll?to=peer-b&timeout=0", { as: "peer-b" }), 429, "rate_limited");
    // peer-a is unaffected.
    expect((await call("GET", "/v1/poll?to=peer-a&timeout=0", { as: "peer-a" })).status).toBe(200);
    await mustPost("peer-a", encode(await fresh("peer-a", "peer-b")));
    for (const p of await Promise.all(polls)) expect(p.envelopes).toHaveLength(1);
    // The slots are released when the polls return.
    expect((await call("GET", "/v1/poll?to=peer-b&timeout=0", { as: "peer-b" })).status).toBe(200);
  });
});

describe("expiry", () => {
  it("deletes envelopes and seen ids after 72 hours", async () => {
    const old = await fresh("peer-a", "peer-b");
    await mustPost("peer-a", encode(old));
    const acked = await fresh("peer-a", "peer-b");
    await mustPost("peer-a", encode(acked));
    expect((await ack("peer-b", acked.id, "peer-b")).status).toBe(200);

    await advance(RETENTION - HOUR);
    const kept = await fresh("peer-a", "peer-b");
    await mustPost("peer-a", encode(kept));
    expect(await counts()).toEqual({ envelopes: 2, ids: 3 });

    await advance(2 * HOUR); // the first two are now past retention
    // Even before the alarm runs, nothing past retention is served.
    const p = await poll("peer-b", "peer-b");
    expect(p.envelopes.map((raw) => JSON.parse(raw).id)).toEqual([kept.id]);

    expect(await runDurableObjectAlarm(relayStub())).toBe(true);
    expect(await counts()).toEqual({ envelopes: 1, ids: 1 });

    // Expired ids are forgotten: a reseal with a fresh ts is accepted.
    await mustPost("peer-a", encode({ ...(await fresh("peer-a", "peer-b")), id: old.id }));
    // The kept one is still remembered.
    expectError(await post("peer-a", encode({ ...(await fresh("peer-a", "peer-b")), id: kept.id })), 409, "duplicate");
  });

  it("keeps an alarm set while anything is stored", async () => {
    await mustPost("peer-a", encode(await fresh("peer-a", "peer-b")));
    expect(await runDurableObjectAlarm(relayStub())).toBe(true); // nothing old yet; it re-arms
    expect(await counts()).toEqual({ envelopes: 1, ids: 1 });
    expect(await runDurableObjectAlarm(relayStub())).toBe(true);
    await advance(RETENTION + MINUTE);
    expect(await runDurableObjectAlarm(relayStub())).toBe(true);
    expect(await counts()).toEqual({ envelopes: 0, ids: 0 });
    // Empty: no alarm left.
    expect(await runDurableObjectAlarm(relayStub())).toBe(false);
  });
});
