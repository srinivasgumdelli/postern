// The HTTP API, matched against internal/relay/server_test.go.

import { beforeEach, describe, expect, it } from "vitest";
import {
  ack,
  call,
  counts,
  encode,
  envelope,
  expectError,
  mustPost,
  poll,
  post,
  resetRelay,
  sleep,
  ulid,
} from "./helpers";

beforeEach(resetRelay);

describe("routes", () => {
  it("serves /healthz without identity", async () => {
    const r = await call("GET", "/healthz");
    expect(r.status).toBe(200);
    expect(r.body).toBe("ok");
    expect(r.headers.get("Cache-Control")).toBe("no-store");
    expect(r.headers.get("X-Content-Type-Options")).toBe("nosniff");
  });

  it("answers unknown routes with 404 and wrong methods with 405", async () => {
    expectError(await call("GET", "/nope", { as: "peer-a" }), 404, "not_found");
    expectError(await call("GET", "/v1/msg/", { as: "peer-a" }), 404, "not_found");
    expectError(await call("POST", "/v1/ack/", { as: "peer-a" }), 404, "not_found");
    expectError(await call("GET", "/", { as: "peer-a" }), 404, "not_found");

    const cases: [string, string, string][] = [
      ["GET", "/v1/msg", "POST"],
      ["PUT", "/v1/msg", "POST"],
      ["POST", "/v1/poll", "GET, HEAD"],
      ["GET", "/v1/ack/" + ulid(), "POST"],
      ["POST", "/healthz", "GET, HEAD"],
    ];
    for (const [method, path, allow] of cases) {
      const r = await call(method, path, { as: "peer-a" });
      expectError(r, 405, "method_not_allowed");
      expect(r.headers.get("Allow")).toBe(allow);
    }
  });

  it("answers a non-canonical path with a plain 404, never a redirect", async () => {
    for (const path of ["/v1//poll", "//healthz", "/v1/poll/"]) {
      const r = await call("GET", path, { as: "peer-a" });
      expectError(r, 404, "not_found");
      expect(r.headers.get("Location")).toBeNull();
    }
    expectError(await call("GET", "/v1/%zz", { as: "peer-a" }), 404, "not_found");
  });

  it("answers HEAD on GET routes without a body", async () => {
    const r = await call("HEAD", "/healthz");
    expect(r.status).toBe(200);
    expect(r.body).toBe("");
    const p = await call("HEAD", "/v1/poll?to=peer-b&timeout=0", { as: "peer-b" });
    expect(p.status).toBe(200);
  });

  it("refuses any hostname but the configured one, and plain HTTP", async () => {
    for (const url of [
      "https://other.example.com/healthz",
      "https://postern.example.com.evil.example/healthz",
      "https://relay.workers.example/v1/poll?to=peer-b&timeout=0",
      "https://postern.example.com:8443/healthz",
      "http://postern.example.com/healthz",
    ]) {
      const r = await call("GET", "", { url, as: "peer-b" });
      expectError(r, 404, "not_found");
    }
  });
});

describe("errors", () => {
  it("never echo input", async () => {
    const marker = "echomarker7731";
    const checks = [
      await call("GET", "/" + marker, { as: "peer-a" }),
      await call("POST", "/v1/msg", { as: "peer-a", body: `{"${marker}":1}` }),
      await call("GET", "/v1/poll?to=" + marker, { as: "peer-a" }),
      await call("GET", "/v1/poll?to=peer-a&after=" + marker, { as: "peer-a" }),
      await call("GET", "/v1/poll?to=peer-a&timeout=" + marker, { as: "peer-a" }),
      await call("POST", "/v1/ack/" + marker, { as: "peer-a", body: '{"to":"peer-a"}' }),
      await call("POST", "/v1/ack/" + ulid(), { as: "peer-a", body: `{"to":"${marker}"}` }),
      await call("POST", "/v1/ack/" + ulid(), { as: "peer-a", body: `{"${marker}":"x"}` }),
      await call("GET", "/healthz", { url: `https://${marker}.example.com/healthz` }),
      await call("PATCH", "/v1/msg?" + marker, { as: "peer-a" }),
    ];
    for (const [i, r] of checks.entries()) {
      expect(r.status, `check ${i}`).toBeGreaterThanOrEqual(400);
      expect(r.body).not.toContain(marker);
      for (const [k, v] of r.headers) {
        expect(`${k}: ${v}`).not.toContain(marker);
      }
    }
  });
});

describe("post, poll, ack", () => {
  it("round-trips one envelope byte for byte", async () => {
    const e = envelope("peer-a", "peer-b");
    const raw = encode(e);
    const r = await post("peer-a", raw);
    expect(r.status).toBe(201);
    expect(r.body).toBe(JSON.stringify({ id: e.id }) + "\n");
    expect(r.headers.get("Content-Type")).toBe("application/json");

    // The sender's own mailbox is empty.
    expect((await poll("peer-a", "peer-a")).envelopes).toHaveLength(0);

    const p = await poll("peer-b", "peer-b");
    expect(p.status).toBe(200);
    expect(p.envelopes).toEqual([raw]);
    expect(p.cursor).toBeGreaterThan(0);

    // The cursor excludes what was already returned.
    const again = await poll("peer-b", "peer-b", p.cursor);
    expect(again.envelopes).toHaveLength(0);
    expect(again.cursor).toBe(p.cursor);

    expect((await ack("peer-b", e.id, "peer-b")).status).toBe(200);
    expect((await ack("peer-b", e.id, "peer-b")).body).toBe(JSON.stringify({ error: "not_found" }) + "\n");
    expect((await poll("peer-b", "peer-b")).envelopes).toHaveLength(0);
  });

  it("stores the canonical re-encoding, not the request bytes", async () => {
    const e = envelope("peer-a", "peer-b");
    const spaced = `{ "box" : ${JSON.stringify(e.box)}, "nonce":${JSON.stringify(e.nonce)}, "ts": ${e.ts},
      "thread":"\\u0074${e.thread.slice(1)}", "to":"peer-b", "from":"peer-a", "id":${JSON.stringify(e.id)}, "v":1 }`;
    expect((await post("peer-a", spaced)).status).toBe(201);
    expect((await poll("peer-b", "peer-b")).envelopes).toEqual([encode(e)]);
  });

  it("returns at most 50 per poll, in order", async () => {
    const ids: string[] = [];
    for (let i = 0; i < 60; i++) {
      const e = envelope("peer-a", "peer-b");
      await mustPost("peer-a", encode(e));
      ids.push(e.id);
    }
    const first = await poll("peer-b", "peer-b");
    expect(first.envelopes).toHaveLength(50);
    const second = await poll("peer-b", "peer-b", first.cursor);
    expect(second.envelopes).toHaveLength(10);
    expect(second.cursor).toBeGreaterThan(first.cursor);
    const got = [...first.envelopes, ...second.envelopes].map((raw) => JSON.parse(raw).id);
    expect(got).toEqual(ids);
  });

  it("long-poll wakes on a new message", async () => {
    const start = Date.now();
    const pending = poll("peer-b", "peer-b", 0, 20);
    let settled = false;
    void pending.then(() => (settled = true));
    await sleep(300);
    expect(settled).toBe(false);
    await mustPost("peer-a", encode(envelope("peer-a", "peer-b")));
    const p = await pending;
    expect(p.envelopes).toHaveLength(1);
    expect(Date.now() - start).toBeLessThan(5000);
  });

  it("long-poll ignores other mailboxes", async () => {
    const pending = poll("peer-b", "peer-b", 0, 1);
    await sleep(100);
    await mustPost("peer-b", encode(envelope("peer-b", "peer-a")));
    expect((await pending).envelopes).toHaveLength(0);
  });

  it("long-poll times out empty with the cursor unchanged", async () => {
    const start = Date.now();
    const p = await poll("peer-b", "peer-b", 42, 1);
    const elapsed = Date.now() - start;
    expect(p.status).toBe(200);
    expect(p.envelopes).toHaveLength(0);
    expect(p.cursor).toBe(42);
    expect(elapsed).toBeGreaterThanOrEqual(900);
    expect(elapsed).toBeLessThan(5000);

    // timeout=0, and a negative timeout clamped to 0, return at once.
    const t0 = Date.now();
    for (const q of ["timeout=0", "timeout=-5", "timeout=%2B0"]) {
      const r = await call("GET", "/v1/poll?to=peer-b&" + q, { as: "peer-b" });
      expect(r.status).toBe(200);
      expect(r.body).toBe('{"envelopes":[],"cursor":0}\n');
    }
    expect(Date.now() - t0).toBeLessThan(2000);
  });

  it("echoes a cursor up to int64 max", async () => {
    const r = await call("GET", "/v1/poll?to=peer-b&timeout=0&after=9223372036854775807", { as: "peer-b" });
    expect(r.body).toBe('{"envelopes":[],"cursor":9223372036854775807}\n');
  });

  it("rejects bad poll parameters", async () => {
    for (const q of [
      "after=-1",
      "after=x",
      "after=1.5",
      "after=9223372036854775808",
      "after=1_0",
      "timeout=abc",
      "timeout=1e3",
      "timeout=99999999999999999999",
      "timeout=+1", // "+" in a query is a space
    ]) {
      expectError(await call("GET", "/v1/poll?to=peer-b&" + q, { as: "peer-b" }), 400, "invalid");
    }
    // Go's query rules: the first value wins, pairs with ";" or a bad escape are dropped.
    expect((await call("GET", "/v1/poll?to=peer-b&to=peer-a&timeout=0", { as: "peer-b" })).status).toBe(200);
    expect((await call("GET", "/v1/poll?to=peer-b&timeout=0&after=%zz", { as: "peer-b" })).status).toBe(200);
    expectError(await call("GET", "/v1/poll?to=peer-b;x&timeout=0", { as: "peer-b" }), 403, "forbidden");
    expect((await call("GET", "/v1/poll?to=peer%2Db&timeout=0", { as: "peer-b" })).status).toBe(200);
  });

  it("validates ack requests", async () => {
    const e = envelope("peer-a", "peer-b");
    await mustPost("peer-a", encode(e));
    const path = "/v1/ack/" + e.id;
    for (const body of ["", "to=peer-b", '{"to":"peer-b","id":"x"}', '{"to":"peer-b"}{}', '["peer-b"]', '{"to":1}']) {
      expectError(await call("POST", path, { as: "peer-b", body }), 400, "invalid");
    }
    // A JSON null or empty object has no "to", which is not the caller's mailbox.
    for (const body of ["null", "{}", '{"to":null}']) {
      expectError(await call("POST", path, { as: "peer-b", body }), 403, "forbidden");
    }
    expectError(await call("POST", path, { as: "peer-b", body: " ".repeat(2048) }), 413, "too_large");
    expectError(await ack("peer-b", "not-a-ulid", "peer-b"), 400, "invalid");
    expectError(await ack("peer-b", e.id.toLowerCase(), "peer-b"), 400, "invalid");
    expect((await ack("peer-b", e.id, "peer-b")).status).toBe(200);
    expect(await counts()).toEqual({ envelopes: 0, ids: 1 });
  });
});
