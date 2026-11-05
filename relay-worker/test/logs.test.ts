// Logs carry fixed event names and routing metadata only: never a box,
// nonce, query string, fingerprint, header or body.

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ack, call, encode, envelope, FP, goodCert, mustPost, poll, post, resetRelay } from "./helpers";

const EVENTS = new Set(["request", "expired", "store_error", "config_invalid"]);
const REQUEST_FIELDS = ["duration_ms", "event", "method", "peer", "route", "status"];

let lines: string[] = [];

beforeEach(async () => {
  await resetRelay();
  lines = [];
  for (const level of ["log", "info", "warn", "error", "debug"] as const) {
    vi.spyOn(console, level).mockImplementation((...args: unknown[]) => {
      lines.push(args.map(String).join(" "));
    });
  }
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("logs", () => {
  it("never contain envelope content, queries, fingerprints or headers", async () => {
    const e = envelope("peer-a", "peer-b");
    const secretHeader = "headermarker5521";
    await mustPost("peer-a", encode(e));
    await post("peer-a", encode(e)); // duplicate
    await post("peer-a", encode({ ...e, id: envelope("peer-a", "peer-b").id, ts: 1 })); // stale
    await post("peer-a", '{"querymarker":1}');
    await poll("peer-b", "peer-b", 0, 0);
    await call("GET", "/v1/poll?to=peer-b&timeout=0&after=0&x=querymarker", { as: "peer-b" });
    await call("GET", "/v1/poll?to=peer-a&timeout=0", { tls: goodCert(FP.stranger) });
    await call("GET", "/healthz", { headers: { "X-Postern-Client-Cert-Sha256": FP["peer-a"], "X-Other": secretHeader } });
    await call("GET", "/querymarker", { as: "peer-a" });
    await ack("peer-b", e.id, "peer-b");

    expect(lines.length).toBeGreaterThanOrEqual(10);
    const all = lines.join("\n");
    const forbidden = [
      e.box,
      e.box.slice(0, 16),
      e.nonce,
      e.thread,
      "querymarker",
      "timeout=",
      "after=",
      "?",
      FP["peer-a"],
      FP["peer-b"],
      FP.stranger,
      secretHeader,
      "postern.example.com",
    ];
    for (const s of forbidden) expect(all).not.toContain(s);

    for (const line of lines) {
      const rec = JSON.parse(line) as Record<string, unknown>;
      expect(EVENTS.has(rec.event as string)).toBe(true);
      if (rec.event === "request") expect(Object.keys(rec).sort()).toEqual(REQUEST_FIELDS);
    }
    // The peer name and the route pattern are logged, as in the Go relay.
    expect(all).toContain('"route":"POST /v1/msg"');
    expect(all).toContain('"peer":"peer-a"');
  });

  it("log an invalid configuration without its values", async () => {
    const placeholder = "<PEER_A_CERT_SHA256>";
    const r = await call("GET", "/healthz", {
      env: { PEERS: JSON.stringify({ "peer-a": [placeholder], "peer-b": [FP["peer-b"]] }) },
    });
    expect(r.status).toBe(500);
    expect(r.body).toBe('{"error":"internal"}\n');
    expect(lines.join("\n")).toContain('"event":"config_invalid"');
    expect(lines.join("\n")).not.toContain(placeholder);
    expect(lines.join("\n")).not.toContain(FP["peer-b"]);
  });
});
