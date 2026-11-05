// Test helpers: requests with an injected edge mTLS result, envelopes
// with valid routing fields (the relay never opens the box, so random
// nonce and ciphertext bytes of the right size stand in for a real seal),
// and access to the Durable Object's clock and tables.

import { env, runInDurableObject } from "cloudflare:test";
import worker, { type Relay } from "../src/index";
import type { RelayEnv } from "../src/config";
import { CLOCK_OFFSET } from "../src/relay";

export const HOST = "https://postern.example.com";

// Fixed fingerprints from test/wrangler.test.jsonc.
export const FP = {
  "peer-a": "a".repeat(64),
  "peer-b": "b".repeat(64),
  "peer-b-rotated": "b2".repeat(32),
  stranger: "c".repeat(64),
} as const;

export type Peer = "peer-a" | "peer-b";

export const testEnv = env as unknown as RelayEnv;

/** What the edge reports for a verified, unrevoked client certificate. */
export function goodCert(fingerprint: string): Record<string, string> {
  return {
    certPresented: "1",
    certVerified: "SUCCESS",
    certRevoked: "0",
    certFingerprintSHA256: fingerprint,
    certFingerprintSHA1: "",
    certIssuerDN: "CN=test-ca",
    certSubjectDN: "CN=test",
    certNotBefore: "",
    certNotAfter: "",
    certSerial: "",
  };
}

export interface CallOptions {
  /** Peer whose certificate the edge reports; omit for no certificate. */
  as?: Peer;
  /** Explicit tlsClientAuth (overrides as). null means the field is absent. */
  tls?: Record<string, string> | null;
  body?: string | Uint8Array;
  headers?: Record<string, string>;
  env?: Partial<RelayEnv>;
  url?: string;
}

export interface Result {
  status: number;
  body: string;
  headers: Headers;
}

export async function call(method: string, path: string, opts: CallOptions = {}): Promise<Result> {
  let tls: Record<string, string> | null = null;
  if (opts.tls !== undefined) tls = opts.tls;
  else if (opts.as) tls = goodCert(FP[opts.as]);
  const cf = tls === null ? {} : { tlsClientAuth: tls };
  const req = new Request(opts.url ?? HOST + path, {
    method,
    body: opts.body,
    headers: opts.headers,
    cf,
  } as RequestInit);
  const res = await worker.fetch(req, { ...testEnv, ...opts.env });
  return { status: res.status, body: await res.text(), headers: res.headers };
}

export function expectError(r: Result, status: number, code: string): void {
  if (r.status !== status || r.body !== JSON.stringify({ error: code }) + "\n") {
    throw new Error(`got ${r.status} ${r.body.trim()}, want ${status} ${code}`);
  }
}

// --- envelopes ---

const CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

export function ulid(ms = Date.now()): string {
  const bytes = new Uint8Array(16);
  let t = BigInt(ms);
  for (let i = 5; i >= 0; i--) {
    bytes[i] = Number(t & 0xffn);
    t >>= 8n;
  }
  crypto.getRandomValues(bytes.subarray(6));
  let n = 0n;
  for (const b of bytes) n = (n << 8n) | BigInt(b);
  let out = "";
  for (let i = 0; i < 26; i++) {
    out = CROCKFORD[Number(n & 31n)] + out;
    n >>= 5n;
  }
  return out;
}

function b64(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

function randomBytes(n: number): Uint8Array {
  const b = new Uint8Array(n);
  for (let off = 0; off < n; off += 65536) crypto.getRandomValues(b.subarray(off, Math.min(n, off + 65536)));
  return b;
}

export interface TestEnvelope {
  v: number;
  id: string;
  from: string;
  to: string;
  thread: string;
  ts: number;
  nonce: string;
  box: string;
}

/** An envelope with valid outer fields and a random stand-in box. */
export function envelope(from: string, to: string, over: Partial<TestEnvelope> = {}, nowMs = Date.now()): TestEnvelope {
  return {
    v: 1,
    id: ulid(nowMs),
    from,
    to,
    thread: "t-" + ulid(nowMs),
    ts: Math.floor(nowMs / 1000),
    nonce: b64(randomBytes(24)),
    box: b64(randomBytes(120)),
    ...over,
  };
}

/** Field order and encoding of Go's json.Marshal. */
export function encode(e: TestEnvelope): string {
  return JSON.stringify({ v: e.v, id: e.id, from: e.from, to: e.to, thread: e.thread, ts: e.ts, nonce: e.nonce, box: e.box });
}

export function post(as: Peer, raw: string, opts: CallOptions = {}): Promise<Result> {
  return call("POST", "/v1/msg", { as, body: raw, headers: { "Content-Type": "application/json" }, ...opts });
}

export async function mustPost(as: Peer, raw: string, opts: CallOptions = {}): Promise<void> {
  const r = await post(as, raw, opts);
  if (r.status !== 201) throw new Error(`post: ${r.status} ${r.body.trim()}`);
}

export interface PollResult {
  status: number;
  envelopes: string[];
  cursor: number;
  body: string;
}

/** Polls and returns each envelope's raw JSON text, as the relay sent it. */
export async function poll(as: Peer, to: string, after = 0, timeout = 0): Promise<PollResult> {
  const r = await call("GET", `/v1/poll?to=${to}&after=${after}&timeout=${timeout}`, { as });
  if (r.status !== 200) return { status: r.status, envelopes: [], cursor: -1, body: r.body };
  const m = /^\{"envelopes":\[(.*)\],"cursor":(\d+)\}\n$/s.exec(r.body);
  if (!m) throw new Error("unexpected poll body shape");
  const inner = m[1]!;
  const envelopes = inner === "" ? [] : splitTopLevel(inner);
  return { status: 200, envelopes, cursor: Number(m[2]), body: r.body };
}

// Splits "{...},{...}" into objects. Envelope JSON holds no braces inside strings.
function splitTopLevel(s: string): string[] {
  const out: string[] = [];
  let depth = 0;
  let start = 0;
  for (let i = 0; i < s.length; i++) {
    if (s[i] === "{") depth++;
    else if (s[i] === "}" && --depth === 0) {
      out.push(s.slice(start, i + 1));
      start = i + 2;
    }
  }
  return out;
}

export function ack(as: Peer, id: string, to: string): Promise<Result> {
  return call("POST", `/v1/ack/${id}`, { as, body: JSON.stringify({ to }) });
}

// --- the Durable Object ---

export function relayStub(): DurableObjectStub<Relay> {
  return testEnv.RELAY.get(testEnv.RELAY.idFromName("relay"));
}

/** The Durable Object's current time (real time plus the test offset). */
export async function relayNow(): Promise<number> {
  return runInDurableObject(relayStub(), (inst: Relay) => Date.now() + inst[CLOCK_OFFSET]);
}

/** Moves the Durable Object's clock forward by ms. */
export async function advance(ms: number): Promise<void> {
  await runInDurableObject(relayStub(), (inst: Relay) => {
    inst[CLOCK_OFFSET] += ms;
  });
}

/** Sets the Durable Object's clock so that now is atMs. */
export async function setClock(atMs: number): Promise<void> {
  await runInDurableObject(relayStub(), (inst: Relay) => {
    inst[CLOCK_OFFSET] = atMs - Date.now();
  });
}

export async function counts(): Promise<{ envelopes: number; ids: number }> {
  return runInDurableObject(relayStub(), (_inst: Relay, state) => {
    const sql = state.storage.sql;
    return {
      envelopes: sql.exec<{ n: number }>("SELECT COUNT(*) AS n FROM envelopes").one().n,
      ids: sql.exec<{ n: number }>("SELECT COUNT(*) AS n FROM seen_ids").one().n,
    };
  });
}

/** Empties every table and resets the clock, between tests. */
export async function resetRelay(): Promise<void> {
  await runInDurableObject(relayStub(), async (inst: Relay, state) => {
    inst[CLOCK_OFFSET] = 0;
    state.storage.sql.exec("DELETE FROM envelopes; DELETE FROM seen_ids; DELETE FROM post_log;");
    await state.storage.deleteAlarm();
  });
}

export function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}
