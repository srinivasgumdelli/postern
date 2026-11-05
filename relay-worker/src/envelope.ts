// Outer envelope validation, equivalent to envelope.ParseEnvelope and
// Envelope.ValidateOuter in the Go code (internal/envelope). The relay
// never opens the box; it checks only the readable routing fields.
// testdata/conformance/envelopes.json holds the cases both must agree on.

import { parseFlatObject, type Scalar } from "./json";

export const VERSION = 1;
export const MAX_ENVELOPE_BYTES = 48 * 1024;
export const CLOCK_SKEW_MS = 10 * 60 * 1000;
export const RETENTION_SECONDS = 72 * 60 * 60;
const NONCE_SIZE = 24;
const BOX_OVERHEAD = 16; // NaCl box (Poly1305 tag)
const INT64_MAX = 9223372036854775807n;

export interface Envelope {
  v: 1;
  id: string;
  from: string;
  to: string;
  thread: string;
  /** Unix seconds. A bigint so the full int64 range survives re-encoding. */
  ts: bigint;
  nonce: string;
  box: string;
}

export type ParseResult =
  | { ok: true; envelope: Envelope; canonical: string }
  | { ok: false; error: "invalid" | "too_large" };

const ULID_CHARS = /^[0-9A-HJKMNP-TV-Z]{26}$/;
const NAME = /^[a-z0-9][a-z0-9-]{0,31}$/;
const THREAD = /^t-[0-9A-HJKMNP-TV-Z]{26}$/;
const KEYS = ["v", "id", "from", "to", "thread", "ts", "nonce", "box"] as const;

/** A canonical upper-case ULID whose value fits in 128 bits. */
export function validULID(s: string): boolean {
  return ULID_CHARS.test(s) && s[0]! >= "0" && s[0]! <= "7";
}

export function validPeerName(s: string): boolean {
  return NAME.test(s);
}

export function validThreadID(s: string): boolean {
  return THREAD.test(s) && validULID(s.slice(2));
}

const B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const B64_INDEX = new Map([...B64].map((c, i) => [c, i]));

/**
 * The decoded length of s under Go's base64.StdEncoding.Strict(), or -1 if
 * Go would reject it: standard alphabet, padding required, unused bits
 * zero. Like Go, CR and LF are ignored anywhere.
 */
export function strictBase64Length(s: string): number {
  s = s.replace(/[\r\n]/g, "");
  if (s.length % 4 !== 0) return -1;
  let pad = 0;
  if (s.endsWith("==")) pad = 2;
  else if (s.endsWith("=")) pad = 1;
  const data = s.length - pad;
  for (let i = 0; i < data; i++) {
    if (!B64_INDEX.has(s[i]!)) return -1;
  }
  if (pad > 0) {
    const last = B64_INDEX.get(s[data - 1]!)!;
    const unused = pad === 1 ? 0b11 : 0b1111;
    if ((last & unused) !== 0) return -1;
  }
  return (s.length / 4) * 3 - pad;
}

function utf8Length(s: string): number {
  return new TextEncoder().encode(s).length;
}

function str(v: Scalar | undefined): string | null {
  return v?.kind === "string" ? v.value : null;
}

/**
 * Parses and validates one envelope from the raw request bytes. On success
 * it also returns the canonical encoding (what Go's json.Marshal produces
 * for the same envelope), which is what the relay stores and serves.
 */
export function parseEnvelope(bytes: Uint8Array): ParseResult {
  if (bytes.length > MAX_ENVELOPE_BYTES) return { ok: false, error: "too_large" };
  const invalid = { ok: false, error: "invalid" } as const;
  // ignoreBOM keeps a leading BOM in the text, so the parser rejects it as
  // encoding/json does. Invalid UTF-8 becomes U+FFFD, also as in Go.
  const text = new TextDecoder("utf-8", { fatal: false, ignoreBOM: true }).decode(bytes);
  const obj = parseFlatObject(text);
  if (obj === null || obj.size !== KEYS.length) return invalid;
  for (const k of KEYS) if (!obj.has(k)) return invalid;

  const v = obj.get("v")!;
  if (v.kind !== "number" || v.literal !== String(VERSION)) return invalid;
  const tsv = obj.get("ts")!;
  // Go decodes ts into an int64: an integer literal in range, and it must be > 0.
  if (tsv.kind !== "number" || !/^[1-9][0-9]*$/.test(tsv.literal)) return invalid;
  const ts = BigInt(tsv.literal);
  if (ts > INT64_MAX) return invalid;

  const id = str(obj.get("id"));
  const from = str(obj.get("from"));
  const to = str(obj.get("to"));
  const thread = str(obj.get("thread"));
  const nonce = str(obj.get("nonce"));
  const box = str(obj.get("box"));
  if (id === null || from === null || to === null || thread === null || nonce === null || box === null) {
    return invalid;
  }

  // ValidateOuter, in the same order.
  if (!validULID(id)) return invalid;
  if (!validPeerName(from) || !validPeerName(to)) return invalid;
  if (from === to) return invalid;
  if (!validThreadID(thread)) return invalid;
  if (strictBase64Length(nonce) !== NONCE_SIZE) return invalid;
  if (utf8Length(box) > MAX_ENVELOPE_BYTES) return { ok: false, error: "too_large" };
  if (strictBase64Length(box) < BOX_OVERHEAD + 4) return invalid;

  const envelope: Envelope = { v: VERSION, id, from, to, thread, ts, nonce, box };
  return { ok: true, envelope, canonical: canonicalJSON(envelope) };
}

/**
 * The envelope as Go's json.Marshal writes it: fixed key order, no
 * whitespace. Every string has passed validation (ASCII, plus CR or LF in
 * base64), and JSON.stringify escapes those exactly as Go does.
 */
export function canonicalJSON(e: Envelope): string {
  const q = JSON.stringify;
  return (
    `{"v":${e.v},"id":${q(e.id)},"from":${q(e.from)},"to":${q(e.to)},` +
    `"thread":${q(e.thread)},"ts":${e.ts.toString()},"nonce":${q(e.nonce)},"box":${q(e.box)}}`
  );
}
