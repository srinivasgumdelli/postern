// The relay's storage and long-poll: one SQLite-backed Durable Object for
// the whole relay (see docs/relay-modes.md for why one and not one per
// mailbox). It mirrors internal/relay/store.go, limits.go and notify.go:
//
//   envelopes  sealed envelopes, canonical JSON, routing columns readable
//   seen_ids   every accepted id for 72 hours, across all mailboxes, so a
//              replay is refused even after the original was acked
//   post_log   per-sender post times for the sliding one-hour rate limit
//
// The Worker in front authenticates the caller and validates the
// envelope; this object only ever receives a peer name the Worker derived
// from the client certificate. It is reachable only through the Worker's
// binding, never from the internet.

import { DurableObject } from "cloudflare:workers";
import { CLOCK_SKEW_MS, RETENTION_SECONDS } from "./envelope";
import { log } from "./log";

export const MAX_POLL_TIMEOUT_SECONDS = 25;
export const MAX_POLL_BATCH = 50;
export const MAX_POLLERS_PER_PEER = 16;
const RATE_WINDOW_MS = 60 * 60 * 1000;
const INT64_MAX = 9223372036854775807n;

/**
 * Symbol-keyed hook for tests to shift this object's clock. Symbol keys
 * are not exposed over RPC, so nothing outside the isolate can reach it.
 */
export const CLOCK_OFFSET = Symbol("clockOffsetMs");

const SCHEMA = `
CREATE TABLE IF NOT EXISTS envelopes (
  seq         INTEGER PRIMARY KEY AUTOINCREMENT,
  id          TEXT    NOT NULL UNIQUE,
  from_peer   TEXT    NOT NULL,
  to_peer     TEXT    NOT NULL,
  thread      TEXT    NOT NULL,
  ts          TEXT    NOT NULL,
  received_at INTEGER NOT NULL,
  raw         TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS envelopes_to_seq ON envelopes (to_peer, seq);
CREATE INDEX IF NOT EXISTS envelopes_received_at ON envelopes (received_at);
CREATE TABLE IF NOT EXISTS seen_ids (
  id      TEXT    PRIMARY KEY,
  seen_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS seen_ids_seen_at ON seen_ids (seen_at);
CREATE TABLE IF NOT EXISTS post_log (
  peer  TEXT    NOT NULL,
  at_ms INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS post_log_peer_at ON post_log (peer, at_ms);
`;

export interface PostInput {
  id: string;
  from: string;
  to: string;
  thread: string;
  /** Unix seconds as a decimal string (int64 range). */
  ts: string;
  /** Canonical JSON of the envelope. */
  raw: string;
}

export interface Limits {
  postsPerHour: number;
  maxQueuedPerPeer: number;
}

export type PostResult = "created" | "stale" | "duplicate" | "rate_limited" | "queue_full";

export type PollResult = { envelopes: string[]; cursor: string } | "rate_limited";

interface Waiter {
  promise: Promise<void>;
  resolve: () => void;
}

export class Relay extends DurableObject {
  private readonly sql: SqlStorage;
  private readonly waiters = new Map<string, Waiter>();
  private readonly pollers = new Map<string, number>();
  [CLOCK_OFFSET] = 0;

  constructor(ctx: DurableObjectState, env: unknown) {
    super(ctx, env as never);
    this.sql = ctx.storage.sql;
    this.sql.exec(SCHEMA);
  }

  private nowMs(): number {
    return Date.now() + this[CLOCK_OFFSET];
  }

  /** Stores an envelope. The checks run in the Go relay's order. */
  async post(e: PostInput, limits: Limits): Promise<PostResult> {
    const now = this.nowMs();
    // +/-10 minutes, as envelope.CheckTime(ts, now, ClockSkew).
    const tsMs = BigInt(e.ts) * 1000n;
    if (tsMs > BigInt(now + CLOCK_SKEW_MS) || tsMs < BigInt(now - CLOCK_SKEW_MS)) return "stale";

    // Everything from here to the insert is synchronous, so no other
    // request can interleave (the Go relay holds postMu for the same span).
    const result = this.ctx.storage.transactionSync((): PostResult => {
      if (this.sql.exec("SELECT 1 FROM seen_ids WHERE id = ?", e.id).toArray().length > 0) return "duplicate";

      // Sliding one-hour window per sender. A rejected post is not
      // recorded; an accepted one is, even if the queue then turns out full.
      this.sql.exec("DELETE FROM post_log WHERE peer = ? AND at_ms <= ?", e.from, now - RATE_WINDOW_MS);
      const posts = this.sql.exec<{ n: number }>("SELECT COUNT(*) AS n FROM post_log WHERE peer = ?", e.from).one().n;
      if (posts >= limits.postsPerHour) return "rate_limited";
      this.sql.exec("INSERT INTO post_log (peer, at_ms) VALUES (?, ?)", e.from, now);

      const queued = this.sql.exec<{ n: number }>("SELECT COUNT(*) AS n FROM envelopes WHERE to_peer = ?", e.to).one().n;
      if (queued >= limits.maxQueuedPerPeer) return "queue_full";

      const nowSec = Math.floor(now / 1000);
      this.sql.exec(
        "INSERT INTO envelopes (id, from_peer, to_peer, thread, ts, received_at, raw) VALUES (?, ?, ?, ?, ?, ?, ?)",
        e.id, e.from, e.to, e.thread, e.ts, nowSec, e.raw,
      );
      this.sql.exec("INSERT INTO seen_ids (id, seen_at) VALUES (?, ?)", e.id, nowSec);
      return "created";
    });
    if (result === "created") {
      this.wake(e.to);
      await this.scheduleExpiry();
    }
    return result;
  }

  /**
   * Long-polls peer's mailbox: returns at once if anything is pending after
   * the cursor, otherwise waits up to timeoutSeconds for a new envelope.
   */
  async poll(peer: string, after: string, timeoutSeconds: number): Promise<PollResult> {
    const inUse = this.pollers.get(peer) ?? 0;
    if (inUse >= MAX_POLLERS_PER_PEER) return "rate_limited";
    this.pollers.set(peer, inUse + 1);
    try {
      const afterN = BigInt(after);
      const timeout = Math.min(Math.max(timeoutSeconds, 0), MAX_POLL_TIMEOUT_SECONDS) * 1000;
      const deadline = Date.now() + timeout;
      for (;;) {
        // Take the waiter before querying, so an envelope stored after the
        // query always resolves a promise this poller already holds.
        const wake = this.waiterFor(peer).promise;
        const envs = this.pending(peer, afterN);
        if (envs.length > 0 || timeout === 0) return this.pollResult(envs, afterN);
        const remaining = deadline - Date.now();
        if (remaining <= 0) return this.pollResult([], afterN);
        let timer: ReturnType<typeof setTimeout> | undefined;
        const timedOut = await Promise.race([
          wake.then(() => false),
          new Promise<boolean>((resolve) => {
            timer = setTimeout(() => resolve(true), remaining);
          }),
        ]);
        if (timer !== undefined) clearTimeout(timer);
        if (timedOut) return this.pollResult([], afterN);
      }
    } finally {
      const n = (this.pollers.get(peer) ?? 1) - 1;
      if (n <= 0) this.pollers.delete(peer);
      else this.pollers.set(peer, n);
    }
  }

  /** Deletes envelope id from peer's mailbox. Its id stays in seen_ids. */
  async ack(peer: string, id: string): Promise<boolean> {
    return this.sql.exec("DELETE FROM envelopes WHERE id = ? AND to_peer = ?", id, peer).rowsWritten > 0;
  }

  async ping(): Promise<boolean> {
    return this.sql.exec<{ one: number }>("SELECT 1 AS one").one().one === 1;
  }

  /** Expiry: deletes envelopes and seen ids older than 72 hours. */
  override async alarm(): Promise<void> {
    this.expire();
    await this.scheduleExpiry(true);
  }

  private expire(): void {
    const now = this.nowMs();
    const cutoff = Math.floor(now / 1000) - RETENTION_SECONDS;
    const n = this.sql.exec("DELETE FROM envelopes WHERE received_at < ?", cutoff).rowsWritten;
    const m = this.sql.exec("DELETE FROM seen_ids WHERE seen_at < ?", cutoff).rowsWritten;
    this.sql.exec("DELETE FROM post_log WHERE at_ms <= ?", now - RATE_WINDOW_MS);
    if (n > 0 || m > 0) log("expired", { envelopes: n, ids: m });
  }

  /**
   * Sets the alarm for the moment the oldest row passes retention. Rows
   * past retention are also filtered out at query time, so a late alarm
   * never serves an expired envelope.
   */
  private async scheduleExpiry(force = false): Promise<void> {
    if (!force && (await this.ctx.storage.getAlarm()) !== null) return;
    const row = this.sql
      .exec<{ oldest: number | null }>(
        "SELECT MIN(t) AS oldest FROM (SELECT MIN(received_at) AS t FROM envelopes UNION ALL SELECT MIN(seen_at) FROM seen_ids)",
      )
      .one();
    if (row.oldest === null) {
      await this.ctx.storage.deleteAlarm();
      return;
    }
    const due = (row.oldest + RETENTION_SECONDS + 1) * 1000 - this[CLOCK_OFFSET];
    await this.ctx.storage.setAlarm(Math.max(due, Date.now()));
  }

  private pending(peer: string, after: bigint): { seq: number; raw: string }[] {
    const notBefore = Math.floor(this.nowMs() / 1000) - RETENTION_SECONDS;
    // No seq ever gets near 2^53; clamp so a huge cursor still binds as an integer.
    const afterBind = after > BigInt(Number.MAX_SAFE_INTEGER) ? Number.MAX_SAFE_INTEGER : Number(after);
    return this.sql
      .exec<{ seq: number; raw: string }>(
        "SELECT seq, raw FROM envelopes WHERE to_peer = ? AND seq > ? AND received_at >= ? ORDER BY seq LIMIT ?",
        peer, afterBind, notBefore, MAX_POLL_BATCH,
      )
      .toArray();
  }

  private pollResult(envs: { seq: number; raw: string }[], after: bigint): PollResult {
    let cursor = after;
    for (const e of envs) if (BigInt(e.seq) > cursor) cursor = BigInt(e.seq);
    if (cursor > INT64_MAX) cursor = INT64_MAX;
    return { envelopes: envs.map((e) => e.raw), cursor: cursor.toString() };
  }

  private waiterFor(peer: string): Waiter {
    let w = this.waiters.get(peer);
    if (!w) {
      let resolve!: () => void;
      const promise = new Promise<void>((r) => (resolve = r));
      w = { promise, resolve };
      this.waiters.set(peer, w);
    }
    return w;
  }

  /** Wakes every poller waiting on peer's mailbox. */
  private wake(peer: string): void {
    const w = this.waiters.get(peer);
    if (w) {
      this.waiters.delete(peer);
      w.resolve();
    }
  }
}
