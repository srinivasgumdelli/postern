// Worker configuration, read from vars and validated before any request
// is served. It follows the Go relay's Config.normalized(): at least two
// peers, valid peer names, every fingerprint 64 hex characters after
// normalizing, and no fingerprint listed twice.

import { validPeerName } from "./envelope";

export const DEFAULT_POSTS_PER_HOUR = 120;
export const DEFAULT_MAX_QUEUED_PER_PEER = 1000;

export interface RelayEnv {
  RELAY: DurableObjectNamespace<import("./relay").Relay>;
  /** The one hostname this relay answers on, e.g. postern.example.com. */
  RELAY_HOSTNAME: string;
  /** JSON object: peer name -> list of client-certificate SHA-256 fingerprints. */
  PEERS: string;
  POSTS_PER_HOUR?: string;
  MAX_QUEUED_PER_PEER?: string;
}

export interface Config {
  hostname: string;
  peers: ReadonlySet<string>;
  peerByFingerprint: ReadonlyMap<string, string>;
  postsPerHour: number;
  maxQueuedPerPeer: number;
}

/** Lower-cases a fingerprint and strips colons and spaces (tlsutil.NormalizeFingerprint). */
export function normalizeFingerprint(s: string): string {
  return s.trim().toLowerCase().replace(/[: ]/g, "");
}

const FINGERPRINT = /^[0-9a-f]{64}$/;
const HOSTNAME = /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/;

function positive(raw: string | undefined, fallback: number, name: string): number {
  if (raw === undefined || raw === "") return fallback;
  if (!/^[0-9]{1,9}$/.test(raw)) throw new Error(`${name} must be a positive integer`);
  const n = Number(raw);
  return n === 0 ? fallback : n;
}

/** Parses and validates the configuration. Error messages never include values. */
export function loadConfig(env: RelayEnv): Config {
  const hostname = (env.RELAY_HOSTNAME ?? "").trim().toLowerCase();
  if (!HOSTNAME.test(hostname)) throw new Error("RELAY_HOSTNAME is not a hostname");

  let parsed: unknown;
  try {
    parsed = JSON.parse(env.PEERS ?? "");
  } catch {
    throw new Error("PEERS is not JSON");
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("PEERS must be an object of peer name to fingerprints");
  }
  const entries = Object.entries(parsed as Record<string, unknown>);
  if (entries.length < 2) throw new Error("PEERS needs at least two peers");

  const peers = new Set<string>();
  const byFP = new Map<string, string>();
  for (const [name, fps] of entries.sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))) {
    if (!validPeerName(name)) throw new Error("PEERS has an invalid peer name");
    if (!Array.isArray(fps) || fps.length === 0) throw new Error("a peer has no certificate fingerprints");
    for (const fp of fps) {
      if (typeof fp !== "string") throw new Error("a fingerprint is not a string");
      const n = normalizeFingerprint(fp);
      if (!FINGERPRINT.test(n)) throw new Error("a fingerprint is not 64 hex characters");
      if (byFP.has(n)) throw new Error("a fingerprint is listed twice");
      byFP.set(n, name);
    }
    peers.add(name);
  }
  return {
    hostname,
    peers,
    peerByFingerprint: byFP,
    postsPerHour: positive(env.POSTS_PER_HOUR, DEFAULT_POSTS_PER_HOUR, "POSTS_PER_HOUR"),
    maxQueuedPerPeer: positive(env.MAX_QUEUED_PER_PEER, DEFAULT_MAX_QUEUED_PER_PEER, "MAX_QUEUED_PER_PEER"),
  };
}

let cached: { key: string; result: Config | Error } | undefined;

/**
 * The validated configuration for env, parsed once per isolate (vars do not
 * change without a redeploy, which starts new isolates). An invalid
 * configuration is cached as an error, so every request fails closed.
 */
export function configFor(env: RelayEnv): Config | Error {
  const key = JSON.stringify([env.RELAY_HOSTNAME, env.PEERS, env.POSTS_PER_HOUR, env.MAX_QUEUED_PER_PEER]);
  if (cached?.key !== key) {
    let result: Config | Error;
    try {
      result = loadConfig(env);
    } catch (e) {
      result = e instanceof Error ? e : new Error("invalid configuration");
    }
    cached = { key, result };
  }
  return cached.result;
}
