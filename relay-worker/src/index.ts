// Postern relay as a Cloudflare Worker. Same HTTP API, status codes and
// error bodies as the Go relay (internal/relay), so a bridge works against
// either without changes.
//
// Identity comes straight from the edge's mTLS check (request.cf.tlsClientAuth):
// a verified, unrevoked client certificate whose SHA-256 fingerprint is
// listed in PEERS. No header is ever trusted for identity, so there is no
// edge secret and no forwarded fingerprint header in this mode.

import { configFor, normalizeFingerprint, type Config, type RelayEnv } from "./config";
import { MAX_ENVELOPE_BYTES, parseEnvelope, validULID } from "./envelope";
import { errorResponse, isCleanPath, jsonResponse, parseInt64, queryGet, readBody, textResponse } from "./http";
import { parseFlatObject } from "./json";
import { log } from "./log";
import { MAX_POLL_TIMEOUT_SECONDS, type Relay } from "./relay";

export { Relay } from "./relay";

const MAX_ACK_BODY_BYTES = 1024;
/** The single Durable Object that holds every mailbox. */
const RELAY_OBJECT_NAME = "relay";

interface RequestInfo {
  /** Route pattern for the log, as Go's r.Pattern. */
  route: string;
  /** Authenticated peer, for the log. */
  peer: string;
}

export default {
  async fetch(request: Request, env: RelayEnv): Promise<Response> {
    const start = Date.now();
    const info: RequestInfo = { route: "", peer: "" };
    let res: Response;
    try {
      res = await handle(request, env, info);
    } catch {
      log("store_error", { op: "handler" });
      res = errorResponse(500, "internal");
    }
    log("request", {
      method: logMethod(request.method),
      route: info.route,
      status: res.status,
      duration_ms: Date.now() - start,
      peer: info.peer,
    });
    if (request.method === "HEAD") {
      return new Response(null, { status: res.status, headers: res.headers });
    }
    return res;
  },
} satisfies ExportedHandler<RelayEnv>;

type Endpoint = "msg" | "poll" | "ack" | "healthz";

const ROUTES: Record<Endpoint, { pattern: string; methodPattern: string; allow: string }> = {
  msg: { pattern: "/v1/msg", methodPattern: "POST /v1/msg", allow: "POST" },
  poll: { pattern: "/v1/poll", methodPattern: "GET /v1/poll", allow: "GET, HEAD" },
  ack: { pattern: "/v1/ack/{id}", methodPattern: "POST /v1/ack/{id}", allow: "POST" },
  healthz: { pattern: "/healthz", methodPattern: "GET /healthz", allow: "GET, HEAD" },
};

function match(segs: string[]): Endpoint | null {
  if (segs.length === 1 && segs[0] === "healthz") return "healthz";
  if (segs[0] !== "v1") return null;
  if (segs.length === 2 && segs[1] === "msg") return "msg";
  if (segs.length === 2 && segs[1] === "poll") return "poll";
  if (segs.length === 3 && segs[1] === "ack" && segs[2] !== "") return "ack";
  return null;
}

function methodAllowed(ep: Endpoint, method: string): boolean {
  return ROUTES[ep].allow === "POST" ? method === "POST" : method === "GET" || method === "HEAD";
}

async function handle(request: Request, env: RelayEnv, info: RequestInfo): Promise<Response> {
  const cfg = configFor(env);
  if (cfg instanceof Error) {
    log("config_invalid");
    return errorResponse(500, "internal");
  }

  // Defence in depth: answer only on the configured hostname, over HTTPS.
  // The workers.dev and preview URLs are disabled in wrangler.toml.example.
  const url = new URL(request.url);
  if (url.protocol !== "https:" || url.hostname !== cfg.hostname || url.port !== "") {
    info.route = "/";
    return errorResponse(404, "not_found");
  }

  // Non-canonical paths get a plain 404, never a redirect that echoes them.
  let segs: string[];
  try {
    if (!isCleanPath(decodeURIComponent(url.pathname))) throw new Error();
    segs = url.pathname.slice(1).split("/").map(decodeURIComponent);
  } catch {
    info.route = "/";
    return errorResponse(404, "not_found");
  }
  const ep = match(segs);
  if (ep === null) {
    info.route = "/";
    return errorResponse(404, "not_found");
  }
  if (!methodAllowed(ep, request.method)) {
    info.route = ROUTES[ep].pattern;
    return errorResponse(405, "method_not_allowed", { Allow: ROUTES[ep].allow });
  }
  info.route = ROUTES[ep].methodPattern;
  const relay = () => env.RELAY.get(env.RELAY.idFromName(RELAY_OBJECT_NAME));

  if (ep === "healthz") return health(relay());

  const auth = authenticate(request, cfg);
  if (auth instanceof Response) return auth;
  info.peer = auth;

  switch (ep) {
    case "msg":
      return handlePost(request, cfg, auth, relay());
    case "poll":
      return handlePoll(url, auth, relay());
    case "ack":
      return handleAck(request, auth, segs[2]!, relay());
  }
}

/**
 * Maps the request's client certificate to a peer. 401 when the edge
 * reports no usable certificate (none presented, not verified, or revoked),
 * 403 when a verified certificate belongs to no configured peer.
 *
 * Field values per Cloudflare's client certificate variables docs:
 * certPresented "1"/"0", certVerified "SUCCESS" / "NONE" / "FAILED:<reason>",
 * certRevoked "1"/"0". All three must say "good"; anything else, including
 * a missing tlsClientAuth (no mTLS on the hostname), is no identity.
 */
function authenticate(request: Request, cfg: Config): string | Response {
  const tls = request.cf?.tlsClientAuth as Record<string, unknown> | null | undefined;
  if (!tls || tls.certPresented !== "1" || tls.certVerified !== "SUCCESS" || tls.certRevoked !== "0") {
    return errorResponse(401, "no_identity");
  }
  const fp = typeof tls.certFingerprintSHA256 === "string" ? normalizeFingerprint(tls.certFingerprintSHA256) : "";
  const peer = cfg.peerByFingerprint.get(fp);
  if (peer === undefined) return errorResponse(403, "forbidden");
  return peer;
}

async function handlePost(request: Request, cfg: Config, peer: string, relay: DurableObjectStub<Relay>): Promise<Response> {
  const body = await readBody(request, MAX_ENVELOPE_BYTES);
  if (body === "too_large") return errorResponse(413, "too_large");
  if (body === "error") return errorResponse(400, "invalid");
  const parsed = parseEnvelope(body);
  if (!parsed.ok) {
    return parsed.error === "too_large" ? errorResponse(413, "too_large") : errorResponse(400, "invalid");
  }
  const e = parsed.envelope;
  if (e.from !== peer) return errorResponse(403, "forbidden");
  if (!cfg.peers.has(e.to)) return errorResponse(400, "invalid");

  let result;
  try {
    result = await relay.post(
      { id: e.id, from: e.from, to: e.to, thread: e.thread, ts: e.ts.toString(), raw: parsed.canonical },
      { postsPerHour: cfg.postsPerHour, maxQueuedPerPeer: cfg.maxQueuedPerPeer },
    );
  } catch {
    log("store_error", { op: "insert" });
    return errorResponse(500, "internal");
  }
  switch (result) {
    case "created":
      return jsonResponse(201, JSON.stringify({ id: e.id }));
    case "stale":
      return errorResponse(422, "stale");
    case "duplicate":
      return errorResponse(409, "duplicate");
    case "rate_limited":
      return errorResponse(429, "rate_limited");
    case "queue_full":
      return errorResponse(429, "queue_full");
  }
}

async function handlePoll(url: URL, peer: string, relay: DurableObjectStub<Relay>): Promise<Response> {
  const query = url.search.startsWith("?") ? url.search.slice(1) : url.search;
  if (queryGet(query, "to") !== peer) return errorResponse(403, "forbidden");
  let after = 0n;
  const afterRaw = queryGet(query, "after");
  if (afterRaw !== "") {
    const n = parseInt64(afterRaw);
    if (n === null || n < 0n) return errorResponse(400, "invalid");
    after = n;
  }
  let timeout = MAX_POLL_TIMEOUT_SECONDS;
  const timeoutRaw = queryGet(query, "timeout");
  if (timeoutRaw !== "") {
    const n = parseInt64(timeoutRaw);
    if (n === null) return errorResponse(400, "invalid");
    timeout = Number(n < 0n ? 0n : n > BigInt(MAX_POLL_TIMEOUT_SECONDS) ? BigInt(MAX_POLL_TIMEOUT_SECONDS) : n);
  }

  let result;
  try {
    result = await relay.poll(peer, after.toString(), timeout);
  } catch {
    log("store_error", { op: "pending" });
    return errorResponse(500, "internal");
  }
  if (result === "rate_limited") return errorResponse(429, "rate_limited");
  // The stored envelopes are canonical JSON already; embed them verbatim.
  return jsonResponse(200, `{"envelopes":[${result.envelopes.join(",")}],"cursor":${result.cursor}}`);
}

async function handleAck(request: Request, peer: string, id: string, relay: DurableObjectStub<Relay>): Promise<Response> {
  const body = await readBody(request, MAX_ACK_BODY_BYTES);
  if (body === "too_large") return errorResponse(413, "too_large");
  if (body === "error") return errorResponse(400, "invalid");
  const obj = parseFlatObject(new TextDecoder("utf-8", { fatal: false, ignoreBOM: true }).decode(body), true);
  if (obj === null) return errorResponse(400, "invalid");
  let to = "";
  for (const [k, v] of obj) {
    if (k !== "to") return errorResponse(400, "invalid");
    if (v.kind === "string") to = v.value;
    else if (v.kind !== "null") return errorResponse(400, "invalid");
  }
  if (to !== peer) return errorResponse(403, "forbidden");
  if (!validULID(id)) return errorResponse(400, "invalid");

  let deleted;
  try {
    deleted = await relay.ack(peer, id);
  } catch {
    log("store_error", { op: "ack" });
    return errorResponse(500, "internal");
  }
  if (!deleted) return errorResponse(404, "not_found");
  return jsonResponse(200, JSON.stringify({ ok: true }));
}

async function health(relay: DurableObjectStub<Relay>): Promise<Response> {
  try {
    if (await relay.ping()) return textResponse(200, "ok");
  } catch {
    // fall through
  }
  return textResponse(503, "unavailable");
}

function logMethod(m: string): string {
  return ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "CONNECT", "TRACE"].includes(m) ? m : "OTHER";
}
