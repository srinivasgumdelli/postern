// PEERS and the other vars are validated like the Go relay's config: a
// bad configuration fails every request closed.

import { describe, expect, it } from "vitest";
import { loadConfig, type RelayEnv } from "../src/config";
import { call, FP, testEnv } from "./helpers";

function env(over: Partial<RelayEnv>): RelayEnv {
  return { ...testEnv, ...over };
}

const twoPeers = { "peer-a": [FP["peer-a"]], "peer-b": [FP["peer-b"]] };

describe("config", () => {
  it("accepts the test configuration", () => {
    const c = loadConfig(testEnv);
    expect([...c.peers].sort()).toEqual(["peer-a", "peer-b"]);
    expect(c.peerByFingerprint.get(FP["peer-b-rotated"])).toBe("peer-b");
    expect(c.hostname).toBe("postern.example.com");
    expect(c.postsPerHour).toBe(120);
    expect(c.maxQueuedPerPeer).toBe(1000);
  });

  it("normalizes fingerprints and applies defaults", () => {
    const colon = FP["peer-a"].toUpperCase().match(/../g)!.join(":");
    const c = loadConfig(env({ PEERS: JSON.stringify({ "peer-a": [colon], "peer-b": [FP["peer-b"]] }), POSTS_PER_HOUR: "0", MAX_QUEUED_PER_PEER: "" }));
    expect(c.peerByFingerprint.get(FP["peer-a"])).toBe("peer-a");
    expect(c.postsPerHour).toBe(120);
    expect(c.maxQueuedPerPeer).toBe(1000);
  });

  it("rejects bad configurations", () => {
    const bad: Record<string, Partial<RelayEnv>> = {
      "PEERS not JSON": { PEERS: "peer-a" },
      "PEERS an array": { PEERS: "[]" },
      "one peer": { PEERS: JSON.stringify({ "peer-a": [FP["peer-a"]] }) },
      "bad peer name": { PEERS: JSON.stringify({ ...twoPeers, "Peer C": [FP.stranger] }) },
      "no fingerprints": { PEERS: JSON.stringify({ ...twoPeers, "peer-c": [] }) },
      placeholder: { PEERS: JSON.stringify({ ...twoPeers, "peer-a": ["<PEER_A_CERT_SHA256>"] }) },
      "short fingerprint": { PEERS: JSON.stringify({ ...twoPeers, "peer-a": ["abcd"] }) },
      "fingerprint for two peers": { PEERS: JSON.stringify({ ...twoPeers, "peer-c": [FP["peer-a"]] }) },
      "fingerprint twice": { PEERS: JSON.stringify({ ...twoPeers, "peer-a": [FP["peer-a"], FP["peer-a"].toUpperCase()] }) },
      "fingerprint not a string": { PEERS: JSON.stringify({ ...twoPeers, "peer-a": [1] }) },
      "no hostname": { RELAY_HOSTNAME: "" },
      "hostname with path": { RELAY_HOSTNAME: "postern.example.com/x" },
      "hostname placeholder": { RELAY_HOSTNAME: "<HOSTNAME>" },
      "negative posts": { POSTS_PER_HOUR: "-1" },
      "posts not a number": { POSTS_PER_HOUR: "lots" },
      "queue not a number": { MAX_QUEUED_PER_PEER: "1e3" },
    };
    for (const [name, over] of Object.entries(bad)) {
      expect(() => loadConfig(env(over)), name).toThrow();
    }
  });

  it("fails every request closed when invalid", async () => {
    const broken = { PEERS: "{}" };
    for (const [method, path] of [
      ["GET", "/healthz"],
      ["GET", "/v1/poll?to=peer-a&timeout=0"],
      ["POST", "/v1/msg"],
    ] as const) {
      const r = await call(method, path, { as: "peer-a", env: broken });
      expect(r.status).toBe(500);
      expect(r.body).toBe('{"error":"internal"}\n');
    }
  });
});
