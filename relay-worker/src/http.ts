// HTTP helpers that reproduce the Go relay's wire behaviour: response
// bodies and headers, Go's query parsing (net/url.ParseQuery) and integer
// parsing (strconv.ParseInt), and the canonical-path rule.

const INT64_MIN = -9223372036854775808n;
const INT64_MAX = 9223372036854775807n;

const BASE_HEADERS = {
  "Cache-Control": "no-store",
  "X-Content-Type-Options": "nosniff",
};

/** A JSON response. body is written as-is, with Go's trailing newline. */
export function jsonResponse(status: number, body: string, extra: Record<string, string> = {}): Response {
  return new Response(body + "\n", {
    status,
    headers: { ...BASE_HEADERS, "Content-Type": "application/json", ...extra },
  });
}

/** {"error":code}. Codes are fixed strings; nothing from the request is echoed. */
export function errorResponse(status: number, code: string, extra: Record<string, string> = {}): Response {
  return jsonResponse(status, JSON.stringify({ error: code }), extra);
}

export function textResponse(status: number, body: string): Response {
  return new Response(body, {
    status,
    headers: { ...BASE_HEADERS, "Content-Type": "text/plain; charset=utf-8" },
  });
}

/** path.Clean(p) === p for a path that starts with "/". */
export function isCleanPath(p: string): boolean {
  if (p === "/") return true;
  if (!p.startsWith("/") || p.endsWith("/")) return false;
  return p
    .slice(1)
    .split("/")
    .every((seg) => seg !== "" && seg !== "." && seg !== "..");
}

/** url.QueryUnescape: "+" is a space, every "%" needs two hex digits. */
function queryUnescape(s: string): string | null {
  if (/%(?![0-9a-fA-F]{2})/.test(s)) return null;
  const bytes: number[] = [];
  for (let i = 0; i < s.length; i++) {
    const c = s[i]!;
    if (c === "%") {
      bytes.push(parseInt(s.slice(i + 1, i + 3), 16));
      i += 2;
    } else if (c === "+") {
      bytes.push(0x20);
    } else {
      for (const b of new TextEncoder().encode(c)) bytes.push(b);
    }
  }
  return new TextDecoder().decode(new Uint8Array(bytes));
}

/**
 * The first value of key in a raw query string, as Go's
 * r.URL.Query().Get(key): pairs containing ";" or a bad escape are
 * skipped, a missing key is "".
 */
export function queryGet(rawQuery: string, key: string): string {
  for (const part of rawQuery.split("&")) {
    if (part === "" || part.includes(";")) continue;
    const eq = part.indexOf("=");
    const k = queryUnescape(eq < 0 ? part : part.slice(0, eq));
    const v = queryUnescape(eq < 0 ? "" : part.slice(eq + 1));
    if (k === null || v === null) continue;
    if (k === key) return v;
  }
  return "";
}

/** strconv.ParseInt(s, 10, 64): optional sign, decimal digits, int64 range. */
export function parseInt64(s: string): bigint | null {
  if (!/^[+-]?[0-9]+$/.test(s)) return null;
  const n = BigInt(s);
  return n < INT64_MIN || n > INT64_MAX ? null : n;
}

export type BodyResult = Uint8Array | "too_large" | "error";

/** Reads at most limit bytes of the request body (http.MaxBytesReader). */
export async function readBody(request: Request, limit: number): Promise<BodyResult> {
  const declared = request.headers.get("Content-Length");
  if (declared !== null && /^[0-9]+$/.test(declared) && Number(declared) > limit) return "too_large";
  if (request.body === null) return new Uint8Array(0);
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > limit) {
        await reader.cancel().catch(() => {});
        return "too_large";
      }
      chunks.push(value);
    }
  } catch {
    return "error";
  }
  const out = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    out.set(c, off);
    off += c.byteLength;
  }
  return out;
}
