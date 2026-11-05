// A strict parser for the only JSON the relay accepts: one flat object
// whose values are strings, numbers, true, false or null. It mirrors what
// encoding/json plus envelope.checkKeys accept in the Go relay:
//
//   - RFC 8259 syntax only: no comments, trailing commas, single quotes,
//     byte order mark or non-JSON whitespace;
//   - no duplicate keys (Go: checkKeys), keys compared exactly;
//   - no control characters inside strings, only the standard escapes;
//   - a lone surrogate escape becomes U+FFFD, as in encoding/json;
//   - numbers keep their literal text, so callers apply Go's integer rules;
//   - nothing but whitespace after the object.
//
// Nested objects or arrays are rejected outright: no relay field can hold
// one, so encoding/json would fail with a type error anyway.

export type Scalar =
  | { kind: "string"; value: string }
  | { kind: "number"; literal: string }
  | { kind: "true" }
  | { kind: "false" }
  | { kind: "null" };

const NUMBER = /-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/y;
const HEX4 = /^[0-9a-fA-F]{4}$/;

class Parser {
  i = 0;
  constructor(readonly s: string) {}

  ws(): void {
    for (;;) {
      const c = this.s.charCodeAt(this.i);
      if (c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d) this.i++;
      else return;
    }
  }

  string(): string | null {
    if (this.s[this.i] !== '"') return null;
    this.i++;
    let out = "";
    let start = this.i;
    for (;;) {
      if (this.i >= this.s.length) return null;
      const c = this.s.charCodeAt(this.i);
      if (c === 0x22) {
        out += this.s.slice(start, this.i);
        this.i++;
        return out;
      }
      if (c < 0x20) return null;
      if (c !== 0x5c) {
        this.i++;
        continue;
      }
      out += this.s.slice(start, this.i);
      const e = this.s[this.i + 1];
      this.i += 2;
      switch (e) {
        case '"': out += '"'; break;
        case "\\": out += "\\"; break;
        case "/": out += "/"; break;
        case "b": out += "\b"; break;
        case "f": out += "\f"; break;
        case "n": out += "\n"; break;
        case "r": out += "\r"; break;
        case "t": out += "\t"; break;
        case "u": {
          const u = this.hex4();
          if (u === null) return null;
          if (u >= 0xd800 && u < 0xdc00) {
            // A high surrogate counts only when a low surrogate escape follows.
            if (this.s[this.i] === "\\" && this.s[this.i + 1] === "u") {
              const save = this.i;
              this.i += 2;
              const lo = this.hex4();
              if (lo === null) return null;
              if (lo >= 0xdc00 && lo < 0xe000) {
                out += String.fromCharCode(u, lo);
                break;
              }
              this.i = save;
            }
            out += "\ufffd";
          } else if (u >= 0xdc00 && u < 0xe000) {
            out += "\ufffd";
          } else {
            out += String.fromCharCode(u);
          }
          break;
        }
        default:
          return null;
      }
      start = this.i;
    }
  }

  hex4(): number | null {
    const h = this.s.slice(this.i, this.i + 4);
    if (!HEX4.test(h)) return null;
    this.i += 4;
    return parseInt(h, 16);
  }

  scalar(): Scalar | null {
    const c = this.s[this.i];
    if (c === '"') {
      const value = this.string();
      return value === null ? null : { kind: "string", value };
    }
    for (const lit of ["true", "false", "null"] as const) {
      if (this.s.startsWith(lit, this.i)) {
        this.i += lit.length;
        return { kind: lit };
      }
    }
    NUMBER.lastIndex = this.i;
    const m = NUMBER.exec(this.s);
    if (m === null || m[0] === "") return null;
    this.i += m[0].length;
    return { kind: "number", literal: m[0] };
  }
}

/**
 * Parses text as one flat JSON object. Returns null for anything that is
 * not exactly that. With allowNull, a document that is just `null` gives an
 * empty map (encoding/json leaves the target untouched for `null`).
 */
export function parseFlatObject(text: string, allowNull = false): Map<string, Scalar> | null {
  const p = new Parser(text);
  p.ws();
  const out = new Map<string, Scalar>();
  if (allowNull && text.startsWith("null", p.i)) {
    p.i += 4;
    p.ws();
    return p.i === text.length ? out : null;
  }
  if (text[p.i] !== "{") return null;
  p.i++;
  p.ws();
  if (text[p.i] === "}") {
    p.i++;
  } else {
    for (;;) {
      const key = p.string();
      if (key === null) return null;
      p.ws();
      if (text[p.i] !== ":") return null;
      p.i++;
      p.ws();
      const value = p.scalar();
      if (value === null || out.has(key)) return null;
      out.set(key, value);
      p.ws();
      if (text[p.i] === ",") {
        p.i++;
        p.ws();
        continue;
      }
      if (text[p.i] === "}") {
        p.i++;
        break;
      }
      return null;
    }
  }
  p.ws();
  return p.i === text.length ? out : null;
}
