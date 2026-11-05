// Logging. One JSON line per event, with a fixed event name and only the
// fields listed here: never a body, subject, query string, header,
// fingerprint, client address or error message.

export type LogEvent = "request" | "expired" | "store_error" | "config_invalid";

type Field = string | number;

export function log(event: LogEvent, fields: Record<string, Field> = {}): void {
  console.log(JSON.stringify({ event, ...fields }));
}
