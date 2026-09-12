import type { SafeHeaders } from "./protocol";

// This deliberately excludes credentials, cookies, forwarding headers, origin,
// referer, and any hop-by-hop header. It is a transport hint allow-list, not a
// transparent HTTP proxy.
const REQUEST_HEADER_NAMES = ["accept", "content-language", "content-encoding"] as const;
const RESPONSE_HEADER_NAMES = [
  "cache-control",
  "content-encoding",
  "content-language",
  "content-type",
  "etag",
  "last-modified",
  "www-authenticate",
] as const;

const MAX_HEADER_VALUE_BYTES = 1024;

function isSafeHeaderValue(value: string): boolean {
  return !/[\r\n]/.test(value) && new TextEncoder().encode(value).byteLength <= MAX_HEADER_VALUE_BYTES;
}

function select(headers: Headers, names: readonly string[]): SafeHeaders {
  const selected: SafeHeaders = {};
  for (const name of names) {
    const value = headers.get(name);
    if (value !== null && isSafeHeaderValue(value)) selected[name] = value;
  }
  return selected;
}

export function selectSafeRequestHeaders(headers: Headers): SafeHeaders {
  return select(headers, REQUEST_HEADER_NAMES);
}

export function selectSafeResponseHeaders(headers: Record<string, unknown>): SafeHeaders | null {
  const selected: SafeHeaders = {};
  for (const name of RESPONSE_HEADER_NAMES) {
    const value = headers[name];
    if (value === undefined) continue;
    if (typeof value !== "string" || !isSafeHeaderValue(value)) return null;
    selected[name] = value;
  }
  return selected;
}
