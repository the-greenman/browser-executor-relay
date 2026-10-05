// Shared HTTP helpers. Fetch API only (no Cloudflare imports) so they run on any runtime.

/** Relay security properties: never application-controlled. Applied to every error and, via withCors, every routed response. */
export const SECURITY_HEADERS: Record<string, string> = {
  "cache-control": "no-store",
  "referrer-policy": "no-referrer",
  "x-frame-options": "DENY",
};

export function jsonResponse(body: unknown, status = 200, headers?: HeadersInit): Response {
  const merged = new Headers(SECURITY_HEADERS);
  new Headers(headers).forEach((value, name) => merged.set(name, value));
  return Response.json(body, { status, headers: merged });
}

export function errorResponse(status: number, error: string): Response {
  return jsonResponse({ error }, status);
}

export function methodNotAllowed(allowedMethod: string): Response {
  return new Response(null, { status: 405, headers: { ...SECURITY_HEADERS, allow: allowedMethod } });
}

// Credentials live in the URL path or an Authorization header and no cookies are used, so CORS is open (`*`, never Allow-Credentials).
// www-authenticate is exposed so browser callers can read the bearer challenge; the relay only challenges on the bearer route.
const CORS_EXPOSE = "etag, last-modified, content-encoding, www-authenticate";

export function withCors(response: Response): Response {
  const headers = new Headers(response.headers);
  for (const [name, value] of Object.entries(SECURITY_HEADERS)) headers.set(name, value);
  headers.set("access-control-allow-origin", "*");
  headers.set("access-control-expose-headers", CORS_EXPOSE);
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}

/** Path shape only: no credential check, no channel lookup, so a preflight reveals nothing. */
export function preflight(request: Request, methods = "GET, POST, OPTIONS"): Response {
  // Reflect requested headers (safe: no credentials are ever honoured; the relay forwards only an allow-list anyway),
  // so browser MCP clients with extra headers are not broken by a stale fixed list.
  const requested = request.headers.get("access-control-request-headers");
  return new Response(null, {
    status: 204,
    headers: {
      "access-control-allow-origin": "*",
      "access-control-allow-methods": methods,
      "access-control-allow-headers":
        requested ?? "content-type, authorization, accept, mcp-protocol-version, mcp-session-id, last-event-id",
      "access-control-max-age": "600",
      vary: "access-control-request-headers",
    },
  });
}

/** Reads at most `max` bytes (counted on bytes read, not content-length), stopping as soon as the total exceeds it; null when exceeded. */
export async function readBody(request: Request, max: number): Promise<Uint8Array | null> {
  const reader = request.body?.getReader();
  if (!reader) return new Uint8Array();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > max) {
      await reader.cancel();
      return null;
    }
    chunks.push(value);
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return bytes;
}
