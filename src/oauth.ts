// Stateless OAuth 2.1 authorization server + bearer verification. Fetch API + WebCrypto only: no Worker-only imports.
import { signingKey, signTyped, verifyTyped } from "./credentials";
import { jsonResponse, methodNotAllowed, preflight, readBody, SECURITY_HEADERS, withCors } from "./http";
import { base64UrlEncode, connectorPath, PAIRING_CODE_LENGTH, PAIRING_WINDOW_SECONDS, utf8Bytes } from "./protocol";
import type { PairingResponse } from "./protocol";

export interface AuthOptions {
  key: string;
  /** The relay's public origin, no trailing slash. */
  origin: string;
  /** Unix ms; default Date.now. */
  now?: () => number;
}

const CODE_TTL_S = 120;
const ACCESS_TTL_S = 3600;
const REFRESH_TTL_S = 2_592_000;
const MAX_BODY = 8192;
const CHANNEL = /^[A-Za-z0-9_-]{43}$/;
const ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const NO_CACHE = { pragma: "no-cache" };

const nowMs = (opts: AuthOptions): number => (opts.now ?? Date.now)();

// ---- pairing code -------------------------------------------------------------------------------------------------

async function pairingCode(channel: string, window: number, key: string): Promise<string> {
  const mac = new Uint8Array(
    await crypto.subtle.sign("HMAC", await signingKey(key), utf8Bytes(`pair|${channel}|${window}`) as unknown as BufferSource),
  );
  let bits = 0n;
  for (let i = 0; i < 7; i++) bits = (bits << 8n) | BigInt(mac[i]);
  bits >>= 6n; // top 50 of 56 bits
  let code = "";
  for (let i = PAIRING_CODE_LENGTH - 1; i >= 0; i--) code += ALPHABET[Number((bits >> BigInt(i * 5)) & 31n)];
  return code;
}

const windowOf = (ms: number): number => Math.floor(ms / 1000 / PAIRING_WINDOW_SECONDS);

/** Crockford normalisation of user input; null when it cannot be a code. */
export function normalisePairingCode(input: string): string | null {
  const code = input.trim().toUpperCase().replace(/[-\s]/g, "").replace(/[IL]/g, "1").replace(/O/g, "0");
  return /^[0-9A-HJKMNP-TV-Z]{10}$/.test(code) ? code : null;
}

export function constantTimeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

/** Current pairing code + conservative expiry for a channel. */
export async function issuePairing(channel: string, opts: AuthOptions): Promise<PairingResponse> {
  const w = windowOf(nowMs(opts));
  const code = await pairingCode(channel, w, opts.key);
  return {
    code: `${code.slice(0, 5)}-${code.slice(5)}`,
    expiresAt: (w + 1) * PAIRING_WINDOW_SECONDS * 1000,
    connectorUrl: opts.origin + connectorPath(channel),
  };
}

/** Accepts the current and previous window. */
async function pairingValid(channel: string, input: string, opts: AuthOptions): Promise<boolean> {
  const candidate = normalisePairingCode(input);
  if (!candidate) return false;
  const w = windowOf(nowMs(opts));
  const current = constantTimeEqual(candidate, await pairingCode(channel, w, opts.key));
  const previous = constantTimeEqual(candidate, await pairingCode(channel, w - 1, opts.key));
  return current || previous;
}

// ---- bearer -------------------------------------------------------------------------------------------------------

/** null = bearer valid for `channel`; otherwise the ready-made 401 Response. */
export async function verifyBearer(request: Request, channel: string, opts: AuthOptions): Promise<Response | null> {
  const header = request.headers.get("authorization");
  const challenge = `Bearer resource_metadata="${opts.origin}/.well-known/oauth-protected-resource${connectorPath(channel)}"`;
  const deny = (error: "unauthorized" | "invalid_token"): Response =>
    jsonResponse({ error }, 401, {
      "www-authenticate": error === "invalid_token" ? `${challenge}, error="invalid_token"` : challenge,
    });
  if (header === null) return deny("unauthorized");
  const token = /^bearer (\S+)$/i.exec(header)?.[1];
  const claims = token ? await verifyTyped(token, "access", opts.key, nowMs(opts)) : null;
  return claims && claims.role === "caller" && claims.channel === channel ? null : deny("invalid_token");
}

// ---- helpers ------------------------------------------------------------------------------------------------------

/** Bounded text body; null when over MAX_BODY. */
async function readText(request: Request): Promise<string | null> {
  const bytes = await readBody(request, MAX_BODY);
  return bytes && new TextDecoder().decode(bytes);
}

function oauthError(error: string, description: string, status = 400, headers?: HeadersInit): Response {
  return jsonResponse({ error, error_description: description }, status, headers);
}

function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
}

/** Canonical form of a resource URL: origin plus path with at most one trailing slash stripped; null with a query/fragment. */
function normaliseResource(value: string): string | null {
  try {
    const url = new URL(value);
    if (url.search || url.hash || value.includes("?") || value.includes("#")) return null;
    return url.origin + url.pathname.replace(/\/$/, "");
  } catch {
    return null;
  }
}

function validRedirectUri(value: unknown): value is string {
  if (typeof value !== "string" || value.length > 200 || value.includes("#")) return false;
  try {
    const url = new URL(value);
    if (url.username || url.password) return false;
    return url.protocol === "https:" || (url.protocol === "http:" && ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname));
  } catch {
    return false;
  }
}

// ---- register -----------------------------------------------------------------------------------------------------

async function register(request: Request, opts: AuthOptions): Promise<Response> {
  const text = await readText(request);
  let body: unknown;
  try {
    body = text === null ? undefined : JSON.parse(text);
  } catch {
    body = undefined;
  }
  if (!body || typeof body !== "object" || Array.isArray(body)) return oauthError("invalid_client_metadata", "Body must be a JSON object of at most 8192 bytes.");
  const { redirect_uris, client_name } = body as Record<string, unknown>;
  if (!Array.isArray(redirect_uris) || redirect_uris.length < 1 || redirect_uris.length > 5 || !redirect_uris.every(validRedirectUri)) {
    return oauthError("invalid_redirect_uri", "redirect_uris must be 1 to 5 https or loopback http URLs without fragments.");
  }
  let name = "MCP client";
  if (client_name !== undefined) {
    if (typeof client_name !== "string") return oauthError("invalid_client_metadata", "client_name must be a string.");
    const cleaned = client_name.replace(/[\u0000-\u001f\u007f-\u009f]/g, "").trim();
    if (cleaned.length > 100) return oauthError("invalid_client_metadata", "client_name is too long.");
    if (cleaned) name = cleaned;
  }
  const now = nowMs(opts);
  const clientId = await signTyped("client", { client_name: name, redirect_uris }, null, opts.key, now);
  return jsonResponse(
    {
      client_id: clientId,
      client_name: name,
      redirect_uris,
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
      token_endpoint_auth_method: "none",
      client_id_issued_at: Math.floor(now / 1000),
    },
    201,
  );
}

// ---- authorize ----------------------------------------------------------------------------------------------------

interface AuthRequest {
  clientName: string;
  redirectUri: string;
  clientId: string;
  codeChallenge: string;
  state: string | null;
  /** The fields echoed as hidden inputs (only those present). */
  fields: Record<string, string>;
}

/** The ONE validation used by GET and POST. Returns an error message, never a redirect. */
async function validateAuthRequest(params: URLSearchParams, channel: string, opts: AuthOptions): Promise<AuthRequest | string> {
  for (const key of new Set(params.keys())) if (params.getAll(key).length > 1) return "Invalid authorization request";
  const clientId = params.get("client_id") ?? "";
  const client = await verifyTyped(clientId, "client", opts.key, nowMs(opts));
  if (!client || !Array.isArray(client.redirect_uris)) return "Unknown or invalid client";
  const redirectUri = params.get("redirect_uri") ?? "";
  if (!client.redirect_uris.includes(redirectUri)) return "Invalid redirect_uri";
  const challenge = params.get("code_challenge") ?? "";
  const state = params.get("state");
  if (
    params.get("response_type") !== "code" ||
    params.get("code_challenge_method") !== "S256" ||
    !/^[A-Za-z0-9_-]{43}$/.test(challenge) ||
    (state !== null && state.length > 512)
  ) {
    return "Invalid authorization request";
  }
  const resource = params.get("resource");
  if (resource !== null && normaliseResource(resource) !== opts.origin + connectorPath(channel)) return "Invalid resource";
  const fields: Record<string, string> = {
    client_id: clientId,
    redirect_uri: redirectUri,
    response_type: "code",
    code_challenge: challenge,
    code_challenge_method: "S256",
  };
  if (state !== null) fields.state = state;
  if (resource !== null) fields.resource = resource;
  return { clientName: String(client.client_name ?? ""), redirectUri, clientId, codeChallenge: challenge, state, fields };
}

function htmlResponse(html: string, status: number, formAction: string): Response {
  return new Response(html, {
    status,
    headers: {
      ...SECURITY_HEADERS,
      "content-type": "text/html; charset=utf-8",
      "content-security-policy": `default-src 'none'; style-src 'unsafe-inline'; form-action ${formAction}; frame-ancestors 'none'; base-uri 'none'`,
      "x-content-type-options": "nosniff",
    },
  });
}

const PAGE_STYLE = "body{font:16px system-ui,sans-serif;max-width:28rem;margin:3rem auto;padding:0 1rem}input{font:inherit;padding:.4rem;margin:.5rem 0;display:block;width:100%;box-sizing:border-box}.err{color:#b00020}";

function page(body: string): string {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Connect</title><style>${PAGE_STYLE}</style></head><body>${body}</body></html>`;
}

function errorPage(message: string): Response {
  return htmlResponse(page(`<h1>Cannot connect</h1><p class="err">${escapeHtml(message)}.</p>`), 400, "'none'");
}

function formPage(channel: string, auth: AuthRequest, error?: string): Response {
  const redirect = new URL(auth.redirectUri);
  const hidden = Object.entries(auth.fields)
    .map(([name, value]) => `<input type="hidden" name="${name}" value="${escapeHtml(value)}">`)
    .join("");
  const html = page(
    `<h1>Connect &ldquo;${escapeHtml(auth.clientName)}&rdquo; to your editor</h1>` +
      `<p>After you confirm, you will be returned to ${escapeHtml(redirect.host)}.</p>` +
      `<p>Enter the pairing code shown in the Agents panel.</p>` +
      (error ? `<p class="err">${escapeHtml(error)}</p>` : "") +
      `<form method="post" action="/c/${channel}/oauth/authorize">` +
      `<input name="pairing_code" autocomplete="off" autocapitalize="characters" spellcheck="false" maxlength="20" autofocus>` +
      `${hidden}<button type="submit">Connect</button></form>`,
  );
  return htmlResponse(html, error ? 400 : 200, `'self' ${redirect.origin}`);
}

async function authorize(request: Request, channel: string, opts: AuthOptions): Promise<Response> {
  if (request.method === "GET") {
    const auth = await validateAuthRequest(new URL(request.url).searchParams, channel, opts);
    return typeof auth === "string" ? errorPage(auth) : formPage(channel, auth);
  }
  if (request.method !== "POST") return methodNotAllowed("GET, POST");
  if (!request.headers.get("content-type")?.toLowerCase().startsWith("application/x-www-form-urlencoded")) return errorPage("Unsupported form encoding");
  const text = await readText(request);
  if (text === null) return errorPage("Request too large");
  const params = new URLSearchParams(text);
  const auth = await validateAuthRequest(params, channel, opts);
  if (typeof auth === "string") return errorPage(auth);
  if (!(await pairingValid(channel, params.get("pairing_code") ?? "", opts))) {
    return formPage(channel, auth, "That code is not valid or has expired.");
  }
  const code = await signTyped(
    "code",
    { channel, client_id: auth.clientId, redirect_uri: auth.redirectUri, code_challenge: auth.codeChallenge },
    CODE_TTL_S,
    opts.key,
    nowMs(opts),
  );
  const location = new URL(auth.redirectUri);
  location.searchParams.set("code", code);
  if (auth.state !== null) location.searchParams.set("state", auth.state);
  return new Response(null, { status: 302, headers: { ...SECURITY_HEADERS, location: location.toString() } });
}

// ---- token --------------------------------------------------------------------------------------------------------

async function issueTokens(channel: string, clientId: string, opts: AuthOptions): Promise<Response> {
  const now = nowMs(opts);
  return jsonResponse(
    {
      access_token: await signTyped("access", { role: "caller", channel }, ACCESS_TTL_S, opts.key, now),
      token_type: "Bearer",
      expires_in: ACCESS_TTL_S,
      refresh_token: await signTyped("refresh", { channel, client_id: clientId }, REFRESH_TTL_S, opts.key, now),
    },
    200,
    NO_CACHE,
  );
}

async function token(request: Request, channel: string, opts: AuthOptions): Promise<Response> {
  const fail = (error: string, description: string): Response => oauthError(error, description, 400, NO_CACHE);
  if (!request.headers.get("content-type")?.toLowerCase().startsWith("application/x-www-form-urlencoded")) {
    return fail("invalid_request", "Content-Type must be application/x-www-form-urlencoded.");
  }
  const text = await readText(request);
  if (text === null) return fail("invalid_request", "Request too large.");
  const params = new URLSearchParams(text);
  const now = nowMs(opts);
  const grant = params.get("grant_type");

  if (grant === "authorization_code") {
    const code = params.get("code");
    const redirectUri = params.get("redirect_uri");
    const clientId = params.get("client_id");
    const verifier = params.get("code_verifier");
    if (!code || !redirectUri || !clientId || !verifier || !/^[A-Za-z0-9\-._~]{43,128}$/.test(verifier)) {
      return fail("invalid_request", "code, redirect_uri, client_id and a valid code_verifier are required.");
    }
    if (!(await verifyTyped(clientId, "client", opts.key, now))) return fail("invalid_client", "Unknown client.");
    const claims = await verifyTyped(code, "code", opts.key, now);
    if (!claims || claims.client_id !== clientId || claims.redirect_uri !== redirectUri || claims.channel !== channel) {
      return fail("invalid_grant", "Invalid or expired code.");
    }
    const resource = params.get("resource");
    if (resource !== null && normaliseResource(resource) !== opts.origin + connectorPath(channel)) return fail("invalid_target", "Invalid resource.");
    const digest = await crypto.subtle.digest("SHA-256", utf8Bytes(verifier) as unknown as BufferSource);
    if (base64UrlEncode(digest) !== claims.code_challenge) return fail("invalid_grant", "PKCE verification failed.");
    return issueTokens(channel, clientId, opts);
  }

  if (grant === "refresh_token") {
    const refresh = params.get("refresh_token");
    const claims = refresh ? await verifyTyped(refresh, "refresh", opts.key, now) : null;
    const clientId = params.get("client_id");
    if (!claims || claims.channel !== channel || (clientId !== null && clientId !== claims.client_id)) {
      return fail("invalid_grant", "Invalid or expired refresh token.");
    }
    return issueTokens(channel, String(claims.client_id), opts);
  }

  return fail("unsupported_grant_type", "Supported grants: authorization_code, refresh_token.");
}

// ---- dispatch -----------------------------------------------------------------------------------------------------

/** CORS-enabled JSON endpoint: OPTIONS preflight, one allowed method. */
async function jsonEndpoint(request: Request, method: "GET" | "POST", run: () => Response | Promise<Response>): Promise<Response> {
  if (request.method === "OPTIONS") return preflight(request, `${method}, OPTIONS`);
  if (request.method !== method) return withCors(methodNotAllowed(method));
  return withCors(await run());
}

/** Returns null for any path it does not own, so the caller falls through. */
export async function handleAuth(request: Request, opts: AuthOptions): Promise<Response | null> {
  const path = new URL(request.url).pathname;
  if (!path.startsWith("/.well-known/") && !path.startsWith("/c/")) return null;
  const protectedResource = /^\/\.well-known\/oauth-protected-resource\/v1\/channels\/([^/]+)\/call$/.exec(path);
  const metadata = /^\/\.well-known\/oauth-authorization-server\/v1\/channels\/([^/]+)\/call$/.exec(path);
  const endpoint = /^\/c\/([^/]+)\/oauth\/(register|authorize|token)$/.exec(path);
  const channel = (protectedResource ?? metadata ?? endpoint)?.[1];
  if (!channel || !CHANNEL.test(channel)) return null;

  if (protectedResource) {
    return jsonEndpoint(request, "GET", () =>
      jsonResponse({
        resource: opts.origin + connectorPath(channel),
        authorization_servers: [opts.origin + connectorPath(channel)],
        bearer_methods_supported: ["header"],
      }),
    );
  }
  if (metadata) {
    // The issuer is the connector URL (RFC 8414 path insertion); the endpoints stay under /c/{ch}.
    const base = `${opts.origin}/c/${channel}/oauth`;
    return jsonEndpoint(request, "GET", () =>
      jsonResponse({
        issuer: opts.origin + connectorPath(channel),
        authorization_endpoint: `${base}/authorize`,
        token_endpoint: `${base}/token`,
        registration_endpoint: `${base}/register`,
        response_types_supported: ["code"],
        grant_types_supported: ["authorization_code", "refresh_token"],
        code_challenge_methods_supported: ["S256"],
        token_endpoint_auth_methods_supported: ["none"],
      }),
    );
  }
  switch (endpoint![2]) {
    case "register":
      return jsonEndpoint(request, "POST", () => register(request, opts));
    case "token":
      return jsonEndpoint(request, "POST", () => token(request, channel, opts));
    default:
      // Browser navigation: no CORS, no OPTIONS.
      return authorize(request, channel, opts);
  }
}
