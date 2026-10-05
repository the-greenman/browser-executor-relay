# Plan: Pairing-code OAuth for callers (portable, stateless)

Issue: the-greenman/browser-executor-relay#12. Tracking/design of record: the-greenman/srs-web#446 (approved; this plan implements it, it does not redesign it). Spec target: MCP authorization 2025-06-18 (OAuth 2.1 + PKCE, RFC 9728, RFC 8414, RFC 7591).

> Usage note: written for an agent to execute. Every name, path, status code and header below is deliberate. Where this plan says "pinned", do not choose differently.

## Summary

Claude and other MCP clients flag the relay's secret-URL caller route as unauthenticated because their only recognised sign-in is the MCP OAuth flow. Add a stateless OAuth 2.1 authorization server plus a bearer caller route to the relay. The user proves consent by typing a short pairing code (shown in srs-web's Agents panel, fetched through an executor-authenticated pairing endpoint). Everything (pairing code, client id, auth code, access and refresh tokens) is an HMAC-signed claim under the existing `RELAY_HMAC_KEY`: no storage, no accounts. All OAuth logic lives in one new module, `src/oauth.ts`, that uses only the Fetch API and WebCrypto so it is runtime-agnostic: Fetch API + WebCrypto only, runnable on Node 20+ (global `crypto`), Bun and Deno via a bundler (source uses extensionless imports; no loader is shipped). `src/index.ts` only mounts it. The existing capability-URL route stays byte-for-byte compatible. No new dependencies.

## Agent Assignments

| Role | Agent |
|---|---|
| Relay Worker (implements all phases, this repo only) | one implementation agent |
| Reviewer: security (token typing, constant-time compare, redirect/open-redirect, CSP, HTML escaping) | one reviewer agent, after Phase 2 and before PR |
| Reviewer: contract (README + protocol.ts vs endpoint behaviour; srs-web vendoring safety) | one reviewer agent, before PR |

Agents push the branch only; the owner reviews the diff before any PR is opened. Do not commit as part of plan drafting.

## Architecture Decisions

This repo has no `docs/adr/`. No ADR file is created; the decisions are recorded here and in the README "Auth" section.

| Decision | Status |
|---|---|
| OAuth logic is one runtime-agnostic module (`src/oauth.ts`, no `cloudflare:` imports); `index.ts` mounts it. | pinned (#446) |
| No storage: all artefacts are HMAC-signed claims under `RELAY_HMAC_KEY`; `typ` claim prevents cross-use. | pinned (#446) |
| Relay stays application-agnostic: OAuth guards a generic HTTP route; no MCP knowledge in code. | pinned (#446) |
| Legacy `/call/{callerCred}` and `/executor/{cred}` routes unchanged. | pinned (#446) |

---

## Contracts

### Wire contract (replaces the template's WASM section)

No WASM, no srs-rust. The contract surface is `src/protocol.ts` (import-free, vendored verbatim by srs-web as `relay-protocol.ts`). Additions, nothing else:

```ts
/** Response of POST /v1/channels/{ch}/pairing/{executorCred}. */
export interface PairingResponse {
  /** Display form XXXXX-XXXXX (Crockford base32, 50 bits). */
  code: string;
  /** Unix ms at which the current 10-minute pairing window ends (conservative display deadline). */
  expiresAt: number;
  /** https://<relay-origin>/v1/channels/{ch}/call: contains no secret. */
  connectorUrl: string;
}
export const PAIRING_ROUTE = "pairing";                 // /v1/channels/{ch}/pairing/{executorCred}
export const PAIRING_WINDOW_SECONDS = 600;
export const PAIRING_CODE_LENGTH = 10;
export function pairingPath(channel: string, executorCredential: string): string {
  return `/v1/channels/${channel}/${PAIRING_ROUTE}/${executorCredential}`;
}
export function connectorPath(channel: string): string { return `/v1/channels/${channel}/call`; }
```

`test/protocol-entry.test.ts` (no imports, no `cloudflare:`, no `DurableObject`) must stay green; add these without any `import`.

### Module contracts (`src/oauth.ts`, Fetch API + WebCrypto only)

```ts
export interface AuthOptions { key: string; origin: string; now?: () => number /* unix ms; default Date.now */ }
export function handleAuth(request: Request, opts: AuthOptions): Promise<Response | null>;
/** null = bearer valid for `channel`; otherwise the ready-made 401 Response. */
export function verifyBearer(request: Request, channel: string, opts: AuthOptions): Promise<Response | null>;
/** Current pairing code + conservative expiry for a channel. */
export function issuePairing(channel: string, opts: AuthOptions): Promise<PairingResponse>;
/** Shared by index.ts: the ONE definition of relay security headers, CORS and JSON helpers (no copy in index.ts). */
export const SECURITY_HEADERS: Record<string, string>;      // cache-control: no-store, referrer-policy: no-referrer, x-frame-options: DENY
export function jsonResponse(body: unknown, status?: number, headers?: HeadersInit): Response; // applies SECURITY_HEADERS
export function errorResponse(status: number, error: string): Response;                        // {error}
export function withCors(response: Response): Response;        // SECURITY_HEADERS + ACAO * + expose etag, last-modified, content-encoding, www-authenticate
export function preflight(request: Request): Response;         // 204; allow-methods "GET, POST, OPTIONS"; reflects requested headers, default includes authorization
```

Duplication rule (pinned): `index.ts` deletes its own `SECURITY_HEADERS`, `errorResponse`, `withCors`, `preflight` and `notAllowed` and imports them from `./oauth` (oauth.ts stays self-contained for other runtimes; index.ts is the only consumer). `notAllowed(method)` also moves to oauth.ts (`methodNotAllowed`). The existing CORS test expecting `allow-methods` of `POST, OPTIONS` is updated to `GET, POST, OPTIONS`.

`verifyBearer` takes `origin` too (the brief listed only `{key, now?}`) because the 401 must carry an absolute `resource_metadata` URL. `opts.origin` is the relay's public origin, no trailing slash. `index.ts` passes `new URL(request.url).origin`.

Per-channel issuer: the channel is carried in the path (`/c/{ch}/...`); `handleAuth` strips the `/c/{ch}` prefix, remembers `ch`, and dispatches to the same handlers for `/oauth/register|authorize|token` (one implementation; the prefix is the only difference).

`handleAuth` returns `null` for any path it does not own (so `index.ts` falls through). It owns exactly: `/.well-known/oauth-protected-resource/v1/channels/{ch}/call`, `/.well-known/oauth-authorization-server/c/{ch}`, `/c/{ch}/oauth/register`, `/c/{ch}/oauth/authorize`, `/c/{ch}/oauth/token`. `{ch}` must match `/^[A-Za-z0-9_-]{43}$/` else not owned (`null`/404).

---

## Scope

In scope: everything in this repo needed for #12 (`src/oauth.ts`, `src/credentials.ts`, `src/index.ts`, `src/protocol.ts`, tests, `vitest.config.ts`, README).

**Out of scope:**

- srs-web UI ("Pair an agent", vendoring `protocol.ts`, countdown): the-greenman/srs-web#447.
- Deploy, submodule bump, real-client verification (claude.ai, second client): the-greenman/semanticops-relay#1 (owner-run).
- Storage, in-worker rate limiting (README recommends a platform rule), per-token revocation, replay-once codes, scopes, consent screens beyond the code, client secrets, DPoP, `package.json` export of `./oauth`.
- Any change to the legacy capability routes' behaviour.

---

## Design (pinned)

### 1. credentials.ts generalisation (byte-compatible)

Keep the on-wire format `base64url(JSON(claims)) + "." + base64url(HMAC-SHA256(payloadString))`. Refactor, in `src/credentials.ts`:

- `signCredential(claims: object, secret): Promise<string>`: widened from `RelayCredentialClaims` to `object`; logic unchanged (no `signClaims` alias).
- `verifyClaims(value, secret): Promise<Record<string, unknown> | null>`: current split/decode/HMAC-verify/`JSON.parse`; returns the parsed object only if it is a non-null, non-array object.
- Output bytes are unchanged (`JSON.stringify` key order is the caller's insertion order, as today); `signTyped` calls the widened `signCredential`.
- `verifyCredential(value, secret)` = `verifyClaims` (internal helper, not exported) then the existing `claimsAreValid`, which gains one condition: `(claims as {typ?: unknown}).typ === undefined`. This makes a typed token (access/refresh/...) unusable as a capability credential even if its other fields were somehow valid.
- `signTyped(typ: ClaimTyp, claims: Record<string, unknown>, ttlSeconds: number | null, secret, nowMs): Promise<string>` signs `{ typ, ...claims, ...(ttlSeconds !== null && { exp: Math.floor(nowMs / 1000) + ttlSeconds }) }` (key order: `typ`, then claims in given order, `exp` last).
- `verifyTyped(value, typ, secret, nowMs): Promise<Record<string, unknown> | null>`: `verifyClaims`, then require `claims.typ === typ`; require `Number.isInteger(exp)` and `exp * 1000 > nowMs` for every `typ` except `"client"` (client ids have no expiry, and carry no `exp`).
- `type ClaimTyp = "client" | "code" | "access" | "refresh"`. Only used inside this module and oauth.ts; not added to protocol.ts.

Byte-compat proof (add to `test/credentials.test.ts`, literals minted by the CURRENT code at base commit 6b2a1ac with secret `legacy-fixture-key`, channel `"A".repeat(43)`):

```text
caller  {channel, role:"caller", version:1}:
eyJjaGFubmVsIjoiQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQSIsInJvbGUiOiJjYWxsZXIiLCJ2ZXJzaW9uIjoxfQ._GNrXdj0UMRF-GKXDY2MqNhnsx-bZsIw2SXAgTp3M2U
executor {channel, role:"executor", version:1, origin:"https://app.example"}:
eyJjaGFubmVsIjoiQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQSIsInJvbGUiOiJleGVjdXRvciIsInZlcnNpb24iOjEsIm9yaWdpbiI6Imh0dHBzOi8vYXBwLmV4YW1wbGUifQ.2L4Ecf5b9SzJYo9kQ86if_p8nGKnSc-JbLim1cU6fdM
```

Assert, for each: `verifyCredential(literal, key)` returns the original claims AND `signCredential(sameClaims, key)` equals the literal exactly. Also assert a typed token (`signTyped("access", ...)`) is rejected by `verifyCredential`, and a capability token is rejected by `verifyTyped(..., "access", ...)`.

### 2. Pairing code

- Alphabet (Crockford base32): `0123456789ABCDEFGHJKMNPQRSTVWXYZ`.
- `window = Math.floor(nowMs / 1000 / 600)`. MAC = HMAC-SHA256(key, utf8(`"pair|" + channel + "|" + window`)). Domain separation from capability tokens holds because those sign base64url strings, which cannot contain `|`.
- Code = first 7 bytes of the MAC read as a big-endian integer, top 50 bits, encoded as 10 base32 chars (5 bits each, MSB first). Display `XXXXX-XXXXX`.
- Input normalisation before compare: trim, uppercase, strip `-` and whitespace, map `I`/`L` to `1`, `O` to `0`; result must match `/^[0-9A-HJKMNP-TV-Z]{10}$/` else invalid.
- Accept window `w` and `w-1` (so a code is valid for 10 to 20 minutes). Compare candidate against both computed codes with a constant-time comparison (`constantTimeEqual(a: string, b: string)`: equal length check on fixed 10-char strings, XOR-accumulate `charCodeAt`, no early return); evaluate both comparisons without short-circuit.
- `issuePairing`: `{ code: "XXXXX-XXXXX" (current window), expiresAt: (w + 1) * 600_000, connectorUrl: origin + connectorPath(channel) }`. The code is deterministic per (channel, window): asking again in the same window returns the same code.

### 3. Lifetimes and claims

| Item | Claims (key order) | Lifetime |
|---|---|---|
| client_id | `{typ:"client", client_name, redirect_uris}` | no `exp` |
| auth code | `{typ:"code", channel, client_id, redirect_uri, code_challenge, exp}` | 120 s |
| access token | `{typ:"access", role:"caller", channel, exp}` | 3600 s |
| refresh token | `{typ:"refresh", channel, client_id, exp}` | 30 d (2 592 000 s) |

Constants in oauth.ts: `CODE_TTL_S = 120`, `ACCESS_TTL_S = 3600`, `REFRESH_TTL_S = 2_592_000`. `verifyBearer` accepts only `typ:"access"`, `role:"caller"`, `channel === requested channel`. The token endpoint's refresh grant accepts only `typ:"refresh"`; the code grant only `typ:"code"`.

### 4. Endpoint contracts (oauth.ts)

Common: every response carries `SECURITY_HEADERS` (`cache-control: no-store`, `referrer-policy: no-referrer`, `x-frame-options: DENY`); token responses also set `pragma: no-cache`. Headers come from the single shared definitions exported by oauth.ts (section 5), not copies. JSON endpoints (`.well-known/*`, register, token) add `access-control-allow-origin: *` (never allow-credentials) and answer `OPTIONS` with 204, `allow-methods: GET|POST, OPTIONS` as appropriate, `allow-headers: content-type, authorization`, `max-age: 600`. `/c/{ch}/oauth/authorize` has no CORS and no OPTIONS (browser navigation). Wrong method on an owned path: `405` with `allow`. All OAuth JSON errors are RFC 6749 shaped: `{"error": "<code>", "error_description": "<short human text>"}`.

**`GET /.well-known/oauth-protected-resource/v1/channels/{ch}/call`** (RFC 9728). `{ch}` must match `/^[A-Za-z0-9_-]{43}$/` else 404 `{"error":"not_found"}`. 200:
`{"resource": "<origin>/v1/channels/{ch}/call", "authorization_servers": ["<origin>/c/{ch}"], "bearer_methods_supported": ["header"]}`.

**`GET /.well-known/oauth-authorization-server/c/{ch}`** (RFC 8414, path-aware; the issuer is per channel so clients that never send `resource` still reach the right channel). 200:
```json
{ "issuer": "<origin>/c/{ch}", "authorization_endpoint": "<origin>/c/{ch}/oauth/authorize", "token_endpoint": "<origin>/c/{ch}/oauth/token",
  "registration_endpoint": "<origin>/c/{ch}/oauth/register", "response_types_supported": ["code"],
  "grant_types_supported": ["authorization_code","refresh_token"], "code_challenge_methods_supported": ["S256"],
  "token_endpoint_auth_methods_supported": ["none"] }
```

**`POST /c/{ch}/oauth/register`** (RFC 7591). Body: JSON, at most 8192 bytes counted on the bytes actually read, not `content-length` (else 400 `invalid_client_metadata`). Require `redirect_uris`: array of 1 to 5 strings, each at most 200 chars (total JSON body is already capped at 8192 bytes, so the signed `client_id` stays small), each a URL with no fragment and either `https:` or `http:` with hostname exactly `localhost`, `127.0.0.1` or `[::1]`; else 400 `invalid_redirect_uri`. `client_name`: optional string, default `"MCP client"`, trimmed, control characters removed, at most 100 chars (longer, or non-string, is 400 `invalid_client_metadata`). `grant_types`, `response_types`, `token_endpoint_auth_method`, `scope` etc. are ignored (response always states the supported values). 201:
`{"client_id": <signTyped client>, "client_name", "redirect_uris", "grant_types": ["authorization_code","refresh_token"], "response_types": ["code"], "token_endpoint_auth_method": "none", "client_id_issued_at": <unix s>}`. No `client_secret`.

**`GET /c/{ch}/oauth/authorize`**. Validate with ONE shared function `validateAuthRequest(params)` used by both GET and POST (POST re-validates everything from the hidden fields; hidden fields are untrusted):
1. `client_id` verifies as `typ:"client"` (else error page 400 "Unknown or invalid client").
2. `redirect_uri` equals (exact string) one of the client's `redirect_uris` (else error page 400; never redirect).
3. `response_type === "code"`; `code_challenge_method === "S256"`; `code_challenge` matches `/^[A-Za-z0-9_-]{43}$/`; `state` (optional) at most 512 chars.
4. The channel comes from the path (`/c/{ch}`). `resource` is OPTIONAL; when present it is normalised (parse as URL; lowercase origin; strip at most one trailing `/` from the path; no query or fragment) and must equal `<origin>/v1/channels/{ch}/call` for the path's `{ch}`, else error page 400 "Invalid resource". The same normalisation is used by the token endpoint.
All failures (including a 2025-03-26-era client that omits `resource`: it now works, because the issuer URL carries the channel) render the HTML error page with status 400 and never redirect (a deliberate simplification of RFC 6749 section 4.1.2.1: the popup shows the problem; no error redirect). On success, 200 HTML form:
- Heading `Connect <client_name> to your editor` with the name shown in quotes as untrusted client-supplied text, and a line "After you confirm, you will be returned to <redirect host>" (`new URL(redirect_uri).host`, escaped, e.g. `claude.ai` or `127.0.0.1:8765`) so open registration cannot pass off a look-alike name unnoticed. Text: "Enter the pairing code shown in the Agents panel." One text input `name="pairing_code"` (`autocomplete="off"`, `autocapitalize="characters"`, `spellcheck="false"`, `maxlength="20"`, `autofocus`), a submit button, and hidden inputs `client_id, redirect_uri, response_type, state (if present), code_challenge, code_challenge_method, resource (if present)`. `method="post"` with `action="/c/{ch}/oauth/authorize"`.
- Every interpolated value (client_name and all hidden values) passes through `escapeHtml` (`& < > " '`). Test with `client_name` `<script>alert(1)</script>"`.
- Headers: `content-type: text/html; charset=utf-8`; `content-security-policy: default-src 'none'; style-src 'unsafe-inline'; form-action 'self' <redirect_uri origin>; frame-ancestors 'none'; base-uri 'none'`; `x-content-type-options: nosniff`; `x-frame-options: DENY`. Error pages: same without `form-action` entry (`form-action 'none'`).
- Deviation to note (decision for reviewer): the brief says `form-action 'self'`. Chrome applies `form-action` to the redirect chain after submit, so a bare `'self'` would block the 302 to the client's redirect_uri. The validated `redirect_uri`'s origin (`new URL(uri).origin`, which cannot contain `;` or whitespace) is appended. Real-client check in semanticops-relay#1 confirms.

**`POST /c/{ch}/oauth/authorize`** (`content-type: application/x-www-form-urlencoded`, body at most 8192 bytes counted on bytes read; else 400 error page). Run `validateAuthRequest`; then verify `pairing_code` for the channel at `now()`.
- Wrong or unparsable code: re-render the same form with an inline error line "That code is not valid or has expired.", status 400, no `Location`, fields preserved.
- Correct: mint the auth code and respond `302` with `Location` = `redirect_uri` with `code` (and `state` if present) set via `URL.searchParams.set`, plus the same security headers.

**`POST /c/{ch}/oauth/token`** (form-encoded, body at most 8192 bytes counted on bytes read; CORS `*`). Success and error responses also carry `pragma: no-cache`. Errors are 400 JSON (`invalid_request`, `invalid_grant`, `invalid_client`, `unsupported_grant_type`), except none are 401. Success 200:
`{"access_token", "token_type": "Bearer", "expires_in": 3600, "refresh_token"}` (no `scope`).
- `grant_type=authorization_code`: require `code`, `redirect_uri`, `client_id`, `code_verifier` (`/^[A-Za-z0-9\-._~]{43,128}$/`). `client_id` must verify as `typ:"client"` (else `invalid_client`). `code` must verify as `typ:"code"` and unexpired (else `invalid_grant`). Claim `client_id` and `redirect_uri` must equal the request values (else `invalid_grant`). The path `{ch}` must equal the code's `channel` claim (else `invalid_grant`). If the request carries `resource`, it must normalise-equal `<origin>/v1/channels/{claim.channel}/call` (else `invalid_target`, 400); absent is accepted. PKCE: `base64url(SHA-256(utf8(code_verifier))) === claim.code_challenge` (plain compare; constant time is only needed for the pairing code), else `invalid_grant`. Then issue a fresh access and refresh pair.
- `grant_type=refresh_token`: require `refresh_token` verifying as `typ:"refresh"`, unexpired, whose `channel` equals the path `{ch}`; if the request has `client_id` it must equal the claim. Issue a new access token AND a new refresh token (fresh 30 days). Stateless: the old refresh token stays valid until its own expiry (documented ceiling).
- Any other `grant_type`: `unsupported_grant_type`.

**401 shape** (returned by `verifyBearer`): status 401, `content-type: application/json`, body `{"error":"unauthorized"}` when no `Authorization` header is present, `{"error":"invalid_token"}` when one is present but bad (wrong scheme, not signed, expired, wrong `typ`, wrong channel). Header:
- absent: `WWW-Authenticate: Bearer resource_metadata="<origin>/.well-known/oauth-protected-resource/v1/channels/{ch}/call"`
- present but bad: the same value followed by `, error="invalid_token"`.
Scheme match is case-insensitive `Bearer` with exactly one space then the token. Plus `cache-control: no-store`, `referrer-policy: no-referrer`.

### 5. index.ts wiring (no duplication)

0. Delete index.ts's own `SECURITY_HEADERS`, `errorResponse`, `notAllowed`, `withCors`, `preflight`; import them from `./oauth` (see section 2 contract).
1. In `route()`, before the `/v1/channels` check: `const auth = await handleAuth(request, { key: env.RELAY_HMAC_KEY, origin: url.origin }); if (auth) return auth;` handleAuth responses already carry their headers/CORS; do not wrap them in `withCors`.
2. `parsePath` gains the route `"pairing"` (5-part path, same credential-required rule) and a sibling `parseBearerPath(pathname): {channel} | null` for the 4-part `/v1/channels/{ch}/call`.
3. `authenticatedChannel(request, env, expectedRole, expectedRoute)` takes the expected route explicitly (callers: executor/"executor", caller/"call", executor/"pairing"); behaviour otherwise identical.
4. Factor the post-auth half of `routeCall` into `forwardCall(request: Request, env: Env, channel: string): Promise<Response>` (content-length check, body read, frame build, DO stub fetch). Legacy `routeCall` = method check, `authenticatedChannel(..., "caller", "call")`, `return forwardCall(...)`. New `routeBearerCall(request, env, channel)` = POST check (405 otherwise), `const denied = await verifyBearer(request, channel, {key, origin}); if (denied) return denied;`, `return forwardCall(...)`. Wrap with `withCors`.
5. New `routePairing(request, env)`: POST only (405 else), `authenticatedChannel(request, env, "executor", "pairing")` (403 `invalid_credential`), then the same origin check as `routeExecutor` (403 `executor_origin_forbidden`), then `Response.json(await issuePairing(channel, {key, origin}))`. Factor the origin check into a tiny shared helper `originForbidden(request, authenticated)` used by both. Wrap with `withCors`.
6. OPTIONS: `preflight(request)` is returned for OPTIONS on the pairing route and the bearer `/call` route (path shape only, as today). `preflight` (now in oauth.ts) allows `GET, POST, OPTIONS` and its default allow-headers list includes `authorization`.
7. Update the stale comment above the CORS expose list: the relay now challenges, but only on the bearer route. `www-authenticate` is added to the expose list in oauth.ts `withCors`.
8. `Env` unchanged. No new bindings, no wrangler changes.

### 6. Tests

**Runner (verified in this worktree).** The Cloudflare plugin cannot run Node-only tests in the same pool, but vitest 4.1.11 `test.projects` works with the existing plugin: a throwaway config with a `workers` project (plugin, all current tests) and a `node` project (`environment: "node"`, no plugin) ran 6 files / 28 tests green. Chosen approach (minimal, single config, `npm test` and `npm run check` unchanged): rewrite `vitest.config.ts` as

```ts
export default defineConfig({
  test: { projects: [
    { plugins: [cloudflareTest({ /* existing wrangler + bindings, unchanged */ })],
      test: { name: "workers", include: ["test/**/*.test.ts"], exclude: ["test/**/*.node.test.ts"] } },
    { test: { name: "node", environment: "node", include: ["test/**/*.node.test.ts"] } },
  ] },
});
```

Naming rule: Node-only tests are `test/*.node.test.ts`. They must not import `node:` modules or use `process` (tsconfig `types` is restricted to the Cloudflare/vitest types, so typecheck would fail). First assertion in the node file: `expect((globalThis as { WebSocketPair?: unknown }).WebSocketPair).toBeUndefined()` to prove it is not in workerd.

**Unit, plain Node: `test/oauth.node.test.ts`** (injected `now`): crockford normalisation (case, hyphen, I/L to 1, O to 0, bad length/chars); code accepted in current and previous window, rejected two windows back and for another channel; `constantTimeEqual`; every claim `typ` substitution (access as refresh, refresh as access, code as either, capability token as bearer, client id as code) rejected; expired and exact-boundary `exp`; metadata documents; register (valid, http loopback ok, http non-loopback rejected, fragment rejected, 6 URIs rejected, oversize name rejected, no `client_secret`); authorize GET validation matrix (bad client_id, unregistered redirect_uri, bad response_type, `plain` method, missing/short challenge, wrong-origin resource, malformed channel in the path, missing `resource` accepted); `resource` normalisation (trailing `/`, uppercase host accepted; other channel rejected); the page shows the quoted client_name AND the redirect host (e.g. `claude.ai`); client_name escaping; per-channel issuer (token/refresh/code from a different `{ch}` path rejected); custom-scheme and non-loopback http redirect_uris rejected; oversize body rejected on bytes read with no `content-length`;  CSP/headers exact strings; POST wrong code gives 400 with no `Location` and re-rendered form; POST right code gives 302 with `code` and echoed `state` and preserves an existing query on redirect_uri; token happy path with real S256, wrong verifier, wrong redirect_uri, wrong client_id, expired code, `resource` mismatch, refresh grant, refresh with wrong client_id, unsupported grant; `verifyBearer` none/malformed/wrong-scheme/expired/other-channel/valid and the exact `WWW-Authenticate` strings; all time-dependent assertions (code windows, auth-code 120 s, access 3600 s, refresh 30 d, exact `exp` boundary) live here with injected `now`; `handleAuth` returns `null` for `/v1/channels`, `/`, and unrelated paths; wrong method gives 405.

**Guard: `test/oauth-portability.test.ts`** (workers project, same `?raw` import pattern as `protocol-entry.test.ts`): for both `../src/oauth.ts?raw` and `../src/credentials.ts?raw`: strip `//` and `/* */` comments first, then (a) parse every `import`/`export ... from` specifier and require it to be `./credentials` or `./protocol`; (b) require no occurrence of the identifiers `DurableObject`, `WebSocketPair`, `DurableObjectNamespace`, `ExecutionContext`, `caches`. A comment mentioning them must not fail the test. Also assert `protocol.ts` still exports `PAIRING_ROUTE` etc. (the import-free guard itself stays in `protocol-entry.test.ts`).

**Credentials: extend `test/credentials.test.ts`** with the byte-compat fixtures above plus typed round-trip, tamper, and cross-use cases.

**Integration: new `describe("pairing-code OAuth")` in `test/relay.integration.test.ts`**, using `worker.default.fetch`, a bootstrap sent with `Origin: https://app.example`, and an echo executor (reuse the file's helpers). One sequential flow test plus targeted negative tests. Flow, asserting at each step:
1. Pair (the channel's executor credential): `POST pairing/{executorCred}` with `Origin: https://app.example` returns 200 `{code, expiresAt, connectorUrl}`, `code` matches `/^[0-9A-Z]{5}-[0-9A-Z]{5}$/`, `connectorUrl === https://relay.example/v1/channels/{ch}/call`, ACAO `*`, `cache-control: no-store`. Also: no/other Origin gives 403 `executor_origin_forbidden`; caller credential gives 403 `invalid_credential`; GET gives 405; OPTIONS gives 204.
2. 401: `POST connectorUrl` with no token returns 401 with exact `WWW-Authenticate: Bearer resource_metadata="https://relay.example/.well-known/oauth-protected-resource/v1/channels/{ch}/call"`; with `Authorization: Bearer junk` adds `, error="invalid_token"`; ACAO `*` and `www-authenticate` exposed.
3. Metadata: fetch the URL from the header, check `resource` and `authorization_servers == [origin + "/c/" + ch]`; fetch `/.well-known/oauth-authorization-server/c/{ch}`, check issuer, `/c/{ch}/oauth/*` endpoints and `S256`.
4. Register at `/c/{ch}/oauth/register` with `redirect_uris:["http://127.0.0.1:8765/cb"]`, `client_name:"Test Client"` to get `client_id`.
5. Authorize GET at `/c/{ch}/oauth/authorize` with PKCE S256 (verifier generated with WebCrypto in the test) and `resource=connectorUrl` (a second variant omits `resource` and succeeds): 200 HTML containing `Test Client`, the host `127.0.0.1:8765` and the pairing input, CSP header present.
6. Authorize POST with the code from step 1: 302 to `http://127.0.0.1:8765/cb?code=...&state=xyz`.
7. Token (form-encoded): 200, `token_type` Bearer, `expires_in` 3600, both tokens.
8. Bearer call: `POST connectorUrl` with `Authorization: Bearer <access>` and body `hello`; the echo executor receives a frame whose `request.headers` has NO `authorization` (the existing allow-list strips it) and body `hello`; response echoes `hello`.
9. Refresh: `grant_type=refresh_token` yields a working new access token (bearer call succeeds again).
Negatives (each own `it`): wrong pairing code gives 400 and no `Location`; wrong `code_verifier` gives 400 `invalid_grant`; wrong `redirect_uri` at the token step gives 400 `invalid_grant`; wrong `redirect_uri` at authorize gives 400 error page, no redirect; access token used as `refresh_token` and refresh token used as bearer both rejected (400 `invalid_grant` / 401 `invalid_token`); caller capability token used as bearer gives 401; access token for channel A on channel B's `/call` gives 401; **old capability route still works**: `bootstrap.callerUrl` call reaches the echo executor exactly as before (existing tests also still pass).
Time: the Workers integration suite uses NO fake timers and makes no time-dependent assertions (expired pairing code, expired auth code, expired tokens are Node unit tests with injected `now`). Do not add a clock binding to `Env`.

### 7. README "Auth" section (new, after "Browser callers / CORS")

Document: the flow in six lines; all routes and statuses from section 4 (including the per-channel issuer `/c/{ch}`); runtime scope ("Fetch API + WebCrypto; Node 20+, Bun, Deno via a bundler"); a recommended platform rate-limit rule on `/c/*/oauth/authorize`; claim table and lifetimes; pairing code construction (so another implementation can follow); the `Authorization` header is verified by the relay and never forwarded (existing allow-list); the capability URL route remains for backward compatibility. Also fix existing text that becomes wrong: the "relay never challenges" statements (security headers/CORS paragraph, `selectSafeResponseHeaders` mention is unaffected) and the OPTIONS list (now includes the bearer `/call` and pairing routes). Add a "Known ceilings" list:

- An auth code can be replayed within its 120 s lifetime; PKCE (verifier) plus exact `redirect_uri` binding contain it.
- No per-IP rate limit; a 50-bit code in a 10 to 20 minute acceptance window is not practically brute-forceable, but nothing throttles attempts. README recommends a platform rate-limit rule on `/c/*/oauth/authorize` (for example a Cloudflare rate-limiting rule).
- Refresh tokens are not rotated or revoked individually (stateless); an old refresh token lives to its expiry.
- Revocation: Rotate in the client mints a new channel, so old tokens reach no executor; global kill is rotating `RELAY_HMAC_KEY` (also invalidates all capability URLs).
- The pairing code is deterministic per (channel, window): re-requesting returns the same code until the window rolls (clients must not offer a "new code" action).

Also list `PairingResponse`, `PAIRING_ROUTE`, `PAIRING_WINDOW_SECONDS`, `PAIRING_CODE_LENGTH`, `pairingPath`, `connectorPath` in the "Protocol entry" bullet list.

---

## Phases

### Phase 1: Foundations (credentials, protocol, test runner)

**Goal:** typed signing exists and is proven byte-compatible; the wire types exist; vitest runs a Node project.

**Agent:** Relay Worker

#### Tasks

- [x] `src/credentials.ts`: widen `signCredential`, add `verifyClaims` (internal), `signTyped`, `verifyTyped`, `ClaimTyp`; re-express `signCredential`/`verifyCredential` on top; add the `typ === undefined` condition to `claimsAreValid`.
- [x] `src/protocol.ts`: add `PairingResponse`, `PAIRING_ROUTE`, `PAIRING_WINDOW_SECONDS`, `PAIRING_CODE_LENGTH`, `pairingPath`, `connectorPath`. No imports.
- [x] `vitest.config.ts`: switch to `test.projects` as specified in section 6.
- [x] `test/credentials.test.ts`: byte-compat fixtures and typed cases.
- [x] `test/oauth-portability.test.ts`: guard covering `src/credentials.ts` and the `protocol.ts` exports now; the `src/oauth.ts` entry is added in Phase 2 when the file exists.

#### Acceptance Criteria

- [x] Fixture literals verify under `verifyCredential` and re-sign to identical bytes.
- [x] A `signTyped("access")` token fails `verifyCredential`; a capability token fails `verifyTyped`.
- [x] All 27 original tests still pass in the `workers` project; a Node-project smoke test runs outside workerd.

#### Testing

```bash
npm run check
```

#### Milestone gate

1. Acceptance criteria met.
2. `npm run check` passes.
3. Tick the checkboxes in this plan.
4. Commit with a message referencing `(#12)` (owner instruction required to commit; do not push to a PR).

### Phase 2: `src/oauth.ts` (all endpoints), unit tests

**Goal:** the portable module is complete and fully unit-tested in Node.

**Agent:** Relay Worker, then Reviewer: security

#### Tasks

- [x] Create `src/oauth.ts` with `handleAuth`, `verifyBearer`, `issuePairing`, pairing-code helpers, `validateAuthRequest`, HTML renderers, per section 4. Imports allowed: `./credentials`, `./protocol` only.
- [x] `test/oauth.node.test.ts` per section 6.
- [x] Extend `test/oauth-portability.test.ts` to cover `src/oauth.ts`.

#### Acceptance Criteria

- [x] Every unit-test group in section 6 present and green in the `node` project.
- [x] Guard test green for `oauth.ts` and `credentials.ts`.
- [x] Security reviewer signs off: constant-time compares for pairing code and PKCE, no reflection of unescaped input, no redirect on any validation failure, `typ` checked on every verify.

#### Testing

```bash
npm run check
```

#### Milestone gate

Same as Phase 1 (tick boxes, `npm run check`, commit referencing `(#12)` when instructed).

### Phase 3: Wire into the Worker, integration test, README

**Goal:** the deployed Worker exposes the full flow; legacy routes unchanged; contract documented.

**Agent:** Relay Worker, then Reviewer: contract

#### Tasks

- [x] `src/index.ts` changes 1 to 8 in section 5, including `forwardCall` factoring with no duplicated forwarding code.
- [x] Integration tests in `test/relay.integration.test.ts` per section 6.
- [x] README "Auth" section and corrections.

#### Acceptance Criteria

- [x] Full flow test green; every negative test green; legacy capability route test green.
- [x] `grep -c "arrayBuffer" src/index.ts` shows the body-read exists once (single shared handler).
- [x] README documents every route and all ceilings listed in section 7.
- [x] Contract reviewer confirms `protocol.ts` additions are what srs-web#447 needs (pairing route constant, response type) and that the file remains import-free. (lead, 2026-10-05: PairingResponse, PAIRING_ROUTE, pairingPath, connectorPath; srs-web derives the executor credential from its stored executorUrl.)

#### Testing

```bash
npm run check
```

#### Milestone gate

Same as Phase 1. Push the branch only; the owner reviews the diff before any PR.

---

## Deviations

- Code review round 1 (9 items) applied in `fix: code review findings (#12)`: bounded `readBody` lives in `src/http.ts` and is used by `forwardCall` and `oauth.ts`; guard also bans dynamic import, `require`, `process`, `Buffer`, `node:`; repeated authorize params rejected; token endpoint checks form content-type and validates `resource` before PKCE; early-return in `handleAuth`.

- Shared HTTP helpers (`withCors`, `preflight`, `SECURITY_HEADERS`, `jsonResponse`, `errorResponse`, `methodNotAllowed`) live in a new portable `src/http.ts` (Fetch API only, no Cloudflare imports), imported by both `index.ts` and `oauth.ts`, instead of being exported from `oauth.ts` (lead decision). The portability guard covers `src/http.ts` too and allows `./http` as an import.
- Phase 2: also added `src/http.ts` (see above) and exported `signingKey` from `credentials.ts` for the pairing HMAC; `oauth.ts` additionally exports `normalisePairingCode` and `constantTimeEqual` for tests. `preflight(request, methods?)` takes an optional allow-methods string so JSON OAuth endpoints answer `GET|POST, OPTIONS`; its allow-headers default is the existing list plus `authorization` (reflected when requested), not the narrower `content-type, authorization`.
- Phase 3: the contract-reviewer criterion is left unticked (outside this worker's scope). Integration tests build a fresh channel and echo executor per test (`setup()`).
- Phase 2: the security-reviewer sign-off criterion is left unticked (reviewer agents are outside this worker's scope).
- Phase 1: the node-project smoke test is `test/smoke.node.test.ts`; Phase 2 adds the real `oauth.node.test.ts`.

## Final Acceptance

- [x] `npm run check` (typecheck + vitest, both projects) passes
- [x] `src/oauth.ts` and `src/credentials.ts` contain no `cloudflare:` import (guard test)
- [x] `src/protocol.ts` still has no imports (existing guard)
- [x] Capability tokens minted by the pre-change code verify unchanged
- [x] Full pair, 401, metadata, register, authorize, token, bearer-call, refresh flow passes in the integration suite
- [x] No new dependencies; `package.json` dependencies untouched; no wrangler changes

## Coordination Rules

- Relay Worker keeps to this repository (`browser-executor-relay-wt-12` worktree) only. Never edit srs-web or semanticops-relay.
- No storage of any kind (no KV, D1, DO storage) and no new bindings.
- The relay stays application-agnostic: no mention of MCP in code identifiers or behaviour; README may name the MCP authorization spec as the interoperability target.
- Do not log secrets, codes or tokens. No `console.*` calls in `src/`.
- The `protocol.ts` additions are the contract srs-web will vendor; freeze names before #447 starts.

## Assumptions

- Real-client behaviour (claude.ai, Claude Code, MCP Inspector) is NOT verified here: semanticops-relay#1 owns that. Known risk: clients implementing only the older 2025-03-26 MCP authorization spec skip RFC 9728 protected-resource discovery and may omit `resource`, and may also probe `/.well-known/oauth-authorization-server` at the root (which the relay does not serve, as it has no single issuer). The per-channel issuer mitigates the missing-`resource` case; the root-probe case is untested and may still fail. Verified only in semanticops-relay#1.
- `resource` is optional at authorize and token (when present it must match after normalisation); the channel is bound by the issuer path and the signed code.
- Authorize failures never redirect (error page only), simpler and safer than RFC 6749 error redirects.
- `form-action` includes the validated redirect_uri origin (Chrome applies form-action to post-submit redirects); confirm in semanticops-relay#1.
- `expiresAt` is the end of the current 10-minute window (conservative); the code actually remains acceptable through the next window.
- A `/c/{ch}` issuer is used instead of one global issuer (review decision); the global `/.well-known/oauth-authorization-server` is therefore not served.
- Pairing code is 50 bits (10 chars, review decision).
- `verifyBearer` takes `origin` in its options (not in the brief) to build the absolute `resource_metadata` URL.
- Only https and loopback-http redirect_uris are accepted (custom schemes would break `form-action`).
- Vitest `test.projects` was verified against vitest 4.1.11 / the installed Cloudflare plugin in this worktree (throwaway config, deleted).
- No CI workflows exist in this repo; the gate is local `npm run check`.

## Post-merge fix (#14)

claude.ai derives the AS metadata URL from the resource path (anthropics/claude-ai-mcp#376), so the issuer is now the connector URL `<origin>/v1/channels/{ch}/call`. AS metadata is served at `/.well-known/oauth-authorization-server/v1/channels/{ch}/call` (RFC 8414 path insertion) and no longer at `/.well-known/oauth-authorization-server/c/{ch}`; the PRM advertises `authorization_servers: [<connector URL>]`. Endpoints stay at `/c/{ch}/oauth/{register,authorize,token}`. This supersedes the `/c/{ch}` issuer wording above.
