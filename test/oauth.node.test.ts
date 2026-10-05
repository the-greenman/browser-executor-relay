import { describe, expect, it } from "vitest";
import { signCredential, signTyped } from "../src/credentials";
import { constantTimeEqual, handleAuth, issuePairing, normalisePairingCode, verifyBearer } from "../src/oauth";
import type { AuthOptions } from "../src/oauth";
import { base64UrlEncode } from "../src/protocol";

const KEY = "unit-test-key";
const ORIGIN = "https://relay.example";
const CH = "A".repeat(43);
const CH2 = "B".repeat(43);
const T0 = 1_700_000_000_000;
const REDIRECT = "http://127.0.0.1:8765/cb";
let clock = T0;
const opts: AuthOptions = { key: KEY, origin: ORIGIN, now: () => clock };
const resource = (ch = CH) => `${ORIGIN}/v1/channels/${ch}/call`;

const callOrNull = (path: string, init?: RequestInit) => handleAuth(new Request(ORIGIN + path, init), opts);
const call = async (path: string, init?: RequestInit): Promise<Response> => {
  const res = await callOrNull(path, init);
  if (!res) throw new Error(`not owned: ${path}`);
  return res;
};
const form = (fields: Record<string, string>) => ({
  method: "POST",
  headers: { "content-type": "application/x-www-form-urlencoded" },
  body: new URLSearchParams(fields),
});

async function sha256Challenge(verifier: string): Promise<string> {
  return base64UrlEncode(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier)));
}
const VERIFIER = "v".repeat(50);

async function registerClient(uris: unknown = [REDIRECT], name: unknown = "Test Client", ch = CH) {
  const res = await call(`/c/${ch}/oauth/register`, {
    method: "POST",
    body: JSON.stringify({ redirect_uris: uris, client_name: name }),
  });
  return { res: res!, body: (await res!.clone().json()) as Record<string, unknown> };
}

async function authParams(overrides: Record<string, string | undefined> = {}) {
  const { body } = await registerClient();
  const params: Record<string, string | undefined> = {
    client_id: body.client_id as string,
    redirect_uri: REDIRECT,
    response_type: "code",
    code_challenge: await sha256Challenge(VERIFIER),
    code_challenge_method: "S256",
    state: "xyz",
    ...overrides,
  };
  return Object.fromEntries(Object.entries(params).filter(([, v]) => v !== undefined)) as Record<string, string>;
}

const authorizeGet = (params: Record<string, string>, ch = CH) =>
  call(`/c/${ch}/oauth/authorize?${new URLSearchParams(params)}`);
const authorizePost = (params: Record<string, string>, ch = CH) => call(`/c/${ch}/oauth/authorize`, form(params));
const tokenPost = (params: Record<string, string>, ch = CH) => call(`/c/${ch}/oauth/token`, form(params));

async function fullFlow() {
  const params = await authParams();
  const { code } = await issuePairing(CH, opts);
  const redirected = await authorizePost({ ...params, pairing_code: code });
  const authCode = new URL(redirected.headers.get("location") ?? "").searchParams.get("code") ?? "";
  const res = await tokenPost({
    grant_type: "authorization_code",
    code: authCode,
    redirect_uri: REDIRECT,
    client_id: params.client_id,
    code_verifier: VERIFIER,
  });
  return { params, authCode, res, tokens: (await res.clone().json()) as Record<string, string> };
}

const bearer = (token: string) => new Request(resource(), { method: "POST", headers: { authorization: `Bearer ${token}` } });

describe("runtime", () => {
  it("runs outside workerd", () => {
    expect((globalThis as { WebSocketPair?: unknown }).WebSocketPair).toBeUndefined();
  });
});

describe("pairing code", () => {
  it("normalises Crockford input", () => {
    expect(normalisePairingCode(" abcde-fghjk ")).toBe("ABCDEFGHJK");
    expect(normalisePairingCode("il0o1-0o1il")).toBe("1100100111");
    expect(normalisePairingCode("ABCDE-FGHJ")).toBeNull();
    expect(normalisePairingCode("ABCDE-FGHJKM")).toBeNull();
    expect(normalisePairingCode("ABCDE-FGHJU")).toBeNull();
  });

  it("is deterministic per window, accepted for current and previous window only, and channel-bound", async () => {
    clock = T0;
    const a = await issuePairing(CH, opts);
    expect(a.code).toMatch(/^[0-9A-Z]{5}-[0-9A-Z]{5}$/);
    expect((await issuePairing(CH, opts)).code).toBe(a.code);
    expect((await issuePairing(CH2, opts)).code).not.toBe(a.code);
    expect(a.connectorUrl).toBe(resource());
    expect(a.expiresAt).toBe((Math.floor(T0 / 600_000) + 1) * 600_000);

    const params = await authParams();
    const submit = async (code: string, ch = CH) => (await authorizePost({ ...params, pairing_code: code }, ch)).status;
    expect(await submit(a.code)).toBe(302);
    expect(await submit(a.code.toLowerCase().replace("-", " "))).toBe(302);
    expect(await submit(a.code, CH2)).toBe(400);
    clock = a.expiresAt + 1; // next window: previous still ok
    expect(await submit(a.code)).toBe(302);
    clock = a.expiresAt + 600_000 + 1; // two windows on
    expect(await submit(a.code)).toBe(400);
    clock = T0;
  });

  it("constantTimeEqual compares", () => {
    expect(constantTimeEqual("ABCDE", "ABCDE")).toBe(true);
    expect(constantTimeEqual("ABCDE", "ABCDF")).toBe(false);
    expect(constantTimeEqual("ABCDE", "ABCD")).toBe(false);
  });
});

describe("dispatch and metadata", () => {
  it("returns null for paths it does not own", async () => {
    for (const path of ["/", "/v1/channels", `/v1/channels/${CH}/call`, "/c/short/oauth/token", `/c/${CH}/other`, "/.well-known/oauth-authorization-server"]) {
      expect(await callOrNull(path)).toBeNull();
    }
  });

  it("serves RFC 9728 and RFC 8414 documents with security headers and CORS", async () => {
    clock = T0;
    const pr = (await call(`/.well-known/oauth-protected-resource/v1/channels/${CH}/call`));
    expect(await pr.json()).toEqual({
      resource: resource(),
      authorization_servers: [`${ORIGIN}/c/${CH}`],
      bearer_methods_supported: ["header"],
    });
    expect(pr.headers.get("access-control-allow-origin")).toBe("*");
    expect(pr.headers.get("cache-control")).toBe("no-store");
    expect(pr.headers.get("x-frame-options")).toBe("DENY");
    const md = (await (await call(`/.well-known/oauth-authorization-server/c/${CH}`))!.json()) as Record<string, unknown>;
    expect(md).toMatchObject({
      issuer: `${ORIGIN}/c/${CH}`,
      authorization_endpoint: `${ORIGIN}/c/${CH}/oauth/authorize`,
      token_endpoint: `${ORIGIN}/c/${CH}/oauth/token`,
      registration_endpoint: `${ORIGIN}/c/${CH}/oauth/register`,
      code_challenge_methods_supported: ["S256"],
    });
  });

  it("answers wrong methods with 405 and OPTIONS with 204", async () => {
    const wrong = (await call(`/c/${CH}/oauth/token`));
    expect(wrong.status).toBe(405);
    expect(wrong.headers.get("allow")).toBe("POST");
    expect((await call(`/.well-known/oauth-protected-resource/v1/channels/${CH}/call`, { method: "POST" }))!.status).toBe(405);
    const pre = (await call(`/c/${CH}/oauth/token`, { method: "OPTIONS" }));
    expect(pre.status).toBe(204);
    expect(pre.headers.get("access-control-allow-methods")).toBe("POST, OPTIONS");
    expect((await call(`/c/${CH}/oauth/authorize`, { method: "PUT" }))!.status).toBe(405);
    expect((await call(`/c/${CH}/oauth/authorize`, { method: "OPTIONS" }))!.status).toBe(405);
  });
});

describe("register", () => {
  it("registers a client without a secret", async () => {
    const { res, body } = await registerClient(["https://claude.ai/cb", "http://localhost:1/x", "http://[::1]:2/y"]);
    expect(res.status).toBe(201);
    expect(body).toMatchObject({ client_name: "Test Client", token_endpoint_auth_method: "none", grant_types: ["authorization_code", "refresh_token"] });
    expect(body).not.toHaveProperty("client_secret");
    expect(typeof body.client_id).toBe("string");
  });

  it.each([
    ["http non-loopback", ["http://evil.example/cb"]],
    ["fragment", ["https://a.example/cb#x"]],
    ["custom scheme", ["myapp://cb"]],
    ["embedded credentials", ["https://u:p@a.example/cb"]],
    ["six uris", Array.from({ length: 6 }, (_, i) => `https://a.example/${i}`)],
    ["empty", []],
    ["too long", [`https://a.example/${"x".repeat(200)}`]],
    ["not an array", "https://a.example/cb"],
  ])("rejects redirect_uris: %s", async (_name, uris) => {
    const { res, body } = await registerClient(uris);
    expect(res.status).toBe(400);
    expect(body.error).toBe("invalid_redirect_uri");
  });

  it("validates client_name and sanitises control characters", async () => {
    expect((await registerClient([REDIRECT], "x".repeat(101))).res.status).toBe(400);
    expect((await registerClient([REDIRECT], 5)).res.status).toBe(400);
    expect((await registerClient([REDIRECT], "  A\u0000B\n ")).body.client_name).toBe("AB");
    expect((await registerClient([REDIRECT], "   ")).body.client_name).toBe("MCP client");
  });

  it("counts body bytes read, not content-length", async () => {
    const big = JSON.stringify({ redirect_uris: [REDIRECT], pad: "x".repeat(9000) });
    const stream = new ReadableStream({ start: (c) => (c.enqueue(new TextEncoder().encode(big)), c.close()) });
    const res = (await call(`/c/${CH}/oauth/register`, { method: "POST", body: stream, duplex: "half" } as RequestInit));
    expect(res.status).toBe(400);
    expect(((await res.json()) as { error: string }).error).toBe("invalid_client_metadata");
  });
});

describe("authorize", () => {
  it("renders the form with quoted client name, redirect host, input and exact CSP", async () => {
    const res = await authorizeGet(await authParams({ resource: resource() }));
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain("&ldquo;Test Client&rdquo;");
    expect(html).toContain("127.0.0.1:8765");
    expect(html).toContain('name="pairing_code"');
    expect(html).toContain(`action="/c/${CH}/oauth/authorize"`);
    expect(res.headers.get("content-security-policy")).toBe(
      "default-src 'none'; style-src 'unsafe-inline'; form-action 'self' http://127.0.0.1:8765; frame-ancestors 'none'; base-uri 'none'",
    );
    expect(res.headers.get("x-content-type-options")).toBe("nosniff");
    expect(res.headers.get("x-frame-options")).toBe("DENY");
    expect(res.headers.get("cache-control")).toBe("no-store");
    expect(res.headers.get("content-type")).toBe("text/html; charset=utf-8");
    expect(res.headers.get("access-control-allow-origin")).toBeNull();
  });

  it("shows the real host for a https redirect", async () => {
    const { body } = await registerClient(["https://claude.ai/api/mcp/auth_callback"]);
    const params = await authParams({ client_id: body.client_id as string, redirect_uri: "https://claude.ai/api/mcp/auth_callback" });
    expect(await (await authorizeGet(params)).text()).toContain("claude.ai");
  });

  it("escapes client_name and hidden values", async () => {
    const { body } = await registerClient([REDIRECT], `<script>alert(1)</script>"`);
    const html = await (await authorizeGet(await authParams({ client_id: body.client_id as string, state: `"><b>` }))).text();
    expect(html).not.toContain("<script>");
    expect(html).not.toContain(`"><b>`);
    expect(html).toContain("&#60;script&#62;");
  });

  it("accepts a missing resource and normalises a present one", async () => {
    expect((await authorizeGet(await authParams())).status).toBe(200);
    expect((await authorizeGet(await authParams({ resource: resource() + "/" }))).status).toBe(200);
    expect((await authorizeGet(await authParams({ resource: resource().replace("relay.example", "RELAY.EXAMPLE") }))).status).toBe(200);
    expect((await authorizeGet(await authParams({ resource: resource(CH2) }))).status).toBe(400);
    expect((await authorizeGet(await authParams({ resource: resource() + "?x=1" }))).status).toBe(400);
  });

  it.each([
    ["bad client_id", { client_id: "junk" }],
    ["unregistered redirect_uri", { redirect_uri: "http://127.0.0.1:8765/other" }],
    ["bad response_type", { response_type: "token" }],
    ["plain method", { code_challenge_method: "plain" }],
    ["missing challenge", { code_challenge: undefined }],
    ["short challenge", { code_challenge: "abc" }],
    ["long state", { state: "s".repeat(513) }],
  ])("shows an error page and never redirects: %s", async (_name, override) => {
    const res = await authorizeGet(await authParams(override));
    expect(res.status).toBe(400);
    expect(res.headers.get("location")).toBeNull();
    expect(res.headers.get("content-security-policy")).toContain("form-action 'none'");
  });

  it("is not owned for a malformed channel in the path", async () => {
    expect(await callOrNull("/c/short/oauth/authorize")).toBeNull();
  });

  it("POST wrong code re-renders with 400 and no Location; right code redirects with state and keeps the query", async () => {
    clock = T0;
    const params = await authParams();
    const wrong = await authorizePost({ ...params, pairing_code: "00000-00000" });
    expect(wrong.status).toBe(400);
    expect(wrong.headers.get("location")).toBeNull();
    const html = await wrong.text();
    expect(html).toContain("That code is not valid or has expired.");
    expect(html).toContain(`name="client_id" value="${params.client_id}"`);

    const { body } = await registerClient(["https://a.example/cb?keep=1"]);
    const p2 = await authParams({ client_id: body.client_id as string, redirect_uri: "https://a.example/cb?keep=1" });
    const ok = await authorizePost({ ...p2, pairing_code: (await issuePairing(CH, opts)).code });
    expect(ok.status).toBe(302);
    const location = new URL(ok.headers.get("location")!);
    expect(location.origin + location.pathname).toBe("https://a.example/cb");
    expect(location.searchParams.get("keep")).toBe("1");
    expect(location.searchParams.get("state")).toBe("xyz");
    expect(location.searchParams.get("code")).toBeTruthy();
    expect(ok.headers.get("cache-control")).toBe("no-store");
  });

  it("POST re-validates hidden fields and rejects other encodings and oversize bodies", async () => {
    const params = await authParams();
    const { code } = await issuePairing(CH, opts);
    expect((await authorizePost({ ...params, redirect_uri: "https://evil.example/cb", pairing_code: code })).status).toBe(400);
    const json = (await call(`/c/${CH}/oauth/authorize`, { method: "POST", headers: { "content-type": "application/json" }, body: "{}" }));
    expect(json.status).toBe(400);
    const big = (await authorizePost({ ...params, pairing_code: code, pad: "x".repeat(9000) }));
    expect(big.status).toBe(400);
    expect(big.headers.get("location")).toBeNull();
  });
});

describe("token", () => {
  it("issues access and refresh tokens for a valid code", async () => {
    clock = T0;
    const { res, tokens } = await fullFlow();
    expect(res.status).toBe(200);
    expect(res.headers.get("pragma")).toBe("no-cache");
    expect(res.headers.get("access-control-allow-origin")).toBe("*");
    expect(tokens).toMatchObject({ token_type: "Bearer", expires_in: 3600 });
    expect(tokens).not.toHaveProperty("scope");
    expect(await verifyBearer(bearer(tokens.access_token), CH, opts)).toBeNull();
  });

  it("rejects bad grants with RFC 6749 errors", async () => {
    clock = T0;
    const { params, authCode } = await fullFlow();
    const base = { grant_type: "authorization_code", code: authCode, redirect_uri: REDIRECT, client_id: params.client_id, code_verifier: VERIFIER };
    const err = async (over: Record<string, string>, ch = CH) => {
      const res = await tokenPost({ ...base, ...over }, ch);
      expect(res.status).toBe(400);
      expect(res.headers.get("pragma")).toBe("no-cache");
      return ((await res.json()) as { error: string }).error;
    };
    expect(await err({ code_verifier: "w".repeat(50) })).toBe("invalid_grant");
    expect(await err({ code_verifier: "short" })).toBe("invalid_request");
    expect(await err({ redirect_uri: "http://127.0.0.1:8765/other" })).toBe("invalid_grant");
    expect(await err({ client_id: (await registerClient([REDIRECT], "Other")).body.client_id as string })).toBe("invalid_grant");
    expect(await err({ client_id: "junk" })).toBe("invalid_client");
    expect(await err({ resource: resource(CH2) })).toBe("invalid_target");
    expect(await err({}, CH2)).toBe("invalid_grant"); // per-channel issuer
    expect(await err({ code: "junk" })).toBe("invalid_grant");
    expect(await err({ grant_type: "password" })).toBe("unsupported_grant_type");
    expect((await tokenPost({ ...base, resource: resource() })).status).toBe(200);
    expect((await tokenPost({ ...base, resource: resource() + "/" })).status).toBe(200);
  });

  it("expires the auth code after 120 s", async () => {
    clock = T0;
    const { params, authCode } = await fullFlow();
    const base = { grant_type: "authorization_code", code: authCode, redirect_uri: REDIRECT, client_id: params.client_id, code_verifier: VERIFIER };
    clock = T0 + 120_000 - 1;
    expect((await tokenPost(base)).status).toBe(200);
    clock = T0 + 120_000;
    expect((await tokenPost(base)).status).toBe(400);
    clock = T0;
  });

  it("refresh grant issues a new pair; wrong client, wrong channel, and typed substitutions are rejected", async () => {
    clock = T0;
    const { params, tokens } = await fullFlow();
    const refresh = async (r: string, extra: Record<string, string> = {}, ch = CH) =>
      tokenPost({ grant_type: "refresh_token", refresh_token: r, ...extra }, ch);
    const ok = await refresh(tokens.refresh_token, { client_id: params.client_id });
    expect(ok.status).toBe(200);
    expect(await verifyBearer(bearer(((await ok.json()) as Record<string, string>).access_token), CH, opts)).toBeNull();
    expect((await refresh(tokens.refresh_token)).status).toBe(200);
    expect((await refresh(tokens.refresh_token, { client_id: "other" })).status).toBe(400);
    expect((await refresh(tokens.refresh_token, {}, CH2)).status).toBe(400);
    expect((await refresh(tokens.access_token)).status).toBe(400); // access as refresh
    expect((await refresh("junk")).status).toBe(400);
    // lifetimes: refresh 30 d, access 1 h
    clock = T0 + 2_592_000_000 - 1;
    expect((await refresh(tokens.refresh_token)).status).toBe(200);
    clock = T0 + 2_592_000_000;
    expect((await refresh(tokens.refresh_token)).status).toBe(400);
    clock = T0;
  });

  it("rejects an oversize token body on bytes read", async () => {
    const res = await tokenPost({ grant_type: "refresh_token", refresh_token: "x".repeat(9000) });
    expect(res.status).toBe(400);
    expect(((await res.json()) as { error: string }).error).toBe("invalid_request");
  });
});

describe("verifyBearer", () => {
  const challenge = `Bearer resource_metadata="${ORIGIN}/.well-known/oauth-protected-resource/v1/channels/${CH}/call"`;
  const check = (headers: Record<string, string>, ch = CH) => verifyBearer(new Request(resource(), { method: "POST", headers }), ch, opts);

  it("challenges with the exact strings", async () => {
    clock = T0;
    const none = (await check({})) as Response;
    expect(none.status).toBe(401);
    expect(none.headers.get("www-authenticate")).toBe(challenge);
    expect(none.headers.get("content-type")).toContain("application/json");
    expect(none.headers.get("cache-control")).toBe("no-store");
    expect(await none.json()).toEqual({ error: "unauthorized" });
    for (const authorization of ["Bearer junk", "Basic abc", "Bearer", "Bearer  two"]) {
      const bad = (await check({ authorization })) as Response;
      expect(bad.status).toBe(401);
      expect(bad.headers.get("www-authenticate")).toBe(`${challenge}, error="invalid_token"`);
      expect(await bad.json()).toEqual({ error: "invalid_token" });
    }
  });

  it("accepts only a live access token for the same channel; scheme is case-insensitive", async () => {
    clock = T0;
    const access = await signTyped("access", { role: "caller", channel: CH }, 3600, KEY, T0);
    expect(await check({ authorization: `bearer ${access}` })).toBeNull();
    expect(await check({ authorization: `Bearer ${access}` }, CH2)).not.toBeNull();
    clock = T0 + 3_600_000 - 1;
    expect(await check({ authorization: `Bearer ${access}` })).toBeNull();
    clock = T0 + 3_600_000;
    expect(await check({ authorization: `Bearer ${access}` })).not.toBeNull();
    clock = T0;
  });

  it("rejects every other typ and capability credentials", async () => {
    clock = T0;
    const mk = (typ: "client" | "code" | "refresh" | "access", claims: Record<string, unknown>) => signTyped(typ, claims, typ === "client" ? null : 3600, KEY, T0);
    const tokens = [
      await mk("refresh", { channel: CH, client_id: "c" }),
      await mk("code", { channel: CH, role: "caller" }),
      await mk("client", { channel: CH, role: "caller" }),
      await mk("access", { role: "executor", channel: CH }),
      await signCredential({ channel: CH, role: "caller", version: 1 }, KEY),
    ];
    for (const t of tokens) expect(await check({ authorization: `Bearer ${t}` })).not.toBeNull();
    // client id as code, code as client id
    const params = await authParams();
    const asCode = await tokenPost({ grant_type: "authorization_code", code: params.client_id, redirect_uri: REDIRECT, client_id: params.client_id, code_verifier: VERIFIER });
    expect(asCode.status).toBe(400);
  });
});
