import { exports } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import { base64UrlDecode, base64UrlEncode, connectorPath, pairingPath } from "../src/protocol";
import type { ChannelBootstrap, PairingResponse, RelayRequestFrame } from "../src/protocol";

const worker = exports as unknown as {
  default: { fetch(input: RequestInfo, init?: RequestInit): Promise<Response> };
};

function nextMessage(socket: WebSocket): Promise<string> {
  return new Promise((resolve) => socket.addEventListener("message", (event) => resolve(event.data as string), { once: true }));
}

function nextMessages(socket: WebSocket, count: number): Promise<string[]> {
  return new Promise((resolve) => {
    const messages: string[] = [];
    socket.addEventListener("message", (event) => {
      messages.push(event.data as string);
      if (messages.length === count) resolve(messages);
    });
  });
}

describe("generic relay", () => {
  it("relays an opaque HTTP request through a generic echo executor", async () => {
    const bootstrapResponse = await worker.default.fetch("https://relay.example/v1/channels", { method: "POST" });
    expect(bootstrapResponse.status).toBe(200);
    const bootstrap = (await bootstrapResponse.json()) as ChannelBootstrap;

    const executorResponse = await worker.default.fetch(bootstrap.executorUrl.replace("wss:", "https:"), {
      headers: {
        upgrade: "websocket",
        origin: "https://app.example",
        "x-relay-executor-generation": "test-executor-generation-0001",
      },
    });
    const executor = executorResponse.webSocket;
    expect(executorResponse.status).toBe(101);
    expect(executor).not.toBeNull();
    executor?.accept();

    const incoming = nextMessage(executor!);
    const caller = worker.default.fetch(bootstrap.callerUrl, {
      method: "POST",
      headers: {
        authorization: "Bearer deliberately-not-forwarded",
        accept: "application/x-example",
        "content-type": "application/octet-stream",
      },
      body: Uint8Array.from([0, 1, 255]),
    });
    const frame = JSON.parse(await incoming) as RelayRequestFrame;
    expect(frame.request.method).toBe("POST");
    expect(frame.request.contentType).toBe("application/octet-stream");
    expect(frame.request.headers).toEqual({ accept: "application/x-example" });
    expect(frame.request.body).toBe(base64UrlEncode(Uint8Array.from([0, 1, 255])));

    executor?.send(
      JSON.stringify({
        version: 1,
        type: "response",
        requestId: frame.requestId,
        executorGeneration: frame.executorGeneration,
        response: {
          status: 201,
          headers: { "cache-control": "public", "content-type": "application/x-example", "set-cookie": "not-forwarded" },
          body: base64UrlEncode(Uint8Array.from([255, 1, 0])),
        },
      }),
    );

    const response = await caller;
    expect(response.status).toBe(201);
    expect(response.headers.get("content-type")).toBe("application/x-example");
    expect(response.headers.get("set-cookie")).toBeNull();
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(response.headers.get("referrer-policy")).toBe("no-referrer");
    expect(new Uint8Array(await response.arrayBuffer())).toEqual(Uint8Array.from([255, 1, 0]));
    executor?.close();
  });

  it("does not reveal any application surface while its executor is offline", async () => {
    const bootstrap = (await (await worker.default.fetch("https://relay.example/v1/channels", { method: "POST" })).json()) as ChannelBootstrap;
    const response = await worker.default.fetch(bootstrap.callerUrl, { method: "POST", body: "opaque" });
    expect(response.status).toBe(503);
    await expect(response.json()).resolves.toEqual({ error: "executor_offline" });
  });

  describe("channel-bound executor origin", () => {
    const boot = async (origin?: string) =>
      worker.default.fetch("https://relay.example/v1/channels", { method: "POST", headers: origin === undefined ? {} : { origin } });
    const up = (b: ChannelBootstrap, origin?: string) =>
      worker.default.fetch(b.executorUrl.replace("wss:", "https:"), {
        headers: { upgrade: "websocket", "x-relay-executor-generation": "test-executor-generation-0000", ...(origin === undefined ? {} : { origin }) },
      });
    const claims = (url: string) => JSON.parse(atob(url.split("/").pop()!.split(".")[0].replace(/-/g, "+").replace(/_/g, "/")));

    it("binds the bootstrap Origin into the executor credential only", async () => {
      const b = (await (await boot("https://site.example")).json()) as ChannelBootstrap;
      expect(claims(b.executorUrl).origin).toBe("https://site.example");
      expect(claims(b.callerUrl).origin).toBeUndefined();
    });

    it("accepts the same origin, rejects other or missing origins", async () => {
      const b = (await (await boot("https://site.example")).json()) as ChannelBootstrap;
      expect((await up(b, "https://other.example")).status).toBe(403);
      const missing = await up(b);
      expect(missing.status).toBe(403);
      await expect(missing.json()).resolves.toEqual({ error: "executor_origin_forbidden" });
      expect((await up(b, "https://site.example")).status).toBe(101);
    });

    it("leaves non-browser bootstraps unbound", async () => {
      const b = (await (await boot()).json()) as ChannelBootstrap;
      expect(claims(b.executorUrl).origin).toBeUndefined();
      expect((await up(b)).status).toBe(101);
      const b2 = (await (await boot()).json()) as ChannelBootstrap;
      expect((await up(b2, "https://anything.example")).status).toBe(101);
    });

    it("fails the signature when the origin claim is tampered", async () => {
      const b = (await (await boot("https://site.example")).json()) as ChannelBootstrap;
      const parts = b.executorUrl.split("/");
      const [payload, sig] = parts.pop()!.split(".");
      const forged = btoa(JSON.stringify({ ...claims(b.executorUrl), origin: "https://evil.example" })).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
      expect(forged).not.toBe(payload);
      const res = await worker.default.fetch([...parts, `${forged}.${sig}`].join("/").replace("wss:", "https:"), {
        headers: { upgrade: "websocket", origin: "https://evil.example", "x-relay-executor-generation": "test-executor-generation-0000" },
      });
      expect(res.status).toBe(403);
      await expect(res.json()).resolves.toEqual({ error: "invalid_credential" });
    });

    it("rejects malformed and null Origins at bootstrap", async () => {
      for (const o of ["null", "https://site.example/path", "site.example", "https://site.example/"]) {
        const res = await boot(o);
        expect(res.status).toBe(400);
        await expect(res.json()).resolves.toEqual({ error: "invalid_origin" });
      }
    });
  });

  it("isolates concurrent callers even when their opaque application IDs collide", async () => {
    const bootstrap = (await (await worker.default.fetch("https://relay.example/v1/channels", { method: "POST" })).json()) as ChannelBootstrap;
    const executorResponse = await worker.default.fetch(bootstrap.executorUrl.replace("wss:", "https:"), {
      headers: {
        upgrade: "websocket",
        origin: "https://app.example",
        "x-relay-executor-generation": "test-executor-generation-0002",
      },
    });
    const executor = executorResponse.webSocket!;
    executor.accept();
    const incoming = nextMessages(executor, 2);
    const first = worker.default.fetch(bootstrap.callerUrl, { method: "POST", body: '{"id":1,"caller":"first"}' });
    const second = worker.default.fetch(bootstrap.callerUrl, { method: "POST", body: '{"id":1,"caller":"second"}' });
    const [frameOne, frameTwo] = (await incoming).map((message) => JSON.parse(message) as RelayRequestFrame);
    expect(frameOne.requestId).not.toBe(frameTwo.requestId);
    const frames = [frameOne, frameTwo];
    const firstFrame = frames.find((frame) => new TextDecoder().decode(base64UrlDecode(frame.request.body)!).includes('"first"'))!;
    const secondFrame = frames.find((frame) => new TextDecoder().decode(base64UrlDecode(frame.request.body)!).includes('"second"'))!;

    for (const [frame, result] of [[secondFrame, "second"], [firstFrame, "first"]] as const) {
      executor.send(JSON.stringify({
        version: 1,
        type: "response",
        requestId: frame.requestId,
        executorGeneration: frame.executorGeneration,
        response: { status: 200, headers: { "content-type": "text/plain" }, body: base64UrlEncode(new TextEncoder().encode(result)) },
      }));
    }
    await expect((await first).text()).resolves.toBe("first");
    await expect((await second).text()).resolves.toBe("second");
    executor.close();
  });

  it("returns an empty, protected 202 response when an executor omits the body", async () => {
    const bootstrap = (await (await worker.default.fetch("https://relay.example/v1/channels", { method: "POST" })).json()) as ChannelBootstrap;
    const executorResponse = await worker.default.fetch(bootstrap.executorUrl.replace("wss:", "https:"), {
      headers: {
        upgrade: "websocket",
        origin: "https://app.example",
        "x-relay-executor-generation": "test-executor-generation-0003",
      },
    });
    const executor = executorResponse.webSocket!;
    executor.accept();
    const incoming = nextMessage(executor);
    const caller = worker.default.fetch(bootstrap.callerUrl, { method: "POST", body: "opaque notification" });
    const frame = JSON.parse(await incoming) as RelayRequestFrame;
    executor.send(JSON.stringify({
      version: 1,
      type: "response",
      requestId: frame.requestId,
      executorGeneration: frame.executorGeneration,
      response: { status: 202, headers: {} },
    }));
    const response = await caller;
    expect(response.status).toBe(202);
    expect((await response.arrayBuffer()).byteLength).toBe(0);
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(response.headers.get("referrer-policy")).toBe("no-referrer");
    executor.close();
  });
});

describe("CORS for browser callers", () => {
  const CH = "A".repeat(43);
  it("answers preflight on both routes without credentials", async () => {
    for (const url of ["https://relay.example/v1/channels", `https://relay.example/v1/channels/${CH}/call/not-a-valid-credential`]) {
      const r = await worker.default.fetch(url, { method: "OPTIONS", headers: { "access-control-request-headers": "content-type, x-custom" } });
      expect(r.status).toBe(204);
      expect(r.headers.get("access-control-allow-origin")).toBe("*");
      expect(r.headers.get("access-control-allow-credentials")).toBeNull();
      expect(r.headers.get("access-control-allow-methods")).toBe("GET, POST, OPTIONS");
      expect(r.headers.get("access-control-allow-headers")).toBe("content-type, x-custom");
      expect(r.headers.get("access-control-max-age")).toBe("600");
    }
    const d = await worker.default.fetch("https://relay.example/v1/channels", { method: "OPTIONS" });
    expect(d.headers.get("access-control-allow-headers")).toContain("mcp-session-id");
  });

  it("adds ACAO to bootstrap, caller errors, and 404s; leaves executor alone", async () => {
    const boot = await worker.default.fetch("https://relay.example/v1/channels", { method: "POST" });
    expect(boot.headers.get("access-control-allow-origin")).toBe("*");
    expect(boot.headers.get("cache-control")).toBe("no-store");
    const b = (await boot.json()) as ChannelBootstrap;
    const offline = await worker.default.fetch(b.callerUrl, { method: "POST", body: "x" });
    expect(offline.status).toBe(503);
    expect(offline.headers.get("access-control-allow-origin")).toBe("*");
    const bad = await worker.default.fetch(`https://relay.example/v1/channels/${CH}/call/bogus`, { method: "POST" });
    expect(bad.status).toBe(403);
    expect(bad.headers.get("access-control-allow-origin")).toBe("*");
    const nf = await worker.default.fetch("https://relay.example/nope");
    expect(nf.headers.get("access-control-allow-origin")).toBe("*");
    const ex = await worker.default.fetch(b.executorUrl.replace("wss:", "https:"));
    expect(ex.status).toBe(426);
    expect(ex.headers.get("access-control-allow-origin")).toBeNull();
    const exPost = await worker.default.fetch(b.executorUrl.replace("wss:", "https:"), { method: "POST" });
    expect(exPost.status).toBe(405);
    expect(exPost.headers.get("cache-control")).toBe("no-store");
  });
});

describe("pairing-code OAuth", () => {
  const ORIGIN = "https://relay.example";
  const APP = "https://app.example";
  const REDIRECT = "http://127.0.0.1:8765/cb";
  const VERIFIER = "v".repeat(60);
  const fetch = (url: string, init?: RequestInit) => worker.default.fetch(url, init);
  const form = (fields: Record<string, string>): RequestInit => ({
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams(fields),
  });

  /** Fresh channel with an echo executor (replies with the request body, text/plain). */
  async function setup() {
    const b = (await (await fetch(`${ORIGIN}/v1/channels`, { method: "POST", headers: { origin: APP } })).json()) as ChannelBootstrap;
    const executorCred = b.executorUrl.split("/").pop()!;
    const up = await fetch(b.executorUrl.replace("wss:", "https:"), {
      headers: { upgrade: "websocket", origin: APP, "x-relay-executor-generation": "test-executor-generation-0100" },
    });
    const ws = up.webSocket!;
    ws.accept();
    const frames: RelayRequestFrame[] = [];
    ws.addEventListener("message", (event) => {
      const frame = JSON.parse(event.data as string) as RelayRequestFrame;
      frames.push(frame);
      ws.send(
        JSON.stringify({
          version: 1,
          type: "response",
          requestId: frame.requestId,
          executorGeneration: frame.executorGeneration,
          response: { status: 200, headers: { "content-type": "text/plain" }, body: frame.request.body },
        }),
      );
    });
    const connector = `${ORIGIN}${connectorPath(b.channel)}`;
    const pair = () => fetch(`${ORIGIN}${pairingPath(b.channel, executorCred)}`, { method: "POST", headers: { origin: APP } });
    const issuer = `${ORIGIN}/c/${b.channel}`;
    return { b, ws, frames, executorCred, connector, pair, issuer };
  }

  async function challenge(verifier: string): Promise<string> {
    return base64UrlEncode(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier)));
  }

  /** Register + authorize + token for a channel; returns the token response body. */
  async function authorizeAll(env: Awaited<ReturnType<typeof setup>>) {
    const reg = await fetch(`${env.issuer}/oauth/register`, {
      method: "POST",
      body: JSON.stringify({ redirect_uris: [REDIRECT], client_name: "Test Client" }),
    });
    const { client_id } = (await reg.json()) as { client_id: string };
    const { code } = (await (await env.pair()).json()) as PairingResponse;
    const fields = {
      client_id,
      redirect_uri: REDIRECT,
      response_type: "code",
      state: "xyz",
      code_challenge: await challenge(VERIFIER),
      code_challenge_method: "S256",
      resource: env.connector,
    };
    const redirected = await fetch(`${env.issuer}/oauth/authorize`, { ...form({ ...fields, pairing_code: code }), redirect: "manual" });
    const location = new URL(redirected.headers.get("location")!);
    const token = await fetch(
      `${env.issuer}/oauth/token`,
      form({ grant_type: "authorization_code", code: location.searchParams.get("code")!, redirect_uri: REDIRECT, client_id, code_verifier: VERIFIER }),
    );
    return { client_id, fields, code, redirected, location, token };
  }

  const callWith = (url: string, token: string, body = "hello") =>
    fetch(url, { method: "POST", headers: { authorization: `Bearer ${token}` }, body });

  it("runs the full pair, challenge, metadata, register, authorize, token, call and refresh flow", async () => {
    const env = await setup();
    const { b, connector, issuer } = env;

    const paired = await env.pair();
    expect(paired.status).toBe(200);
    const pairing = (await paired.json()) as PairingResponse;
    expect(pairing.code).toMatch(/^[0-9A-Z]{5}-[0-9A-Z]{5}$/);
    expect(pairing.connectorUrl).toBe(connector);
    expect(pairing.expiresAt).toBeGreaterThan(Date.now());
    expect(paired.headers.get("access-control-allow-origin")).toBe("*");
    expect(paired.headers.get("cache-control")).toBe("no-store");

    const none = await fetch(connector, { method: "POST", body: "x" });
    const resourceMetadata = `${ORIGIN}/.well-known/oauth-protected-resource/v1/channels/${b.channel}/call`;
    expect(none.status).toBe(401);
    expect(none.headers.get("www-authenticate")).toBe(`Bearer resource_metadata="${resourceMetadata}"`);
    expect(none.headers.get("access-control-allow-origin")).toBe("*");
    expect(none.headers.get("access-control-expose-headers")).toContain("www-authenticate");
    const junk = await callWith(connector, "junk");
    expect(junk.status).toBe(401);
    expect(junk.headers.get("www-authenticate")).toBe(`Bearer resource_metadata="${resourceMetadata}", error="invalid_token"`);

    const pr = (await (await fetch(resourceMetadata)).json()) as { resource: string; authorization_servers: string[] };
    expect(pr.resource).toBe(connector);
    expect(pr.authorization_servers).toEqual([issuer]);
    const md = (await (await fetch(`${ORIGIN}/.well-known/oauth-authorization-server/c/${b.channel}`)).json()) as Record<string, unknown>;
    expect(md).toMatchObject({
      issuer,
      authorization_endpoint: `${issuer}/oauth/authorize`,
      token_endpoint: `${issuer}/oauth/token`,
      registration_endpoint: `${issuer}/oauth/register`,
      code_challenge_methods_supported: ["S256"],
    });

    const reg = await fetch(`${issuer}/oauth/register`, {
      method: "POST",
      body: JSON.stringify({ redirect_uris: [REDIRECT], client_name: "Test Client" }),
    });
    expect(reg.status).toBe(201);
    const { client_id } = (await reg.json()) as { client_id: string };
    const params = {
      client_id,
      redirect_uri: REDIRECT,
      response_type: "code",
      state: "xyz",
      code_challenge: await challenge(VERIFIER),
      code_challenge_method: "S256",
    };
    for (const extra of [{ resource: connector }, {} as Record<string, string>]) {
      const page = await fetch(`${issuer}/oauth/authorize?${new URLSearchParams({ ...params, ...extra })}`);
      expect(page.status).toBe(200);
      const html = await page.text();
      expect(html).toContain("Test Client");
      expect(html).toContain("127.0.0.1:8765");
      expect(html).toContain('name="pairing_code"');
      expect(page.headers.get("content-security-policy")).toContain("frame-ancestors 'none'");
    }

    const redirected = await fetch(`${issuer}/oauth/authorize`, {
      ...form({ ...params, resource: connector, pairing_code: pairing.code }),
      redirect: "manual",
    });
    expect(redirected.status).toBe(302);
    const location = new URL(redirected.headers.get("location")!);
    expect(location.origin + location.pathname).toBe(REDIRECT);
    expect(location.searchParams.get("state")).toBe("xyz");

    const tokenRes = await fetch(
      `${issuer}/oauth/token`,
      form({ grant_type: "authorization_code", code: location.searchParams.get("code")!, redirect_uri: REDIRECT, client_id, code_verifier: VERIFIER }),
    );
    expect(tokenRes.status).toBe(200);
    const tokens = (await tokenRes.json()) as Record<string, string | number>;
    expect(tokens).toMatchObject({ token_type: "Bearer", expires_in: 3600 });

    const called = await callWith(connector, tokens.access_token as string);
    expect(called.status).toBe(200);
    await expect(called.text()).resolves.toBe("hello");
    expect(env.frames.at(-1)!.request.headers).not.toHaveProperty("authorization");

    const refreshed = await fetch(`${issuer}/oauth/token`, form({ grant_type: "refresh_token", refresh_token: tokens.refresh_token as string }));
    expect(refreshed.status).toBe(200);
    const again = await callWith(connector, ((await refreshed.json()) as { access_token: string }).access_token);
    await expect(again.text()).resolves.toBe("hello");
    env.ws.close();
  });

  it("guards the pairing endpoint", async () => {
    const env = await setup();
    const url = `${ORIGIN}${pairingPath(env.b.channel, env.executorCred)}`;
    const noOrigin = await fetch(url, { method: "POST" });
    expect(noOrigin.status).toBe(403);
    await expect(noOrigin.json()).resolves.toEqual({ error: "executor_origin_forbidden" });
    expect((await fetch(url, { method: "POST", headers: { origin: "https://other.example" } })).status).toBe(403);
    const callerCred = env.b.callerUrl.split("/").pop()!;
    const asCaller = await fetch(`${ORIGIN}${pairingPath(env.b.channel, callerCred)}`, { method: "POST", headers: { origin: APP } });
    expect(asCaller.status).toBe(403);
    await expect(asCaller.json()).resolves.toEqual({ error: "invalid_credential" });
    expect((await fetch(url, { headers: { origin: APP } })).status).toBe(405);
    expect((await fetch(url, { method: "OPTIONS" })).status).toBe(204);
    env.ws.close();
  });

  it("rejects a wrong pairing code without redirecting", async () => {
    const env = await setup();
    const { client_id } = (await (await fetch(`${env.issuer}/oauth/register`, { method: "POST", body: JSON.stringify({ redirect_uris: [REDIRECT] }) })).json()) as { client_id: string };
    const res = await fetch(`${env.issuer}/oauth/authorize`, {
      ...form({ client_id, redirect_uri: REDIRECT, response_type: "code", code_challenge: await challenge(VERIFIER), code_challenge_method: "S256", pairing_code: "00000-00000" }),
      redirect: "manual",
    });
    expect(res.status).toBe(400);
    expect(res.headers.get("location")).toBeNull();
    env.ws.close();
  });

  it("rejects a wrong redirect_uri at authorize with an error page, and wrong verifier or redirect_uri at token", async () => {
    const env = await setup();
    const flow = await authorizeAll(env);
    const bad = await fetch(
      `${env.issuer}/oauth/authorize?${new URLSearchParams({ ...flow.fields, redirect_uri: "http://127.0.0.1:8765/other" })}`,
      { redirect: "manual" },
    );
    expect(bad.status).toBe(400);
    expect(bad.headers.get("location")).toBeNull();

    const { code } = (await (await env.pair()).json()) as PairingResponse;
    const redirected = await fetch(`${env.issuer}/oauth/authorize`, { ...form({ ...flow.fields, pairing_code: code }), redirect: "manual" });
    const authCode = new URL(redirected.headers.get("location")!).searchParams.get("code")!;
    const exchange = (over: Record<string, string>) =>
      fetch(`${env.issuer}/oauth/token`, form({ grant_type: "authorization_code", code: authCode, redirect_uri: REDIRECT, client_id: flow.client_id, code_verifier: VERIFIER, ...over }));
    const wrongVerifier = await exchange({ code_verifier: "w".repeat(60) });
    expect(wrongVerifier.status).toBe(400);
    expect(((await wrongVerifier.json()) as { error: string }).error).toBe("invalid_grant");
    const wrongRedirect = await exchange({ redirect_uri: "http://127.0.0.1:8765/other" });
    expect(wrongRedirect.status).toBe(400);
    expect(((await wrongRedirect.json()) as { error: string }).error).toBe("invalid_grant");
    env.ws.close();
  });

  it("keeps token types apart and binds access tokens to their channel", async () => {
    const env = await setup();
    const tokens = (await (await authorizeAll(env)).token.json()) as { access_token: string; refresh_token: string };

    const accessAsRefresh = await fetch(`${env.issuer}/oauth/token`, form({ grant_type: "refresh_token", refresh_token: tokens.access_token }));
    expect(accessAsRefresh.status).toBe(400);
    expect(((await accessAsRefresh.json()) as { error: string }).error).toBe("invalid_grant");
    expect((await callWith(env.connector, tokens.refresh_token)).status).toBe(401);

    const callerCred = env.b.callerUrl.split("/").pop()!;
    expect((await callWith(env.connector, callerCred)).status).toBe(401);

    const other = await setup();
    expect((await callWith(other.connector, tokens.access_token)).status).toBe(401);
    env.ws.close();
    other.ws.close();
  });

  it("leaves the capability-URL route working", async () => {
    const env = await setup();
    const res = await fetch(env.b.callerUrl, { method: "POST", body: "legacy" });
    expect(res.status).toBe(200);
    await expect(res.text()).resolves.toBe("legacy");
    env.ws.close();
  });

  it("rejects an oversize chunked body without content-length on both call routes", async () => {
    const env = await setup();
    const { access_token } = (await (await authorizeAll(env)).token.json()) as { access_token: string };
    const chunked = () =>
      new ReadableStream({
        start(c) {
          for (let i = 0; i < 3; i++) c.enqueue(new Uint8Array(300 * 1024));
          c.close();
        },
      });
    const init = { method: "POST", duplex: "half" } as RequestInit;
    const legacy = await fetch(env.b.callerUrl, { ...init, body: chunked() });
    expect(legacy.status).toBe(413);
    const bearer = await fetch(env.connector, { ...init, body: chunked(), headers: { authorization: `Bearer ${access_token}` } });
    expect(bearer.status).toBe(413);
    env.ws.close();
  });
});
