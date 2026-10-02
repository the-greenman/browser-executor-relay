import { exports } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import { base64UrlDecode, base64UrlEncode } from "../src/protocol";
import type { ChannelBootstrap, RelayRequestFrame } from "../src/protocol";

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
      expect(r.headers.get("access-control-allow-methods")).toBe("POST, OPTIONS");
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
