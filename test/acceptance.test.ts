import { exports } from "cloudflare:workers";
import { env, evictDurableObject, abortAllDurableObjects } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { base64UrlEncode } from "../src/codec";
import type { ChannelBootstrap, RelayRequestFrame } from "../src/protocol";

const worker = (exports as unknown as { default: { fetch(i: RequestInfo, init?: RequestInit): Promise<Response> } }).default;
const enc = (s: string) => base64UrlEncode(new TextEncoder().encode(s));
let n = 0;

async function bootstrap(): Promise<ChannelBootstrap> {
  return (await (await worker.fetch("https://relay.example/v1/channels", { method: "POST" })).json()) as ChannelBootstrap;
}

async function connect(b: ChannelBootstrap, extra: Record<string, string> = {}) {
  const res = await worker.fetch(b.executorUrl.replace("wss:", "https:"), {
    headers: { upgrade: "websocket", origin: "https://app.example", "x-relay-executor-generation": `generation-${String(++n).padStart(16, "0")}`, ...extra },
  });
  return res;
}

/** Generic echo executor: replies with the request body bytes. */
function echo(ws: WebSocket, onFrame?: (f: RelayRequestFrame) => void) {
  ws.accept();
  ws.addEventListener("message", (e) => {
    const f = JSON.parse(e.data as string) as RelayRequestFrame;
    onFrame?.(f);
    ws.send(JSON.stringify({ version: 1, type: "response", requestId: f.requestId, executorGeneration: f.executorGeneration, response: { status: 200, headers: {}, body: f.request.body } }));
  });
}

const call = (b: ChannelBootstrap, body: string) => worker.fetch(b.callerUrl, { method: "POST", body });

describe("acceptance", () => {
  it("credentials cannot cross roles or channels", async () => {
    const a = await bootstrap();
    const b = await bootstrap();
    const executorCred = a.executorUrl.split("/").pop()!;
    const callerCred = a.callerUrl.split("/").pop()!;
    // executor credential on the call route, caller credential on the executor route
    const asCaller = await worker.fetch(`https://relay.example/v1/channels/${a.channel}/call/${executorCred}`, { method: "POST", body: "x" });
    expect(asCaller.status).toBe(403);
    const asExecutor = await connect({ ...a, executorUrl: `https://relay.example/v1/channels/${a.channel}/executor/${callerCred}` });
    expect(asExecutor.status).toBe(403);
    // credential for another channel
    const other = await worker.fetch(`https://relay.example/v1/channels/${b.channel}/call/${callerCred}`, { method: "POST", body: "x" });
    expect(other.status).toBe(403);
    // tampered signature
    const forged = await worker.fetch(a.callerUrl.slice(0, -2) + "AA", { method: "POST", body: "x" });
    expect(forged.status).toBe(403);
  });

  it("echo executor isolates many concurrent callers with identical application ids", async () => {
    const b = await bootstrap();
    const ex = (await connect(b)).webSocket!;
    echo(ex);
    const bodies = Array.from({ length: 10 }, (_, i) => `{"id":1,"caller":${i}}`);
    const results = await Promise.all(bodies.map(async (body) => (await call(b, body)).text()));
    expect(results).toEqual(bodies);
    ex.close();
  });

  it("returns executor_offline after the executor disconnects, failing in-flight calls", async () => {
    const b = await bootstrap();
    const ex = (await connect(b)).webSocket!;
    ex.accept();
    const incoming = new Promise((r) => ex.addEventListener("message", r, { once: true }));
    const inflight = call(b, "pending");
    await incoming;
    ex.close();
    const failed = await inflight;
    expect(failed.status).toBe(503);
    await expect(failed.json()).resolves.toEqual({ error: "executor_offline" });
    const after = await call(b, "again");
    expect(after.status).toBe(503);
    await expect(after.json()).resolves.toEqual({ error: "executor_offline" });
  });

  it("survives DO eviction (hibernation) with the executor socket restored from its attachment, no storage", async () => {
    const b = await bootstrap();
    const ex = (await connect(b)).webSocket!;
    echo(ex);
    expect(await (await call(b, "before")).text()).toBe("before");
    await evictDurableObject(env.RELAY_CHANNEL.getByName(b.channel));
    expect(await (await call(b, "after")).text()).toBe("after");
    ex.close();
  });

  it("restores service by reconnecting after all Durable Objects are aborted (redeploy), without migration", async () => {
    const b = await bootstrap();
    const ex = (await connect(b)).webSocket!;
    echo(ex);
    expect(await (await call(b, "one")).text()).toBe("one");
    await abortAllDurableObjects();
    // same credentials still valid: they are self-contained and the Worker holds no registry
    const ex2 = (await connect(b)).webSocket!;
    echo(ex2);
    expect(await (await call(b, "two")).text()).toBe("two");
    ex2.close();
  });

  it("rejects a second executor without takeover and replaces with takeover", async () => {
    const b = await bootstrap();
    const first = (await connect(b)).webSocket!;
    echo(first);
    expect((await connect(b)).status).toBe(409);
    const second = (await connect(b, { "x-relay-executor-takeover": "true" })).webSocket!;
    echo(second);
    expect(await (await call(b, "x")).text()).toBe("x");
    second.close();
  });

  it("accepts generation and takeover as query params (browser executors) and rejects bad ones", async () => {
    const b = await bootstrap();
    const url = b.executorUrl.replace("wss:", "https:");
    const up = (qs: string) => worker.fetch(`${url}${qs}`, { headers: { upgrade: "websocket", origin: "https://app.example" } });
    expect((await up("")).status).toBe(400);
    expect((await up("?generation=short")).status).toBe(400);
    const first = (await up("?generation=query-generation-0001")).webSocket!;
    echo(first);
    expect((await up("?generation=query-generation-0002")).status).toBe(409);
    const second = (await up("?generation=query-generation-0002&takeover=true")).webSocket!;
    echo(second);
    expect(await (await call(b, "q")).text()).toBe("q");
    second.close();
  });

  it("fails fast with 502 response_too_large when the executor response exceeds the limit", async () => {
    const b = await bootstrap();
    const ex = (await connect(b)).webSocket!;
    ex.accept();
    ex.addEventListener("message", (e) => {
      const f = JSON.parse(e.data as string) as RelayRequestFrame;
      ex.send(JSON.stringify({ version: 1, type: "response", requestId: f.requestId, executorGeneration: f.executorGeneration, response: { status: 200, headers: {}, body: base64UrlEncode(new Uint8Array(128 * 1024 + 1)) } }));
    });
    const res = await call(b, "big");
    expect(res.status).toBe(502);
    await expect(res.json()).resolves.toEqual({ error: "response_too_large" });
    ex.close();
  });

  it("enforces body size, pending-call and deadline limits", async () => {
    const b = await bootstrap();
    expect((await call(b, "x".repeat(128 * 1024 + 1))).status).toBe(413);
    const ex = (await connect(b)).webSocket!;
    ex.accept(); // never responds
    const slow = Array.from({ length: 12 }, (_, i) => call(b, `p${i}`));
    await new Promise((r) => setTimeout(r, 50));
    expect((await call(b, "c")).status).toBe(429);
    const done = await Promise.all(slow);
    expect(done.map((r) => r.status)).toEqual(Array(12).fill(504));
    ex.close();
  });

  it("holds no persistent Durable Object storage", async () => {
    const b = await bootstrap();
    const ex = (await connect(b)).webSocket!;
    echo(ex);
    await call(b, "x");
    const { runInDurableObject } = await import("cloudflare:test");
    const keys = await runInDurableObject(env.RELAY_CHANNEL.getByName(b.channel), async (_i, state) => [...(await state.storage.list()).keys()]);
    expect(keys).toEqual([]);
    ex.close();
  });
});
