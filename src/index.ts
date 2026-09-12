import { DurableObject } from "cloudflare:workers";
import { base64UrlDecode, base64UrlEncode, randomBase64Url } from "./codec";
import { signCredential, verifyCredential } from "./credentials";
import {
  DEFAULT_LIMITS,
  RELAY_PROTOCOL_VERSION,
  type ChannelBootstrap,
  type ExecutorAttachment,
  type RelayCredentialRole,
  type RelayRequestFrame,
  type RelayResponseFrame,
} from "./protocol";
import { selectSafeRequestHeaders, selectSafeResponseHeaders } from "./safe-headers";

export interface Env {
  RELAY_CHANNEL: DurableObjectNamespace<RelayChannel>;
  /** Single durable relay secret. Configure with `wrangler secret put`. */
  RELAY_HMAC_KEY: string;
  /** Optional exact browser origin for executor WebSocket upgrades. */
  EXECUTOR_ORIGIN?: string;
}

const JSON_HEADERS = {
  "content-type": "application/json; charset=utf-8",
  "cache-control": "no-store",
  "referrer-policy": "no-referrer",
};

function errorResponse(status: number, error: string): Response {
  return Response.json({ error }, { status, headers: JSON_HEADERS });
}

function notAllowed(allowedMethod: "GET" | "POST"): Response {
  return new Response(null, { status: 405, headers: { allow: allowedMethod } });
}

function parsePath(pathname: string): { channel: string; route: "executor" | "call"; credential: string } | null {
  const parts = pathname.split("/").filter(Boolean);
  if (parts.length !== 5 || parts[0] !== "v1" || parts[1] !== "channels") return null;
  const [channel, route, credential] = parts.slice(2);
  if (!/^[A-Za-z0-9_-]{43}$/.test(channel) || (route !== "executor" && route !== "call") || !credential) return null;
  return { channel, route, credential };
}

async function authenticatedChannel(
  request: Request,
  env: Env,
  expectedRole: RelayCredentialRole,
): Promise<{ channel: string; credential: string } | null> {
  const parsed = parsePath(new URL(request.url).pathname);
  const expectedRoute = expectedRole === "caller" ? "call" : "executor";
  if (!parsed || parsed.route !== expectedRoute) return null;
  const claims = await verifyCredential(parsed.credential, env.RELAY_HMAC_KEY);
  if (!claims || claims.channel !== parsed.channel || claims.role !== expectedRole) return null;
  return { channel: parsed.channel, credential: parsed.credential };
}

function executorOriginAllowed(request: Request, env: Env): boolean {
  const origin = request.headers.get("origin");
  return Boolean(env.EXECUTOR_ORIGIN && origin === env.EXECUTOR_ORIGIN);
}

async function bootstrap(request: Request, env: Env): Promise<Response> {
  if (request.method !== "POST") return notAllowed("POST");
  const channel = randomBase64Url(32);
  const executorCredential = await signCredential({ channel, role: "executor", version: RELAY_PROTOCOL_VERSION }, env.RELAY_HMAC_KEY);
  const callerCredential = await signCredential({ channel, role: "caller", version: RELAY_PROTOCOL_VERSION }, env.RELAY_HMAC_KEY);
  const base = new URL(request.url);
  const result: ChannelBootstrap = {
    channel,
    executorUrl: `${base.protocol === "https:" ? "wss:" : "ws:"}//${base.host}/v1/channels/${channel}/executor/${executorCredential}`,
    callerUrl: `${base.origin}/v1/channels/${channel}/call/${callerCredential}`,
  };
  return Response.json(result, { headers: JSON_HEADERS });
}

async function routeExecutor(request: Request, env: Env): Promise<Response> {
  if (request.method !== "GET") return notAllowed("GET");
  if (request.headers.get("upgrade")?.toLowerCase() !== "websocket") return errorResponse(426, "websocket_upgrade_required");
  if (!executorOriginAllowed(request, env)) return errorResponse(403, "executor_origin_forbidden");
  const authenticated = await authenticatedChannel(request, env, "executor");
  if (!authenticated) return errorResponse(403, "invalid_credential");
  const generation = request.headers.get("x-relay-executor-generation");
  if (!generation || !/^[A-Za-z0-9_-]{16,128}$/.test(generation)) return errorResponse(400, "invalid_executor_generation");
  const takeover = request.headers.get("x-relay-executor-takeover") === "true";
  const stub = env.RELAY_CHANNEL.getByName(authenticated.channel);
  return stub.fetch("https://relay.internal/executor", {
    headers: {
      upgrade: "websocket",
      "x-relay-executor-generation": generation,
      "x-relay-executor-takeover": takeover ? "true" : "false",
    },
  });
}

async function routeCall(request: Request, env: Env): Promise<Response> {
  if (request.method !== "POST") return notAllowed("POST");
  const authenticated = await authenticatedChannel(request, env, "caller");
  if (!authenticated) return errorResponse(403, "invalid_credential");
  const declaredLength = Number(request.headers.get("content-length") ?? "0");
  if (!Number.isFinite(declaredLength) || declaredLength > DEFAULT_LIMITS.maxBodyBytes) return errorResponse(413, "request_too_large");
  const body = await request.arrayBuffer();
  if (body.byteLength > DEFAULT_LIMITS.maxBodyBytes) return errorResponse(413, "request_too_large");
  const relayRequest = {
    request: {
      method: "POST" as const,
      contentType: request.headers.get("content-type"),
      headers: selectSafeRequestHeaders(request.headers),
      body: base64UrlEncode(body),
    },
  };
  const stub = env.RELAY_CHANNEL.getByName(authenticated.channel);
  return stub.fetch("https://relay.internal/call", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(relayRequest),
    signal: request.signal,
  });
}

export class RelayChannel extends DurableObject<Env> {
  private executor: WebSocket | null = null;
  private executorGeneration: string | null = null;
  private readonly pending = new Map<string, { resolve: (response: Response) => void; timeout: number }>();

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.restoreExecutor();
  }

  private restoreExecutor(): void {
    const sockets = this.ctx.getWebSockets("executor");
    const socket = sockets.find((candidate) => candidate.readyState === 1);
    if (!socket) return;
    const attachment = socket.deserializeAttachment() as ExecutorAttachment | null;
    if (!attachment || attachment.kind !== "executor" || attachment.version !== RELAY_PROTOCOL_VERSION) return;
    this.executor = socket;
    this.executorGeneration = attachment.generation;
  }

  private executorIsLive(): boolean {
    if (!this.executor || this.executor.readyState !== 1) {
      this.executor = null;
      this.executorGeneration = null;
      this.restoreExecutor();
    }
    return this.executor !== null && this.executor.readyState === 1;
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    if (url.pathname === "/executor") return this.acceptExecutor(request);
    if (url.pathname === "/call") return this.callExecutor(request);
    return errorResponse(404, "not_found");
  }

  private acceptExecutor(request: Request): Response {
    const generation = request.headers.get("x-relay-executor-generation");
    const takeover = request.headers.get("x-relay-executor-takeover") === "true";
    if (!generation) return errorResponse(400, "invalid_executor_generation");
    if (this.executorIsLive()) {
      if (!takeover) return errorResponse(409, "executor_already_connected");
      this.executor?.close(4002, "executor_replaced");
      this.rejectPending("executor_replaced");
    }
    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);
    server.serializeAttachment({
      version: RELAY_PROTOCOL_VERSION,
      kind: "executor",
      generation,
      connectedAtUnixMs: Date.now(),
    } satisfies ExecutorAttachment);
    this.ctx.acceptWebSocket(server, ["executor"]);
    this.executor = server;
    this.executorGeneration = generation;
    return new Response(null, { status: 101, webSocket: client });
  }

  private async callExecutor(request: Request): Promise<Response> {
    let input: { request?: RelayRequestFrame["request"] };
    try {
      input = await request.json();
    } catch {
      return errorResponse(400, "invalid_relay_request");
    }
    if (!input.request || input.request.method !== "POST" || typeof input.request.body !== "string") return errorResponse(400, "invalid_relay_request");
    if (!this.executorIsLive() || !this.executorGeneration) return errorResponse(503, "executor_offline");
    if (this.pending.size >= DEFAULT_LIMITS.maxPendingCalls) return errorResponse(429, "executor_busy");
    const requestId = randomBase64Url(16);
    const frame: RelayRequestFrame = {
      version: RELAY_PROTOCOL_VERSION,
      type: "request",
      requestId,
      executorGeneration: this.executorGeneration,
      deadlineUnixMs: Date.now() + DEFAULT_LIMITS.deadlineMs,
      request: input.request,
    };
    return new Promise<Response>((resolve) => {
      const timeout = setTimeout(() => {
        this.pending.delete(requestId);
        resolve(errorResponse(504, "executor_timeout"));
      }, DEFAULT_LIMITS.deadlineMs) as unknown as number;
      this.pending.set(requestId, { resolve, timeout });
      try {
        this.executor?.send(JSON.stringify(frame));
      } catch {
        clearTimeout(timeout);
        this.pending.delete(requestId);
        resolve(errorResponse(503, "executor_offline"));
      }
    });
  }

  webSocketMessage(socket: WebSocket, message: string | ArrayBuffer): void {
    if (typeof message !== "string") return;
    const attachment = socket.deserializeAttachment() as ExecutorAttachment | null;
    if (!attachment || attachment.kind !== "executor") return;
    let frame: RelayResponseFrame;
    try {
      frame = JSON.parse(message) as RelayResponseFrame;
    } catch {
      return;
    }
    if (
      frame.version !== RELAY_PROTOCOL_VERSION ||
      frame.type !== "response" ||
      typeof frame.requestId !== "string" ||
      frame.executorGeneration !== attachment.generation ||
      !frame.response ||
      !Number.isInteger(frame.response.status) ||
      frame.response.status < 200 ||
      frame.response.status > 599 ||
      (frame.response.body !== undefined && typeof frame.response.body !== "string")
    ) return;
    const body = frame.response.body === undefined ? new Uint8Array() : base64UrlDecode(frame.response.body);
    const headers = selectSafeResponseHeaders(frame.response.headers ?? {});
    const pending = this.pending.get(frame.requestId);
    if (!pending || !body || body.byteLength > DEFAULT_LIMITS.maxBodyBytes || !headers) return;
    clearTimeout(pending.timeout);
    this.pending.delete(frame.requestId);
    const responseHeaders = new Headers(headers);
    // These are relay security properties, never application-controlled fields.
    responseHeaders.set("cache-control", "no-store");
    responseHeaders.set("referrer-policy", "no-referrer");
    pending.resolve(new Response(body as unknown as BodyInit, { status: frame.response.status, headers: responseHeaders }));
  }

  webSocketClose(socket: WebSocket): void {
    if (socket === this.executor) {
      this.executor = null;
      this.executorGeneration = null;
      this.rejectPending("executor_offline");
    }
  }

  webSocketError(socket: WebSocket): void {
    if (socket === this.executor) {
      this.executor = null;
      this.executorGeneration = null;
      this.rejectPending("executor_offline");
    }
  }

  private rejectPending(error: string): void {
    for (const [requestId, pending] of this.pending) {
      clearTimeout(pending.timeout);
      pending.resolve(errorResponse(503, error));
      this.pending.delete(requestId);
    }
  }
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    if (url.pathname === "/v1/channels") return bootstrap(request, env);
    const parsed = parsePath(url.pathname);
    if (!parsed) return errorResponse(404, "not_found");
    return parsed.route === "executor" ? routeExecutor(request, env) : routeCall(request, env);
  },
};
