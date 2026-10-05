import { DurableObject } from "cloudflare:workers";
import { signCredential, verifyCredential } from "./credentials";
import { errorResponse, methodNotAllowed, preflight, withCors } from "./http";
import { handleAuth, issuePairing, verifyBearer } from "./oauth";
import {
  CLOSE_EXECUTOR_REPLACED,
  DEFAULT_LIMITS,
  EXECUTOR_GENERATION_HEADER,
  EXECUTOR_GENERATION_PARAM,
  EXECUTOR_GENERATION_PATTERN,
  EXECUTOR_TAKEOVER_HEADER,
  EXECUTOR_TAKEOVER_PARAM,
  PAIRING_ROUTE,
  base64UrlDecode,
  base64UrlEncode,
  randomBase64Url,
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
  /** Optional overrides of DEFAULT_LIMITS (positive integers); mainly for tests. */
  DEADLINE_MS?: string;
  MAX_PENDING_CALLS?: string;
}

function limit(value: string | undefined, fallback: number): number {
  const n = Number(value);
  return Number.isInteger(n) && n > 0 ? n : fallback;
}

type Route = "executor" | "call" | typeof PAIRING_ROUTE;

function parsePath(pathname: string): { channel: string; route: Route; credential: string } | null {
  const parts = pathname.split("/").filter(Boolean);
  if (parts.length !== 5 || parts[0] !== "v1" || parts[1] !== "channels") return null;
  const [channel, route, credential] = parts.slice(2);
  if (!/^[A-Za-z0-9_-]{43}$/.test(channel) || (route !== "executor" && route !== "call" && route !== PAIRING_ROUTE) || !credential) return null;
  return { channel, route, credential };
}

/** The credential-less bearer route: /v1/channels/{ch}/call. */
function parseBearerPath(pathname: string): { channel: string } | null {
  const parts = pathname.split("/").filter(Boolean);
  if (parts.length !== 4 || parts[0] !== "v1" || parts[1] !== "channels" || parts[3] !== "call") return null;
  return /^[A-Za-z0-9_-]{43}$/.test(parts[2]) ? { channel: parts[2] } : null;
}

async function authenticatedChannel(
  request: Request,
  env: Env,
  expectedRole: RelayCredentialRole,
  expectedRoute: Route,
): Promise<{ channel: string; credential: string; origin?: string } | null> {
  const parsed = parsePath(new URL(request.url).pathname);
  if (!parsed || parsed.route !== expectedRoute) return null;
  const claims = await verifyCredential(parsed.credential, env.RELAY_HMAC_KEY);
  if (!claims || claims.channel !== parsed.channel || claims.role !== expectedRole) return null;
  return { channel: parsed.channel, credential: parsed.credential, origin: claims.origin };
}

/** A serialized origin: scheme://host[:port], no path. Opaque origins ("null") cannot be re-verified. */
function wellFormedOrigin(value: string): boolean {
  try {
    return value !== "null" && new URL(value).origin === value;
  } catch {
    return false;
  }
}

/** A credential bound to an Origin only works from that Origin (non-browser credentials carry none). */
function originForbidden(request: Request, authenticated: { origin?: string }): boolean {
  return authenticated.origin !== undefined && request.headers.get("origin") !== authenticated.origin;
}

/** Browsers cannot set WebSocket upgrade headers, so query params are accepted; headers serve non-browser executors. Never logged. */
function executorParams(request: Request): { generation: string | null; takeover: boolean } {
  const url = new URL(request.url);
  const generation = url.searchParams.get(EXECUTOR_GENERATION_PARAM) ?? request.headers.get(EXECUTOR_GENERATION_HEADER);
  const takeover = (url.searchParams.get(EXECUTOR_TAKEOVER_PARAM) ?? request.headers.get(EXECUTOR_TAKEOVER_HEADER)) === "true";
  return { generation, takeover };
}

async function bootstrap(request: Request, env: Env): Promise<Response> {
  if (request.method !== "POST") return methodNotAllowed("POST");
  const origin = request.headers.get("origin");
  if (origin !== null && !wellFormedOrigin(origin)) return errorResponse(400, "invalid_origin");
  const channel = randomBase64Url(32);
  const executorCredential = await signCredential(
    { channel, role: "executor", version: RELAY_PROTOCOL_VERSION, ...(origin !== null && { origin }) },
    env.RELAY_HMAC_KEY,
  );
  const callerCredential = await signCredential({ channel, role: "caller", version: RELAY_PROTOCOL_VERSION }, env.RELAY_HMAC_KEY);
  const base = new URL(request.url);
  const result: ChannelBootstrap = {
    channel,
    executorUrl: `${base.protocol === "https:" ? "wss:" : "ws:"}//${base.host}/v1/channels/${channel}/executor/${executorCredential}`,
    callerUrl: `${base.origin}/v1/channels/${channel}/call/${callerCredential}`,
  };
  return Response.json(result);
}

async function routeExecutor(request: Request, env: Env): Promise<Response> {
  if (request.method !== "GET") return methodNotAllowed("GET");
  if (request.headers.get("upgrade")?.toLowerCase() !== "websocket") return errorResponse(426, "websocket_upgrade_required");
  const authenticated = await authenticatedChannel(request, env, "executor", "executor");
  if (!authenticated) return errorResponse(403, "invalid_credential");
  if (originForbidden(request, authenticated)) return errorResponse(403, "executor_origin_forbidden");
  const { generation, takeover } = executorParams(request);
  if (!generation || !EXECUTOR_GENERATION_PATTERN.test(generation)) return errorResponse(400, "invalid_executor_generation");
  const stub = env.RELAY_CHANNEL.getByName(authenticated.channel);
  return stub.fetch("https://relay.internal/executor", {
    headers: {
      upgrade: "websocket",
      [EXECUTOR_GENERATION_HEADER]: generation,
      [EXECUTOR_TAKEOVER_HEADER]: takeover ? "true" : "false",
    },
  });
}

/** Post-auth half of a caller request, shared by the capability-URL and bearer routes. */
async function forwardCall(request: Request, env: Env, channel: string): Promise<Response> {
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
  const stub = env.RELAY_CHANNEL.getByName(channel);
  return stub.fetch("https://relay.internal/call", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(relayRequest),
    signal: request.signal,
  });
}

async function routeCall(request: Request, env: Env): Promise<Response> {
  if (request.method !== "POST") return methodNotAllowed("POST");
  const authenticated = await authenticatedChannel(request, env, "caller", "call");
  if (!authenticated) return errorResponse(403, "invalid_credential");
  return forwardCall(request, env, authenticated.channel);
}

async function routeBearerCall(request: Request, env: Env, channel: string): Promise<Response> {
  if (request.method !== "POST") return methodNotAllowed("POST");
  const denied = await verifyBearer(request, channel, { key: env.RELAY_HMAC_KEY, origin: new URL(request.url).origin });
  return denied ?? forwardCall(request, env, channel);
}

async function routePairing(request: Request, env: Env): Promise<Response> {
  if (request.method !== "POST") return methodNotAllowed("POST");
  const authenticated = await authenticatedChannel(request, env, "executor", PAIRING_ROUTE);
  if (!authenticated) return errorResponse(403, "invalid_credential");
  if (originForbidden(request, authenticated)) return errorResponse(403, "executor_origin_forbidden");
  return Response.json(await issuePairing(authenticated.channel, { key: env.RELAY_HMAC_KEY, origin: new URL(request.url).origin }));
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
    const generation = request.headers.get(EXECUTOR_GENERATION_HEADER);
    const takeover = request.headers.get(EXECUTOR_TAKEOVER_HEADER) === "true";
    if (!generation) return errorResponse(400, "invalid_executor_generation");
    if (this.executorIsLive()) {
      if (!takeover) return errorResponse(409, "executor_already_connected");
      this.executor?.close(CLOSE_EXECUTOR_REPLACED, "executor_replaced");
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
    if (this.pending.size >= limit(this.env.MAX_PENDING_CALLS, DEFAULT_LIMITS.maxPendingCalls)) return errorResponse(429, "executor_busy");
    const requestId = randomBase64Url(16);
    const deadlineMs = limit(this.env.DEADLINE_MS, DEFAULT_LIMITS.deadlineMs);
    const frame: RelayRequestFrame = {
      version: RELAY_PROTOCOL_VERSION,
      type: "request",
      requestId,
      executorGeneration: this.executorGeneration,
      deadlineUnixMs: Date.now() + deadlineMs,
      request: input.request,
    };
    return new Promise<Response>((resolve) => {
      const timeout = setTimeout(() => {
        this.pending.delete(requestId);
        resolve(errorResponse(504, "executor_timeout"));
      }, deadlineMs) as unknown as number;
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
    if (!pending || !body || !headers) return;
    clearTimeout(pending.timeout);
    this.pending.delete(frame.requestId);
    if (body.byteLength > DEFAULT_LIMITS.maxBodyBytes) return pending.resolve(errorResponse(502, "response_too_large"));
    const responseHeaders = new Headers(headers);
    pending.resolve(new Response(body as unknown as BodyInit, { status: frame.response.status, headers: responseHeaders }));
  }

  private dropExecutor(socket: WebSocket): void {
    if (socket !== this.executor) return;
    this.executor = null;
    this.executorGeneration = null;
    this.rejectPending("executor_offline");
  }

  webSocketClose(socket: WebSocket): void {
    this.dropExecutor(socket);
  }

  webSocketError(socket: WebSocket): void {
    this.dropExecutor(socket);
  }

  private rejectPending(error: string): void {
    for (const [requestId, pending] of this.pending) {
      clearTimeout(pending.timeout);
      pending.resolve(errorResponse(503, error));
      this.pending.delete(requestId);
    }
  }
}

async function route(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const auth = await handleAuth(request, { key: env.RELAY_HMAC_KEY, origin: url.origin });
  if (auth) return auth;
  if (url.pathname === "/v1/channels") return request.method === "OPTIONS" ? preflight(request) : withCors(await bootstrap(request, env));
  const bearer = parseBearerPath(url.pathname);
  if (bearer) return request.method === "OPTIONS" ? preflight(request) : withCors(await routeBearerCall(request, env, bearer.channel));
  const parsed = parsePath(url.pathname);
  if (!parsed) return withCors(errorResponse(404, "not_found"));
  // Executor route is a WebSocket upgrade: no CORS (origin is bound per channel).
  if (parsed.route === "executor") return routeExecutor(request, env);
  if (request.method === "OPTIONS") return preflight(request);
  return withCors(parsed.route === PAIRING_ROUTE ? await routePairing(request, env) : await routeCall(request, env));
}

export default {
  fetch: route,
};
