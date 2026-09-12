/**
 * Generic relay protocol. `body` is base64url encoded bytes and is opaque to
 * this package: it may contain any application protocol.
 */
export const RELAY_PROTOCOL_VERSION = 1;

export const DEFAULT_LIMITS = {
  maxBodyBytes: 128 * 1024,
  maxPendingCalls: 32,
  deadlineMs: 30_000,
} as const;

export type SafeHeaders = Record<string, string>;

export interface RelayHttpRequest {
  method: "POST";
  contentType: string | null;
  headers: SafeHeaders;
  body: string;
}

export interface RelayHttpResponse {
  status: number;
  headers: SafeHeaders;
  /** Omitted for a bodyless executor response, such as an accepted notification. */
  body?: string;
}

export interface RelayRequestFrame {
  version: typeof RELAY_PROTOCOL_VERSION;
  type: "request";
  requestId: string;
  executorGeneration: string;
  deadlineUnixMs: number;
  request: RelayHttpRequest;
}

export interface RelayResponseFrame {
  version: typeof RELAY_PROTOCOL_VERSION;
  type: "response";
  requestId: string;
  executorGeneration: string;
  response: RelayHttpResponse;
}

export interface ExecutorAttachment {
  version: typeof RELAY_PROTOCOL_VERSION;
  kind: "executor";
  generation: string;
  connectedAtUnixMs: number;
}

export type RelayCredentialRole = "executor" | "caller";

export interface RelayCredentialClaims {
  channel: string;
  role: RelayCredentialRole;
  version: typeof RELAY_PROTOCOL_VERSION;
}

export interface ChannelBootstrap {
  channel: string;
  executorUrl: string;
  callerUrl: string;
}
