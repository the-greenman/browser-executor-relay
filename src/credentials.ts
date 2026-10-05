import { base64UrlDecode, base64UrlEncode, utf8Bytes } from "./protocol";
import type { RelayCredentialClaims } from "./protocol";

const encoder = new TextEncoder();

async function signingKey(secret: string): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"],
  );
}

export type ClaimTyp = "client" | "code" | "access" | "refresh";

function claimsAreValid(value: unknown): value is RelayCredentialClaims {
  if (!value || typeof value !== "object") return false;
  const claims = value as Partial<RelayCredentialClaims> & { typ?: unknown };
  return (
    // Typed (OAuth) tokens are never capability credentials.
    claims.typ === undefined &&
    typeof claims.channel === "string" &&
    /^[A-Za-z0-9_-]{43}$/.test(claims.channel) &&
    (claims.role === "executor" || claims.role === "caller") &&
    claims.version === 1 &&
    (claims.origin === undefined || (claims.role === "executor" && typeof claims.origin === "string"))
  );
}

/** Creates a self-contained, signed claim set. No token is recorded server-side. */
export async function signCredential(claims: object, secret: string): Promise<string> {
  const payload = base64UrlEncode(utf8Bytes(JSON.stringify(claims)));
  const signature = await crypto.subtle.sign("HMAC", await signingKey(secret), utf8Bytes(payload) as unknown as BufferSource);
  return `${payload}.${base64UrlEncode(signature)}`;
}

/** Returns the claims object only if the signature verifies; callers still validate the claims. */
async function verifyClaims(value: string, secret: string): Promise<Record<string, unknown> | null> {
  const [payload, signature, extra] = value.split(".");
  if (!payload || !signature || extra !== undefined) return null;
  const signatureBytes = base64UrlDecode(signature);
  const payloadBytes = base64UrlDecode(payload);
  if (!signatureBytes || !payloadBytes) return null;
  const verified = await crypto.subtle.verify(
    "HMAC",
    await signingKey(secret),
    signatureBytes as unknown as BufferSource,
    utf8Bytes(payload) as unknown as BufferSource,
  );
  if (!verified) return null;
  try {
    const claims: unknown = JSON.parse(new TextDecoder().decode(payloadBytes));
    return claims && typeof claims === "object" && !Array.isArray(claims) ? (claims as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

/** Returns null for malformed, altered, or invalid claims. */
export async function verifyCredential(value: string, secret: string): Promise<RelayCredentialClaims | null> {
  const claims = await verifyClaims(value, secret);
  return claimsAreValid(claims) ? claims : null;
}

/** Signs `{typ, ...claims, exp?}`; `ttlSeconds` null means no expiry. */
export function signTyped(
  typ: ClaimTyp,
  claims: Record<string, unknown>,
  ttlSeconds: number | null,
  secret: string,
  nowMs: number,
): Promise<string> {
  return signCredential({ typ, ...claims, ...(ttlSeconds !== null && { exp: Math.floor(nowMs / 1000) + ttlSeconds }) }, secret);
}

/** Verifies signature, `typ`, and (except for "client") an unexpired integer `exp`. */
export async function verifyTyped(value: string, typ: ClaimTyp, secret: string, nowMs: number): Promise<Record<string, unknown> | null> {
  const claims = await verifyClaims(value, secret);
  if (!claims || claims.typ !== typ) return null;
  if (typ !== "client" && (!Number.isInteger(claims.exp) || (claims.exp as number) * 1000 <= nowMs)) return null;
  return claims;
}
