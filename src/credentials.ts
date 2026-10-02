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

function claimsAreValid(value: unknown): value is RelayCredentialClaims {
  if (!value || typeof value !== "object") return false;
  const claims = value as Partial<RelayCredentialClaims>;
  return (
    typeof claims.channel === "string" &&
    /^[A-Za-z0-9_-]{43}$/.test(claims.channel) &&
    (claims.role === "executor" || claims.role === "caller") &&
    claims.version === 1 &&
    (claims.origin === undefined || (claims.role === "executor" && typeof claims.origin === "string"))
  );
}

/** Creates a self-contained, role-bound credential. No token is recorded server-side. */
export async function signCredential(claims: RelayCredentialClaims, secret: string): Promise<string> {
  const payload = base64UrlEncode(utf8Bytes(JSON.stringify(claims)));
  const signature = await crypto.subtle.sign("HMAC", await signingKey(secret), utf8Bytes(payload) as unknown as BufferSource);
  return `${payload}.${base64UrlEncode(signature)}`;
}

/** Returns null for malformed, altered, or invalid claims. */
export async function verifyCredential(value: string, secret: string): Promise<RelayCredentialClaims | null> {
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
    return claimsAreValid(claims) ? claims : null;
  } catch {
    return null;
  }
}
