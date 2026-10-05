import { describe, expect, it } from "vitest";
import { randomBase64Url } from "../src/protocol";
import { signCredential, signTyped, verifyCredential, verifyTyped } from "../src/credentials";

describe("self-contained credentials", () => {
  const secret = "test signing key";

  it("is role-bound and rejects alteration", async () => {
    const channel = randomBase64Url(32);
    const credential = await signCredential({ channel, role: "caller", version: 1 }, secret);
    await expect(verifyCredential(credential, secret)).resolves.toEqual({ channel, role: "caller", version: 1 });
    await expect(verifyCredential(`${credential}x`, secret)).resolves.toBeNull();
  });
});

describe("origin claim", () => {
  it("round-trips on executor credentials and is refused on caller credentials", async () => {
    const channel = randomBase64Url(32);
    const ok = await signCredential({ channel, role: "executor", version: 1, origin: "https://a.example" }, "k");
    await expect(verifyCredential(ok, "k")).resolves.toMatchObject({ origin: "https://a.example" });
    const bad = await signCredential({ channel, role: "caller", version: 1, origin: "https://a.example" }, "k");
    await expect(verifyCredential(bad, "k")).resolves.toBeNull();
  });
});

describe("byte compatibility with pre-typed credentials", () => {
  // Literals minted by the code at base commit 6b2a1ac.
  const key = "legacy-fixture-key";
  const channel = "A".repeat(43);
  const fixtures = [
    {
      claims: { channel, role: "caller", version: 1 },
      token:
        "eyJjaGFubmVsIjoiQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQSIsInJvbGUiOiJjYWxsZXIiLCJ2ZXJzaW9uIjoxfQ._GNrXdj0UMRF-GKXDY2MqNhnsx-bZsIw2SXAgTp3M2U",
    },
    {
      claims: { channel, role: "executor", version: 1, origin: "https://app.example" },
      token:
        "eyJjaGFubmVsIjoiQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQSIsInJvbGUiOiJleGVjdXRvciIsInZlcnNpb24iOjEsIm9yaWdpbiI6Imh0dHBzOi8vYXBwLmV4YW1wbGUifQ.2L4Ecf5b9SzJYo9kQ86if_p8nGKnSc-JbLim1cU6fdM",
    },
  ];

  it.each(fixtures)("verifies and re-signs $claims.role to identical bytes", async ({ claims, token }) => {
    await expect(verifyCredential(token, key)).resolves.toEqual(claims);
    await expect(signCredential(claims, key)).resolves.toBe(token);
  });
});

describe("typed tokens", () => {
  const key = "typed key";
  const now = 1_000_000_000_000;

  it("round-trips and expires at the exact boundary", async () => {
    const token = await signTyped("access", { role: "caller", channel: "c" }, 60, key, now);
    const claims = await verifyTyped(token, "access", key, now);
    expect(claims).toEqual({ typ: "access", role: "caller", channel: "c", exp: now / 1000 + 60 });
    await expect(verifyTyped(token, "access", key, now + 60_000 - 1)).resolves.not.toBeNull();
    await expect(verifyTyped(token, "access", key, now + 60_000)).resolves.toBeNull();
  });

  it("client tokens carry no exp and never expire", async () => {
    const token = await signTyped("client", { client_name: "x" }, null, key, now);
    await expect(verifyTyped(token, "client", key, now * 1000)).resolves.toEqual({ typ: "client", client_name: "x" });
  });

  it("rejects tampering, wrong secret, wrong typ and cross-use with capability credentials", async () => {
    const access = await signTyped("access", { role: "caller", channel: "A".repeat(43), version: 1 }, 60, key, now);
    await expect(verifyTyped(access, "refresh", key, now)).resolves.toBeNull();
    await expect(verifyTyped(`${access}x`, "access", key, now)).resolves.toBeNull();
    await expect(verifyTyped(access, "access", "other", now)).resolves.toBeNull();
    await expect(verifyCredential(access, key)).resolves.toBeNull();
    const capability = await signCredential({ channel: "A".repeat(43), role: "caller", version: 1 }, key);
    await expect(verifyTyped(capability, "access", key, now)).resolves.toBeNull();
  });
});
