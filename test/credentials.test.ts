import { describe, expect, it } from "vitest";
import { randomBase64Url } from "../src/codec";
import { signCredential, verifyCredential } from "../src/credentials";

describe("self-contained credentials", () => {
  const secret = "test signing key";

  it("is role-bound and rejects alteration", async () => {
    const channel = randomBase64Url(32);
    const credential = await signCredential({ channel, role: "caller", version: 1 }, secret);
    await expect(verifyCredential(credential, secret)).resolves.toEqual({ channel, role: "caller", version: 1 });
    await expect(verifyCredential(`${credential}x`, secret)).resolves.toBeNull();
  });
});
