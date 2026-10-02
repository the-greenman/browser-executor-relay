import { describe, expect, it } from "vitest";
import { base64UrlDecode, base64UrlEncode } from "../src/protocol";
import { selectSafeRequestHeaders, selectSafeResponseHeaders } from "../src/safe-headers";

describe("generic opaque protocol helpers", () => {
  it("round-trips opaque bytes without treating them as text", () => {
    const bytes = Uint8Array.from([0, 1, 255, 42]);
    expect(base64UrlDecode(base64UrlEncode(bytes))).toEqual(bytes);
  });

  it("forwards only the documented safe metadata", () => {
    const headers = new Headers({
      accept: "application/octet-stream",
      authorization: "Bearer must-not-forward",
      cookie: "must-not-forward",
      "content-language": "en",
    });
    expect(selectSafeRequestHeaders(headers)).toEqual({ accept: "application/octet-stream", "content-language": "en" });
    expect(selectSafeResponseHeaders({ "content-type": "application/octet-stream", "set-cookie": "blocked" })).toEqual({
      "content-type": "application/octet-stream",
    });
  });
});
