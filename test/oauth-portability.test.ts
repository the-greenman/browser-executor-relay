import { describe, expect, it } from "vitest";
import * as protocol from "../src/protocol";

const sources: Record<string, () => Promise<{ default: string }>> = {
  // @ts-expect-error vite ?raw import has no type declaration
  "src/credentials.ts": () => import("../src/credentials.ts?raw"),
  // @ts-expect-error vite ?raw import has no type declaration
  "src/http.ts": () => import("../src/http.ts?raw"),
  // @ts-expect-error vite ?raw import has no type declaration
  "src/oauth.ts": () => import("../src/oauth.ts?raw"),
};

const ALLOWED_IMPORTS = ["./credentials", "./http", "./protocol"];
const FORBIDDEN = ["DurableObject", "WebSocketPair", "DurableObjectNamespace", "ExecutionContext", "caches", "process", "Buffer", "require"];

describe("portable modules", () => {
  it.each(Object.keys(sources))("%s imports only portable siblings and no Worker-only globals", async (name) => {
    const code = (await sources[name]()).default.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/.*$/gm, "");
    const specifiers = [...code.matchAll(/(?:\bfrom\s+|\bimport\s+)["']([^"']+)["']/g)].map((m) => m[1]);
    for (const specifier of specifiers) expect(ALLOWED_IMPORTS).toContain(specifier);
    expect(code).not.toMatch(/\bimport\s*\(|\brequire\s*\(|node:/);
    for (const identifier of FORBIDDEN) expect(code).not.toMatch(new RegExp(`\\b${identifier}\\b`));
  });

  it("protocol.ts exports the pairing contract", () => {
    expect(protocol.PAIRING_ROUTE).toBe("pairing");
    expect(protocol.PAIRING_WINDOW_SECONDS).toBe(600);
    expect(protocol.PAIRING_CODE_LENGTH).toBe(10);
    expect(protocol.pairingPath("c", "k")).toBe("/v1/channels/c/pairing/k");
    expect(protocol.connectorPath("c")).toBe("/v1/channels/c/call");
  });
});
