import { describe, expect, it } from "vitest";
import {
  CLOSE_EXECUTOR_REPLACED,
  EXECUTOR_GENERATION_PATTERN,
  base64UrlDecode,
  executorSocketUrl,
  newExecutorGeneration,
} from "../src/protocol";

describe("./protocol entry", () => {
  it("has no imports, so it bundles in a browser without Worker modules", async () => {
    // @ts-expect-error vite ?raw import has no type declaration
    const { default: source } = (await import("../src/protocol.ts?raw")) as { default: string };
    expect(source).not.toMatch(/^\s*import\s|\bfrom\s+["']|cloudflare:|DurableObject/m);
  });

  it("builds an executor URL with a valid generation and takeover flag", () => {
    const generation = newExecutorGeneration();
    expect(generation).toMatch(EXECUTOR_GENERATION_PATTERN);
    const url = new URL(executorSocketUrl("wss://r.example/v1/channels/c/executor/cred", generation, true));
    expect(url.searchParams.get("generation")).toBe(generation);
    expect(url.searchParams.get("takeover")).toBe("true");
    expect(new URL(executorSocketUrl("wss://r.example/x", generation)).searchParams.has("takeover")).toBe(false);
    expect(CLOSE_EXECUTOR_REPLACED).toBe(4002);
    expect(base64UrlDecode("not base64!")).toBeNull();
  });
});
