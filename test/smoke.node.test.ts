import { expect, it } from "vitest";

it("runs outside workerd", () => {
  expect((globalThis as { WebSocketPair?: unknown }).WebSocketPair).toBeUndefined();
});
