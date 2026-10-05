import { cloudflareTest } from "@cloudflare/vitest-plugin";
import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    projects: [
      {
        plugins: [
          cloudflareTest({
            wrangler: { configPath: "./wrangler.jsonc" },
            miniflare: {
              bindings: {
                RELAY_HMAC_KEY: "test-relay-hmac-key",
                DEADLINE_MS: "300",
                MAX_PENDING_CALLS: "12",
              },
            },
          }),
        ],
        test: { name: "workers", include: ["test/**/*.test.ts"], exclude: ["test/**/*.node.test.ts"] },
      },
      // Portable-module tests run in plain Node, outside workerd.
      { test: { name: "node", environment: "node", include: ["test/**/*.node.test.ts"] } },
    ],
  },
});
