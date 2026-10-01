import { cloudflareTest } from "@cloudflare/vitest-plugin";
import { defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [
    cloudflareTest({
      wrangler: { configPath: "./wrangler.jsonc" },
      miniflare: {
        bindings: {
          RELAY_HMAC_KEY: "test-relay-hmac-key",
          EXECUTOR_ORIGIN: "https://app.example",
          DEADLINE_MS: "300",
          MAX_PENDING_CALLS: "12",
        },
      },
    }),
  ],
});
