import { defineConfig } from "@playwright/test";

const dbBaseUrl = process.env.DB_BASE_URL ?? "https://localhost:5002";
const proxyBaseUrl = process.env.PROXY_BASE_URL ?? "https://localhost:8080";

export default defineConfig({
  testDir: "./tests",
  timeout: 60_000,
  expect: {
    timeout: 10_000,
  },
  retries: process.env.CI ? 1 : 0,
  workers: 1,
  reporter: process.env.CI ? [["github"], ["html", { open: "never" }]] : [["list"], ["html", { open: "never" }]],
  use: {
    ignoreHTTPSErrors: true,
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
    video: "retain-on-failure",
  },
  metadata: {
    dbBaseUrl,
    proxyBaseUrl,
  },
});
