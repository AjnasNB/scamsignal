import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: ".",
  testMatch: "**/*.spec.ts",
  timeout: 45000,
  fullyParallel: false,
  reporter: "list",
  use: {
    baseURL: process.env.WEB_TEST_URL || "http://localhost:5173",
    headless: true,
    trace: "retain-on-failure",
  },
  outputDir: "../../.local/web-test-results",
});
