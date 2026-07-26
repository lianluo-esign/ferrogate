import { defineConfig } from "@playwright/test";

const baseURL = "http://127.0.0.1:4173";

export default defineConfig({
  testDir: "./e2e",
  // Browser specs only. `e2e/support/*.test.ts` are vitest unit tests over the
  // pure support modules (the #348 registered-route inventory) and would
  // otherwise be picked up by Playwright's default `*.test.ts` match.
  testMatch: "**/*.spec.ts",
  outputDir: "test-results/playwright",
  fullyParallel: true,
  forbidOnly: true,
  retries: 0,
  reporter: [
    ["list"],
    ["html", { open: "never", outputFolder: "playwright-report" }],
  ],
  use: {
    baseURL,
    browserName: "chromium",
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
    video: "retain-on-failure",
  },
  webServer: {
    command: "npm run dev -- --host 127.0.0.1 --port 4173",
    url: baseURL,
    reuseExistingServer: false,
    timeout: 120_000,
  },
  projects: [
    {
      name: "mobile-390",
      grepInvert: /@desktop/,
      use: { viewport: { width: 390, height: 844 } },
    },
    {
      name: "tablet-768",
      grepInvert: /@desktop/,
      use: { viewport: { width: 768, height: 1024 } },
    },
    {
      name: "desktop-1440",
      use: { viewport: { width: 1440, height: 900 } },
    },
  ],
});
