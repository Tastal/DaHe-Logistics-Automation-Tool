import { defineConfig } from "@playwright/test";
import { fileURLToPath } from "node:url";

const projectRoot = fileURLToPath(new URL("..", import.meta.url));
const python = `${projectRoot}\\.venv\\Scripts\\python.exe`;
const e2eServer = `${projectRoot}\\tools\\start_playwright_e2e_server.py`;
const externalBaseUrl = process.env.DAHE_E2E_BASE_URL;

export default defineConfig({
  testDir: "./e2e",
  outputDir: "../output/playwright/test-results",
  reporter: "line",
  timeout: 30_000,
  use: {
    baseURL: externalBaseUrl ?? "http://127.0.0.1:8899",
    channel: "msedge",
    locale: "zh-CN",
    screenshot: "only-on-failure",
    trace: "retain-on-failure",
  },
  webServer: externalBaseUrl
    ? undefined
    : {
        command: `"${python}" "${e2eServer}"`,
        reuseExistingServer: false,
        timeout: 120_000,
        url: "http://127.0.0.1:8899/",
      },
});
