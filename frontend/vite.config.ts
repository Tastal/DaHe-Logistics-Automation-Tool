import react from "@vitejs/plugin-react";
import { configDefaults, defineConfig } from "vitest/config";

import packageJson from "./package.json";

export const LOCAL_API_ORIGIN = "http://127.0.0.1:8877";

export function applyLocalApiOriginHeader(request: {
  setHeader(name: string, value: string): void;
}) {
  request.setHeader("Origin", LOCAL_API_ORIGIN);
}

export default defineConfig({
  plugins: [react()],
  define: {
    __APP_VERSION__: JSON.stringify(packageJson.version),
  },
  server: {
    host: "127.0.0.1",
    port: 5173,
    strictPort: true,
    proxy: {
      "/api": {
        target: LOCAL_API_ORIGIN,
        changeOrigin: true,
        configure(proxy) {
          proxy.on("proxyReq", applyLocalApiOriginHeader);
        },
      },
    },
  },
  test: {
    environment: "jsdom",
    setupFiles: "./src/test/setup.ts",
    css: true,
    restoreMocks: true,
    exclude: [...configDefaults.exclude, "e2e/**"],
  },
});
