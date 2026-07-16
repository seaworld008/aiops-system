import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

function developmentProxy(command: string) {
  if (command !== "serve") {
    return undefined;
  }
  const value = process.env.VITE_API_PROXY_TARGET;
  if (value === undefined || value === "") {
    return undefined;
  }
  const target = new URL(value);
  if (
    (target.protocol !== "http:" && target.protocol !== "https:") ||
    target.username !== "" ||
    target.password !== "" ||
    target.pathname !== "/" ||
    target.search !== "" ||
    target.hash !== ""
  ) {
    throw new Error("VITE_API_PROXY_TARGET must be an HTTP(S) origin without credentials or path");
  }
  return {
    "/api": {
      target: target.origin,
      changeOrigin: false,
      secure: true,
    },
  };
}

export default defineConfig(({ command }) => {
  const proxy = developmentProxy(command);
  return {
    plugins: [react()],
    resolve: {
      alias: {
        "@": new URL("./src", import.meta.url).pathname,
      },
    },
    server: {
      ...(proxy === undefined ? {} : { proxy }),
    },
    build: {
      target: "es2024",
      sourcemap: false,
      manifest: true,
      reportCompressedSize: true,
    },
    test: {
      environment: "jsdom",
      setupFiles: ["./src/test/setup.ts"],
      restoreMocks: true,
      clearMocks: true,
      coverage: {
        provider: "v8",
        reporter: ["text", "json-summary"],
        thresholds: {
          lines: 85,
          functions: 85,
          branches: 80,
          statements: 85,
        },
      },
    },
  };
});
