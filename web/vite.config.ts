import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: ["./src/test/setup.ts"],
    coverage: {
      provider: "v8",
      reporter: ["text", "text-summary"],
      // Section 14.1: generated code + thin main entry shell excluded.
      include: ["src/**/*.{ts,tsx}"],
      exclude: [
        "src/types/generated/**",
        "src/main.tsx",
        "src/test/**",
        "src/**/*.test.{ts,tsx}",
      ],
      // Per-directory gate: every covered directory must clear 80%.
      thresholds: {
        lines: 80,
        functions: 80,
        branches: 80,
        statements: 80,
        perFile: false,
        autoUpdate: false,
      },
    },
  },
  server: {
    port: 5173,
  },
});
