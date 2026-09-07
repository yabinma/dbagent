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
      // Per-file gate: every covered file must clear the bar. Design §14.1 is
      // *line* coverage, strictly above 80%. Vitest only accepts integer
      // thresholds, so 81 is the enforceable floor that rejects exactly-80%
      // files the previous aggregate gate accepted (code review round 6, W2).
      // Branches are reported but not gated — partial short-circuit arms in
      // presentational components are not the §14.1 bar.
      thresholds: {
        lines: 81,
        functions: 81,
        statements: 81,
        perFile: true,
        autoUpdate: false,
      },
    },
  },
  server: {
    port: 5173,
  },
});
