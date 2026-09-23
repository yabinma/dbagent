#!/usr/bin/env node
// Generates TypeScript types from the JSON Schema source of truth into
// web/src/types/generated/*.ts (design.md Section 11: "schemas generate
// pydantic + TS types").
//
// Requires `npm ci` in this directory first (schemas/node_modules is
// gitignored). Output is gitignored too, never committed -- run this
// before your first local build if you need these types; no CI job
// depends on it yet (dashboard-web doesn't exist yet -- see the
// "Generated-code policy" note at the top of .github/workflows/ci.yml).
"use strict";

const fs = require("fs");
const path = require("path");
const { compileFromFile } = require("json-schema-to-typescript");

const SCHEMA_DIR = __dirname;
const OUT_DIR = path.join(__dirname, "..", "web", "src", "types", "generated");

const SCHEMAS = [
  "alert_event.schema.json",
  "rca_report.schema.json",
  "plan.schema.json",
  "tool_result_envelope.schema.json",
];

async function main() {
  fs.mkdirSync(OUT_DIR, { recursive: true });
  for (const file of SCHEMAS) {
    const schemaPath = path.join(SCHEMA_DIR, file);
    const ts = await compileFromFile(schemaPath, {
      bannerComment:
        "/* eslint-disable */\n/**\n * Generated from " +
        path.relative(path.join(__dirname, ".."), schemaPath) +
        " -- do not edit by hand.\n */",
      cwd: SCHEMA_DIR,
    });
    const outFile = path.join(
      OUT_DIR,
      file.replace(/\.schema\.json$/, ".ts")
    );
    fs.writeFileSync(outFile, ts);
    console.log("wrote", outFile);
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
