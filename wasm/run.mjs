// Loads the module that wasm/src/lib.rs builds, calls each group of checks and fails unless every
// check of it passed. Prints the engine and the module's SHA-256 for the record.
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

const file = process.argv[2];
if (file === undefined) {
  throw new Error("give the path of the built .wasm module");
}
const bytes = readFileSync(file);
const digest = createHash("sha256").update(bytes).digest("hex");
const { instance } = await WebAssembly.instantiate(bytes);
const groups = [
  ["buffers", 6],
  ["input", 4],
  ["fallbacks", 8],
];

console.log(`Node ${process.version}, V8 ${process.versions.v8}, module SHA-256 ${digest}`);
for (const [name, expected] of groups) {
  const passed = instance.exports[name]();
  console.log(`${name}: ${passed} of ${expected} checks passed`);
  if (passed !== expected) {
    process.exitCode = 1;
  }
}
