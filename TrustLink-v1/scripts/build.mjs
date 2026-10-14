import { cp, mkdir, rm, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const dist = path.join(root, "dist");
const placeholder = "__TRUSTLINK_FIREBASE_API_KEY__";
const apiKey = process.env.TRUSTLINK_FIREBASE_API_KEY?.trim() || "";

// Strict allowlist: only ship runtime extension files, exclude tests, scripts, rules, markdown, env files
const SHIPPED_ALLOWLIST = [
  "manifest.json",
  "background.js",
  "analyzer.js",
  "content.js",
  "popup.html",
  "popup.js",
  "popup.css",
  "app.html",
  "app.js",
  "app.css",
  "blocked.html",
  "blocked.js",
  "blocked.css",
  "ui-core.js",
  "cybroatrix-logo.png",
  "icon16.png",
  "icon32.png",
  "icon48.png",
  "icon128.png",
  "lib",
];

await rm(dist, { recursive: true, force: true });
await mkdir(dist, { recursive: true });

for (const entry of SHIPPED_ALLOWLIST) {
  const src = path.join(root, entry);
  const dest = path.join(dist, entry);
  await cp(src, dest, { recursive: true, force: true });
}

const configPath = path.join(dist, "lib", "firebase-config.js");
let config = await readFile(configPath, "utf8");
if (apiKey) config = config.replaceAll(placeholder, apiKey);
else console.warn("TRUSTLINK_FIREBASE_API_KEY is not set; building a local-only TrustLink package.");
await writeFile(configPath, config, "utf8");
console.log(`Build complete: ${dist}`);
