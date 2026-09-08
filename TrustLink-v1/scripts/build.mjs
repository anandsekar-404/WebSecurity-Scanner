import { cp, mkdir, readdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const dist = path.join(root, "dist");
const placeholder = "__TRUSTLINK_FIREBASE_API_KEY__";
const apiKey = process.env.TRUSTLINK_FIREBASE_API_KEY?.trim() || "";

await mkdir(dist, { recursive: true });
for (const entry of await readdir(root, { withFileTypes: true })) {
  if (["dist", ".git", "node_modules"].includes(entry.name)) continue;
  await cp(path.join(root, entry.name), path.join(dist, entry.name), { recursive: true, force: true });
}
const configPath = path.join(dist, "lib", "firebase-config.js");
let config = await readFile(configPath, "utf8");
if (apiKey) config = config.replaceAll(placeholder, apiKey);
else console.warn("TRUSTLINK_FIREBASE_API_KEY is not set; building a local-only TrustLink package.");
await writeFile(configPath, config, "utf8");
console.log(`Build complete: ${dist}`);
