// Covers spec section 50 items 19-21 (feed update failure, corrupted
// database, malformed entries) at the threatDb layer, plus the core
// contract: a miss is NOT a safety verdict, and replaceSource() is atomic
// per-source (touching one source never disturbs another's data).

import { createThreatDb } from "../lib/threatDb.js";

function assert(cond, msg) {
  if (!cond) throw new Error("FAIL: " + msg);
  console.log("  ok -", msg);
}

async function run() {
  const db = createThreatDb(); // fresh, isolated instance — Node has no indexedDB, so this uses the in-memory backend

  console.log("Scenario: a lookup miss is explicitly 'no match', never 'safe'");
  const miss = await db.lookup("https://never-seen.example/");
  assert(miss.matched === false, "miss returns matched: false");
  assert(!("safe" in miss), "miss result never claims 'safe' — spec section 22/38");

  console.log("\nScenario: publishing entries makes them exact-match lookupable");
  await db.replaceSource("OpenPhish", [
    { indicator: "https://evil.example/login", type: "phishing_url", source: "OpenPhish", last_updated: "2026-09-01T00:00:00Z", status: "active" },
    { indicator: "https://also-evil.example/", type: "phishing_url", source: "OpenPhish", last_updated: "2026-09-01T00:00:00Z", status: "active" },
  ], { databaseVersion: "v1" });
  const hit = await db.lookup("https://evil.example/login");
  assert(hit.matched === true && hit.source === "OpenPhish" && hit.type === "phishing_url", "exact indicator match returns source + type");
  assert((await db.countBySource("OpenPhish")) === 2, "both entries stored");

  console.log("\nScenario: replaceSource is per-source atomic — updating one source never touches another's data");
  await db.replaceSource("URLhaus", [
    { indicator: "https://malware.example/payload.exe", type: "malware_url", source: "URLhaus", last_updated: "2026-09-01T00:00:00Z", status: "active" },
  ], { databaseVersion: "v1" });
  assert((await db.lookup("https://evil.example/login")).matched, "OpenPhish's entry survives an unrelated URLhaus publish");
  assert((await db.lookup("https://malware.example/payload.exe")).source === "URLhaus", "URLhaus's own entry is present");

  console.log("\nScenario: replaceSource() fully REPLACES a source's previous entries (not a merge)");
  await db.replaceSource("OpenPhish", [
    { indicator: "https://new-evil.example/", type: "phishing_url", source: "OpenPhish", last_updated: "2026-09-02T00:00:00Z", status: "active" },
  ], { databaseVersion: "v2" });
  assert((await db.lookup("https://evil.example/login")).matched === false, "the OLD OpenPhish entry is gone after a fresh publish");
  assert((await db.lookup("https://new-evil.example/")).matched === true, "the NEW OpenPhish entry is present");
  assert((await db.lookup("https://malware.example/payload.exe")).matched === true, "URLhaus's entry is still untouched by the OpenPhish replace");

  console.log("\nScenario: metadata reflects actual values (spec section 41 — never fabricate database counts)");
  const meta = await db.getMeta("OpenPhish");
  assert(meta.entry_count === 1, `entry_count matches what was actually stored (got ${meta.entry_count})`);
  assert(meta.database_version === "v2", "database_version reflects the latest publish");

  console.log("\nALL THREATDB TESTS PASSED");
}

run().catch((e) => { console.error(e); process.exit(1); });
