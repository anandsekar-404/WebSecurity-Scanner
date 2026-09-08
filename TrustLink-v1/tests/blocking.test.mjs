// In-memory chrome.storage.local stub — good enough for remoteConfig.js's
// getCachedTrustLinkConfig() (which never fetches, only ever reads this).
const storageData = {};
globalThis.chrome = {
  webNavigation: { onBeforeNavigate: { addListener(cb) { globalThis.__navListener = cb; } } },
  runtime: { getURL: (p) => `chrome-extension://fake-id/${p}`, getManifest: () => ({ version: "2.0.0" }) },
  tabs: { update: async (tabId, info) => { globalThis.__lastTabUpdate = { tabId, info }; } },
  storage: {
    local: {
      get(defaults, cb) {
        const result = {};
        for (const key of Object.keys(defaults)) result[key] = key in storageData ? storageData[key] : defaults[key];
        cb(result);
      },
      set(values, cb) {
        Object.assign(storageData, values);
        cb?.();
      },
    },
  },
};
// Node has a built-in global crypto.randomUUID already (Node 19+), so no
// stub needed here.

function assert(cond, msg) {
  if (!cond) throw new Error("FAIL: " + msg);
  console.log("  ok -", msg);
}

async function run() {
  const { analyzeUrl, grade } = await import("../analyzer.js");

  console.log("Scenario: harmful/dangerous URL classification (would trigger pre-navigation block)");
  const dangerous = analyzeUrl("http://xn--pypal-4ve.secure-login-verify.top/account/login-update?redirect=http://evil.example");
  const dangerGrade = grade(dangerous.score);
  assert(dangerGrade.tone === "danger", `dangerous URL scores as danger (score=${dangerous.score})`);

  console.log("\nScenario: safe URL is NOT flagged");
  const safe = analyzeUrl("https://github.com/anthropics/claude-code");
  const safeGrade = grade(safe.score);
  assert(safeGrade.tone !== "danger", `known-good URL does not score as danger (score=${safe.score}, tone=${safeGrade.tone})`);

  console.log("\nScenario: approve-once / Continue Anyway suppresses re-blocking for that tab+url");
  const blocking = await import("../lib/blocking.js");
  // getBlockReason should return null for unknown ids (expired/garbage-collected)
  assert(blocking.getBlockReason("nonexistent") === null, "unknown blockId returns null (page shows 'warning expired')");
  // approveOnce doesn't throw and is callable independently of webNavigation actually firing
  blocking.approveOnce(42, "https://example.com/");
  console.log("  ok - approveOnce() runs without throwing");

  console.log("\nScenario: end-to-end pre-navigation listener — heuristically dangerous URL redirects to blocked.html");
  blocking.initBlocking();
  const listener = globalThis.__navListener;
  assert(typeof listener === "function", "initBlocking() registered a webNavigation listener");
  globalThis.__lastTabUpdate = null;
  await listener({ frameId: 0, tabId: 7, url: "http://xn--pypal-4ve.secure-login-verify.top/account/login-update?redirect=http://evil.example" });
  await new Promise((r) => setTimeout(r, 10)); // listener body is an async IIFE
  assert(globalThis.__lastTabUpdate?.tabId === 7, "dangerous URL triggers tabs.update() to redirect the tab");
  assert(globalThis.__lastTabUpdate?.info.url.startsWith("chrome-extension://fake-id/blocked.html?id="), "redirect target is blocked.html with a block id");

  console.log("\nScenario: safe URL does NOT trigger a redirect");
  globalThis.__lastTabUpdate = null;
  await listener({ frameId: 0, tabId: 8, url: "https://github.com/anthropics/claude-code" });
  await new Promise((r) => setTimeout(r, 10));
  assert(globalThis.__lastTabUpdate === null, "safe URL does not trigger tabs.update()");

  console.log("\nScenario: a mild/borderline URL that's a CONFIRMED threat-database match still blocks, as Critical");
  const { defaultThreatDb: db } = await import("../lib/threatDb.js");
  const { normalizeForLookup } = await import("../lib/urlUtils.js");
  // ESM caches modules, so this is the SAME defaultThreatDb instance
  // lib/blocking.js itself imported — seeding it here reaches the exact
  // in-memory store blocking.js's lookup() will read from.
  const mildUrl = "https://harmless-looking-shop.example/checkout";
  const mildAnalysis = analyzeUrl(mildUrl);
  assert(grade(mildAnalysis.score).tone === "safe", `sanity check — this URL scores as safe on heuristics alone (score=${mildAnalysis.score})`);
  await db.replaceSource("OpenPhish", [
    { indicator: normalizeForLookup(mildUrl), type: "phishing_url", source: "OpenPhish", last_updated: new Date().toISOString(), status: "active" },
  ], { databaseVersion: "test" });
  globalThis.__lastTabUpdate = null;
  await listener({ frameId: 0, tabId: 9, url: mildUrl });
  await new Promise((r) => setTimeout(r, 10));
  assert(globalThis.__lastTabUpdate?.tabId === 9, "a confirmed threat-DB match blocks even though the heuristic score alone was 'safe'");

  console.log("\nALL BLOCKING TESTS PASSED");
}

run().catch((e) => {
  console.error(e);
  process.exit(1);
});
