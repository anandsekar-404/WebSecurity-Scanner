// In-memory chrome.storage stub
const storageData = {};
const sessionStorageData = {};
globalThis.chrome = {
  webNavigation: {
    onBeforeNavigate: { addListener(cb) { globalThis.__navListener = cb; } },
    onCommitted: { addListener(cb) { globalThis.__committedListener = cb; } },
  },
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
    session: {
      get(defaults, cb) {
        const result = {};
        const defObj = defaults && typeof defaults === "object" && !Array.isArray(defaults) ? defaults : {};
        const keyList = Array.isArray(defaults) ? defaults : typeof defaults === "string" ? [defaults] : Object.keys(defObj);
        for (const key of keyList) result[key] = key in sessionStorageData ? sessionStorageData[key] : defObj[key] ?? null;
        if (typeof cb === "function") cb(result);
        return Promise.resolve(result);
      },
      set(values, cb) {
        Object.assign(sessionStorageData, values);
        if (typeof cb === "function") cb?.();
        return Promise.resolve();
      },
      remove(keys, cb) {
        const keyList = Array.isArray(keys) ? keys : [keys];
        for (const key of keyList) delete sessionStorageData[key];
        if (typeof cb === "function") cb?.();
        return Promise.resolve();
      },
    },
  },
};

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
  assert((await blocking.getBlockReason("nonexistent")) === null, "unknown blockId returns null (page shows 'warning expired')");
  await blocking.approveOnce(42, "https://example.com/");
  assert((await blocking.isApproved(42, "https://example.com/")) === true, "isApproved returns true for approved tab+url");
  assert((await blocking.isApproved(43, "https://example.com/")) === false, "isApproved returns false for different tab");
  console.log("  ok - approveOnce() and isApproved() operate correctly with chrome.storage.session");

  console.log("\nScenario: end-to-end pre-navigation listener — heuristically dangerous URL redirects to blocked.html");
  blocking.initBlocking();
  const listener = globalThis.__navListener;
  assert(typeof listener === "function", "initBlocking() registered a webNavigation onBeforeNavigate listener");
  globalThis.__lastTabUpdate = null;
  await listener({ frameId: 0, tabId: 7, url: "http://xn--pypal-4ve.secure-login-verify.top/account/login-update?redirect=http://evil.example" });
  await new Promise((r) => setTimeout(r, 20));
  assert(globalThis.__lastTabUpdate?.tabId === 7, "dangerous URL triggers tabs.update() to redirect the tab");
  assert(globalThis.__lastTabUpdate?.info.url.startsWith("chrome-extension://fake-id/blocked.html?id="), "redirect target is blocked.html with a block id");

  // Verify the blockId can be retrieved from session storage
  const blockId = new URL(globalThis.__lastTabUpdate.info.url).searchParams.get("id");
  const storedReason = await blocking.getBlockReason(blockId);
  assert(storedReason !== null && storedReason.tabId === 7, "stored block reason has tabId and url preserved in session storage");

  console.log("\nScenario: webNavigation.onCommitted catches server-side redirects to dangerous URLs");
  const committedListener = globalThis.__committedListener;
  assert(typeof committedListener === "function", "initBlocking() registered a webNavigation onCommitted listener");
  globalThis.__lastTabUpdate = null;
  await committedListener({
    frameId: 0,
    tabId: 15,
    url: "http://xn--pypal-4ve.secure-login-verify.top/account/login-update?redirect=http://evil.example",
    transitionQualifiers: ["server_redirect"],
  });
  await new Promise((r) => setTimeout(r, 20));
  assert(globalThis.__lastTabUpdate?.tabId === 15, "server-side redirect to dangerous URL triggers tabs.update()");

  console.log("\nScenario: safe URL does NOT trigger a redirect");
  globalThis.__lastTabUpdate = null;
  await listener({ frameId: 0, tabId: 8, url: "https://github.com/anthropics/claude-code" });
  await new Promise((r) => setTimeout(r, 20));
  assert(globalThis.__lastTabUpdate === null, "safe URL does not trigger tabs.update()");

  console.log("\nScenario: a mild/borderline URL that's a CONFIRMED threat-database match still blocks, as Critical");
  const { defaultThreatDb: db } = await import("../lib/threatDb.js");
  const { normalizeForLookup } = await import("../lib/urlUtils.js");
  const mildUrl = "https://harmless-looking-shop.example/checkout";
  const mildAnalysis = analyzeUrl(mildUrl);
  assert(grade(mildAnalysis.score).tone === "safe", `sanity check — this URL scores as safe on heuristics alone (score=${mildAnalysis.score})`);
  await db.replaceSource("OpenPhish", [
    { indicator: normalizeForLookup(mildUrl), type: "phishing_url", source: "OpenPhish", last_updated: new Date().toISOString(), status: "active" },
    { indicator: "domain:harmless-looking-shop.example", type: "phishing_domain", source: "OpenPhish", last_updated: new Date().toISOString(), status: "active" },
  ], { databaseVersion: "test" });
  globalThis.__lastTabUpdate = null;
  await listener({ frameId: 0, tabId: 9, url: mildUrl });
  await new Promise((r) => setTimeout(r, 20));
  assert(globalThis.__lastTabUpdate?.tabId === 9, "a confirmed threat-DB match blocks even though the heuristic score alone was 'safe'");

  console.log("\nScenario: domain-level threat match blocks when exact path is new");
  globalThis.__lastTabUpdate = null;
  // mildUrl has domain harmless-looking-shop.example. Now try a totally new path on that domain:
  const newPathUrl = "https://harmless-looking-shop.example/different/new-kit-path";
  await listener({ frameId: 0, tabId: 10, url: newPathUrl });
  await new Promise((r) => setTimeout(r, 20));
  assert(globalThis.__lastTabUpdate?.tabId === 10, "new path on a known phishing domain blocks via domain-level matching");

  console.log("\nALL BLOCKING TESTS PASSED");
}

run().catch((e) => {
  console.error(e);
  process.exit(1);
});
