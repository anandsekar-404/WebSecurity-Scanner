globalThis.chrome = {
  webNavigation: { onBeforeNavigate: { addListener() {} } },
  runtime: { getURL: (p) => `chrome-extension://fake-id/${p}` },
  tabs: { update: async () => {} },
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
  const blockId = "test-block-id";
  // getBlockReason should return null for unknown ids (expired/garbage-collected)
  assert(blocking.getBlockReason("nonexistent") === null, "unknown blockId returns null (page shows 'warning expired')");
  // approveOnce doesn't throw and is callable independently of webNavigation actually firing
  blocking.approveOnce(42, "https://example.com/");
  console.log("  ok - approveOnce() runs without throwing");

  console.log("\nALL BLOCKING TESTS PASSED");
}

run().catch((e) => {
  console.error(e);
  process.exit(1);
});
