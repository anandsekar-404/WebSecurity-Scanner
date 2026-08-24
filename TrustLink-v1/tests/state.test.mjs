// Stubs just enough of the chrome extension API for lib/state.js (and its
// firebaseSync import, which no-ops since firebase-config.js is unconfigured
// by default) to run under plain Node for logic testing.

const store = {};
globalThis.chrome = {
  storage: {
    local: {
      get(defaults, cb) {
        const out = {};
        for (const k of Object.keys(defaults)) out[k] = k in store ? store[k] : defaults[k];
        cb(out);
      },
      set(values, cb) {
        Object.assign(store, values);
        cb && cb();
      },
    },
  },
};

function resetStore() {
  for (const k of Object.keys(store)) delete store[k];
}

function assert(cond, msg) {
  if (!cond) throw new Error("FAIL: " + msg);
  console.log("  ok -", msg);
}

async function run() {
  const state = await import("../lib/state.js");

  console.log("Scenario: brand-new user, 4 sequential manual scans, no prior verification");
  resetStore();
  {
    let gate = await state.canRunManualScan();
    assert(gate.allowed, "1st manual scan is allowed (free)");
    await state.recordManualScanCompleted();

    gate = await state.canRunManualScan();
    assert(gate.allowed, "2nd manual scan is allowed (free)");
    await state.recordManualScanCompleted();

    gate = await state.canRunManualScan();
    assert(!gate.allowed && gate.reason === "instagram-required", "3rd manual scan is BLOCKED, requires Instagram");

    // user opens Instagram + self-confirms
    const confirmed = await state.confirmInstagramFollow();
    assert(confirmed.instagramCompleted === true, "confirmInstagramFollow marks completed");

    gate = await state.canRunManualScan();
    assert(gate.allowed, "3rd manual scan now allowed after confirming");
    await state.recordManualScanCompleted();

    gate = await state.canRunManualScan();
    assert(gate.allowed, "4th manual scan allowed (already verified, no re-prompt)");
    await state.recordManualScanCompleted();

    const finalState = await state.getGateState();
    assert(finalState.manualScanCount === 4, `manualScanCount is 4 (got ${finalState.manualScanCount})`);
    assert(finalState.instagramCompleted === true, "instagramCompleted stays true");
  }

  console.log("\nScenario: already-verified user from a previous session (e.g. re-installed / new browser profile with synced flag)");
  resetStore();
  {
    // Simulate a user who was already verified previously — flag pre-set,
    // count starts fresh (e.g. synced from Firebase on a new device).
    await new Promise((r) => chrome.storage.local.set({ tl_igCompleted: true, tl_manualScanCount: 0 }, r));
    let gate = await state.canRunManualScan();
    assert(gate.allowed, "1st scan allowed");
    await state.recordManualScanCompleted();
    gate = await state.canRunManualScan();
    assert(gate.allowed, "2nd scan allowed");
    await state.recordManualScanCompleted();
    gate = await state.canRunManualScan();
    assert(gate.allowed, "3rd scan allowed WITHOUT modal — already verified, never re-prompted");
  }

  console.log("\nScenario: auto-scan toggle (Stop Scanning)");
  resetStore();
  {
    let enabled = await state.isAutoScanEnabled();
    assert(enabled === true, "auto-scan enabled by default for new user");
    await state.setAutoScanEnabled(false);
    enabled = await state.isAutoScanEnabled();
    assert(enabled === false, "auto-scan can be stopped");
    await state.setAutoScanEnabled(true);
    enabled = await state.isAutoScanEnabled();
    assert(enabled === true, "auto-scan can be resumed");
  }

  console.log("\nScenario: manual scan gating is fully independent of the auto-scan toggle");
  resetStore();
  {
    await state.setAutoScanEnabled(false); // automatic scanner stopped
    const gate = await state.canRunManualScan();
    assert(gate.allowed, "manual scans still work (1st free) even while automatic scanner is stopped");
  }

  console.log("\nALL STATE TESTS PASSED");
}

run().catch((e) => {
  console.error(e);
  process.exit(1);
});
