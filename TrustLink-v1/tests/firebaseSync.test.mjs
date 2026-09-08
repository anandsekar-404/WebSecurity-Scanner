// Proves the Remote Config / Firestore-sync decoupling fix:
//   - Firestore sync is OFF by default, as its own independent flag —
//     not merely because apiKey/projectId happen to be blank.
//   - Configuring Firebase for Remote Config (which this project's
//     lib/firebase-config.js does, with a real apiKey/projectId) does NOT
//     by itself cause lib/firebaseSync.js to make any network or storage
//     call. Zero fetch calls, zero chrome.storage access — not just "it
//     happens to return null", but "it never even tries".
//   - Remote Config itself is completely unaffected — it works from the
//     exact same firebase-config.js in the exact same test run.

let storageCalls = 0;
let fetchCalls = 0;

globalThis.chrome = {
  runtime: { getManifest: () => ({ version: "2.0.0" }) },
  storage: {
    local: {
      get(defaults, cb) {
        storageCalls++;
        // Only relevant for the Remote Config assertions below — Firestore
        // sync should never reach this at all (see assertions).
        cb(defaults);
      },
      set(values, cb) {
        storageCalls++;
        cb?.();
      },
    },
  },
};

function assert(cond, msg) {
  if (!cond) throw new Error("FAIL: " + msg);
  console.log("  ok -", msg);
}

async function run() {
  const { firebaseConfig, isFirebaseConfigured, firestoreSyncEnabled, isFirestoreSyncConfigured } = await import("../lib/firebase-config.js");

  console.log("Scenario: Firestore sync is disabled by default, as its OWN flag");
  assert(firestoreSyncEnabled === false, "firestoreSyncEnabled defaults to false");
  assert(isFirebaseConfigured === true, `this project's real Firebase Web App config IS present (apiKey/projectId set) — got isFirebaseConfigured=${isFirebaseConfigured}`);
  assert(isFirestoreSyncConfigured === false, "despite a valid Firebase config being present, isFirestoreSyncConfigured is still false — proves the two are decoupled, not just 'both happen to be off'");

  console.log("\nScenario: Firestore sync does NOT activate merely because Remote Config is configured — zero network calls, zero storage access");
  {
    fetchCalls = 0;
    storageCalls = 0;
    globalThis.fetch = async () => {
      fetchCalls++;
      throw new Error("lib/firebaseSync.js must never call fetch while Firestore sync is disabled");
    };

    const { pullRemoteState, pushRemoteState } = await import("../lib/firebaseSync.js");

    const pulled = await pullRemoteState();
    assert(pulled === null, "pullRemoteState() resolves to null when Firestore sync is disabled");
    assert(fetchCalls === 0, `pullRemoteState() made ZERO fetch calls (got ${fetchCalls}) — it never even attempts auth`);
    assert(storageCalls === 0, `pullRemoteState() made ZERO chrome.storage calls (got ${storageCalls}) — short-circuits before touching storage at all`);

    const pushed = await pushRemoteState({ manualScanCount: 5 });
    assert(pushed === false, "pushRemoteState() resolves to false when Firestore sync is disabled");
    assert(fetchCalls === 0, `pushRemoteState() also made ZERO fetch calls (got ${fetchCalls})`);
    assert(storageCalls === 0, `pushRemoteState() also made ZERO chrome.storage calls (got ${storageCalls})`);
  }

  console.log("\nScenario: Remote Config is COMPLETELY UNAFFECTED — it still fetches normally from the same firebase-config.js, in the same run");
  {
    fetchCalls = 0;
    storageCalls = 0;
    globalThis.fetch = async (url) => {
      fetchCalls++;
      const u = String(url);
      if (u.includes("firebaseinstallations.googleapis.com")) {
        return { ok: true, json: async () => ({ fid: "test-fid", authToken: { token: "t", expiresIn: "3600s" }, refreshToken: "r" }) };
      }
      if (u.includes("firebaseremoteconfig.googleapis.com")) {
        return { ok: true, json: async () => ({ entries: { detection_ip_url_score: "40" }, templateVersion: "1" }) };
      }
      throw new Error("unexpected fetch in test: " + u);
    };

    const { getTrustLinkConfig } = await import("../lib/remoteConfig.js");
    const config = await getTrustLinkConfig({ forceRefresh: true });

    assert(fetchCalls === 2, `Remote Config made its normal 2 REST calls (Installations + fetch) — got ${fetchCalls}`);
    assert(config.source === "remote", "Remote Config successfully fetched and applied a remote value");
    assert(config.weights.detection_ip_url_score === 40, "the fetched override was correctly applied — Remote Config's own logic is untouched by the Firestore-sync fix");
  }

  console.log("\nScenario: firebaseConfig itself still holds the real public Web App fields (unchanged by this fix)");
  assert(Boolean(firebaseConfig.apiKey) && Boolean(firebaseConfig.projectId), "firebaseConfig still has apiKey/projectId — this fix only added a gate, it didn't touch the config values");

  console.log("\nALL FIREBASE-SYNC DECOUPLING TESTS PASSED");
}

run().catch((e) => { console.error(e); process.exit(1); });
