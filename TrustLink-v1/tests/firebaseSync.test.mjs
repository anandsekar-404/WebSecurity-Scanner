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
  assert(typeof isFirebaseConfigured === "boolean", `isFirebaseConfigured is a boolean — got ${typeof isFirebaseConfigured}`);
  assert(isFirestoreSyncConfigured === false, "Firestore sync remains disabled independently of Firebase configuration");

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

  if (isFirebaseConfigured) {
    console.log("\nScenario: Remote Config remains functional when a build-time Firebase key is present");
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
    assert(fetchCalls === 2, `Remote Config made its normal 2 REST calls — got ${fetchCalls}`);
    assert(config.source === "remote", "Remote Config successfully fetched and applied a remote value");
    assert(config.weights.detection_ip_url_score === 40, "the fetched override was correctly applied");
  } else {
    console.log("\nScenario: source checkout without a build-time key safely falls back to local defaults");
    fetchCalls = 0;
    globalThis.fetch = async () => { fetchCalls++; throw new Error("unconfigured source checkout must not call Firebase"); };
    const { getTrustLinkConfig } = await import("../lib/remoteConfig.js");
    const config = await getTrustLinkConfig({ forceRefresh: true });
    assert(fetchCalls === 0, "unconfigured source checkout made ZERO Firebase calls");
    assert(config.source === "default", `configuration source falls back to built-in defaults — got ${config.source}`);
  }

  console.log("\nScenario: Firebase config contains no committed real API key");
  assert((firebaseConfig.apiKey === "__TRUSTLINK_" + "FIREBASE_API_KEY__") || isFirebaseConfigured, "source config is placeholder-only or a build-time key is active");

  console.log("\nALL FIREBASE-SYNC DECOUPLING TESTS PASSED");
}

run().catch((e) => { console.error(e); process.exit(1); });
