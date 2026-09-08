// Covers spec sections 6/7 (Installations + Remote Config REST calls),
// 11 (validation), 12 (fallback chain: remote -> cache -> defaults),
// 13 (fetch throttling), and section 50 items 15-18 (Firebase unavailable/
// timeout, invalid Remote Config, no cached configuration) plus the
// emergency-configuration path (section 52) as it flows through the
// manager end to end. Heuristic-level enforcement of feature flags and
// disable_* switches is already covered in tests/heuristics.test.mjs —
// this file is specifically about remoteConfig.js's own fetch/validate/
// cache/fallback plumbing.
//
// Every network call is mocked — this test suite never touches the real
// internet or the real Firebase project.

let storageData;
function resetStorage() { storageData = {}; }

globalThis.chrome = {
  runtime: { getManifest: () => ({ version: "2.0.0" }) },
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

function makeFetchMock({ installationsFails = false, remoteConfigFails = false, remoteConfigStatus = 200, entries = {}, templateVersion = "1" } = {}) {
  const calls = [];
  async function fetchMock(url, opts) {
    calls.push({ url: String(url), opts });
    const u = String(url);
    if (u.includes("firebaseinstallations.googleapis.com")) {
      if (installationsFails) throw new Error("simulated network failure (installations)");
      return {
        ok: true, status: 200,
        json: async () => ({ fid: "test-fid-abcdefghijklmnop", authToken: { token: "test-auth-token", expiresIn: "3600s" }, refreshToken: "test-refresh-token" }),
      };
    }
    if (u.includes("firebaseremoteconfig.googleapis.com")) {
      if (remoteConfigFails) throw new Error("simulated network failure (remote config)");
      return {
        ok: remoteConfigStatus < 400,
        status: remoteConfigStatus,
        json: async () => ({ entries, templateVersion }),
      };
    }
    throw new Error("unexpected fetch URL in test: " + u);
  }
  fetchMock.calls = calls;
  return fetchMock;
}

function assert(cond, msg) {
  if (!cond) throw new Error("FAIL: " + msg);
  console.log("  ok -", msg);
}

async function run() {
  const { getTrustLinkConfig, getCachedTrustLinkConfig, getDebugStatus } = await import("../lib/remoteConfig.js");
  const { isFirebaseConfigured } = await import("../lib/firebase-config.js");
  const { buildDefaultConfig } = await import("../lib/heuristics/defaults.js");
  const defaults = buildDefaultConfig();

  if (!isFirebaseConfigured) {
    console.log("Scenario: source checkout without a build-time Firebase key falls back to local defaults");
    resetStorage();
    let calls = 0;
    globalThis.fetch = async () => { calls++; throw new Error("unconfigured source checkout must not call Firebase"); };
    const config = await getTrustLinkConfig({ forceRefresh: true });
    assert(calls === 0, "unconfigured source checkout made ZERO Firebase calls");
    assert(config.source === "default", `configuration source is built-in defaults — got ${config.source}`);
    console.log("ALL REMOTE CONFIG SOURCE-CHECKOUT TESTS PASSED");
    return;
  }

  console.log("Scenario: successful fetch calls Installations THEN Remote Config, in that order");
  {
    resetStorage();
    const mock = makeFetchMock({ entries: { detection_punycode_score: "40" } });
    globalThis.fetch = mock;
    const config = await getTrustLinkConfig();
    const hosts = mock.calls.map((c) => new URL(c.url).host);
    assert(hosts.includes("firebaseinstallations.googleapis.com"), "an Installations REST request was made");
    assert(hosts.includes("firebaseremoteconfig.googleapis.com"), "a Remote Config REST request was made");
    assert(hosts.indexOf("firebaseinstallations.googleapis.com") < hosts.indexOf("firebaseremoteconfig.googleapis.com"), "Installations is called before Remote Config (auth token is needed for the fetch)");
    assert(config.source === "remote", "successful fetch reports source: remote");
  }

  console.log("\nScenario: successful fetch + configuration validation are both applied");
  {
    resetStorage();
    globalThis.fetch = makeFetchMock({ entries: { detection_punycode_score: "40", feature_typosquatting: "false", not_a_real_param: "true" } });
    const config = await getTrustLinkConfig();
    assert(config.weights.detection_punycode_score === 40, "a valid numeric override was applied (and coerced from the Remote Config string)");
    assert(config.features.feature_typosquatting === false, "a valid boolean override was applied (and coerced from string)");
    assert(config.weights.detection_homograph_score === defaults.weights.detection_homograph_score, "an untouched param keeps its default value");
    assert(!("not_a_real_param" in config), "an unrecognized param is never merged into the config shape at all");
  }

  console.log("\nScenario: cache behavior — the validated config is cached, and read back correctly next time");
  {
    resetStorage();
    globalThis.fetch = makeFetchMock({ entries: { detection_ip_url_score: "17" } });
    await getTrustLinkConfig();
    const cachedOnly = await getCachedTrustLinkConfig();
    assert(cachedOnly.weights.detection_ip_url_score === 17, "the cached config (read with zero network calls) reflects the last successful fetch");
    assert(cachedOnly.source === "cache", "getCachedTrustLinkConfig reports its source as cache, never triggers a fetch");
  }

  console.log("\nScenario: configuration throttle — a second call within the minimum fetch interval does NOT hit the network again");
  {
    resetStorage();
    const mock = makeFetchMock({ entries: {} });
    globalThis.fetch = mock;
    await getTrustLinkConfig(); // first call: fetches
    const callsAfterFirst = mock.calls.length;
    await getTrustLinkConfig(); // second call: should be throttled
    assert(mock.calls.length === callsAfterFirst, `no additional network calls were made on the second call within the throttle window (calls stayed at ${callsAfterFirst})`);
  }

  console.log("\nScenario: forceRefresh bypasses the throttle");
  {
    resetStorage();
    const mock = makeFetchMock({ entries: {} });
    globalThis.fetch = mock;
    await getTrustLinkConfig();
    const callsAfterFirst = mock.calls.length;
    await getTrustLinkConfig({ forceRefresh: true });
    assert(mock.calls.length > callsAfterFirst, "forceRefresh: true triggers a fresh network attempt even inside the throttle window");
  }

  console.log("\nScenario: Firebase/network failure on a first-ever call (no cache yet) falls back to built-in defaults, never throws");
  {
    resetStorage();
    globalThis.fetch = makeFetchMock({ installationsFails: true });
    const config = await getTrustLinkConfig();
    assert(config.weights.detection_punycode_score === defaults.weights.detection_punycode_score, "built-in default weight is used");
    assert(config.features.feature_openphish === defaults.features.feature_openphish, "built-in default feature flag is used");
  }

  console.log("\nScenario: Firebase/network failure AFTER a good cache exists falls back to the CACHE, not bare defaults");
  {
    resetStorage();
    globalThis.fetch = makeFetchMock({ entries: { detection_ip_url_score: "33" } });
    await getTrustLinkConfig(); // seeds a good cache
    globalThis.fetch = makeFetchMock({ installationsFails: true }); // now Firebase goes down
    const config = await getTrustLinkConfig({ forceRefresh: true });
    assert(config.weights.detection_ip_url_score === 33, "the previously cached (non-default) value is preserved when a later fetch fails");
    assert(config.source === "cache", "source correctly reported as cache, not remote, after the failed refresh");
  }

  console.log("\nScenario: invalid/malformed Remote Config response (entries is not an object) is rejected wholesale — no corruption");
  {
    resetStorage();
    // Simulate the fetch succeeding at the transport level but the backend
    // returning a shape our code can't use (e.g. `entries` missing/null).
    globalThis.fetch = async (url) => {
      if (String(url).includes("firebaseinstallations")) {
        return { ok: true, json: async () => ({ fid: "f", authToken: { token: "t", expiresIn: "3600s" }, refreshToken: "r" }) };
      }
      return { ok: true, json: async () => ({ entries: null, templateVersion: "1" }) };
    };
    const config = await getTrustLinkConfig();
    assert(config.weights.detection_punycode_score === defaults.weights.detection_punycode_score, "malformed entries payload leaves the (default, since no prior cache) config completely untouched");
  }

  console.log("\nScenario: a Remote Config HTTP error (non-2xx) is treated as a failure, not an empty-but-valid config");
  {
    resetStorage();
    globalThis.fetch = makeFetchMock({ remoteConfigStatus: 500, entries: { detection_punycode_score: "99" } });
    const config = await getTrustLinkConfig();
    assert(config.weights.detection_punycode_score === defaults.weights.detection_punycode_score, "a 500 response never applies its (irrelevant) body — falls back to defaults");
  }

  console.log("\nScenario: emergency configuration fields round-trip through fetch -> validate -> cache correctly");
  {
    resetStorage();
    globalThis.fetch = makeFetchMock({ entries: { protection_emergency_enabled: "true", disable_homograph: "true", feature_homograph: "true" } });
    const config = await getTrustLinkConfig();
    assert(config.protection.protection_emergency_enabled === true, "protection_emergency_enabled applied");
    assert(config.protection.disable_homograph === true, "an individual disable_* switch applied even though its feature_* flag is still true");
    assert(config.features.feature_homograph === true, "the feature flag itself is untouched by the emergency switch — spec section 52: the master switch must never silently disable everything by itself");
  }

  console.log("\nScenario: getDebugStatus() reflects reality without ever triggering a fetch");
  {
    resetStorage();
    const mock = makeFetchMock({ entries: { detection_ip_url_score: "50" } });
    globalThis.fetch = mock;
    await getTrustLinkConfig();
    const callsAfterFetch = mock.calls.length;
    const status = await getDebugStatus();
    assert(status.configurationValid === true, "debug status reports the cached config as valid");
    assert(status.configurationSource === "remote", "debug status reports the correct source");
    assert(mock.calls.length === callsAfterFetch, "getDebugStatus() made zero additional network calls");
  }

  console.log("\nALL REMOTE CONFIG TESTS PASSED");
}

run().catch((e) => { console.error(e); process.exit(1); });
