// lib/remoteConfig.js — spec sections 6, 7, 12, 13
//
// RemoteConfigManager. The REST of TrustLink calls ONLY getTrustLinkConfig()
// — nothing else in the extension talks to Firebase Remote Config directly,
// per spec section 7 ("Firebase Remote Config → RemoteConfigManager →
// Validated TrustLink Config → Detection Engine").
//
// Deliberately uses raw REST calls instead of the `firebase/remote-config`
// npm SDK — this project has no bundler (see lib/firebaseSync.js for the
// same choice already made for Firestore), and adding a build step just for
// Remote Config would be exactly the kind of over-engineering spec section
// 57 warns against. The two calls below (Installations, then Remote
// Config's `:fetch`) are what the official SDK calls internally; there's no
// functional difference to the Remote Config backend, just no bundle.
//
// EVERY exported function here is best-effort and NEVER throws out to the
// caller — same rule as firebaseSync.js. A Firebase outage must never be
// able to degrade TrustLink's own detection, only its ability to receive
// remote tuning.

import { firebaseConfig, isFirebaseConfigured } from "./firebase-config.js";
import { buildDefaultConfig } from "./heuristics/defaults.js";
import { mergeValidatedConfig } from "./configValidation.js";

const STORAGE_KEYS = {
  fid: "tl_rc_fid",
  authToken: "tl_rc_authToken",
  authTokenExpiry: "tl_rc_authTokenExpiry",
  refreshToken: "tl_rc_refreshToken",
  cachedConfig: "tl_rc_cachedConfig",
  cachedVersion: "tl_rc_cachedVersion",
  lastFetchAttempt: "tl_rc_lastFetchAttempt",
  lastSuccessfulFetch: "tl_rc_lastSuccessfulFetch",
  lastSource: "tl_rc_lastSource", // "remote" | "cache" | "default"
  lastRejectedKeys: "tl_rc_lastRejectedKeys",
};

const SDK_VERSION_STRING = "w:0.0.0-trustlink-rest"; // self-identifying, not a real Firebase SDK build

async function getLocal(defaults) {
  return new Promise((resolve) => chrome.storage.local.get(defaults, resolve));
}
async function setLocal(values) {
  return new Promise((resolve) => chrome.storage.local.set(values, resolve));
}

// --- Firebase Installations (needed to authenticate the Remote Config fetch) ---

/** Generates a Firebase-Installations-compatible FID: 17 random bytes, top nibble forced to 0111, base64url, no padding. */
function generateFid() {
  const bytes = new Uint8Array(17);
  crypto.getRandomValues(bytes);
  bytes[0] = 0b01110000 | (bytes[0] & 0b00001111); // RFC4122-ish "variant" nibble Firebase's SDK uses
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").substring(0, 22);
}

async function registerInstallation(fid) {
  const res = await fetch(
    `https://firebaseinstallations.googleapis.com/v1/projects/${encodeURIComponent(firebaseConfig.projectId)}/installations`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json", "x-goog-api-key": firebaseConfig.apiKey },
      body: JSON.stringify({
        fid, appId: firebaseConfig.appId, authVersion: "FIS_v2", sdkVersion: SDK_VERSION_STRING,
      }),
    }
  );
  if (!res.ok) throw new Error(`Installations register failed (${res.status})`);
  return res.json(); // { fid, authToken: { token, expiresIn }, refreshToken }
}

async function refreshInstallationToken(fid, refreshToken) {
  const res = await fetch(
    `https://firebaseinstallations.googleapis.com/v1/projects/${encodeURIComponent(firebaseConfig.projectId)}/installations/${encodeURIComponent(fid)}/authTokens:generate`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-goog-api-key": firebaseConfig.apiKey,
        Authorization: `FIS_v2 ${refreshToken}`,
      },
      body: JSON.stringify({ installation: { sdkVersion: SDK_VERSION_STRING, appId: firebaseConfig.appId } }),
    }
  );
  if (!res.ok) throw new Error(`Installations token refresh failed (${res.status})`);
  return res.json(); // { token, expiresIn }
}

/** Returns { fid, authToken } or null. Never throws. */
async function getInstallation() {
  try {
    const cached = await getLocal(STORAGE_KEYS);
    const now = Date.now();

    if (cached[STORAGE_KEYS.fid] && cached[STORAGE_KEYS.authToken] && cached[STORAGE_KEYS.authTokenExpiry] > now + 30_000) {
      return { fid: cached[STORAGE_KEYS.fid], authToken: cached[STORAGE_KEYS.authToken] };
    }

    if (cached[STORAGE_KEYS.fid] && cached[STORAGE_KEYS.refreshToken]) {
      const refreshed = await refreshInstallationToken(cached[STORAGE_KEYS.fid], cached[STORAGE_KEYS.refreshToken]);
      await setLocal({
        [STORAGE_KEYS.authToken]: refreshed.token,
        [STORAGE_KEYS.authTokenExpiry]: now + Number(refreshed.expiresIn?.replace?.("s", "") || 3600) * 1000,
      });
      return { fid: cached[STORAGE_KEYS.fid], authToken: refreshed.token };
    }

    const fid = generateFid();
    const created = await registerInstallation(fid);
    await setLocal({
      [STORAGE_KEYS.fid]: created.fid || fid,
      [STORAGE_KEYS.authToken]: created.authToken.token,
      [STORAGE_KEYS.authTokenExpiry]: now + Number(String(created.authToken.expiresIn).replace("s", "")) * 1000,
      [STORAGE_KEYS.refreshToken]: created.refreshToken,
    });
    return { fid: created.fid || fid, authToken: created.authToken.token };
  } catch {
    return null; // offline or Firebase unreachable
  }
}

// --- Remote Config fetch ---------------------------------------------------

async function fetchRemoteEntries(installation) {
  const res = await fetch(
    `https://firebaseremoteconfig.googleapis.com/v1/projects/${encodeURIComponent(firebaseConfig.messagingSenderId)}/namespaces/firebase:fetch?key=${encodeURIComponent(firebaseConfig.apiKey)}`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        app_instance_id: installation.fid,
        app_instance_id_token: installation.authToken,
        app_id: firebaseConfig.appId,
        app_version: (chrome.runtime.getManifest?.() || {}).version || "0.0.0",
        sdk_version: SDK_VERSION_STRING,
      }),
    }
  );
  if (!res.ok) throw new Error(`Remote Config fetch failed (${res.status})`);
  const data = await res.json();
  return { entries: data.entries || {}, templateVersion: data.templateVersion || null };
}

/** Remote Config values always arrive as strings. Coerce each by its OWN param's expected shape before validation ever sees it. */
function coerceEntries(rawEntries) {
  const coerced = {};
  for (const [key, rawString] of Object.entries(rawEntries)) {
    if (
      key.startsWith("feature_") || key === "protection_emergency_enabled" || key.startsWith("disable_")
    ) {
      coerced[key] = rawString === "true" ? true : rawString === "false" ? false : rawString;
    } else if (
      key.startsWith("detection_") || key.startsWith("risk_") || key.startsWith("system_")
    ) {
      const n = Number(rawString);
      coerced[key] = Number.isNaN(n) ? rawString : n;
    } else if (["protectedBrands", "suspiciousTlds", "suspiciousKeywords", "redirectParamNames"].includes(key)) {
      try { coerced[key] = JSON.parse(rawString); } catch { coerced[key] = rawString; }
    } else {
      coerced[key] = rawString; // unknown key — mergeValidatedConfig's isValidParam will reject it
    }
  }
  return coerced;
}

// --- Public API --------------------------------------------------------

/**
 * The ONLY function the rest of TrustLink should call.
 * Returns a fully-populated, validated TrustLink config object — from
 * Remote Config if a fresh fetch succeeded, from the last good cache if
 * not, or the built-in defaults if neither is available. Never throws,
 * never returns partial/undefined shape.
 */
async function loadCachedOrDefaultConfig() {
  const stored = await getLocal({ [STORAGE_KEYS.cachedConfig]: null });
  if (stored[STORAGE_KEYS.cachedConfig]) {
    try {
      return { ...JSON.parse(stored[STORAGE_KEYS.cachedConfig]), source: "cache" };
    } catch {
      return buildDefaultConfig(); // corrupted cache — never let it break TrustLink, fall back to defaults
    }
  }
  return buildDefaultConfig();
}

/**
 * Reads the cached/default config WITHOUT ever attempting a network fetch.
 * For latency-sensitive callers (lib/blocking.js's pre-navigation check)
 * that need weights/feature-flags fast and can't afford to wait on Firebase
 * — the periodic full refresh in background.js's inspect() flow is what
 * actually keeps the cache warm.
 */
export async function getCachedTrustLinkConfig() {
  return loadCachedOrDefaultConfig();
}

export async function getTrustLinkConfig({ forceRefresh = false } = {}) {
  const stored = await getLocal({ [STORAGE_KEYS.lastFetchAttempt]: 0 });
  const base = await loadCachedOrDefaultConfig();

  if (!isFirebaseConfigured) return base;

  const now = Date.now();
  const minInterval = base.system.system_min_fetch_interval_ms;
  if (!forceRefresh && now - (stored[STORAGE_KEYS.lastFetchAttempt] || 0) < minInterval) {
    return base; // respect Remote Config's own fetch-throttling expectations — don't hammer the backend
  }

  await setLocal({ [STORAGE_KEYS.lastFetchAttempt]: now });

  try {
    const installation = await getInstallation();
    if (!installation) return base;

    const { entries, templateVersion } = await fetchRemoteEntries(installation);
    const coerced = coerceEntries(entries);
    const { config: merged, rejectedKeys, wholesaleRejected } = mergeValidatedConfig(base, coerced);

    if (wholesaleRejected) return base;

    const finalConfig = { ...merged, source: "remote" };
    await setLocal({
      [STORAGE_KEYS.cachedConfig]: JSON.stringify(finalConfig),
      [STORAGE_KEYS.cachedVersion]: templateVersion,
      [STORAGE_KEYS.lastSuccessfulFetch]: now,
      [STORAGE_KEYS.lastSource]: "remote",
      [STORAGE_KEYS.lastRejectedKeys]: rejectedKeys,
    });
    return finalConfig;
  } catch {
    return base; // network/auth/parse failure — cached-or-default config stands, TrustLink keeps working
  }
}

/** Spec section 48 — developer-only diagnostics panel data. Read-only, never triggers a fetch. */
export async function getDebugStatus() {
  const data = await getLocal({
    [STORAGE_KEYS.cachedConfig]: null,
    [STORAGE_KEYS.cachedVersion]: null,
    [STORAGE_KEYS.lastSuccessfulFetch]: null,
    [STORAGE_KEYS.lastSource]: null,
    [STORAGE_KEYS.lastRejectedKeys]: [],
  });
  let configValid = false;
  try { configValid = Boolean(data[STORAGE_KEYS.cachedConfig] && JSON.parse(data[STORAGE_KEYS.cachedConfig])); } catch { /* stays false */ }
  return {
    firebaseConfigured: isFirebaseConfigured,
    configurationSource: data[STORAGE_KEYS.lastSource] || (isFirebaseConfigured ? "default" : "default (Firebase unconfigured)"),
    configurationVersion: data[STORAGE_KEYS.cachedVersion],
    lastSuccessfulFetch: data[STORAGE_KEYS.lastSuccessfulFetch],
    configurationValid: configValid,
    rejectedKeys: data[STORAGE_KEYS.lastRejectedKeys] || [],
  };
}
