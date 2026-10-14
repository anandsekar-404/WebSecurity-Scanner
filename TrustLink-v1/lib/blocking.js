// lib/blocking.js
//
// MV3 no longer allows extensions to synchronously cancel a network request
// (blocking webRequest was removed for most extensions). The standard,
// MV3-compatible way to stop a dangerous navigation is what we do here:
// listen for webNavigation.onBeforeNavigate on the main frame, run our fast
// *URL-only* heuristics PLUS a local threat-database lookup (both are local,
// no network round-trip, so this is still effectively instant), and if
// either one already indicates High Risk / a confirmed threat match,
// immediately re-point the tab at our interstitial before the dangerous
// page can finish loading.
//
// Deliberately uses getCachedTrustLinkConfig() (never getTrustLinkConfig())
// here — this path must never wait on a live Firebase round-trip. Remote
// Config still applies here (weights, feature flags), just from whatever
// was last cached; background.js's normal inspect() flow is what keeps
// that cache warm.
//
// Header-based signals (HSTS, CSP, redirect-chain checks, etc.) need a
// network round trip and can't be evaluated before navigation starts, so
// those continue to surface via the in-page banner (content.js) and the
// popup, exactly as before — this module is an additional, earlier layer,
// not a replacement for that deeper check.

import { analyzeUrl, grade, applyThreatMatch } from "../analyzer.js";
import { getCachedTrustLinkConfig } from "./remoteConfig.js";
import { defaultThreatDb as threatDb } from "./threatDb.js";
import { normalizeForLookup } from "./urlUtils.js";

const APPROVAL_TTL_MS = 5 * 60 * 1000; // "Continue anyway" stays honored for 5 minutes per tab+url

// Fallback in-memory map for environments without chrome.storage.session (e.g. Node unit tests)
const memorySessionStore = new Map();

async function getSessionData(keys) {
  if (typeof chrome !== "undefined" && chrome.storage?.session?.get) {
    return new Promise((resolve) => chrome.storage.session.get(keys, resolve));
  }
  const result = {};
  const defaults = keys && typeof keys === "object" && !Array.isArray(keys) ? keys : {};
  const keyList = Array.isArray(keys) ? keys : typeof keys === "string" ? [keys] : Object.keys(defaults);
  for (const k of keyList) {
    result[k] = memorySessionStore.has(k) ? memorySessionStore.get(k) : defaults[k] ?? null;
  }
  return result;
}

async function setSessionData(items) {
  if (typeof chrome !== "undefined" && chrome.storage?.session?.set) {
    return new Promise((resolve) => chrome.storage.session.set(items, resolve));
  }
  for (const [k, v] of Object.entries(items)) {
    memorySessionStore.set(k, v);
  }
}

async function removeSessionData(keys) {
  if (typeof chrome !== "undefined" && chrome.storage?.session?.remove) {
    return new Promise((resolve) => chrome.storage.session.remove(keys, resolve));
  }
  const keyList = Array.isArray(keys) ? keys : [keys];
  for (const k of keyList) memorySessionStore.delete(k);
}

function approvalKey(tabId, url) {
  return `tl_appr_${tabId}_${encodeURIComponent(url)}`;
}

function isCheckableUrl(url) {
  return /^https?:\/\//i.test(url);
}

function shouldSkip(url) {
  if (!url) return true;
  const extUrl = typeof chrome !== "undefined" && chrome.runtime?.getURL ? chrome.runtime.getURL("") : "chrome-extension://";
  return url.startsWith(extUrl) || /^(chrome|edge|about|chrome-extension|devtools|file|data):/i.test(url);
}

export async function approveOnce(tabId, url) {
  await setSessionData({ [approvalKey(tabId, url)]: Date.now() + APPROVAL_TTL_MS });
}

export async function isApproved(tabId, url) {
  const key = approvalKey(tabId, url);
  const data = await getSessionData({ [key]: 0 });
  const expiry = data[key] || 0;
  if (!expiry) return false;
  if (Date.now() > expiry) {
    await removeSessionData(key);
    return false;
  }
  return true;
}

export async function getBlockReason(blockId) {
  if (!blockId) return null;
  const key = `tl_block_${blockId}`;
  const data = await getSessionData({ [key]: null });
  return data[key] || null;
}

export async function storeBlockReason(payload) {
  const id = crypto.randomUUID();
  const key = `tl_block_${id}`;
  await setSessionData({ [key]: { id, ...payload, createdAt: Date.now() } });

  // Clean up after 10 minutes to avoid bloating session storage
  const timer = setTimeout(() => removeSessionData(key).catch(() => {}), 10 * 60 * 1000);
  if (typeof timer?.unref === "function") timer.unref();
  return id;
}

async function checkAndBlockNavigation(tabId, url) {
  if (shouldSkip(url) || !isCheckableUrl(url)) return;
  if (await isApproved(tabId, url)) return;

  let config;
  try {
    config = await getCachedTrustLinkConfig();
  } catch {
    return; // never let a config-loading hiccup block navigation
  }

  let base;
  try {
    base = analyzeUrl(url, config);
  } catch {
    return;
  }

  let result = { ...base, ...grade(base.score) };

  // Local threat-database check — a confirmed match always wins,
  // regardless of what the heuristic score alone would have said.
  if (config.features.feature_openphish && !config.protection.disable_openphish) {
    try {
      const indicator = normalizeForLookup(url);
      const match = await threatDb.lookup(indicator);
      if (match.matched) result = applyThreatMatch(result, match);
    } catch {
      // local DB unavailable
    }
  }

  if (result.tone !== "danger" && result.tone !== "critical") return;

  const blockId = await storeBlockReason({
    url,
    tabId,
    score: result.score,
    tone: result.tone,
    label: result.label,
    action: result.action,
    findings: result.findings,
  });

  chrome.tabs.update(tabId, { url: chrome.runtime.getURL(`blocked.html?id=${blockId}`) }).catch(() => {});
}

export function initBlocking() {
  chrome.webNavigation.onBeforeNavigate.addListener((details) => {
    if (details.frameId !== 0) return; // main frame only
    const { url, tabId } = details;
    checkAndBlockNavigation(tabId, url).catch(() => {});
  });

  // Catch server-side redirects (HTTP 301/302/307/308) which bypass onBeforeNavigate
  if (chrome.webNavigation.onCommitted?.addListener) {
    chrome.webNavigation.onCommitted.addListener((details) => {
      if (details.frameId !== 0) return; // main frame only
      const isServerRedirect = details.transitionQualifiers?.includes("server_redirect");
      if (isServerRedirect) {
        checkAndBlockNavigation(details.tabId, details.url).catch(() => {});
      }
    });
  }
}
