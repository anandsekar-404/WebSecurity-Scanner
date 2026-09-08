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
const approvals = new Map(); // `${tabId}::${url}` -> expiry timestamp
const blockReasons = new Map(); // blockId -> { url, score, tone, label, action, findings }

function approvalKey(tabId, url) {
  return `${tabId}::${url}`;
}

function isCheckableUrl(url) {
  return /^https?:\/\//i.test(url);
}

function shouldSkip(url) {
  return url.startsWith(chrome.runtime.getURL("")) || /^(chrome|edge|about|chrome-extension|devtools|file|data):/i.test(url);
}

export function approveOnce(tabId, url) {
  approvals.set(approvalKey(tabId, url), Date.now() + APPROVAL_TTL_MS);
}

function isApproved(tabId, url) {
  const expiry = approvals.get(approvalKey(tabId, url));
  if (!expiry) return false;
  if (Date.now() > expiry) {
    approvals.delete(approvalKey(tabId, url));
    return false;
  }
  return true;
}

export function getBlockReason(blockId) {
  return blockReasons.get(blockId) || null;
}

function storeBlockReason(payload) {
  const id = crypto.randomUUID();
  blockReasons.set(id, payload);
  // Keep memory bounded — this data is only needed for the few seconds
  // between redirecting and blocked.html reading it back.
  const timer = setTimeout(() => blockReasons.delete(id), 10 * 60 * 1000);
  // .unref() only exists in Node (which is how the test suite runs this
  // file) — a real MV3 service worker's setTimeout returns a plain number
  // with no such method, so this is a no-op there and harmless either way.
  if (typeof timer?.unref === "function") timer.unref();
  return id;
}

export function initBlocking() {
  chrome.webNavigation.onBeforeNavigate.addListener((details) => {
    if (details.frameId !== 0) return; // main frame only
    const { url, tabId } = details;
    if (shouldSkip(url) || !isCheckableUrl(url)) return;
    if (isApproved(tabId, url)) return;

    (async () => {
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
          // local DB unavailable for some reason — fall through to the
          // heuristic-only result rather than failing the whole check
        }
      }

      if (result.tone !== "danger" && result.tone !== "critical") return;

      const blockId = storeBlockReason({
        url,
        score: result.score,
        tone: result.tone,
        label: result.label,
        action: result.action,
        findings: result.findings,
      });

      chrome.tabs.update(tabId, { url: chrome.runtime.getURL(`blocked.html?id=${blockId}`) }).catch(() => {});
    })();
  });
}
