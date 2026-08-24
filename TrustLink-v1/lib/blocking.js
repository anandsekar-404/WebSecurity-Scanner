// lib/blocking.js
//
// MV3 no longer allows extensions to synchronously cancel a network request
// (blocking webRequest was removed for most extensions). The standard,
// MV3-compatible way to stop a dangerous navigation is what we do here:
// listen for webNavigation.onBeforeNavigate on the main frame, run our fast
// *URL-only* heuristics (no network round-trip, so it's effectively
// instant), and if that alone already scores High Risk, immediately
// re-point the tab at our interstitial before the dangerous page can
// finish loading.
//
// Header-based signals (HSTS, CSP, redirect-chain checks, etc.) need a
// network round trip and can't be evaluated before navigation starts, so
// those continue to surface via the in-page banner (content.js) and the
// popup, exactly as before — this module is an additional, earlier layer,
// not a replacement for that deeper check.

import { analyzeUrl, grade } from "../analyzer.js";

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
  setTimeout(() => blockReasons.delete(id), 10 * 60 * 1000);
  return id;
}

export function initBlocking() {
  chrome.webNavigation.onBeforeNavigate.addListener((details) => {
    if (details.frameId !== 0) return; // main frame only
    const { url, tabId } = details;
    if (shouldSkip(url) || !isCheckableUrl(url)) return;
    if (isApproved(tabId, url)) return;

    let base;
    try {
      base = analyzeUrl(url);
    } catch {
      return;
    }
    const g = grade(base.score);
    if (g.tone !== "danger") return;

    const blockId = storeBlockReason({
      url,
      score: base.score,
      tone: g.tone,
      label: g.label,
      action: g.action,
      findings: base.findings,
    });

    chrome.tabs.update(tabId, { url: chrome.runtime.getURL(`blocked.html?id=${blockId}`) }).catch(() => {});
  });
}
