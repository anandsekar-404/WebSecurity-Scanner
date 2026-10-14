import { analyzeUrl, analyzeResponse, grade, applyThreatMatch } from "./analyzer.js";
import {
  getGateState,
  canRunManualScan,
  recordManualScanCompleted,
  confirmInstagramFollow,
  setAutoScanEnabled,
  isAutoScanEnabled,
} from "./lib/state.js";
import { initBlocking, approveOnce, getBlockReason } from "./lib/blocking.js";
import { getTrustLinkConfig, getDebugStatus } from "./lib/remoteConfig.js";
import { defaultThreatDb as threatDb } from "./lib/threatDb.js";
import { normalizeForLookup } from "./lib/urlUtils.js";
import { updateOpenPhishFeed, SOURCE_NAME as OPENPHISH_SOURCE } from "./lib/adapters/openphish.js";
import { unavailableReason as phishtankUnavailableReason } from "./lib/adapters/phishtank.js";

// Short-lived in-memory cache so re-opening the popup on the same page
// doesn't repeat the network request. Cleared on service worker restart.
const cache = new Map();
const CACHE_MS = 60_000;

function normalizeUrl(raw) {
  const trimmed = (raw || "").trim();
  if (!trimmed) return trimmed;
  if (/^https?:\/\//i.test(trimmed)) return trimmed;
  if (/^[a-z][a-z0-9+.-]*:/i.test(trimmed)) return trimmed; // some other scheme, leave as-is
  return `https://${trimmed}`;
}

async function checkThreatDatabase(config, urlString) {
  if (!config.features.feature_openphish || config.protection.disable_openphish) return { matched: false };
  try {
    return await threatDb.lookup(normalizeForLookup(urlString));
  } catch {
    return { matched: false }; // local DB hiccup must never break a scan
  }
}

// Passive header capture and redirect tracking that survives service worker sleep.
const KEEP_HEADERS = [
  "strict-transport-security",
  "content-security-policy",
  "x-frame-options",
  "x-content-type-options",
  "referrer-policy",
  "permissions-policy",
  "feature-policy",
];

const memorySessionStore = new Map();

async function getSessionData(key) {
  if (typeof chrome !== "undefined" && chrome.storage?.session?.get) {
    return new Promise((resolve) => {
      chrome.storage.session.get(key, (res) => resolve(res?.[key] || null));
    });
  }
  return memorySessionStore.get(key) || null;
}

async function setSessionData(key, value) {
  if (typeof chrome !== "undefined" && chrome.storage?.session?.set) {
    return new Promise((resolve) => {
      chrome.storage.session.set({ [key]: value }, resolve);
    });
  }
  memorySessionStore.set(key, value);
}

async function removeSessionData(keys) {
  const arr = Array.isArray(keys) ? keys : [keys];
  if (typeof chrome !== "undefined" && chrome.storage?.session?.remove) {
    return new Promise((resolve) => {
      chrome.storage.session.remove(arr, resolve);
    });
  }
  for (const k of arr) memorySessionStore.delete(k);
}

if (typeof chrome !== "undefined" && chrome.webNavigation?.onBeforeNavigate) {
  chrome.webNavigation.onBeforeNavigate.addListener((details) => {
    if (details.frameId === 0 && details.tabId >= 0) {
      removeSessionData(`tl_origin_${details.tabId}`).catch(() => {});
    }
  });
}

if (typeof chrome !== "undefined" && chrome.webRequest?.onBeforeRedirect) {
  chrome.webRequest.onBeforeRedirect.addListener(
    (details) => {
      if (details.type === "main_frame" && details.tabId >= 0) {
        getSessionData(`tl_origin_${details.tabId}`).then((origin) => {
          if (!origin) {
            setSessionData(`tl_origin_${details.tabId}`, details.url).catch(() => {});
          }
        }).catch(() => {});
      }
    },
    { urls: ["http://*/*", "https://*/*"], types: ["main_frame"] }
  );
}

if (typeof chrome !== "undefined" && chrome.webRequest?.onHeadersReceived) {
  chrome.webRequest.onHeadersReceived.addListener(
    async (details) => {
      if (details.type !== "main_frame" || details.tabId < 0) return;
      const headers = {};
      for (const h of details.responseHeaders || []) {
        const n = h.name?.toLowerCase();
        if (KEEP_HEADERS.includes(n)) {
          headers[n] = h.value || "1";
        }
      }
      const origin = await getSessionData(`tl_origin_${details.tabId}`).catch(() => null);
      await setSessionData(`tl_hdr_${details.tabId}`, {
        url: details.url,
        origin,
        statusCode: details.statusCode,
        headers,
      }).catch(() => {});
    },
    { urls: ["http://*/*", "https://*/*"], types: ["main_frame"] },
    ["responseHeaders"]
  );
}

if (typeof chrome !== "undefined" && chrome.tabs?.onRemoved) {
  chrome.tabs.onRemoved.addListener((tabId) => {
    removeSessionData([`tl_hdr_${tabId}`, `tl_origin_${tabId}`]).catch(() => {});
  });
}

function isExtensionSender(sender) {
  if (!sender || sender.id !== chrome.runtime.id) return false;
  const extPrefix = chrome.runtime.getURL("");
  return typeof sender.url === "string" && sender.url.startsWith(extPrefix);
}

async function inspect(rawUrl, { isPasted = false, deepCheck = false, tabId = null } = {}) {
  const urlString = normalizeUrl(rawUrl);
  const key = `${urlString}::pasted=${isPasted}::deep=${deepCheck}::tab=${tabId || ""}`;
  const hit = cache.get(key);
  if (hit && Date.now() - hit.time < CACHE_MS) return hit.result;

  // Best-effort: uses cached/default config immediately if Firebase is slow
  // or unreachable — never blocks a scan on Remote Config (spec section 12).
  const config = await getTrustLinkConfig();

  const base = analyzeUrl(urlString, config);
  let score = base.score;
  let findings = [...base.findings];
  let cachedHeaders = null;

  if (base.safeToFetch) {
    cachedHeaders = tabId != null ? await getSessionData(`tl_hdr_${tabId}`).catch(() => null) : null;

    if (cachedHeaders && cachedHeaders.headers) {
      // Passive header check: read from session storage (zero duplicate requests, survives SW sleep)
      const passiveResponse = {
        url: cachedHeaders.url || urlString,
        status: cachedHeaders.statusCode || 200,
        headers: {
          get: (name) => cachedHeaders.headers[name.toLowerCase()] || null,
        },
      };
      const headerCheck = analyzeResponse(cachedHeaders.origin || urlString, passiveResponse, config);
      score += headerCheck.scoreDelta;
      findings = [...findings, ...headerCheck.findings];
    } else if (deepCheck) {
      // Opt-in active deep check: strip query string and fragment for privacy
      let probeUrl = urlString;
      try {
        const parsed = new URL(urlString);
        parsed.search = "";
        parsed.hash = "";
        probeUrl = parsed.toString();
      } catch {}

      try {
        const response = await fetch(probeUrl, {
          method: "HEAD",
          redirect: "follow",
          cache: "no-store",
          credentials: "omit",
          signal: AbortSignal.timeout(8000),
        });

        if (response.status === 403 || response.status === 405) {
          findings.push({
            id: "header-check-unavailable",
            level: "low",
            title: "Header check unavailable",
            detail: `The server returned HTTP ${response.status} to a HEAD probe. Header-based signals are unavailable; URL checks remain active.`,
          });
        } else {
          const headerCheck = analyzeResponse(urlString, response, config);
          score += headerCheck.scoreDelta;
          findings = [...findings, ...headerCheck.findings];
        }
      } catch {
        findings.push({
          id: "header-check-unavailable",
          level: "low",
          title: "Header check unavailable",
          detail: "This site didn't respond to a lightweight probe within 8 seconds, so header-based signals aren't available. URL-based checks are still shown above.",
        });
      }
    } else if (isPasted) {
      findings.push({
        id: "passive-only",
        level: "good",
        title: "Passive URL inspection (privacy-first)",
        detail: "This pasted address was checked locally with heuristics and threat feeds without contacting the server. Deep live header checks are opt-in.",
      });
    }
  }

  const finalScore = Math.max(0, Math.min(Math.round(score), 100));
  let result = {
    url: urlString,
    domain: base.host,
    score: finalScore,
    redirected: Boolean(cachedHeaders?.origin),
    ...grade(finalScore),
    findings,
    checkedAt: new Date().toISOString(),
  };

  // A confirmed local threat-database match overrides the heuristic grade
  // entirely — this is the ONLY path that produces tone: "critical". See
  // analyzer.js's applyThreatMatch() doc comment.
  const match = await checkThreatDatabase(config, urlString);
  if (match.matched) result = applyThreatMatch(result, match);

  cache.set(key, { result, time: Date.now() });
  return result;
}

function setBadge(tabId, result) {
  if (tabId == null) return;
  const byTone = {
    critical: { text: "!!", color: "#8b0000" },
    danger: { text: "!", color: "#ff4d68" },
    warning: { text: "!", color: "#f6c752" },
    safe: { text: "", color: "#35d6ab" },
  };
  const { text, color } = byTone[result.tone] || byTone.safe;
  chrome.action.setBadgeBackgroundColor({ tabId, color }).catch(() => {});
  chrome.action.setBadgeText({ tabId, text }).catch(() => {});
  chrome.action.setBadgeTextColor?.({ tabId, color: "#04070d" }).catch(() => {});
}

async function clearAllBadges() {
  try {
    const tabs = await chrome.tabs.query({});
    for (const tab of tabs) {
      if (tab.id != null) chrome.action.setBadgeText({ tabId: tab.id, text: "" }).catch(() => {});
    }
  } catch { /* best-effort only */ }
}

// Pre-navigation dangerous-page blocking (section 4 of the spec). Registers
// its own webNavigation listener; independent of manual-scan gating and the
// automatic content-script scan below.
initBlocking();

// Best-effort, fire-and-forget local threat-database refresh. Runs once per
// service-worker wake, never blocks message-listener registration above,
// and updateOpenPhishFeed() internally no-ops if the feed was refreshed
// more recently than system_feed_update_interval_ms (spec section 13 — no
// aggressive polling). A failed refresh silently keeps whatever database
// TrustLink already had (spec section 39).
(async () => {
  try {
    const config = await getTrustLinkConfig();
    if (config.features.feature_openphish && !config.protection.disable_openphish) {
      await updateOpenPhishFeed(threatDb, { minIntervalMs: config.system.system_feed_update_interval_ms });
    }
  } catch { /* best-effort startup refresh only */ }
})();

chrome.runtime.onMessage.addListener((message, sender, respond) => {
  switch (message?.type) {
    // Ungated: used by the automatic content-script scan on every page load,
    // and by the popup's initial "show me the current tab" load. Never
    // counts toward the Manual Page Scan limit and never shows the
    // Instagram gate.
    case "inspect": {
      isAutoScanEnabled().then((enabled) => {
        if (message.isAutomatic && !enabled) {
          respond({ stopped: true });
          return;
        }
        const resolvedTabId = message.tabId ?? sender.tab?.id ?? null;
        const badgeTabId = message.updateBadge ? resolvedTabId : null;
        inspect(message.url, {
          isPasted: Boolean(message.isPasted),
          deepCheck: Boolean(message.deepCheck),
          tabId: resolvedTabId,
        })
          .then((result) => {
            setBadge(badgeTabId, result);
            respond(result);
          })
          .catch((error) => respond({ error: error.message }));
      });
      return true;
    }

    // Gated: explicit user-triggered scans (the link-check bar and the
    // popup's "re-run check" button). Subject to the 1st/2nd-free,
    // 3rd-requires-Instagram-follow rule. See lib/state.js for the exact
    // logic and the security notes on why this is best-effort, not
    // tamper-proof.
    case "manualScan": {
      canRunManualScan()
        .then(async (gate) => {
          if (!gate.allowed) {
            respond({ gated: true, reason: gate.reason });
            return;
          }
          const resolvedTabId = message.tabId ?? sender.tab?.id ?? null;
          const badgeTabId = message.updateBadge ? resolvedTabId : null;
          try {
            const result = await inspect(message.url, {
              isPasted: Boolean(message.isPasted),
              deepCheck: Boolean(message.deepCheck),
              tabId: resolvedTabId,
            });
            await recordManualScanCompleted();
            setBadge(badgeTabId, result);
            respond({ gated: false, ...result });
          } catch (error) {
            respond({ error: error.message });
          }
        })
        .catch((error) => respond({ error: error.message }));
      return true;
    }

    case "getGateState": {
      getGateState().then(respond).catch(() => respond(null));
      return true;
    }

    case "confirmInstagramFollow": {
      if (!isExtensionSender(sender)) {
        respond({ ok: false, error: "Unauthorized sender" });
        return false;
      }
      confirmInstagramFollow().then((r) => respond({ ok: true, ...r })).catch(() => respond({ ok: false }));
      return true;
    }

    case "getAutoScanEnabled": {
      isAutoScanEnabled().then((enabled) => respond({ enabled })).catch(() => respond({ enabled: true }));
      return true;
    }

    case "setAutoScanEnabled": {
      if (!isExtensionSender(sender)) {
        respond({ error: "Unauthorized sender" });
        return false;
      }
      setAutoScanEnabled(message.enabled)
        .then(async (enabled) => {
          if (!enabled) await clearAllBadges();
          respond({ enabled });
        })
        .catch(() => respond({ enabled: true }));
      return true;
    }

    case "getBlockInfo": {
      if (!isExtensionSender(sender)) {
        respond(null);
        return false;
      }
      getBlockReason(message.id).then(respond).catch(() => respond(null));
      return true;
    }

    case "approveContinue": {
      if (!isExtensionSender(sender)) {
        respond({ ok: false, error: "Unauthorized sender" });
        return false;
      }
      const blockId = message.id || message.blockId;
      if (!blockId) {
        respond({ ok: false, error: "Missing block ID" });
        return false;
      }
      getBlockReason(blockId).then(async (record) => {
        if (!record || !record.url) {
          respond({ ok: false, error: "Block record expired or not found" });
          return;
        }
        const targetTabId = sender.tab?.id ?? record.tabId;
        if (targetTabId != null) {
          await approveOnce(targetTabId, record.url);
          chrome.tabs.update(targetTabId, { url: record.url }).catch(() => {});
        }
        respond({ ok: true });
      }).catch(() => respond({ ok: false, error: "Approval failed" }));
      return true;
    }

    // Developer-only diagnostics panel (spec section 48). Read-only —
    // never triggers a fetch itself, just reports the state of the last one.
    case "getDebugStatus": {
      if (!isExtensionSender(sender)) {
        respond({ error: "Unauthorized sender" });
        return false;
      }
      Promise.all([getDebugStatus(), threatDb.getStatus()])
        .then(([remoteConfigStatus, threatDbStatus]) => {
          respond({
            firebase: remoteConfigStatus,
            threatSources: {
              [OPENPHISH_SOURCE]: threatDbStatus.find((s) => s.source === OPENPHISH_SOURCE) || { database_status: "no data yet" },
              PhishTank: { database_status: "unavailable", reason: phishtankUnavailableReason },
            },
          });
        })
        .catch((error) => respond({ error: error.message }));
      return true;
    }

    // Manual "force refresh" for the debug panel — bypasses both Remote
    // Config's and the OpenPhish adapter's normal fetch-interval throttling.
    case "forceRefreshThreatData": {
      if (!isExtensionSender(sender)) {
        respond({ error: "Unauthorized sender" });
        return false;
      }
      (async () => {
        try {
          const config = await getTrustLinkConfig({ forceRefresh: true });
          const feedResult = await updateOpenPhishFeed(threatDb, { force: true });
          respond({ ok: true, config: config.source, feedResult });
        } catch (error) {
          respond({ ok: false, error: error.message });
        }
      })();
      return true;
    }

    default:
      return false;
  }
});
