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

async function inspect(rawUrl) {
  const urlString = normalizeUrl(rawUrl);
  const key = urlString;
  const hit = cache.get(key);
  if (hit && Date.now() - hit.time < CACHE_MS) return hit.result;

  // Best-effort: uses cached/default config immediately if Firebase is slow
  // or unreachable — never blocks a scan on Remote Config (spec section 12).
  const config = await getTrustLinkConfig();

  const base = analyzeUrl(urlString, config);
  let score = base.score;
  let findings = [...base.findings];

  if (base.safeToFetch) {
    try {
      const response = await fetch(urlString, { method: "HEAD", redirect: "follow", cache: "no-store" });
      const headerCheck = analyzeResponse(urlString, response, config);
      score += headerCheck.scoreDelta;
      findings = [...findings, ...headerCheck.findings];
    } catch {
      findings.push({
        id: "header-check-unavailable", level: "low", title: "Header check unavailable",
        detail: "This site didn't respond to a lightweight background request, so header-based signals aren't available. URL-based checks are still shown above."
      });
    }
  }

  const finalScore = Math.max(0, Math.min(Math.round(score), 100));
  let result = {
    url: urlString,
    domain: base.host,
    score: finalScore,
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
        const tabId = message.updateBadge ? (message.tabId ?? sender.tab?.id ?? null) : null;
        inspect(message.url)
          .then((result) => {
            setBadge(tabId, result);
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
          const tabId = message.updateBadge ? (message.tabId ?? sender.tab?.id ?? null) : null;
          try {
            const result = await inspect(message.url);
            await recordManualScanCompleted();
            setBadge(tabId, result);
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
      confirmInstagramFollow().then((r) => respond({ ok: true, ...r })).catch(() => respond({ ok: false }));
      return true;
    }

    case "getAutoScanEnabled": {
      isAutoScanEnabled().then((enabled) => respond({ enabled })).catch(() => respond({ enabled: true }));
      return true;
    }

    case "setAutoScanEnabled": {
      setAutoScanEnabled(message.enabled)
        .then(async (enabled) => {
          if (!enabled) await clearAllBadges();
          respond({ enabled });
        })
        .catch(() => respond({ enabled: true }));
      return true;
    }

    case "getBlockInfo": {
      respond(getBlockReason(message.id));
      return false;
    }

    case "approveContinue": {
      if (message.tabId != null && message.url) {
        approveOnce(message.tabId, message.url);
        chrome.tabs.update(message.tabId, { url: message.url }).catch(() => {});
      }
      respond({ ok: true });
      return false;
    }

    // Developer-only diagnostics panel (spec section 48). Read-only —
    // never triggers a fetch itself, just reports the state of the last one.
    case "getDebugStatus": {
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
