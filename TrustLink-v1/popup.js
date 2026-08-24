// Page-specific logic for the toolbar popup. Shared rendering helpers
// (render, setLoading, showError, icons, etc.) live in ui-core.js.

// Free, ungated: shows the current tab's status the moment the popup opens.
// This is convenience display, not a user-triggered "Manual Page Scan".
async function scanCurrentTab() {
  setLoading();
  $("#manualNotice").hidden = true;
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const url = tab?.url;
  if (!url || !/^https?:/i.test(url)) {
    return showError("Open a website (http/https) to run a TrustLink check.");
  }
  lastKnownTab = { id: tab.id, url };
  $("#domainName").textContent = safeHost(url);
  try {
    const result = await chrome.runtime.sendMessage({ type: "inspect", url, tabId: tab.id, updateBadge: true });
    render(result, { isManual: false, tab });
  } catch (err) {
    showError(err.message || "Could not reach the TrustLink background service.");
  }
}

// Gated: an explicit user-triggered re-scan of the current tab. Counts as a
// Manual Page Scan (1st/2nd free, then requires the Instagram step).
async function manualRescanCurrentTab() {
  if (!lastKnownTab?.url) return scanCurrentTab();
  setLoading();
  $("#manualNotice").hidden = true;
  try {
    const result = await chrome.runtime.sendMessage({
      type: "manualScan", url: lastKnownTab.url, tabId: lastKnownTab.id, updateBadge: true,
    });
    if (result?.gated) {
      openInstagramGate(() => manualRescanCurrentTab());
      return;
    }
    render(result, { isManual: false, tab: lastKnownTab });
  } catch (err) {
    showError(err.message || "Could not reach the TrustLink background service.");
  }
}

// Gated: checking an arbitrary pasted link. Counts as a Manual Page Scan.
// Rather than rendering inline in the popup, hand off to the full-screen
// app page — it has room to show the full breakdown — and pass along the
// "manual" flag so app.js runs this as a gated Manual Page Scan, not the
// free ?url= handoff used by the expand button.
async function checkManualLink(rawValue) {
  const value = (rawValue || "").trim();
  if (!value) return;
  await chrome.tabs.create({
    url: chrome.runtime.getURL(`app.html?url=${encodeURIComponent(value)}&manual=1`),
  });
  window.close();
}

function safeHost(url) {
  try { return new URL(url).hostname; } catch { return url; }
}

$("#refresh").addEventListener("click", () => manualRescanCurrentTab().catch((e) => showError(e.message)));

$("#linkCheckForm").addEventListener("submit", (e) => {
  e.preventDefault();
  const input = $("#linkInput");
  checkManualLink(input.value).catch((err) => showError(err.message));
});

$("#backToTab").addEventListener("click", () => {
  $("#linkInput").value = "";
  scanCurrentTab().catch((e) => showError(e.message));
});

$("#expand").addEventListener("click", async () => {
  const target = lastKnownTab?.url ? `app.html?url=${encodeURIComponent(lastKnownTab.url)}` : "app.html";
  await chrome.tabs.create({ url: chrome.runtime.getURL(target) });
  window.close();
});

// "Pin this extension" nudge — only shown when the browser reports the
// extension isn't pinned yet, and only until the user dismisses it. Chrome
// gives extensions no way to pin themselves (by design, for security), so
// this is a plain text reminder rather than a fake "do it for you" button.
async function initPinBanner() {
  const banner = $("#pinBanner");
  if (!banner) return;
  try {
    const { pinBannerDismissed } = await chrome.storage.local.get("pinBannerDismissed");
    if (pinBannerDismissed) return;

    if (chrome.action?.getUserSettings) {
      const settings = await chrome.action.getUserSettings();
      if (settings?.isOnToolbar) return; // already pinned, nothing to nudge about
    }
    banner.hidden = false;
  } catch {
    // If we can't tell either way, err on the side of not nagging.
  }
}

function dismissPinBanner() {
  $("#pinBanner").hidden = true;
  chrome.storage.local.set({ pinBannerDismissed: true }).catch(() => {});
}

$("#pinBannerClose")?.addEventListener("click", dismissPinBanner);

spawnParticles();
initStopScanButton();
initPinBanner();
scanCurrentTab().catch((e) => showError(e.message));
