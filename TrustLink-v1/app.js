// Page-specific logic for the full-screen link checker. Shared rendering
// helpers (render, setLoading, showError, icons, etc.) live in ui-core.js.

// Ungated: used only for the initial load when handed off from the popup
// (?url=...), which is a continuation of a check the popup already showed
// for free, not a new user-triggered scan.
async function loadInitial(rawValue) {
  const value = (rawValue || "").trim();
  if (!value) return;
  setLoading();
  $("#domainName").textContent = "Checking…";
  try {
    const result = await chrome.runtime.sendMessage({ type: "inspect", url: value });
    render(result, { isManual: false, tab: null });
    $("#linkInput").value = result.url || value;
  } catch (err) {
    showError(err.message || "Could not run that check.");
  }
}

// Gated: the user explicitly pressing "Check link" on this page. Counts as
// a Manual Page Scan (1st/2nd free, then requires the Instagram step).
async function checkLink(rawValue) {
  const value = (rawValue || "").trim();
  if (!value) return;
  setLoading();
  $("#domainName").textContent = "Checking…";
  try {
    const result = await chrome.runtime.sendMessage({ type: "manualScan", url: value });
    if (result?.gated) {
      openInstagramGate(() => checkLink(value));
      return;
    }
    render(result, { isManual: false, tab: null });
    $("#linkInput").value = result.url || value;
  } catch (err) {
    showError(err.message || "Could not run that check.");
  }
}

$("#linkCheckForm").addEventListener("submit", (e) => {
  e.preventDefault();
  checkLink($("#linkInput").value).catch((err) => showError(err.message));
});

spawnParticles();
initStopScanButton();

// If opened from the popup's expand button, the current tab's URL is passed
// along so the full-screen view picks up right where the popup left off.
// If opened from the popup's paste-a-link form (?manual=1), run it as a
// gated Manual Page Scan instead — that check hasn't happened yet.
const params = new URLSearchParams(location.search);
const initialUrl = params.get("url");
if (initialUrl) {
  if (params.get("manual") === "1") {
    $("#linkInput").value = initialUrl;
    checkLink(initialUrl).catch((err) => showError(err.message));
  } else {
    loadInitial(initialUrl).catch((err) => showError(err.message));
  }
}
