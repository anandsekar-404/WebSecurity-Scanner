const params = new URLSearchParams(location.search);
const blockId = params.get("id");

async function init() {
  const info = await chrome.runtime.sendMessage({ type: "getBlockInfo", id: blockId }).catch(() => null);
  if (!info) {
    document.getElementById("blockedUrl").textContent = "This warning has expired. Go back and try again.";
    return;
  }

  document.getElementById("blockedUrl").textContent = info.url;
  document.getElementById("blockedScoreBadge").textContent = `${info.score} / 100`;
  document.getElementById("blockedLabel").textContent = info.label;

  const titles = {
    critical: "Known phishing website blocked",
    danger: "Dangerous website blocked",
  };
  document.getElementById("blockedTitle").textContent = titles[info.tone] || "This site needs a closer look";

  // A confirmed threat-database match is always the first finding (see
  // analyzer.js's applyThreatMatch) — surface it as its own line, spec
  // section 37's "Threat Intelligence: <source>" format, ahead of the
  // regular heuristic reasons.
  const threatMatch = info.findings.find((f) => f.id === "known-threat-match");

  document.getElementById("bgGlow")?.classList.add(info.tone === "critical" ? "critical" : "danger");
  document.querySelector(".blocked-shell")?.classList.add(info.tone === "critical" ? "critical" : "danger");

  const list = document.getElementById("blockedReasonsList");
  const reasons = info.findings.filter((f) => f.id !== "known-threat-match" && (f.level === "high" || f.level === "medium")).slice(0, 6);
  const items = [];
  if (threatMatch) items.push(`<li><strong>${escapeHtml(threatMatch.title)}</strong> — ${escapeHtml(threatMatch.detail)}</li>`);
  items.push(...(reasons.length ? reasons : items.length ? [] : [{ title: "Multiple risk signals detected in this address" }]).map((f) => `<li>${escapeHtml(f.title)}</li>`));
  list.innerHTML = items.join("");

  window.__blockInfo = info;
}

function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = str ?? "";
  return div.innerHTML;
}

document.getElementById("goBackBtn").addEventListener("click", async () => {
  const tab = await chrome.tabs.getCurrent();
  if (tab?.id != null) {
    chrome.tabs.goBack(tab.id).catch(() => {
      chrome.tabs.update(tab.id, { url: "https://www.google.com/" }).catch(() => {});
    });
  }
});

document.getElementById("revealContinue").addEventListener("click", () => {
  document.getElementById("continueConfirm").hidden = false;
  document.getElementById("revealContinue").hidden = true;
});

document.getElementById("cancelContinue").addEventListener("click", () => {
  document.getElementById("continueConfirm").hidden = true;
  document.getElementById("revealContinue").hidden = false;
});

document.getElementById("continueAnywayBtn").addEventListener("click", async () => {
  const info = window.__blockInfo;
  const tab = await chrome.tabs.getCurrent();
  if (!info || tab?.id == null) return;
  await chrome.runtime.sendMessage({ type: "approveContinue", url: info.url, tabId: tab.id }).catch(() => {});
});

init();
spawnParticles();
