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
  document.getElementById("blockedTitle").textContent =
    info.tone === "danger" ? "Dangerous website blocked" : "This site needs a closer look";

  const list = document.getElementById("blockedReasonsList");
  const reasons = info.findings.filter((f) => f.level === "high" || f.level === "medium").slice(0, 6);
  list.innerHTML = (reasons.length ? reasons : [{ title: "Multiple risk signals detected in this address" }])
    .map((f) => `<li>${escapeHtml(f.title)}</li>`)
    .join("");

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
