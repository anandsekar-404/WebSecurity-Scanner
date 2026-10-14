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
  list.replaceChildren();

  if (threatMatch) {
    const li = document.createElement("li");
    const strong = document.createElement("strong");
    strong.textContent = threatMatch.title || "";
    li.appendChild(strong);
    li.appendChild(document.createTextNode(` — ${threatMatch.detail || ""}`));
    list.appendChild(li);
  }

  const reasons = (info.findings || []).filter((f) => f.id !== "known-threat-match" && (f.level === "high" || f.level === "medium")).slice(0, 6);
  if (reasons.length > 0) {
    for (const f of reasons) {
      const li = document.createElement("li");
      li.textContent = f.title || "";
      list.appendChild(li);
    }
  } else if (!threatMatch) {
    const li = document.createElement("li");
    li.textContent = "Multiple risk signals detected in this address";
    list.appendChild(li);
  }

  window.__blockInfo = info;
}

function escapeHtml(str) {
  return String(str ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
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
  if (!blockId) return;
  await chrome.runtime.sendMessage({ type: "approveContinue", id: blockId }).catch(() => {});
});

init();
spawnParticles();
