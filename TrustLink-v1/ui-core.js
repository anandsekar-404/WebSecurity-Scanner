const $ = (sel) => document.querySelector(sel);
const RING_CIRC = 364.4; // 2 * PI * r(58)

const ICONS = {
  triangle: '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0Z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>',
  lockOpen: '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="10" rx="2"/><path d="M7 11V7a5 5 0 0 1 9.9-1"/></svg>',
  linkBroken: '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 17H7A5 5 0 0 1 7 7h2M15 7h2a5 5 0 1 1 0 10h-2M8 12h1m6 0h1"/></svg>',
  shieldCheck: '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/></svg>',
  info: '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>',
  check: '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>',
  spinner: '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round"><path d="M21 12a9 9 0 1 1-9-9"/></svg>',
};

let lastKnownTab = null; // { id, url } of the browser tab this popup opened on

function cardIcon(finding) {
  const id = finding.id || "";
  if (finding.level === "good") return ICONS.shieldCheck;
  if (id.includes("https") || id.includes("downgrade")) return ICONS.lockOpen;
  if (id.includes("redirect")) return ICONS.linkBroken;
  if (finding.level === "low") return ICONS.info;
  return ICONS.triangle;
}

function pillIcon(tone) {
  if (tone === "safe") return ICONS.check;
  if (tone === "warning" || tone === "danger" || tone === "critical") return ICONS.triangle;
  return ICONS.spinner;
}

function setRing(score, tone) {
  const fill = $("#ringFill");
  const offset = RING_CIRC - (Math.max(0, Math.min(100, score)) / 100) * RING_CIRC;
  fill.style.strokeDashoffset = String(offset);
  $("#ringWrap").className = `ring-wrap ${toneClass(tone)}`;
}

function countUp(el, to, duration = 700) {
  const from = 0;
  const start = performance.now();
  function tick(now) {
    const p = Math.min(1, (now - start) / duration);
    const eased = 1 - Math.pow(1 - p, 3);
    el.textContent = String(Math.round(from + (to - from) * eased));
    if (p < 1) requestAnimationFrame(tick);
  }
  requestAnimationFrame(tick);
}

function setSafeIcon(el, iconHtml) {
  if (!el) return;
  if (Object.values(ICONS).includes(iconHtml)) {
    el.innerHTML = iconHtml;
  } else {
    el.textContent = "";
  }
}

function toneClass(tone) {
  return { safe: "safe", warning: "warning", danger: "danger", critical: "critical" }[tone] || "loading";
}

function setLoading() {
  $("#statusPill").className = "status-pill loading";
  setSafeIcon($("#pillIcon"), pillIcon("loading"));
  $("#score").textContent = "…";
  $("#statusLabel").textContent = "Analyzing";
  $("#statusDesc").textContent = "Running passive security checks…";
  $("#adviceBox").className = "advice-box";
  $("#adviceTitle").textContent = "Please wait";
  $("#adviceSub").textContent = "Gathering signals for this page.";
  $("#ctaRow").hidden = true;
  setRing(0, "loading");
}

function showError(message) {
  $("#statusPill").className = "status-pill warning";
  setSafeIcon($("#pillIcon"), pillIcon("warning"));
  $("#score").textContent = "!";
  $("#statusLabel").textContent = "Check unavailable";
  $("#statusDesc").textContent = message;
  $("#adviceBox").className = "advice-box warning";
  $("#adviceTitle").textContent = "Couldn't complete this check";
  $("#adviceSub").textContent = message;
  $("#findingsGrid").replaceChildren();
  $("#moreSignalsBtn").hidden = true;
  $("#findingsExtra").replaceChildren();
  $("#findingsExtra").hidden = true;
  $("#signalCount").textContent = "";
  $("#ctaRow").hidden = true;
  setRing(0, "warning");
}

function adviceCopy(result) {
  if (result.tone === "critical") return { title: "Known threat — do not proceed", sub: result.action };
  if (result.tone === "danger") return { title: "Do not proceed", sub: result.action };
  if (result.tone === "warning") return { title: "Proceed carefully", sub: result.action };
  return { title: "You're good to go", sub: result.action };
}

function createFindingCard(f, index) {
  const card = document.createElement("article");
  const validLevel = ["good", "low", "medium", "high"].includes(f.level) ? f.level : "low";
  card.className = `finding-card ${validLevel}`;
  card.style.animationDelay = `${140 + index * 55}ms`;

  const top = document.createElement("div");
  top.className = "card-top";

  const iconSpan = document.createElement("span");
  iconSpan.className = "card-icon";
  setSafeIcon(iconSpan, cardIcon(f));
  top.appendChild(iconSpan);

  const body = document.createElement("div");
  const h3 = document.createElement("h3");
  h3.textContent = f.title || "";
  const p = document.createElement("p");
  p.textContent = f.detail || "";
  body.appendChild(h3);
  body.appendChild(p);

  card.appendChild(top);
  card.appendChild(body);
  return card;
}

function createFindingRow(f) {
  const row = document.createElement("div");
  const validLevel = ["good", "low", "medium", "high"].includes(f.level) ? f.level : "low";
  row.className = `finding-row ${validLevel}`;

  const dot = document.createElement("span");
  dot.className = "dot";

  const body = document.createElement("div");
  const h4 = document.createElement("h4");
  h4.textContent = f.title || "";
  const p = document.createElement("p");
  p.textContent = f.detail || "";
  body.appendChild(h4);
  body.appendChild(p);

  row.appendChild(dot);
  row.appendChild(body);
  return row;
}

function render(result, { isManual = false, tab = null } = {}) {
  if (!result || result.error) return showError(result?.error || "Something went wrong running this check.");

  $("#manualNotice").hidden = !isManual;
  $("#domainName").textContent = result.domain || result.url || "Unknown site";

  const tone = result.tone;
  $("#statusPill").className = `status-pill ${toneClass(tone)}`;
  setSafeIcon($("#pillIcon"), pillIcon(tone));
  $("#statusLabel").textContent = result.label;
  $("#statusDesc").textContent = `Risk score ${result.score}/100 — ${result.findings.length} signal${result.findings.length === 1 ? "" : "s"} reviewed.`;
  countUp($("#score"), result.score);
  setRing(result.score, tone);

  const advice = adviceCopy(result);
  $("#adviceBox").className = `advice-box ${toneClass(tone)}`;
  $("#adviceTitle").textContent = advice.title;
  $("#adviceSub").textContent = advice.sub;

  const order = { high: 0, medium: 1, low: 2, good: 3 };
  const sorted = [...result.findings].sort((a, b) => (order[a.level] ?? 4) - (order[b.level] ?? 4));
  const actionable = sorted.filter((f) => f.level !== "good").length;

  $("#signalCount").className = `issue-count ${actionable === 0 ? "ok" : ""}`;
  $("#signalCount").textContent = actionable === 0
    ? "no issues found"
    : `${actionable} issue${actionable === 1 ? "" : "s"} found`;

  const primary = sorted.slice(0, 4);
  const rest = sorted.slice(4);

  const grid = $("#findingsGrid");
  grid.replaceChildren();
  if (primary.length) {
    for (let i = 0; i < primary.length; i++) {
      grid.appendChild(createFindingCard(primary[i], i));
    }
  } else {
    const emptyP = document.createElement("p");
    emptyP.className = "muted";
    emptyP.style.cssText = "grid-column:1/-1;color:var(--muted);font-size:11px;";
    emptyP.textContent = "No notable signals found.";
    grid.appendChild(emptyP);
  }

  const moreBtn = $("#moreSignalsBtn");
  const extra = $("#findingsExtra");
  if (rest.length) {
    moreBtn.hidden = false;
    moreBtn.textContent = `+ ${rest.length} more signal${rest.length === 1 ? "" : "s"}`;
    extra.hidden = true;
    extra.replaceChildren();
    for (const f of rest) {
      extra.appendChild(createFindingRow(f));
    }
    moreBtn.onclick = () => {
      const opening = extra.hidden;
      extra.hidden = !opening;
      moreBtn.textContent = opening
        ? "Show fewer signals"
        : `+ ${rest.length} more signal${rest.length === 1 ? "" : "s"}`;
    };
  } else {
    moreBtn.hidden = true;
    extra.hidden = true;
  }

  const ctaRow = $("#ctaRow");
  if ((tone === "danger" || tone === "critical") && !isManual && tab) {
    ctaRow.hidden = false;
    $("#ctaPrimary").onclick = () => {
      chrome.tabs.goBack(tab.id).catch(() => {
        chrome.tabs.update(tab.id, { url: "about:blank" }).catch(() => {});
      });
      window.close();
    };
    $("#ctaSecondary").onclick = () => window.close();
  } else {
    ctaRow.hidden = true;
  }
}

function escapeHtml(str) {
  return String(str ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function spawnParticles() {
  const host = $("#bgParticles");
  if (!host) return;
  const palette = ["#38f8e7", "#22d3ee", "#3b82f6", "#8b7bff"];
  const count = 34;
  for (let i = 0; i < count; i++) {
    const p = document.createElement("span");
    const left = Math.random() * 100;
    const duration = 5 + Math.random() * 9;
    const delay = Math.random() * 12;
    const size = 1.5 + Math.random() * 3.5;
    const color = palette[Math.floor(Math.random() * palette.length)];
    const drift = (Math.random() * 60 - 30).toFixed(0);
    p.style.left = `${left}%`;
    p.style.width = `${size}px`;
    p.style.height = `${size}px`;
    p.style.background = color;
    p.style.color = color;
    p.style.setProperty("--drift", `${drift}px`);
    p.style.animationDuration = `${duration}s`;
    p.style.animationDelay = `${delay}s`;
    host.appendChild(p);
  }
}

/**
 * Shows the "follow to keep scanning" modal. IMPORTANT (honesty): there is
 * no API that lets an extension verify a specific user follows a specific
 * Instagram account. This is intentionally a self-reported confirmation —
 * we require the user to actually click through to Instagram first (the
 * confirm button stays disabled until they do), but we never claim to have
 * cryptographically verified anything.
 */
function openInstagramGate(onUnlocked) {
  const modal = $("#igModal");
  if (!modal) { onUnlocked?.(); return; }
  const openLink = $("#igOpenLink");
  const confirmBtn = $("#igConfirmBtn");
  const closeBtn = $("#igClose");

  modal.hidden = false;
  confirmBtn.disabled = true;
  confirmBtn.textContent = "I've followed — Continue";

  function cleanup() {
    openLink.removeEventListener("click", onOpen);
    confirmBtn.removeEventListener("click", onConfirm);
    closeBtn.removeEventListener("click", onClose);
  }
  function onOpen() { confirmBtn.disabled = false; }
  async function onConfirm() {
    confirmBtn.disabled = true;
    confirmBtn.textContent = "Confirming…";
    try { await chrome.runtime.sendMessage({ type: "confirmInstagramFollow" }); } catch {}
    cleanup();
    modal.hidden = true;
    onUnlocked?.();
  }
  function onClose() { cleanup(); modal.hidden = true; }

  openLink.addEventListener("click", onOpen);
  confirmBtn.addEventListener("click", onConfirm);
  closeBtn.addEventListener("click", onClose);
}

/** Wires up the corner "Stop Scanning" toggle for the Automatic Scanner. */
async function initStopScanButton() {
  const btn = $("#stopScanBtn");
  if (!btn) return;

  function paint(enabled) {
    btn.dataset.state = enabled ? "on" : "off";
    btn.title = enabled ? "Automatic scanning is ON — click to stop" : "Automatic scanning is OFF — click to resume";
    btn.setAttribute("aria-pressed", String(!enabled));
    btn.querySelector(".stop-scan-label").textContent = enabled ? "Scanning" : "Stopped";
  }

  btn.addEventListener("click", async () => {
    const currentlyOn = btn.dataset.state !== "off";
    const res = await chrome.runtime.sendMessage({ type: "setAutoScanEnabled", enabled: !currentlyOn }).catch(() => null);
    paint(res ? res.enabled : currentlyOn);
  });

  const res = await chrome.runtime.sendMessage({ type: "getAutoScanEnabled" }).catch(() => ({ enabled: true }));
  paint(res ? res.enabled !== false : true);
}

