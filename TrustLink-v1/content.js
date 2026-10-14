(() => {
  if (window.top !== window) return; // only the top frame, never inside iframes

  let lastScanResult = null;
  let dismissed = false;
  let observerFired = false;
  let debounceTimer = null;

  const MULTI = new Set([
    "co.uk", "org.uk", "me.uk", "ltd.uk", "plc.uk", "net.uk", "sch.uk", "ac.uk", "gov.uk",
    "co.in", "net.in", "org.in", "gen.in", "firm.in", "ind.in", "nic.in", "ac.in", "edu.in", "res.in", "gov.in", "mil.in",
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "asn.au", "id.au",
    "co.jp", "ne.jp", "or.jp", "ac.jp", "ed.jp", "go.jp", "gr.jp", "lg.jp",
    "com.br", "net.br", "org.br", "gov.br", "edu.br",
    "co.nz", "net.nz", "org.nz", "govt.nz", "ac.nz",
    "co.za", "net.za", "org.za", "gov.za", "ac.za",
    "com.sg", "net.sg", "org.sg", "gov.sg", "edu.sg",
    "com.mx", "org.mx", "gob.mx", "edu.mx",
    "co.kr", "ne.kr", "or.kr", "re.kr", "pe.kr", "go.kr", "mil.kr", "ac.kr",
    "com.tr", "net.tr", "org.tr", "gov.tr", "edu.tr",
    "com.tw", "net.tw", "org.tw", "gov.tw", "edu.tw",
    "com.hk", "net.hk", "org.hk", "gov.hk", "edu.hk",
    "com.my", "net.my", "org.my", "gov.my", "edu.my",
    "com.ar", "net.ar", "org.ar", "gob.ar", "edu.ar",
    "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn",
    "com.co", "net.co", "org.co", "gov.co", "edu.co",
    "com.ng", "net.ng", "org.ng", "gov.ng", "edu.ng",
    "com.pk", "net.pk", "org.pk", "gov.pk", "edu.pk",
  ]);

  function registrableDomain(host) {
    if (!host) return "";
    const clean = host.replace(/^\[|\]$/g, "").trim().toLowerCase();
    const p = clean.split(".");
    if (p.length >= 3 && MULTI.has(p.slice(-2).join("."))) return p.slice(-3).join(".");
    return p.length <= 2 ? clean : p.slice(-2).join(".");
  }

  const KNOWN_IDPS = new Set([
    "accounts.google.com",
    "login.microsoftonline.com",
    "appleid.apple.com",
    "auth0.com",
    "okta.com",
    "onelogin.com",
    "id.atlassian.com",
    "github.com",
    "facebook.com",
    "amazon.com",
    "auth.pingidentity.com",
  ]);

  function checkCredentialGuard(scanResult) {
    if (!scanResult || dismissed) return;
    const passwordInputs = Array.from(document.querySelectorAll('input[type="password"]'));
    if (passwordInputs.length === 0) return;

    // Check 1: Form submitting password to a different registrable domain
    for (const input of passwordInputs) {
      const form = input.closest("form");
      if (form) {
        const action = form.getAttribute("action");
        if (action) {
          try {
            const targetUrl = new URL(action, location.href);
            if (targetUrl.protocol !== "http:" && targetUrl.protocol !== "https:") continue;
            const currentReg = registrableDomain(location.hostname);
            const targetReg = registrableDomain(targetUrl.hostname);
            if (targetReg && currentReg && targetReg !== currentReg) {
              const isKnownIdp =
                KNOWN_IDPS.has(targetUrl.hostname) ||
                Array.from(KNOWN_IDPS).some((idp) => targetUrl.hostname.endsWith(`.${idp}`));

              if (isKnownIdp) {
                injectBanner({
                  tone: "warning",
                  label: "External Identity Provider",
                  score: Math.min(Math.max(scanResult.score || 0, 35), 45),
                  domain: location.hostname,
                  action: `This login form submits credentials to a recognized identity provider (${targetUrl.hostname}). Verify that you intended to sign in with this third-party provider.`,
                  findings: [
                    {
                      id: "external-idp-form",
                      level: "medium",
                      title: "Form submits to external identity provider",
                      detail: `This page posts login credentials to ${targetUrl.hostname}. This is common for federated single sign-on (SSO), but verify the site's legitimacy.`,
                    },
                    ...(scanResult.findings || []),
                  ],
                });
                return;
              }

              const findings = [
                {
                  id: "cross-domain-credential-form",
                  level: "high",
                  title: "Password form submits to different domain",
                  detail: `This login form submits credentials to "${targetUrl.hostname}", which is outside "${location.hostname}". This is a common phishing harvest technique.`,
                },
                ...(scanResult.findings || []),
              ];
              injectBanner({
                tone: "danger",
                label: "Off-Site Credential Form",
                score: Math.max(scanResult.score || 0, 80),
                domain: location.hostname,
                action: `Do not enter passwords. This form sends credentials to an external domain (${targetUrl.hostname}).`,
                findings,
              });
              return;
            }
          } catch {}
        }
      }
    }

    // Check 2: Password field on a page that is danger (score >= 60) or critical
    if (scanResult.score >= 60 || scanResult.tone === "danger" || scanResult.tone === "critical") {
      const findings = [
        {
          id: "credential-field-risk",
          level: "high",
          title: "Password field on suspicious site",
          detail: `This site shows high risk signals (score: ${scanResult.score}/100) and contains a password field. Review the risk signals before typing any credentials.`,
        },
        ...(scanResult.findings || []),
      ];
      injectBanner({
        tone: scanResult.tone === "critical" ? "critical" : "danger",
        label: scanResult.label === "Looks Safe" ? "Suspicious Login Form" : scanResult.label,
        score: scanResult.score,
        domain: scanResult.domain || location.hostname,
        action: "Do not enter passwords on this page. Review the risk signals before continuing.",
        findings,
      });
    }
  }

  // This is the Automatic Scanner: it runs on every page load, independent
  // of Manual Page Scan's gating, and is skipped entirely while the user
  // has paused it via the "Stop Scanning" control.
  chrome.runtime.sendMessage({ type: "inspect", url: location.href, updateBadge: true, isAutomatic: true }).then((result) => {
    if (!result || result.error || result.stopped) return;
    lastScanResult = result;

    if (result.tone === "danger" || result.tone === "critical") {
      injectBanner(result);
    }

    checkCredentialGuard(result);
  }).catch(() => {});

  document.addEventListener("focusin", (e) => {
    if (dismissed) return;
    if (e.target && e.target.type === "password") {
      checkCredentialGuard(lastScanResult);
    }
  }, true);

  const observer = new MutationObserver(() => {
    if (dismissed || observerFired) return;
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(() => {
      if (dismissed || observerFired) return;
      if (lastScanResult && document.querySelector('input[type="password"]')) {
        observerFired = true;
        observer.disconnect();
        checkCredentialGuard(lastScanResult);
      }
    }, 200);
  });

  if (document.body) {
    observer.observe(document.body, { childList: true, subtree: true });
  } else {
    document.addEventListener("DOMContentLoaded", () => {
      if (document.body && !observerFired && !dismissed) {
        observer.observe(document.body, { childList: true, subtree: true });
      }
    });
  }

  const BANNER_STYLES = `
    :host { all: initial; }
    .card {
      font-family: -apple-system, "Segoe UI", Inter, system-ui, sans-serif;
      width: min(380px, calc(100vw - 32px));
      background: linear-gradient(150deg, #2b0812, #150308 65%);
      border: 1px solid rgba(255, 90, 120, 0.7);
      box-shadow: 0 20px 50px rgba(180, 10, 40, 0.35), 0 0 0 1px rgba(0,0,0,0.4);
      border-radius: 14px;
      color: #ffe9ee;
      padding: 16px 16px 14px;
      animation: tl-in 220ms ease-out, tl-neon-pulse 2.2s ease-in-out 220ms infinite;
      box-sizing: border-box;
    }
    @keyframes tl-in { from { opacity: 0; transform: translateY(-8px); } to { opacity: 1; transform: translateY(0); } }
    @keyframes tl-neon-pulse {
      0%, 100% {
        box-shadow: 0 20px 50px rgba(180, 10, 40, 0.35), 0 0 10px rgba(255, 68, 100, 0.35), 0 0 0 1px rgba(255,90,120,0.25) inset;
        border-color: rgba(255, 90, 120, 0.65);
      }
      50% {
        box-shadow: 0 20px 50px rgba(180, 10, 40, 0.35), 0 0 26px rgba(255, 68, 100, 0.85), 0 0 46px rgba(255, 68, 100, 0.4), 0 0 0 1px rgba(255,90,120,0.5) inset;
        border-color: rgba(255, 130, 155, 1);
      }
    }
    .row { display: flex; align-items: flex-start; gap: 10px; }
    .badge {
      flex: 0 0 auto; width: 30px; height: 30px; border-radius: 8px;
      display: flex; align-items: center; justify-content: center;
      background: rgba(255, 68, 100, 0.18); border: 1px solid rgba(255,120,140,0.5);
      font-size: 16px; color: #ff8fa3;
      text-shadow: 0 0 8px rgba(255,143,163,0.9);
    }
    .title { font-size: 13px; font-weight: 700; letter-spacing: 0.2px; color: #fff; margin: 0; }
    .sub { font-size: 11px; color: #ffb7c3; margin: 2px 0 0; letter-spacing: 0.4px; text-transform: uppercase; }
    .msg { font-size: 12.5px; line-height: 1.5; color: #ffd7de; margin: 10px 0 12px; }
    .actions { display: flex; gap: 8px; }
    button {
      font: inherit; font-size: 11.5px; font-weight: 600; cursor: pointer;
      border-radius: 8px; padding: 7px 11px; border: 1px solid transparent;
    }
    .details-btn { background: rgba(255,255,255,0.08); color: #ffe9ee; border-color: rgba(255,255,255,0.16); }
    .details-btn:hover { background: rgba(255,255,255,0.14); }
    .dismiss-btn { background: transparent; color: #ffb7c3; border-color: rgba(255,120,140,0.35); margin-left: auto; }
    .dismiss-btn:hover { background: rgba(255,120,140,0.12); }
    .score { font-variant-numeric: tabular-nums; color: #ff8fa3; font-weight: 800; }
    .signals-panel {
      margin-top: 12px;
      padding: 10px 12px;
      background: rgba(10, 2, 5, 0.7);
      border: 1px solid rgba(255, 90, 120, 0.3);
      border-radius: 8px;
      max-height: 200px;
      overflow-y: auto;
    }
    .signals-title {
      font-weight: 700;
      color: #ffb7c3;
      margin-bottom: 8px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      font-size: 10px;
    }
    .signals-list {
      list-style: none;
      margin: 0;
      padding: 0;
      display: flex;
      flex-direction: column;
      gap: 8px;
    }
    .signals-item { line-height: 1.35; color: #ffd7de; font-size: 11px; }
    .signals-item-title { font-weight: 600; color: #fff; }
    .signals-item-detail { color: #ffc4cf; font-size: 10.5px; margin-top: 2px; }
  `;

  function injectBanner(result) {
    if (dismissed) return;
    const existing = document.getElementById("trustlink-warning");
    if (existing) existing.remove();

    const host = document.createElement("div");
    host.id = "trustlink-warning";
    Object.assign(host.style, {
      all: "initial",
      position: "fixed",
      top: "16px",
      right: "16px",
      zIndex: "2147483647",
      display: "block",
    });

    const root = host.attachShadow({ mode: "closed" });

    const styleEl = document.createElement("style");
    styleEl.textContent = BANNER_STYLES;
    root.appendChild(styleEl);

    const card = document.createElement("div");
    card.className = "card";
    card.setAttribute("role", "alert");

    const row = document.createElement("div");
    row.className = "row";

    const badge = document.createElement("div");
    badge.className = "badge";
    badge.textContent = result.tone === "critical" ? "⛔" : "⚠";

    const titleWrap = document.createElement("div");
    const titleP = document.createElement("p");
    titleP.className = "title";
    titleP.textContent = `TrustLink — ${result.label || "Warning"} (`;
    const scoreSpan = document.createElement("span");
    scoreSpan.className = "score";
    scoreSpan.textContent = String(result.score ?? 0);
    titleP.appendChild(scoreSpan);
    titleP.appendChild(document.createTextNode("/100)"));

    const subP = document.createElement("p");
    subP.className = "sub";
    subP.textContent = result.domain || "";

    titleWrap.appendChild(titleP);
    titleWrap.appendChild(subP);
    row.appendChild(badge);
    row.appendChild(titleWrap);
    card.appendChild(row);

    const msgP = document.createElement("p");
    msgP.className = "msg";
    msgP.textContent = result.action || "";
    card.appendChild(msgP);

    const actions = document.createElement("div");
    actions.className = "actions";

    const detailsBtn = document.createElement("button");
    detailsBtn.className = "details-btn";
    detailsBtn.type = "button";
    detailsBtn.textContent = "See signals";

    const dismissBtn = document.createElement("button");
    dismissBtn.className = "dismiss-btn";
    dismissBtn.type = "button";
    dismissBtn.textContent = "Dismiss";

    actions.appendChild(detailsBtn);
    actions.appendChild(dismissBtn);
    card.appendChild(actions);

    const signalsPanel = document.createElement("div");
    signalsPanel.className = "signals-panel";
    signalsPanel.hidden = true;

    const signalsTitle = document.createElement("div");
    signalsTitle.className = "signals-title";
    signalsTitle.textContent = "Detected Signals";
    signalsPanel.appendChild(signalsTitle);

    const signalsList = document.createElement("ul");
    signalsList.className = "signals-list";

    const highMediumFindings = (result.findings || [])
      .filter((f) => f.level === "high" || f.level === "medium")
      .slice(0, 6);

    if (highMediumFindings.length > 0) {
      for (const f of highMediumFindings) {
        const li = document.createElement("li");
        li.className = "signals-item";
        const titleSpan = document.createElement("span");
        titleSpan.className = "signals-item-title";
        titleSpan.textContent = `• ${f.title || ""}`;
        const detailDiv = document.createElement("div");
        detailDiv.className = "signals-item-detail";
        detailDiv.textContent = f.detail || "";
        li.appendChild(titleSpan);
        li.appendChild(detailDiv);
        signalsList.appendChild(li);
      }
    } else {
      const li = document.createElement("li");
      li.className = "signals-item";
      li.textContent = "General suspicious signals detected.";
      signalsList.appendChild(li);
    }

    signalsPanel.appendChild(signalsList);
    card.appendChild(signalsPanel);

    root.appendChild(card);
    document.documentElement.appendChild(host);

    dismissBtn.addEventListener("click", () => {
      dismissed = true;
      host.remove();
    });

    detailsBtn.addEventListener("click", () => {
      const isHidden = signalsPanel.hidden;
      signalsPanel.hidden = !isHidden;
      detailsBtn.textContent = isHidden ? "Hide signals" : "See signals";
    });
  }

  function escapeHtml(str) {
    return String(str ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }
})();
