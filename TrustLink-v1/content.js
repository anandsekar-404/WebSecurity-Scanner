(() => {
  if (window.top !== window) return; // only the top frame, never inside iframes

  let lastScanResult = null;

  function getRegistrableDomain(host) {
    if (!host) return "";
    const clean = host.toLowerCase().replace(/^\[|\]$/g, "");
    const parts = clean.split(".");
    if (parts.length <= 2) return clean;
    const secondLast = parts[parts.length - 2];
    if (["co", "com", "org", "net", "gov", "edu", "ac"].includes(secondLast) && parts.length >= 3) {
      return parts.slice(-3).join(".");
    }
    return parts.slice(-2).join(".");
  }

  function checkCredentialGuard(scanResult) {
    if (!scanResult) return;
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
            const currentReg = getRegistrableDomain(location.hostname);
            const targetReg = getRegistrableDomain(targetUrl.hostname);
            if (targetReg && currentReg && targetReg !== currentReg) {
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

    // Check 2: Password field on a page that scores warning or higher (score >= 30)
    if (scanResult.score >= 30 || scanResult.tone === "warning" || scanResult.tone === "danger" || scanResult.tone === "critical") {
      const findings = [
        {
          id: "credential-field-risk",
          level: "high",
          title: "Password field on suspicious site",
          detail: `This site shows risk signals (score: ${scanResult.score}/100) and contains a password field. Review the risk signals before typing any credentials.`,
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
    if (e.target && e.target.type === "password") {
      checkCredentialGuard(lastScanResult);
    }
  }, true);

  const observer = new MutationObserver(() => {
    if (lastScanResult && document.querySelector('input[type="password"]')) {
      checkCredentialGuard(lastScanResult);
    }
  });
  if (document.body) {
    observer.observe(document.body, { childList: true, subtree: true });
  } else {
    document.addEventListener("DOMContentLoaded", () => {
      if (document.body) observer.observe(document.body, { childList: true, subtree: true });
    });
  }

  function injectBanner(result) {
    const existing = document.getElementById("trustlink-warning");
    if (existing) existing.remove();

    const host = document.createElement("div");
    host.id = "trustlink-warning";
    // all: "initial" MUST be applied FIRST so layout properties are not wiped
    Object.assign(host.style, {
      all: "initial",
      position: "fixed",
      top: "16px",
      right: "16px",
      zIndex: "2147483647",
      display: "block",
    });

    const root = host.attachShadow({ mode: "closed" });
    const wrap = document.createElement("div");
    wrap.innerHTML = `
      <style>
        :host { all: initial; }
        .card {
          font-family: -apple-system, "Segoe UI", Inter, system-ui, sans-serif;
          width: min(360px, calc(100vw - 32px));
          background: linear-gradient(150deg, #2b0812, #150308 65%);
          border: 1px solid rgba(255, 90, 120, 0.7);
          box-shadow: 0 20px 50px rgba(180, 10, 40, 0.35), 0 0 0 1px rgba(0,0,0,0.4);
          border-radius: 14px;
          color: #ffe9ee;
          padding: 16px 16px 14px;
          animation: tl-in 220ms ease-out, tl-neon-pulse 2.2s ease-in-out 220ms infinite;
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
        .dismiss-btn { background: transparent; color: #ffb7c3; border-color: rgba(255,120,140,0.35); margin-left: auto; }
        .score { font-variant-numeric: tabular-nums; color: #ff8fa3; font-weight: 800; }
      </style>
      <div class="card" role="alert">
        <div class="row">
          <div class="badge">${result.tone === "critical" ? "⛔" : "⚠"}</div>
          <div>
            <p class="title">TrustLink — ${escapeHtml(result.label)} (<span class="score">${result.score}</span>/100)</p>
            <p class="sub">${escapeHtml(result.domain || "")}</p>
          </div>
        </div>
        <p class="msg">${escapeHtml(result.action)}</p>
        <div class="actions">
          <button class="details-btn" type="button">See signals</button>
          <button class="dismiss-btn" type="button">Dismiss</button>
        </div>
      </div>
    `;
    root.appendChild(wrap);
    document.documentElement.appendChild(host);

    root.querySelector(".dismiss-btn").addEventListener("click", () => host.remove());
    root.querySelector(".details-btn").addEventListener("click", () => {
      alert(
        "TrustLink found:\n\n" +
        result.findings
          .filter((f) => f.level === "high" || f.level === "medium")
          .slice(0, 6)
          .map((f) => `• ${f.title}`)
          .join("\n")
      );
    });
  }

  function escapeHtml(str) {
    const div = document.createElement("div");
    div.textContent = str ?? "";
    return div.innerHTML;
  }
})();
