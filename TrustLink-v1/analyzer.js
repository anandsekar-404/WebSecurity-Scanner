/**
 * TrustLink — passive risk analyzer
 * ------------------------------------
 * Everything here is a PASSIVE, READ-ONLY check performed on data the
 * browser already has (the current tab's URL, and the response headers
 * from a single standard HEAD request to that same page). Nothing here
 * probes, floods, brute-forces, exploits, or actively scans a target.
 *
 * Score model: starts at 2 (baseline) and each signal adds weighted risk.
 * Final score is clamped to 0-100.
 *   0-29  -> Looks Safe
 *   30-59 -> Use Caution
 *   60-100-> High Risk
 */

export const THRESHOLDS = { caution: 30, high: 60 };

const PHISHING_TERMS = [
  "login", "signin", "verify", "verification", "secure", "security", "account",
  "wallet", "bonus", "gift", "invoice", "crypto", "banking", "password",
  "update", "confirm", "auth", "suspended", "unlock", "limited", "urgent",
  "recover", "billing", "support-center", "reset"
];

const TRUSTED_BRANDS = [
  "paypal.com", "google.com", "microsoft.com", "apple.com", "amazon.com",
  "netflix.com", "facebook.com", "instagram.com", "coinbase.com", "chase.com",
  "wellsfargo.com", "bankofamerica.com", "dropbox.com", "linkedin.com",
  "github.com", "outlook.com", "office.com", "icloud.com"
];

const ABUSED_TLDS = new Set([
  "zip", "mov", "top", "xyz", "click", "link", "gq", "cf", "tk", "ml", "ga",
  "work", "support", "country", "stream", "gdn", "kim", "loan", "men", "date",
  "review", "party", "science", "download", "racing"
]);

const REDIRECT_PARAM_NAMES = ["url", "redirect", "redir", "next", "continue", "returnurl", "return_to", "dest", "destination", "target"];

function levenshtein(a, b) {
  const m = a.length, n = b.length;
  const dp = Array.from({ length: m + 1 }, (_, i) => [i, ...Array(n).fill(0)]);
  for (let j = 0; j <= n; j++) dp[0][j] = j;
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      dp[i][j] = a[i - 1] === b[j - 1]
        ? dp[i - 1][j - 1]
        : 1 + Math.min(dp[i - 1][j - 1], dp[i - 1][j], dp[i][j - 1]);
    }
  }
  return dp[m][n];
}

function isIpLiteral(host) {
  const ipv4 = /^(\d{1,3}\.){3}\d{1,3}$/;
  const ipv6 = /^\[[0-9a-f:]+\]$/i;
  return ipv4.test(host) || ipv6.test(host);
}

function isPrivateHost(host) {
  return host === "localhost" || /^127\./.test(host) || /^10\./.test(host) ||
    /^192\.168\./.test(host) || /^172\.(1[6-9]|2\d|3[0-1])\./.test(host);
}

function registrableDomain(host) {
  const parts = host.split(".");
  return parts.length <= 2 ? host : parts.slice(-2).join(".");
}

/** Client-side checks over the URL itself — no network required. */
export function analyzeUrl(urlString) {
  const findings = [];
  let score = 2;
  let url;
  try {
    url = new URL(urlString);
  } catch {
    return { score: 0, findings: [], safeToFetch: false };
  }

  const host = url.hostname.toLowerCase();
  const path = `${url.pathname}${url.search}`.toLowerCase();
  const full = `${host}${path}`;
  const labels = host.split(".");
  const tld = labels[labels.length - 1];
  const isLocal = isPrivateHost(host);

  // --- Transport ---------------------------------------------------
  if (url.protocol !== "https:" && !isLocal) {
    score += 26;
    findings.push({
      id: "no-https", level: "high", title: "Not using HTTPS",
      detail: "Data sent to or from this page (including anything you type) is not encrypted in transit and could be intercepted."
    });
  } else if (url.protocol === "https:") {
    findings.push({
      id: "https", level: "good", title: "Encrypted connection (HTTPS)",
      detail: "The connection to this page is encrypted, so casual eavesdropping on the network can't read it."
    });
  }

  if (isLocal) {
    return {
      score: 0,
      findings: [{ id: "local", level: "good", title: "Local / private address", detail: "This is a local or private-network address, not a public website." }],
      safeToFetch: false, host, isLocal: true
    };
  }

  // --- Structural red flags -----------------------------------------
  if (host.includes("xn--")) {
    score += 30;
    findings.push({
      id: "punycode", level: "high", title: "Encoded (punycode) domain",
      detail: "This domain uses punycode, a way to register lookalike characters (e.g. a Cyrillic “а” instead of “a”) that can visually impersonate a trusted name."
    });
  }

  if (url.username || full.includes("@")) {
    score += 34;
    findings.push({
      id: "userinfo", level: "high", title: "Misleading @ URL structure",
      detail: "This address embeds text before an “@” symbol — a classic trick to make a malicious domain look like it belongs to a trusted site."
    });
  }

  if (isIpLiteral(host)) {
    score += 22;
    findings.push({
      id: "ip-literal", level: "high", title: "Raw IP address instead of a domain",
      detail: "Legitimate sites almost always use a named domain. A bare IP address is a common trait of throwaway phishing or malware infrastructure."
    });
  }

  if (url.port && !["80", "443", ""].includes(url.port)) {
    score += 8;
    findings.push({
      id: "nonstandard-port", level: "medium", title: "Non-standard port",
      detail: `This site is served on port ${url.port} instead of the standard web ports. Not dangerous by itself, but unusual for consumer-facing sites.`
    });
  }

  if (labels.length >= 5) {
    score += 12;
    findings.push({
      id: "deep-subdomain", level: "medium", title: "Unusually deep subdomain chain",
      detail: `“${host}” has ${labels.length} parts. Long subdomain chains are sometimes used to bury the real domain (the last two labels) out of view.`
    });
  }

  if (host.split("-").length - 1 >= 3) {
    score += 12;
    findings.push({
      id: "hyphenated", level: "medium", title: "Heavily hyphenated domain",
      detail: "Multiple hyphens in a domain name are common in disposable, auto-generated, or look-alike domains."
    });
  }

  if (host.length > 40) {
    score += 6;
    findings.push({
      id: "long-host", level: "low", title: "Very long domain name",
      detail: "Unusually long domain names can be used to push the real brand name off-screen in a browser's address bar on small devices."
    });
  }

  if (ABUSED_TLDS.has(tld)) {
    score += 10;
    findings.push({
      id: "abused-tld", level: "medium", title: `Frequently abused top-level domain (.${tld})`,
      detail: `The .${tld} extension is inexpensive and commonly used for short-lived phishing or spam campaigns. It doesn't mean this site is malicious, just worth extra caution.`
    });
  }

  const matchedTerms = PHISHING_TERMS.filter((t) => full.includes(t));
  if (matchedTerms.length >= 2) {
    score += 16;
    findings.push({
      id: "phishing-words", level: "medium", title: "Sensitive-action wording in the address",
      detail: `The URL contains terms often paired with credential or payment phishing: ${matchedTerms.slice(0, 4).join(", ")}.`
    });
  }

  // --- Brand impersonation / look-alike domains ----------------------
  const reg = registrableDomain(host);
  let impersonationFlagged = false;
  for (const brand of TRUSTED_BRANDS) {
    const brandName = brand.split(".")[0];
    if (reg === brand) continue; // it IS the real brand domain
    if (host.includes(brandName) && reg !== brand) {
      score += 28;
      findings.push({
        id: "brand-impersonation", level: "high", title: "Possible brand impersonation",
        detail: `The address references “${brandName}” but the actual domain is “${reg}”, not “${brand}”. Legitimate ${brandName} pages only live on their real domain.`
      });
      impersonationFlagged = true;
      break;
    }
  }
  if (!impersonationFlagged) {
    for (const brand of TRUSTED_BRANDS) {
      if (reg === brand) continue;
      const dist = levenshtein(reg, brand);
      if (dist > 0 && dist <= 2 && Math.abs(reg.length - brand.length) <= 3) {
        score += 30;
        findings.push({
          id: "lookalike-domain", level: "high", title: "Look-alike domain detected",
          detail: `“${reg}” is only ${dist} character${dist > 1 ? "s" : ""} different from the well-known domain “${brand}” — a common typosquatting pattern.`
        });
        break;
      }
    }
  }

  // --- Open-redirect style query parameters --------------------------
  for (const [key, value] of url.searchParams) {
    if (REDIRECT_PARAM_NAMES.includes(key.toLowerCase()) && /^https?:\/\//i.test(value)) {
      try {
        const dest = new URL(value);
        if (registrableDomain(dest.hostname.toLowerCase()) !== reg) {
          score += 14;
          findings.push({
            id: "redirect-param", level: "medium", title: "Off-site redirect parameter",
            detail: `The link's “${key}” parameter points to a different site (${dest.hostname}). Redirect parameters like this are sometimes used to disguise the true destination.`
          });
        }
      } catch { /* ignore malformed value */ }
    }
  }

  // --- Dangerous schemes handled elsewhere; encoded payload check ----
  if (/%[0-9a-f]{2}.*%[0-9a-f]{2}.*%[0-9a-f]{2}/i.test(path)) {
    score += 6;
    findings.push({
      id: "heavy-encoding", level: "low", title: "Heavily percent-encoded address",
      detail: "This URL contains several encoded characters, which can be used to obscure what a link actually points to."
    });
  }

  return { score, findings, safeToFetch: true, host, isLocal: false };
}

/** Header / transport checks that require one passive HEAD request. */
export function analyzeResponse(requestedUrl, response) {
  const findings = [];
  let scoreDelta = 0;

  const finalUrl = new URL(response.url || requestedUrl);
  const requested = new URL(requestedUrl);

  if (response.redirected && registrableDomain(finalUrl.hostname) !== registrableDomain(requested.hostname)) {
    scoreDelta += 18;
    findings.push({
      id: "cross-domain-redirect", level: "medium", title: "Redirected to a different domain",
      detail: `This link led to “${finalUrl.hostname}” instead of “${requested.hostname}”. Cross-domain redirects are sometimes used to send you somewhere unexpected after a first, trustworthy-looking click.`
    });
  }
  if (response.redirected && requested.protocol === "https:" && finalUrl.protocol !== "https:") {
    scoreDelta += 24;
    findings.push({
      id: "https-downgrade", level: "high", title: "Redirected away from HTTPS",
      detail: "The site redirected you from a secure connection to an insecure one. That's very unusual for a legitimate site."
    });
  }

  const h = (name) => response.headers.get(name);

  if (finalUrl.protocol === "https:") {
    if (h("strict-transport-security")) {
      findings.push({ id: "hsts", level: "good", title: "HSTS enabled", detail: "The site tells browsers to only ever load it over HTTPS, which helps prevent downgrade attacks." });
    } else {
      scoreDelta += 5;
      findings.push({ id: "no-hsts", level: "low", title: "HSTS not detected", detail: "No Strict-Transport-Security header was seen. Not dangerous alone, but it's a good hardening signal most well-run sites enable." });
    }
  }

  const csp = h("content-security-policy");
  if (csp) {
    findings.push({ id: "csp", level: "good", title: "Content Security Policy present", detail: "A CSP restricts what scripts and resources a page can load, reducing the impact of certain injection attacks." });
  } else {
    scoreDelta += 4;
    findings.push({ id: "no-csp", level: "low", title: "No Content Security Policy detected", detail: "Without a CSP header, the site has fewer built-in protections against malicious script injection." });
  }

  const xfo = h("x-frame-options");
  const frameAncestors = csp && /frame-ancestors/i.test(csp);
  if (xfo || frameAncestors) {
    findings.push({ id: "clickjacking", level: "good", title: "Clickjacking protection present", detail: "The site blocks itself from being embedded in a hidden frame on another page — a common clickjacking technique." });
  } else {
    scoreDelta += 5;
    findings.push({ id: "no-clickjacking", level: "low", title: "No clickjacking protection detected", detail: "Neither X-Frame-Options nor a CSP frame-ancestors rule was found, so this page could potentially be embedded invisibly on another site." });
  }

  if (h("x-content-type-options") === "nosniff") {
    findings.push({ id: "xcto", level: "good", title: "MIME-sniffing protection present", detail: "The browser is told not to guess file types, which helps prevent some file-based attacks." });
  } else {
    scoreDelta += 3;
    findings.push({ id: "no-xcto", level: "low", title: "MIME-sniffing protection not detected", detail: "Without X-Content-Type-Options: nosniff, browsers may misinterpret file types in edge cases." });
  }

  if (h("referrer-policy")) {
    findings.push({ id: "referrer-policy", level: "good", title: "Referrer-Policy configured", detail: "The site controls how much of its URL is leaked to other sites when you click outbound links." });
  }

  if (h("permissions-policy") || h("feature-policy")) {
    findings.push({ id: "permissions-policy", level: "good", title: "Permissions-Policy configured", detail: "The site explicitly restricts access to sensitive browser features like camera, microphone, and location." });
  }

  return { scoreDelta, findings };
}

export function grade(score) {
  if (score >= THRESHOLDS.high) {
    return {
      label: "High Risk", tone: "danger",
      action: "Do not enter passwords, payment details, or download files from this page."
    };
  }
  if (score >= THRESHOLDS.caution) {
    return {
      label: "Use Caution", tone: "warning",
      action: "Double-check the address bar and avoid entering sensitive information until you're sure this is the real site."
    };
  }
  return {
    label: "Looks Safe", tone: "safe",
    action: "No strong warning signs were found by TrustLink's passive checks."
  };
}
