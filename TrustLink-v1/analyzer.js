/**
 * TrustLink — passive risk analyzer (coordinator)
 * ------------------------------------------------
 * Everything here is a PASSIVE, READ-ONLY check performed on data the
 * browser already has (the current tab's URL, and the response headers
 * from a single standard HEAD request to that same page). Nothing here
 * probes, floods, brute-forces, exploits, or actively scans a target.
 *
 * As of TrustLink V2, this file is a COORDINATOR, not where the detection
 * logic itself lives — every individual signal (punycode, homograph,
 * typosquatting, suspicious TLD, etc.) is its own module under
 * lib/heuristics/, each independently testable and independently
 * enable/disable-able via lib/remoteConfig.js. This file:
 *   1. Handles the two checks that have to happen before any detector can
 *      run at all (parse the URL; short-circuit local/private addresses).
 *   2. Runs the inline HTTPS check (not a "detector" — foundational).
 *   3. Delegates everything else to heuristics/index.js#runAll().
 *   4. Grades the combined score into TrustLink's ORIGINAL 3-tier model.
 *
 * IMPORTANT: grade()/THRESHOLDS below are unchanged from TrustLink v1 on
 * purpose. A confirmed threat-database match (OpenPhish, etc.) does NOT
 * change these thresholds or this function — it's a separate, 4th
 * "Critical" tier applied on top of this result by background.js, once the
 * local threat-database lookup (lib/threatDb.js) comes back. That keeps
 * "what does Use Caution vs High Risk mean" exactly as it always was for
 * every score this file ever produces.
 */
import { buildUrlContext, isPrivateHost } from "./lib/urlUtils.js";
import { runAll, runResponseChecks } from "./lib/heuristics/index.js";
import { buildDefaultConfig } from "./lib/heuristics/defaults.js";

export const THRESHOLDS = { caution: 30, high: 60 };

/**
 * Validates and clamps risk scores strictly to integers in the range [0, 100].
 * Non-finite, NaN, and negative values are handled safely.
 */
export function clampScore(score) {
  const num = typeof score === "number" ? score : Number(score);
  if (Number.isNaN(num) || !Number.isFinite(num)) return 0;
  return Math.max(0, Math.min(100, Math.round(num)));
}

/** Client-side checks over the URL itself — no network required. */
export function analyzeUrl(urlString, config = buildDefaultConfig()) {
  let url;
  try {
    url = new URL(urlString);
  } catch {
    return {
      score: 0,
      findings: [
        {
          id: "invalid-url",
          level: "medium",
          title: "Malformed URL",
          detail: "Could not parse this address as a valid standard web URL.",
        },
      ],
      safeToFetch: false,
      error: "Malformed address",
      confidence: "none",
    };
  }

  const ctx = buildUrlContext(url);
  const isLocal = isPrivateHost(ctx.host);

  if (isLocal) {
    return {
      score: 0,
      findings: [{ id: "local", level: "good", title: "Local / private address", detail: "This is a local or private-network address, not a public website." }],
      safeToFetch: false, host: ctx.host, isLocal: true,
      confidence: "heuristic",
    };
  }

  let score = 2; // baseline
  const findings = [];

  if (url.protocol !== "https:") {
    score += config.weights.detection_no_https_score;
    findings.push({
      id: "no-https", level: "high", title: "Not using HTTPS",
      detail: "Data sent to or from this page (including anything you type) is not encrypted in transit and could be intercepted.",
    });
  } else {
    findings.push({
      id: "https", level: "good", title: "Encrypted connection (HTTPS)",
      detail: "The connection to this page is encrypted, so casual eavesdropping on the network can't read it.",
    });
  }

  const detectorFindings = runAll(ctx, config);
  for (const f of detectorFindings) {
    score += f.score || 0;
  }

  // Combination bonus: brand or look-alike signals combined with untrusted infrastructure
  // (no HTTPS, raw IP, suspicious TLD, or credential keywords) are a hallmark of active phishing.
  const hasBrandOrLookalike = detectorFindings.some(
    (f) => f.id === "brand-impersonation" || f.id === "lookalike-domain" || f.id === "homograph"
  );
  const hasSuspiciousCompanion =
    url.protocol !== "https:" ||
    detectorFindings.some(
      (f) => f.id === "ip-literal" || f.id === "abused-tld" || f.id === "phishing-words"
    );

  if (hasBrandOrLookalike && hasSuspiciousCompanion) {
    score += 20;
    findings.push({
      id: "compound-phishing-signal",
      level: "high",
      title: "High-risk indicator combination",
      detail: "This site pairs brand or look-alike indicators with suspicious infrastructure signals (such as an abused TLD, sensitive keywords, raw IP, or lack of encryption). This combination strongly correlates with active phishing attacks.",
    });
  }

  findings.push(...detectorFindings.map(({ score: _s, ...rest }) => rest)); // don't leak internal per-finding score into the UI-facing object

  score = clampScore(score);

  return { score, findings, safeToFetch: true, host: ctx.host, isLocal: false, confidence: "heuristic" };
}

/** Header / transport checks that require one passive HEAD request. */
export function analyzeResponse(requestedUrl, response, config = buildDefaultConfig()) {
  const findings = [];
  let scoreDelta = 0;

  const redirectCheck = runResponseChecks(requestedUrl, response, config);
  scoreDelta += redirectCheck.scoreDelta;
  findings.push(...redirectCheck.findings);

  const finalUrl = new URL(response.url || requestedUrl);
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
  if (score == null || typeof score !== "number" || Number.isNaN(score) || !Number.isFinite(score)) {
    return {
      label: "Check Unavailable",
      tone: "warning",
      action: "Analysis could not produce a valid security score for this address. Exercise caution.",
    };
  }
  const clamped = clampScore(score);
  if (clamped >= THRESHOLDS.high) {
    return {
      label: "High Risk",
      tone: "danger",
      action: "Do not enter passwords, payment details, or download files from this page.",
    };
  }
  if (clamped >= THRESHOLDS.caution) {
    return {
      label: "Use Caution",
      tone: "warning",
      action: "Double-check the address bar and avoid entering sensitive information until you're sure this is the real site.",
    };
  }
  return {
    label: "Looks Safe",
    tone: "safe",
    action: "No strong warning signs were found by TrustLink's passive checks.",
  };
}

/**
 * Applies a confirmed local threat-database match on top of an already-
 * graded heuristic result. This is the ONLY way a "Critical" tone can be
 * produced — see the file header comment. Never call this speculatively;
 * only after lib/threatDb.js has returned matched: true.
 */
export function applyThreatMatch(baseResult, match) {
  const isDomain = match.type === "phishing_domain";
  const title = isDomain
    ? `Known phishing domain (${match.source})`
    : `Known ${match.type === "malware_url" ? "malware" : "phishing"} URL`;
  const detail = isDomain
    ? `TrustLink flagged this entire domain as associated with phishing in the ${match.source} threat database (last updated ${match.lastUpdated || "recently"}). Even though the path differs, the domain itself is a confirmed threat.`
    : `TrustLink found this exact address in the ${match.source} threat database (last updated ${match.lastUpdated || "recently"}). This is a confirmed match, not a heuristic guess.`;

  return {
    ...baseResult,
    score: 100,
    label: "Known Threat",
    tone: "critical",
    confidence: "verified",
    action: "Do not enter passwords, OTP codes, payment information, or other sensitive information. Go back.",
    findings: [
      {
        id: "known-threat-match",
        level: "high",
        title,
        detail,
      },
      ...baseResult.findings,
    ],
  };
}
