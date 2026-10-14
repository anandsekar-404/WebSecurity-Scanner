// lib/heuristics/index.js
//
// The detector registry. analyzer.js calls runAll(ctx, config) once per URL
// and gets back every finding every enabled detector produced — analyzer.js
// itself no longer contains any per-signal logic, just orchestration
// (baseline score, HTTPS/local-host short-circuits, and combining this
// output with the threat-database result upstream in background.js).
//
// Each entry decides for itself whether it's "on" by checking BOTH:
//   - config.features[configFlag]  (a normal remote feature flag)
//   - config.protection[emergencyDisableKey]  (spec section 10's individual
//     emergency kill-switches, e.g. disable_homograph)
//   - config.protection.protection_emergency_enabled overriding nothing by
//     itself — per spec section 52, the emergency master switch must never
//     be able to silently disable ALL protection; it only gates whatever
//     individual disable_* switches are set, same as if it were absent.

import * as ipUrl from "./ipUrl.js";
import * as punycode from "./punycode.js";
import * as homograph from "./homograph.js";
import * as typosquatting from "./typosquatting.js";
import * as brandImpersonation from "./brandImpersonation.js";
import * as suspiciousTld from "./suspiciousTld.js";
import * as suspiciousKeywords from "./suspiciousKeywords.js";
import * as suspiciousSubdomain from "./suspiciousSubdomain.js";
import * as redirect from "./redirect.js";
import * as urlObfuscation from "./urlObfuscation.js";

const EMERGENCY_DISABLE_KEY = {
  openphish: "disable_openphish",
  phishtank: "disable_phishtank",
  homograph: "disable_homograph",
  typosquatting: "disable_typosquatting",
  redirect: "disable_redirect",
  page_analysis: "disable_page_analysis",
};

function isEnabled(config, configFlag, emergencyKey) {
  if (configFlag && config.features[configFlag] === false) return false;
  if (emergencyKey && config.protection[emergencyKey] === true) return false;
  return true;
}

/** URL-only detectors — no network required. Mirrors what lib/blocking.js can run pre-navigation. */
export function runAll(ctx, config) {
  const findings = [];
  const w = config.weights;

  if (isEnabled(config, ipUrl.configFlag)) {
    const f = ipUrl.detect(ctx, w.detection_ip_url_score);
    if (f) findings.push(f);
  }
  if (isEnabled(config, punycode.configFlag, EMERGENCY_DISABLE_KEY.homograph)) {
    const f = punycode.detect(ctx, w.detection_punycode_score);
    if (f) findings.push(f);
  }
  if (isEnabled(config, homograph.configFlag, EMERGENCY_DISABLE_KEY.homograph)) {
    const f = homograph.detect(ctx, w.detection_homograph_score);
    if (f) findings.push(f);
  }
  if (isEnabled(config, typosquatting.configFlag, EMERGENCY_DISABLE_KEY.typosquatting)) {
    const f = typosquatting.detect(ctx, w.detection_typosquatting_score, config.lists.protectedBrands);
    if (f) findings.push(f);
  }
  // Brand impersonation and typosquatting are mutually exclusive in the
  // original design (impersonation is checked first; the edit-distance
  // check only runs if impersonation didn't already fire) to avoid
  // double-counting the same domain under two different findings.
  let impersonationFound = false;
  if (isEnabled(config, brandImpersonation.configFlag)) {
    const f = brandImpersonation.detect(
      ctx,
      w.detection_brand_impersonation_score,
      config.lists.protectedBrands,
      new Set(config.lists.suspiciousTlds),
      config.lists.suspiciousKeywords
    );
    if (f) { findings.push(f); impersonationFound = true; }
  }
  if (impersonationFound) {
    const idx = findings.findIndex((f) => f.id === "lookalike-domain");
    if (idx !== -1) findings.splice(idx, 1);
  }
  if (isEnabled(config, suspiciousTld.configFlag)) {
    const f = suspiciousTld.detect(ctx, w.detection_suspicious_tld_score, new Set(config.lists.suspiciousTlds));
    if (f) findings.push(f);
  }
  {
    const f = suspiciousKeywords.detect(ctx, w.detection_suspicious_keyword_score, config.lists.suspiciousKeywords);
    if (f) findings.push(f);
  }
  {
    const f = suspiciousSubdomain.detect(ctx, w.detection_excessive_subdomain_score);
    if (f) findings.push(f);
  }
  if (isEnabled(config, redirect.configFlag, EMERGENCY_DISABLE_KEY.redirect)) {
    const f = redirect.detectParam(ctx, w.detection_redirect_score, config.lists.redirectParamNames);
    if (f) findings.push(f);
  }
  if (isEnabled(config, urlObfuscation.configFlag)) {
    findings.push(...urlObfuscation.detect(ctx, {
      userinfo: w.detection_userinfo_score,
      nonstandardPort: w.detection_nonstandard_port_score,
      hyphenated: w.detection_hyphenated_domain_score,
      longHost: w.detection_long_url_score,
      heavyEncoding: w.detection_encoded_url_score,
    }));
  }

  return findings;
}

/** Header/response-based checks — needs the one passive HEAD request. Called separately from runAll(). */
export function runResponseChecks(requestedUrl, response, config) {
  if (!isEnabled(config, redirect.configFlag, EMERGENCY_DISABLE_KEY.redirect)) {
    return { scoreDelta: 0, findings: [] };
  }
  return redirect.analyzeResponse(
    requestedUrl, response,
    config.weights.detection_cross_domain_redirect_score,
    config.weights.detection_https_downgrade_score
  );
}
