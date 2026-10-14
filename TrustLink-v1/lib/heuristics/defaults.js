// lib/heuristics/defaults.js
//
// Every built-in default value TrustLink ships with, in one place, so:
//   1. lib/remoteConfig.js has something concrete to validate Remote Config
//      values against (ranges, types) and to fall back to if Firebase is
//      unavailable and there's no cache yet (spec section 12).
//   2. analyzer.js and lib/heuristics/*.js never hardcode a number twice.
//
// Changing a number here changes TrustLink's out-of-the-box behavior for
// every user who has never been reached by a Remote Config fetch — treat it
// with the same care as changing analyzer.js itself.

export const DEFAULT_WEIGHTS = {
  detection_no_https_score: 26,
  detection_ip_url_score: 22,
  detection_punycode_score: 30,
  detection_homograph_score: 28,
  detection_typosquatting_score: 30,
  detection_brand_impersonation_score: 28,
  detection_suspicious_tld_score: 10,
  detection_suspicious_keyword_score: 16,
  detection_excessive_subdomain_score: 12,
  detection_userinfo_score: 60,
  detection_nonstandard_port_score: 8,
  detection_hyphenated_domain_score: 12,
  detection_long_url_score: 6,
  detection_encoded_url_score: 6,
  detection_redirect_score: 14,
  detection_cross_domain_redirect_score: 18,
  detection_https_downgrade_score: 24,
};

// risk_* — unrelated to the 0-100 heuristic thresholds inside analyzer.js
// (those stay fixed at 30/60 by design — see grade() — because changing
// them changes what "Use Caution" vs "High Risk" *mean* across the whole
// UI). These are a *separate* signal: what should count as a "known-bad"
// database match severity band for the debug panel / explain-view only.
export const DEFAULT_RISK = {
  risk_low_threshold: 20,
  risk_medium_threshold: 40,
  risk_high_threshold: 70,
  risk_critical_threshold: 90,
};

export const DEFAULT_FEATURES = {
  feature_openphish: true,
  feature_phishtank: false, // no keyless registration has existed since 2020 — see lib/adapters/phishtank.js
  feature_urlhaus: false, // requires a bring-your-own Auth-Key — see lib/adapters/urlhaus.js
  feature_homograph: true,
  feature_typosquatting: true,
  feature_redirect: true,
  feature_brand_detection: true,
  feature_url_obfuscation: true,
  feature_ip_detection: true,
  feature_suspicious_tld: true,
  feature_page_analysis: false, // not yet implemented client-side (spec section 33) — reserved flag
};

export const DEFAULT_PROTECTION = {
  protection_emergency_enabled: true,
  disable_openphish: false,
  disable_phishtank: false,
  disable_homograph: false,
  disable_typosquatting: false,
  disable_redirect: false,
  disable_page_analysis: false,
};

export const DEFAULT_LISTS = {
  protectedBrands: [
    "paypal.com", "google.com", "microsoft.com", "apple.com", "amazon.com",
    "netflix.com", "facebook.com", "instagram.com", "coinbase.com", "chase.com",
    "wellsfargo.com", "bankofamerica.com", "dropbox.com", "linkedin.com",
    "github.com", "outlook.com", "office.com", "icloud.com",
  ],
  suspiciousTlds: [
    "zip", "mov", "top", "xyz", "click", "link", "gq", "cf", "tk", "ml", "ga",
    "work", "support", "country", "stream", "gdn", "kim", "loan", "men", "date",
    "review", "party", "science", "download", "racing",
  ],
  suspiciousKeywords: [
    "login", "signin", "verify", "verification", "secure", "security", "account",
    "wallet", "bonus", "gift", "invoice", "crypto", "banking", "password",
    "update", "confirm", "auth", "suspended", "unlock", "limited", "urgent",
    "recover", "billing", "support-center", "reset",
  ],
  redirectParamNames: ["url", "redirect", "redir", "next", "continue", "returnurl", "return_to", "dest", "destination", "target"],
};

export const DEFAULT_SYSTEM = {
  system_config_version: 1,
  system_min_fetch_interval_ms: 60 * 60 * 1000, // 1 hour — matches Remote Config's own default production minimum fetch interval
  system_feed_update_interval_ms: 12 * 60 * 60 * 1000, // matches OpenPhish community feed's ~12h update cadence — no point polling faster than the source publishes
};

/** Everything above, merged into the single "TrustLink Config" shape the rest of the extension consumes. */
export function buildDefaultConfig() {
  return {
    weights: { ...DEFAULT_WEIGHTS },
    risk: { ...DEFAULT_RISK },
    features: { ...DEFAULT_FEATURES },
    protection: { ...DEFAULT_PROTECTION },
    lists: {
      protectedBrands: [...DEFAULT_LISTS.protectedBrands],
      suspiciousTlds: [...DEFAULT_LISTS.suspiciousTlds],
      suspiciousKeywords: [...DEFAULT_LISTS.suspiciousKeywords],
      redirectParamNames: [...DEFAULT_LISTS.redirectParamNames],
    },
    system: { ...DEFAULT_SYSTEM },
    source: "default",
  };
}
