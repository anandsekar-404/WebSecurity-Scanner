// lib/configValidation.js — spec section 11
//
// Remote Config is never trusted blindly. Every parameter is validated
// independently: bad type, out-of-range, or missing → that ONE parameter
// keeps its previous safe value (cached, or built-in default) rather than
// the entire fetch being discarded. A single malformed field in an
// otherwise-good Remote Config publish should not throw away every other
// correctly-tuned parameter — but a config that's malformed as a WHOLE
// (not valid JSON, missing the expected shape entirely) IS rejected
// wholesale, per spec section 11's "reject configuration" instruction.
//
// This file has no side effects and does no I/O — pure validation, fully
// unit-testable.

const WEIGHT_RANGE = [5, 65]; // Detection weights cannot be zeroed out (floor: 5) or bloated (ceiling: 65)
const RISK_THRESHOLD_BOUNDS = {
  risk_low_threshold: [0, 40],
  risk_medium_threshold: [0, 60],
  risk_high_threshold: [0, 85],
  risk_critical_threshold: [0, 95],
};
const MIN_PROTECTED_BRANDS = 10; // Remote Config cannot wipe or gut the protected brands list
const MAX_LIST_SIZE = 200;
const MAX_STRING_LEN = 253; // longest legal DNS name

function isFiniteNumberInRange(v, [min, max]) {
  return typeof v === "number" && Number.isFinite(v) && v >= min && v <= max;
}

function isBoolean(v) {
  return typeof v === "boolean";
}

function isStringList(v, maxItems = MAX_LIST_SIZE, maxLen = MAX_STRING_LEN, minItems = 1) {
  return Array.isArray(v) && v.length >= minItems && v.length <= maxItems && v.every((s) => typeof s === "string" && s.length > 0 && s.length <= maxLen);
}

/**
 * Validates one raw (already type-coerced from string, per REMOTE_PARAM_TYPES)
 * value against its expected shape. Returns true/false — never throws.
 */
export function isValidParam(key, value) {
  if (key.startsWith("detection_") && key.endsWith("_score")) return isFiniteNumberInRange(value, WEIGHT_RANGE);
  if (key in RISK_THRESHOLD_BOUNDS) return isFiniteNumberInRange(value, RISK_THRESHOLD_BOUNDS[key]);
  if (key.startsWith("risk_") && key.endsWith("_threshold")) return isFiniteNumberInRange(value, [0, 100]);
  if (key.startsWith("feature_")) return isBoolean(value);
  if (key === "protection_emergency_enabled") return isBoolean(value);
  // Never allow remote config to silently switch off OpenPhish threat intelligence
  if (key === "disable_openphish") return value === false;
  if (key.startsWith("disable_")) return isBoolean(value);
  if (key === "protectedBrands") return isStringList(value, MAX_LIST_SIZE, MAX_STRING_LEN, MIN_PROTECTED_BRANDS);
  if (key === "suspiciousTlds" || key === "suspiciousKeywords" || key === "redirectParamNames") return isStringList(value);
  if (key === "system_config_version") return Number.isInteger(value) && value >= 0;
  if (key === "system_min_fetch_interval_ms" || key === "system_feed_update_interval_ms") return isFiniteNumberInRange(value, [60_000, 7 * 24 * 60 * 60 * 1000]);
  return false; // unknown key — never trust something we don't have a rule for
}

/** critical > high > medium > low, per spec section 11's example relationship. */
function riskThresholdsAreOrdered(risk) {
  return risk.risk_critical_threshold > risk.risk_high_threshold
    && risk.risk_high_threshold > risk.risk_medium_threshold
    && risk.risk_medium_threshold > risk.risk_low_threshold;
}

/**
 * Merges validated remote values onto a base config (defaults or previous
 * cache). Returns { config, rejectedKeys, wholesaleRejected }.
 *   - wholesaleRejected: true if `remoteEntries` wasn't even a usable object
 *     (parse failure, wrong shape) — base is returned completely untouched.
 *   - rejectedKeys: individual keys that failed validation and were kept at
 *     their base value instead.
 */
export function mergeValidatedConfig(base, remoteEntries) {
  if (!remoteEntries || typeof remoteEntries !== "object" || Array.isArray(remoteEntries)) {
    return { config: base, rejectedKeys: [], wholesaleRejected: true };
  }

  const next = {
    weights: { ...base.weights },
    risk: { ...base.risk },
    features: { ...base.features },
    protection: { ...base.protection },
    lists: {
      protectedBrands: [...base.lists.protectedBrands],
      suspiciousTlds: [...base.lists.suspiciousTlds],
      suspiciousKeywords: [...base.lists.suspiciousKeywords],
      redirectParamNames: [...base.lists.redirectParamNames],
    },
    system: { ...base.system },
    source: base.source,
  };
  const rejectedKeys = [];

  const LIST_KEY_MAP = {
    protectedBrands: ["lists", "protectedBrands"],
    suspiciousTlds: ["lists", "suspiciousTlds"],
    suspiciousKeywords: ["lists", "suspiciousKeywords"],
    redirectParamNames: ["lists", "redirectParamNames"],
  };

  for (const [key, rawValue] of Object.entries(remoteEntries)) {
    if (!isValidParam(key, rawValue)) {
      rejectedKeys.push(key);
      continue;
    }
    if (key.startsWith("detection_")) next.weights[key] = rawValue;
    else if (key.startsWith("risk_")) next.risk[key] = rawValue;
    else if (key.startsWith("feature_")) next.features[key] = rawValue;
    else if (key === "protection_emergency_enabled" || key.startsWith("disable_")) next.protection[key] = rawValue;
    else if (LIST_KEY_MAP[key]) { const [a, b] = LIST_KEY_MAP[key]; next[a][b] = rawValue; }
    else if (key.startsWith("system_")) next.system[key] = rawValue;
  }

  // Threshold ordering is a RELATIONSHIP across multiple params — validate it
  // after the merge. If the remote publish broke the ordering, don't ship a
  // config where "critical" is a lower bar than "high" — fall back to the
  // base's risk thresholds as a set (not a partial mix).
  if (!riskThresholdsAreOrdered(next.risk)) {
    rejectedKeys.push("risk_*_threshold (ordering)");
    next.risk = { ...base.risk };
  }

  return { config: next, rejectedKeys, wholesaleRejected: false };
}
