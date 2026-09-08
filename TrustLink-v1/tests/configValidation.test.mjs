// Spec section 50 items 17-18 (invalid Remote Config, no cached
// configuration) at the pure-validation layer — no network involved.

import { mergeValidatedConfig, isValidParam } from "../lib/configValidation.js";
import { buildDefaultConfig } from "../lib/heuristics/defaults.js";

function assert(cond, msg) {
  if (!cond) throw new Error("FAIL: " + msg);
  console.log("  ok -", msg);
}

console.log("Scenario: a well-formed remote publish is applied on top of defaults");
{
  const base = buildDefaultConfig();
  const { config, rejectedKeys, wholesaleRejected } = mergeValidatedConfig(base, {
    detection_punycode_score: 45,
    feature_typosquatting: false,
  });
  assert(!wholesaleRejected, "a valid object is never wholesale-rejected");
  assert(rejectedKeys.length === 0, "no keys rejected when everything validates");
  assert(config.weights.detection_punycode_score === 45, "numeric weight override applied");
  assert(config.features.feature_typosquatting === false, "feature flag override applied");
  assert(config.weights.detection_homograph_score === base.weights.detection_homograph_score, "keys NOT present in the remote publish keep their base value");
}

console.log("\nScenario: a structurally broken response (not an object) is wholesale-rejected — base untouched");
{
  const base = buildDefaultConfig();
  const r1 = mergeValidatedConfig(base, null);
  const r2 = mergeValidatedConfig(base, "not an object");
  const r3 = mergeValidatedConfig(base, ["array", "not", "a", "map"]);
  assert(r1.wholesaleRejected && r1.config === base, "null entries object -> wholesale rejected, base returned as-is");
  assert(r2.wholesaleRejected, "string entries object -> wholesale rejected");
  assert(r3.wholesaleRejected, "array entries object -> wholesale rejected");
}

console.log("\nScenario: ONE bad field doesn't discard an otherwise-good publish");
{
  const base = buildDefaultConfig();
  const { config, rejectedKeys } = mergeValidatedConfig(base, {
    detection_punycode_score: "not a number", // bad
    feature_typosquatting: false, // good
  });
  assert(rejectedKeys.includes("detection_punycode_score"), "the bad field is reported as rejected");
  assert(config.weights.detection_punycode_score === base.weights.detection_punycode_score, "the bad field keeps its base value");
  assert(config.features.feature_typosquatting === false, "the good field in the SAME publish still applies");
}

console.log("\nScenario: out-of-range weight is rejected");
{
  const base = buildDefaultConfig();
  const { rejectedKeys } = mergeValidatedConfig(base, { detection_ip_url_score: 500 });
  assert(rejectedKeys.includes("detection_ip_url_score"), "a weight far outside 0-100 is rejected");
}

console.log("\nScenario: broken risk-threshold ORDERING (critical > high > medium > low) is rejected as a set");
{
  const base = buildDefaultConfig();
  const { config, rejectedKeys } = mergeValidatedConfig(base, {
    risk_critical_threshold: 10, // now LOWER than high — invalid relationship
    risk_high_threshold: 70,
  });
  assert(rejectedKeys.some((k) => k.includes("ordering")), "ordering violation is flagged");
  assert(config.risk.risk_critical_threshold === base.risk.risk_critical_threshold, "risk thresholds fall back to the base SET (not a partial mix) when ordering breaks");
}

console.log("\nScenario: unknown keys are never trusted, whatever their shape");
{
  assert(isValidParam("some_made_up_param", true) === false, "an unrecognized key is always rejected, even with a plausible-looking value");
}

console.log("\nALL CONFIG VALIDATION TESTS PASSED");
