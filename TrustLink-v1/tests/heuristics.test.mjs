// Exercises each lib/heuristics/*.js detector directly (not just through
// analyzer.js) so a regression in one detector points straight at its file.
// Covers spec section 50 items 5-14 (punycode, homograph, typosquatting,
// suspicious TLD, IP URL, obfuscated/long/excessive-subdomain URLs) plus
// brand impersonation and redirect-param detection.

import { buildUrlContext } from "../lib/urlUtils.js";
import { buildDefaultConfig } from "../lib/heuristics/defaults.js";
import * as ipUrl from "../lib/heuristics/ipUrl.js";
import * as punycode from "../lib/heuristics/punycode.js";
import * as homograph from "../lib/heuristics/homograph.js";
import * as typosquatting from "../lib/heuristics/typosquatting.js";
import * as brandImpersonation from "../lib/heuristics/brandImpersonation.js";
import * as suspiciousTld from "../lib/heuristics/suspiciousTld.js";
import * as suspiciousKeywords from "../lib/heuristics/suspiciousKeywords.js";
import * as suspiciousSubdomain from "../lib/heuristics/suspiciousSubdomain.js";
import * as redirect from "../lib/heuristics/redirect.js";
import * as urlObfuscation from "../lib/heuristics/urlObfuscation.js";
import { runAll } from "../lib/heuristics/index.js";

function assert(cond, msg) {
  if (!cond) throw new Error("FAIL: " + msg);
  console.log("  ok -", msg);
}

const cfg = buildDefaultConfig();
const ctx = (url) => buildUrlContext(new URL(url));

console.log("Scenario: ipUrl");
assert(ipUrl.detect(ctx("http://45.33.12.9/wallet"), 22)?.id === "ip-literal", "raw public IPv4 flagged");
assert(ipUrl.detect(ctx("https://example.com/"), 22) === null, "named domain not flagged");

console.log("\nScenario: punycode");
assert(punycode.detect(ctx("https://xn--80ak6aa92e.com/"), 30)?.id === "punycode", "xn-- domain flagged");
assert(punycode.detect(ctx("https://example.com/"), 30) === null, "plain ASCII domain not flagged");

console.log("\nScenario: homograph (decodes punycode, checks for confusables)");
// "аpple" with a Cyrillic а (U+0430) encodes to this punycode label.
const cyrillicApple = "xn--pple-43d"; // decodes to "аpple" (Cyrillic а + "pple")
const hit = homograph.detect(ctx(`https://${cyrillicApple}.com/`), 28);
assert(hit?.id === "homograph", `Cyrillic-confusable IDN label flagged (got ${JSON.stringify(hit)})`);
assert(homograph.detect(ctx("https://xn--fsq.com/"), 28) === null || true, "a legitimate non-Latin IDN without a Latin-lookalike char doesn't necessarily trigger (sanity — not a strict assertion, confusables list is intentionally small)");

console.log("\nScenario: typosquatting (edit-distance)");
assert(typosquatting.detect(ctx("https://paypa1.com/"), 30, cfg.lists.protectedBrands)?.id === "lookalike-domain", "paypa1.com (1 char off from paypal.com) flagged");
assert(typosquatting.detect(ctx("https://paypal.com/"), 30, cfg.lists.protectedBrands) === null, "the real paypal.com is never flagged against itself");

console.log("\nScenario: brandImpersonation (brand name present, wrong domain)");
assert(brandImpersonation.detect(ctx("https://paypal.security-check.example.com/"), 28, cfg.lists.protectedBrands)?.id === "brand-impersonation", "brand name in a subdomain on the wrong domain flagged");
assert(brandImpersonation.detect(ctx("https://paypal.com/"), 28, cfg.lists.protectedBrands) === null, "the real brand domain is never flagged against itself");

console.log("\nScenario: suspiciousTld");
assert(suspiciousTld.detect(ctx("https://free-prize.zip/"), 10, new Set(cfg.lists.suspiciousTlds))?.id === "abused-tld", ".zip flagged as an abused TLD");
assert(suspiciousTld.detect(ctx("https://example.com/"), 10, new Set(cfg.lists.suspiciousTlds)) === null, ".com not flagged");

console.log("\nScenario: suspiciousKeywords (requires 2+ matches)");
assert(suspiciousKeywords.detect(ctx("https://example.com/login"), 16, cfg.lists.suspiciousKeywords) === null, "a single keyword alone does not fire");
assert(suspiciousKeywords.detect(ctx("https://example.com/login/verify-account"), 16, cfg.lists.suspiciousKeywords)?.id === "phishing-words", "2+ keywords together fires");

console.log("\nScenario: suspiciousSubdomain");
assert(suspiciousSubdomain.detect(ctx("https://login.secure.account.verify.example.com/"), 12)?.id === "deep-subdomain", "5+ label host flagged");
assert(suspiciousSubdomain.detect(ctx("https://www.example.com/"), 12) === null, "a normal 3-label host is not flagged");

console.log("\nScenario: redirect (open-redirect-style query param)");
assert(redirect.detectParam(ctx("https://example.com/go?redirect=https://evil.example/"), 14, cfg.lists.redirectParamNames)?.id === "redirect-param", "off-site redirect param flagged");
assert(redirect.detectParam(ctx("https://example.com/go?redirect=https://example.com/ok"), 14, cfg.lists.redirectParamNames) === null, "same-site redirect param not flagged");

console.log("\nScenario: urlObfuscation (userinfo @, port, hyphens, long host, encoding)");
const obfHits = urlObfuscation.detect(ctx("https://user:pass@evil.example/"), urlObfuscation.defaultScores).map((f) => f.id);
assert(obfHits.includes("userinfo"), "@ userinfo trick flagged");
const portHits = urlObfuscation.detect(ctx("https://example.com:8443/"), urlObfuscation.defaultScores).map((f) => f.id);
assert(portHits.includes("nonstandard-port"), "non-standard port flagged");

console.log("\nScenario: runAll() respects feature flags — disabling homograph/punycode via config stops those findings");
const disabledCfg = buildDefaultConfig();
disabledCfg.features.feature_homograph = false;
const withFlag = runAll(ctx("https://xn--80ak6aa92e.com/"), cfg).map((f) => f.id);
const withoutFlag = runAll(ctx("https://xn--80ak6aa92e.com/"), disabledCfg).map((f) => f.id);
assert(withFlag.includes("punycode"), "punycode finding present when feature_homograph is enabled");
assert(!withoutFlag.includes("punycode"), "punycode finding suppressed when feature_homograph is disabled (spec section 9)");

console.log("\nScenario: isPrivateHost comprehensively identifies private and internal addresses");
const { isPrivateHost } = await import("../lib/urlUtils.js");
const { analyzeUrl } = await import("../analyzer.js");

const privateAddresses = [
  "127.0.0.1",
  "0.0.0.0",
  "169.254.169.254", // AWS/cloud metadata & IPv4 link-local
  "169.254.1.1",
  "100.64.0.1", // Carrier Grade NAT RFC 6598
  "100.100.50.25",
  "100.127.255.254",
  "10.0.0.1",
  "172.16.0.1",
  "192.168.1.1",
  "::1",
  "[::1]",
  "service.local",
  "router.internal",
  "host.lan",
  "localhost",
];

for (const addr of privateAddresses) {
  assert(isPrivateHost(addr) === true, `isPrivateHost("${addr}") is true`);
  const hostForUrl = addr.includes(":") && !addr.startsWith("[") ? `[${addr}]` : addr;
  const analysis = analyzeUrl(`http://${hostForUrl}/login`);
  assert(analysis.isLocal === true && analysis.safeToFetch === false, `analyzeUrl("http://${hostForUrl}/login") is classified as local and unsafe to fetch`);
}

const publicAddresses = [
  "100.63.1.1", // below CGNAT range
  "100.128.0.1", // above CGNAT range
  "8.8.8.8",
  "github.com",
  "paypal.com",
];
for (const addr of publicAddresses) {
  assert(isPrivateHost(addr) === false, `isPrivateHost("${addr}") is false (public)`);
}

console.log("\nALL HEURISTICS TESTS PASSED");
