// lib/heuristics/urlObfuscation.js — spec section 28
// Groups every "the URL itself is trying to hide something" structural
// signal: heavy percent-encoding, the @ userinfo trick, unusual ports,
// excessive hyphenation, and very long hostnames. Each fires independently
// and additively, exactly as the original inline checks did.
export const key = "urlObfuscation";
export const configFlag = "feature_url_obfuscation";
export const defaultScores = {
  userinfo: 60,
  nonstandardPort: 8,
  hyphenated: 12,
  longHost: 6,
  heavyEncoding: 6,
};
const HYPHEN_THRESHOLD = 3; // 3+ hyphens in the host
const LONG_HOST_THRESHOLD = 40; // characters

export function detect(ctx, scores = defaultScores) {
  const findings = [];

  if (ctx.url.username || ctx.full.includes("@")) {
    findings.push({
      id: "userinfo", level: "high", title: "Misleading @ URL structure",
      detail: "This address embeds text before an “@” symbol — a classic trick to make a malicious domain look like it belongs to a trusted site.",
      score: scores.userinfo,
    });
  }

  if (ctx.url.port && !["80", "443", ""].includes(ctx.url.port)) {
    findings.push({
      id: "nonstandard-port", level: "medium", title: "Non-standard port",
      detail: `This site is served on port ${ctx.url.port} instead of the standard web ports. Not dangerous by itself, but unusual for consumer-facing sites.`,
      score: scores.nonstandardPort,
    });
  }

  const plain = ctx.labels.filter((l) => !l.startsWith("xn--")).join(".");
  if (plain.split("-").length - 1 >= HYPHEN_THRESHOLD) {
    findings.push({
      id: "hyphenated", level: "medium", title: "Heavily hyphenated domain",
      detail: "Multiple hyphens in a domain name are common in disposable, auto-generated, or look-alike domains.",
      score: scores.hyphenated,
    });
  }

  if (ctx.host.length > LONG_HOST_THRESHOLD) {
    findings.push({
      id: "long-host", level: "low", title: "Very long domain name",
      detail: "Unusually long domain names can be used to push the real brand name off-screen in a browser's address bar on small devices.",
      score: scores.longHost,
    });
  }

  if (/%[0-9a-f]{2}.*%[0-9a-f]{2}.*%[0-9a-f]{2}/i.test(ctx.path)) {
    findings.push({
      id: "heavy-encoding", level: "low", title: "Heavily percent-encoded address",
      detail: "This URL contains several encoded characters, which can be used to obscure what a link actually points to.",
      score: scores.heavyEncoding,
    });
  }

  return findings;
}
