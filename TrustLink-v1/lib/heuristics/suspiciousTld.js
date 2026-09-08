// lib/heuristics/suspiciousTld.js — spec section 27
// TLD reputation as a risk signal only — never a reason to block a whole
// extension outright. The list is remotely configurable (Remote Config
// param: suspicious_tlds) so it can be updated without a store release.
export const key = "suspiciousTld";
export const configFlag = "feature_suspicious_tld";
export const defaultScore = 10;

export function detect(ctx, score, tldSet) {
  if (!tldSet.has(ctx.tld)) return null;
  return {
    id: "abused-tld", level: "medium", title: `Frequently abused top-level domain (.${ctx.tld})`,
    detail: `The .${ctx.tld} extension is inexpensive and commonly used for short-lived phishing or spam campaigns. It doesn't mean this site is malicious, just worth extra caution.`,
    score,
  };
}
