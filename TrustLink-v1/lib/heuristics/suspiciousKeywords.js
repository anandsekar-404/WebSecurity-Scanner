// lib/heuristics/suspiciousKeywords.js — spec section 30
// Sensitive-action wording in the URL. Requires 2+ distinct hits before
// firing at all — a single word like "login" appears on huge numbers of
// completely legitimate pages, so one match alone must never be treated as
// suspicious (spec's own instruction).
export const key = "suspiciousKeywords";
export const configFlag = null; // always-on structural signal, not a togglable "feature"
export const defaultScore = 16;
export const minMatches = 2;

export function detect(ctx, score, keywordList, threshold = minMatches) {
  const tokens = new Set(ctx.full.split(/[^a-z0-9]+/));
  const matched = keywordList.filter((k) => (k.includes("-") ? ctx.full.includes(k) : tokens.has(k)));
  if (matched.length < threshold) return null;
  return {
    id: "phishing-words", level: "medium", title: "Sensitive-action wording in the address",
    detail: `The URL contains terms often paired with credential or payment phishing: ${matched.slice(0, 4).join(", ")}.`,
    score,
  };
}
