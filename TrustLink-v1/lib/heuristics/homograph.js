// lib/heuristics/homograph.js — spec section 25 (part 2: what's inside)
// Decodes each "xn--" label back to Unicode (RFC 3492, no dependency — see
// urlUtils.js) and checks it against a small curated confusables map. This
// is what lets TrustLink tell "an IDN domain" apart from "an IDN domain
// visually pretending to be Latin text" — the latter is the real phishing
// pattern, the former is just, say, a legitimate domain in Chinese.
import { punycodeDecodeLabel, findConfusables } from "../urlUtils.js";

export const key = "homograph";
export const configFlag = "feature_homograph";
export const defaultScore = 28;

export function detect(ctx, score) {
  for (const label of ctx.labels) {
    if (!label.startsWith("xn--")) continue;
    const decoded = punycodeDecodeLabel(label);
    if (!decoded) continue;
    const hits = findConfusables(decoded);
    if (hits.length === 0) continue;
    const preview = hits.slice(0, 3).map((h) => `“${h.char}” → “${h.looksLike}”`).join(", ");
    return {
      id: "homograph", level: "high", title: "Visually deceptive characters in domain",
      detail: `This domain decodes to text containing look-alike characters from a different script (${preview}). This is a classic homograph attack used to impersonate a trusted name.`,
      score,
    };
  }
  return null;
}
