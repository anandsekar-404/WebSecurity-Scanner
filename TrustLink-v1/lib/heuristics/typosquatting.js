// lib/heuristics/typosquatting.js — spec section 26
// Edit-distance comparison against a configurable protected-brand list.
// A risk signal, never a standalone verdict — see brandImpersonation.js for
// the "substring of a brand name but on the wrong domain" pattern; this file
// is specifically for near-miss spellings (paypa1, micros0ft, g00gle).
import { levenshtein, registrableDomain } from "../urlUtils.js";

export const key = "typosquatting";
export const configFlag = "feature_typosquatting";
export const defaultScore = 30;

export function detect(ctx, score, protectedBrands) {
  const reg = ctx.reg;
  for (const brand of protectedBrands) {
    if (reg === brand) continue; // it IS the real brand domain
    const dist = levenshtein(reg, brand);
    if (dist > 0 && dist <= 2 && Math.abs(reg.length - brand.length) <= 3) {
      return {
        id: "lookalike-domain", level: "high", title: "Look-alike domain detected",
        detail: `“${reg}” is only ${dist} character${dist > 1 ? "s" : ""} different from the well-known domain “${brand}” — a common typosquatting pattern.`,
        score,
      };
    }
  }
  return null;
}

export { registrableDomain };
