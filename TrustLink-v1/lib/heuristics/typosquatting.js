// lib/heuristics/typosquatting.js — spec section 26
// Edit-distance comparison against a configurable protected-brand list.
// Compares only the second-level domain (SLD) and skips multi-tenant shared hosts.
import { levenshtein, registrableDomain, isSharedHost } from "../urlUtils.js";

export const key = "typosquatting";
export const configFlag = "feature_typosquatting";
export const defaultScore = 30;

const KNOWN_BENIGN_DOMAINS = new Set([
  "gitlab.com", "bitbucket.org", "wikipedia.org", "wikimedia.org", "w3.org", "who.int",
]);

export function detect(ctx, score, protectedBrands) {
  if (isSharedHost(ctx.host)) return null;

  const reg = ctx.reg;
  if (KNOWN_BENIGN_DOMAINS.has(reg)) return null;
  if (protectedBrands.includes(reg)) return null; // Never flag a protected brand as a typosquat of another

  const sld = reg.split(".")[0];
  if (!sld || sld.length < 3) return null;

  for (const brand of protectedBrands) {
    const brandSld = brand.split(".")[0];
    if (sld === brandSld) continue; // it IS the brand or brand ccTLD

    const minLen = Math.min(sld.length, brandSld.length);
    // 3-letter acronyms (ibm, amd, bbc, rbs, sbi) must not match each other
    if (minLen <= 3) continue;

    const maxDist = minLen <= 4 ? 1 : 2;
    const dist = levenshtein(sld, brandSld);
    if (dist > 0 && dist <= maxDist && Math.abs(sld.length - brandSld.length) <= 1) {
      return {
        id: "lookalike-domain",
        level: "high",
        title: "Look-alike domain detected",
        detail: `“${sld}” is only ${dist} character${dist > 1 ? "s" : ""} different from the well-known brand “${brandSld}” (${brand}) — a common typosquatting pattern.`,
        score,
      };
    }
  }
  return null;
}

export { registrableDomain };
