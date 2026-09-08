// lib/heuristics/brandImpersonation.js — spec section 32
// Detects a trusted brand's name appearing in the address while the actual
// registrable domain is something else entirely. Combined with the calling
// site's own findings (suspicious path, login/credential wording), this is
// meant to be one signal feeding the centralized risk engine, never a
// standalone "malicious" verdict.
export const key = "brandImpersonation";
export const configFlag = "feature_brand_detection";
export const defaultScore = 28;

export function detect(ctx, score, protectedBrands) {
  const reg = ctx.reg;
  for (const brand of protectedBrands) {
    const brandName = brand.split(".")[0];
    if (reg === brand) continue; // it IS the real brand domain
    if (ctx.host.includes(brandName) && reg !== brand) {
      return {
        id: "brand-impersonation", level: "high", title: "Possible brand impersonation",
        detail: `The address references “${brandName}” but the actual domain is “${reg}”, not “${brand}”. Legitimate ${brandName} pages only live on their real domain.`,
        score,
      };
    }
  }
  return null;
}
