// lib/heuristics/brandImpersonation.js — spec section 32
// Detects a trusted brand's name appearing in the address while the actual
// registrable domain is something else entirely. Combined with the calling
// site's own findings (suspicious path, login/credential wording), this is
// meant to be one signal feeding the centralized risk engine, never a
// standalone "malicious" verdict.
export const key = "brandImpersonation";
export const configFlag = "feature_brand_detection";
export const defaultScore = 28;

const OFFICIAL_DOMAINS = new Set([
  "googleapis.com",
  "githubusercontent.com",
  "microsoftonline.com",
  "googleusercontent.com",
  "gstatic.com",
  "1e100.net",
  "azureedge.net",
  "cloudfront.net",
  "fbcdn.net",
  "apple-dns.net",
]);

export function detect(ctx, score, protectedBrands, suspiciousTlds = new Set()) {
  const reg = ctx.reg;
  const sld = reg.split(".")[0];
  const tokens = ctx.labels.flatMap((l) => l.split("-"));
  const tldSet = suspiciousTlds instanceof Set ? suspiciousTlds : new Set(suspiciousTlds || []);

  for (const brand of protectedBrands) {
    const brandName = brand.split(".")[0];
    if (reg === brand) continue; // it IS the real brand domain
    if (
      tokens.includes(brandName) &&
      reg !== brand &&
      !OFFICIAL_DOMAINS.has(reg) &&
      !(sld === brandName && !tldSet.has(ctx.tld))
    ) {
      return {
        id: "brand-impersonation",
        level: "high",
        title: "Possible brand impersonation",
        detail: `The address references “${brandName}” but the actual domain is “${reg}”, not “${brand}”. Legitimate ${brandName} pages only live on their real domain.`,
        score,
      };
    }
  }
  return null;
}
