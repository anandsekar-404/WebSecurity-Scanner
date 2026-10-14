// lib/heuristics/brandImpersonation.js — spec section 32
// Detects a trusted brand's name appearing in the address while the actual
// registrable domain is something else entirely. Only fires on real spoofing
// patterns: brand embedded in subdomain (e.g. paypal.com.evil.com), brand token
// paired with a credential/phishing keyword (e.g. paypal-login.com), or brand
// embedded in misleading userinfo.
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
  "google-analytics.com",
  "googletagmanager.com",
  "googleadservices.com",
  "doubleclick.net",
  "msftauth.net",
  "live.com",
  "office365.com",
  "awsstatic.com",
]);

export function detect(ctx, score, protectedBrands, suspiciousTlds = new Set(), keywords = []) {
  const reg = ctx.reg;
  const sld = reg.split(".")[0];
  const tokens = ctx.labels.flatMap((l) => l.split("-"));
  const tldSet = suspiciousTlds instanceof Set ? suspiciousTlds : new Set(suspiciousTlds || []);
  const keywordList = Array.isArray(keywords) ? keywords : [];

  const regParts = ctx.reg.split(".").length;
  const subLabels = ctx.labels.slice(0, Math.max(0, ctx.labels.length - regParts));

  for (const brand of protectedBrands) {
    const brandName = brand.split(".")[0];
    if (reg === brand) continue; // it IS the real brand domain
    if (OFFICIAL_DOMAINS.has(reg)) continue;
    if (sld === brandName && !tldSet.has(ctx.tld)) continue; // legitimate ccTLD country variant

    const brandInSubdomain = subLabels.includes(brandName);
    const brandInUserinfo = Boolean(ctx.url?.username && (ctx.url.username.includes(brandName) || ctx.url.username === brand));
    const brandPlusKeyword = tokens.includes(brandName) && keywordList.some((k) => ctx.host.includes(k));

    if (brandInSubdomain || brandPlusKeyword || brandInUserinfo) {
      const finalScore = brandInSubdomain ? score + 10 : score;
      return {
        id: "brand-impersonation",
        level: "high",
        title: "Possible brand impersonation",
        detail: `The address references “${brandName}” but the actual domain is “${reg}”, not “${brand}”. Legitimate ${brandName} pages only live on their real domain.`,
        score: finalScore,
      };
    }
  }
  return null;
}
