// lib/heuristics/redirect.js — spec section 31
// Two independent checks that both fall under "redirect analysis":
//  1. detectParam() — URL-only, no network: an open-redirect-style query
//     parameter pointing off-site (e.g. ?redirect=http://evil.example).
//  2. analyzeResponse() — needs the one passive HEAD request TrustLink
//     already performs: did the actual navigation cross domains, or drop
//     from HTTPS to HTTP along the way.
import { registrableDomain } from "../urlUtils.js";

export const key = "redirect";
export const configFlag = "feature_redirect";
export const defaultParamScore = 14;
export const defaultCrossDomainScore = 18;
export const defaultDowngradeScore = 24;

const REDIRECT_PARAM_NAMES = ["url", "redirect", "redir", "next", "continue", "returnurl", "return_to", "dest", "destination", "target"];

export function detectParam(ctx, score, paramNames = REDIRECT_PARAM_NAMES) {
  for (const [key, value] of ctx.url.searchParams) {
    if (paramNames.includes(key.toLowerCase()) && /^https?:\/\//i.test(value)) {
      try {
        const dest = new URL(value);
        if (registrableDomain(dest.hostname.toLowerCase()) !== ctx.reg) {
          return {
            id: "redirect-param", level: "medium", title: "Off-site redirect parameter",
            detail: `The link's “${key}” parameter points to a different site (${dest.hostname}). Redirect parameters like this are sometimes used to disguise the true destination.`,
            score,
          };
        }
      } catch { /* ignore malformed value */ }
    }
  }
  return null;
}

export function analyzeResponse(requestedUrl, response, crossDomainScore, downgradeScore) {
  const findings = [];
  let scoreDelta = 0;
  const finalUrl = new URL(response.url || requestedUrl);
  const requested = new URL(requestedUrl);

  if (response.redirected && registrableDomain(finalUrl.hostname) !== registrableDomain(requested.hostname)) {
    scoreDelta += crossDomainScore;
    findings.push({
      id: "cross-domain-redirect", level: "medium", title: "Redirected to a different domain",
      detail: `This link led to “${finalUrl.hostname}” instead of “${requested.hostname}”. Cross-domain redirects are sometimes used to send you somewhere unexpected after a first, trustworthy-looking click.`,
    });
  }
  if (response.redirected && requested.protocol === "https:" && finalUrl.protocol !== "https:") {
    scoreDelta += downgradeScore;
    findings.push({
      id: "https-downgrade", level: "high", title: "Redirected away from HTTPS",
      detail: "The site redirected you from a secure connection to an insecure one. That's very unusual for a legitimate site.",
    });
  }
  return { scoreDelta, findings };
}
