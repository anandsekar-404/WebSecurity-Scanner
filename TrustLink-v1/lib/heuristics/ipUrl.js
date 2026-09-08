// lib/heuristics/ipUrl.js — spec section 24
// Detects a raw IP literal used instead of a named domain. A signal, not an
// automatic verdict: plenty of legitimate internal tools use bare IPs.
import { isIpLiteral } from "../urlUtils.js";

export const key = "ipUrl";
export const configFlag = "feature_ip_detection";
export const defaultScore = 22;

export function detect(ctx, score) {
  if (!isIpLiteral(ctx.host)) return null;
  return {
    id: "ip-literal", level: "high", title: "Raw IP address instead of a domain",
    detail: "Legitimate sites almost always use a named domain. A bare IP address is a common trait of throwaway phishing or malware infrastructure.",
    score,
  };
}
