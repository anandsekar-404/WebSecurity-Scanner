// lib/heuristics/suspiciousSubdomain.js — spec section 29
// Excessive subdomain depth (e.g. login.secure.account.verify.example.com)
// as a signal, not proof — some legitimate infra genuinely has deep
// subdomains.
export const key = "suspiciousSubdomain";
export const configFlag = null;
export const defaultScore = 12;
export const minLabels = 5;

export function detect(ctx, score, threshold = minLabels) {
  if (ctx.labels.length < threshold) return null;
  return {
    id: "deep-subdomain", level: "medium", title: "Unusually deep subdomain chain",
    detail: `“${ctx.host}” has ${ctx.labels.length} parts. Long subdomain chains are sometimes used to bury the real domain (the last two labels) out of view.`,
    score,
  };
}
