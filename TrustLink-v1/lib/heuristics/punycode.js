// lib/heuristics/punycode.js — spec section 25 (part 1: the encoding itself)
// Flags any "xn--" label. Doesn't inspect what it decodes to — that deeper
// look lives in homograph.js — this just flags "this domain uses IDN
// encoding at all", which is worth a smaller, separate signal.
export const key = "punycode";
export const configFlag = "feature_homograph"; // spec groups punycode+homograph under one flag
export const defaultScore = 30;

export function detect(ctx, score) {
  if (!ctx.host.includes("xn--")) return null;
  return {
    id: "punycode", level: "high", title: "Encoded (punycode) domain",
    detail: "This domain uses punycode, a way to register lookalike characters (e.g. a Cyrillic “а” instead of “a”) that can visually impersonate a trusted name.",
    score,
  };
}
