// lib/urlUtils.js
//
// Small, dependency-free URL/string utilities shared by analyzer.js and the
// lib/heuristics/* detectors. Nothing here does network I/O — pure functions
// only, so every one of these is trivially unit-testable in plain Node.

export function levenshtein(a, b) {
  const m = a.length, n = b.length;
  const dp = Array.from({ length: m + 1 }, (_, i) => [i, ...Array(n).fill(0)]);
  for (let j = 0; j <= n; j++) dp[0][j] = j;
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      dp[i][j] = a[i - 1] === b[j - 1]
        ? dp[i - 1][j - 1]
        : 1 + Math.min(dp[i - 1][j - 1], dp[i - 1][j], dp[i][j - 1]);
    }
  }
  return dp[m][n];
}

export function isIpLiteral(host) {
  const ipv4 = /^(\d{1,3}\.){3}\d{1,3}$/;
  const ipv6 = /^\[[0-9a-f:]+\]$/i;
  return ipv4.test(host) || ipv6.test(host);
}

export function isPrivateHost(host) {
  if (!host) return false;
  const clean = host.replace(/^\[|\]$/g, "").trim().toLowerCase();

  // Internal / local domains
  if (/(^|\.)(localhost|local|internal|lan|home|corp)$/i.test(clean)) return true;

  // IPv4 checks
  if (clean === "0.0.0.0" || /^0\./.test(clean)) return true;
  if (/^127\./.test(clean)) return true; // Loopback (127.0.0.0/8)
  if (/^10\./.test(clean)) return true; // Private RFC 1918 (10.0.0.0/8)
  if (/^172\.(1[6-9]|2\d|3[0-1])\./.test(clean)) return true; // Private RFC 1918 (172.16.0.0/12)
  if (/^192\.168\./.test(clean)) return true; // Private RFC 1918 (192.168.0.0/16)
  if (/^169\.254\./.test(clean)) return true; // Link-local RFC 3927 (169.254.0.0/16)
  if (/^100\.(6[4-9]|[7-9]\d|1[0-1]\d|12[0-7])\./.test(clean)) return true; // CGNAT RFC 6598 (100.64.0.0/10)

  // IPv6 checks
  if (clean === "::1" || clean === "::" || clean === "0:0:0:0:0:0:0:1" || clean === "0:0:0:0:0:0:0:0") return true;
  if (/^fe[89ab][0-9a-f]?::?/i.test(clean)) return true; // Link-local fe80::/10
  if (/^f[cd][0-9a-f]{2}::?/i.test(clean)) return true; // Unique local fc00::/7
  if (/^::ffff:/i.test(clean)) {
    const v4 = clean.replace(/^::ffff:/i, "");
    return isPrivateHost(v4);
  }

  return false;
}

// Shared platforms where multi-tenant subdomains/paths exist.
// These must be excluded from domain-level threat matching so single phishing links
// don't cause entire public hosting platforms or document services to be blocked.
export const SHARED_HOST_EXCLUSIONS = new Set([
  // Static / code / app hosting
  "github.io", "gitlab.io", "pages.dev", "vercel.app", "netlify.app",
  "web.app", "firebaseapp.com", "azurewebsites.net", "herokuapp.com",
  "glitch.me", "repl.co", "workers.dev", "render.com", "onrender.com",
  // Cloud storage, forms & docs
  "blob.core.windows.net", "s3.amazonaws.com", "amazonaws.com",
  "google.com", "docs.google.com", "drive.google.com", "sites.google.com",
  "forms.gle", "sharepoint.com", "dropbox.com", "onedrive.live.com",
  // URL shorteners & redirection
  "bit.ly", "tinyurl.com", "t.co", "cutt.ly", "is.gd", "rebrand.ly", "ow.ly",
  // Tunnels
  "ngrok.io", "ngrok-free.app", "loca.lt", "pagekite.me",
  // Free website builders
  "000webhostapp.com", "wixsite.com", "weebly.com", "wordpress.com", "blogspot.com",
]);

export function isSharedHost(host) {
  if (!host) return false;
  const clean = host.replace(/^\[|\]$/g, "").trim().toLowerCase();
  if (SHARED_HOST_EXCLUSIONS.has(clean)) return true;
  for (const shared of SHARED_HOST_EXCLUSIONS) {
    if (clean.endsWith(`.${shared}`)) return true;
  }
  return false;
}

export const MULTI_TLD = new Set([
  "co.uk", "org.uk", "me.uk", "ltd.uk", "plc.uk", "net.uk", "sch.uk", "ac.uk", "gov.uk",
  "co.in", "net.in", "org.in", "gen.in", "firm.in", "ind.in", "nic.in", "ac.in", "edu.in", "res.in", "gov.in", "mil.in",
  "com.au", "net.au", "org.au", "edu.au", "gov.au", "asn.au", "id.au",
  "co.jp", "ne.jp", "or.jp", "ac.jp", "ed.jp", "go.jp", "gr.jp", "lg.jp",
  "com.br", "net.br", "org.br", "gov.br", "edu.br",
  "co.nz", "net.nz", "org.nz", "govt.nz", "ac.nz",
  "co.za", "net.za", "org.za", "gov.za", "ac.za",
  "com.sg", "net.sg", "org.sg", "gov.sg", "edu.sg",
  "com.mx", "org.mx", "gob.mx", "edu.mx",
  "co.kr", "ne.kr", "or.kr", "re.kr", "pe.kr", "go.kr", "mil.kr", "ac.kr",
  "com.tr", "net.tr", "org.tr", "gov.tr", "edu.tr",
  "com.tw", "net.tw", "org.tw", "gov.tw", "edu.tw",
  "com.hk", "net.hk", "org.hk", "gov.hk", "edu.hk",
  "com.my", "net.my", "org.my", "gov.my", "edu.my",
  "com.ar", "net.ar", "org.ar", "gob.ar", "edu.ar",
  "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn",
  "com.co", "net.co", "org.co", "gov.co", "edu.co",
  "com.ng", "net.ng", "org.ng", "gov.ng", "edu.ng",
  "com.pk", "net.pk", "org.pk", "gov.pk", "edu.pk",
]);

export function registrableDomain(host) {
  if (!host) return "";
  const clean = host.replace(/^\[|\]$/g, "").trim().toLowerCase();
  const p = clean.split(".");
  if (p.length >= 3 && MULTI_TLD.has(p.slice(-2).join("."))) return p.slice(-3).join(".");
  return p.length <= 2 ? clean : p.slice(-2).join(".");
}

/**
 * Builds the shared "context" object passed to every heuristics/*.js
 * detector, so each URL is only parsed once per analysis.
 */
export function buildUrlContext(url) {
  const host = url.hostname.toLowerCase();
  const path = `${url.pathname}${url.search}`.toLowerCase();
  const full = `${host}${path}`;
  const labels = host.split(".");
  const tld = labels[labels.length - 1];
  return { url, host, path, full, labels, tld, reg: registrableDomain(host) };
}

// --- Minimal RFC 3492 Punycode decoder (no dependency) -------------------
// Used by heuristics/homograph.js to look *through* an "xn--" label at the
// actual Unicode it represents, so we can flag mixed-script / confusable
// characters — not just the bare fact that a domain is IDN-encoded (that's
// heuristics/punycode.js's job).
const PUNY_BASE = 36, PUNY_TMIN = 1, PUNY_TMAX = 26, PUNY_SKEW = 38, PUNY_DAMP = 700, PUNY_INITIAL_BIAS = 72, PUNY_INITIAL_N = 128;

function punyAdapt(delta, numPoints, firstTime) {
  delta = firstTime ? Math.floor(delta / PUNY_DAMP) : delta >> 1;
  delta += Math.floor(delta / numPoints);
  let k = 0;
  while (delta > ((PUNY_BASE - PUNY_TMIN) * PUNY_TMAX) >> 1) {
    delta = Math.floor(delta / (PUNY_BASE - PUNY_TMIN));
    k += PUNY_BASE;
  }
  return k + Math.floor(((PUNY_BASE - PUNY_TMIN + 1) * delta) / (delta + PUNY_SKEW));
}

function punyDecodeDigit(cp) {
  if (cp >= 48 && cp <= 57) return cp - 22; // 0-9
  if (cp >= 65 && cp <= 90) return cp - 65; // A-Z
  if (cp >= 97 && cp <= 122) return cp - 97; // a-z
  return -1;
}

/** Decodes one "xn--..." label to its Unicode string. Returns null on any malformed input (never throws). */
export function punycodeDecodeLabel(label) {
  if (!/^xn--/i.test(label)) return null;
  const input = label.slice(4);
  const lastDelim = input.lastIndexOf("-");
  let output = lastDelim >= 0 ? input.slice(0, lastDelim).split("") : [];
  let i = 0, n = PUNY_INITIAL_N, bias = PUNY_INITIAL_BIAS;
  let pos = lastDelim >= 0 ? lastDelim + 1 : 0;
  try {
    while (pos < input.length) {
      const oldi = i;
      let w = 1, k = PUNY_BASE;
      for (;;) {
        if (pos >= input.length) return null;
        const digit = punyDecodeDigit(input.charCodeAt(pos++));
        if (digit < 0) return null;
        i += digit * w;
        const t = k <= bias ? PUNY_TMIN : (k >= bias + PUNY_TMAX ? PUNY_TMAX : k - bias);
        if (digit < t) break;
        w *= PUNY_BASE - t;
        k += PUNY_BASE;
      }
      const numPoints = output.length + 1;
      bias = punyAdapt(i - oldi, numPoints, oldi === 0);
      n += Math.floor(i / numPoints);
      i %= numPoints;
      output.splice(i, 0, String.fromCodePoint(n));
      i++;
    }
    return output.join("");
  } catch {
    return null;
  }
}

// A short, curated set of Unicode characters that are visually near-identical
// to a common ASCII Latin letter — enough to catch the classic homograph
// tricks (Cyrillic а/е/о/р/с/х/у, Greek ο/ρ, etc.) without pretending to be
// an exhaustive confusables database.
const CONFUSABLES = {
  "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y", "і": "i",
  "ѕ": "s", "ј": "j", "ԁ": "d", "ɡ": "g", "ⅼ": "l", "ο": "o", "ρ": "p", "ѵ": "v",
};

/** Returns the list of confusable (Latin-lookalike, non-Latin) characters found in a decoded label. */
export function findConfusables(decoded) {
  const hits = [];
  for (const ch of decoded) {
    if (CONFUSABLES[ch]) hits.push({ char: ch, looksLike: CONFUSABLES[ch] });
  }
  return hits;
}

// --- Secure URL normalization (spec section 23) ---------------------------
// Produces a canonical string used ONLY for threat-database matching, never
// for the risk-scoring heuristics above (those need the real, unmodified
// URL). Genuinely different URLs must never collapse to the same indicator.
export function normalizeForLookup(urlString) {
  let url;
  try {
    url = new URL(urlString);
  } catch {
    return null;
  }
  let host = url.hostname.toLowerCase();
  const defaultPort = url.protocol === "https:" ? "443" : url.protocol === "http:" ? "80" : null;
  const port = url.port && url.port !== defaultPort ? `:${url.port}` : "";
  let path = url.pathname.replace(/\/+$/, "") || "/";
  // Normalize percent-encoding case (%2F vs %2f) without altering which
  // characters are encoded — that would change the indicator's meaning.
  path = path.replace(/%[0-9a-f]{2}/gi, (m) => m.toUpperCase());
  const search = url.search || "";
  return `${url.protocol}//${host}${port}${path}${search}`;
}
