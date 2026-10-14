# Chrome Web Store — Permission Justification & Store Listing Documentation

This document contains the official Single Purpose statement and permission justifications prepared for Chrome Web Store Developer Dashboard review.

---

## 1. Single Purpose Description

> **TrustLink is a passive, privacy-first web security assistant that analyzes visited links and pages in real time to calculate a 0–100 risk score, explain detected phishing/impersonation signals, and proactively block dangerous destinations before page content loads.**

---

## 2. Host Permissions Justification (`http://*/*`, `https://*/*`)

### Why does TrustLink require access to all websites?

1. **Unpredictable Threat Distribution:**
   Phishing, brand impersonation, typosquatting, and credential harvesting infrastructure are deployed across thousands of newly registered domains, obscure ccTLDs, and cloud hosting subdomains daily. A static or pre-defined host allowlist cannot protect users against zero-day phishing links or novel threats encountered during everyday browsing.

2. **Pre-Navigation Interception & Blocking:**
   To protect users from malicious pages before they render or execute arbitrary scripts, TrustLink must be able to evaluate navigation targets across all web protocols (`http://` and `https://`) and redirect high-risk or known-malicious URLs to an educational block interstitial (`blocked.html`).

3. **On-Page Credential Harvest Defense:**
   TrustLink's isolated content script runs on visited pages to detect high-risk credential handling behaviors, specifically:
   - Password fields presented on unencrypted or high-risk lookalike pages.
   - Login forms designed to submit sensitive passwords cross-origin to a different registrable domain (off-site credential harvesting).

4. **Zero-Tracking Privacy Guarantee:**
   All heuristic evaluations and threat lookups are performed **100% locally on the user's device**. TrustLink never transmits browsing history, visited URLs, form data, or personal identifiers to any remote server.

---

## 3. API Permissions Justification

| Permission | Technical Requirement & Justification |
|---|---|
| `webNavigation` | Required to intercept navigation on `onBeforeNavigate` and `onCommitted` (handling server-side redirects). This enables TrustLink to check incoming URLs against local threat heuristics and pre-emptively redirect the tab to `blocked.html` before dangerous page content loads. |
| `webRequest` | Required for a non-blocking `onHeadersReceived` listener on main-frame requests. This allows TrustLink to passively inspect security headers (Strict-Transport-Security, Content-Security-Policy, X-Frame-Options, X-Content-Type-Options) directly from the browser's real response without issuing duplicate network requests, preserving user bandwidth and battery. |
| `storage` | Required for `chrome.storage.local` to store offline configuration caches and user scan counts, and `chrome.storage.session` to store short-lived, tab-scoped navigation approval tokens across service worker wake/sleep cycles. |

---

## 4. Minimum Chrome Version

- **`"minimum_chrome_version": "103"`**:
  Required for native `AbortSignal.timeout()` support in service worker fetch requests without third-party polyfills.

---

## 5. Privacy Policy Compliance Summary

- **Personal Data Collected:** None.
- **Browsing History Stored Remotely:** None. Visited URLs and navigation targets are analyzed 100% locally on the user's device and are never logged or transmitted.
- **Client Identifiers:** The only identifier transmitted is an anonymous, randomly generated Firebase Installation ID (FID) per installation, used strictly to fetch client-side Remote Config parameter bundles. The FID is never associated with personal identity, user profiles, Google accounts, or browsing history.
- **External Network Calls:** Strictly limited to:
  1. Scheduled bulk download of the OpenPhish community threat feed (cached in local IndexedDB).
  2. Optional Firebase Remote Config fetch for detection tuning (cached in `chrome.storage.local`).
- **No Intrusive Probing:** TrustLink performs read-only, passive analysis without port scanning, credential stuffing, or intrusive server probing.
