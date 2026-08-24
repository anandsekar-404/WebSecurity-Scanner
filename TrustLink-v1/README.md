# TrustLink

**Verify the link. Protect the click.**

TrustLink is a Chrome Manifest V3 extension that analyzes the website you're
currently on — or any link you paste in — and gives it a clear risk score
from 0–100: "Looks Safe," "Use Caution," or "High Risk," with plain-language
explanations of exactly what was found. It also proactively blocks
navigation to pages it classifies as dangerous, with a full warning
interstitial explaining why.

## Install locally (unpacked)

1. Open `chrome://extensions` in Chrome.
2. Turn on **Developer mode** (top-right toggle).
3. Click **Load unpacked** and select this folder.
4. Pin **TrustLink** from the extensions toolbar menu.

All extension files sit flat in the root (no subfolders needed for Chrome to
load them) — `lib/`, `tests/`, and `firestore.rules` are supporting
files/tooling, not required at the top level.

---

## What's in this upgrade

### 1. Automatic Scanner vs. Manual Page Scan — two independent systems

TrustLink has always had an **Automatic Scanner**: `content.js` quietly
checks every page you load and, separately, shows you the current tab's
score the instant you open the popup. That's free, unlimited, and untouched
by anything below.

**Manual Page Scan** is a distinct, explicit action: pressing the popup's
refresh (re-run check) button, or using the "paste a link to check" bar in
the popup or full-screen page. Only *these* count toward the follow gate:

- **1st manual scan** — always allowed immediately.
- **2nd manual scan** — always allowed immediately.
- **3rd manual scan onward** — if you've never completed the Instagram step,
  a modal asks you to follow `@cybroatrix` before continuing. If you *have*
  already completed it (ever), you're never asked again — the 3rd, 4th, and
  every scan after that just works.

This logic lives in `lib/state.js` and is unit-tested in
`tests/state.test.mjs` (run `node tests/state.test.mjs` — it exercises
exactly the scenarios asked for: 1st/2nd/3rd/4th scan, an already-verified
user, and confirms the Automatic Scanner is completely unaffected by any of
this).

**Honesty note, on purpose:** there is no API that lets a browser extension
verify a specific user follows a specific Instagram account. TrustLink does
not pretend to. The modal requires you to actually click through to
Instagram (the confirm button stays disabled until you do), then asks you to
self-confirm. That's clearly worded as self-confirmation in the UI, not
"verifying your follow…" with a fake spinner.

### 2. Stop Scanning

A small pill in the top-right corner of the popup and full-screen page shows
**Scanning** (green, pulsing) or **Stopped** (red) and toggles the Automatic
Scanner on click. While stopped:

- `content.js` skips its per-page check entirely (checked via
  `getAutoScanEnabled` before doing any work — no wasted fetches).
- The toolbar badge is cleared across all open tabs immediately.
- Manual Page Scan is **not** affected — you can still explicitly check a
  link even while automatic scanning is paused, per the spec.

Click it again any time to resume.

### 3. Dangerous-page blocking (pre-navigation)

MV3 removed extensions' ability to synchronously cancel a network request,
so TrustLink uses the standard modern approach instead: `lib/blocking.js`
listens for `webNavigation.onBeforeNavigate` on the main frame, runs the
*URL-only* heuristics (no network round-trip — effectively instant), and if
that alone already scores High Risk, immediately re-points the tab at
`blocked.html` before the dangerous page can finish loading.

`blocked.html` shows:
- The score, threat label, and specific reasons ("Encoded (punycode)
  domain", "Look-alike domain detected", "Not using HTTPS", etc.)
- A prominent **Go back to safety** button (navigates the tab back in
  history)
- A deliberately less prominent **"I understand the risk — show advanced
  option"** link that reveals a second confirmation step before "Continue
  anyway" actually navigates you there — never a single accidental click.

Header-based signals (HSTS, CSP, redirect chains) need a network round trip
and can't be evaluated before navigation starts, so those continue to
surface via the in-page banner and popup, exactly as before — pre-navigation
blocking is an earlier, additional layer on top of that, not a replacement.

### 4. Reliability: chrome.storage.local + optional Firebase sync

All the state above lives in `chrome.storage.local` by default — the
extension is fully functional offline, with no setup required. On top of
that, `lib/firebaseSync.js` can mirror `manualScanCount`,
`instagramRequirementCompleted`, and `instagramVerifiedAt` to Firestore
(Anonymous Auth), so clearing local browser data doesn't quietly reset a
verified user: on every load, TrustLink takes the *more permissive* of
{local, remote} rather than trusting a wiped local value of 0.

**To turn Firebase sync on:**
1. Create a Firebase project → enable **Anonymous** sign-in (Authentication
   → Sign-in method) → create a **Firestore** database.
2. Firebase Console → Project Settings → your web app → copy the config.
3. Paste `apiKey` and `projectId` into `lib/firebase-config.js`.
4. Paste `firestore.rules` (repo root) into Firestore → Rules → Publish.

Leave `lib/firebase-config.js` as-is (empty `apiKey`) to stay in local-only
mode forever — nothing else changes.

Implementation note: this uses the plain Firebase REST APIs (Identity
Toolkit + Firestore v1) via `fetch()`, not the bundled JS SDK — same
capability, far smaller footprint, nothing to build/bundle.

**Security note (read `firestore.rules` for the full comment):** these rules
stop user A from reading/writing user B's document. They do **not** make
the gate un-forgeable by the document's own owner via devtools — no
purely-client extension can do that without a trusted backend, and since
Instagram doesn't expose a "does user X follow account Y" API anyway, that
limitation is inherent to the feature, not a shortcut taken here.

---

## Everything from before, still intact

**URL / domain analysis** — HTTPS check, punycode/IDN, `user@host` tricks,
raw-IP hosts, non-standard ports, excessive subdomains, hyphenation, long
domains, abused TLDs, phishing wording, brand impersonation, look-alike/
typosquat detection, suspicious redirect params, heavy percent-encoding.

**Header analysis** — HSTS, CSP, clickjacking protection, X-Content-Type-
Options, Referrer-Policy, Permissions-Policy, cross-domain/HTTPS-downgrade
redirects.

**UI** — dark navy cyber dashboard, animated background (drifting glow,
panning grid, rising particles), glowing score ring, color-coded signal
cards, glassmorphism panels, neon cyan/blue accents with red/amber reserved
for warnings, link-check bar, full-screen mode via the expand icon, toolbar
risk badge, on-page warning banner (Shadow DOM, isolated from the page),
small CybroatriX footer credit.

---

## Permissions, and why

| Permission | Why it's needed |
|---|---|
| `activeTab` / `tabs` | Read the current tab's URL; let "Go back to safety" navigate it. |
| `storage` | `chrome.storage.local` for all reliability state (and `chrome.storage.session`-free — we use an in-memory Map in the background service worker for block reasons instead, see `lib/blocking.js`). |
| `webNavigation` | **New.** Lets `lib/blocking.js` detect and pre-empt dangerous navigations before the page loads. |
| `host_permissions` (`http`/`https`) | The passive `HEAD` request used for header checks, and the on-page banner. |

No browsing history, page content, or personal data is collected beyond
what's described above, and Firebase sync (if you enable it) only ever
carries the four reliability fields — never the sites you've actually
visited or checked.

## Testing

```
node tests/state.test.mjs      # manual-scan gating: 1st/2nd/3rd/4th scan,
                                # already-verified user, stop-scan independence
node tests/blocking.test.mjs   # dangerous vs. safe URL classification,
                                # approve-once/Continue-Anyway bookkeeping
```

Both stub `chrome.storage.local` / `chrome.tabs` / `chrome.webNavigation`
just enough to exercise the real logic in Node, no browser required. For the
UI itself (modal, blocked page, stop-scan toggle, all the existing scan
flows), load the extension unpacked and click through — every flow above was
also visually verified with mocked Chrome APIs before shipping this build.

## Honest scope

TrustLink is a **client-side heuristic assistant**, not a full vulnerability
scanner or malware/phishing-reputation service, and its gating/reliability
features are best-effort, not unbeatable (see the security notes in
`lib/state.js` and `firestore.rules`). A low score means no common red flags
were found by these specific checks — it doesn't certify a site is safe.
Consider adding a reputable phishing/malware-reputation API through a small
backend to complement these local heuristics before any public release.

## File structure

```
manifest.json            Manifest V3 configuration
analyzer.js               Shared scoring engine (URL + header heuristics)
background.js             Service worker — routes messages, orchestrates everything below
content.js                 Automatic Scanner: on-page checks + warning banner
ui-core.js                 Shared rendering logic (popup/app/blocked pages)
popup.html/css/js          Toolbar popup UI
app.html/css/js            Full-screen link-checker page
blocked.html/css/js        Dangerous-page interstitial
lib/state.js                Manual-scan gating + Instagram-confirm state machine
lib/blocking.js             Pre-navigation dangerous-URL detection & blocking
lib/firebaseSync.js         Firebase Auth + Firestore sync via REST (optional)
lib/firebase-config.js      Your Firebase project config goes here (optional)
firestore.rules            Firestore security rules to paste into your project
tests/state.test.mjs        Gating logic tests (run with plain `node`)
tests/blocking.test.mjs     Blocking logic tests (run with plain `node`)
icon16/32/48/128.png       TrustLink logo
cybroatrix-logo.png         Footer credit mark
```

## Developed by

Built by **[GitHub](https://github.com/anandsekar-404)**, **[LinkedIn](https://www.linkedin.com/in/anand1802)**, **[Instagram](https://www.instagram.com/404.ech0?igsh=dXNjdHd0b2ZyYjNj)** — anand.404 on Discord.

## Contact

- Instagram: [@404.ech0](https://www.instagram.com/404.ech0?igsh=dXNjdHd0b2ZyYjNj)
- LinkedIn: [anand1802](https://www.linkedin.com/in/anand1802)
- GitHub: [anandsekar-404](https://github.com/anandsekar-404)
- Discord: anand.404
