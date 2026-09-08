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

## TrustLink V2 — Firebase Remote Config + Local Threat Intelligence

### 5. Firebase Remote Config (remote-tunable detection rules)

TrustLink's detection weights, thresholds, and per-feature on/off switches
can now be tuned from the Firebase Console **without a new Chrome Web Store
release**. This uses raw Firebase REST calls (`lib/remoteConfig.js`) —
Firebase Installations, then Remote Config's fetch endpoint — the same
"REST over the bundled SDK" choice already made for Firestore sync in
`lib/firebaseSync.js`, since this project intentionally ships with no
build step.

**The rest of the extension never talks to Firebase directly.** Everything
goes through one function, `getTrustLinkConfig()`, which always returns a
complete, validated config — from Remote Config if a fresh fetch just
succeeded, from the last good cache if not, or TrustLink's built-in
defaults (`lib/heuristics/defaults.js`) if neither is available:

```
Firebase Remote Config → validate → cache (chrome.storage.local) → Detection Engine
                ↓ (unavailable / invalid)
         last good cache
                ↓ (no cache exists yet)
         built-in defaults
```

A Firebase outage, a slow network, or a malformed publish can never break
TrustLink's own detection — the worst case is that TrustLink keeps using
whatever configuration it already trusted.

**To turn Remote Config on:**
1. Firebase Console → your project (`trsutlink`) → **Remote Config** →
   create the parameters from the table below (all optional — anything you
   don't create just uses TrustLink's built-in default).
2. Publish. TrustLink picks it up on its next scheduled fetch (see
   "Fetch behavior" below) — no extension update needed.

`lib/firebase-config.js` already contains this project's public Web App
config (`apiKey`, `projectId`, `messagingSenderId`, `appId`). **This is not
a secret** — Firebase web API keys are meant to be public; nothing about
access control depends on hiding it. No Admin SDK key, service-account
JSON, or any other credential is (or should ever be) present in this
repository.

**Fetch behavior / caching:** TrustLink respects a minimum fetch interval
(`system_min_fetch_interval_ms`, defaults to 1 hour — Remote Config's own
production default) between network attempts; calls inside that window
return the cached config immediately with zero network I/O. The
pre-navigation blocker (`lib/blocking.js`) specifically uses
`getCachedTrustLinkConfig()`, which **never** fetches — it must stay fast,
so it always reads whatever was last cached and relies on the normal scan
flow in `background.js` to keep that cache warm.

**Validation:** every parameter is checked independently
(`lib/configValidation.js`) — wrong type, out-of-range, or an unrecognized
key keeps that ONE parameter at its previous safe value rather than
discarding an otherwise-good publish. A structurally broken response (not
valid JSON / wrong shape) is rejected wholesale, and the four risk
thresholds are validated as an ordered *set* (`critical > high > medium >
low`) — if a publish breaks that ordering, all four fall back together
rather than mixing old and new.

**Note on `risk_*_threshold`:** these are informational display-tier
groupings only. They do **not** change what "Looks Safe / Use Caution /
High Risk" mean — those three tiers stay fixed at the original 0/30/60
boundaries in `analyzer.js`'s `grade()` on purpose, so remote tuning can
never quietly redefine what those labels mean for every existing user. The
one score-independent thing that *can* change a result's tier is a
confirmed threat-database match — see the CRITICAL tier below.

#### Remote Config parameter table

| Parameter | Type | Default | Purpose |
|---|---|---|---|
| `detection_no_https_score` | Number | 26 | Score added when the page isn't HTTPS |
| `detection_ip_url_score` | Number | 22 | Raw IP literal instead of a domain |
| `detection_punycode_score` | Number | 30 | Domain uses `xn--` (IDN) encoding |
| `detection_homograph_score` | Number | 28 | Decoded IDN label has a confusable/look-alike character |
| `detection_typosquatting_score` | Number | 30 | Domain is 1–2 edits from a protected brand |
| `detection_brand_impersonation_score` | Number | 28 | Brand name present, wrong domain |
| `detection_suspicious_tld_score` | Number | 10 | Domain uses a frequently-abused TLD |
| `detection_suspicious_keyword_score` | Number | 16 | 2+ sensitive-action keywords in the URL |
| `detection_excessive_subdomain_score` | Number | 12 | 5+ label subdomain chain |
| `detection_userinfo_score` | Number | 34 | `user@host` misleading-URL trick |
| `detection_nonstandard_port_score` | Number | 8 | Non-standard port |
| `detection_hyphenated_domain_score` | Number | 12 | Heavily hyphenated domain |
| `detection_long_url_score` | Number | 6 | Very long hostname |
| `detection_encoded_url_score` | Number | 6 | Heavy percent-encoding |
| `detection_redirect_score` | Number | 14 | Off-site redirect query parameter |
| `detection_cross_domain_redirect_score` | Number | 18 | Actual navigation redirected cross-domain |
| `detection_https_downgrade_score` | Number | 24 | Redirected from HTTPS to HTTP |
| `risk_low_threshold` / `risk_medium_threshold` / `risk_high_threshold` / `risk_critical_threshold` | Number | 20 / 40 / 70 / 90 | Informational display bands only — see note above |
| `feature_openphish` | Boolean | `true` | Enable OpenPhish local threat-database matching |
| `feature_phishtank` | Boolean | `false` | Reserved — see PhishTank status below |
| `feature_urlhaus` | Boolean | `false` | Reserved — see URLhaus status below |
| `feature_homograph` | Boolean | `true` | Enables both punycode and homograph decoding |
| `feature_typosquatting` | Boolean | `true` | Enables the edit-distance brand check |
| `feature_redirect` | Boolean | `true` | Enables both redirect-param and redirect-response checks |
| `feature_brand_detection` | Boolean | `true` | Enables the brand-impersonation check |
| `feature_url_obfuscation` | Boolean | `true` | Enables the userinfo/port/hyphenation/long-host/encoding group |
| `feature_ip_detection` | Boolean | `true` | Enables the raw-IP check |
| `feature_suspicious_tld` | Boolean | `true` | Enables the abused-TLD check |
| `feature_page_analysis` | Boolean | `false` | Reserved — not implemented client-side yet |
| `protection_emergency_enabled` | Boolean | `true` | Master flag — see note below |
| `disable_openphish` / `disable_phishtank` / `disable_homograph` / `disable_typosquatting` / `disable_redirect` / `disable_page_analysis` | Boolean | `false` | Individual emergency kill-switches |
| `protectedBrands` | JSON array string | 18 well-known domains | e.g. `["paypal.com","google.com",...]` |
| `suspiciousTlds` | JSON array string | 24 TLDs | e.g. `["zip","top","xyz",...]` |
| `suspiciousKeywords` | JSON array string | 24 keywords | e.g. `["login","verify","wallet",...]` |
| `redirectParamNames` | JSON array string | 10 names | e.g. `["url","redirect","next",...]` |
| `system_feed_update_interval_ms` | Number | 43200000 (12h) | How often the OpenPhish feed is refreshed |
| `system_min_fetch_interval_ms` | Number | 3600000 (1h) | Remote Config's own minimum fetch interval |

List-type parameters (`protectedBrands`, `suspiciousTlds`,
`suspiciousKeywords`, `redirectParamNames`) must be entered in the Firebase
Console as a JSON array **string** (Remote Config only stores strings) —
e.g. the parameter value is literally the text `["paypal.com","google.com"]`.

**Important — `protection_emergency_enabled` never disables everything by
itself.** It's a namespacing flag for the `disable_*` switches, not a
kill-all. Setting it `true` with no individual `disable_*` switches set has
*zero* effect; you still turn off a specific detector via its own
`disable_x` parameter. This is deliberate — see spec/test coverage in
`tests/remoteConfig.test.mjs` — an emergency response should be able to
turn off one broken/noisy detector without silently blinding the entire
extension.

**Firebase limitations, stated plainly:** Remote Config has a real backend
minimum fetch interval in production (TrustLink defaults to matching it —
1 hour); fetching more aggressively than that will eventually be throttled
by Firebase itself, not just by TrustLink's own client-side check. Remote
Config is not designed to hold large datasets — see the next section for
where the actual threat data lives.

### 6. Local threat intelligence (OpenPhish / PhishTank / URLhaus)

TrustLink now maintains a **local, offline-queryable threat database**
(`lib/threatDb.js`, IndexedDB-backed) that's checked before the heuristic
score is finalized. A match here is a *confirmed* known-bad indicator, not
a guess — and it's the **only** thing that produces the new **Critical**
tier (`tone: "critical"`), one level above the original "High Risk," shown
with a `⛔` badge and a distinct dark-red color throughout the UI. Nothing
about the original three tiers (Looks Safe / Use Caution / High Risk) or
their 0/30/60 boundaries changed.

**The lookup is 100% local.** TrustLink downloads a threat feed in bulk on
a schedule and matches every URL you visit against its own local database —
it never sends the URL you're checking to OpenPhish, PhishTank, URLhaus, or
anyone else.

| Source | Status | Why |
|---|---|---|
| **OpenPhish** (community feed) | ✅ Active by default | Free, keyless, plain-text feed at `openphish.com/feed.txt`, refreshed roughly every 12 hours. **Non-commercial use only**, per OpenPhish's published terms — keep that in mind if TrustLink is ever monetized. |
| **PhishTank** | ❌ Not integrated (documented, not faked) | PhishTank has not accepted new API-key registrations since 2020. There is currently no officially-available keyless path to their data for a new project, so `lib/adapters/phishtank.js` is a real, working module that makes zero network calls and reports exactly why. `feature_phishtank` defaults to `false`. |
| **URLhaus** (abuse.ch) | ⏸️ Disabled by default, bring-your-own key | abuse.ch now requires a free Auth-Key for essentially all API/feed access (their older keyless downloads were retired). Registration is free and self-service at abuse.ch. Supply your own key in `lib/adapters/urlhaus.js` and flip `feature_urlhaus` to `true` to enable it — it stays completely inert otherwise. |

**Update mechanism:** `background.js` kicks off a best-effort OpenPhish
refresh once per service-worker wake, which itself no-ops if the feed was
refreshed more recently than `system_feed_update_interval_ms` — there's no
aggressive polling loop. A download is validated (size ceiling, minimum
entry count, per-line URL parsing with malformed lines dropped and counted,
not stored) before it's allowed to replace the previous database at all; a
failed or suspicious-looking download leaves the previous, still-valid
database completely untouched (`tests/openphish.test.mjs` covers this
directly, including "5 lines when 60+ were expected" and "network dies
mid-update").

**No per-URL API key or paid lookup is required** for OpenPhish matching —
"unlimited" here specifically means unlimited *local* lookups against the
already-downloaded database, never unlimited feed downloads or provider API
calls. TrustLink does not bypass, rotate around, or claim to exceed any
provider's stated rate limits, authentication requirements, or licensing.

### 7. Developer diagnostics

Two new internal message types (not exposed in the popup UI, meant for
`chrome://extensions` → service worker console, or your own debug build of
the popup):

- `{ type: "getDebugStatus" }` → Firebase connection/config status
  (source: remote/cache/default, last successful fetch, validity, any
  rejected parameter keys) plus each threat source's database status and
  entry count.
- `{ type: "forceRefreshThreatData" }` → bypasses both Remote Config's and
  the OpenPhish adapter's normal throttling for an immediate refresh.

---

## Everything from before, still intact

**URL / domain analysis** — HTTPS check, punycode/IDN, `user@host` tricks,
raw-IP hosts, non-standard ports, excessive subdomains, hyphenation, long
domains, abused TLDs, phishing wording, brand impersonation, look-alike/
typosquat detection, suspicious redirect params, heavy percent-encoding.
As of V2 each of these lives in its own file under `lib/heuristics/`
(independently testable, independently enable/disable-able via Remote
Config), with `analyzer.js` acting purely as the coordinator — see "What's
in this upgrade" above.

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
| `storage` | `chrome.storage.local` for all reliability state, the Remote Config cache, and Firebase Installations credentials (see below) — plus an in-memory Map in the background service worker for block reasons (`lib/blocking.js`). |
| `webNavigation` | Lets `lib/blocking.js` detect and pre-empt dangerous navigations before the page loads. |
| `host_permissions` (`http`/`https`) | The passive `HEAD` request used for header checks, the on-page banner, the OpenPhish feed download, and the Firebase REST calls. |

**V2 added zero new permissions.** The existing `https://*/*` host
permission already covers every new destination (OpenPhish, Firebase
Installations, Firebase Remote Config) — no manifest change beyond the
version bump was needed, and IndexedDB (the local threat database) doesn't
require a permission at all.

No browsing history, page content, or personal data is collected beyond
what's described above. Remote Config only ever receives TrustLink's own
install identifier (for Firebase's per-app scoping) — never the sites you
visit or check. Firebase sync (if you enable it, see section 4) only ever
carries the four reliability fields, also never the sites you've visited.

## Testing

```
node tests/state.test.mjs             # manual-scan gating: 1st/2nd/3rd/4th scan,
                                       # already-verified user, stop-scan independence
node tests/blocking.test.mjs          # dangerous vs. safe URL classification,
                                       # approve-once/Continue-Anyway bookkeeping,
                                       # end-to-end pre-nav listener, Critical-tier threat-DB blocking
node tests/heuristics.test.mjs        # every lib/heuristics/*.js detector individually,
                                       # feature-flag + emergency-switch gating
node tests/configValidation.test.mjs  # Remote Config per-parameter validation,
                                       # wholesale rejection, threshold-ordering
node tests/remoteConfig.test.mjs      # Installations + Remote Config REST flow,
                                       # cache/fallback chain, throttling, emergency config
node tests/openphish.test.mjs         # feed download/parse/validate/publish,
                                       # malformed/duplicate/empty feeds, failed-update safety
node tests/threatDb.test.mjs          # local threat database: exact-match lookup,
                                       # per-source atomic replace, metadata accuracy
```

Or run everything at once:

```
for f in tests/*.test.mjs; do node "$f" || break; done
```

All of the above stub `chrome.storage.local` / `chrome.tabs` /
`chrome.webNavigation` and mock `fetch` just enough to exercise the real
logic in plain Node — no browser, no real network access, and no real
Firebase project required to run the test suite. `lib/threatDb.js`
specifically uses a real IndexedDB in the actual extension but
automatically falls back to an equivalent in-memory store when `indexedDB`
isn't present (i.e., in this Node test environment), so the exact same
code path is exercised by the tests with no special-casing.

For the UI itself (modal, blocked page, Critical-tier styling, stop-scan
toggle, debug status), load the extension unpacked and click through.

## Honest scope

TrustLink is a **client-side heuristic assistant** augmented with one real
threat-intelligence source (OpenPhish's free community feed), not a full
vulnerability scanner or a paid multi-source reputation service. Its
gating/reliability features are best-effort, not unbeatable (see the
security notes in `lib/state.js` and `firestore.rules`). A "Looks Safe" or
"Use Caution" result means no common red flags were found by these
specific checks and heuristics — it doesn't certify a site is safe. Only a
**Critical** result (an exact match in the local OpenPhish database) is a
confirmed detection rather than a heuristic judgment call, and even that is
data as recent as OpenPhish's last feed publish (up to ~12 hours old), not
a live, real-time check. PhishTank and URLhaus are documented as
unavailable/optional rather than faked — see the Threat Intelligence
section above for exactly why.

## File structure

```
manifest.json               Manifest V3 configuration
analyzer.js                  Passive risk-scoring COORDINATOR (URL + header heuristics);
                              delegates individual signals to lib/heuristics/*.js
background.js                Service worker — routes messages, orchestrates Remote Config,
                              the threat database, and the scoring pipeline
content.js                   Automatic Scanner: on-page checks + warning banner
ui-core.js                   Shared rendering logic (popup/app/blocked pages)
popup.html/css/js            Toolbar popup UI
app.html/css/js              Full-screen link-checker page
blocked.html/css/js          Dangerous/Critical-page interstitial
lib/state.js                 Manual-scan gating + Instagram-confirm state machine
lib/blocking.js              Pre-navigation dangerous/Critical-URL detection & blocking
lib/firebaseSync.js          Firebase Auth + Firestore sync via REST (optional, gating state)
lib/firebase-config.js       Firebase Web App config (Remote Config + Firestore sync)
lib/remoteConfig.js          RemoteConfigManager: REST fetch, validate, cache, fallback
lib/configValidation.js      Per-parameter Remote Config validation rules
lib/threatDb.js              Local threat database (IndexedDB, auto in-memory fallback)
lib/urlUtils.js              Shared URL parsing, punycode decoder, normalization
lib/heuristics/              One file per detection signal + the registry (index.js)
lib/adapters/openphish.js    OpenPhish community feed downloader/validator
lib/adapters/phishtank.js    Documented no-op — see Threat Intelligence status above
lib/adapters/urlhaus.js      Bring-your-own-key adapter, disabled by default
firestore.rules              Firestore security rules to paste into your project
tests/*.test.mjs             Full test suite (run with plain `node`, see Testing above)
icon16/32/48/128.png         TrustLink logo
cybroatrix-logo.png          Footer credit mark
```

## Developed by

Built by **[GitHub](https://github.com/anandsekar-404)**, **[LinkedIn](https://www.linkedin.com/in/anand1802)**, **[Instagram](https://www.instagram.com/404.ech0?igsh=dXNjdHd0b2ZyYjNj)** — anand.404 on Discord.

## Contact

- Instagram: [@404.ech0](https://www.instagram.com/404.ech0?igsh=dXNjdHd0b2ZyYjNj)
- LinkedIn: [anand1802](https://www.linkedin.com/in/anand1802)
- GitHub: [anandsekar-404](https://github.com/anandsekar-404)
- Discord: anand.404


## Build-time Firebase API key injection

The source repository contains a placeholder instead of the Firebase Web API key.
Run `npm run build` with `TRUSTLINK_FIREBASE_API_KEY` set to create `dist/` with
the key injected. Without the variable, the build is local-only and uses the
built-in TrustLink detection defaults.

For GitHub Actions, add a repository secret named
`TRUSTLINK_FIREBASE_API_KEY`. The included workflow passes it only to the build
step. The key is public Firebase client configuration by design; this workflow
keeps it out of the source repository, but it cannot make the key secret inside
the final Chrome extension package.
