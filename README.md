# 🛡️ TrustLink V2

<div align="center">

### 🔗 Verify the Link. Protect the Click.

**A privacy-focused Chrome Manifest V3 extension for detecting suspicious and potentially dangerous URLs before you trust them.**

<br>

<img src="https://readme-typing-svg.demolab.com?font=Fira+Code&size=22&duration=3000&pause=1000&center=true&vCenter=true&width=600&lines=Scan+Suspicious+URLs;Detect+Phishing+Indicators;Analyze+Threat+Intelligence;Protect+Before+You+Click" alt="TrustLink Animation">

</div>

---

## 🚀 What is TrustLink?

**TrustLink V2** is a modern browser security assistant that analyzes URLs in real time using modular security heuristics, local threat intelligence, and passive response header analysis.

It provides a transparent **0–100 risk score**, explains detected security signals in plain language, and proactively blocks navigation to high-risk or known-malicious pages before content loads.

> ⚠️ TrustLink provides passive risk analysis and does not guarantee that a website is completely safe or malicious.

---

## ✨ V2 Key Features

### 🔍 URL Security Analysis
- 🔍 **0–100 Transparent Risk Score:** Instant classification into Looks Safe, Use Caution, High Risk, or Known Threat.
- 🧠 **Modular Security Heuristics:** 12 independent detectors covering homographs, typosquatting, abused TLDs, and obfuscated URLs.
- 🏷️ **Brand Impersonation Defense:** Tokenized matching against protected brands with official domain exclusions and ccTLD awareness.
- 🎭 **Confusable & Homograph Detection:** Decodes RFC 3492 Punycode labels to detect mixed-script Unicode spoofing.
- ⚡ **Compound Phishing Bonus:** Correlates brand impersonation with untrusted infrastructure (raw IP, HTTP, suspicious TLD, credential words).
- 🛡️ **Passive Header Analysis:** Non-blocking capture of HSTS, CSP, X-Frame-Options, and X-Content-Type-Options without issuing duplicate network requests.

### 🛑 Protection & Credential Guard
- 🛑 **Pre-Navigation Interception:** Stops high-risk or threat-matched navigations on `onBeforeNavigate` and displays a detailed interstitial (`blocked.html`).
- 🔑 **Credential Form Harvest Guard:** Alerts if a password form submits credentials off-site to a different registrable domain.
- 🗄️ **Local Threat Database:** Offline IndexedDB cache storing OpenPhish community feed indicators for instant $O(1)$ lookups.
- 🔒 **Shadow DOM Encapsulation:** Warning banners render in closed Shadow DOM with CSS reset (`all: initial`) preventing host-page styling interference.

### ⚙️ Remote Config & State
- ⚙️ **Firebase Remote Config:** Fine-tune weights, feature toggles, and brand lists remotely without extension republishing.
- 🛡️ **Tamper-Proof Validation:** Enforces minimum floors, weight ceilings (5–65), monotonic threshold ordering, and prevents disabling threat feeds.
- 🔄 **State Persistence:** Local-first storage (`chrome.storage.local` / `chrome.storage.session`) with optional Firestore synchronization.

---

## 🧭 How It Works

```text
        🔗 Target URL
              │
              ▼
    ┌───────────────────┐
    │  URL Normalizer   │
    └─────────┬─────────┘
              │
              ▼
    ┌───────────────────┐
    │  Local Threat DB  │ ──► [Confirmed Match?] ──► 🚨 Known Threat (Score: 100)
    └─────────┬─────────┘                                    │
              │ (No match)                                   ▼
              ▼                                        Redirect Tab to
    ┌───────────────────┐                             blocked.html
    │ Modular Heuristics│
    └─────────┬─────────┘
              │
              ▼
    ┌───────────────────┐
    │  Compound Scoring │
    └─────────┬─────────┘
              │
              ▼
       📊 Risk Score
              │
       ┌──────┴────────────────────────┐
       ▼                               ▼
    🟢 Looks Safe (<30)         🔴 High Risk (≥60)
    🟡 Use Caution (30–59)             │
                                       ▼
                              Redirect Tab to
                              blocked.html
```

### 📊 Risk Levels

| Score | Tone / Label | Meaning & User Guidance |
|---|---|---|
| 🟢 **0–29** | **Looks Safe** | No strong warning signs detected by TrustLink's passive checks. |
| 🟡 **30–59** | **Use Caution** | Double-check the address bar; avoid entering sensitive information until verified. |
| 🔴 **60–100** | **High Risk** | Multiple high-risk signals; do not enter passwords, payment details, or download files. |
| 🚨 **Confirmed Match** | **Known Threat** | Exact indicator matched in local threat intelligence (OpenPhish). Navigation blocked. |

---

## 🔬 Example Analysis

```text
🔗 URL: https://paypal.secure-login.xyz
  ↓
🧠 Detected Signals:
  • Brand Impersonation: References "paypal" on foreign domain "secure-login.xyz" (+28)
  • Abused TLD: ".xyz" top-level domain (+10)
  • Phishing Keywords: Contains "secure" and "login" (+16)
  • High-Risk Combination: Brand look-alike paired with suspicious infrastructure (+20)
  • Baseline: (+2)
  ↓
📊 Risk Score: 76 / 100 — 🔴 HIGH RISK
  ↓
🛑 Pre-Navigation Action: Tab immediately redirected to blocked.html
```

---

## 🔐 Privacy & Safety Principles

TrustLink is architected from the ground up to respect user privacy:

- **100% Local Evaluation:** All heuristic evaluations and threat lookups occur locally on the user's machine.
- **Zero Browsing History Uploads:** URLs, visited domains, search queries, and form inputs are **never** transmitted to any remote server.
- **Passive Inspection:** Zero port scanning, automated exploitation, brute-forcing, or disruptive network probing.
- **Privacy-Preserving Probes:** Query strings and hash fragments are stripped before optional active HEAD checks.
- **Least Privilege:** Declarative Manifest V3 permissions strictly scoped and documented in [`TrustLink-v1/STORE_JUSTIFICATION.md`](TrustLink-v1/STORE_JUSTIFICATION.md).

---

## 🏗️ Architecture

```text
                     ┌───────────────────┐
                     │     TrustLink     │
                     └─────────┬─────────┘
                               │
               ┌───────────────┼───────────────┐
               │               │               │
               ▼               ▼               ▼
         🔍 Detection    🛡️ Threat Intel   ⚙️ Config
               │               │               │
               ▼               ▼               ▼
         URL Heuristics    OpenPhish        Remote Config
         Brand Detection   IndexedDB        Validation
         Homograph / IDN   Threat DB        REST Client
         Redirects / HSTS  Atomic Replace   Offline Fallback
               │               │
               └───────┬───────┘
                       ▼
                 📊 Risk Engine
                       │
                       ▼
         ┌─────────────┴─────────────┐
         ▼                           ▼
  ⚠️ On-Page Banner           🛑 Pre-Navigation
  (Closed Shadow DOM)         (blocked.html Interstitial)
```

---

## 📁 Project Structure

```text
TrustLink-v1/
├── manifest.json              # Chrome Manifest V3 manifest
├── background.js              # Service worker: passive webRequest, badges, messaging
├── analyzer.js                # Risk engine coordinator & compound scoring bonus
├── content.js                 # Automatic page scanner, credential guard & banner
├── ui-core.js                 # Shared UI rendering logic
├── popup.html / css / js      # Toolbar popup UI & link scanner
├── blocked.html / css / js    # Pre-navigation interstitial block page
├── app.html / css / js        # Full-screen link inspector
├── STORE_JUSTIFICATION.md     # Chrome Web Store review documentation
│
├── lib/
│   ├── blocking.js            # Pre-navigation interception & bypass session store
│   ├── configValidation.js    # Remote Config boundary & floor validation
│   ├── firebase-config.js     # Public Firebase Web App client configuration
│   ├── firebaseSync.js        # Optional Firestore synchronization via REST
│   ├── remoteConfig.js        # REST Remote Config client with offline caching
│   ├── state.js               # Scan count quotas & auto-scan toggling
│   ├── threatDb.js            # IndexedDB threat database with in-memory fallback
│   ├── urlUtils.js            # MULTI_TLD parser, Punycode decoder & normalizer
│   │
│   ├── adapters/
│   │   ├── openphish.js       # OpenPhish community feed streaming parser
│   │   ├── phishtank.js       # Documented no-op adapter (API retired)
│   │   └── urlhaus.js         # Opt-in bring-your-own-key adapter
│   │
│   └── heuristics/            # 12 Modular detection heuristics
│       ├── brandImpersonation.js
│       ├── defaults.js
│       ├── homograph.js
│       ├── index.js
│       ├── ipUrl.js
│       ├── punycode.js
│       ├── redirect.js
│       ├── suspiciousKeywords.js
│       ├── suspiciousSubdomain.js
│       ├── suspiciousTld.js
│       ├── typosquatting.js
│       └── urlObfuscation.js
│
├── tests/                     # 9 Complete Node.js unit test suites
└── firestore.rules            # Firestore security rules
```

---

## 📥 Installation

### 1️⃣ Clone the Repository
```bash
git clone https://github.com/anandsekar-404/WebSecurity-Scanner.git
```

### 2️⃣ Open Chrome Extensions
Navigate to:
```text
chrome://extensions
```

### 3️⃣ Enable Developer Mode
Turn on the **Developer mode** toggle in the top-right corner.

### 4️⃣ Load TrustLink
Click **Load unpacked**, then select the `TrustLink-v1` directory inside the cloned repo.

### 5️⃣ Pin TrustLink
Pin TrustLink from the Chrome Extensions toolbar for quick access.

---

## 🧪 Running Tests

Tests run directly in Node.js using native ES modules and Node's built-in test runner:

```bash
cd TrustLink-v1
npm test
```

Or run individual test suites:
```bash
node tests/blocking.test.mjs
node tests/heuristics.test.mjs
node tests/securityHardening.test.mjs
node tests/openphish.test.mjs
node tests/remoteConfig.test.mjs
node tests/configValidation.test.mjs
node tests/threatDb.test.mjs
node tests/state.test.mjs
node tests/firebaseSync.test.mjs
```

---

## ⚠️ Disclaimer

TrustLink uses security heuristics, response headers, and threat-intelligence indicators to estimate risk. A low score does not guarantee absolute safety, and a high score does not by itself prove malicious intent. Always exercise caution when entering passwords or downloading files.

<div align="center">

🛡️ **Think Before You Click.**

<img src="https://readme-typing-svg.demolab.com?font=Fira+Code&size=20&duration=2500&pause=800&center=true&vCenter=true&width=550&lines=Detect.;Analyze.;Verify.;Protect.;TrustLink+V2+%F0%9F%9B%A1%EF%B8%8F" alt="TrustLink Animation">

**TrustLink V2 — Verify the Link. Protect the Click.**

</div>
