# 🛡️ TrustLink V2

<div align="center">

![TrustLink](https://img.shields.io/badge/TrustLink-Verify%20the%20Link.%20Protect%20the%20Click.-00d4ff?style=for-the-badge)

### 🔗 Verify the Link. Protect the Click.

**A privacy-focused Chrome extension that detects suspicious and potentially dangerous URLs before you trust them.**

![Chrome](https://img.shields.io/badge/Chrome-Extension-brightgreen?style=flat-square)
![Manifest V3](https://img.shields.io/badge/Manifest-V3-blue?style=flat-square)
![Version](https://img.shields.io/badge/Version-2.0-purple?style=flat-square)
![Cybersecurity](https://img.shields.io/badge/Focus-Cybersecurity-red?style=flat-square)

</div>

---

## 🚀 About

**TrustLink V2** is a browser security extension that analyzes URLs using multiple security signals and threat-intelligence sources.

It provides a simple **0–100 risk score** and explains why a URL may be suspicious.

V2 adds a modular detection system, local threat intelligence, Remote Config support, and stronger threat handling.

> ⚠️ TrustLink provides a risk assessment. It does not guarantee that a website is completely safe or malicious.

---

## ✨ V2 Features

### 🔍 Smart URL Analysis

TrustLink checks multiple suspicious URL characteristics, including:

- 🔒 Missing HTTPS
- 🌐 Punycode domains
- 🎭 Homograph/look-alike domains
- 📍 IP-based URLs
- 🔗 URL obfuscation
- 🌍 Suspicious TLDs
- 🧪 Suspicious keywords
- 🏷️ Brand impersonation
- 🔀 Suspicious redirects
- 🌐 Suspicious subdomains
- ✏️ Typosquatting

---

### 🛡️ Threat Intelligence

V2 introduces a local threat-intelligence system with support for:

- OpenPhish
- PhishTank
- URLhaus

Threat data can be stored locally and checked against URLs during analysis.

Known threats can receive a **Critical / Known Threat** result instead of relying only on heuristic scoring.

---

### 📊 Risk Scoring

TrustLink uses a **0–100 risk score**:

| Score | Risk |
|---|---|
| 🟢 0–29 | Looks Safe |
| 🟡 30–59 | Use Caution |
| 🔴 60–100 | High Risk |
| 🚨 Confirmed threat | Critical / Known Threat |

The result also includes the reasons detected by TrustLink.

---

### ⚙️ Modular Detection

V2 separates detection logic into independent heuristic modules.

```text
lib/heuristics/
├── punycode.js
├── homograph.js
├── typosquatting.js
├── brandImpersonation.js
├── suspiciousTld.js
├── suspiciousSubdomain.js
├── ipUrl.js
├── urlObfuscation.js
├── redirect.js
└── suspiciousKeywords.js

This makes the detection system easier to test, maintain, and improve.

☁️ Remote Configuration

TrustLink V2 supports optional Firebase Remote Config for remotely managing safe configuration values such as:

Detection weights
Risk thresholds
Feature flags

Remote configuration is validated before being used.

If Remote Config is unavailable, TrustLink falls back to built-in defaults.

🔥 Firebase / Firestore

Firestore synchronization is available as an optional feature.

By default:

Firestore Sync: OFF

TrustLink remains functional without enabling Firestore synchronization.

🔐 Privacy First

TrustLink is designed around privacy and passive security analysis.

It does not attempt to:

❌ Exploit websites
❌ Attack servers
❌ Brute-force targets
❌ Flood websites
❌ Perform intrusive scanning

Threat-intelligence data can be cached locally to reduce unnecessary requests.

🧪 Testing

V2 includes dedicated tests for:

Heuristics
Threat database
OpenPhish
Remote Config
Configuration validation
Firebase synchronization
Blocking
State management

Run the tests:

for f in tests/*.test.mjs; do node "$f" || break; done

On Windows PowerShell:

Get-ChildItem tests\*.test.mjs | ForEach-Object { node $_.FullName }
📁 Project Structure
TrustLink-v1/
│
├── manifest.json
├── analyzer.js
├── background.js
├── content.js
├── popup.html
├── popup.css
├── popup.js
├── blocked.html
├── blocked.css
├── blocked.js
├── ui-core.js
│
├── lib/
│   ├── adapters/
│   │   ├── openphish.js
│   │   ├── phishtank.js
│   │   └── urlhaus.js
│   │
│   ├── heuristics/
│   ├── configValidation.js
│   ├── remoteConfig.js
│   ├── threatDb.js
│   ├── urlUtils.js
│   ├── firebase-config.js
│   ├── firebaseSync.js
│   ├── blocking.js
│   └── state.js
│
└── tests/
📥 Installation
1. Clone the repository
git clone https://github.com/anandsekar-404/WebSecurity-Scanner.git
2. Open Chrome
chrome://extensions
3. Enable

Developer mode

4. Select

Load unpacked

5. Choose
TrustLink-v1/

That's it. 🚀

🛠️ Built With
JavaScript (ES6+)
HTML5
CSS3
Chrome Extensions API
Chrome Manifest V3
Chrome Storage API
Firebase / Firestore
Threat Intelligence Feeds
⚠️ Disclaimer

TrustLink uses heuristics and threat-intelligence data to estimate website risk.

A low score does not guarantee safety, and a high score does not always prove malicious activity unless supported by confirmed threat intelligence.

Always verify important websites and avoid entering sensitive information on suspicious pages.

🔮 V3 Roadmap

Planned improvements include:

 Pre-navigation protection
 Right-click URL analysis
 Hover link analysis
 Explainable security reports
 Redirect-chain analysis
 Improved brand impersonation detection
 Domain intelligence
 Risk history
 Enhanced threat intelligence
<div align="center">
🛡️ Think Before You Click.

TrustLink — Verify the Link. Protect the Click.

⭐ If you find TrustLink useful, consider giving the repository a star!

</div>
