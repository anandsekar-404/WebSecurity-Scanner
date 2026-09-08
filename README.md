# 🛡️ TrustLink V2

<div align="center">

### 🔗 Verify the Link. Protect the Click.

**A privacy-focused Chrome extension for detecting suspicious and potentially dangerous URLs before you trust them.**

<br>

<img src="https://readme-typing-svg.demolab.com?font=Fira+Code&size=22&duration=3000&pause=1000&center=true&vCenter=true&width=600&lines=Scan+Suspicious+URLs;Detect+Phishing+Indicators;Analyze+Threat+Intelligence;Protect+Before+You+Click" alt="TrustLink Animation">

</div>

---

## 🚀 What is TrustLink?

**TrustLink V2** is a browser security assistant that analyzes URLs using multiple security signals and threat-intelligence data.

It provides a simple **0–100 risk score**, explains suspicious indicators, and can warn users about high-risk websites.

> ⚠️ TrustLink provides risk analysis and does not guarantee that a website is completely safe or malicious.

---

## ✨ V2 Features

### 🔍 URL Security Analysis

- 🔍 **0–100 URL Risk Score**
- 🧠 **Modular security heuristics**
- 🎭 **Homograph & typosquatting detection**
- 🏷️ **Brand impersonation detection**
- 🌐 **Punycode & suspicious TLD detection**
- 📍 **IP-based URL detection**
- 🔗 **URL obfuscation & redirect detection**
- 🧪 **Suspicious keyword/subdomain detection**

### 🛡️ Threat Intelligence

- 🚨 **Critical threat handling**
- 🛡️ **OpenPhish threat intelligence**
- 🗄️ **Local threat database**
- 🔄 **PhishTank & URLhaus adapters**

### ⚙️ Configuration

- ⚙️ **Firebase Remote Config support**
- 🔐 **Remote configuration validation**
- 💾 **Optional Firestore synchronization**

---

## 🧭 How It Works

```text
        🔗 URL
          │
          ▼
   ┌───────────────┐
   │ URL Normalize │
   └───────┬───────┘
           │
           ▼
   ┌────────────────┐
   │ Threat Database│
   └───────┬────────┘
           │
           ▼
   ┌────────────────┐
   │ Security       │
   │ Heuristics     │
   └───────┬────────┘
           │
           ▼
      📊 Risk Score
           │
           ▼
   ┌────────────────┐
   │ Risk / Threat  │
   │ Verdict        │
   └───────┬────────┘
           │
      ┌────┴────┐
      ▼         ▼
   ✅ Allow   ⚠️ Warn
📊 Risk Levels
Score	Risk Level
🟢 0–29	Looks Safe
🟡 30–59	Use Caution
🔴 60–100	High Risk
🚨 Confirmed threat	Critical / Known Threat


A confirmed threat-intelligence match can take priority over the normal heuristic score.
🔬 Example Analysis
🔗 URL
https://example-login-security.com

        ↓

🧠 URL Analysis

✓ HTTPS detected
⚠ Suspicious subdomain
⚠ Login-related keyword
⚠ Brand impersonation indicator
⚠ Domain structure anomaly

        ↓

📊 Risk Score: 78 / 100

🔴 HIGH RISK
⚡ Security Analysis Flow
<div align="center">

🔗 URL
  ↓
🔍 Normalize
  ↓
🛡️ Threat Database
  ↓
🧠 Heuristics
  ↓
📊 Risk Scoring
  ↓
🚨 Threat Verdict
  ↓
✅ Allow / ⚠️ Warn

<img src="https://readme-typing-svg.demolab.com?font=Fira+Code&size=18&duration=2500&pause=700&center=true&vCenter=true&width=650&lines=URL+Normalization+%E2%9C%93;Threat+Database+Check+%E2%9C%93;Security+Heuristics+%E2%9C%93;Risk+Scoring+%E2%9C%93;Threat+Verdict+%E2%9C%93" alt="Analysis Animation">

</div>

🔐 Privacy & Safety
TrustLink is designed around passive, read-only analysis.
It does not intentionally:
- Exploit websites
- Brute-force targets
- Flood servers
- Perform intrusive security testing
Threat intelligence is designed to be cached and checked locally where supported.
Firebase/Firestore features are optional, and Firestore synchronization is disabled by default.
🏗️ Architecture
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
        Brand Detection   URLhaus          Validation
        Homograph         PhishTank        Firebase
        Redirects         Threat DB
              │               │
              └───────┬───────┘
                      ▼
                📊 Risk Engine
                      │
                      ▼
               ⚠️ User Warning
📁 Project Structure
TrustLink-v1/
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
├── app.html
├── app.css
├── app.js
├── ui-core.js
│
├── lib/
│   ├── adapters/
│   ├── heuristics/
│   ├── blocking.js
│   ├── configValidation.js
│   ├── firebase-config.js
│   ├── firebaseSync.js
│   ├── remoteConfig.js
│   ├── state.js
│   ├── threatDb.js
│   └── urlUtils.js
│
├── tests/
└── firestore.rules
📥 Installation
1️⃣ Clone the Repository
git clone https://github.com/anandsekar-404/WebSecurity-Scanner.git
2️⃣ Open Chrome Extensions
chrome://extensions
3️⃣ Enable Developer Mode
Turn on:
Developer mode
4️⃣ Load TrustLink
Click:
Load unpacked
Then select:
TrustLink-v1
5️⃣ Pin TrustLink
Pin TrustLink from the Chrome Extensions menu.
🧪 Tests
Run the V2 tests from inside TrustLink-v1.
PowerShell
Get-ChildItem tests\*.test.mjs | ForEach-Object { node $_.FullName }
Linux / macOS
for f in tests/*.test.mjs; do node "$f" || break; done
🛠️ Built With
<div align="center">


</div>

📈 TrustLink Evolution
                 🛡️ TrustLink
                      │
          ┌───────────┴───────────┐
          │                       │
         V1                      V2
          │                       │
          ▼                       ▼
   Basic URL Analysis      Modular Heuristics
   Suspicious URLs         Threat Intelligence
   Risk Scoring            OpenPhish
                           Threat Database
                           Brand Detection
                           Homograph Detection
                           Remote Config
                           Extensive Testing
                                  │
                                  ▼
                              V3 🚀
                                  │
                    ┌─────────────┼─────────────┐
                    ▼             ▼             ▼
              Browser        Domain         Advanced
              Protection    Intelligence    Detection
                    │             │             │
                    └─────────────┼─────────────┘
                                  ▼
                         Next-Generation
                         Phishing Protection
🔄 V2 Security Pipeline
<div align="center">

<img src="https://readme-typing-svg.demolab.com?font=Fira+Code&size=20&duration=2000&pause=500&center=true&vCenter=true&width=700&lines=%5B+URL+%5D;%E2%86%93;%5B+Normalize+%5D;%E2%86%93;%5B+Threat+DB+%5D;%E2%86%93;%5B+Heuristics+%5D;%E2%86%93;%5B+Risk+Score+%5D;%E2%86%93;%5B+Threat+Verdict+%5D" alt="TrustLink Security Pipeline">

</div>

⚠️ Disclaimer
TrustLink uses security heuristics and threat-intelligence indicators to estimate risk.
A low score does not guarantee safety, and a high score does not by itself prove malicious intent.
Always verify important websites, avoid suspicious downloads, and never enter sensitive information on a site you do not trust.
<div align="center">

🛡️ Think Before You Click.
<img src="https://readme-typing-svg.demolab.com?font=Fira+Code&size=20&duration=2500&pause=800&center=true&vCenter=true&width=550&lines=Detect.;Analyze.;Verify.;Protect.;TrustLink+V2+%F0%9F%9B%A1%EF%B8%8F" alt="TrustLink Animation">


TrustLink V2 — Verify the Link. Protect the Click.
⭐ If you find the project useful, consider starring the repository.
</div>
```
