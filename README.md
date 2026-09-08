🛡️ TrustLink V2

<div align="center">

🔗 Verify the Link. Protect the Click.

A privacy-focused Chrome extension for detecting suspicious and potentially dangerous URLs before you trust them.






</div>

🚀 What is TrustLink?

TrustLink V2 is a browser security assistant that analyzes URLs using multiple security signals and threat-intelligence data.

It provides a simple 0–100 risk score, explains suspicious indicators, and can warn users about high-risk websites.

⚠️ TrustLink provides risk analysis and does not guarantee that a website is completely safe or malicious.

✨ V2 Features

🔍 0–100 URL Risk Score

🧠 Modular security heuristics

🎭 Homograph & typosquatting detection

🏷️ Brand impersonation detection

🌐 Punycode & suspicious TLD detection

📍 IP-based URL detection

🔗 URL obfuscation & redirect detection

🧪 Suspicious keyword/subdomain detection

🚨 Critical threat handling

🛡️ OpenPhish threat intelligence

🗄️ Local threat database

🔄 PhishTank & URLhaus adapters

⚙️ Firebase Remote Config support

🔐 Remote configuration validation

💾 Optional Firestore synchronization

🧭 How It Works

URL
 ↓
URL Normalization
 ↓
Threat Database Check
 ↓
Security Heuristics
 ↓
Risk Score
 ↓
Risk Level / Threat Verdict
 ↓
Warn or Allow

Risk Levels

Score

Level

🟢 0–29

Looks Safe

🟡 30–59

Use Caution

🔴 60–100

High Risk

🚨 Confirmed threat

Critical / Known Threat

A confirmed threat-intelligence match can take priority over the normal heuristic score.

🔒 Privacy & Safety

TrustLink is designed around passive, read-only analysis.

It does not intentionally:

Exploit websites

Brute-force targets

Flood servers

Perform intrusive security testing

Threat intelligence is designed to be cached and checked locally where supported.

Firebase/Firestore features are optional, and Firestore synchronization is disabled by default.

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
├── tests/
└── firestore.rules

📥 Installation

Clone or download the repository.

Open chrome://extensions.

Enable Developer mode.

Click Load unpacked.

Select the TrustLink-v1 folder.

Pin TrustLink from the Chrome Extensions menu.

🧪 Tests

Run the V2 tests from inside TrustLink-v1:

PowerShell

Get-ChildItem tests\*.test.mjs | ForEach-Object { node $_.FullName }

Linux / macOS

for f in tests/*.test.mjs; do node "$f" || break; done

🛠️ Built With

JavaScript (ES6+)

HTML5

CSS3

Chrome Extensions API

Manifest V3

Chrome Storage API

Firebase / Firestore (optional)

⚠️ Disclaimer

TrustLink uses security heuristics and threat-intelligence indicators to estimate risk.

A low score does not guarantee safety, and a high score does not by itself prove malicious intent.

Always verify important websites, avoid suspicious downloads, and never enter sensitive information on a site you do not trust.

<div align="center">

🛡️ Think Before You Click.

TrustLink V2 — Verify the Link. Protect the Click.

⭐ If you find the project useful, consider starring the repository.

</div>
