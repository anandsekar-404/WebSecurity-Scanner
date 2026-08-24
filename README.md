# 🛡️ TrustLink

<div align="center">

![TrustLink Banner](https://img.shields.io/badge/TrustLink-Security%20Starts%20Before%20You%20Click-00d4ff?style=for-the-badge)

### 🔗 Verify the Link. Protect the Click.

**A privacy-first Chrome extension that helps you identify suspicious and potentially dangerous websites before you trust them.**

![Chrome Extension](https://img.shields.io/badge/Chrome-Extension-brightgreen?style=flat-square)
![Manifest V3](https://img.shields.io/badge/Manifest-V3-blue?style=flat-square)
![Version](https://img.shields.io/badge/Version-1.3.2-purple?style=flat-square)
![Cybersecurity](https://img.shields.io/badge/Focus-Cybersecurity-red?style=flat-square)

</div>

---

## 🚀 About TrustLink

**TrustLink** is a browser security assistant designed to help users make safer decisions before interacting with suspicious websites.

It analyzes URLs using multiple passive security signals and provides a simple **risk score from 0–100**, along with clear explanations of the detected warning signs.

Instead of simply saying a website is "safe" or "unsafe," TrustLink helps users understand **why a link may be suspicious**.

> ⚠️ **TrustLink is a security assistant, not a guarantee that a website is completely safe or malicious.**

---

# ✨ Features

## 🔍 Smart URL Risk Analysis

TrustLink analyzes suspicious characteristics in a URL and calculates a risk score.

### 🟢 0–29 — Looks Safe

No major warning signals were detected.

### 🟡 30–59 — Use Caution

Some suspicious characteristics were found.

### 🔴 60–100 — High Risk

Multiple strong warning signals were detected.

---

## 🧠 Detects Suspicious Signals

TrustLink can identify indicators such as:

* 🔒 Missing HTTPS encryption
* 🌐 Punycode / encoded domains
* 🎭 Look-alike domains
* 📍 Raw IP addresses used instead of domains
* ⚠️ Misleading `@` URL structures
* 🔗 Suspicious redirect parameters
* 🧪 Phishing-related keywords
* 🌍 Potentially risky domain structures
* 🚨 Suspicious ports
* 🔄 Redirect-related indicators
* 🏷️ Trusted-brand impersonation attempts

---

## 🛑 Dangerous Website Blocking

When TrustLink detects a URL with strong high-risk indicators, it can redirect the user to a warning page before the suspicious website fully loads.

The warning page provides:

* 🚨 Risk score
* 📊 Threat level
* 🔍 Specific reasons for the warning
* 🏠 **Go back to safety** option
* ⚠️ Advanced option to continue anyway after confirmation

This gives users an opportunity to stop and think before proceeding.

---

## 🤖 Automatic Background Scanning

TrustLink can automatically analyze supported webpages while you browse.

You can easily control this feature:

🟢 **Scanning** — Automatic protection is active
🔴 **Stopped** — Automatic scanning is paused

Manual scanning remains available even when automatic scanning is turned off.

---

## ✋ Manual Link Scanner

You can manually check:

* The website currently open in your browser
* Any URL pasted into TrustLink

Simply enter a link and let TrustLink analyze its visible risk signals.

---

## 🔐 Privacy-First Design

TrustLink is designed with privacy in mind.

The project focuses on **passive, read-only security checks** and does not attempt to:

* ❌ Exploit websites
* ❌ Attack servers
* ❌ Brute-force targets
* ❌ Flood websites with requests
* ❌ Perform intrusive scanning

The goal is simple:

> **Help users recognize suspicious links without performing harmful actions against websites.**

---

## ☁️ Optional Firebase Sync

TrustLink works locally using Chrome storage.

Optional Firebase integration can synchronize selected application state, helping maintain certain settings across local data resets.

The extension is designed to remain functional even without Firebase configuration.

---

# 🖥️ Project Structure

```text
TrustLink-v1/
│
├── 📄 manifest.json
│
├── 🧠 analyzer.js
├── ⚙️ background.js
├── 📡 content.js
│
├── 🎨 app.html
├── 🎨 app.css
├── ⚡ app.js
│
├── 🪟 popup.html
├── 🎨 popup.css
├── ⚡ popup.js
│
├── 🚨 blocked.html
├── 🎨 blocked.css
├── ⚡ blocked.js
│
├── 🧩 ui-core.js
│
├── 📁 lib/
│   ├── blocking.js
│   ├── firebase-config.js
│   ├── firebaseSync.js
│   └── state.js
│
├── 📁 tests/
│   ├── blocking.test.mjs
│   └── state.test.mjs
│
├── 🔥 firestore.rules
│
├── 🖼️ icon16.png
├── 🖼️ icon32.png
├── 🖼️ icon48.png
├── 🖼️ icon128.png
├── 🖼️ cybroatrix-logo.png
│
└── 📖 README.md
```

---

# 📥 Installation

## Method 1 — Load as an Unpacked Extension

### Step 1

Download or clone this repository.

```bash
git clone https://github.com/YOUR-USERNAME/YOUR-REPOSITORY.git
```

### Step 2

Open Google Chrome and go to:

```text
chrome://extensions
```

### Step 3

Enable:

> 🛠️ Developer mode

### Step 4

Click:

> 📂 Load unpacked

### Step 5

Select the main **TrustLink-v1** project folder.

### Step 6

Pin **TrustLink** from the Chrome Extensions menu.

🎉 **TrustLink is now ready to use!**

---

# 🧪 Running Tests

The project includes tests for important application logic.

For example:

```bash
node tests/state.test.mjs
```

Tests help verify the application's state and security-related logic.

---

# 🛠️ Built With

* 🌐 JavaScript
* 🎨 HTML5
* 💅 CSS3
* 🧩 Chrome Extensions API
* 🛡️ Chrome Manifest V3
* 💾 Chrome Storage API
* 🔥 Firebase / Firestore *(optional)*

---

# 🧭 How It Works

```text
        User Opens a Website
                │
                ▼
        ┌─────────────────┐
        │   TrustLink     │
        │ Automatic Scan  │
        └────────┬────────┘
                 │
                 ▼
        ┌─────────────────┐
        │ URL Analysis    │
        │ Security Signals│
        └────────┬────────┘
                 │
                 ▼
        ┌─────────────────┐
        │ Risk Score      │
        │    0 ── 100     │
        └────────┬────────┘
                 │
        ┌────────┼────────┐
        ▼        ▼        ▼
      🟢 Safe   🟡 Caution  🔴 High Risk
                            │
                            ▼
                     🚨 Warning Page
```

---

# ⚠️ Important Disclaimer

TrustLink uses heuristic analysis and security indicators to estimate potential risk.

A high score does **not always prove** that a website is malicious.

Similarly, a low score does **not guarantee** that a website is completely safe.

Users should always:

* Verify important websites manually
* Avoid entering passwords on suspicious pages
* Check the domain carefully
* Avoid unknown downloads
* Be cautious with urgent messages and redirects

> **TrustLink helps you make a better decision — but cybersecurity awareness is always the strongest protection.**

---

# 🔮 Future Ideas

Some ideas planned for future versions:

* [ ] Improved phishing detection
* [ ] AI-assisted URL analysis
* [ ] Community threat reporting
* [ ] Domain reputation checking
* [ ] Advanced browser notifications
* [ ] Better threat intelligence integration
* [ ] Scan history dashboard
* [ ] Trusted website allowlist
* [ ] Improved Firebase synchronization
* [ ] Enhanced visual threat reports

---

# 👨‍💻 Project

**TrustLink**
*Verify the Link. Protect the Click.*

A cybersecurity-focused browser extension project built to promote safer browsing and better awareness of suspicious links.

---

<div align="center">

### 🛡️ Think Before You Click.

**TrustLink — Verify the Link. Protect the Click.**

⭐ **If you find this project useful, consider giving the repository a star!**

</div>
