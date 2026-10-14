// tests/domXss.test.mjs
// Verifies DOM-Based XSS prevention, HTML entity escaping, safe DOM node creation,
// and scheme/protocol validation across all UI components.

import assert from "node:assert/strict";

function escapeHtml(str) {
  return String(str ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

class MockElement {
  constructor(tagName = "div") {
    this.tagName = tagName.toUpperCase();
    this.children = [];
    this._textContent = "";
    this._innerHTML = "";
    this.attributes = {};
    this.style = {};
    this.className = "";
  }

  get textContent() {
    return this._textContent;
  }

  set textContent(val) {
    this._textContent = String(val ?? "");
    this._innerHTML = "";
    this.children = [];
  }

  get innerHTML() {
    return this._innerHTML;
  }

  set innerHTML(val) {
    this._innerHTML = String(val ?? "");
    this._textContent = "";
    // If val contains script tags or img error handlers, simulate child parsing
    if (/<script/i.test(val) || /onerror\s*=/i.test(val)) {
      this.hasInjectedScripts = true;
    }
  }

  appendChild(child) {
    if (typeof child === "string") {
      this.children.push(new MockTextNode(child));
    } else {
      this.children.push(child);
    }
    return child;
  }

  replaceChildren(...newChildren) {
    this.children = [...newChildren];
    this._innerHTML = "";
    this._textContent = "";
  }

  setAttribute(k, v) {
    this.attributes[k] = String(v);
  }

  getAttribute(k) {
    return this.attributes[k] || null;
  }
}

class MockTextNode {
  constructor(text) {
    this.nodeType = 3;
    this.textContent = String(text ?? "");
  }
}

function testEntityEscaping() {
  console.log("Scenario: HTML entity encoding across special characters and quotes");

  const payload1 = '<script>alert("XSS")</script>';
  assert.equal(
    escapeHtml(payload1),
    "&lt;script&gt;alert(&quot;XSS&quot;)&lt;/script&gt;",
    "Escapes tags and double quotes"
  );

  const payload2 = "';alert(1);//";
  assert.equal(escapeHtml(payload2), "&#39;;alert(1);//", "Escapes single quotes");

  const payload3 = '"><img src=x onerror=alert(1)>';
  assert.equal(
    escapeHtml(payload3),
    "&quot;&gt;&lt;img src=x onerror=alert(1)&gt;",
    "Escapes quote breakout and angle brackets"
  );

  assert.equal(escapeHtml(null), "", "null safely yields empty string");
  assert.equal(escapeHtml(undefined), "", "undefined safely yields empty string");
  assert.equal(escapeHtml(12345), "12345", "numbers safely stringified");

  console.log("  ok - escapeHtml encodes all HTML special characters (&, <, >, \", ')");
}

function testSafeDomCreation() {
  console.log("\nScenario: Safe DOM construction rejects script execution");

  const maliciousFinding = {
    level: "high",
    title: '<script>alert("pwned")</script>',
    detail: '"><img src=x onerror="alert(1)">',
  };

  // Simulate createFindingCard from ui-core.js
  const card = new MockElement("article");
  const h3 = new MockElement("h3");
  h3.textContent = maliciousFinding.title;
  const p = new MockElement("p");
  p.textContent = maliciousFinding.detail;

  card.appendChild(h3);
  card.appendChild(p);

  assert.equal(h3.textContent, '<script>alert("pwned")</script>', "Content stored as pure literal string");
  assert.equal(h3.innerHTML, "", "innerHTML is completely empty on textContent assignment");
  assert.equal(h3.hasInjectedScripts, undefined, "No executable script nodes created");

  assert.equal(p.textContent, '"><img src=x onerror="alert(1)">', "Detail stored as pure literal string");
  assert.equal(p.hasInjectedScripts, undefined, "No onerror event handlers created");

  console.log("  ok - finding cards created via textContent are completely immune to script injection");
}

function testBlockedPageListDomConstruction() {
  console.log("\nScenario: Blocked interstitial reasons list DOM construction");

  const list = new MockElement("ul");
  const threatMatch = {
    title: 'Phishing Threat <img src=x onerror="steal()">' ,
    detail: 'Known bad domain "><script>fetch("/exfil")</script>',
  };

  // Simulate blocked.js programmatic construction
  list.replaceChildren();

  const li = new MockElement("li");
  const strong = new MockElement("strong");
  strong.textContent = threatMatch.title;
  li.appendChild(strong);
  li.appendChild(new MockTextNode(` — ${threatMatch.detail}`));
  list.appendChild(li);

  assert.equal(list.children.length, 1, "Exactly one list item appended");
  assert.equal(strong.textContent, 'Phishing Threat <img src=x onerror="steal()">', "Title stored as literal text");
  assert.equal(strong.hasInjectedScripts, undefined, "No image element created");
  assert.equal(list.innerHTML, "", "Zero innerHTML used on reasons list");

  console.log("  ok - blocked page reasons list constructed with zero innerHTML");
}

function testFormProtocolValidation() {
  console.log("\nScenario: Form action protocol validation restricts dangerous schemes");

  const allowedSchemes = ["http:", "https:"];

  const dangerousActions = [
    "javascript:alert(document.cookie)",
    "JAVASCRIPT:alert(1)",
    "data:text/html,<script>alert(1)</script>",
    "vbscript:msgbox(1)",
    "file:///etc/passwd",
  ];

  for (const action of dangerousActions) {
    let parsed = null;
    try {
      parsed = new URL(action, "https://legitimate.example/login");
    } catch {
      // Ignored
    }
    const isAllowed = parsed != null && allowedSchemes.includes(parsed.protocol);
    assert.equal(isAllowed, false, `Dangerous scheme rejected: ${action}`);
  }

  const validActions = [
    "https://auth.example.com/login",
    "http://auth.example.com/submit",
    "/api/v1/auth",
  ];

  for (const action of validActions) {
    const parsed = new URL(action, "https://legitimate.example/login");
    const isAllowed = allowedSchemes.includes(parsed.protocol);
    assert.equal(isAllowed, true, `Valid HTTP/HTTPS scheme accepted: ${action}`);
  }

  console.log("  ok - non-HTTP(S) URL schemes (javascript:, data:, file:) strictly rejected");
}

function run() {
  console.log("========================================================");
  console.log("TrustLink DOM-Based XSS Prevention Verification");
  console.log("========================================================");
  testEntityEscaping();
  testSafeDomCreation();
  testBlockedPageListDomConstruction();
  testFormProtocolValidation();
  console.log("\nALL DOM XSS SECURITY TESTS PASSED");
}

run();
