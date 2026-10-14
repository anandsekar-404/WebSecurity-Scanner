// tests/securityHardening.test.mjs
// Verifies sender checks, secure approveContinue, and credential guard logic.

let messageListener = null;
const sessionData = {};
const tabUpdates = [];

globalThis.chrome = {
  runtime: {
    id: "test-extension-id",
    getURL: (p = "") => `chrome-extension://test-extension-id/${p}`,
    onMessage: {
      addListener(cb) {
        messageListener = cb;
      },
    },
  },
  storage: {
    local: {
      get: (keys, cb) => cb({}),
      set: (items, cb) => cb?.(),
    },
    session: {
      get(defaults, cb) {
        const result = {};
        const defObj = defaults && typeof defaults === "object" && !Array.isArray(defaults) ? defaults : {};
        const keyList = Array.isArray(defaults) ? defaults : typeof defaults === "string" ? [defaults] : Object.keys(defObj);
        for (const k of keyList) result[k] = k in sessionData ? sessionData[k] : defObj[k] ?? null;
        if (typeof cb === "function") cb(result);
        return Promise.resolve(result);
      },
      set(items, cb) {
        Object.assign(sessionData, items);
        if (typeof cb === "function") cb?.();
        return Promise.resolve();
      },
      remove(keys, cb) {
        const keyList = Array.isArray(keys) ? keys : [keys];
        for (const k of keyList) delete sessionData[k];
        if (typeof cb === "function") cb?.();
        return Promise.resolve();
      },
    },
  },
  action: {
    setBadgeBackgroundColor: async () => {},
    setBadgeText: async () => {},
    setBadgeTextColor: async () => {},
  },
  tabs: {
    query: async () => [],
    update: async (tabId, opts) => {
      tabUpdates.push({ tabId, opts });
      return { id: tabId, ...opts };
    },
  },
  webNavigation: {
    onBeforeNavigate: { addListener: () => {} },
    onCommitted: { addListener: () => {} },
  },
};

function assert(cond, msg) {
  if (!cond) throw new Error("FAIL: " + msg);
  console.log("  ok -", msg);
}

function sendMsg(msg, sender) {
  return new Promise((resolve) => {
    const keepChannel = messageListener(msg, sender, resolve);
    if (!keepChannel) resolve(null);
  });
}

async function run() {
  console.log("Scenario: load background and verify sender checks on privileged messages");
  await import("../background.js");
  assert(typeof messageListener === "function", "message listener registered");

  const contentScriptSender = {
    id: "test-extension-id",
    url: "https://evil.example/malicious-page.html",
    tab: { id: 99 },
  };

  const extensionPageSender = {
    id: "test-extension-id",
    url: "chrome-extension://test-extension-id/blocked.html?id=xyz",
    tab: { id: 42 },
  };

  const externalSender = {
    id: "other-extension-id",
    url: "https://external.example/",
  };

  // Test setAutoScanEnabled rejected from content script
  {
    const res = await sendMsg({ type: "setAutoScanEnabled", enabled: false }, contentScriptSender);
    assert(res?.error === "Unauthorized sender", "setAutoScanEnabled rejected from content script sender");
  }

  // Test forceRefreshThreatData rejected from content script
  {
    const res = await sendMsg({ type: "forceRefreshThreatData" }, contentScriptSender);
    assert(res?.error === "Unauthorized sender", "forceRefreshThreatData rejected from content script sender");
  }

  // Test getDebugStatus rejected from content script
  {
    const res = await sendMsg({ type: "getDebugStatus" }, contentScriptSender);
    assert(res?.error === "Unauthorized sender", "getDebugStatus rejected from content script sender");
  }

  // Test approveContinue rejected from content script
  {
    const res = await sendMsg({ type: "approveContinue", id: "fake-id", url: "https://bypass.example", tabId: 1 }, contentScriptSender);
    assert(res?.ok === false && res?.error === "Unauthorized sender", "approveContinue rejected from content script sender");
  }

  // Test external sender rejected
  {
    const res = await sendMsg({ type: "approveContinue", id: "fake-id" }, externalSender);
    assert(res?.ok === false && res?.error === "Unauthorized sender", "approveContinue rejected from external sender");
  }

  console.log("\nScenario: approveContinue only trusts stored block reason, never message params");
  {
    const { storeBlockReason, isApproved } = await import("../lib/blocking.js");

    const genuineUrl = "https://flagged-site.example/login";
    const genuineTabId = 42;
    const blockId = await storeBlockReason({
      url: genuineUrl,
      tabId: genuineTabId,
      score: 85,
      tone: "danger",
      label: "Dangerous",
      action: "Do not enter passwords",
      findings: [],
    });

    tabUpdates.length = 0;

    // Attacker sends arbitrary url and tabId in message
    const res = await sendMsg({
      type: "approveContinue",
      id: blockId,
      url: "https://attacker-forged-url.example/bypass",
      tabId: 999,
    }, extensionPageSender);

    assert(res?.ok === true, "approveContinue succeeds for extension page sender");
    assert(tabUpdates.length === 1, "tabs.update called once");
    assert(tabUpdates[0].tabId === genuineTabId, "tabs.update called for genuine tabId (42), NOT forged tabId (999)");
    assert(tabUpdates[0].opts.url === genuineUrl, "tabs.update redirected to genuine stored URL, NOT attacker forged URL");

    const approved = await isApproved(genuineTabId, genuineUrl);
    assert(approved === true, "genuine URL is marked approved");
    const forgedApproved = await isApproved(genuineTabId, "https://attacker-forged-url.example/bypass");
    assert(forgedApproved === false, "attacker forged URL is NOT approved");
  }

  console.log("\nALL SECURITY HARDENING TESTS PASSED");
}

run().catch((e) => {
  console.error(e);
  process.exit(1);
});
