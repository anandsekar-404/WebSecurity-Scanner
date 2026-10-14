// Covers spec section 50 items 1 (known OpenPhish match, exercised via the
// full download->parse->validate->publish pipeline here), 19-21 (feed
// update failure, corrupted database, malformed entries), plus empty/
// invalid feed handling. fetch is fully mocked — never touches the real
// openphish.com endpoint.

globalThis.chrome = undefined; // threatDb's in-memory backend needs no chrome API at all

function assert(cond, msg) {
  if (!cond) throw new Error("FAIL: " + msg);
  console.log("  ok -", msg);
}

function feedResponse(text, { ok = true, status = 200, contentLength } = {}) {
  return {
    ok, status,
    headers: { get: (name) => (name === "content-length" ? String(contentLength ?? text.length) : null) },
    text: async () => text,
  };
}

async function run() {
  const { updateOpenPhishFeed, SOURCE_NAME } = await import("../lib/adapters/openphish.js");
  const { createThreatDb } = await import("../lib/threatDb.js");

  // A "healthy" feed needs to clear MIN_ENTRIES_FOR_VALID_UPDATE (50) — build
  // one programmatically rather than hand-typing 50+ URLs.
  const healthyUrls = Array.from({ length: 60 }, (_, i) => `http://phish-${i}.example.com/login/verify`);
  const healthyFeedText = healthyUrls.join("\n");

  console.log("Scenario: successful download -> parse -> validate -> publish");
  {
    const db = createThreatDb();
    globalThis.fetch = async (url) => {
      assert(String(url) === "https://openphish.com/feed.txt", "fetches the documented OpenPhish community feed URL, nothing else");
      return feedResponse(healthyFeedText);
    };
    const result = await updateOpenPhishFeed(db);
    assert(result.success === true, `update reports success (got ${JSON.stringify(result)})`);
    assert(result.entryCount === 60, `all 60 well-formed URLs were parsed (got ${result.entryCount})`);
    const hit = await db.lookup(new URL(healthyUrls[0]).toString().replace(/\/$/, ""));
    assert(hit.matched === true && hit.source === SOURCE_NAME, "a fed-in URL is now an exact-match lookup hit");
  }

  console.log("\nScenario: malformed lines are dropped, not stored");
  {
    const db = createThreatDb();
    const mixed = [...healthyUrls, "not a url at all", "ftp://also-not-http.example/", "   ", ""].join("\n");
    globalThis.fetch = async () => feedResponse(mixed);
    const result = await updateOpenPhishFeed(db);
    assert(result.success === true, "update still succeeds when most entries are valid");
    assert(result.malformedDropped >= 1, `malformed/non-http(s) lines were counted and dropped (got ${result.malformedDropped})`);
    assert(result.entryCount === 60, "only the 60 well-formed URLs were actually stored");
  }

  console.log("\nScenario: duplicate lines are de-duplicated");
  {
    const db = createThreatDb();
    const withDupes = [...healthyUrls, ...healthyUrls.slice(0, 10)].join("\n"); // 10 URLs repeated
    globalThis.fetch = async () => feedResponse(withDupes);
    const result = await updateOpenPhishFeed(db);
    assert(result.entryCount === 60, `duplicates collapse to the original 60 unique entries (got ${result.entryCount})`);
  }

  console.log("\nScenario: empty feed is treated as a bad download, NOT as 'the internet has 0 phishing sites today'");
  {
    const db = createThreatDb();
    globalThis.fetch = async () => feedResponse("");
    const result = await updateOpenPhishFeed(db);
    assert(result.success === false, "an empty feed body is rejected");
    assert(/entries parsed/.test(result.reason), `reason explains why (got: ${result.reason})`);
  }

  console.log("\nScenario: a feed with too few valid entries (suspiciously truncated download) is rejected");
  {
    const db = createThreatDb();
    globalThis.fetch = async () => feedResponse(healthyUrls.slice(0, 5).join("\n")); // only 5, below the 50 sanity floor
    const result = await updateOpenPhishFeed(db);
    assert(result.success === false, "a drastically undersized feed is rejected rather than silently accepted");
  }

  console.log("\nScenario: an oversized feed (sanity ceiling) is rejected rather than processed");
  {
    const db = createThreatDb();
    const hugeText = "a".repeat(200);
    globalThis.fetch = async () => feedResponse(hugeText, { contentLength: 999_999_999 });
    const result = await updateOpenPhishFeed(db);
    assert(result.success === false, "a Content-Length far beyond the sanity ceiling is rejected before the body is even read for parsing");
  }

  console.log("\nScenario: HTTP failure (e.g. openphish.com down / rate-limited) is handled gracefully");
  {
    const db = createThreatDb();
    globalThis.fetch = async () => feedResponse("", { ok: false, status: 503 });
    const result = await updateOpenPhishFeed(db);
    assert(result.success === false, "a non-2xx response is reported as a failed update, not a crash");
  }

  console.log("\nScenario: network-level failure (fetch throws) never throws OUT of updateOpenPhishFeed");
  {
    const db = createThreatDb();
    globalThis.fetch = async () => { throw new Error("simulated DNS failure"); };
    const result = await updateOpenPhishFeed(db);
    assert(result.success === false && typeof result.reason === "string", "a thrown network error is caught and reported, not propagated");
  }

  console.log("\nScenario: A FAILED update preserves the PREVIOUS valid database untouched (spec section 39)");
  {
    const db = createThreatDb();
    globalThis.fetch = async () => feedResponse(healthyFeedText);
    const first = await updateOpenPhishFeed(db);
    assert(first.success === true, "seed a good, valid database first");
    const beforeCount = await db.countBySource(SOURCE_NAME);

    globalThis.fetch = async () => { throw new Error("simulated outage on the next scheduled update"); };
    const second = await updateOpenPhishFeed(db);
    assert(second.success === false, "the second update attempt fails");
    const afterCount = await db.countBySource(SOURCE_NAME);
    assert(afterCount === beforeCount, `the previous database is completely untouched after a failed update (before=${beforeCount}, after=${afterCount})`);
    const stillThere = await db.lookup(new URL(healthyUrls[0]).toString().replace(/\/$/, ""));
    assert(stillThere.matched === true, "a specific previously-known-bad URL is STILL a match after the failed refresh");
  }

  console.log("\nScenario: respects its own minimum update interval (no aggressive polling — spec section 13)");
  {
    const db = createThreatDb();
    let fetchCalls = 0;
    globalThis.fetch = async () => { fetchCalls++; return feedResponse(healthyFeedText); };
    await updateOpenPhishFeed(db, { minIntervalMs: 12 * 60 * 60 * 1000 });
    assert(fetchCalls === 1, "first call fetches");
    const result = await updateOpenPhishFeed(db, { minIntervalMs: 12 * 60 * 60 * 1000 });
    assert(fetchCalls === 1, "a second call inside the interval does NOT re-fetch");
    assert(result.skipped === true, "the skipped call is reported as such, not as a fresh success");
  }

  console.log("\nScenario: a feed that shrinks to under half the previous count is rejected");
  {
    const db = createThreatDb();
    const largeFeedUrls = Array.from({ length: 200 }, (_, i) => `http://phish-large-${i}.example.org/login/verify`);
    globalThis.fetch = async () => feedResponse(largeFeedUrls.join("\n")); // 200 entries
    const first = await updateOpenPhishFeed(db);
    assert(first.success === true, "seed initial 200 entries");
    const countBefore = await db.countBySource(SOURCE_NAME);

    // Now server returns 70 entries (above the 50 minimum, but under half of 200)
    const shrankText = largeFeedUrls.slice(0, 70).join("\n");
    globalThis.fetch = async () => feedResponse(shrankText);
    const result = await updateOpenPhishFeed(db);
    assert(result.success === false, "shrunk feed is rejected");
    assert(result.reason.includes("shrank suspiciously"), `reason flags shrinkage (got: ${result.reason})`);
    const countAfter = await db.countBySource(SOURCE_NAME);
    assert(countAfter === countBefore, "previous threat entries preserved untouched after suspicious shrink");
  }

  console.log("\nScenario: streaming reader enforces byte limit on chunked downloads");
  {
    const db = createThreatDb();
    let readerCancelled = false;
    const oversizedChunk = new Uint8Array(6 * 1024 * 1024); // 6MB chunk
    globalThis.fetch = async () => ({
      ok: true,
      status: 200,
      headers: { get: () => null }, // no content-length (chunked)
      body: {
        getReader() {
          let call = 0;
          return {
            async read() {
              call++;
              if (call <= 2) return { done: false, value: oversizedChunk }; // 2 chunks = 12MB > 10MB limit
              return { done: true };
            },
            async cancel() { readerCancelled = true; },
          };
        },
      },
    });
    const result = await updateOpenPhishFeed(db);
    assert(result.success === false, "streaming reader over 10MB is rejected");
    assert(readerCancelled === true, "stream reader was cancelled to stop unnecessary download");
  }

  console.log("\nScenario: domain-level matching excludes shared hosting platforms");
  {
    const db = createThreatDb();
    const urlsWithShared = [
      ...Array.from({ length: 50 }, (_, i) => `https://isolated-phish-${i}.example.org/login`),
      "https://isolated-phish-1.example.org/verify",
      "https://isolated-phish-1.example.org/session",
      "https://attacker.github.io/phishing-page",
      "https://docs.google.com/forms/d/e/12345/viewform",
    ];
    globalThis.fetch = async () => feedResponse(urlsWithShared.join("\n"));
    const updateResult = await updateOpenPhishFeed(db);
    assert(updateResult.success === true, "feed with shared hosts parses successfully");

    // Exact match for the shared host URL still works
    const exactHit = await db.lookup("https://attacker.github.io/phishing-page");
    assert(exactHit.matched === true, "exact match for shared host URL works");

    // But different path on github.io or docs.google.com MUST NOT be blocked via domain match
    const innocentGithub = await db.lookup("https://innocent-user.github.io/my-project");
    assert(innocentGithub.matched === false, "unrelated site on shared host (github.io) is NOT blocked");
    const innocentGoogle = await db.lookup("https://docs.google.com/document/d/safe-doc");
    assert(innocentGoogle.matched === false, "unrelated doc on shared host (docs.google.com) is NOT blocked");

    // Whereas a non-shared domain matches even on a new path
    const domainKitHit = await db.lookup("https://isolated-phish-1.example.org/brand-new-path/auth");
    assert(domainKitHit.matched === true && domainKitHit.type === "phishing_domain", "non-shared domain matches on new path");
  }

  console.log("\nALL OPENPHISH ADAPTER TESTS PASSED");
}

run().catch((e) => { console.error(e); process.exit(1); });
