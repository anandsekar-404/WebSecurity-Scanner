// lib/adapters/openphish.js — spec section 17
//
// SOURCE: OpenPhish Community Feed — https://openphish.com/feed.txt
// A free, keyless, plain-text list of URLs (one per line), no application
// or account required. Per OpenPhish's published terms (openphish.com/terms.html):
//   - Free for NON-COMMERCIAL use only.
//   - Updated roughly every 12 hours (community feed cadence; OpenPhish's
//     paid "Premium" tier updates faster and adds structured metadata —
//     NOT used here, this project only integrates the free community feed).
// TrustLink respects this by polling on the interval in
// heuristics/defaults.js's system_feed_update_interval_ms (12h default,
// remotely tunable but never something this adapter races ahead of), and by
// never sending per-URL queries to OpenPhish — the feed is downloaded in
// bulk on a schedule and matched against ENTIRELY locally afterward
// (spec sections 16, 44).
//
// The feed itself is DATA ONLY: it is never executed, never eval'd, and
// every line is validated as a well-formed URL before being stored — a
// malformed or corrupted line is silently dropped, not stored as-is
// (spec section 40).

import { normalizeForLookup } from "../urlUtils.js";

export const SOURCE_NAME = "OpenPhish";
const FEED_URL = "https://openphish.com/feed.txt";
const MAX_FEED_BYTES = 10 * 1024 * 1024; // 10MB sanity ceiling — the real feed is far smaller; a huge response signals something's wrong upstream
const MAX_ENTRIES = 100_000;
const MIN_ENTRIES_FOR_VALID_UPDATE = 50; // a healthy feed has thousands; anything drastically smaller suggests a truncated/broken download

/**
 * Downloads, validates, and — only if validation passes — publishes the
 * OpenPhish feed into `threatDb`. Never throws; returns a result object the
 * caller (background.js) can log/surface in the debug panel. On ANY
 * failure, the previous database for this source is left completely
 * untouched (spec section 39).
 */
export async function updateOpenPhishFeed(threatDb, { force = false, minIntervalMs } = {}) {
  try {
    if (!force && minIntervalMs) {
      const meta = await threatDb.getMeta(SOURCE_NAME);
      if (meta?.last_successful_update && Date.now() - new Date(meta.last_successful_update).getTime() < minIntervalMs) {
        return { success: true, skipped: true, reason: "up-to-date" };
      }
    }

    const res = await fetch(FEED_URL, { method: "GET" });
    if (!res.ok) return { success: false, reason: `feed request failed (${res.status})` };

    const contentLength = Number(res.headers.get("content-length") || 0);
    if (contentLength > MAX_FEED_BYTES) {
      return { success: false, reason: "feed larger than expected — refusing to process" };
    }

    const text = await res.text();
    if (text.length > MAX_FEED_BYTES) {
      return { success: false, reason: "feed larger than expected — refusing to process" };
    }

    const lines = text.split("\n").map((l) => l.trim()).filter(Boolean);
    if (lines.length > MAX_ENTRIES) {
      return { success: false, reason: `feed had ${lines.length} lines, exceeding the ${MAX_ENTRIES} sanity cap` };
    }

    const seen = new Set();
    const entries = [];
    let malformed = 0;
    const nowIso = new Date().toISOString();

    for (const line of lines) {
      if (!/^https?:\/\//i.test(line)) { malformed++; continue; } // OpenPhish's feed is HTTP(S) phishing URLs only — anything else is not a valid entry for this source
      const normalized = normalizeForLookup(line);
      if (!normalized) { malformed++; continue; } // not a parseable URL — dropped, never stored raw
      if (seen.has(normalized)) continue; // de-dupe
      seen.add(normalized);
      entries.push({
        indicator: normalized,
        type: "phishing_url",
        source: SOURCE_NAME,
        last_updated: nowIso,
        status: "active",
        // NOTE: no `first_seen` field — the community feed doesn't supply
        // per-entry timestamps, and spec section 21 says only store fields
        // the provider actually gives us. Don't invent one.
      });
    }

    if (entries.length < MIN_ENTRIES_FOR_VALID_UPDATE) {
      return { success: false, reason: `only ${entries.length} valid entries parsed (expected far more) — treating as a bad download, keeping previous database` };
    }

    const meta = await threatDb.replaceSource(SOURCE_NAME, entries, { databaseVersion: nowIso, status: "active" });
    return { success: true, entryCount: entries.length, malformedDropped: malformed, meta };
  } catch (err) {
    return { success: false, reason: err?.message || "network error" };
  }
}
