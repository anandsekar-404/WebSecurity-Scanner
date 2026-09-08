// lib/adapters/urlhaus.js — spec section 19
//
// STATUS: DISABLED BY DEFAULT, bring-your-own key.
//
// abuse.ch's URLhaus now requires a free Auth-Key for essentially all API
// and feed access (their older fully-keyless plain-text downloads have been
// retired). Registration itself is free and self-service at abuse.ch, but
// this project ships with NO key configured, and per spec section 19/45
// will not fabricate one or pretend keyless access still works.
//
// URLhaus is primarily a MALWARE-distribution URL source, not phishing —
// entries stored with type "malware_url" so the risk engine and warning UI
// can word things accurately (spec section 21's "only store fields actually
// supplied by the provider" extends to not mislabeling the entry TYPE
// either).
//
// To enable: supply your own Auth-Key via `authKey` below, flip
// feature_urlhaus to true (Remote Config or defaults.js), and re-verify
// URLhaus's current terms/endpoint — like any external dependency, this can
// change after the fact.

import { normalizeForLookup } from "../urlUtils.js";

export const SOURCE_NAME = "URLhaus";
const FEED_URL = "https://urlhaus.abuse.ch/downloads/csv_recent/";
const MAX_FEED_BYTES = 20 * 1024 * 1024;

export async function updateUrlhausFeed(threatDb, { authKey, force = false, minIntervalMs } = {}) {
  if (!authKey) {
    return { success: false, skipped: true, reason: "no Auth-Key configured — URLhaus stays disabled (see file header)" };
  }

  try {
    if (!force && minIntervalMs) {
      const meta = await threatDb.getMeta(SOURCE_NAME);
      if (meta?.last_successful_update && Date.now() - new Date(meta.last_successful_update).getTime() < minIntervalMs) {
        return { success: true, skipped: true, reason: "up-to-date" };
      }
    }

    const res = await fetch(FEED_URL, { headers: { "Auth-Key": authKey } });
    if (!res.ok) return { success: false, reason: `feed request failed (${res.status}) — check your Auth-Key` };

    const text = await res.text();
    if (text.length > MAX_FEED_BYTES) return { success: false, reason: "feed larger than expected — refusing to process" };

    // URLhaus CSV columns: id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
    const lines = text.split("\n").filter((l) => l && !l.startsWith("#"));
    const seen = new Set();
    const entries = [];
    const nowIso = new Date().toISOString();

    for (const line of lines) {
      const cols = line.split(",");
      if (cols.length < 4) continue;
      const rawUrl = cols[2]?.replace(/^"|"$/g, "");
      const status = cols[3]?.replace(/^"|"$/g, "");
      if (status !== "online") continue; // only actively-serving malware URLs
      const normalized = normalizeForLookup(rawUrl);
      if (!normalized || seen.has(normalized)) continue;
      seen.add(normalized);
      entries.push({ indicator: normalized, type: "malware_url", source: SOURCE_NAME, last_updated: nowIso, status: "active" });
    }

    if (entries.length === 0) return { success: false, reason: "0 valid entries parsed — treating as a bad download" };

    const meta = await threatDb.replaceSource(SOURCE_NAME, entries, { databaseVersion: nowIso, status: "active" });
    return { success: true, entryCount: entries.length, meta };
  } catch (err) {
    return { success: false, reason: err?.message || "network error" };
  }
}
