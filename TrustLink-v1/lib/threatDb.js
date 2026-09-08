// lib/threatDb.js — spec sections 20-22, 39-42
//
// Provider-independent local threat database. Adapters (lib/adapters/*.js)
// call replaceSource() to publish a freshly-downloaded, freshly-validated
// feed; analyzer.js/background.js call lookup() for O(1) exact matching —
// never a linear scan, per spec section 42's explicit performance
// requirement.
//
// Storage backend: real IndexedDB when it's available (every actual Chrome
// MV3 service worker has it — this is what gives TrustLink a threat
// database that survives the service worker being unloaded between
// navigations, without needing SQLite or any external dependency). When
// `indexedDB` isn't present (this is ONLY true today inside the plain-Node
// test environment — see tests/threatDb.test.mjs), an equivalent in-memory
// Map is used automatically so the exact same code path is exercised by
// tests with zero special-casing. Both implementations satisfy the same
// contract below and are equally "atomic" for a single replaceSource()
// call — IndexedDB via one readwrite transaction, memory trivially via JS's
// single-threaded execution.
//
// A lookup MISS is not a verdict. See lookup()'s return shape.

const DB_NAME = "trustlink-threatdb";
const DB_VERSION = 1;
const STORE_INDICATORS = "indicators";
const STORE_META = "meta";

function hasIndexedDb() {
  return typeof indexedDB !== "undefined";
}

// --- IndexedDB-backed implementation ---------------------------------------

function openIdb() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(STORE_INDICATORS)) {
        const store = db.createObjectStore(STORE_INDICATORS, { keyPath: "indicator" });
        store.createIndex("bySource", "source", { unique: false });
      }
      if (!db.objectStoreNames.contains(STORE_META)) {
        db.createObjectStore(STORE_META, { keyPath: "source" });
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

function idbRequest(req) {
  return new Promise((resolve, reject) => {
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

function createIndexedDbBackend() {
  let dbPromise = null;
  const getDb = () => (dbPromise ||= openIdb());

  return {
    async lookup(indicator) {
      const db = await getDb();
      const tx = db.transaction(STORE_INDICATORS, "readonly");
      const result = await idbRequest(tx.objectStore(STORE_INDICATORS).get(indicator));
      return result || null;
    },
    async replaceSource(source, entries, meta) {
      const db = await getDb();
      const tx = db.transaction([STORE_INDICATORS, STORE_META], "readwrite");
      const indicatorStore = tx.objectStore(STORE_INDICATORS);
      const idx = indicatorStore.index("bySource");
      // Delete every existing entry for this source first (within the SAME
      // transaction as the inserts below — if anything fails, IndexedDB
      // rolls the whole transaction back and the previous entries for this
      // source are left exactly as they were: spec section 39's "atomic
      // database replacement" / "never delete a valid database because an
      // update failed").
      const existingKeys = await idbRequest(idx.getAllKeys(IDBKeyRange.only(source)));
      for (const key of existingKeys) indicatorStore.delete(key);
      for (const entry of entries) indicatorStore.put(entry);
      tx.objectStore(STORE_META).put({ source, ...meta });
      return new Promise((resolve, reject) => {
        tx.oncomplete = () => resolve(true);
        tx.onerror = () => reject(tx.error);
        tx.onabort = () => reject(tx.error || new Error("transaction aborted"));
      });
    },
    async getMeta(source) {
      const db = await getDb();
      const tx = db.transaction(STORE_META, "readonly");
      const result = await idbRequest(tx.objectStore(STORE_META).get(source));
      return result || null;
    },
    async getAllMeta() {
      const db = await getDb();
      const tx = db.transaction(STORE_META, "readonly");
      return idbRequest(tx.objectStore(STORE_META).getAll());
    },
    async countBySource(source) {
      const db = await getDb();
      const tx = db.transaction(STORE_INDICATORS, "readonly");
      const idx = tx.objectStore(STORE_INDICATORS).index("bySource");
      return idbRequest(idx.count(IDBKeyRange.only(source)));
    },
  };
}

// --- In-memory fallback (used automatically wherever indexedDB is absent) --

function createMemoryBackend() {
  const indicators = new Map(); // indicator -> entry
  const meta = new Map(); // source -> meta

  return {
    async lookup(indicator) {
      return indicators.get(indicator) || null;
    },
    async replaceSource(source, entries, entryMeta) {
      for (const [key, entry] of indicators) {
        if (entry.source === source) indicators.delete(key);
      }
      for (const entry of entries) indicators.set(entry.indicator, entry);
      meta.set(source, { source, ...entryMeta });
      return true;
    },
    async getMeta(source) {
      return meta.get(source) || null;
    },
    async getAllMeta() {
      return [...meta.values()];
    },
    async countBySource(source) {
      let n = 0;
      for (const entry of indicators.values()) if (entry.source === source) n++;
      return n;
    },
  };
}

/**
 * Creates a ThreatDb instance. `backend` can be injected directly (used by
 * tests that want to assert against a known backend); otherwise the right
 * backend is chosen automatically.
 */
export function createThreatDb(backend = hasIndexedDb() ? createIndexedDbBackend() : createMemoryBackend()) {
  return {
    /**
     * Exact-match lookup. Returns { matched: true, source, type, lastUpdated }
     * or { matched: false } — a miss is explicitly "no known match", never
     * "safe" (spec section 22/38).
     */
    async lookup(normalizedIndicator) {
      if (!normalizedIndicator) return { matched: false };
      const entry = await backend.lookup(normalizedIndicator);
      if (!entry) return { matched: false };
      return { matched: true, source: entry.source, type: entry.type, lastUpdated: entry.last_updated };
    },

    /**
     * Atomically replaces every entry previously stored for `source` with
     * `entries` (each already validated/shaped by the calling adapter — see
     * lib/adapters/openphish.js). Updates that source's metadata (spec
     * section 41). Throws only if the underlying transaction genuinely
     * fails — the CALLER (the adapter) is responsible for catching that and
     * leaving the previous database untouched, i.e. simply not calling
     * this at all when the download/validation step failed.
     */
    async replaceSource(source, entries, { databaseVersion, status = "active" } = {}) {
      const meta = {
        database_version: databaseVersion || new Date().toISOString(),
        last_successful_update: new Date().toISOString(),
        entry_count: entries.length,
        database_status: status,
      };
      await backend.replaceSource(source, entries, meta);
      return meta;
    },

    async getMeta(source) {
      return backend.getMeta(source);
    },

    async getStatus() {
      return backend.getAllMeta();
    },

    async countBySource(source) {
      return backend.countBySource(source);
    },
  };
}

/**
 * The single shared instance every part of the extension should use —
 * background.js, lib/blocking.js, and the adapters all need to be reading
 * and writing the SAME database. Import this rather than calling
 * createThreatDb() yourself unless you specifically need an isolated
 * instance (e.g. a focused unit test).
 */
export const defaultThreatDb = createThreatDb();
