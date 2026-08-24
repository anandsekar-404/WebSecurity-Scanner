// lib/state.js
//
// SECURITY NOTE (read this before changing gating numbers):
// This is a client-side extension with no trusted server, so no local gate
// is truly tamper-proof — a determined user can always edit chrome.storage
// via devtools. What we CAN do, and do here:
//   1. Keep the counter in chrome.storage.local, not in a page-readable
//      place (content scripts / web pages cannot read extension storage).
//   2. Mirror it to Firestore (if configured) so clearing local browser
//      data alone doesn't reset a verified user — on next load we restore
//      the higher of {local, remote} rather than trusting a wiped local
//      value of 0.
//   3. Never let the content script or an untrusted message sender set
//      these values directly — only background.js's own gating functions
//      mutate them, and message handlers only expose narrow actions
//      ("record one completed manual scan", "confirm follow"), never a
//      raw "setCount" API.

import { pullRemoteState, pushRemoteState } from "./firebaseSync.js";

const KEYS = {
  manualScanCount: "tl_manualScanCount",
  igCompleted: "tl_igCompleted",
  igVerifiedAt: "tl_igVerifiedAt",
  autoScanEnabled: "tl_autoScanEnabled",
  createdAt: "tl_createdAt",
  updatedAt: "tl_updatedAt",
};

const FREE_MANUAL_SCANS = 2; // 1st and 2nd manual scans are always free

async function getLocal(defaults) {
  return new Promise((resolve) => chrome.storage.local.get(defaults, resolve));
}
async function setLocal(values) {
  return new Promise((resolve) => chrome.storage.local.set(values, resolve));
}

/** Called once, lazily, to reconcile local state with Firebase (if configured). */
let reconciled = false;
async function reconcileWithRemote() {
  if (reconciled) return;
  reconciled = true;
  try {
    const remote = await pullRemoteState();
    if (!remote) return; // offline, unconfigured, or no remote doc yet — local stays authoritative
    const local = await getLocal({
      [KEYS.manualScanCount]: 0,
      [KEYS.igCompleted]: false,
    });
    // Never let a wiped/cleared local value silently downgrade a verified
    // or higher-count user. Take the max/most-permissive of each field.
    const merged = {
      [KEYS.manualScanCount]: Math.max(local[KEYS.manualScanCount] || 0, remote.manualScanCount || 0),
      [KEYS.igCompleted]: Boolean(local[KEYS.igCompleted] || remote.instagramRequirementCompleted),
      [KEYS.igVerifiedAt]: remote.instagramVerifiedAt || local[KEYS.igVerifiedAt] || null,
    };
    await setLocal(merged);
  } catch {
    // Offline or Firebase unreachable — local state is used as-is. Never throw.
  }
}

export async function getGateState() {
  await reconcileWithRemote();
  const data = await getLocal({
    [KEYS.manualScanCount]: 0,
    [KEYS.igCompleted]: false,
    [KEYS.igVerifiedAt]: null,
    [KEYS.autoScanEnabled]: true,
  });
  return {
    manualScanCount: data[KEYS.manualScanCount] || 0,
    instagramCompleted: Boolean(data[KEYS.igCompleted]),
    instagramVerifiedAt: data[KEYS.igVerifiedAt] || null,
    autoScanEnabled: data[KEYS.autoScanEnabled] !== false,
    freeScansRemaining: Math.max(0, FREE_MANUAL_SCANS - (data[KEYS.manualScanCount] || 0)),
  };
}

/**
 * Call BEFORE performing a manual scan. Returns whether it's allowed to
 * proceed right now, without mutating any counters (dry-run check).
 */
export async function canRunManualScan() {
  const state = await getGateState();
  if (state.manualScanCount < FREE_MANUAL_SCANS) return { allowed: true };
  if (state.instagramCompleted) return { allowed: true };
  return { allowed: false, reason: "instagram-required" };
}

/** Call AFTER a manual scan actually completes successfully. */
export async function recordManualScanCompleted() {
  const data = await getLocal({ [KEYS.manualScanCount]: 0, [KEYS.createdAt]: null });
  const count = (data[KEYS.manualScanCount] || 0) + 1;
  const now = Date.now();
  await setLocal({
    [KEYS.manualScanCount]: count,
    [KEYS.createdAt]: data[KEYS.createdAt] || now,
    [KEYS.updatedAt]: now,
  });
  pushRemoteState({ manualScanCount: count }).catch(() => {});
  return count;
}

/** User clicked "I've followed — Continue" after opening the Instagram link. */
export async function confirmInstagramFollow() {
  const now = Date.now();
  await setLocal({
    [KEYS.igCompleted]: true,
    [KEYS.igVerifiedAt]: now,
    [KEYS.updatedAt]: now,
  });
  pushRemoteState({ instagramRequirementCompleted: true, instagramVerifiedAt: now }).catch(() => {});
  return { instagramCompleted: true, instagramVerifiedAt: now };
}

export async function setAutoScanEnabled(enabled) {
  await setLocal({ [KEYS.autoScanEnabled]: Boolean(enabled), [KEYS.updatedAt]: Date.now() });
  return Boolean(enabled);
}

export async function isAutoScanEnabled() {
  const data = await getLocal({ [KEYS.autoScanEnabled]: true });
  return data[KEYS.autoScanEnabled] !== false;
}
