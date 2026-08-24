// lib/firebaseSync.js
//
// Uses the Firebase REST APIs directly (Identity Toolkit for anonymous auth,
// Firestore v1 REST for the database) instead of bundling the Firebase JS
// SDK. This keeps the extension package small and avoids shipping a large
// third-party bundle. Every function here is best-effort and MUST NOT throw
// out to the caller — sync failures should never block or corrupt the
// local, authoritative chrome.storage.local state.

import { firebaseConfig, isFirebaseConfigured } from "./firebase-config.js";

const TOKEN_KEYS = {
  uid: "tl_fb_uid",
  idToken: "tl_fb_idToken",
  idTokenExpiry: "tl_fb_idTokenExpiry",
  refreshToken: "tl_fb_refreshToken",
};

async function getLocal(defaults) {
  return new Promise((resolve) => chrome.storage.local.get(defaults, resolve));
}
async function setLocal(values) {
  return new Promise((resolve) => chrome.storage.local.set(values, resolve));
}

async function signUpAnonymous() {
  const res = await fetch(
    `https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=${encodeURIComponent(firebaseConfig.apiKey)}`,
    { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ returnSecureToken: true }) }
  );
  if (!res.ok) throw new Error(`Firebase anonymous sign-in failed (${res.status})`);
  return res.json(); // { idToken, refreshToken, localId, expiresIn }
}

async function refreshIdToken(refreshToken) {
  const res = await fetch(`https://securetoken.googleapis.com/v1/token?key=${encodeURIComponent(firebaseConfig.apiKey)}`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: "refresh_token", refresh_token: refreshToken }).toString(),
  });
  if (!res.ok) throw new Error(`Firebase token refresh failed (${res.status})`);
  const data = await res.json();
  return { idToken: data.id_token, refreshToken: data.refresh_token, expiresIn: data.expires_in, uid: data.user_id };
}

/** Returns { uid, idToken } or null if unconfigured/offline/failed. Never throws. */
async function getAuthContext() {
  if (!isFirebaseConfigured) return null;
  try {
    const cached = await getLocal(TOKEN_KEYS);
    const now = Date.now();

    if (cached[TOKEN_KEYS.idToken] && cached[TOKEN_KEYS.idTokenExpiry] > now + 30_000) {
      return { uid: cached[TOKEN_KEYS.uid], idToken: cached[TOKEN_KEYS.idToken] };
    }

    if (cached[TOKEN_KEYS.refreshToken]) {
      const refreshed = await refreshIdToken(cached[TOKEN_KEYS.refreshToken]);
      await setLocal({
        [TOKEN_KEYS.uid]: refreshed.uid || cached[TOKEN_KEYS.uid],
        [TOKEN_KEYS.idToken]: refreshed.idToken,
        [TOKEN_KEYS.refreshToken]: refreshed.refreshToken,
        [TOKEN_KEYS.idTokenExpiry]: now + Number(refreshed.expiresIn || 3600) * 1000,
      });
      return { uid: refreshed.uid || cached[TOKEN_KEYS.uid], idToken: refreshed.idToken };
    }

    const created = await signUpAnonymous();
    await setLocal({
      [TOKEN_KEYS.uid]: created.localId,
      [TOKEN_KEYS.idToken]: created.idToken,
      [TOKEN_KEYS.refreshToken]: created.refreshToken,
      [TOKEN_KEYS.idTokenExpiry]: now + Number(created.expiresIn || 3600) * 1000,
    });
    return { uid: created.localId, idToken: created.idToken };
  } catch {
    return null; // offline or Firebase unreachable — caller falls back to local-only
  }
}

function docUrl(uid) {
  return `https://firestore.googleapis.com/v1/projects/${encodeURIComponent(firebaseConfig.projectId)}/databases/(default)/documents/users/${encodeURIComponent(uid)}`;
}

function toFirestoreFields(obj) {
  const fields = {};
  for (const [key, value] of Object.entries(obj)) {
    if (typeof value === "boolean") fields[key] = { booleanValue: value };
    else if (typeof value === "number") fields[key] = { integerValue: String(Math.round(value)) };
    else if (value === null || value === undefined) fields[key] = { nullValue: null };
    else fields[key] = { stringValue: String(value) };
  }
  return fields;
}

function fromFirestoreFields(fields) {
  const out = {};
  for (const [key, wrapped] of Object.entries(fields || {})) {
    if ("booleanValue" in wrapped) out[key] = wrapped.booleanValue;
    else if ("integerValue" in wrapped) out[key] = Number(wrapped.integerValue);
    else if ("doubleValue" in wrapped) out[key] = Number(wrapped.doubleValue);
    else if ("nullValue" in wrapped) out[key] = null;
    else if ("stringValue" in wrapped) out[key] = wrapped.stringValue;
  }
  return out;
}

/** Reads the user's remote reliability doc. Returns null if unavailable for any reason. */
export async function pullRemoteState() {
  const auth = await getAuthContext();
  if (!auth) return null;
  try {
    const res = await fetch(docUrl(auth.uid), { headers: { Authorization: `Bearer ${auth.idToken}` } });
    if (res.status === 404) return null; // no remote doc yet — will be created on first push
    if (!res.ok) return null;
    const doc = await res.json();
    return fromFirestoreFields(doc.fields);
  } catch {
    return null;
  }
}

/**
 * Upserts (merges) the given fields into the user's remote doc.
 * Fire-and-forget from the caller's perspective — never throws.
 */
export async function pushRemoteState(partial) {
  const auth = await getAuthContext();
  if (!auth) return false;
  try {
    const payload = { ...partial, updatedAt: Date.now() };
    const mask = Object.keys(payload).map((k) => `updateMask.fieldPaths=${encodeURIComponent(k)}`).join("&");
    const res = await fetch(`${docUrl(auth.uid)}?${mask}`, {
      method: "PATCH",
      headers: { Authorization: `Bearer ${auth.idToken}`, "Content-Type": "application/json" },
      body: JSON.stringify({ fields: toFirestoreFields(payload) }),
    });
    return res.ok;
  } catch {
    return false;
  }
}
