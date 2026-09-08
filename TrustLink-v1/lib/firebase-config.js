// lib/firebase-config.js
//
// Fill these in with your own Firebase project's Web App config
// (Firebase Console → Project Settings → General → Your apps → SDK setup).
// The apiKey here is NOT a secret — Firebase web API keys are meant to be
// public; access control is enforced by Firestore Security Rules
// (see firestore.rules in the project root) and Remote Config's own
// per-app scoping, not by hiding this key.
//
// Leave apiKey as "" to run TrustLink in local-only mode: everything works
// exactly the same (including Remote Config, which just falls back to the
// built-in defaults in lib/heuristics/defaults.js), it just won't pick up
// remotely-tuned detection rules or (see firestoreSyncEnabled below) sync
// scan-gate state across devices.

export const firebaseConfig = {
  apiKey: "__TRUSTLINK_FIREBASE_API_KEY__",
  authDomain: "trsutlink.firebaseapp.com",
  projectId: "trsutlink",
  storageBucket: "trsutlink.firebasestorage.app",
  messagingSenderId: "36487115218",
  appId: "1:36487115218:web:93397f2e9bdfcabfbf980b",
};

// Gates Remote Config (lib/remoteConfig.js) ONLY. Having a valid
// apiKey/projectId above is necessary for Remote Config to attempt a
// fetch, but — deliberately — it is NOT sufficient on its own to enable
// Firestore reliability sync. See firestoreSyncEnabled below.
const SOURCE_PLACEHOLDER = "__TRUSTLINK_" + "FIREBASE_API_KEY__";
export const isFirebaseConfigured = Boolean(
  firebaseConfig.apiKey &&
  firebaseConfig.apiKey !== SOURCE_PLACEHOLDER &&
  firebaseConfig.projectId
);

// Separate, explicit opt-in for lib/firebaseSync.js (Firestore sync of the
// manual-scan-count / Instagram-gate reliability fields — never URLs,
// browsing history, or scan results). Remote Config and Firestore sync are
// two independent Firebase features that happen to share one project's
// config; using Remote Config must never silently turn Firestore sync on
// as a side effect. Leave this false to use Remote Config only. Flip it to
// true ONLY after you've also completed the Firestore-specific setup in
// TrustLink-v1/README.md (Anonymous Auth enabled, Firestore database
// created, firestore.rules published) — this flag does not create or
// configure any of that for you, it only stops TrustLink from attempting
// to use it before you're ready.
export const firestoreSyncEnabled = false;

// The single value lib/firebaseSync.js actually gates on — both a valid
// config AND the explicit opt-in above must be true.
export const isFirestoreSyncConfigured = Boolean(isFirebaseConfigured && firestoreSyncEnabled);
