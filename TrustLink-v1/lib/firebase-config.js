// lib/firebase-config.js
//
// Fill these in with your own Firebase project's Web App config
// (Firebase Console → Project Settings → General → Your apps → SDK setup).
// The apiKey here is NOT a secret — Firebase web API keys are meant to be
// public; access control is enforced by Firestore Security Rules
// (see firestore.rules in the project root), not by hiding this key.
//
// Leave apiKey as "" to run TrustLink in local-only mode: everything works
// exactly the same, it just won't sync across devices/browsers.

export const firebaseConfig = {
  apiKey: "",
  projectId: "",
};

export const isFirebaseConfigured = Boolean(firebaseConfig.apiKey && firebaseConfig.projectId);
