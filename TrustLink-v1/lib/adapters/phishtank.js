// lib/adapters/phishtank.js — spec section 18
//
// STATUS: NOT INTEGRATED. Documented, not fabricated.
//
// PhishTank's API has required a registered "app key" for its data-dump
// downloads, and — critically — PhishTank has NOT accepted new user/API-key
// registrations since 2020. There is currently no officially-available
// keyless path to PhishTank's data for a new project, and this project does
// not have (and will not fabricate) an app key.
//
// Per spec section 18 ("If no official keyless feed is available, do not
// fabricate one") and section 45 ("never use leaked API keys... never claim
// unlimited access when the provider imposes limits"), this adapter is a
// documented no-op: the interface exists so PhishTank can be wired in the
// moment that changes (e.g. if you obtain a legacy/grandfathered app key),
// but it makes ZERO network calls today.
//
// feature_phishtank defaults to false in lib/heuristics/defaults.js for
// exactly this reason — flip it on only after actually supplying a working
// app key below AND re-verifying PhishTank's current terms yourself, since
// this could change again after this was written.

export const SOURCE_NAME = "PhishTank";
export const isAvailable = false;
export const unavailableReason = "PhishTank has not accepted new API-key registrations since 2020 — no keyless feed exists for a new integration.";

export async function updatePhishTankFeed() {
  return { success: false, skipped: true, reason: unavailableReason };
}
