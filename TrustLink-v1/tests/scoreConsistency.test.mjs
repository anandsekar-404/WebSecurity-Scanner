// tests/scoreConsistency.test.mjs
// Verifies score boundary invariants, NaN/Infinity protections, and consistent severity grading.

import assert from "node:assert/strict";
import { clampScore, grade, analyzeUrl, applyThreatMatch, THRESHOLDS } from "../analyzer.js";

function testScoreClamping() {
  console.log("Scenario: clampScore boundary and invariant testing");

  // Valid boundaries
  assert.equal(clampScore(0), 0, "clampScore(0) is 0");
  assert.equal(clampScore(1), 1, "clampScore(1) is 1");
  assert.equal(clampScore(29), 29, "clampScore(29) is 29");
  assert.equal(clampScore(30), 30, "clampScore(30) is 30");
  assert.equal(clampScore(59), 59, "clampScore(59) is 59");
  assert.equal(clampScore(60), 60, "clampScore(60) is 60");
  assert.equal(clampScore(99), 99, "clampScore(99) is 99");
  assert.equal(clampScore(100), 100, "clampScore(100) is 100");

  // Negative boundaries
  assert.equal(clampScore(-0.1), 0, "clampScore(-0.1) clamps to 0");
  assert.equal(clampScore(-1), 0, "clampScore(-1) clamps to 0");
  assert.equal(clampScore(-100), 0, "clampScore(-100) clamps to 0");

  // Exceeding boundaries
  assert.equal(clampScore(100.1), 100, "clampScore(100.1) clamps to 100");
  assert.equal(clampScore(101), 100, "clampScore(101) clamps to 100");
  assert.equal(clampScore(9999), 100, "clampScore(9999) clamps to 100");

  // Non-finite / malformed inputs
  assert.equal(clampScore(NaN), 0, "clampScore(NaN) defaults safely to 0");
  assert.equal(clampScore(Infinity), 0, "clampScore(Infinity) defaults safely to 0");
  assert.equal(clampScore(-Infinity), 0, "clampScore(-Infinity) defaults safely to 0");
  assert.equal(clampScore(null), 0, "clampScore(null) defaults safely to 0");
  assert.equal(clampScore(undefined), 0, "clampScore(undefined) defaults safely to 0");
  assert.equal(clampScore("not-a-number"), 0, "clampScore('not-a-number') defaults safely to 0");
  assert.equal(clampScore("42"), 42, "clampScore('42') coerces valid numeric string to 42");

  console.log("  ok - clampScore satisfies all boundary invariants [0, 100]");
}

function testGradeBoundaries() {
  console.log("\nScenario: grade() severity bands and boundary consistency");

  // Safe tier: [0, 29]
  {
    const g0 = grade(0);
    assert.equal(g0.tone, "safe");
    assert.equal(g0.label, "Looks Safe");

    const g1 = grade(1);
    assert.equal(g1.tone, "safe");
    assert.equal(g1.label, "Looks Safe");

    const g29 = grade(29);
    assert.equal(g29.tone, "safe");
    assert.equal(g29.label, "Looks Safe");
  }

  // Caution tier: [30, 59]
  {
    const g30 = grade(30);
    assert.equal(g30.tone, "warning");
    assert.equal(g30.label, "Use Caution");

    const g45 = grade(45);
    assert.equal(g45.tone, "warning");
    assert.equal(g45.label, "Use Caution");

    const g59 = grade(59);
    assert.equal(g59.tone, "warning");
    assert.equal(g59.label, "Use Caution");
  }

  // High Risk tier: [60, 100]
  {
    const g60 = grade(60);
    assert.equal(g60.tone, "danger");
    assert.equal(g60.label, "High Risk");

    const g85 = grade(85);
    assert.equal(g85.tone, "danger");
    assert.equal(g85.label, "High Risk");

    const g100 = grade(100);
    assert.equal(g100.tone, "danger");
    assert.equal(g100.label, "High Risk");
  }

  // Out of range inputs (clamped behavior)
  {
    const gNeg = grade(-15);
    assert.equal(gNeg.tone, "safe", "Negative score clamped to 0 -> safe");

    const gOver = grade(120);
    assert.equal(gOver.tone, "danger", "Score > 100 clamped to 100 -> danger");
  }

  // Malformed / Non-finite inputs must NEVER be classified as 'safe'
  {
    const gNan = grade(NaN);
    assert.notEqual(gNan.tone, "safe", "NaN score is NEVER classified as safe");
    assert.equal(gNan.tone, "warning", "NaN score returns warning tier");
    assert.equal(gNan.label, "Check Unavailable");

    const gInf = grade(Infinity);
    assert.notEqual(gInf.tone, "safe", "Infinity score is NEVER classified as safe");
    assert.equal(gInf.tone, "warning");

    const gNull = grade(null);
    assert.notEqual(gNull.tone, "safe", "null score is NEVER classified as safe");
    assert.equal(gNull.tone, "warning");

    const gUndef = grade(undefined);
    assert.notEqual(gUndef.tone, "safe", "undefined score is NEVER classified as safe");
    assert.equal(gUndef.tone, "warning");
  }

  console.log("  ok - grade() adheres to exact severity boundaries (0-29 Safe, 30-59 Caution, 60-100 Danger)");
  console.log("  ok - grade() never silently treats NaN or non-finite inputs as safe");
}

function testThreatMatchAndConfidence() {
  console.log("\nScenario: applyThreatMatch and confidence attribution");

  const baseResult = {
    score: 2,
    tone: "safe",
    label: "Looks Safe",
    action: "No strong signs",
    findings: [{ id: "https", level: "good", title: "Encrypted connection" }],
  };

  const threatMatch = {
    source: "OpenPhish",
    type: "phishing_url",
    lastUpdated: "2026-10-14T00:00:00Z",
  };

  const criticalResult = applyThreatMatch(baseResult, threatMatch);

  assert.equal(criticalResult.score, 100, "Threat match sets score to 100");
  assert.equal(criticalResult.tone, "critical", "Threat match produces tone 'critical'");
  assert.equal(criticalResult.label, "Known Threat", "Threat match produces label 'Known Threat'");
  assert.equal(criticalResult.confidence, "verified", "Threat match is explicitly confidence: verified");
  assert.equal(criticalResult.findings[0].id, "known-threat-match", "Prepend known-threat-match finding");

  // Verify heuristic scan preserves confidence: 'heuristic'
  const heuristicResult = analyzeUrl("https://example.com");
  assert.equal(heuristicResult.confidence, "heuristic", "analyzeUrl outputs confidence: heuristic");

  // Verify malformed URL scan has confidence: 'none'
  const invalidResult = analyzeUrl("not_a_valid_url");
  assert.equal(invalidResult.confidence, "none", "Invalid URL outputs confidence: none");
  assert.equal(invalidResult.error, "Malformed address", "Invalid URL returns descriptive error");

  console.log("  ok - verified threat matches produce critical 100 with confidence: verified");
  console.log("  ok - heuristic scans produce confidence: heuristic");
}

function run() {
  console.log("========================================================");
  console.log("TrustLink Score Boundary & Consistency Verification");
  console.log("========================================================");
  testScoreClamping();
  testGradeBoundaries();
  testThreatMatchAndConfidence();
  console.log("\nALL SCORE CONSISTENCY & BOUNDARY TESTS PASSED");
}

run();
