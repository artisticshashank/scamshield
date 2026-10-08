import assert from "node:assert/strict";
import test from "node:test";

const selectionUrl = (scanId) =>
  `/forensics?scan_id=${encodeURIComponent(scanId)}`;

test("history selection preserves the selected scan ID", () => {
  const googleId = "google-scan-id";
  const paypalId = "paypal-scan-id";
  const googleUrl = selectionUrl(googleId);
  const paypalUrl = selectionUrl(paypalId);

  assert.equal(new URL(`http://localhost:3000${googleUrl}`).searchParams.get("scan_id"), googleId);
  assert.equal(new URL(`http://localhost:3000${paypalUrl}`).searchParams.get("scan_id"), paypalId);
  assert.notEqual(googleUrl, paypalUrl);
});

test("explicit scan ID is resolved before any latest fallback", () => {
  const records = new Map([
    ["google-scan-id", { original_input: "https://www.google.com", risk_score: 1.4497808615516485 }],
    ["paypal-scan-id", {
      original_input: "https://paypal-login-security.example.com/verify-account",
      risk_score: 68.64665033835915,
    }],
  ]);
  const latest = records.get("google-scan-id");
  const requested = new URL("http://localhost:3000/forensics?scan_id=paypal-scan-id")
    .searchParams.get("scan_id");

  assert.equal(records.get(requested)?.original_input, "https://paypal-login-security.example.com/verify-account");
  assert.equal(records.get(requested)?.risk_score, 68.64665033835915);
  assert.notEqual(records.get(requested), latest);
});

test("an unknown explicit scan ID does not fall back to latest", () => {
  const records = new Map([["google-scan-id", { original_input: "https://www.google.com" }]]);
  const requested = new URL("http://localhost:3000/forensics?scan_id=missing-id")
    .searchParams.get("scan_id");

  assert.equal(records.get(requested) ?? null, null);
});
