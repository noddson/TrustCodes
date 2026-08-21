import test from "node:test";
import assert from "node:assert/strict";
import { assessVaultPassword, generateVaultRecoveryCode, isGeneratedVaultRecoveryCode } from "./vault-password.js";

test("recovery codes contain 160 on-device random bits in a distinct format", () => {
  const code = generateVaultRecoveryCode(Uint8Array.from({ length: 20 }, (_, index) => index));
  assert.equal(code, "TCVR-000G-40R4-0M30-E209-185G-R38E-1W81-24GK");
  assert.equal(isGeneratedVaultRecoveryCode(code), true);
  assert.equal(assessVaultPassword(code).label, "Excellent");
});

test("user-chosen recovery passwords require length but not composition", () => {
  assert.match(assessVaultPassword("seven7").problem, /8/);
  assert.equal(assessVaultPassword("8charsok").acceptable, true);
  assert.equal(assessVaultPassword("8charsok").label, "Weak");
  assert.equal(assessVaultPassword("orchid lantern meadow riverstone").acceptable, true);
  assert.equal(assessVaultPassword("alllowercasebutlongandunique").acceptable, true);
});

test("common, predictable, sequential, and repeated passwords remain a warned user choice", () => {
  for (const password of ["Password123!!!!", "P@ssw0rd1234567", "TrustCodes2026!!!", "recovery-password-123", "abcabcabcabcabc", "0123456789012345", "password password password password password"]) {
    const assessment = assessVaultPassword(password);
    assert.equal(assessment.acceptable, true, password);
    assert.equal(assessment.label, "Weak", password);
    assert.match(assessment.warning, /allowed|easier to compromise/i, password);
  }
});

test("Good passwords are accepted with a warning and longer values rate higher", () => {
  const good = assessVaultPassword("moss-cabin-47-owl");
  assert.equal(good.label, "Good");
  assert.equal(good.acceptable, true);
  assert.match(good.warning, /Strong or Excellent/);
  assert.equal(assessVaultPassword("moss cabin zephyr violet").label, "Strong");
  assert.equal(assessVaultPassword("moss cabin zephyr violet lantern").label, "Excellent");
});
