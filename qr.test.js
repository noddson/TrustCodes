import test from "node:test";
import assert from "node:assert/strict";
import jsQR from "jsqr";

import { createQrMatrix, renderQrPixels } from "./qr.js";
import { cameraErrorMessage, normalizeScannedSetupCode } from "./qr-scanner.js";

test("generated setup QR codes decode to the exact original payload", () => {
  const setupCode = `TC2-${"A1b2C3d4E5f6G7h8J9k0".repeat(18)}`;
  const pixels = renderQrPixels(createQrMatrix(setupCode), 420);
  const decoded = jsQR(pixels.data, pixels.width, pixels.height, { inversionAttempts: "dontInvert" });
  assert.equal(decoded?.data, setupCode);
});

test("QR generation rejects empty or oversized values", () => {
  assert.throws(() => createQrMatrix(""), /cannot be represented/i);
  assert.throws(() => createQrMatrix("X".repeat(20_001)), /cannot be represented/i);
});

test("the scanner accepts only bounded TrustCodes setup payloads", () => {
  assert.equal(normalizeScannedSetupCode("  TC1-abc123  "), "");
  assert.equal(normalizeScannedSetupCode("  TC2-encrypted123  "), "TC2-encrypted123");
  assert.equal(normalizeScannedSetupCode("https://example.com"), "");
  assert.equal(normalizeScannedSetupCode(`TC2-${"a".repeat(20_000)}`), "");
  assert.equal(normalizeScannedSetupCode("TC3-unsupported"), "");
});

test("camera failures have actionable privacy-preserving messages", () => {
  assert.match(cameraErrorMessage({ name: "NotAllowedError" }, true), /not allowed/i);
  assert.match(cameraErrorMessage({ name: "NotFoundError" }, true), /no compatible camera/i);
  assert.match(cameraErrorMessage({}, false), /HTTPS or localhost/i);
});
