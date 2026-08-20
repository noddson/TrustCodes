import test from "node:test";
import assert from "node:assert/strict";

import { createDeviceUnlock, deviceUnlockAvailable, deviceUnlockSupported, getDeviceUnlock } from "./passkey.js";

function credential(rawId, extension) {
  return {
    rawId,
    getClientExtensionResults: () => ({ prf: extension }),
  };
}

test("device unlock availability requires a secure WebAuthn credential environment", () => {
  assert.equal(deviceUnlockAvailable({ isSecureContext: true, PublicKeyCredential() {}, navigator: { credentials: { create() {}, get() {} } } }), true);
  assert.equal(deviceUnlockAvailable({ isSecureContext: false, PublicKeyCredential() {}, navigator: { credentials: { create() {}, get() {} } } }), false);
  assert.equal(deviceUnlockAvailable({ isSecureContext: true, navigator: { credentials: { create() {}, get() {} } } }), false);
});

test("client capability detection honors an explicit WebAuthn PRF result", async () => {
  const platform = (prf) => ({
    isSecureContext: true,
    PublicKeyCredential: { getClientCapabilities: async () => ({ "extension:prf": prf }) },
    navigator: { credentials: { create() {}, get() {} } },
  });
  assert.equal(await deviceUnlockSupported(platform(true)), true);
  assert.equal(await deviceUnlockSupported(platform(false)), false);
  assert.equal(await deviceUnlockSupported({ ...platform(true), PublicKeyCredential: {} }), true);
});

test("creating device unlock captures a credential-bound 32-byte PRF secret", async () => {
  const rawId = new Uint8Array([1, 2, 3, 4]);
  const secret = new Uint8Array(32).fill(7);
  let creationOptions;
  const result = await createDeviceUnlock({
    async create(options) {
      creationOptions = options;
      return credential(rawId, { enabled: true, results: { first: secret.buffer } });
    },
    async get() { throw new Error("assertion should not be needed"); },
  });
  assert.equal(result.type, "webauthn-prf");
  assert.equal(result.secret.byteLength, 32);
  assert.deepEqual(result.secret, secret);
  assert.equal(creationOptions.publicKey.authenticatorSelection.userVerification, "required");
  assert.equal(creationOptions.publicKey.authenticatorSelection.authenticatorAttachment, "platform");
  assert.equal(creationOptions.publicKey.extensions.prf.eval.first.byteLength, 32);
});

test("creation obtains the PRF secret with an assertion when registration returns only enabled", async () => {
  const rawId = new Uint8Array([5, 6, 7]);
  const secret = new Uint8Array(32).fill(9);
  let assertionOptions;
  const result = await createDeviceUnlock({
    async create() { return credential(rawId, { enabled: true }); },
    async get(options) {
      assertionOptions = options;
      return credential(rawId, { results: { first: secret.buffer } });
    },
  });
  assert.deepEqual(result.secret, secret);
  assert.equal(assertionOptions.publicKey.userVerification, "required");
  assert.equal(assertionOptions.publicKey.allowCredentials.length, 1);
});

test("an existing device credential is evaluated with its stored PRF input", async () => {
  const secret = new Uint8Array(32).fill(11);
  let assertionOptions;
  const device = await getDeviceUnlock({ type: "webauthn-prf", credentialId: "AQID", prfInput: "BAUG" }, {
    async get(options) {
      assertionOptions = options;
      return credential(new Uint8Array([1, 2, 3]), { results: { first: secret.buffer } });
    },
  });
  assert.deepEqual(device.secret, secret);
  assert.equal(device.credentialId, "AQID");
  assert.deepEqual(new Uint8Array(assertionOptions.publicKey.extensions.prf.eval.first), new Uint8Array([4, 5, 6]));
});

test("a passkey provider without PRF support is rejected", async () => {
  await assert.rejects(
    createDeviceUnlock({
      async create() { return credential(new Uint8Array([1]), { enabled: false }); },
      async get() { throw new Error("not reached"); },
    }),
    /WebAuthn PRF/i,
  );
});
