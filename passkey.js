import { decodeBase64Url, encodeBase64Url } from "./otp.js";

const DEVICE_UNLOCK_NAME = "Trust Codes vault";

function randomBytes(length = 32) {
  return crypto.getRandomValues(new Uint8Array(length));
}

function prfResult(credential) {
  const result = credential?.getClientExtensionResults?.()?.prf?.results?.first;
  return result ? new Uint8Array(result) : null;
}

function deviceUnlockError(error) {
  if (error?.name === "NotAllowedError") return new Error("Device unlock was cancelled or timed out.");
  if (error?.name === "SecurityError") return new Error("Device unlock requires this secure Trust Codes address.");
  if (error?.name === "InvalidStateError") return new Error("This device already has a conflicting Trust Codes passkey.");
  return new Error("This passkey provider does not support the WebAuthn PRF device-unlock feature.");
}

export function deviceUnlockAvailable(platform = globalThis) {
  return Boolean(
    platform.isSecureContext
    && platform.PublicKeyCredential
    && platform.navigator?.credentials?.create
    && platform.navigator?.credentials?.get,
  );
}

export async function deviceUnlockSupported(platform = globalThis) {
  if (!deviceUnlockAvailable(platform)) return false;
  const getCapabilities = platform.PublicKeyCredential.getClientCapabilities;
  if (typeof getCapabilities !== "function") return true;
  try {
    const capabilities = await getCapabilities.call(platform.PublicKeyCredential);
    return capabilities["extension:prf"] === true;
  } catch {
    return false;
  }
}

async function evaluateCredential(credentials, credentialId, prfInput) {
  const credential = await credentials.get({
    publicKey: {
      challenge: randomBytes(),
      allowCredentials: [{ type: "public-key", id: decodeBase64Url(credentialId) }],
      userVerification: "required",
      timeout: 60_000,
      extensions: { prf: { eval: { first: decodeBase64Url(prfInput) } } },
    },
  });
  const secret = prfResult(credential);
  if (!secret || secret.byteLength !== 32) throw new Error("This passkey did not provide a WebAuthn PRF secret.");
  return secret;
}

export async function createDeviceUnlock(credentials = navigator.credentials) {
  const prfInput = randomBytes();
  try {
    const credential = await credentials.create({
      publicKey: {
        challenge: randomBytes(),
        rp: { name: "Trust Codes" },
        user: {
          id: randomBytes(),
          name: `local-vault-${encodeBase64Url(randomBytes(9))}`,
          displayName: DEVICE_UNLOCK_NAME,
        },
        pubKeyCredParams: [
          { type: "public-key", alg: -7 },
          { type: "public-key", alg: -257 },
        ],
        authenticatorSelection: {
          authenticatorAttachment: "platform",
          residentKey: "preferred",
          userVerification: "required",
        },
        attestation: "none",
        timeout: 60_000,
        extensions: { prf: { eval: { first: prfInput } } },
      },
    });
    const extension = credential?.getClientExtensionResults?.()?.prf;
    if (extension?.enabled === false) throw new Error("This passkey provider does not support the WebAuthn PRF device-unlock feature.");
    const credentialId = encodeBase64Url(new Uint8Array(credential.rawId));
    const encodedInput = encodeBase64Url(prfInput);
    const secret = prfResult(credential) || await evaluateCredential(credentials, credentialId, encodedInput);
    return { type: "webauthn-prf", credentialId, prfInput: encodedInput, secret };
  } catch (error) {
    if (error?.message?.includes("WebAuthn PRF") || error?.message?.includes("PRF secret")) throw error;
    throw deviceUnlockError(error);
  }
}

export async function getDeviceUnlock(device, credentials = navigator.credentials) {
  if (!device || device.type !== "webauthn-prf" || !device.credentialId || !device.prfInput) {
    throw new Error("This vault does not have device unlock configured.");
  }
  try {
    const secret = await evaluateCredential(credentials, device.credentialId, device.prfInput);
    return { type: device.type, credentialId: device.credentialId, prfInput: device.prfInput, secret };
  } catch (error) {
    if (error?.message?.includes("PRF secret")) throw error;
    throw deviceUnlockError(error);
  }
}
