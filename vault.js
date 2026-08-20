import { decodeBase64Url, encodeBase64Url } from "./otp.js";

const DB_NAME = "trust-codes-vault";
const STORE_NAME = "vault";
const RECORD_ID = "primary";
export const VAULT_ITERATIONS = 600_000;
const AAD_V1 = new TextEncoder().encode("TrustCodesVault/v1");
const AAD_V2 = new TextEncoder().encode("TrustCodesVault/v2");
const PASSWORD_WRAP_AAD = new TextEncoder().encode("TrustCodesVault/password-wrap/v1");
const DEVICE_WRAP_AAD = new TextEncoder().encode("TrustCodesVault/device-wrap/v1");
const DEVICE_KDF_INFO = new TextEncoder().encode("TrustCodesVault/WebAuthn-PRF/v1");

function openDatabase() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, 1);
    request.onupgradeneeded = () => request.result.createObjectStore(STORE_NAME, { keyPath: "id" });
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

async function withStore(mode, action) {
  const database = await openDatabase();
  try {
    return await new Promise((resolve, reject) => {
      const transaction = database.transaction(STORE_NAME, mode);
      const request = action(transaction.objectStore(STORE_NAME));
      let result;
      request.onsuccess = () => { result = request.result; };
      request.onerror = () => reject(request.error);
      transaction.oncomplete = () => resolve(result);
      transaction.onerror = () => reject(transaction.error);
      transaction.onabort = () => reject(transaction.error || new Error("The vault storage transaction was aborted."));
    });
  } finally {
    database.close();
  }
}

export async function getVaultRecord() {
  return withStore("readonly", (store) => store.get(RECORD_ID));
}

export async function vaultExists() {
  return Boolean(await getVaultRecord());
}

export async function purgeVault() {
  await withStore("readwrite", (store) => store.delete(RECORD_ID));
}

export async function getVaultDevice() {
  const device = (await getVaultRecord())?.device;
  if (!device) return null;
  const { wrappedKey, hkdfSalt, ...publicDevice } = device;
  return publicDevice;
}

export async function deriveVaultKey(passphrase, salt, iterations = VAULT_ITERATIONS) {
  const material = await crypto.subtle.importKey("raw", new TextEncoder().encode(passphrase.normalize("NFC")), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

async function deriveDeviceKey(secret, salt) {
  const material = await crypto.subtle.importKey("raw", secret, "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt, info: DEVICE_KDF_INFO },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

async function encryptBytes(bytes, key, additionalData) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData }, key, bytes);
  return { iv: encodeBase64Url(iv), ciphertext: encodeBase64Url(new Uint8Array(ciphertext)) };
}

async function decryptBytes(record, key, additionalData) {
  return new Uint8Array(await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: decodeBase64Url(record.iv), additionalData },
    key,
    decodeBase64Url(record.ciphertext),
  ));
}

async function importDataKey(rawKey) {
  return crypto.subtle.importKey("raw", rawKey, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}

export async function encryptVaultEntries(entries, key, iv = crypto.getRandomValues(new Uint8Array(12)), additionalData = AAD_V1) {
  const safeEntries = entries.map((entry) => {
    const { context, contextRequired, ...safe } = entry;
    return safe;
  });
  const plaintext = new TextEncoder().encode(JSON.stringify(safeEntries));
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData }, key, plaintext);
  return { iv: encodeBase64Url(iv), ciphertext: encodeBase64Url(new Uint8Array(ciphertext)) };
}

export async function decryptVaultEntries(record, key, additionalData = AAD_V1) {
  try {
    const plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: decodeBase64Url(record.iv), additionalData },
      key,
      decodeBase64Url(record.ciphertext),
    );
    const entries = JSON.parse(new TextDecoder().decode(plaintext));
    if (!Array.isArray(entries)) throw new Error();
    return entries;
  } catch {
    throw new Error("The vault password or device unlock is incorrect, or the vault data is damaged.");
  }
}

function supportedV1(record) {
  return record?.version === 1 && record.kdf === "PBKDF2-HMAC-SHA256" && record.iterations === VAULT_ITERATIONS;
}

function supportedV2(record) {
  return record?.version === 2
    && record.password?.kdf === "PBKDF2-HMAC-SHA256"
    && record.password?.iterations === VAULT_ITERATIONS
    && record.password?.wrappedKey;
}

async function decryptEntriesForRecord(record, key) {
  return decryptVaultEntries(record, key, record.version === 2 ? AAD_V2 : AAD_V1);
}

async function makeV2Record(passphrase, entries, deviceAccess = null) {
  const rawDataKey = crypto.getRandomValues(new Uint8Array(32));
  const dataKey = await importDataKey(rawDataKey);
  const passwordSalt = crypto.getRandomValues(new Uint8Array(16));
  const passwordKey = await deriveVaultKey(passphrase, passwordSalt);
  const password = {
    kdf: "PBKDF2-HMAC-SHA256",
    iterations: VAULT_ITERATIONS,
    salt: encodeBase64Url(passwordSalt),
    wrappedKey: await encryptBytes(rawDataKey, passwordKey, PASSWORD_WRAP_AAD),
  };
  let device = null;
  if (deviceAccess) {
    if (deviceAccess.type !== "webauthn-prf" || !deviceAccess.credentialId || !deviceAccess.prfInput || deviceAccess.secret?.byteLength !== 32) {
      throw new Error("The device-unlock credential is incomplete.");
    }
    const hkdfSalt = crypto.getRandomValues(new Uint8Array(16));
    const deviceKey = await deriveDeviceKey(deviceAccess.secret, hkdfSalt);
    device = {
      type: deviceAccess.type,
      credentialId: deviceAccess.credentialId,
      prfInput: deviceAccess.prfInput,
      hkdfSalt: encodeBase64Url(hkdfSalt),
      wrappedKey: await encryptBytes(rawDataKey, deviceKey, DEVICE_WRAP_AAD),
    };
  }
  rawDataKey.fill(0);
  return {
    key: dataKey,
    record: {
      id: RECORD_ID,
      version: 2,
      cipher: "AES-256-GCM",
      password,
      ...(device ? { device } : {}),
      ...await encryptVaultEntries(entries, dataKey, undefined, AAD_V2),
    },
  };
}

export async function createVault(passphrase, entries = [], deviceAccess = null) {
  const next = await makeV2Record(passphrase, entries, deviceAccess);
  await withStore("readwrite", (store) => store.put(next.record));
  return next.key;
}

export async function unlockVault(passphrase) {
  const record = await getVaultRecord();
  if (supportedV1(record)) {
    const key = await deriveVaultKey(passphrase, decodeBase64Url(record.salt), record.iterations);
    return { key, entries: await decryptVaultEntries(record, key) };
  }
  if (!supportedV2(record)) throw new Error("No supported encrypted vault was found.");
  try {
    const passwordKey = await deriveVaultKey(passphrase, decodeBase64Url(record.password.salt), record.password.iterations);
    const rawDataKey = await decryptBytes(record.password.wrappedKey, passwordKey, PASSWORD_WRAP_AAD);
    const key = await importDataKey(rawDataKey);
    rawDataKey.fill(0);
    return { key, entries: await decryptEntriesForRecord(record, key) };
  } catch {
    throw new Error("The vault password is incorrect or the vault data is damaged.");
  }
}

export async function unlockVaultWithDevice(deviceAccess) {
  const record = await getVaultRecord();
  if (!supportedV2(record) || !record.device) throw new Error("This vault does not have device unlock configured.");
  if (deviceAccess?.credentialId !== record.device.credentialId || deviceAccess?.secret?.byteLength !== 32) {
    throw new Error("The device-unlock credential does not match this vault.");
  }
  try {
    const deviceKey = await deriveDeviceKey(deviceAccess.secret, decodeBase64Url(record.device.hkdfSalt));
    const rawDataKey = await decryptBytes(record.device.wrappedKey, deviceKey, DEVICE_WRAP_AAD);
    const key = await importDataKey(rawDataKey);
    rawDataKey.fill(0);
    return { key, entries: await decryptEntriesForRecord(record, key) };
  } catch {
    throw new Error("Device unlock could not decrypt this vault. Use the recovery password instead.");
  }
}

export async function updateVaultCredentials(currentKey, newPassphrase, entries, deviceAccess = null) {
  const record = await getVaultRecord();
  if (!record || (!supportedV1(record) && !supportedV2(record))) throw new Error("No supported encrypted vault was found.");
  await decryptEntriesForRecord(record, currentKey);
  const next = await makeV2Record(newPassphrase, entries, deviceAccess);
  await withStore("readwrite", (store) => store.put(next.record));
  return next.key;
}

export async function changeVaultPassphrase(currentPassphrase, newPassphrase, entries, deviceAccess = null) {
  const current = await unlockVault(currentPassphrase);
  return updateVaultCredentials(current.key, newPassphrase, entries, deviceAccess);
}

export async function saveVault(key, entries) {
  const record = await getVaultRecord();
  if (!record) throw new Error("The encrypted vault no longer exists.");
  await decryptEntriesForRecord(record, key);
  const encrypted = await encryptVaultEntries(entries, key, undefined, record.version === 2 ? AAD_V2 : AAD_V1);
  await withStore("readwrite", (store) => store.put({ ...record, ...encrypted }));
}
