import { decodeBase64Url, encodeBase64Url } from "./otp.js";

const DB_NAME = "trust-codes-vault";
const STORE_NAME = "vault";
const RECORD_ID = "primary";
export const VAULT_ITERATIONS = 600_000;
const AAD = new TextEncoder().encode("TrustCodesVault/v1");

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
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
      transaction.onerror = () => reject(transaction.error);
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

export async function encryptVaultEntries(entries, key, iv = crypto.getRandomValues(new Uint8Array(12))) {
  const safeEntries = entries.map((entry) => {
    const { context, contextRequired, ...safe } = entry;
    return safe;
  });
  const plaintext = new TextEncoder().encode(JSON.stringify(safeEntries));
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: AAD }, key, plaintext);
  return { iv: encodeBase64Url(iv), ciphertext: encodeBase64Url(new Uint8Array(ciphertext)) };
}

export async function decryptVaultEntries(record, key) {
  try {
    const plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: decodeBase64Url(record.iv), additionalData: AAD },
      key,
      decodeBase64Url(record.ciphertext),
    );
    const entries = JSON.parse(new TextDecoder().decode(plaintext));
    if (!Array.isArray(entries)) throw new Error();
    return entries;
  } catch {
    throw new Error("The vault passphrase is incorrect or the vault data is damaged.");
  }
}

export async function createVault(passphrase, entries = []) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await deriveVaultKey(passphrase, salt);
  const encrypted = await encryptVaultEntries(entries, key);
  const record = { id: RECORD_ID, version: 1, kdf: "PBKDF2-HMAC-SHA256", iterations: VAULT_ITERATIONS, salt: encodeBase64Url(salt), ...encrypted };
  await withStore("readwrite", (store) => store.put(record));
  return key;
}

export async function unlockVault(passphrase) {
  const record = await getVaultRecord();
  if (!record || record.version !== 1 || record.kdf !== "PBKDF2-HMAC-SHA256" || record.iterations !== VAULT_ITERATIONS) throw new Error("No supported encrypted vault was found.");
  const key = await deriveVaultKey(passphrase, decodeBase64Url(record.salt), record.iterations);
  return { key, entries: await decryptVaultEntries(record, key) };
}

export async function saveVault(key, entries) {
  const record = await getVaultRecord();
  if (!record) throw new Error("The encrypted vault no longer exists.");
  const encrypted = await encryptVaultEntries(entries, key);
  await withStore("readwrite", (store) => store.put({ ...record, ...encrypted }));
}
