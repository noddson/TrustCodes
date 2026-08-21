import test from "node:test";
import assert from "node:assert/strict";

import { encodeBase64Url } from "./otp.js";
import {
  createVault,
  decryptVaultEntries,
  deriveVaultKey,
  encryptVaultEntries,
  getVaultDevice,
  getVaultRecord,
  purgeVault,
  replaceVaultRecord,
  saveVault,
  unlockVault,
  unlockVaultWithDevice,
  updateVaultCredentials,
  validateVaultBackupRecord,
  vaultPassphraseProblem,
  vaultExists,
} from "./vault.js";

const salt = new Uint8Array(16).fill(7);
const iv = new Uint8Array(12).fill(9);

test("the vault encrypts and authenticates serialized entries", async () => {
  const entries = [{ id: "one", scheme: "mutual", secret: "not-plaintext-storage", photo: "data:image/jpeg;base64,private-photo", persisted: true }];
  const key = await deriveVaultKey("a long test passphrase", salt, 1_000);
  const record = await encryptVaultEntries(entries, key, iv);
  assert.equal(record.ciphertext.includes("not-plaintext-storage"), false);
  assert.equal(record.ciphertext.includes("private-photo"), false);
  assert.deepEqual(await decryptVaultEntries(record, key), entries);
});

test("the vault refuses to serialize a plaintext context", async () => {
  const entries = [{ id: "one", context: "never-store-this", contextRequired: true, scheme: "mutual" }];
  const key = await deriveVaultKey("a long test passphrase", salt, 1_000);
  const record = await encryptVaultEntries(entries, key, iv);
  const [restored] = await decryptVaultEntries(record, key);
  assert.equal(restored.context, undefined);
  assert.equal(restored.contextRequired, undefined);
  assert.equal(restored.scheme, "mutual");
});

test("a wrong vault key cannot decrypt or forge the record", async () => {
  const key = await deriveVaultKey("correct long passphrase", salt, 1_000);
  const wrongKey = await deriveVaultKey("incorrect long phrase", salt, 1_000);
  const record = await encryptVaultEntries([{ id: "one" }], key, iv);
  await assert.rejects(decryptVaultEntries(record, wrongKey), /incorrect|damaged/i);
});

test("authenticated vault ciphertext rejects modification", async () => {
  const key = await deriveVaultKey("correct long passphrase", salt, 1_000);
  const record = await encryptVaultEntries([{ id: "one" }], key, iv);
  const last = record.ciphertext.at(-1);
  record.ciphertext = `${record.ciphertext.slice(0, -1)}${last === "A" ? "B" : "A"}`;
  await assert.rejects(decryptVaultEntries(record, key), /incorrect|damaged/i);
});

function memoryIndexedDb(initialRecord) {
  let initialized = false;
  let stored = initialRecord ? structuredClone(initialRecord) : undefined;
  const request = (action, complete) => {
    const result = {};
    queueMicrotask(() => {
      try {
        result.result = action();
        result.onsuccess?.();
        queueMicrotask(complete);
      } catch (error) {
        result.error = error;
        result.onerror?.();
      }
    });
    return result;
  };
  const database = {
    createObjectStore() {},
    transaction() {
      const transaction = { error: null };
      const complete = () => transaction.oncomplete?.();
      const objectStore = {
        get: () => request(() => stored, complete),
        put: (value) => request(() => { stored = structuredClone(value); return value.id; }, complete),
        delete: () => request(() => { stored = undefined; }, complete),
      };
      transaction.objectStore = () => objectStore;
      return transaction;
    },
    close() {},
  };
  return {
    open() {
      const result = { result: database };
      queueMicrotask(() => {
        if (!initialized) {
          initialized = true;
          result.onupgradeneeded?.();
        }
        result.onsuccess?.();
      });
      return result;
    },
  };
}

test("passphrase and WebAuthn PRF access wrap the same encrypted vault key", async () => {
  const previousIndexedDb = globalThis.indexedDB;
  globalThis.indexedDB = memoryIndexedDb();
  const deviceAccess = {
    type: "webauthn-prf",
    credentialId: "credential-one",
    prfInput: "prf-input-one",
    secret: new Uint8Array(32).fill(21),
  };
  const entries = [{ id: "saved", secret: "encrypted-entry", photo: "private-photo" }];
  try {
    const key = await createVault("Old Recovery 7!Pass", entries, deviceAccess);
    const record = await getVaultRecord();
    assert.equal(record.version, 2);
    assert.equal(JSON.stringify(record).includes("encrypted-entry"), false);
    assert.equal(JSON.stringify(record).includes("private-photo"), false);
    assert.equal(JSON.stringify(record).includes(JSON.stringify([...deviceAccess.secret])), false);
    assert.deepEqual(await getVaultDevice(), {
      type: "webauthn-prf",
      credentialId: deviceAccess.credentialId,
      prfInput: deviceAccess.prfInput,
    });

    assert.deepEqual((await unlockVault("Old Recovery 7!Pass")).entries, entries);
    assert.deepEqual((await unlockVaultWithDevice(deviceAccess)).entries, entries);
    await assert.rejects(
      unlockVaultWithDevice({ ...deviceAccess, secret: new Uint8Array(32).fill(22) }),
      /recovery passphrase/i,
    );

    const nextKey = await updateVaultCredentials(key, "New Recovery 8!Pass", entries, null);
    assert.equal(await getVaultDevice(), null);
    await assert.rejects(unlockVault("Old Recovery 7!Pass"), /incorrect|damaged/i);
    assert.deepEqual((await unlockVault("New Recovery 8!Pass")).entries, entries);

    const updatedEntries = [...entries, { id: "second", secret: "another" }];
    await saveVault(nextKey, updatedEntries);
    assert.deepEqual((await unlockVault("New Recovery 8!Pass")).entries, updatedEntries);
    assert.equal(await vaultExists(), true);
    await purgeVault();
    assert.equal(await vaultExists(), false);
  } finally {
    if (previousIndexedDb === undefined) delete globalThis.indexedDB;
    else globalThis.indexedDB = previousIndexedDb;
  }
});

test("a legacy passphrase-derived vault unlocks and migrates when credentials change", async () => {
  const legacySalt = new Uint8Array(16).fill(31);
  const legacyEntries = [{ id: "legacy", secret: "still-readable" }];
  const legacyKey = await deriveVaultKey("legacy vault password", legacySalt);
  const encrypted = await encryptVaultEntries(legacyEntries, legacyKey);
  const legacyRecord = {
    id: "primary",
    version: 1,
    kdf: "PBKDF2-HMAC-SHA256",
    iterations: 600_000,
    salt: encodeBase64Url(legacySalt),
    ...encrypted,
  };
  const previousIndexedDb = globalThis.indexedDB;
  globalThis.indexedDB = memoryIndexedDb(legacyRecord);
  try {
    const unlocked = await unlockVault("legacy vault password");
    assert.deepEqual(unlocked.entries, legacyEntries);
    const migratedKey = await updateVaultCredentials(unlocked.key, "New Migrated 6!Pass", legacyEntries);
    assert.equal((await getVaultRecord()).version, 2);
    await saveVault(migratedKey, legacyEntries);
    assert.deepEqual((await unlockVault("New Migrated 6!Pass")).entries, legacyEntries);
  } finally {
    if (previousIndexedDb === undefined) delete globalThis.indexedDB;
    else globalThis.indexedDB = previousIndexedDb;
  }
});

test("cloud restore validation accepts only supported encrypted vault fields", async () => {
  const previousIndexedDb = globalThis.indexedDB;
  globalThis.indexedDB = memoryIndexedDb();
  try {
    await createVault("Backup Validation 9!Pass", [{ id: "encrypted" }]);
    const record = await getVaultRecord();
    const validated = validateVaultBackupRecord({ ...record, ignoredCloudField: "not persisted" });
    assert.equal(validated.ignoredCloudField, undefined);
    assert.deepEqual(validated, record);

    const damaged = structuredClone(record);
    damaged.iv = "too-short";
    assert.throws(() => validateVaultBackupRecord(damaged), /invalid vault IV/i);

    await replaceVaultRecord({ ...record, ignoredCloudField: "not persisted" });
    assert.equal((await getVaultRecord()).ignoredCloudField, undefined);
    assert.deepEqual((await unlockVault("Backup Validation 9!Pass")).entries, [{ id: "encrypted" }]);
  } finally {
    if (previousIndexedDb === undefined) delete globalThis.indexedDB;
    else globalThis.indexedDB = previousIndexedDb;
  }
});

test("new vault passphrases require length and mixed character classes", async () => {
  assert.match(vaultPassphraseProblem("Short 1!"), /12/);
  assert.match(vaultPassphraseProblem(`Uppercase7!${"a".repeat(64)}`), /64/);
  assert.match(vaultPassphraseProblem("lowercase only 123!"), /uppercase/i);
  assert.match(vaultPassphraseProblem("UPPERCASE ONLY 123!"), /lowercase/i);
  assert.match(vaultPassphraseProblem("Uppercase And Symbol!"), /number/i);
  assert.match(vaultPassphraseProblem("Uppercase And Number 7"), /symbol/i);
  assert.equal(vaultPassphraseProblem("Strong Recovery 7!Pass"), "");

  const previousIndexedDb = globalThis.indexedDB;
  globalThis.indexedDB = memoryIndexedDb();
  try {
    await assert.rejects(createVault("weak recovery password"), /not strong enough/i);
    await createVault("Strong Recovery 7!Pass");
    assert.equal(await vaultExists(), true);
  } finally {
    if (previousIndexedDb === undefined) delete globalThis.indexedDB;
    else globalThis.indexedDB = previousIndexedDb;
  }
});
