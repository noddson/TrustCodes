import test from "node:test";
import assert from "node:assert/strict";

import { decryptVaultEntries, deriveVaultKey, encryptVaultEntries } from "./vault.js";

const salt = new Uint8Array(16).fill(7);
const iv = new Uint8Array(12).fill(9);

test("the vault encrypts and authenticates serialized entries", async () => {
  const entries = [{ id: "one", scheme: "mutual", secret: "not-plaintext-storage", persisted: true }];
  const key = await deriveVaultKey("a long test passphrase", salt, 1_000);
  const record = await encryptVaultEntries(entries, key, iv);
  assert.equal(record.ciphertext.includes("not-plaintext-storage"), false);
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
