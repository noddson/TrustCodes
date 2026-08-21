import test from "node:test";
import assert from "node:assert/strict";
import { DEFAULT_LOCK_TIMEOUT_MINUTES, LOCK_TIMEOUT_OPTIONS, readLockTimeout, writeLockTimeout } from "./lock-settings.js";

function memoryStorage(initial = null) {
  let value = initial;
  return { getItem: () => value, setItem: (_key, next) => { value = next; } };
}

test("automatic secure lock defaults on and validates stored settings", () => {
  assert.equal(readLockTimeout(memoryStorage(null)), DEFAULT_LOCK_TIMEOUT_MINUTES);
  assert.equal(readLockTimeout(memoryStorage("garbage")), DEFAULT_LOCK_TIMEOUT_MINUTES);
  assert.equal(readLockTimeout(memoryStorage("10")), 10);
});

test("supported timeout choices, including Never, persist locally", () => {
  assert.deepEqual(LOCK_TIMEOUT_OPTIONS, [3, 5, 10, 15, 20, 30, 45, 60, 0]);
  const storage = memoryStorage();
  assert.equal(writeLockTimeout(30, storage), 30);
  assert.equal(readLockTimeout(storage), 30);
  assert.equal(writeLockTimeout(0, storage), 0);
  assert.equal(readLockTimeout(storage), 0);
});
