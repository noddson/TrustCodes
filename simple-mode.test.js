import test from "node:test";
import assert from "node:assert/strict";

import { initialsForName, readSimpleModePreference, SIMPLE_MODE_STORAGE_KEY, writeSimpleModePreference } from "./simple-mode.js";

function memoryStorage(initial = {}) {
  const values = new Map(Object.entries(initial));
  return {
    getItem(key) { return values.get(key) ?? null; },
    setItem(key, value) { values.set(key, value); },
  };
}

test("simple mode preference is browser-local and round trips", () => {
  const storage = memoryStorage();
  assert.equal(readSimpleModePreference(storage), false);
  writeSimpleModePreference(true, storage);
  assert.equal(storage.getItem(SIMPLE_MODE_STORAGE_KEY), "true");
  assert.equal(readSimpleModePreference(storage), true);
  writeSimpleModePreference(false, storage);
  assert.equal(readSimpleModePreference(storage), false);
});

test("simple mode tolerates unavailable browser storage", () => {
  const storage = {
    getItem() { throw new Error("denied"); },
    setItem() { throw new Error("denied"); },
  };
  assert.equal(readSimpleModePreference(storage), false);
  assert.doesNotThrow(() => writeSimpleModePreference(true, storage));
});

test("contact initials remain short and recognizable", () => {
  assert.equal(initialsForName("Maya"), "M");
  assert.equal(initialsForName("Nora Singh"), "NS");
  assert.equal(initialsForName(""), "?");
});
