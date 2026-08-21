export const LOCK_TIMEOUT_STORAGE_KEY = "trust-codes-lock-timeout-minutes";
export const DEFAULT_LOCK_TIMEOUT_MINUTES = 10;
export const LOCK_TIMEOUT_OPTIONS = [3, 5, 10, 15, 20, 30, 45, 60, 0];

export function normalizeLockTimeout(value) {
  if (value === null || value === undefined || value === "") return DEFAULT_LOCK_TIMEOUT_MINUTES;
  const minutes = Number(value);
  return LOCK_TIMEOUT_OPTIONS.includes(minutes) ? minutes : DEFAULT_LOCK_TIMEOUT_MINUTES;
}

export function readLockTimeout(storage = globalThis.localStorage) {
  try { return normalizeLockTimeout(storage?.getItem(LOCK_TIMEOUT_STORAGE_KEY)); }
  catch { return DEFAULT_LOCK_TIMEOUT_MINUTES; }
}

export function writeLockTimeout(minutes, storage = globalThis.localStorage) {
  const normalized = normalizeLockTimeout(minutes);
  try { storage?.setItem(LOCK_TIMEOUT_STORAGE_KEY, String(normalized)); }
  catch { /* The setting remains active for this page even if storage is unavailable. */ }
  return normalized;
}
