import test from "node:test";
import assert from "node:assert/strict";
import { appendAuditLog, AUDIT_ACTION_LABELS, AUDIT_ACTIONS, auditLogViewingEnabled, clearVaultUnlockFailures, MAX_AUDIT_LOG_ENTRIES, mergeAuditLogs, noteVaultUnlockFailure, readPendingAuditLog, UNLOCK_FAILURE_STORAGE_KEY, validateAuditLog, writePendingAuditLog } from "./audit-log.js";

function memoryStorage() {
  const values = new Map();
  return { getItem: (key) => values.get(key) ?? null, setItem: (key, value) => values.set(key, value), removeItem: (key) => values.delete(key) };
}

test("audit entries contain only an ISO date and allowlisted action", () => {
  const date = new Date("2026-08-21T15:04:05.000Z");
  const auditLog = appendAuditLog([], AUDIT_ACTIONS.AUTOMATIC_LOCK_DISABLED, date);
  assert.deepEqual(auditLog, [{ date: date.toISOString(), action: "automatic_lock_disabled" }]);
  assert.throws(() => validateAuditLog([{ ...auditLog[0], detail: "must not persist" }]), /invalid/i);
  assert.throws(() => appendAuditLog([], "arbitrary_action", date), /unsupported/i);
});

test("audit history is capped to its newest entries", () => {
  let auditLog = [];
  for (let index = 0; index < MAX_AUDIT_LOG_ENTRIES + 5; index += 1) {
    auditLog = appendAuditLog(auditLog, AUDIT_ACTIONS.LOW_STRENGTH_CODE_CREATED, new Date(index * 1000));
  }
  assert.equal(auditLog.length, MAX_AUDIT_LOG_ENTRIES);
  assert.equal(auditLog[0].date, new Date(5_000).toISOString());
  assert.equal(mergeAuditLogs(auditLog.slice(0, 60), auditLog.slice(60)).length, MAX_AUDIT_LOG_ENTRIES);
  assert.equal(mergeAuditLogs(auditLog, [auditLog.at(-1)]).length, MAX_AUDIT_LOG_ENTRIES);
});

test("a locked-vault choice can wait locally for encrypted merge on unlock", () => {
  const storage = memoryStorage();
  const pending = appendAuditLog([], AUDIT_ACTIONS.AUTOMATIC_LOCK_DISABLED, new Date("2026-08-21T15:04:05.000Z"));
  writePendingAuditLog(pending, storage);
  assert.deepEqual(readPendingAuditLog(storage), pending);
});

test("all security lifecycle actions are allowlisted", () => {
  const actions = Object.values(AUDIT_ACTIONS);
  assert.deepEqual(actions, [
    "automatic_lock_disabled",
    "device_unlock_enabled",
    "device_unlock_removed",
    "good_recovery_password_accepted",
    "google_drive_backup_completed",
    "google_drive_restore_completed",
    "low_strength_circle_signal_created",
    "recovery_code_downloaded",
    "repeated_vault_unlock_failures",
    "vault_recovery_changed",
    "weak_recovery_password_accepted",
  ]);
  for (const action of actions) assert.doesNotThrow(() => appendAuditLog([], action));
  assert.deepEqual(Object.keys(AUDIT_ACTION_LABELS).sort(), [...actions].sort());
});

test("only the fifth consecutive vault unlock failure reaches the audit threshold", () => {
  const storage = memoryStorage();
  for (let attempt = 1; attempt < 5; attempt += 1) assert.equal(noteVaultUnlockFailure(storage), false);
  assert.equal(noteVaultUnlockFailure(storage), true);
  assert.equal(noteVaultUnlockFailure(storage), false);
  clearVaultUnlockFailures(storage);
  assert.equal(storage.getItem(UNLOCK_FAILURE_STORAGE_KEY), null);
  assert.equal(noteVaultUnlockFailure(storage), false);
});

test("audit viewing requires the exact opt-in URL parameter", () => {
  assert.equal(auditLogViewingEnabled("?viewauditlog=true"), true);
  assert.equal(auditLogViewingEnabled("?mode=simple&viewauditlog=true"), true);
  assert.equal(auditLogViewingEnabled("?viewauditlog=false"), false);
  assert.equal(auditLogViewingEnabled("?viewauditlog=True"), false);
  assert.equal(auditLogViewingEnabled("?viewAuditLog=true"), false);
  assert.equal(auditLogViewingEnabled(""), false);
});
