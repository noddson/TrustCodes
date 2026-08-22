export const MAX_AUDIT_LOG_ENTRIES = 100;
export const PENDING_AUDIT_STORAGE_KEY = "circle-signal-pending-audit-log";
export const UNLOCK_FAILURE_STORAGE_KEY = "circle-signal-vault-unlock-failures";
export const UNLOCK_FAILURE_AUDIT_THRESHOLD = 5;

export const AUDIT_ACTIONS = Object.freeze({
  AUTOMATIC_LOCK_DISABLED: "automatic_lock_disabled",
  DEVICE_UNLOCK_ENABLED: "device_unlock_enabled",
  DEVICE_UNLOCK_REMOVED: "device_unlock_removed",
  GOOD_RECOVERY_PASSWORD_ACCEPTED: "good_recovery_password_accepted",
  GOOGLE_DRIVE_BACKUP_COMPLETED: "google_drive_backup_completed",
  GOOGLE_DRIVE_RESTORE_COMPLETED: "google_drive_restore_completed",
  LOW_STRENGTH_CODE_CREATED: "low_strength_circle_signal_created",
  RECOVERY_CODE_DOWNLOADED: "recovery_code_downloaded",
  REPEATED_VAULT_UNLOCK_FAILURES: "repeated_vault_unlock_failures",
  VAULT_RECOVERY_CHANGED: "vault_recovery_changed",
  WEAK_RECOVERY_PASSWORD_ACCEPTED: "weak_recovery_password_accepted",
});

const ALLOWED_ACTIONS = new Set(Object.values(AUDIT_ACTIONS));

export const AUDIT_ACTION_LABELS = Object.freeze({
  [AUDIT_ACTIONS.AUTOMATIC_LOCK_DISABLED]: "Automatic locking disabled",
  [AUDIT_ACTIONS.DEVICE_UNLOCK_ENABLED]: "Device unlock enabled",
  [AUDIT_ACTIONS.DEVICE_UNLOCK_REMOVED]: "Device unlock removed",
  [AUDIT_ACTIONS.GOOD_RECOVERY_PASSWORD_ACCEPTED]: "Good recovery password accepted",
  [AUDIT_ACTIONS.GOOGLE_DRIVE_BACKUP_COMPLETED]: "Google Drive backup completed",
  [AUDIT_ACTIONS.GOOGLE_DRIVE_RESTORE_COMPLETED]: "Google Drive restore completed",
  [AUDIT_ACTIONS.LOW_STRENGTH_CODE_CREATED]: "Below-Good CircleSignal created",
  [AUDIT_ACTIONS.RECOVERY_CODE_DOWNLOADED]: "Recovery code downloaded",
  [AUDIT_ACTIONS.REPEATED_VAULT_UNLOCK_FAILURES]: "Five consecutive vault unlock failures reached",
  [AUDIT_ACTIONS.VAULT_RECOVERY_CHANGED]: "Vault recovery changed",
  [AUDIT_ACTIONS.WEAK_RECOVERY_PASSWORD_ACCEPTED]: "Weak recovery password accepted",
});

export function auditLogViewingEnabled(search = globalThis.location?.search || "") {
  return new URLSearchParams(search).get("viewauditlog") === "true";
}

export function validateAuditLog(value) {
  if (!Array.isArray(value) || value.length > MAX_AUDIT_LOG_ENTRIES) throw new Error("The encrypted audit log is invalid.");
  return value.map((entry) => {
    if (!entry || typeof entry !== "object" || Array.isArray(entry) || Object.keys(entry).some((key) => !["date", "action"].includes(key))) {
      throw new Error("The encrypted audit log is invalid.");
    }
    const date = String(entry.date || "");
    const action = String(entry.action || "");
    if (!ALLOWED_ACTIONS.has(action) || !date || Number.isNaN(Date.parse(date)) || new Date(date).toISOString() !== date) {
      throw new Error("The encrypted audit log is invalid.");
    }
    return { date, action };
  });
}

export function appendAuditLog(auditLog, action, now = new Date()) {
  if (!ALLOWED_ACTIONS.has(action)) throw new Error("The audit action is unsupported.");
  const existing = validateAuditLog(auditLog || []);
  const next = [...existing, { date: now.toISOString(), action }];
  return next.slice(-MAX_AUDIT_LOG_ENTRIES);
}

export function mergeAuditLogs(...logs) {
  const seen = new Set();
  return logs.flatMap((log) => validateAuditLog(log || [])).filter((entry) => {
    const key = `${entry.date}\0${entry.action}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  }).slice(-MAX_AUDIT_LOG_ENTRIES);
}

export function readPendingAuditLog(storage = globalThis.localStorage) {
  try {
    const value = storage?.getItem(PENDING_AUDIT_STORAGE_KEY);
    return value ? validateAuditLog(JSON.parse(value)) : [];
  } catch { return []; }
}

export function writePendingAuditLog(auditLog, storage = globalThis.localStorage) {
  const validated = validateAuditLog(auditLog);
  try {
    storage?.setItem(PENDING_AUDIT_STORAGE_KEY, JSON.stringify(validated));
  }
  catch { /* The event remains unavailable until an unlocked vault can store it. */ }
  return validated;
}

export function clearPendingAuditLog(storage = globalThis.localStorage) {
  try {
    storage?.removeItem(PENDING_AUDIT_STORAGE_KEY);
  }
  catch { /* A stale validated pending entry may be retried on a later unlock. */ }
}

export function noteVaultUnlockFailure(storage = globalThis.localStorage) {
  let failures = 0;
  try {
    const stored = Number(storage?.getItem(UNLOCK_FAILURE_STORAGE_KEY));
    if (Number.isSafeInteger(stored) && stored > 0) failures = Math.min(stored, UNLOCK_FAILURE_AUDIT_THRESHOLD + 1);
    failures = Math.min(failures + 1, UNLOCK_FAILURE_AUDIT_THRESHOLD + 1);
    storage?.setItem(UNLOCK_FAILURE_STORAGE_KEY, String(failures));
  } catch { /* The failure count is an optional local signal. */ }
  return failures === UNLOCK_FAILURE_AUDIT_THRESHOLD;
}

export function clearVaultUnlockFailures(storage = globalThis.localStorage) {
  try {
    storage?.removeItem(UNLOCK_FAILURE_STORAGE_KEY);
  }
  catch { /* A stale count may remain if browser storage is unavailable. */ }
}
