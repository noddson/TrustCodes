export const DRIVE_APPDATA_SCOPE = "https://www.googleapis.com/auth/drive.appdata";
export const DRIVE_BACKUP_FILE_NAME = "trustcodes-encrypted-vault-backup.json";
export const DRIVE_BACKUP_MIME_TYPE = "application/vnd.trustcodes.encrypted-vault-backup+json";
export const DRIVE_BACKUP_FORMAT = "trustcodes-encrypted-vault-backup";
const DRIVE_FILES_URL = "https://www.googleapis.com/drive/v3/files";
const DRIVE_UPLOAD_URL = "https://www.googleapis.com/upload/drive/v3/files";
const MAX_BACKUP_BYTES = 18 * 1024 * 1024;

export function googleDriveConfigured(clientId) {
  return typeof clientId === "string" && /^[0-9]+-[A-Za-z0-9_-]+\.apps\.googleusercontent\.com$/.test(clientId.trim());
}

export function createVaultBackupEnvelope(vault, now = new Date()) {
  return {
    format: DRIVE_BACKUP_FORMAT,
    version: 1,
    createdAt: now.toISOString(),
    sourceOrigin: globalThis.location?.origin || "unknown",
    vault,
  };
}

export function parseVaultBackupEnvelope(value, validateVault) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || value.format !== DRIVE_BACKUP_FORMAT || value.version !== 1
    || typeof value.createdAt !== "string" || !Number.isFinite(Date.parse(value.createdAt))
    || typeof value.sourceOrigin !== "string" || value.sourceOrigin.length > 2048) {
    throw new Error("The Google Drive file is not a supported TrustCodes backup.");
  }
  return {
    format: DRIVE_BACKUP_FORMAT,
    version: 1,
    createdAt: new Date(value.createdAt).toISOString(),
    sourceOrigin: value.sourceOrigin,
    vault: validateVault(value.vault),
  };
}

export function loadGoogleIdentityServices(documentRef = globalThis.document) {
  if (globalThis.google?.accounts?.oauth2) return Promise.resolve(globalThis.google);
  if (!documentRef) return Promise.reject(new Error("Google sign-in is unavailable in this browser."));
  return new Promise((resolve, reject) => {
    const existing = documentRef.querySelector('script[data-trustcodes-google-identity]');
    const script = existing || documentRef.createElement("script");
    const ready = () => globalThis.google?.accounts?.oauth2
      ? resolve(globalThis.google)
      : reject(new Error("Google sign-in did not load correctly."));
    script.addEventListener("load", ready, { once: true });
    script.addEventListener("error", () => reject(new Error("Google sign-in could not be loaded. Check the connection and try again.")), { once: true });
    if (!existing) {
      script.src = "https://accounts.google.com/gsi/client";
      script.async = true;
      script.defer = true;
      script.dataset.trustcodesGoogleIdentity = "true";
      documentRef.head.append(script);
    }
  });
}

async function responseError(response) {
  try {
    const body = await response.json();
    return body?.error?.message || body?.error_description || `Google Drive returned ${response.status}.`;
  } catch { return `Google Drive returned ${response.status}.`; }
}

export class GoogleDriveVaultBackup {
  constructor({ clientId, fetchImpl = globalThis.fetch, loadIdentity = loadGoogleIdentityServices } = {}) {
    this.clientId = clientId?.trim() || "";
    this.fetchImpl = fetchImpl;
    this.loadIdentity = loadIdentity;
    this.accessToken = null;
    this.expiresAt = 0;
    this.googleApi = null;
  }

  get configured() { return googleDriveConfigured(this.clientId); }
  get connected() { return Boolean(this.accessToken && Date.now() < this.expiresAt); }

  async connect() {
    if (!this.configured) throw new Error("Google Drive backup is not configured for this deployment.");
    const googleApi = await this.loadIdentity();
    this.googleApi = googleApi;
    const response = await new Promise((resolve, reject) => {
      const client = googleApi.accounts.oauth2.initTokenClient({
        client_id: this.clientId,
        scope: DRIVE_APPDATA_SCOPE,
        callback: (tokenResponse) => tokenResponse?.error
          ? reject(new Error(tokenResponse.error_description || "Google authorization was not completed."))
          : resolve(tokenResponse),
        error_callback: () => reject(new Error("Google authorization was cancelled or could not be completed.")),
      });
      client.requestAccessToken({ prompt: "consent" });
    });
    this.accessToken = response.access_token;
    this.expiresAt = Date.now() + Math.max(0, Number(response.expires_in || 3600) - 60) * 1000;
    return true;
  }

  disconnect() {
    const token = this.accessToken;
    this.accessToken = null;
    this.expiresAt = 0;
    if (token && this.googleApi?.accounts?.oauth2?.revoke) this.googleApi.accounts.oauth2.revoke(token, () => {});
  }

  async authorizedFetch(url, options = {}) {
    if (!this.connected) throw new Error("Connect Google Drive first.");
    const response = await this.fetchImpl(url, {
      ...options,
      headers: { Authorization: `Bearer ${this.accessToken}`, ...options.headers },
    });
    if (response.status === 401) {
      this.accessToken = null;
      this.expiresAt = 0;
      throw new Error("The Google Drive connection expired. Connect again and retry.");
    }
    if (!response.ok) throw new Error(await responseError(response));
    return response;
  }

  async listBackups() {
    const params = new URLSearchParams({
      spaces: "appDataFolder",
      q: `name = '${DRIVE_BACKUP_FILE_NAME}'`,
      fields: "files(id,name,modifiedTime,version,size)",
      pageSize: "10",
    });
    const response = await this.authorizedFetch(`${DRIVE_FILES_URL}?${params}`);
    const body = await response.json();
    return Array.isArray(body.files) ? body.files : [];
  }

  async backup(envelope) {
    const contents = JSON.stringify(envelope);
    if (new TextEncoder().encode(contents).byteLength > MAX_BACKUP_BYTES) throw new Error("The encrypted vault is too large for this backup format.");
    const files = await this.listBackups();
    if (files.length > 1) throw new Error("Multiple TrustCodes backups were found. No file was overwritten; remove duplicates in Google Drive before retrying.");
    if (files.length === 1) {
      const response = await this.authorizedFetch(`${DRIVE_UPLOAD_URL}/${encodeURIComponent(files[0].id)}?uploadType=media&fields=id,name,modifiedTime,version,size`, {
        method: "PATCH",
        headers: { "Content-Type": DRIVE_BACKUP_MIME_TYPE },
        body: contents,
      });
      return response.json();
    }
    const boundary = `trustcodes_${crypto.randomUUID?.() || Date.now()}`;
    const metadata = JSON.stringify({ name: DRIVE_BACKUP_FILE_NAME, parents: ["appDataFolder"], mimeType: DRIVE_BACKUP_MIME_TYPE });
    const body = `--${boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n${metadata}\r\n--${boundary}\r\nContent-Type: ${DRIVE_BACKUP_MIME_TYPE}\r\n\r\n${contents}\r\n--${boundary}--`;
    const response = await this.authorizedFetch(`${DRIVE_UPLOAD_URL}?uploadType=multipart&fields=id,name,modifiedTime,version,size`, {
      method: "POST",
      headers: { "Content-Type": `multipart/related; boundary=${boundary}` },
      body,
    });
    return response.json();
  }

  async restore(validateVault) {
    const files = await this.listBackups();
    if (!files.length) throw new Error("No TrustCodes backup was found in this Google Drive account.");
    if (files.length > 1) throw new Error("Multiple TrustCodes backups were found. Restore stopped to avoid choosing the wrong file.");
    const response = await this.authorizedFetch(`${DRIVE_FILES_URL}/${encodeURIComponent(files[0].id)}?alt=media`);
    const text = await response.text();
    if (new TextEncoder().encode(text).byteLength > MAX_BACKUP_BYTES) throw new Error("The Google Drive backup is too large to restore safely.");
    let value;
    try { value = JSON.parse(text); }
    catch { throw new Error("The Google Drive backup is not valid JSON."); }
    return { envelope: parseVaultBackupEnvelope(value, validateVault), file: files[0] };
  }
}
