import test from "node:test";
import assert from "node:assert/strict";

import {
  createVaultBackupEnvelope,
  DRIVE_APPDATA_SCOPE,
  DRIVE_BACKUP_FORMAT,
  GoogleDriveVaultBackup,
  googleDriveConfigured,
  parseVaultBackupEnvelope,
} from "./google-drive.js";

const CLIENT_ID = "123456-example.apps.googleusercontent.com";

function connectedDrive(fetchImpl) {
  const drive = new GoogleDriveVaultBackup({ clientId: CLIENT_ID, fetchImpl });
  drive.accessToken = "access-token";
  drive.expiresAt = Date.now() + 60_000;
  return drive;
}

test("Google Drive configuration accepts only OAuth web client IDs", () => {
  assert.equal(googleDriveConfigured(CLIENT_ID), true);
  assert.equal(googleDriveConfigured(""), false);
  assert.equal(googleDriveConfigured("client-secret"), false);
  assert.equal(DRIVE_APPDATA_SCOPE, "https://www.googleapis.com/auth/drive.appdata");
});

test("backup envelopes are timestamped and require vault validation", () => {
  const vault = { id: "primary", ciphertext: "encrypted" };
  const envelope = createVaultBackupEnvelope(vault, new Date("2026-08-20T12:00:00Z"));
  assert.equal(envelope.format, DRIVE_BACKUP_FORMAT);
  assert.equal(envelope.lastBackedUpAt, "2026-08-20T12:00:00.000Z");
  let validated = false;
  const parsed = parseVaultBackupEnvelope(envelope, (candidate) => { validated = true; return { ...candidate, checked: true }; });
  assert.equal(validated, true);
  assert.equal(parsed.vault.checked, true);
  assert.throws(() => parseVaultBackupEnvelope({ ...envelope, version: 2 }, () => vault), /not a supported/i);
});

test("restore accepts the earlier createdAt timestamp field", () => {
  const legacyEnvelope = {
    format: DRIVE_BACKUP_FORMAT,
    version: 1,
    createdAt: "2026-08-19T12:00:00Z",
    sourceOrigin: "https://noddson.github.io",
    vault: { id: "primary" },
  };
  const parsed = parseVaultBackupEnvelope(legacyEnvelope, (vault) => vault);
  assert.equal(parsed.lastBackedUpAt, "2026-08-19T12:00:00.000Z");
});

test("a first backup creates one hidden appData file containing the encrypted envelope", async () => {
  const requests = [];
  const drive = connectedDrive(async (url, options = {}) => {
    requests.push({ url: String(url), options });
    if (requests.length === 1) return new Response(JSON.stringify({ files: [] }), { status: 200 });
    return new Response(JSON.stringify({ id: "created", modifiedTime: "2026-08-20T12:01:00Z" }), { status: 200 });
  });
  const result = await drive.backup(createVaultBackupEnvelope({ id: "primary", ciphertext: "ciphertext" }));
  assert.equal(result.id, "created");
  assert.match(requests[0].url, /spaces=appDataFolder/);
  assert.equal(requests[0].options.headers.Authorization, "Bearer access-token");
  assert.match(requests[1].url, /uploadType=multipart/);
  assert.equal(requests[1].options.method, "POST");
  assert.match(requests[1].options.body, /"parents":\["appDataFolder"\]/);
  assert.match(requests[1].options.body, /"format":"trustcodes-encrypted-vault-backup"/);
});

test("an existing single backup is updated, while duplicates stop writes", async () => {
  let uploadCalled = false;
  const drive = connectedDrive(async (url, options = {}) => {
    if (String(url).includes("upload")) {
      uploadCalled = true;
      assert.match(String(url), /files\/existing/);
      assert.equal(options.method, "PATCH");
      return new Response(JSON.stringify({ id: "existing" }), { status: 200 });
    }
    return new Response(JSON.stringify({ files: [{ id: "existing" }] }), { status: 200 });
  });
  await drive.backup(createVaultBackupEnvelope({ id: "primary" }));
  assert.equal(uploadCalled, true);

  const duplicates = connectedDrive(async () => new Response(JSON.stringify({ files: [{ id: "one" }, { id: "two" }] }), { status: 200 }));
  await assert.rejects(duplicates.backup(createVaultBackupEnvelope({ id: "primary" })), /multiple/i);
});

test("restore downloads the only backup and validates it before returning", async () => {
  const envelope = createVaultBackupEnvelope({ id: "primary", ciphertext: "opaque" }, new Date("2026-08-20T12:00:00Z"));
  let request = 0;
  const drive = connectedDrive(async () => {
    request += 1;
    return request === 1
      ? new Response(JSON.stringify({ files: [{ id: "backup", modifiedTime: "2026-08-20T12:00:00Z" }] }), { status: 200 })
      : new Response(JSON.stringify(envelope), { status: 200 });
  });
  const restored = await drive.restore((vault) => ({ ...vault, validated: true }));
  assert.equal(restored.file.id, "backup");
  assert.equal(restored.envelope.vault.validated, true);
});

test("authorization is kept only in memory and can be revoked", async () => {
  let requested;
  let revoked;
  const googleApi = { accounts: { oauth2: {
    initTokenClient(options) {
      return { requestAccessToken(requestOptions) {
        requested = { options, requestOptions };
        options.callback({ access_token: "fresh-token", expires_in: 3600 });
      } };
    },
    revoke(token, callback) { revoked = token; callback(); },
  } } };
  const drive = new GoogleDriveVaultBackup({ clientId: CLIENT_ID, loadIdentity: async () => googleApi });
  await drive.connect();
  assert.equal(requested.options.scope, DRIVE_APPDATA_SCOPE);
  assert.equal(requested.requestOptions.prompt, "consent");
  assert.equal(drive.connected, true);
  drive.disconnect();
  assert.equal(revoked, "fresh-token");
  assert.equal(drive.connected, false);
});

test("the default browser fetch keeps its required global receiver", async () => {
  const previousFetch = globalThis.fetch;
  let called = false;
  globalThis.fetch = function fetchWithRequiredReceiver() {
    assert.equal(this, globalThis);
    called = true;
    return Promise.resolve(new Response("{}", { status: 200 }));
  };
  try {
    const drive = connectedDrive(undefined);
    await drive.authorizedFetch("https://www.googleapis.com/drive/v3/files");
    assert.equal(called, true);
  } finally {
    globalThis.fetch = previousFetch;
  }
});
