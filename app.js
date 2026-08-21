import {
  clearProofCache,
  consumeProof,
  createChannelPair,
  decodeSetupCode,
  encodeSetupCode,
  generateMutualCode,
  generateProofPhrase,
  normalizeCode,
  permutationCount,
  verifyProofPhrase,
} from "./otp.js";
import { drawQrCode } from "./qr.js";
import { cameraErrorMessage, normalizeScannedSetupCode, QrCameraScanner } from "./qr-scanner.js";
import { createDeviceUnlock, deviceUnlockSupported, getDeviceUnlock } from "./passkey.js";
import { createVault, getVaultDevice, getVaultRecord, purgeVault, replaceVaultRecord, saveVault, unlockVault, unlockVaultWithDevice, updateVaultCredentials, validateVaultBackupRecord, vaultExists, vaultPassphraseProblem } from "./vault.js";
import { GOOGLE_DRIVE_CLIENT_ID } from "./google-drive-config.js";
import { createVaultBackupEnvelope, GoogleDriveVaultBackup } from "./google-drive.js";
import { loadBuildVersion } from "./build-version.js";
import { initialsForName, photoDataUrl, readSimpleModePreference, writeSimpleModePreference } from "./simple-mode.js";

const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => [...document.querySelectorAll(selector)];
const LENGTHS = { numeric: [4, 6, 8, 10, 12, 16], base32: [4, 6, 8, 10, 12, 16], words: [4, 5, 6, 7, 8] };
const FORMAT_HELP = { numeric: "Familiar and easy to read aloud.", base32: "Crockford Base32 uses 0–9 and uppercase letters except I, L, O, and U. Typed O maps to 0; I or L maps to 1.", words: "Uses the complete 2,048-word BIP-39 dictionary." };
const ESTIMATE_RATE = 20_000_000_000;

const el = {
  setupStart: $("#setup-start"), importView: $("#import-view"), shareView: $("#share-view"),
  name: $("#channel-name"), context: $("#channel-context"), format: $("#code-format"), length: $("#code-length"),
  formatHelp: $("#format-help"), strengthRating: $("#strength-rating"), mutualSettings: $("#mutual-settings"), proofSettings: $("#proof-settings"),
  proofTotal: $("#proof-total"), proofWords: $("#proof-words"), proofStrengthDetails: $("#proof-strength-details"), showImport: $("#show-import"), importCode: $("#import-code"), setupCode: $("#setup-code"),
  shareInstruction: $("#share-instruction"), setupQrPanel: $("#setup-qr-panel"), setupQr: $("#setup-qr"), showSetupQr: $("#show-setup-qr"),
  startScanner: $("#start-scanner"), stopScanner: $("#stop-scanner"), scannerView: $("#scanner-view"), scannerVideo: $("#scanner-video"), scannerCanvas: $("#scanner-canvas"), scannerStatus: $("#scanner-status"),
  saveChannel: $("#save-channel"), saveImport: $("#save-import"), saveHelp: $("#save-help"), error: $("#setup-error"),
  empty: $("#empty-state"), workspace: $("#code-workspace"), select: $("#channel-select"), schemeBadge: $("#scheme-badge"), methodBadge: $("#method-badge"), useContext: $("#use-context"), contextStatus: $("#context-status"),
  generateCard: $("#generate-card"), generateLabel: $("#generate-label"), generateHeading: $("#generate-heading"), generatePrompt: $("#generate-prompt"), remainingText: $("#remaining-text"),
  generated: $("#generated-code"), timer: $("#totp-timer"), timerFill: $("#timer-fill"), timerText: $("#timer-text"), next: $("#next-code"), consume: $("#consume-proof"),
  verifyCard: $("#verify-card"), verifyInput: $("#verify-code"), verifyButton: $("#verify-button"), verifyPrompt: $("#verify-prompt"), verifyRemaining: $("#verify-remaining"), result: $("#verify-result"), toast: $("#toast"),
  vaultDot: $("#vault-dot"), vaultStatus: $("#vault-status"), vaultDetail: $("#vault-detail"), vaultAction: $("#vault-action"), vaultSettings: $("#vault-settings"), vaultLock: $("#vault-lock"),
  vaultDialog: $("#vault-dialog"), vaultForm: $("#vault-form"), vaultDialogTitle: $("#vault-dialog-title"), vaultDialogCopy: $("#vault-dialog-copy"),
  vaultPassphrase: $("#vault-passphrase"), vaultConfirmField: $("#vault-confirm-field"), vaultConfirm: $("#vault-confirm"), vaultSubmit: $("#vault-submit"), vaultError: $("#vault-error"),
  vaultDeviceOption: $("#vault-device-option"), vaultDeviceUnlock: $("#vault-device-unlock"), vaultDeviceSubmit: $("#vault-device-submit"), vaultUnlockDivider: $("#vault-unlock-divider"),
  contextConfirmDialog: $("#context-confirm-dialog"), contextConfirmForm: $("#context-confirm-form"), contextConfirm: $("#context-confirm"),
  contextConfirmSubmit: $("#context-confirm-submit"), contextConfirmError: $("#context-confirm-error"),
  simpleMode: $("#simple-mode"), simpleEnter: $("#simple-mode-enter"), simpleExit: $("#simple-mode-exit"),
  simplePhotoButton: $("#simple-photo-button"), simplePhoto: $("#simple-photo"), simplePhotoInitials: $("#simple-photo-initials"),
  simpleName: $("#simple-person-name"), simplePrompt: $("#simple-prompt"), simplePeopleList: $("#simple-people-list"),
  simpleGenerateCard: $("#simple-generate-card"), simpleGenerated: $("#simple-generated-code"), simpleTimer: $("#simple-totp-timer"),
  simpleTimerProgress: $("#simple-timer-progress"), simpleTimerText: $("#simple-timer-text"), simpleRemaining: $("#simple-remaining"),
  simpleNext: $("#simple-next-code"), simpleConsume: $("#simple-consume-proof"), simpleVerifyCard: $("#simple-verify-card"),
  simpleVerifyInput: $("#simple-verify-code"), simpleVerifyButton: $("#simple-verify-button"), simpleVerifyResult: $("#simple-verify-result"), simpleVerifyRemaining: $("#simple-verify-remaining"),
  simplePhotoInput: $("#simple-photo-input"),
  vaultOptionsDialog: $("#vault-options-dialog"), vaultOptionsCopy: $("#vault-options-copy"), settingsChangePassword: $("#settings-change-password"),
  localVaultSettings: $("#local-vault-settings"), localVaultDangerSettings: $("#local-vault-danger-settings"),
  driveStatus: $("#drive-backup-status"), driveConnect: $("#drive-connect"), driveBackup: $("#drive-backup"),
  driveRestoreOpen: $("#drive-restore-open"), driveDisconnect: $("#drive-disconnect"),
  driveRestoreDialog: $("#drive-restore-dialog"), driveRestoreForm: $("#drive-restore-form"), driveRestoreCopy: $("#drive-restore-copy"),
  driveRestoreConfirmation: $("#drive-restore-confirmation"), driveRestoreSubmit: $("#drive-restore-submit"), driveRestoreError: $("#drive-restore-error"),
  changePasswordDialog: $("#change-password-dialog"), changePasswordForm: $("#change-password-form"), currentVaultPassword: $("#current-vault-password"),
  newVaultPassword: $("#new-vault-password"), confirmNewVaultPassword: $("#confirm-new-vault-password"), changePasswordSubmit: $("#change-password-submit"), changePasswordError: $("#change-password-error"),
  changeDeviceOption: $("#change-device-option"), changeDeviceUnlock: $("#change-device-unlock"), changeDeviceCopy: $("#change-device-copy"),
  purgeVaultDialog: $("#purge-vault-dialog"), purgeVaultForm: $("#purge-vault-form"), purgeVaultFirst: $("#purge-vault-first"), purgeVaultFinal: $("#purge-vault-final"),
  purgeVaultConfirmation: $("#purge-vault-confirmation"), purgeVaultSubmit: $("#purge-vault-submit"), purgeVaultError: $("#purge-vault-error"),
};

let entries = [];
let activeId = null;
let pendingLocal = null;
let pendingPeer = null;
let activeContext = "";
let vaultKey = null;
let vaultPresent = false;
let vaultAvailable = true;
let vaultDevice = null;
let openVaultOptionsAfterUnlock = false;
let deviceUnlockCapable = false;
let lastCounter = -1;
let toastTimer;
let contextTimer;
let cameraScanner = null;
let pendingCreateConfig = null;
let simpleModeRequested = readSimpleModePreference();
let simpleRenderedId = null;
const googleDriveBackup = new GoogleDriveVaultBackup({ clientId: GOOGLE_DRIVE_CLIENT_ID });
let driveStatusMessage = "";
let pendingDriveRestore = null;

function active() { return entries.find((entry) => entry.id === activeId) || entries[0] || null; }
function selected(name) { return $(`input[name="${name}"]:checked`).value; }
function showToast(message) { el.toast.textContent = message; el.toast.hidden = false; clearTimeout(toastTimer); toastTimer = setTimeout(() => { el.toast.hidden = true; }, 2400); }
function showError(message) { el.error.textContent = message; el.error.hidden = false; }
function clearError() { el.error.hidden = true; el.error.textContent = ""; }
function showVaultError(message) { el.vaultError.textContent = message; el.vaultError.hidden = false; }

function showContextConfirmError(message) {
  el.contextConfirmError.textContent = message;
  el.contextConfirmError.hidden = false;
}

function clearContextConfirm() {
  pendingCreateConfig = null;
  el.contextConfirm.value = "";
  el.contextConfirmError.textContent = "";
  el.contextConfirmError.hidden = true;
}

function restoreContextInput(context) {
  requestAnimationFrame(() => {
    el.context.value = context;
    el.context.focus();
  });
}

function withoutContext(entry) {
  const { context, contextRequired, ...stored } = entry;
  if (stored.scheme === "proof" && !stored.contextProtection && !stored.proofContextMode) stored.proofContextMode = "chain";
  return stored;
}

function clearActiveContext() {
  const entry = active();
  if (entry) clearProofCache(entry);
  activeContext = "";
  el.useContext.value = "";
  el.contextStatus.textContent = "No context applied";
  clearTimeout(contextTimer);
  lastCounter = -1;
}

function hideSetupQr() {
  el.setupQrPanel.hidden = true;
  el.setupQr.width = 0;
  el.setupQr.height = 0;
  el.showSetupQr.textContent = "Show QR";
}

function stopCameraScanner(message = "Camera off") {
  cameraScanner?.stop();
  el.scannerView.hidden = true;
  el.startScanner.disabled = false;
  el.scannerStatus.textContent = message;
}

function scannerInstance() {
  cameraScanner ||= new QrCameraScanner({
    video: el.scannerVideo,
    canvas: el.scannerCanvas,
    onStatus: (message) => { el.scannerStatus.textContent = message; },
    onDetected: async (value) => {
      const setupCode = normalizeScannedSetupCode(value);
      if (!setupCode) {
        el.scannerStatus.textContent = "A QR code was found, but it is not a TrustCodes setup code.";
        return false;
      }
      try { decodeSetupCode(setupCode); }
      catch {
        el.scannerStatus.textContent = "That TrustCodes QR code is damaged or unsupported.";
        return false;
      }
      el.importCode.value = setupCode;
      stopCameraScanner("Setup code scanned");
      showToast("Setup code scanned—review and import it");
      $("#import-channel").focus();
      return true;
    },
  });
  return cameraScanner;
}

function contextFor() { return activeContext; }

function escapeHtml(value) {
  return String(value).replace(/[&<>"]/g, (character) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[character]);
}

function switchTab(name) {
  if (name !== "setup") stopCameraScanner();
  if (name !== "use" || $('[data-panel="use"]').hidden) clearActiveContext();
  $$('[data-panel]').forEach((panel) => { panel.hidden = panel.dataset.panel !== name; });
  $$('[data-tab]').forEach((tab) => tab.classList.toggle("is-active", tab.dataset.tab === name));
  if (name === "use") renderWorkspace();
}

function resetSetupViews() {
  stopCameraScanner();
  hideSetupQr();
  el.setupCode.textContent = "";
  pendingLocal = null; pendingPeer = null;
  el.setupStart.hidden = false; el.importView.hidden = true; el.shareView.hidden = true;
  clearError();
}

function entropyBits(format, length) {
  if (format === "numeric") return Math.floor(length * Math.log2(10));
  if (format === "base32") return length * 5;
  return length * 11;
}

function assuranceLabel(bits) {
  if (bits < 17) return "Very weak";
  if (bits < 22) return "Weak";
  if (bits < 33) return "Basic";
  if (bits < 44) return "Fair";
  if (bits < 55) return "Okay";
  if (bits < 66) return "Good";
  if (bits < 77) return "Great";
  if (bits < 88) return "Excellent";
  return "Fantastic";
}

function conciseNumber(value) {
  return new Intl.NumberFormat("en-US", { maximumFractionDigits: value < 10 ? 2 : value < 100 ? 1 : 0 }).format(value);
}

function formatDuration(seconds) {
  if (seconds < 1) return "under 1 second";
  if (seconds < 60) return `${conciseNumber(seconds)} seconds`;
  if (seconds < 3600) return `${conciseNumber(seconds / 60)} minutes`;
  if (seconds < 86_400) return `${conciseNumber(seconds / 3600)} hours`;
  if (seconds < 31_557_600) return `${conciseNumber(seconds / 86_400)} days`;
  const years = seconds / 31_557_600;
  if (years >= 1_000_000_000) return `${conciseNumber(years / 1_000_000_000)} billion years`;
  if (years >= 1_000_000) return `${conciseNumber(years / 1_000_000)} million years`;
  if (years >= 1000) return `${conciseNumber(years / 1000)} thousand years`;
  return `${conciseNumber(years)} years`;
}

function strengthRatingMarkup(format, length, proof = false) {
  const bits = entropyBits(format, length);
  const permutations = permutationCount(format, length);
  const exhaustiveSeconds = Number(permutations) / ESTIMATE_RATE;
  const noun = format === "words" ? "phrases" : "codes";
  const relevance = proof
    ? "This offline model matters if the verifier anchor is exposed; it does not determine whether the request is safe. Actual attacks vary."
    : "This does not estimate recovery of the shared secret: a displayed mutual code does not provide an offline correctness test or determine whether the request is safe. Actual attacks vary.";
  const details = `${permutations.toLocaleString("en-US")} possible ${noun}. At 20 billion trials/second: ${formatDuration(exhaustiveSeconds / 2)} on average, or ${formatDuration(exhaustiveSeconds)} to exhaust every possibility. ${relevance}`;
  return `<details class="strength-disclosure"><summary><strong>${assuranceLabel(bits)}</strong><span class="rating-bits">~${bits} bits raw guess space</span></summary><p>${details} Learn more here: <a href="https://en.wikipedia.org/wiki/Phishing" target="_blank" rel="noopener noreferrer">Phishing</a>.</p></details>`;
}

function updateProofStrengthDetails() {
  el.proofStrengthDetails.innerHTML = strengthRatingMarkup("words", Number(el.proofWords.value), true);
}

function updateStrengthOptions() {
  const format = el.format.value, previous = Number(el.length.value);
  el.length.innerHTML = LENGTHS[format].map((length) => {
    return `<option value="${length}">${format === "words" ? `${length} words` : `${length} characters`}</option>`;
  }).join("");
  el.length.value = String(LENGTHS[format].includes(previous) ? previous : 6);
  el.formatHelp.textContent = FORMAT_HELP[format];
  const length = Number(el.length.value);
  el.strengthRating.innerHTML = strengthRatingMarkup(format, length, false);
}

function updateScheme() {
  const proof = selected("scheme") === "proof";
  el.mutualSettings.hidden = proof;
  el.proofSettings.hidden = !proof;
}

function updateVaultUI() {
  const unlocked = Boolean(vaultKey);
  el.vaultDot.className = !vaultAvailable ? "unavailable" : unlocked ? "unlocked" : "";
  if (!vaultAvailable) {
    el.vaultStatus.textContent = "Encrypted vault unavailable";
    el.vaultDetail.textContent = "IndexedDB is disabled in this browser context.";
    el.vaultAction.hidden = true;
  } else if (unlocked) {
    const count = entries.filter((entry) => entry.persisted).length;
    el.vaultStatus.textContent = "Encrypted vault unlocked";
    el.vaultDetail.textContent = `${count} saved ${count === 1 ? "entry" : "entries"} · key held in memory`;
    el.vaultAction.hidden = true;
  } else {
    el.vaultStatus.textContent = vaultPresent ? "Encrypted vault locked" : "No encrypted vault yet";
    el.vaultDetail.textContent = vaultPresent ? "Unlock to load saved entries." : "Create one to encrypt saved entries at rest.";
    el.vaultAction.hidden = false;
    el.vaultAction.disabled = false;
    el.vaultAction.classList.toggle("vault-unlock-icon", vaultPresent);
    el.vaultAction.setAttribute("aria-label", vaultPresent ? "Vault locked — unlock vault" : "Create vault");
    el.vaultAction.title = vaultPresent ? "Vault locked — click to unlock" : "";
    el.vaultAction.innerHTML = vaultPresent
      ? '<svg viewBox="0 0 24 24" aria-hidden="true"><rect x="5" y="10" width="14" height="10" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/></svg>'
      : "Create vault";
  }
  el.vaultSettings.hidden = !vaultAvailable;
  el.vaultLock.hidden = !unlocked;
  el.saveChannel.disabled = !unlocked;
  el.saveImport.disabled = !unlocked;
  el.saveHelp.textContent = unlocked ? "Encrypted with AES-256-GCM when saved." : "Create or unlock the vault first. Otherwise this entry lasts only until reload.";
}

async function savePersisted() {
  if (!vaultKey) return;
  try {
    await saveVault(vaultKey, entries.filter((entry) => entry.persisted).map(withoutContext));
    updateVaultUI();
  } catch (error) { showToast(error.message); }
}

function addEntry(entry) {
  entries.push(entry);
  activeId = entry.id;
  renderWorkspace();
  savePersisted();
}

function presentForSharing(local, peer) {
  stopCameraScanner();
  hideSetupQr();
  pendingLocal = local; pendingPeer = peer;
  el.context.value = "";
  el.setupStart.hidden = true; el.importView.hidden = true; el.shareView.hidden = false;
  el.setupCode.textContent = encodeSetupCode(peer);
  const contextReminder = " The context itself is not in this setup code; tell them the remembered value separately, or tell them to leave it empty if you created the channel without one.";
  if (local.scheme === "mutual") el.shareInstruction.textContent = `Their setup contains independently salted, context-wrapped shared-secret material. Transfer it through a trusted method.${contextReminder}`;
  else if (local.role === "prove") el.shareInstruction.textContent = `Their setup contains only an independently salted, context-wrapped hash-chain anchor. It cannot generate future phrases.${contextReminder}`;
  else el.shareInstruction.textContent = `Their setup contains an independently salted, context-wrapped chain seed, making their device the prover. Transfer it through a trusted method and do not retain extra copies.${contextReminder}`;
  clearError();
}

function formatForDisplay(code, format) {
  if (format === "words") return code;
  const group = format === "numeric" ? 3 : 4;
  return code.match(new RegExp(`.{1,${group}}`, "g"))?.join(" ") || code;
}

function formatLabel(entry) {
  if (entry.scheme === "proof") return `${entry.length} words · ${entry.remaining}/${entry.total} remaining`;
  if (entry.format === "words") return `${entry.length} words`;
  return `${entry.length} ${entry.format === "numeric" ? "digits" : "characters"}`;
}

function setContactPhoto(image, initials, entry) {
  const hasPhoto = Boolean(entry?.photo);
  image.hidden = !hasPhoto;
  if (hasPhoto) image.src = entry.photo;
  else image.removeAttribute("src");
  image.alt = hasPhoto ? `Photo for ${entry.name}` : "";
  initials.hidden = hasPhoto;
  initials.textContent = initialsForName(entry?.name);
}

function renderSimplePeople(entry) {
  el.simplePeopleList.replaceChildren(...entries.map((item) => {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "simple-person";
    button.setAttribute("aria-pressed", String(item.id === entry.id));
    button.setAttribute("aria-label", `${item.name}${item.id === entry.id ? ", selected" : ""}`);

    const portrait = document.createElement("span");
    portrait.className = "simple-person-photo";
    const image = document.createElement("img");
    const initials = document.createElement("span");
    initials.className = "simple-person-initials";
    initials.setAttribute("aria-hidden", "true");
    setContactPhoto(image, initials, item);
    portrait.append(image, initials);

    const copy = document.createElement("span");
    const label = document.createElement("strong");
    label.textContent = item.name;
    const status = document.createElement("small");
    status.textContent = item.id === entry.id ? "Selected" : "Tap to view";
    copy.append(label, status);
    button.append(portrait, copy);
    button.addEventListener("click", () => {
      if (item.id === activeId) return;
      clearActiveContext();
      activeId = item.id;
      renderWorkspace();
    });
    return button;
  }));
}

function renderSimpleWorkspace(entry = active()) {
  const available = Boolean(entry);
  el.simpleEnter.disabled = !available;
  el.simpleEnter.title = available ? "Show only the current trust code" : "Create or unlock a trust channel first";
  const visible = simpleModeRequested && available;
  el.simpleMode.hidden = !visible;
  document.body.classList.toggle("simple-mode-active", visible);
  if (!visible) return;

  if (simpleRenderedId !== entry.id) {
    simpleRenderedId = entry.id;
    el.simpleVerifyInput.value = "";
    el.simpleVerifyResult.hidden = true;
  }

  setContactPhoto(el.simplePhoto, el.simplePhotoInitials, entry);
  el.simplePhotoButton.setAttribute("aria-label", `${entry.photo ? "Change" : "Add"} photo for ${entry.name}`);
  el.simpleName.textContent = entry.name;
  const canGenerate = entry.scheme === "mutual" || entry.role === "prove";
  el.simpleGenerateCard.hidden = !canGenerate;
  el.simpleVerifyCard.hidden = canGenerate;
  el.simpleTimer.hidden = entry.scheme !== "mutual" || entry.method !== "totp";
  el.simpleNext.hidden = entry.scheme !== "mutual" || entry.method !== "hotp";
  el.simpleConsume.hidden = entry.scheme !== "proof" || entry.role !== "prove";
  el.simpleRemaining.hidden = entry.scheme !== "proof";

  if (entry.scheme === "mutual") {
    el.simplePrompt.textContent = "Ask them to read their trust code aloud. Make sure it matches below. Don’t tell them your code.";
  } else if (entry.role === "prove") {
    el.simplePrompt.textContent = `Read this phrase aloud to ${entry.name}`;
    el.simpleRemaining.textContent = `${entry.remaining} phrases remaining`;
    el.simpleConsume.disabled = entry.remaining < 1;
  } else {
    el.simplePrompt.textContent = `Ask ${entry.name} to read their phrase aloud`;
    el.simpleVerifyInput.placeholder = `${entry.length}-word phrase…`;
    el.simpleVerifyRemaining.textContent = `${entry.remaining} phrases remaining`;
    el.simpleVerifyButton.disabled = entry.remaining < 1;
  }
  renderSimplePeople(entry);
}

async function renderGenerated(force = false) {
  const entry = active();
  if (!entry || (entry.scheme === "proof" && entry.role !== "prove")) return;
  const context = contextFor();
  const counter = entry.scheme === "mutual" && entry.method === "totp" ? Math.floor(Date.now() / 1000 / entry.period) : entry.scheme === "mutual" ? entry.counter : entry.remaining;
  if (!force && counter === lastCounter) return;
  lastCounter = counter;
  const code = entry.scheme === "proof" ? await generateProofPhrase(entry, context) : await generateMutualCode(entry, Date.now(), undefined, context);
  if (active()?.id !== entry.id || contextFor() !== context) return;
  el.generated.textContent = formatForDisplay(code, entry.scheme === "proof" ? "words" : entry.format);
  el.generated.classList.toggle("word-code", entry.scheme === "proof" || entry.format === "words");
  el.simpleGenerated.textContent = el.generated.textContent;
  el.simpleGenerated.classList.toggle("word-code", entry.scheme === "proof" || entry.format === "words");
}

function renderWorkspace() {
  const entry = active();
  el.empty.hidden = Boolean(entry); el.workspace.hidden = !entry;
  if (!entry) { updateVaultUI(); renderSimpleWorkspace(null); return; }
  activeId = entry.id;
  el.select.innerHTML = entries.map((item) => `<option value="${item.id}"${item.id === entry.id ? " selected" : ""}>${escapeHtml(item.name)} — ${item.scheme === "mutual" ? item.method.toUpperCase() : item.role === "prove" ? "I prove" : "I verify"}</option>`).join("");
  el.schemeBadge.textContent = entry.scheme === "mutual" ? "Mutual comparison" : entry.role === "prove" ? "One-way · I prove" : "One-way · I verify";
  el.methodBadge.textContent = entry.scheme === "mutual" ? `${entry.method.toUpperCase()} · ${formatLabel(entry)}` : formatLabel(entry);
  const canGenerate = entry.scheme === "mutual" || entry.role === "prove";
  el.generateCard.hidden = !canGenerate;
  el.verifyCard.hidden = entry.scheme !== "proof" || entry.role !== "verify";
  el.timer.hidden = entry.scheme !== "mutual" || entry.method !== "totp";
  el.next.hidden = entry.scheme !== "mutual" || entry.method !== "hotp";
  el.consume.hidden = entry.scheme !== "proof" || entry.role !== "prove";
  el.remainingText.hidden = entry.scheme !== "proof";
  if (entry.scheme === "proof") {
    el.generateLabel.textContent = "One-way proof";
    el.generateHeading.textContent = "Current proof phrase";
    el.generatePrompt.textContent = `Read this ${entry.length}-word phrase once. Consume it only after the verifier reports a match.`;
    el.verifyPrompt.textContent = `Ask for their current ${entry.length}-word phrase. A successful proof is consumed immediately.`;
    el.verifyInput.placeholder = `${entry.length}-word proof phrase…`;
    el.remainingText.textContent = `${entry.remaining} of ${entry.total} proofs remaining`;
    el.verifyRemaining.textContent = `${entry.remaining} of ${entry.total} proofs remaining`;
    el.consume.disabled = entry.remaining < 1;
    el.verifyButton.disabled = entry.remaining < 1;
  } else {
    el.generateLabel.textContent = "Compare together";
    el.generateHeading.textContent = "Current mutual code";
    el.generatePrompt.textContent = entry.method === "totp" ? "Both devices should show the same value during this time window." : "Both devices should show the same value. Advance only after a successful conversation.";
  }
  el.verifyInput.value = ""; el.result.hidden = true;
  lastCounter = -1;
  if (canGenerate && (entry.scheme !== "proof" || entry.remaining > 0)) renderGenerated(true);
  else {
    el.generated.textContent = "Chain complete";
    el.simpleGenerated.textContent = "Chain complete";
  }
  renderSimpleWorkspace(entry);
  updateVaultUI();
}

async function tick() {
  const entry = active();
  if (!entry || entry.scheme !== "mutual" || entry.method !== "totp") return;
  const elapsed = (Date.now() / 1000) % entry.period;
  const remaining = Math.max(0, Math.ceil(entry.period - elapsed));
  el.timerText.textContent = `${remaining}s`;
  el.timerFill.style.width = `${(entry.period - elapsed) / entry.period * 100}%`;
  el.timerFill.style.background = remaining <= 5 ? "#cf624e" : "";
  el.simpleTimerText.textContent = `${remaining} second${remaining === 1 ? "" : "s"}`;
  el.simpleTimerProgress.style.strokeDashoffset = String(88 * (1 - (entry.period - elapsed) / entry.period));
  el.simpleTimerProgress.classList.toggle("is-ending", remaining <= 5);
  await renderGenerated();
}

async function copyText(text, message) {
  try { await navigator.clipboard.writeText(text); }
  catch {
    const area = document.createElement("textarea"); area.value = text; area.style.cssText = "position:fixed;opacity:0"; document.body.append(area); area.select(); document.execCommand("copy"); area.remove();
  }
  showToast(message);
}

function verificationResult(valid, message) {
  el.result.hidden = false;
  el.result.className = `verify-result ${valid ? "success" : "failure"}`;
  el.result.textContent = message;
}

function clearVaultCredentialInputs() {
  el.vaultPassphrase.value = "";
  el.vaultConfirm.value = "";
  el.currentVaultPassword.value = "";
  el.newVaultPassword.value = "";
  el.confirmNewVaultPassword.value = "";
}

function openVaultDialog() {
  const creating = !vaultPresent;
  el.vaultDialog.dataset.mode = creating ? "create" : "unlock";
  el.vaultDialogTitle.textContent = creating ? "Create encrypted vault" : "Unlock encrypted vault";
  el.vaultDialogCopy.textContent = creating
    ? "Choose a recovery passphrase. On compatible devices, you can also unlock with Face ID, fingerprint, or the device passcode."
    : vaultDevice
      ? "Unlock with this device, or use the recovery passphrase."
      : "Your recovery passphrase unlocks the encrypted entries saved in this browser context.";
  el.vaultConfirmField.hidden = !creating;
  el.vaultConfirm.required = creating;
  el.vaultPassphrase.minLength = creating ? 12 : 1;
  el.vaultPassphrase.maxLength = creating ? 64 : 4096;
  el.vaultPassphrase.autocomplete = creating ? "new-password" : "current-password";
  el.vaultDeviceOption.hidden = !creating || !deviceUnlockCapable;
  el.vaultDeviceUnlock.checked = false;
  el.vaultDeviceSubmit.hidden = creating || !vaultDevice || !deviceUnlockCapable;
  el.vaultUnlockDivider.hidden = el.vaultDeviceSubmit.hidden;
  el.vaultSubmit.textContent = creating ? "Create encrypted vault" : "Unlock vault";
  clearVaultCredentialInputs();
  el.vaultError.hidden = true;
  el.vaultDialog.showModal();
  (el.vaultDeviceSubmit.hidden ? el.vaultPassphrase : el.vaultDeviceSubmit).focus();
}

function openVaultOptionsDialog() {
  el.localVaultSettings.hidden = !vaultPresent;
  el.localVaultDangerSettings.hidden = !vaultPresent;
  if (vaultPresent) {
    el.vaultOptionsCopy.textContent = vaultKey
      ? "Change the recovery passphrase or configure native device unlock."
      : "Unlock the vault before changing its passphrase or device-unlock method.";
    el.settingsChangePassword.textContent = vaultKey ? "Change" : "Unlock and change";
  }
  updateDriveBackupUI();
  el.vaultOptionsDialog.showModal();
}

function updateDriveBackupUI(message = driveStatusMessage) {
  driveStatusMessage = message;
  const configured = googleDriveBackup.configured;
  const connected = googleDriveBackup.connected;
  el.driveConnect.hidden = connected;
  el.driveConnect.disabled = !configured;
  el.driveBackup.hidden = !connected;
  el.driveRestoreOpen.hidden = !connected;
  el.driveDisconnect.hidden = !connected;
  el.driveBackup.disabled = !vaultPresent;
  el.driveStatus.textContent = message || (!configured
    ? "Google Drive backup is not configured for this deployment."
    : connected
      ? "Connected. Backups are manual and contain only the encrypted vault record."
      : "Connect Google Drive to back up or restore the encrypted vault.");
}

function driveFileStatus(file) {
  if (!file?.modifiedTime) return "Connected to Google Drive.";
  const timestamp = new Date(file.modifiedTime);
  return Number.isNaN(timestamp.valueOf()) ? "Connected to Google Drive." : `Encrypted backup last updated ${timestamp.toLocaleString()}.`;
}

function setDriveBusy(button, busy, busyText, normalText) {
  button.disabled = busy;
  button.textContent = busy ? busyText : normalText;
}

function resetDriveRestoreDialog() {
  pendingDriveRestore = null;
  el.driveRestoreConfirmation.value = "";
  el.driveRestoreSubmit.disabled = true;
  el.driveRestoreSubmit.textContent = "Replace and restore";
  el.driveRestoreError.hidden = true;
  el.driveRestoreError.textContent = "";
}

function clearChangePasswordForm() {
  clearVaultCredentialInputs();
  el.changePasswordError.textContent = "";
  el.changePasswordError.hidden = true;
  const canOfferDevice = deviceUnlockCapable;
  el.changeDeviceOption.hidden = !canOfferDevice && !vaultDevice;
  el.changeDeviceUnlock.checked = Boolean(vaultDevice);
  el.changeDeviceCopy.textContent = vaultDevice
    ? canOfferDevice
      ? "Keep device unlock enabled. You will confirm with the device while the vault keys are refreshed."
      : "Device unlock is configured but unavailable in this browser. Turn it off to continue with passphrase-only access."
    : "Use a passkey with Face ID, fingerprint, or your device passcode. Your new passphrase remains the recovery method.";
}

function openChangePasswordDialog() {
  clearChangePasswordForm();
  el.changePasswordDialog.showModal();
  el.currentVaultPassword.focus();
}

function restoreUnlockedVault(unlocked) {
  vaultKey = unlocked.key;
  clearActiveContext();
  const ephemeral = entries.filter((entry) => !entry.persisted);
  const restored = unlocked.entries.map((entry) => ({ ...withoutContext(entry), persisted: true }));
  entries = [...restored, ...ephemeral];
  activeId = entries[0]?.id || null;
  return restored;
}

function resetPurgeDialog() {
  el.purgeVaultFirst.hidden = false;
  el.purgeVaultFinal.hidden = true;
  el.purgeVaultConfirmation.value = "";
  el.purgeVaultSubmit.disabled = true;
  el.purgeVaultError.hidden = true;
  el.purgeVaultError.textContent = "";
}

async function initializeVault() {
  try {
    deviceUnlockCapable = await deviceUnlockSupported();
    vaultPresent = await vaultExists();
    vaultDevice = vaultPresent ? await getVaultDevice() : null;
  }
  catch { vaultAvailable = false; }
  updateVaultUI();
}

async function renderBuildVersion() {
  const versionElement = $("#app-version");
  if (!versionElement) return;

  const version = await loadBuildVersion(window.location.href);
  if (!version) return;

  const label = document.createTextNode("Version: ");
  const link = document.createElement("a");
  link.href = version.githubCommitUrl;
  link.textContent = version.displayVersion;
  link.target = "_blank";
  link.rel = "noopener noreferrer";
  link.title = version.fullSha;
  versionElement.replaceChildren(label, link);
}

async function applySelectedPhoto(input) {
  const file = input.files?.[0];
  input.value = "";
  if (!file) return;
  const entry = active();
  if (!entry) return;
  try {
    el.simplePhotoButton.disabled = true;
    entry.photo = await photoDataUrl(file);
    await savePersisted();
    renderWorkspace();
    showToast("Photo added on this device");
  } catch (error) { showToast(error.message); }
  finally { el.simplePhotoButton.disabled = false; }
}

$$('[data-tab]').forEach((button) => button.addEventListener("click", () => switchTab(button.dataset.tab)));
$$('[data-go-setup]').forEach((button) => button.addEventListener("click", () => { resetSetupViews(); switchTab("setup"); }));
$$('input[name="scheme"]').forEach((radio) => radio.addEventListener("change", updateScheme));
el.format.addEventListener("change", updateStrengthOptions);
el.length.addEventListener("change", updateStrengthOptions);
el.proofWords.addEventListener("change", updateProofStrengthDetails);
el.simpleEnter.addEventListener("click", () => {
  if (!active()) return showToast("Create or unlock a trust channel first");
  simpleModeRequested = true;
  writeSimpleModePreference(true);
  switchTab("use");
  el.simpleExit.focus();
});
el.simpleExit.addEventListener("click", () => {
  simpleModeRequested = false;
  writeSimpleModePreference(false);
  renderSimpleWorkspace();
  requestAnimationFrame(() => el.simpleEnter.focus());
});
el.simplePhotoButton.addEventListener("click", () => {
  if (active()) el.simplePhotoInput.click();
});
el.simplePhotoInput.addEventListener("change", () => applySelectedPhoto(el.simplePhotoInput));
el.vaultSettings.addEventListener("click", openVaultOptionsDialog);
$("#vault-options-close").addEventListener("click", () => el.vaultOptionsDialog.close());
el.driveConnect.addEventListener("click", async () => {
  setDriveBusy(el.driveConnect, true, "Connecting…", "Connect");
  try {
    await googleDriveBackup.connect();
    const files = await googleDriveBackup.listBackups();
    updateDriveBackupUI(files.length === 1
      ? driveFileStatus(files[0])
      : files.length > 1
        ? "Connected, but multiple TrustCodes backups were found. Backup and restore are blocked until duplicates are removed."
        : "Connected. No encrypted TrustCodes backup exists yet.");
  } catch (error) {
    updateDriveBackupUI(error.message);
  } finally {
    setDriveBusy(el.driveConnect, false, "Connecting…", "Connect");
    updateDriveBackupUI();
  }
});
el.driveDisconnect.addEventListener("click", () => {
  googleDriveBackup.disconnect();
  updateDriveBackupUI("Disconnected from Google Drive in this tab.");
});
el.driveBackup.addEventListener("click", async () => {
  if (!vaultPresent) return updateDriveBackupUI("Create or restore an encrypted vault before backing up.");
  setDriveBusy(el.driveBackup, true, "Backing up…", "Back up now");
  try {
    const record = validateVaultBackupRecord(await getVaultRecord());
    const file = await googleDriveBackup.backup(createVaultBackupEnvelope(record));
    updateDriveBackupUI(driveFileStatus(file));
    showToast("Encrypted vault backed up to Google Drive");
  } catch (error) {
    updateDriveBackupUI(error.message);
  } finally {
    setDriveBusy(el.driveBackup, false, "Backing up…", "Back up now");
    updateDriveBackupUI();
  }
});
el.driveRestoreOpen.addEventListener("click", async () => {
  setDriveBusy(el.driveRestoreOpen, true, "Checking…", "Restore…");
  try {
    pendingDriveRestore = await googleDriveBackup.restore(validateVaultBackupRecord);
    const backedUp = new Date(pendingDriveRestore.envelope.lastBackedUpAt).toLocaleString();
    el.driveRestoreCopy.textContent = vaultPresent
      ? `This vault was last backed up ${backedUp}. It will replace the encrypted vault currently saved in this browser.`
      : `This vault was last backed up ${backedUp}. It will become the encrypted vault in this browser.`;
    el.vaultOptionsDialog.close();
    el.driveRestoreDialog.showModal();
    el.driveRestoreConfirmation.focus();
  } catch (error) {
    updateDriveBackupUI(error.message);
  } finally {
    setDriveBusy(el.driveRestoreOpen, false, "Checking…", "Restore…");
    updateDriveBackupUI();
  }
});
$("#drive-restore-cancel").addEventListener("click", () => {
  resetDriveRestoreDialog();
  el.driveRestoreDialog.close();
});
el.driveRestoreDialog.addEventListener("cancel", resetDriveRestoreDialog);
el.driveRestoreConfirmation.addEventListener("input", () => {
  el.driveRestoreSubmit.disabled = el.driveRestoreConfirmation.value.trim() !== "RESTORE";
  el.driveRestoreError.hidden = true;
});
el.driveRestoreForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!pendingDriveRestore || el.driveRestoreConfirmation.value.trim() !== "RESTORE") {
    el.driveRestoreError.textContent = "Type RESTORE exactly to confirm replacement of this browser’s encrypted vault.";
    el.driveRestoreError.hidden = false;
    return;
  }
  el.driveRestoreSubmit.disabled = true;
  el.driveRestoreSubmit.textContent = "Restoring…";
  try {
    await replaceVaultRecord(pendingDriveRestore.envelope.vault);
    clearActiveContext();
    entries = entries.filter((entry) => !entry.persisted);
    vaultKey = null;
    vaultPresent = true;
    vaultDevice = await getVaultDevice();
    activeId = entries[0]?.id || null;
    resetDriveRestoreDialog();
    el.driveRestoreDialog.close();
    renderWorkspace();
    updateVaultUI();
    showToast("Encrypted vault restored; unlock it with its recovery passphrase");
    requestAnimationFrame(openVaultDialog);
  } catch (error) {
    el.driveRestoreError.textContent = error.message;
    el.driveRestoreError.hidden = false;
    el.driveRestoreSubmit.disabled = false;
    el.driveRestoreSubmit.textContent = "Replace and restore";
  }
});
el.settingsChangePassword.addEventListener("click", () => {
  el.vaultOptionsDialog.close();
  if (vaultKey) return openChangePasswordDialog();
  openVaultOptionsAfterUnlock = true;
  openVaultDialog();
});
$("#change-password-cancel").addEventListener("click", () => { clearChangePasswordForm(); el.changePasswordDialog.close(); });
[el.currentVaultPassword, el.newVaultPassword, el.confirmNewVaultPassword].forEach((input) => input.addEventListener("input", () => {
  el.changePasswordError.textContent = "";
  el.changePasswordError.hidden = true;
}));
el.changePasswordForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!vaultKey || !vaultPresent) {
    el.changePasswordError.textContent = "Unlock the encrypted vault before changing its passphrase.";
    el.changePasswordError.hidden = false;
    return;
  }
  const currentPassphrase = el.currentVaultPassword.value;
  const newPassphrase = el.newVaultPassword.value;
  const passphraseProblem = vaultPassphraseProblem(newPassphrase);
  if (passphraseProblem) {
    el.changePasswordError.textContent = passphraseProblem;
    el.changePasswordError.hidden = false;
    return;
  }
  if (newPassphrase !== el.confirmNewVaultPassword.value) {
    el.changePasswordError.textContent = "The new passphrase confirmation does not match.";
    el.changePasswordError.hidden = false;
    el.confirmNewVaultPassword.select();
    return;
  }
  if (newPassphrase === currentPassphrase) {
    el.changePasswordError.textContent = "Choose a different passphrase.";
    el.changePasswordError.hidden = false;
    return;
  }
  el.changePasswordSubmit.disabled = true;
  el.changePasswordSubmit.textContent = "Re-encrypting…";
  try {
    const current = await unlockVault(currentPassphrase);
    let deviceAccess = null;
    if (el.changeDeviceUnlock.checked) {
      if (!deviceUnlockCapable) throw new Error("Device unlock is not available in this browser. Turn it off to continue with passphrase-only access.");
      el.changePasswordSubmit.textContent = vaultDevice ? "Confirm on device…" : "Creating device unlock…";
      deviceAccess = vaultDevice ? await getDeviceUnlock(vaultDevice) : await createDeviceUnlock();
    }
    const persisted = entries.filter((entry) => entry.persisted).map(withoutContext);
    el.changePasswordSubmit.textContent = "Re-encrypting…";
    vaultKey = await updateVaultCredentials(current.key, newPassphrase, persisted, deviceAccess);
    vaultDevice = await getVaultDevice();
    clearChangePasswordForm();
    el.changePasswordDialog.close();
    updateVaultUI();
    showToast(vaultDevice ? "Vault passphrase and device unlock updated" : "Vault passphrase changed");
  } catch (error) {
    el.changePasswordError.textContent = error.message;
    el.changePasswordError.hidden = false;
    el.currentVaultPassword.select();
  } finally {
    el.changePasswordSubmit.disabled = false;
    el.changePasswordSubmit.textContent = "Change passphrase";
  }
});

$("#vault-purge-open").addEventListener("click", () => {
  el.vaultOptionsDialog.close();
  resetPurgeDialog();
  el.purgeVaultDialog.showModal();
  $("#purge-vault-cancel").focus();
});
$("#purge-vault-cancel").addEventListener("click", () => { resetPurgeDialog(); el.purgeVaultDialog.close(); });
$("#purge-vault-continue").addEventListener("click", () => {
  el.purgeVaultFirst.hidden = true;
  el.purgeVaultFinal.hidden = false;
  el.purgeVaultConfirmation.focus();
});
$("#purge-vault-back").addEventListener("click", () => {
  resetPurgeDialog();
  $("#purge-vault-continue").focus();
});
el.purgeVaultConfirmation.addEventListener("input", () => {
  el.purgeVaultSubmit.disabled = el.purgeVaultConfirmation.value.trim() !== "PURGE";
  el.purgeVaultError.hidden = true;
});
el.purgeVaultForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (el.purgeVaultConfirmation.value.trim() !== "PURGE") {
    el.purgeVaultError.textContent = "Type PURGE exactly to confirm permanent deletion.";
    el.purgeVaultError.hidden = false;
    return;
  }
  el.purgeVaultSubmit.disabled = true;
  el.purgeVaultSubmit.textContent = "Purging…";
  try {
    await purgeVault();
    clearActiveContext();
    entries = entries.filter((entry) => !entry.persisted);
    vaultKey = null;
    vaultDevice = null;
    vaultPresent = false;
    activeId = entries[0]?.id || null;
    resetPurgeDialog();
    el.purgeVaultDialog.close();
    renderWorkspace();
    updateVaultUI();
    if (!entries.length) switchTab("setup");
    showToast("Encrypted vault permanently purged from this browser context");
  } catch (error) {
    el.purgeVaultError.textContent = error.message;
    el.purgeVaultError.hidden = false;
  } finally {
    el.purgeVaultSubmit.textContent = "Permanently purge vault";
  }
});

async function createConfiguredChannel(config) {
  const button = $("#create-channel");
  button.disabled = true; button.textContent = "Preparing secure channel…";
  try {
    const pair = await createChannelPair(config);
    pair.local.persisted = el.saveChannel.checked && Boolean(vaultKey);
    presentForSharing(pair.local, pair.peer);
  } catch (error) { showError(error.message); }
  finally { button.disabled = false; button.innerHTML = 'Create private channel <span aria-hidden="true">→</span>'; }
}

$("#create-channel").addEventListener("click", async () => {
  clearError();
  const scheme = selected("scheme");
  const config = {
    name: el.name.value.trim() || "Private channel", context: el.context.value,
    scheme, method: selected("method"), format: el.format.value,
    role: selected("proof-role"), total: Number(el.proofTotal.value),
    length: scheme === "proof" ? Number(el.proofWords.value) : Number(el.length.value),
  };
  if (!config.context.trim()) return createConfiguredChannel(config);
  clearContextConfirm();
  pendingCreateConfig = config;
  el.contextConfirmDialog.showModal();
  el.contextConfirm.focus();
});

$("#context-confirm-cancel").addEventListener("click", () => {
  const context = pendingCreateConfig?.context ?? "";
  clearContextConfirm();
  el.contextConfirmDialog.close();
  restoreContextInput(context);
});
el.contextConfirmDialog.addEventListener("cancel", () => {
  const context = pendingCreateConfig?.context ?? "";
  clearContextConfirm();
  restoreContextInput(context);
});
el.contextConfirm.addEventListener("input", () => {
  el.contextConfirmError.textContent = "";
  el.contextConfirmError.hidden = true;
});
el.contextConfirmForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!pendingCreateConfig) return el.contextConfirmDialog.close();
  if (el.contextConfirm.value !== pendingCreateConfig.context) {
    showContextConfirmError("The contexts do not match. Re-enter the exact context used during setup.");
    el.contextConfirm.select();
    return;
  }
  const config = pendingCreateConfig;
  el.contextConfirmSubmit.disabled = true;
  clearContextConfirm();
  el.contextConfirmDialog.close();
  try { await createConfiguredChannel(config); }
  finally { el.contextConfirmSubmit.disabled = false; }
});

el.showImport.addEventListener("click", () => { stopCameraScanner(); el.setupStart.hidden = true; el.importView.hidden = false; clearError(); el.importCode.focus(); });
$("#cancel-import").addEventListener("click", resetSetupViews);
$("#cancel-share").addEventListener("click", resetSetupViews);
$("#import-channel").addEventListener("click", () => {
  try {
    const entry = decodeSetupCode(el.importCode.value);
    entry.persisted = el.saveImport.checked && Boolean(vaultKey);
    stopCameraScanner(); addEntry(entry); el.importCode.value = ""; switchTab("use"); showToast("Trust channel imported");
  } catch (error) { showError(error.message); }
});

$("#copy-setup").addEventListener("click", () => copyText(el.setupCode.textContent, "Setup code copied"));
el.showSetupQr.addEventListener("click", () => {
  try {
    drawQrCode(el.setupCode.textContent, el.setupQr);
    el.setupQrPanel.hidden = false;
    el.showSetupQr.textContent = "Refresh QR";
  } catch (error) { showError(error.message); }
});
$("#hide-setup-qr").addEventListener("click", () => { hideSetupQr(); el.showSetupQr.textContent = "Show QR"; });
el.startScanner.addEventListener("click", async () => {
  el.startScanner.disabled = true;
  el.scannerView.hidden = false;
  try { await scannerInstance().start(); }
  catch (error) {
    cameraScanner?.stop();
    el.startScanner.disabled = false;
    el.scannerStatus.textContent = cameraErrorMessage(error);
  }
});
el.stopScanner.addEventListener("click", () => stopCameraScanner());
$("#finish-setup").addEventListener("click", () => {
  addEntry(pendingLocal); pendingLocal = null; pendingPeer = null;
  hideSetupQr(); el.setupCode.textContent = ""; switchTab("use");
});
el.useContext.addEventListener("input", () => {
  const entry = active();
  if (entry) clearProofCache(entry);
  activeContext = el.useContext.value;
  el.contextStatus.textContent = activeContext.trim() ? "Context applied in memory" : "No context applied";
  lastCounter = -1;
  clearTimeout(contextTimer);
  contextTimer = setTimeout(renderWorkspace, 350);
});
$("#clear-context").addEventListener("click", () => { clearActiveContext(); renderWorkspace(); el.useContext.focus(); showToast("Context cleared from memory"); });
el.select.addEventListener("change", () => { clearActiveContext(); activeId = el.select.value; renderWorkspace(); el.useContext.focus(); });
$("#copy-code").addEventListener("click", () => {
  const entry = active();
  const format = entry?.scheme === "proof" ? "words" : entry?.format;
  copyText(normalizeCode(el.generated.textContent, format), "Trust code copied");
});

el.next.addEventListener("click", async () => {
  const entry = active(); entry.counter += 1; await savePersisted(); renderWorkspace(); showToast("Counter advanced on this device");
});
el.simpleNext.addEventListener("click", async () => {
  const entry = active(); entry.counter += 1; await savePersisted(); renderWorkspace(); showToast("Next code shown");
});
el.consume.addEventListener("click", async () => {
  const entry = active(); consumeProof(entry); await savePersisted(); renderWorkspace(); showToast("Proof consumed—do not reuse the previous phrase");
});
el.simpleConsume.addEventListener("click", async () => {
  const entry = active(); consumeProof(entry); await savePersisted(); renderWorkspace(); showToast("Next phrase shown");
});
el.verifyInput.addEventListener("input", () => { el.result.hidden = true; });
el.verifyButton.addEventListener("click", async () => {
  const entry = active(); el.verifyButton.disabled = true;
  try {
    const result = await verifyProofPhrase(el.verifyInput.value, entry, contextFor());
    if (result.valid) {
      await savePersisted();
      el.verifyRemaining.textContent = `${entry.remaining} of ${entry.total} proofs remaining`;
      el.methodBadge.textContent = formatLabel(entry);
      el.verifyInput.value = "";
      verificationResult(true, result.exhausted ? "Valid final proof—the chain is now exhausted." : "Valid one-way proof. It has been consumed and cannot be replayed.");
    } else verificationResult(false, "Invalid proof. Stop and reconnect through a contact method you trust.");
  } catch (error) { verificationResult(false, error.message); }
  finally { el.verifyButton.disabled = entry.remaining < 1; }
});
el.simpleVerifyInput.addEventListener("input", () => { el.simpleVerifyResult.hidden = true; });
el.simpleVerifyButton.addEventListener("click", async () => {
  const entry = active();
  if (!entry || entry.scheme !== "proof" || entry.role !== "verify") return;
  el.simpleVerifyButton.disabled = true;
  try {
    const result = await verifyProofPhrase(el.simpleVerifyInput.value, entry, contextFor());
    el.simpleVerifyResult.hidden = false;
    el.simpleVerifyResult.className = `simple-verify-result ${result.valid ? "success" : "failure"}`;
    if (result.valid) {
      await savePersisted();
      el.simpleVerifyInput.value = "";
      el.simpleVerifyResult.textContent = result.exhausted ? "Correct. This was the final phrase." : "Correct. This phrase cannot be used again.";
      el.simpleVerifyRemaining.textContent = `${entry.remaining} phrases remaining`;
    } else {
      el.simpleVerifyResult.textContent = "That phrase does not match. Stop and contact them another way.";
    }
  } catch (error) {
    el.simpleVerifyResult.hidden = false;
    el.simpleVerifyResult.className = "simple-verify-result failure";
    el.simpleVerifyResult.textContent = error.message;
  } finally { el.simpleVerifyButton.disabled = entry.remaining < 1; }
});

$("#forget-channel").addEventListener("click", async () => {
  const entry = active();
  if (!entry || !confirm(`Forget “${entry.name}” on this device? You will need a setup backup to restore it.`)) return;
  clearActiveContext();
  entries = entries.filter((item) => item.id !== entry.id); activeId = entries[0]?.id || null;
  await savePersisted(); renderWorkspace(); if (!entries.length) switchTab("setup"); showToast("Channel forgotten");
});

el.vaultAction.addEventListener("click", openVaultDialog);
el.vaultLock.addEventListener("click", () => {
  clearActiveContext();
  clearVaultCredentialInputs();
  entries = entries.filter((entry) => !entry.persisted);
  vaultKey = null; activeId = entries[0]?.id || null; renderWorkspace(); updateVaultUI(); showToast("Encrypted vault locked");
});
$("#vault-cancel").addEventListener("click", () => { openVaultOptionsAfterUnlock = false; el.vaultDialog.close(); });
el.vaultDialog.addEventListener("cancel", () => { openVaultOptionsAfterUnlock = false; });
el.vaultDialog.addEventListener("close", clearVaultCredentialInputs);
el.changePasswordDialog.addEventListener("close", clearVaultCredentialInputs);
el.vaultDeviceSubmit.addEventListener("click", async () => {
  el.vaultDeviceSubmit.disabled = true;
  el.vaultDeviceSubmit.textContent = "Confirm on device…";
  el.vaultError.hidden = true;
  try {
    const deviceAccess = await getDeviceUnlock(vaultDevice);
    const unlocked = await unlockVaultWithDevice(deviceAccess);
    const restored = restoreUnlockedVault(unlocked);
    await saveVault(vaultKey, restored.map(withoutContext));
    el.vaultDialog.close();
    updateVaultUI();
    renderWorkspace();
    showToast("Encrypted vault unlocked with this device");
    if (openVaultOptionsAfterUnlock) {
      openVaultOptionsAfterUnlock = false;
      requestAnimationFrame(openChangePasswordDialog);
    }
  } catch (error) { showVaultError(error.message); }
  finally { el.vaultDeviceSubmit.disabled = false; el.vaultDeviceSubmit.textContent = "Unlock with this device"; }
});
el.vaultForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const creating = el.vaultDialog.dataset.mode === "create";
  const passphrase = el.vaultPassphrase.value;
  if (creating) {
    const passphraseProblem = vaultPassphraseProblem(passphrase);
    if (passphraseProblem) return showVaultError(passphraseProblem);
  }
  if (creating && passphrase !== el.vaultConfirm.value) return showVaultError("The confirmation does not match.");
  el.vaultSubmit.disabled = true; el.vaultSubmit.textContent = creating ? "Creating…" : "Unlocking…";
  try {
    if (creating) {
      let deviceAccess = null;
      if (el.vaultDeviceUnlock.checked) {
        el.vaultSubmit.textContent = "Creating device unlock…";
        deviceAccess = await createDeviceUnlock();
      }
      el.vaultSubmit.textContent = "Creating…";
      vaultKey = await createVault(passphrase, [], deviceAccess);
      vaultPresent = true;
      vaultDevice = await getVaultDevice();
    } else {
      const unlocked = await unlockVault(passphrase);
      const restored = restoreUnlockedVault(unlocked);
      await saveVault(vaultKey, restored.map(withoutContext));
    }
    el.vaultDialog.close(); updateVaultUI(); renderWorkspace(); showToast(creating ? "Encrypted vault created" : "Encrypted vault unlocked");
    if (!creating && openVaultOptionsAfterUnlock) {
      openVaultOptionsAfterUnlock = false;
      requestAnimationFrame(openChangePasswordDialog);
    }
  } catch (error) { showVaultError(error.message); }
  finally { el.vaultSubmit.disabled = false; el.vaultSubmit.textContent = creating ? "Create encrypted vault" : "Unlock vault"; }
});

document.addEventListener("visibilitychange", () => { if (document.hidden) stopCameraScanner(); });
window.addEventListener("pagehide", () => stopCameraScanner());

updateStrengthOptions(); updateProofStrengthDetails(); updateScheme(); renderWorkspace(); initializeVault(); renderBuildVersion(); tick(); setInterval(tick, 250);
