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
import { createVault, saveVault, unlockVault, vaultExists } from "./vault.js";
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
  vaultDot: $("#vault-dot"), vaultStatus: $("#vault-status"), vaultDetail: $("#vault-detail"), vaultAction: $("#vault-action"), vaultLock: $("#vault-lock"),
  vaultDialog: $("#vault-dialog"), vaultForm: $("#vault-form"), vaultDialogTitle: $("#vault-dialog-title"), vaultDialogCopy: $("#vault-dialog-copy"),
  vaultPassphrase: $("#vault-passphrase"), vaultConfirmField: $("#vault-confirm-field"), vaultConfirm: $("#vault-confirm"), vaultSubmit: $("#vault-submit"), vaultError: $("#vault-error"),
  contextConfirmDialog: $("#context-confirm-dialog"), contextConfirmForm: $("#context-confirm-form"), contextConfirm: $("#context-confirm"),
  contextConfirmSubmit: $("#context-confirm-submit"), contextConfirmError: $("#context-confirm-error"),
  simpleMode: $("#simple-mode"), simpleEnter: $("#simple-mode-enter"), simpleExit: $("#simple-mode-exit"),
  simplePhotoButton: $("#simple-photo-button"), simplePhoto: $("#simple-photo"), simplePhotoInitials: $("#simple-photo-initials"),
  simpleName: $("#simple-person-name"), simplePrompt: $("#simple-prompt"), simplePeopleList: $("#simple-people-list"),
  simpleGenerateCard: $("#simple-generate-card"), simpleGenerated: $("#simple-generated-code"), simpleTimer: $("#simple-totp-timer"),
  simpleTimerProgress: $("#simple-timer-progress"), simpleTimerText: $("#simple-timer-text"), simpleRemaining: $("#simple-remaining"),
  simpleNext: $("#simple-next-code"), simpleConsume: $("#simple-consume-proof"), simpleVerifyCard: $("#simple-verify-card"),
  simpleVerifyInput: $("#simple-verify-code"), simpleVerifyButton: $("#simple-verify-button"), simpleVerifyResult: $("#simple-verify-result"), simpleVerifyRemaining: $("#simple-verify-remaining"),
  photoDialog: $("#photo-dialog"), takePhoto: $("#take-photo"), choosePhoto: $("#choose-photo"), removePhoto: $("#remove-photo"),
  cameraPhotoInput: $("#camera-photo-input"), libraryPhotoInput: $("#library-photo-input"),
};

let entries = [];
let activeId = null;
let pendingLocal = null;
let pendingPeer = null;
let activeContext = "";
let vaultKey = null;
let vaultPresent = false;
let vaultAvailable = true;
let lastCounter = -1;
let toastTimer;
let contextTimer;
let cameraScanner = null;
let pendingCreateConfig = null;
let simpleModeRequested = readSimpleModePreference();
let simpleRenderedId = null;

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
        el.scannerStatus.textContent = "A QR code was found, but it is not a Trust Codes setup code.";
        return false;
      }
      try { decodeSetupCode(setupCode); }
      catch {
        el.scannerStatus.textContent = "That Trust Codes QR code is damaged or unsupported.";
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
    el.vaultAction.textContent = vaultPresent ? "Unlock vault" : "Create vault";
  }
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
    el.simplePrompt.textContent = "Read this code aloud and compare it together";
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

function openVaultDialog() {
  const creating = !vaultPresent;
  el.vaultDialog.dataset.mode = creating ? "create" : "unlock";
  el.vaultDialogTitle.textContent = creating ? "Create encrypted vault" : "Unlock encrypted vault";
  el.vaultDialogCopy.textContent = creating ? "The passphrase derives an encryption key locally. There is no recovery service." : "Your passphrase derives the key that decrypts saved entries.";
  el.vaultConfirmField.hidden = !creating;
  el.vaultConfirm.required = creating;
  el.vaultSubmit.textContent = creating ? "Create encrypted vault" : "Unlock vault";
  el.vaultPassphrase.value = ""; el.vaultConfirm.value = ""; el.vaultError.hidden = true;
  el.vaultDialog.showModal();
  el.vaultPassphrase.focus();
}

async function initializeVault() {
  try { vaultPresent = await vaultExists(); }
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
  const entry = active();
  if (!entry) return;
  el.removePhoto.hidden = !entry.photo;
  el.photoDialog.showModal();
});
el.takePhoto.addEventListener("click", () => { el.photoDialog.close(); el.cameraPhotoInput.click(); });
el.choosePhoto.addEventListener("click", () => { el.photoDialog.close(); el.libraryPhotoInput.click(); });
el.cameraPhotoInput.addEventListener("change", () => applySelectedPhoto(el.cameraPhotoInput));
el.libraryPhotoInput.addEventListener("change", () => applySelectedPhoto(el.libraryPhotoInput));
$("#photo-cancel").addEventListener("click", () => el.photoDialog.close());
el.removePhoto.addEventListener("click", async () => {
  const entry = active();
  if (!entry?.photo) return;
  delete entry.photo;
  el.photoDialog.close();
  await savePersisted();
  renderWorkspace();
  showToast("Photo removed from this device");
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
  entries = entries.filter((entry) => !entry.persisted);
  vaultKey = null; activeId = entries[0]?.id || null; renderWorkspace(); updateVaultUI(); showToast("Encrypted vault locked");
});
$("#vault-cancel").addEventListener("click", () => el.vaultDialog.close());
el.vaultForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const creating = el.vaultDialog.dataset.mode === "create";
  const passphrase = el.vaultPassphrase.value;
  if (passphrase.length < 12) return showVaultError("Use at least 12 characters; a longer multi-word passphrase is strongly recommended.");
  if (creating && passphrase !== el.vaultConfirm.value) return showVaultError("The confirmation does not match.");
  el.vaultSubmit.disabled = true; el.vaultSubmit.textContent = creating ? "Creating…" : "Unlocking…";
  try {
    if (creating) {
      vaultKey = await createVault(passphrase, []); vaultPresent = true;
    } else {
      const unlocked = await unlockVault(passphrase); vaultKey = unlocked.key;
      clearActiveContext();
      const ephemeral = entries.filter((entry) => !entry.persisted);
      const restored = unlocked.entries.map((entry) => ({ ...withoutContext(entry), persisted: true }));
      entries = [...restored, ...ephemeral];
      await saveVault(vaultKey, restored.map(withoutContext));
      activeId = entries[0]?.id || null;
    }
    el.vaultDialog.close(); updateVaultUI(); renderWorkspace(); showToast(creating ? "Encrypted vault created" : "Encrypted vault unlocked");
  } catch (error) { showVaultError(error.message); }
  finally { el.vaultSubmit.disabled = false; el.vaultSubmit.textContent = creating ? "Create encrypted vault" : "Unlock vault"; }
});

document.addEventListener("visibilitychange", () => { if (document.hidden) stopCameraScanner(); });
window.addEventListener("pagehide", () => stopCameraScanner());

updateStrengthOptions(); updateProofStrengthDetails(); updateScheme(); renderWorkspace(); initializeVault(); renderBuildVersion(); tick(); setInterval(tick, 250);
