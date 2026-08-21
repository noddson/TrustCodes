import { WORDS } from "./words-2048.js";

export { WORDS };

const BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const CROCKFORD_BASE32 = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const DEFAULT_PROOF_WORDS = 6;
const PROOF_WORD_LENGTHS = [5, 6, 7, 8, 9, 10];
const CONTEXT_ITERATIONS = 600_000;
const encoder = new TextEncoder();
const SETUP_AAD = encoder.encode("TrustCodes/AuthenticatedSetup/v1");
export const SETUP_KDF_ITERATIONS = 600_000;
export const SETUP_PASSPHRASE_WORDS = 8;
export const SETUP_FINGERPRINT_HEX_DIGITS = 12;
const proofCaches = new WeakMap();
const contextKeyCaches = new WeakMap();

function encodeWithAlphabet(bytes, alphabet) {
  let bits = 0, value = 0, output = "";
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += alphabet[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits) output += alphabet[(value << (5 - bits)) & 31];
  return output;
}

export function encodeBase32(bytes) {
  return encodeWithAlphabet(bytes, BASE32);
}

export function encodeCrockfordBase32(bytes) {
  return encodeWithAlphabet(bytes, CROCKFORD_BASE32);
}

export function decodeBase32(input) {
  const value = input.toUpperCase().replace(/[\s=-]/g, "");
  if (!value || /[^A-Z2-7]/.test(value)) throw new Error("The secret is not valid Base32.");
  let bits = 0, buffer = 0;
  const bytes = [];
  for (const character of value) {
    buffer = (buffer << 5) | BASE32.indexOf(character);
    bits += 5;
    if (bits >= 8) {
      bytes.push((buffer >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return new Uint8Array(bytes);
}

export function encodeBase64Url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function decodeBase64Url(value) {
  const encoded = value.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(encoded + "=".repeat((4 - encoded.length % 4) % 4));
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

export function generateSecret(size = 20) {
  return encodeBase32(crypto.getRandomValues(new Uint8Array(size)));
}

export function createId() {
  if (typeof crypto.randomUUID === "function") return crypto.randomUUID();
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  bytes[6] = (bytes[6] & 15) | 64;
  bytes[8] = (bytes[8] & 63) | 128;
  const hex = [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function counterBytes(counter) {
  let value = BigInt(counter);
  if (value < 0n) throw new Error("Counter cannot be negative.");
  const result = new Uint8Array(8);
  for (let index = 7; index >= 0; index -= 1) {
    result[index] = Number(value & 255n);
    value >>= 8n;
  }
  return result;
}

function concatBytes(...arrays) {
  const result = new Uint8Array(arrays.reduce((total, array) => total + array.length, 0));
  let offset = 0;
  for (const array of arrays) { result.set(array, offset); offset += array.length; }
  return result;
}

function xorBytes(left, right) {
  if (left.length !== right.length) throw new Error("Proof context mask has the wrong size.");
  return Uint8Array.from(left, (byte, index) => byte ^ right[index]);
}

function normalizedContext(context = "") {
  return String(context).trim().normalize("NFC").slice(0, 96);
}

async function contextKey(entry, context) {
  const normalized = normalizedContext(context);
  if (!normalized) return null;
  const cached = contextKeyCaches.get(entry);
  if (cached?.context === normalized) return cached.promise;
  const promise = (async () => {
    const material = await crypto.subtle.importKey("raw", encoder.encode(normalized), "PBKDF2", false, ["deriveBits"]);
    const salt = concatBytes(encoder.encode("TrustCodes/ContextWrap/v1\0"), decodeBase64Url(entry.contextSalt));
    return new Uint8Array(await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations: CONTEXT_ITERATIONS }, material, 256));
  })();
  contextKeyCaches.set(entry, { context: normalized, promise });
  return promise;
}

async function contextMaterialMask(entry, context, label, length, words) {
  const keyBytes = await contextKey(entry, context);
  if (!keyBytes) return new Uint8Array(length);
  const key = await crypto.subtle.importKey("raw", keyBytes, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const digest = new Uint8Array(await crypto.subtle.sign("HMAC", key, encoder.encode(`TrustCodes/ContextMaterial/v1\0${label}`)));
  return words ? canonicalProofBytes(digest, words) : digest.slice(0, length);
}

async function transformContextMaterial(entry, material, context, label, words) {
  const mask = await contextMaterialMask(entry, context, label, material.length, words);
  return xorBytes(material, mask);
}

function movingFactorMessage(counter, context, method) {
  const movingFactor = counterBytes(counter);
  const normalized = normalizedContext(context);
  if (!normalized) return movingFactor;
  const prefix = encoder.encode(`TrustCodes/Mutual/v1\0${method}\0${normalized}\0`);
  return concatBytes(prefix, movingFactor);
}

export async function hmacForCounter(secret, counter, context = "", method = "hotp") {
  const key = await crypto.subtle.importKey("raw", decodeBase32(secret), { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", key, movingFactorMessage(counter, context, method)));
}

function bytesToBigInt(bytes) {
  let value = 0n;
  for (const byte of bytes) value = (value << 8n) | BigInt(byte);
  return value;
}

function standardDecimal(digest, length) {
  const offset = digest[digest.length - 1] & 15;
  const binary = ((digest[offset] & 127) << 24) | ((digest[offset + 1] & 255) << 16) | ((digest[offset + 2] & 255) << 8) | (digest[offset + 3] & 255);
  return String(binary % 10 ** length).padStart(length, "0");
}

export function bytesToWords(bytes, length) {
  if (!Number.isSafeInteger(length) || length < 1 || length * 11 > bytes.length * 8) throw new Error("The requested word strength exceeds the available digest.");
  const value = bytesToBigInt(bytes);
  const totalBits = bytes.length * 8;
  return Array.from({ length }, (_, index) => {
    const shift = BigInt(totalBits - 11 * (index + 1));
    return WORDS[Number((value >> shift) & 2047n)];
  }).join(" ");
}

function proofByteLength(words) {
  return Math.ceil(words * 11 / 8);
}

function canonicalProofBytes(bytes, words) {
  const length = proofByteLength(words);
  const result = new Uint8Array(bytes).slice(0, length);
  if (result.length !== length) throw new Error("The proof state has the wrong size.");
  const paddingBits = length * 8 - words * 11;
  if (paddingBits) result[length - 1] &= (255 << paddingBits) & 255;
  return result;
}

export function wordsToBytes(phrase, expectedLength) {
  const parts = normalizeCode(phrase, "words").split(" ").filter(Boolean);
  const length = expectedLength ?? parts.length;
  if (!PROOF_WORD_LENGTHS.includes(length)) throw new Error("Proof phrases must contain between 5 and 10 words.");
  if (parts.length !== length) throw new Error(`Enter all ${length} words.`);
  let value = 0n;
  for (const word of parts) {
    const index = WORDS.indexOf(word);
    if (index < 0) throw new Error(`“${word}” is not in the TrustCodes dictionary.`);
    value = (value << 11n) | BigInt(index);
  }
  const bytes = new Uint8Array(proofByteLength(length));
  value <<= BigInt(bytes.length * 8 - length * 11);
  for (let index = bytes.length - 1; index >= 0; index -= 1) {
    bytes[index] = Number(value & 255n);
    value >>= 8n;
  }
  return bytes;
}

export function formatDigest(digest, format = "numeric", length = 6) {
  if (format === "words") return bytesToWords(digest, length);
  if (format === "base32") return encodeCrockfordBase32(digest).slice(0, length);
  if (format === "numeric") {
    if (length <= 8) return standardDecimal(digest, length);
    return String(bytesToBigInt(digest) % (10n ** BigInt(length))).padStart(length, "0");
  }
  throw new Error("Unsupported code format.");
}

export function permutationCount(format, length) {
  const bases = { numeric: 10n, base32: 32n, words: 2048n };
  if (!(format in bases) || !Number.isSafeInteger(length) || length < 1) throw new Error("Unsupported permutation calculation.");
  return bases[format] ** BigInt(length);
}

export function timeCounter(time = Date.now(), period = 30) {
  return Math.floor(time / 1000 / period);
}

async function mutualSecretForContext(entry, context) {
  if (entry.contextProtection !== "pbkdf2-wrap") return entry.secret;
  const wrapped = decodeBase32(entry.secret);
  return encodeBase32(await transformContextMaterial(entry, wrapped, context, "mutual-secret"));
}

export async function generateMutualCode(entry, time = Date.now(), counterOverride, context = entry.context || "") {
  const counter = counterOverride ?? (entry.method === "totp" ? timeCounter(time, entry.period || 30) : entry.counter);
  const secret = await mutualSecretForContext(entry, context);
  const digest = await hmacForCounter(secret, counter, context, entry.method);
  return formatDigest(digest, entry.format, entry.length);
}

export function normalizeCode(value, format) {
  if (format === "words") return value.toLowerCase().trim().replace(/[^a-z]+/g, " ").trim();
  if (format === "base32") return value.toUpperCase().replace(/O/g, "0").replace(/[IL]/g, "1").replace(/[^0-9A-HJKMNP-TV-Z]/g, "");
  return value.replace(/\D/g, "");
}

function safeEqualBytes(left, right) {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) difference |= left[index] ^ right[index];
  return difference === 0;
}

function safeEqualText(left, right) {
  return safeEqualBytes(encoder.encode(left), encoder.encode(right));
}

export async function verifyMutualCode(input, entry, time = Date.now(), context = entry.context || "") {
  const token = normalizeCode(input, entry.format);
  if (entry.method === "totp") {
    const current = timeCounter(time, entry.period || 30);
    for (let offset = -1; offset <= 1; offset += 1) {
      const expected = normalizeCode(await generateMutualCode(entry, time, current + offset, context), entry.format);
      if (safeEqualText(token, expected)) return { valid: true, counter: current + offset };
    }
    return { valid: false };
  }
  return { valid: safeEqualText(token, normalizeCode(await generateMutualCode(entry, time, undefined, context), entry.format)), counter: entry.counter };
}

export async function hashChainStep(value, context = "", words = DEFAULT_PROOF_WORDS) {
  const prefix = encoder.encode(`TrustCodes/Proof/v1\0${normalizedContext(context)}\0`);
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", concatBytes(prefix, value)));
  return canonicalProofBytes(digest, words);
}

export async function deriveChainValue(seed, steps, context = "", words = DEFAULT_PROOF_WORDS) {
  let value = new Uint8Array(seed);
  for (let index = 0; index < steps; index += 1) value = await hashChainStep(value, context, words);
  return value;
}

function proofContextMode(entry) {
  if (entry.contextProtection === "pbkdf2-wrap") return "wrap";
  return entry.proofContextMode === "chain" ? "chain" : "mask";
}

async function proofContextMask(context, anchor, words) {
  const normalized = normalizedContext(context);
  if (!normalized) return new Uint8Array(proofByteLength(words));
  const key = await crypto.subtle.importKey("raw", encoder.encode(normalized), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const message = concatBytes(encoder.encode("TrustCodes/ProofContext/v1\0"), anchor);
  const digest = new Uint8Array(await crypto.subtle.sign("HMAC", key, message));
  return canonicalProofBytes(digest, words);
}

async function proofValues(entry, context = entry.context || "") {
  const mode = proofContextMode(entry);
  const normalized = ["chain", "wrap"].includes(mode) ? normalizedContext(context) : "";
  let cached = proofCaches.get(entry);
  if (cached?.context === normalized) return cached.values;
  if (!entry.seed) throw new Error("This prover has no chain seed.");
  let seed = decodeBase64Url(entry.seed);
  if (mode === "wrap") seed = await transformContextMaterial(entry, seed, context, "proof-seed", entry.length);
  const values = [seed];
  const chainContext = mode === "chain" ? normalized : "";
  for (let index = 1; index <= entry.total; index += 1) {
    values.push(await hashChainStep(values[index - 1], chainContext, entry.length));
  }
  proofCaches.set(entry, { context: normalized, values });
  return values;
}

export function clearProofCache(entry) {
  proofCaches.delete(entry);
  contextKeyCaches.delete(entry);
}

export async function generateProofPhrase(entry, context = entry.context || "") {
  if (entry.scheme !== "proof" || entry.role !== "prove") throw new Error("This entry cannot generate proofs.");
  if (!PROOF_WORD_LENGTHS.includes(entry.length)) throw new Error("This proof phrase strength is no longer supported. Create a new channel with 5 to 10 words.");
  if (entry.remaining < 1) throw new Error("This proof chain is exhausted.");
  const values = await proofValues(entry, context);
  let value = values[entry.remaining - 1];
  if (proofContextMode(entry) === "mask" && normalizedContext(context)) {
    value = xorBytes(value, await proofContextMask(context, values[entry.remaining], entry.length));
  }
  return bytesToWords(value, entry.length);
}

export function consumeProof(entry) {
  if (entry.remaining < 1) throw new Error("This proof chain is exhausted.");
  entry.remaining -= 1;
}

export async function verifyProofPhrase(phrase, entry, context = entry.context || "") {
  if (entry.scheme !== "proof" || entry.role !== "verify") throw new Error("This entry cannot verify proofs.");
  if (!PROOF_WORD_LENGTHS.includes(entry.length)) throw new Error("This proof phrase strength is no longer supported. Create a new channel with 5 to 10 words.");
  if (entry.remaining < 1) return { valid: false, exhausted: true };
  const mode = proofContextMode(entry);
  let anchor = decodeBase64Url(entry.anchor);
  if (mode === "wrap") anchor = await transformContextMaterial(entry, anchor, context, "proof-anchor", entry.length);
  let candidate = wordsToBytes(phrase, entry.length);
  if (mode === "mask" && normalizedContext(context)) {
    candidate = xorBytes(candidate, await proofContextMask(context, anchor, entry.length));
  }
  const chainContext = mode === "chain" ? context : "";
  const expected = await hashChainStep(candidate, chainContext, entry.length);
  const valid = safeEqualBytes(expected, anchor);
  if (valid) {
    const storedAnchor = mode === "wrap" ? await transformContextMaterial(entry, candidate, context, "proof-anchor", entry.length) : candidate;
    entry.anchor = encodeBase64Url(storedAnchor);
    entry.remaining -= 1;
  }
  return { valid, exhausted: entry.remaining < 1 };
}

export async function createChannelPair(config) {
  const context = normalizedContext(config.context);
  const common = {
    name: String(config.name || "Private channel").slice(0, 48),
    dictionary: 1,
    persisted: false,
  };
  const protection = () => ({ contextProtection: "pbkdf2-wrap", contextSalt: encodeBase64Url(crypto.getRandomValues(new Uint8Array(16))) });
  if (config.scheme === "mutual") {
    const rawSecret = crypto.getRandomValues(new Uint8Array(20));
    const local = { ...common, ...protection(), id: createId(), scheme: "mutual", method: config.method, period: 30, counter: 0, format: config.format, length: config.length };
    const peer = { ...common, ...protection(), id: createId(), scheme: "mutual", method: config.method, period: 30, counter: 0, format: config.format, length: config.length };
    local.secret = encodeBase32(await transformContextMaterial(local, rawSecret, context, "mutual-secret"));
    peer.secret = encodeBase32(await transformContextMaterial(peer, rawSecret, context, "mutual-secret"));
    clearProofCache(local);
    clearProofCache(peer);
    return { local, peer };
  }

  const total = Number(config.total) || 1000;
  if (!Number.isSafeInteger(total) || total < 1 || total > 5000) throw new Error("A proof chain must contain between 1 and 5,000 proofs.");
  const length = Number(config.length) || DEFAULT_PROOF_WORDS;
  if (!PROOF_WORD_LENGTHS.includes(length)) throw new Error("A proof phrase must contain between 5 and 10 words.");
  const seed = canonicalProofBytes(crypto.getRandomValues(new Uint8Array(proofByteLength(length))), length);
  const anchor = await deriveChainValue(seed, total, "", length);
  const prover = { ...common, ...protection(), id: createId(), scheme: "proof", role: "prove", remaining: total, total, length };
  const verifier = { ...common, ...protection(), id: createId(), scheme: "proof", role: "verify", remaining: total, total, length };
  prover.seed = encodeBase64Url(await transformContextMaterial(prover, seed, context, "proof-seed", length));
  verifier.anchor = encodeBase64Url(await transformContextMaterial(verifier, anchor, context, "proof-anchor", length));
  clearProofCache(prover);
  clearProofCache(verifier);
  return config.role === "prove" ? { local: prover, peer: verifier } : { local: verifier, peer: prover };
}

function serializableEntry(entry) {
  const wrapped = entry.contextProtection === "pbkdf2-wrap";
  if (entry.scheme === "mutual") {
    return { v: wrapped ? 6 : 5, q: "mutual", n: entry.name, ...(wrapped ? { w: 1, s: entry.contextSalt } : {}), m: entry.method, k: entry.secret, p: entry.period, c: entry.counter, f: entry.format, l: entry.length, d: 1 };
  }
  return { v: wrapped ? 6 : 5, q: "proof", n: entry.name, ...(wrapped ? { w: 1, s: entry.contextSalt } : {}), r: entry.role, z: entry.role === "prove" ? entry.seed : entry.anchor, e: entry.remaining, t: entry.total, l: entry.length, d: 1 };
}

function entryFromSetupData(data) {
  if (![3, 4, 5, 6].includes(data.v) || data.d !== 1 || !["mutual", "proof"].includes(data.q)) throw new Error();
  if (data.v === 6 && (data.w !== 1 || decodeBase64Url(data.s).length !== 16)) throw new Error();
  const protection = data.v === 6 ? { contextProtection: "pbkdf2-wrap", contextSalt: data.s } : {};
  const common = { id: createId(), name: String(data.n || "Private channel").slice(0, 48), ...protection, scheme: data.q, dictionary: 1, persisted: false };
  if (data.q === "mutual") {
    if (!["totp", "hotp"].includes(data.m) || !["numeric", "base32", "words"].includes(data.f)) throw new Error();
    const secret = decodeBase32(data.k);
    if (secret.length < 16 || secret.length > 64) throw new Error();
    const allowed = data.f === "words" ? PROOF_WORD_LENGTHS : [4, 6, 8, 10, 12, 16];
    if (!allowed.includes(data.l)) throw new Error();
    return { ...common, method: data.m, secret: data.k, period: 30, counter: Number.isSafeInteger(data.c) && data.c >= 0 ? data.c : 0, format: data.f, length: data.l };
  }
  if (!["prove", "verify"].includes(data.r) || !PROOF_WORD_LENGTHS.includes(data.l) || !Number.isSafeInteger(data.e) || data.e < 0 || !Number.isSafeInteger(data.t) || data.t < data.e || data.t < 1 || data.t > 5000) throw new Error();
  const material = decodeBase64Url(data.z);
  if (material.length !== proofByteLength(data.l)) throw new Error();
  if (!safeEqualBytes(material, canonicalProofBytes(material, data.l))) throw new Error();
  const legacyMode = data.v === 5 ? { proofContextMode: "mask" } : data.v < 5 ? { proofContextMode: "chain" } : {};
  return { ...common, ...legacyMode, role: data.r, [data.r === "prove" ? "seed" : "anchor"]: data.z, remaining: data.e, total: data.t, length: data.l };
}

function setupPassphraseWords(passphrase) {
  const words = normalizeCode(String(passphrase || ""), "words").split(" ").filter(Boolean);
  if (words.length !== SETUP_PASSPHRASE_WORDS || words.some((word) => !WORDS.includes(word))) {
    throw new Error("Enter the complete eight-word setup passphrase.");
  }
  return words;
}

async function deriveSetupKey(passphrase, salt) {
  const passphraseBytes = encoder.encode(setupPassphraseWords(passphrase).join(" "));
  try {
    const material = await crypto.subtle.importKey("raw", passphraseBytes, "PBKDF2", false, ["deriveKey"]);
    return crypto.subtle.deriveKey(
      { name: "PBKDF2", hash: "SHA-256", salt, iterations: SETUP_KDF_ITERATIONS },
      material,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"],
    );
  } finally {
    passphraseBytes.fill(0);
  }
}

function protectedSetupEnvelope(input) {
  const value = String(input || "").trim();
  if (!value.startsWith("TC2-")) throw new Error();
  if (value.length > 20_000) throw new Error();
  const envelope = JSON.parse(new TextDecoder().decode(decodeBase64Url(value.slice(4))));
  if (envelope?.v !== 1 || envelope.k !== "PBKDF2-HMAC-SHA256" || envelope.i !== SETUP_KDF_ITERATIONS) throw new Error();
  if (decodeBase64Url(envelope.s).length !== 16 || decodeBase64Url(envelope.n).length !== 12) throw new Error();
  const ciphertext = decodeBase64Url(envelope.c);
  if (ciphertext.length < 17 || ciphertext.length > 15_000) throw new Error();
  return { value, envelope, ciphertext };
}

export function generateSetupPassphrase() {
  const random = crypto.getRandomValues(new Uint32Array(SETUP_PASSPHRASE_WORDS));
  return Array.from(random, (value) => WORDS[value & 2047]).join(" ");
}

export function isProtectedSetupCode(input) {
  return String(input || "").trim().startsWith("TC2-");
}

export function validateProtectedSetupCode(input) {
  try {
    protectedSetupEnvelope(input);
    return true;
  } catch {
    return false;
  }
}

export async function encodeProtectedSetupCode(entry, passphrase) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveSetupKey(passphrase, salt);
  const plaintext = encoder.encode(JSON.stringify(serializableEntry(entry)));
  try {
    const ciphertext = new Uint8Array(await crypto.subtle.encrypt(
      { name: "AES-GCM", iv, additionalData: SETUP_AAD },
      key,
      plaintext,
    ));
    const envelope = {
      v: 1,
      k: "PBKDF2-HMAC-SHA256",
      i: SETUP_KDF_ITERATIONS,
      s: encodeBase64Url(salt),
      n: encodeBase64Url(iv),
      c: encodeBase64Url(ciphertext),
    };
    return `TC2-${encodeBase64Url(encoder.encode(JSON.stringify(envelope)))}`;
  } finally {
    plaintext.fill(0);
  }
}

export async function decodeProtectedSetupCode(input, passphrase) {
  try {
    const { envelope, ciphertext } = protectedSetupEnvelope(input);
    const key = await deriveSetupKey(passphrase, decodeBase64Url(envelope.s));
    const plaintext = new Uint8Array(await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: decodeBase64Url(envelope.n), additionalData: SETUP_AAD },
      key,
      ciphertext,
    ));
    try {
      return entryFromSetupData(JSON.parse(new TextDecoder().decode(plaintext)));
    } finally {
      plaintext.fill(0);
    }
  } catch {
    throw new Error("The setup passphrase is incorrect, or the setup code is damaged or unsupported.");
  }
}

export async function setupFingerprint(input) {
  const value = String(input || "").trim();
  if (value.length > 20_000 || (!value.startsWith("TC1-") && !value.startsWith("TC2-"))) {
    throw new Error("That setup code is damaged or unsupported.");
  }
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(value)));
  const hex = Array.from(digest.slice(0, SETUP_FINGERPRINT_HEX_DIGITS / 2), (byte) => byte.toString(16).padStart(2, "0")).join("").toUpperCase();
  return hex.match(/.{4}/g).join("-");
}

export function encodeSetupCode(entry) {
  return `TC1-${encodeBase64Url(encoder.encode(JSON.stringify(serializableEntry(entry))))}`;
}

export function decodeSetupCode(input) {
  const value = input.trim();
  if (!value.startsWith("TC1-")) throw new Error("A TrustCodes setup code begins with TC1-.");
  if (value.length > 20_000) throw new Error("That setup code is too large.");
  try {
    const data = JSON.parse(new TextDecoder().decode(decodeBase64Url(value.slice(4))));
    return entryFromSetupData(data);
  } catch {
    throw new Error("That setup code is damaged, incomplete, or unsupported.");
  }
}
