import { encodeCrockfordBase32 } from "./otp.js";

export const VAULT_PASSWORD_MIN_LENGTH = 8;
export const VAULT_PASSWORD_MAX_LENGTH = 128;
export const GENERATED_RECOVERY_CODE_BYTES = 20;

const COMMON_VALUES = new Set([
  "123456", "12345678", "123456789", "1234567890", "111111", "000000",
  "abc123", "qwerty", "qwerty123", "password", "password1", "password123",
  "letmein", "welcome", "welcome1", "admin", "administrator", "changeme",
  "iloveyou", "monkey", "dragon", "football", "baseball", "circlesignal",
  "circlesignal1", "circlesignal123", "recovery", "recoverypassword",
  "weakrecoverypassword", "correcthorsebatterystaple", "princess", "sunshine",
  "master", "shadow", "superman", "michael", "jennifer", "charlie", "donald",
  "freedom", "whatever", "secret", "login", "starwars", "computer", "internet",
  "default", "access", "private", "secure", "security", "trustno1", "passw0rd",
  "pssword", "pssw0rd", "qazwsx", "1q2w3e4r", "1qaz2wsx", "zaq12wsx",
]);

const GENERATED_CODE_PATTERN = /^CSVR-(?:[0-9A-HJKMNP-TV-Z]{4}-){7}[0-9A-HJKMNP-TV-Z]{4}$/;

function characterLength(value) { return [...value].length; }

function compactForComparison(value) {
  return value.normalize("NFKC").toLocaleLowerCase("en-US").replaceAll("@", "a").replaceAll("$", "s").replaceAll("!", "i").replace(/[^a-z0-9]/g, "");
}

function normalizeLeetspeak(value) {
  return value.replaceAll("0", "o").replaceAll("1", "i").replaceAll("3", "e").replaceAll("4", "a").replaceAll("5", "s").replaceAll("7", "t").replaceAll("8", "b");
}

function hasRepeatedWordPattern(value, compact) {
  const words = value.normalize("NFKC").toLocaleLowerCase("en-US").match(/[\p{L}\p{N}]+/gu) || [];
  if (words.length >= 3) {
    for (let patternLength = 1; patternLength <= Math.floor(words.length / 3); patternLength += 1) {
      if (words.every((word, index) => word === words[index % patternLength])) return true;
    }
    const counts = new Map();
    for (const word of words) counts.set(word, (counts.get(word) || 0) + 1);
    if (words.some((word) => word.length >= 3 && counts.get(word) >= 3)) return true;
  }
  return /^(.{1,32})\1{2,}$/.test(compact);
}

function predictablePasswordProblem(value) {
  const compact = compactForComparison(value);
  const leetspeak = normalizeLeetspeak(compact);
  if (COMMON_VALUES.has(compact) || COMMON_VALUES.has(leetspeak)) return "Choose a less common recovery password. This value is easy to guess.";
  if (/^(password|passphrase|circlesignal?|welcome|letmein|changeme|admin(?:istrator)?|recovery(?:password)?|summer|winter|spring|autumn|fall)(?:20\d{2}|\d{0,6})*$/.test(compact)
    || /^(password|passphrase|circlesignal?|welcome|letmein|changeme|admin(?:istrator)?|recovery(?:password)?)[a-z0-9]{0,12}$/.test(leetspeak)) {
    return "Choose a less predictable recovery password. Names, common words, and number suffixes are easy to guess.";
  }
  if (/^(.)\1{7,}$/u.test(value) || /^(.{1,4})\1{3,}$/u.test(value) || hasRepeatedWordPattern(value, compact)) {
    return "Choose a recovery password without repeated characters, words, or phrases.";
  }
  if (["0123456789", "9876543210", "abcdefghijklmnopqrstuvwxyz", "zyxwvutsrqponmlkjihgfedcba", "qwertyuiop", "asdfghjkl", "zxcvbnm"].some((sequence) => compact.includes(sequence))) {
    return "Choose a recovery password without keyboard or sequential patterns.";
  }
  return "";
}

export function isGeneratedVaultRecoveryCode(value) {
  return GENERATED_CODE_PATTERN.test(String(value || "").trim().toUpperCase());
}

export function generateVaultRecoveryCode(randomBytes = null) {
  const bytes = randomBytes ? new Uint8Array(randomBytes) : crypto.getRandomValues(new Uint8Array(GENERATED_RECOVERY_CODE_BYTES));
  if (bytes.byteLength !== GENERATED_RECOVERY_CODE_BYTES) throw new Error(`Recovery-code generation requires ${GENERATED_RECOVERY_CODE_BYTES} random bytes.`);
  const encoded = encodeCrockfordBase32(bytes);
  return `CSVR-${encoded.match(/.{4}/g).join("-")}`;
}

export function assessVaultPassword(password) {
  const value = String(password || "").normalize("NFC");
  if (isGeneratedVaultRecoveryCode(value)) {
    return { acceptable: true, label: "Excellent", level: 4, problem: "", warning: "", message: "Excellent — device-generated 160-bit recovery code." };
  }
  const length = characterLength(value);
  if (length < VAULT_PASSWORD_MIN_LENGTH) {
    const problem = `Use at least ${VAULT_PASSWORD_MIN_LENGTH} characters.`;
    return { acceptable: false, label: "Too short", level: 1, problem, warning: "", message: `Too short — ${problem}` };
  }
  if (length > VAULT_PASSWORD_MAX_LENGTH) {
    const problem = `Use no more than ${VAULT_PASSWORD_MAX_LENGTH} characters.`;
    return { acceptable: false, label: "Too long", level: 1, problem, warning: "", message: `Too long — ${problem}` };
  }
  const predictableProblem = predictablePasswordProblem(value);
  if (predictableProblem) {
    const warning = `${predictableProblem} It is allowed, but substantially easier to compromise.`;
    return { acceptable: true, label: "Weak", level: 1, problem: "", warning, message: `Weak — ${warning}` };
  }
  if (length < 12) {
    const warning = "This is allowed, but a longer recovery password is much safer. Good, Strong, or Excellent is recommended.";
    return { acceptable: true, label: "Weak", level: 1, problem: "", warning, message: `Weak — ${warning}` };
  }
  if (length < 20) {
    const warning = "Good is accepted, but a Strong or Excellent recovery password is recommended.";
    return { acceptable: true, label: "Good", level: 2, problem: "", warning, message: `Good — ${warning}` };
  }
  if (length < 28) return { acceptable: true, label: "Strong", level: 3, problem: "", warning: "", message: "Strong — long and not found in the local predictable-password checks." };
  return { acceptable: true, label: "Excellent", level: 4, problem: "", warning: "", message: "Excellent — very long and not found in the local predictable-password checks." };
}
