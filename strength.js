const ENTROPY_LEVELS = [
  [110, "Legendary"],
  [99, "Fantastic"],
  [88, "Excellent"],
  [77, "Great"],
  [66, "Strong"],
  [55, "Good"],
  [44, "OK"],
  [33, "Mediocre"],
  [26, "Poor"],
  [19, "Weak"],
  [13, "Very Weak"],
];

export function entropyBits(format, length) {
  if (!Number.isSafeInteger(length) || length < 1) throw new Error("Unsupported strength length.");
  if (format === "numeric") return Math.floor(length * Math.log2(10));
  if (format === "base32") return length * 5;
  if (format === "words") return length * 11;
  throw new Error("Unsupported strength format.");
}

export function entropyClassification(bits) {
  if (!Number.isSafeInteger(bits) || bits < 0) throw new Error("Unsupported entropy strength.");
  return ENTROPY_LEVELS.find(([minimum]) => bits >= minimum)?.[1] || "Very Weak";
}

export function entropyTone(bits) {
  if (!Number.isSafeInteger(bits) || bits < 0) throw new Error("Unsupported entropy strength.");
  return entropyClassification(bits).toLowerCase().replace(" ", "-");
}

export function strengthOptionLabel(format, length) {
  const unit = format === "words" ? "words" : "characters";
  return `${length} ${unit} · ${entropyBits(format, length)} bits`;
}
