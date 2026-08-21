import test from "node:test";
import assert from "node:assert/strict";

import {
  WORDS,
  consumeProof,
  createChannelPair,
  decodeBase32,
  decodeBase64Url,
  decodeProtectedSetupCode,
  decodeSetupCode,
  encodeBase32,
  encodeBase64Url,
  encodeCrockfordBase32,
  encodeProtectedSetupCode,
  encodeSetupCode,
  formatDigest,
  generateSetupPassphrase,
  generateMutualCode,
  generateProofPhrase,
  hmacForCounter,
  isProtectedSetupCode,
  normalizeCode,
  permutationCount,
  setupFingerprint,
  validateProtectedSetupCode,
  verifyMutualCode,
  verifyProofPhrase,
} from "./otp.js";

const SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

test("the word dictionary has 2,048 unique BIP-39 entries", () => {
  assert.equal(WORDS.length, 2048);
  assert.equal(new Set(WORDS).size, 2048);
  assert.equal(WORDS[0], "abandon");
  assert.equal(WORDS[2047], "zoo");
});

test("11-bit word indexes cover the complete dictionary", () => {
  assert.equal(formatDigest(new Uint8Array(20), "words", 1), "abandon");
  assert.equal(formatDigest(new Uint8Array(20).fill(255), "words", 1), "zoo");
});

test("permutation counts are exact for every display alphabet", () => {
  assert.equal(permutationCount("numeric", 6), 1_000_000n);
  assert.equal(permutationCount("base32", 6), 1_073_741_824n);
  assert.equal(permutationCount("words", 8), 309_485_009_821_345_068_724_781_056n);
});

test("Base32 round-trips the RFC secret", () => {
  const bytes = new TextEncoder().encode("12345678901234567890");
  assert.deepEqual(decodeBase32(encodeBase32(bytes)), bytes);
});

test("Crockford Base32 is used for displayed codes and accepts human aliases", () => {
  const encoded = encodeCrockfordBase32(Uint8Array.from({ length: 32 }, (_, index) => index * 7));
  assert.match(encoded, /^[0-9A-HJKMNP-TV-Z]+$/);
  assert.doesNotMatch(encoded, /[ILOU]/);
  assert.equal(normalizeCode("O-I-l-8-9-U-Z", "base32"), "01189Z");
});

test("empty-context HOTP matches all RFC 4226 vectors", async () => {
  const expected = ["755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489"];
  const entry = { scheme: "mutual", method: "hotp", secret: SECRET, counter: 0, format: "numeric", length: 6, context: "" };
  for (let counter = 0; counter < expected.length; counter += 1) {
    assert.equal(await generateMutualCode(entry, 0, counter), expected[counter]);
  }
});

test("custom formats are deterministic at their configured strength", async () => {
  const digest = await hmacForCounter(SECRET, 3);
  assert.match(formatDigest(digest, "base32", 16), /^[0-9A-HJKMNP-TV-Z]{16}$/);
  assert.match(formatDigest(digest, "numeric", 16), /^\d{16}$/);
  assert.equal(formatDigest(digest, "words", 8).split(" ").length, 8);
});

test("optional context personalizes mutual codes", async () => {
  const base = { scheme: "mutual", method: "hotp", secret: SECRET, counter: 2, format: "numeric", length: 8 };
  const noContext = await generateMutualCode({ ...base, context: "" });
  const family = await generateMutualCode({ ...base, context: "Family phone calls" });
  assert.notEqual(family, noContext);
  assert.equal(family, await generateMutualCode({ ...base, context: "  Family phone calls  " }));
});

test("TOTP verifier accepts the adjacent time window", async () => {
  const entry = { scheme: "mutual", method: "totp", secret: SECRET, period: 30, format: "numeric", length: 6, context: "" };
  assert.equal((await verifyMutualCode("287082", entry, 59_000)).valid, true);
  assert.equal((await verifyMutualCode("755224", entry, 30_000)).valid, true);
  assert.equal((await verifyMutualCode("123456", entry, 59_000)).valid, false);
});

test("setup codes omit context while manually matching contexts still interoperate", async () => {
  const { local, peer } = await createChannelPair({ name: "Spouses", context: "calls", scheme: "mutual", method: "totp", format: "words", length: 5 });
  const encoded = encodeSetupCode(peer);
  const payload = JSON.parse(new TextDecoder().decode(decodeBase64Url(encoded.slice(4))));
  const imported = decodeSetupCode(encoded);
  assert.equal(payload.v, 6);
  assert.equal(payload.x, undefined);
  assert.equal(payload.h, undefined);
  assert.equal(payload.w, 1);
  assert.equal(decodeBase64Url(payload.s).length, 16);
  assert.equal(imported.scheme, "mutual");
  assert.equal(imported.context, undefined);
  assert.equal(local.context, undefined);
  assert.equal(imported.format, "words");
  assert.equal(imported.length, 5);
  assert.equal(imported.secret, peer.secret);
  const time = 1_900_000_000_000;
  assert.equal(
    await generateMutualCode(local, time, undefined, "calls"),
    await generateMutualCode(imported, time, undefined, "calls"),
  );
  assert.notEqual(
    await generateMutualCode(local, time, undefined, "calls"),
    await generateMutualCode(imported, time, undefined, ""),
  );
  assert.notEqual(
    await generateMutualCode(local, time, undefined, ""),
    await generateMutualCode(imported, time, undefined, ""),
    "two devices omitting a configured context must not agree by accident",
  );
});

test("authenticated setup codes require the generated passphrase and expose a comparable fingerprint", async () => {
  const { peer } = await createChannelPair({ name: "Authenticated setup", context: "", scheme: "mutual", method: "totp", format: "numeric", length: 8 });
  const passphrase = generateSetupPassphrase();
  const words = passphrase.split(" ");
  assert.equal(words.length, 8);
  assert.equal(words.every((word) => WORDS.includes(word)), true);

  const code = await encodeProtectedSetupCode(peer, passphrase);
  assert.equal(isProtectedSetupCode(code), true);
  assert.equal(validateProtectedSetupCode(code), true);
  const envelopeText = new TextDecoder().decode(decodeBase64Url(code.slice(4)));
  assert.equal(envelopeText.includes(peer.secret), false);
  assert.equal(envelopeText.includes(peer.name), false);

  const imported = await decodeProtectedSetupCode(code, passphrase);
  assert.equal(imported.scheme, peer.scheme);
  assert.equal(imported.secret, peer.secret);
  assert.equal(imported.format, peer.format);
  await assert.rejects(decodeProtectedSetupCode(code, "abandon abandon abandon abandon abandon abandon abandon abandon"), /incorrect|damaged/i);

  const envelope = JSON.parse(envelopeText);
  const ciphertext = decodeBase64Url(envelope.c);
  ciphertext[0] ^= 1;
  envelope.c = encodeBase64Url(ciphertext);
  const tampered = `TC2-${encodeBase64Url(new TextEncoder().encode(JSON.stringify(envelope)))}`;
  assert.equal(validateProtectedSetupCode(tampered), true, "structural validation alone cannot authenticate ciphertext");
  await assert.rejects(decodeProtectedSetupCode(tampered, passphrase), /incorrect|damaged/i);

  const fingerprint = await setupFingerprint(code);
  assert.match(fingerprint, /^[0-9A-F]{4}(?:-[0-9A-F]{4}){2}$/);
  assert.notEqual(await setupFingerprint(tampered), fingerprint);
});

test("blank setup context preserves normal mutual behavior", async () => {
  const { local, peer } = await createChannelPair({ name: "No context", context: "", scheme: "mutual", method: "hotp", format: "numeric", length: 6 });
  assert.equal(await generateMutualCode(local), await generateMutualCode(peer));
});

test("legacy setup codes discard embedded context and require live re-entry", async () => {
  const payload = { v: 3, q: "mutual", n: "Legacy", x: "old embedded context", m: "hotp", k: SECRET, p: 30, c: 0, f: "numeric", l: 6, d: 1 };
  const code = `TC1-${encodeBase64Url(new TextEncoder().encode(JSON.stringify(payload)))}`;
  const imported = decodeSetupCode(code);
  assert.equal(imported.context, undefined);
  assert.equal(imported.contextProtection, undefined);
  assert.equal(await generateMutualCode(imported, 0, 0, "old embedded context"), await generateMutualCode({ ...imported, context: "old embedded context" }, 0, 0));
});

test("one-way setup sends an anchor to the verifier, not the seed", async () => {
  const { local, peer } = await createChannelPair({ name: "Dad", context: "", scheme: "proof", role: "prove", total: 3 });
  assert.ok(local.seed);
  assert.equal(local.anchor, undefined);
  assert.ok(peer.anchor);
  assert.equal(peer.seed, undefined);

  const importedVerifier = decodeSetupCode(encodeSetupCode(peer));
  assert.equal(importedVerifier.role, "verify");
  assert.ok(importedVerifier.anchor);
  assert.equal(importedVerifier.seed, undefined);
});

test("one-way phrases verify once and advance in lockstep", async () => {
  const { local: prover, peer: verifierSetup } = await createChannelPair({ name: "Dad", context: "family calls", scheme: "proof", role: "prove", total: 3, length: 5 });
  const verifier = decodeSetupCode(encodeSetupCode(verifierSetup));
  assert.equal(prover.context, undefined);
  assert.equal(verifier.context, undefined);
  const first = await generateProofPhrase(prover, "family calls");
  assert.equal(first.split(" ").length, 5);
  assert.equal((await verifyProofPhrase(first, verifier, "family calls")).valid, true);
  assert.equal((await verifyProofPhrase(first, verifier, "family calls")).valid, false, "a consumed phrase cannot be replayed");

  consumeProof(prover);
  const second = await generateProofPhrase(prover, "family calls");
  assert.notEqual(second, first);
  assert.equal((await verifyProofPhrase(second, verifier, "family calls")).valid, true);
  consumeProof(prover);
  assert.equal(prover.remaining, verifier.remaining);
});

test("all one-way proof strengths from 5 through 10 words round-trip and verify", async (t) => {
  for (const length of [5, 6, 7, 8, 9, 10]) {
    await t.test(`${length} words`, async () => {
      const { local: prover, peer } = await createChannelPair({ name: "Range", context: "strength", scheme: "proof", role: "prove", total: 2, length });
      const verifier = decodeSetupCode(encodeSetupCode(peer));
      const phrase = await generateProofPhrase(prover, "strength");
      assert.equal(phrase.split(" ").length, length);
      assert.equal(verifier.length, length);
      assert.equal((await verifyProofPhrase(phrase, verifier, "strength")).valid, true);
    });
  }
});

test("four-word one-way proofs can no longer be created", async () => {
  await assert.rejects(
    createChannelPair({ name: "Too weak", context: "", scheme: "proof", role: "prove", total: 2, length: 4 }),
    /between 5 and 10 words/i,
  );

  const legacyFourWordSetup = {
    v: 5,
    q: "proof",
    n: "Legacy weak proof",
    r: "verify",
    z: encodeBase64Url(new Uint8Array(6)),
    e: 2,
    t: 2,
    l: 4,
    d: 1,
  };
  const code = `TC1-${encodeBase64Url(new TextEncoder().encode(JSON.stringify(legacyFourWordSetup)))}`;
  assert.throws(() => decodeSetupCode(code), /damaged|unsupported/i);
});

test("a different proof context fails verification", async () => {
  const { local: prover, peer: verifier } = await createChannelPair({ name: "Dad", context: "correct", scheme: "proof", role: "prove", total: 2 });
  const phrase = await generateProofPhrase(prover, "correct");
  assert.equal((await verifyProofPhrase(phrase, verifier, "wrong")).valid, false);
  assert.equal(verifier.remaining, 2);
});

test("two devices using the same wrong proof context still cannot agree", async () => {
  const { local: prover, peer: verifier } = await createChannelPair({ name: "Dad", context: "correct", scheme: "proof", role: "prove", total: 2 });
  const wrongPhrase = await generateProofPhrase(prover, "wrong");
  assert.equal((await verifyProofPhrase(wrongPhrase, verifier, "wrong")).valid, false);
  assert.equal(verifier.remaining, 2);
});

test("a verifier entry cannot generate proof phrases", async () => {
  const { peer: verifier } = await createChannelPair({ name: "Dad", scheme: "proof", role: "prove", total: 2 });
  await assert.rejects(generateProofPhrase(verifier), /cannot generate/i);
});
