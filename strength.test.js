import assert from "node:assert/strict";
import test from "node:test";

import { entropyBits, entropyClassification, strengthOptionLabel } from "./strength.js";

test("entropy anchors use the shared classification table", () => {
  const levels = [
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
  for (const [bits, classification] of levels) assert.equal(entropyClassification(bits), classification);
});

test("values between anchors use the greatest threshold they meet", () => {
  assert.equal(entropyClassification(109), "Fantastic");
  assert.equal(entropyClassification(65), "Good");
  assert.equal(entropyClassification(43), "Mediocre");
  assert.equal(entropyClassification(25), "Weak");
  assert.equal(entropyClassification(12), "Very Weak");
});

test("mutual and one-way word options receive identical classifications", () => {
  const expected = new Map([
    [4, "4 words · OK"],
    [5, "5 words · Good"],
    [6, "6 words · Strong"],
    [7, "7 words · Great"],
    [8, "8 words · Excellent"],
    [9, "9 words · Fantastic"],
    [10, "10 words · Legendary"],
  ]);
  for (const [words, label] of expected) {
    assert.equal(entropyBits("words", words), words * 11);
    assert.equal(strengthOptionLabel("words", words), label);
  }
});

test("numeric and Base32 options use the same threshold scale", () => {
  assert.equal(strengthOptionLabel("numeric", 4), "4 characters · Very Weak");
  assert.equal(strengthOptionLabel("numeric", 8), "8 characters · Poor");
  assert.equal(strengthOptionLabel("base32", 8), "8 characters · Mediocre");
  assert.equal(strengthOptionLabel("base32", 12), "12 characters · Good");
});
