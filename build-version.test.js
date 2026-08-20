import test from "node:test";
import assert from "node:assert/strict";

import { loadBuildVersion, parseBuildVersion } from "./build-version.js";

const fullSha = "56b4eb5dcabd519c1b009f6238ea7896d43da66d";
const validVersion = {
  displayVersion: "2026.08.56b4eb5",
  fullSha,
  githubCommitUrl: `https://github.com/noddson/TrustCodes/commit/${fullSha}`,
};

test("accepts commit-linked build metadata", () => {
  assert.deepEqual(parseBuildVersion(validVersion), validVersion);
});

test("rejects incomplete, mismatched, or unsafe build metadata", () => {
  assert.equal(parseBuildVersion(null), null);
  assert.equal(parseBuildVersion({ displayVersion: validVersion.displayVersion }), null);
  assert.equal(parseBuildVersion({ ...validVersion, displayVersion: "2026.08.0000000" }), null);
  assert.equal(parseBuildVersion({ ...validVersion, githubCommitUrl: "javascript:alert(1)" }), null);
  assert.equal(parseBuildVersion({ ...validVersion, githubCommitUrl: `https://example.com/commit/${fullSha}` }), null);
  assert.equal(parseBuildVersion({ ...validVersion, githubCommitUrl: `https://github.com/noddson/TrustCodes/commit/${"0".repeat(40)}` }), null);
});

test("loads version metadata without using a cached response", async () => {
  let requestedUrl;
  let requestedOptions;
  const loaded = await loadBuildVersion("https://noddson.github.io/TrustCodes/", async (url, options) => {
    requestedUrl = url.href;
    requestedOptions = options;
    return { ok: true, json: async () => validVersion };
  });

  assert.deepEqual(loaded, validVersion);
  assert.equal(requestedUrl, "https://noddson.github.io/TrustCodes/version.json");
  assert.deepEqual(requestedOptions, { cache: "no-store" });
});
