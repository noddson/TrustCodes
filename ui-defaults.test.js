import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

test("new mutual channels default to time-based six-word codes", () => {
  const html = readFileSync("index.html", "utf8");
  assert.match(html, /<input type="radio" name="method" value="totp" checked>/);
  assert.match(html, /<option value="words" selected>Memorable words<\/option>/);
  assert.match(html, /<select id="code-length" data-default-length="6"><\/select>/);
});

test("the version footer uses a mobile-responsive disclosure", () => {
  const html = readFileSync("index.html", "utf8");
  const app = readFileSync("app.js", "utf8");
  assert.match(html, /<details id="app-footer-disclosure" class="app-footer-disclosure">/);
  assert.doesNotMatch(html, /class="app-footer-disclosure" open/);
  assert.match(html, /<summary class="app-footer-summary"><span id="app-version"/);
  assert.match(html, /<p id="app-version-source" class="app-version-source" hidden><\/p>/);
  assert.match(app, /matchMedia\("\(max-width: 900px\)"\)/);
  assert.match(app, /footer\.open = !compact\.matches/);
  assert.match(app, /versionElement\.textContent = `Version: \$\{version\.displayVersion\}`/);
  assert.match(app, /sourceElement\.replaceChildren\(link\)/);
});
