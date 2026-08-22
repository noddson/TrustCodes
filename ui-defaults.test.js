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
  assert.match(html, /<summary class="app-footer-summary">[\s\S]*<span id="app-version"/);
  assert.match(html, /<span class="app-footer-chevron" aria-hidden="true">⌄<\/span>/);
  assert.doesNotMatch(html, /View this version on GitHub/);
  assert.match(app, /matchMedia\("\(max-width: 900px\)"\)/);
  assert.match(app, /footer\.open = !compact\.matches/);
  assert.match(app, /link\.textContent = version\.displayVersion/);
  assert.match(app, /link\.addEventListener\("click", \(event\) => event\.stopPropagation\(\)\)/);
  assert.match(app, /versionElement\.replaceChildren\(label, link\)/);
  assert.match(app, /if \(compact\.matches\) footer\.open = !footer\.open/);
});
