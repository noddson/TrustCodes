import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const pages = ["index.html", "privacy.html"];
const requiredCsp = [
  "default-src 'self'",
  "base-uri 'none'",
  "object-src 'none'",
  "script-src 'self' https://accounts.google.com",
  "connect-src 'self' https://accounts.google.com https://oauth2.googleapis.com https://www.googleapis.com",
  "form-action 'self'",
  "upgrade-insecure-requests",
];

test("HTML pages enforce CSP and no-referrer before loading resources", () => {
  for (const page of pages) {
    const html = readFileSync(page, "utf8");
    const cspPosition = html.indexOf('http-equiv="Content-Security-Policy"');
    assert.notEqual(cspPosition, -1, `${page} is missing its CSP`);
    assert.ok(cspPosition < html.search(/<(?:link|script|style)\b/i), `${page} must declare CSP before resources`);
    assert.match(html, /<meta name="referrer" content="no-referrer">/);
    for (const directive of requiredCsp) assert.ok(html.includes(directive), `${page} CSP is missing ${directive}`);
  }
});

test("the portable response-header policy includes response-only protections", () => {
  const headers = readFileSync("_headers", "utf8");
  for (const header of [
    "Content-Security-Policy:",
    "frame-ancestors 'none'",
    "Referrer-Policy: no-referrer",
    "X-Content-Type-Options: nosniff",
    "X-Frame-Options: DENY",
    "X-XSS-Protection: 0",
    "Permissions-Policy:",
    "Cross-Origin-Opener-Policy: same-origin-allow-popups",
    "Cross-Origin-Resource-Policy: same-origin",
    "Strict-Transport-Security:",
  ]) assert.ok(headers.includes(header), `_headers is missing ${header}`);
});
