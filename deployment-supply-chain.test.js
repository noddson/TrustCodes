import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const workflow = readFileSync(".github/workflows/deploy-pages.yml", "utf8");

test("deployment actions use immutable commits and least-privilege checkout", () => {
  const actionReferences = [...workflow.matchAll(/\buses:\s+([^\s@]+)@([^\s#]+)/g)];
  const expectedActions = new Set([
    "actions/checkout",
    "actions/setup-node",
    "actions/configure-pages",
    "actions/upload-pages-artifact",
    "actions/deploy-pages",
  ]);
  assert.equal(actionReferences.length, 6);
  for (const [, action, reference] of actionReferences) {
    assert.ok(expectedActions.has(action), `unexpected workflow dependency: ${action}`);
    assert.match(reference, /^[0-9a-f]{40}$/, `${action} must be pinned to a full commit SHA`);
  }
  assert.equal((workflow.match(/persist-credentials:\s+false/g) || []).length, 2);
  assert.equal((workflow.match(/runs-on:\s+ubuntu-24\.04/g) || []).length, 2);
  assert.match(workflow, /node-version:\s+24\.19\.0/);
});

test("CI installs only the integrity-locked graph without package scripts", () => {
  assert.match(workflow, /npm ci --ignore-scripts/);
  assert.match(workflow, /npm audit --audit-level=high/);

  const manifest = JSON.parse(readFileSync("package.json", "utf8"));
  for (const version of Object.values(manifest.devDependencies || {})) {
    assert.match(version, /^\d+\.\d+\.\d+$/, "manifest dependencies must use exact versions");
  }

  const lock = JSON.parse(readFileSync("package-lock.json", "utf8"));
  for (const [path, dependency] of Object.entries(lock.packages)) {
    if (!path) continue;
    assert.match(dependency.version, /^\d+\.\d+\.\d+$/);
    assert.match(dependency.resolved, /^https:\/\/registry\.npmjs\.org\//);
    assert.match(dependency.integrity, /^sha512-/);
  }
});

test("Dependabot monitors both npm and workflow dependencies", () => {
  const dependabot = readFileSync(".github/dependabot.yml", "utf8");
  assert.match(dependabot, /package-ecosystem:\s+npm/);
  assert.match(dependabot, /package-ecosystem:\s+github-actions/);
  assert.equal((dependabot.match(/interval:\s+weekly/g) || []).length, 2);
});
