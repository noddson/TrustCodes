import { execSync } from "node:child_process";
import { readFileSync } from "node:fs";

function run(command) {
  return execSync(command, { encoding: "utf8" }).trim();
}

function fail(message) {
  console.error(message);
  process.exit(1);
}

run("VERSION_ASSUME_CLEAN=true npm run generate:version");

const headSha = run("git rev-parse HEAD");
let version;

try {
  version = JSON.parse(readFileSync("./version.json", "utf8"));
} catch {
  fail("version.json was not generated as valid JSON.");
}

if (version.fullSha !== headSha || version.shortSha !== headSha.slice(0, 7)) {
  fail("version.json was not generated for the current commit.");
}

if (version.dirty !== false || !version.displayVersion.endsWith(version.shortSha)) {
  fail("version.json does not contain clean commit version metadata.");
}

console.log("version.json generated correctly for this commit.");
