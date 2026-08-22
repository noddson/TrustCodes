import { execSync } from "node:child_process";
import { writeFileSync } from "node:fs";

function run(command) {
  return execSync(command, { encoding: "utf8" }).trim();
}

function tryRun(command) {
  try {
    return run(command);
  } catch {
    return "";
  }
}

function isDirty() {
  if ((process.env.VERSION_ASSUME_CLEAN || "").toLowerCase() === "true") return false;

  try {
    execSync("git diff --quiet --ignore-submodules HEAD --", { stdio: "ignore" });
    return false;
  } catch {
    return true;
  }
}

function generateVersionMetadata() {
  const now = new Date();
  const year = now.getUTCFullYear();
  const month = String(now.getUTCMonth() + 1).padStart(2, "0");
  const envSha = (process.env.GITHUB_SHA || process.env.COMMIT_SHA || "").trim();
  const fullSha = envSha || run("git rev-parse HEAD");
  const shortSha = fullSha.slice(0, 7);
  const remoteUrl = tryRun("git config --get remote.origin.url");
  const defaultOwner = "noddson";
  const defaultRepo = "CircleSignal";
  const [, owner = defaultOwner, repo = defaultRepo] = remoteUrl.match(/github\.com[:/]([^/]+)\/(.+?)(?:\.git)?$/) || [];
  const dirty = isDirty();
  const displayVersion = `${year}.${month}.${shortSha}${dirty ? ".d" : ""}`;

  return {
    displayVersion,
    fullSha,
    shortSha,
    dirty,
    githubCommitUrl: `https://github.com/${owner}/${repo}/commit/${fullSha}`,
  };
}

const metadata = generateVersionMetadata();
writeFileSync("./version.json", `${JSON.stringify(metadata, null, 2)}\n`, "utf8");
console.log(`Generated version.json: ${metadata.displayVersion}`);
