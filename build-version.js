const SHA_PATTERN = /^[0-9a-f]{40}$/i;

export function parseBuildVersion(value) {
  if (!value || typeof value !== "object") return null;

  const { displayVersion, fullSha, githubCommitUrl } = value;
  if (typeof displayVersion !== "string" || !SHA_PATTERN.test(fullSha) || typeof githubCommitUrl !== "string") return null;
  if (!displayVersion.includes(fullSha.slice(0, 7))) return null;

  try {
    const url = new URL(githubCommitUrl);
    const pathParts = url.pathname.split("/").filter(Boolean);
    if (url.protocol !== "https:" || url.hostname !== "github.com") return null;
    if (pathParts.length !== 4 || pathParts[2] !== "commit" || pathParts[3].toLowerCase() !== fullSha.toLowerCase()) return null;
  } catch {
    return null;
  }

  return { displayVersion, fullSha, githubCommitUrl };
}

export async function loadBuildVersion(pageUrl, fetcher = fetch) {
  try {
    const response = await fetcher(new URL("./version.json", pageUrl), { cache: "no-store" });
    if (!response.ok) return null;
    return parseBuildVersion(await response.json());
  } catch {
    return null;
  }
}
