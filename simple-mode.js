export const SIMPLE_MODE_STORAGE_KEY = "trust-codes-simple-mode";

export function readSimpleModePreference(storage = globalThis.localStorage) {
  try { return storage?.getItem(SIMPLE_MODE_STORAGE_KEY) === "true"; }
  catch { return false; }
}

export function writeSimpleModePreference(enabled, storage = globalThis.localStorage) {
  try { storage?.setItem(SIMPLE_MODE_STORAGE_KEY, String(Boolean(enabled))); }
  catch { /* The mode still works for this page when browser storage is unavailable. */ }
}

export function initialsForName(name) {
  const parts = String(name || "").trim().split(/\s+/).filter(Boolean);
  if (!parts.length) return "?";
  return `${parts[0][0]}${parts.length > 1 ? parts.at(-1)[0] : ""}`.toUpperCase();
}

export async function photoDataUrl(file, size = 480) {
  if (!file?.type?.startsWith("image/")) throw new Error("Choose an image file.");
  if (file.size > 20 * 1024 * 1024) throw new Error("Choose a photo smaller than 20 MB.");

  let source;
  let releaseSource = () => {};
  if (typeof createImageBitmap === "function") {
    source = await createImageBitmap(file);
    releaseSource = () => source.close();
  } else {
    const url = URL.createObjectURL(file);
    source = new Image();
    source.src = url;
    try { await source.decode(); }
    catch {
      URL.revokeObjectURL(url);
      throw new Error("This browser could not read that photo.");
    }
    releaseSource = () => URL.revokeObjectURL(url);
  }
  try {
    const edge = Math.min(source.width, source.height);
    const sourceX = Math.max(0, (source.width - edge) / 2);
    const sourceY = Math.max(0, (source.height - edge) / 2);
    const outputSize = Math.min(size, edge);
    const canvas = document.createElement("canvas");
    canvas.width = outputSize;
    canvas.height = outputSize;
    const context = canvas.getContext("2d", { alpha: false });
    if (!context) throw new Error("This browser could not prepare the photo.");
    context.drawImage(source, sourceX, sourceY, edge, edge, 0, 0, outputSize, outputSize);
    return canvas.toDataURL("image/jpeg", 0.82);
  } finally {
    releaseSource();
  }
}
