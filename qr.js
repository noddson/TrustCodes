import qrcode from "./vendor/qrcode.mjs";

const QUIET_ZONE_MODULES = 4;
const MAX_QR_TEXT_LENGTH = 20_000;

export function createQrMatrix(text, errorCorrection = "M") {
  if (typeof text !== "string" || !text || text.length > MAX_QR_TEXT_LENGTH) {
    throw new Error("The setup code cannot be represented as a QR code.");
  }
  const qr = qrcode(0, errorCorrection);
  qr.addData(text, "Byte");
  qr.make();
  const size = qr.getModuleCount();
  const modules = Array.from({ length: size }, (_, row) =>
    Array.from({ length: size }, (_, column) => qr.isDark(row, column)),
  );
  return { size, modules };
}

export function renderQrPixels(matrix, preferredSize = 320) {
  const fullModules = matrix.size + QUIET_ZONE_MODULES * 2;
  const scale = Math.max(1, Math.floor(preferredSize / fullModules));
  const size = fullModules * scale;
  const data = new Uint8ClampedArray(size * size * 4);
  data.fill(255);

  for (let row = 0; row < matrix.size; row += 1) {
    for (let column = 0; column < matrix.size; column += 1) {
      if (!matrix.modules[row][column]) continue;
      const startX = (column + QUIET_ZONE_MODULES) * scale;
      const startY = (row + QUIET_ZONE_MODULES) * scale;
      for (let y = startY; y < startY + scale; y += 1) {
        for (let x = startX; x < startX + scale; x += 1) {
          const offset = (y * size + x) * 4;
          data[offset] = 0;
          data[offset + 1] = 0;
          data[offset + 2] = 0;
        }
      }
    }
  }
  return { data, width: size, height: size };
}

export function drawQrCode(text, canvas, preferredSize = 320) {
  const pixels = renderQrPixels(createQrMatrix(text), preferredSize);
  canvas.width = pixels.width;
  canvas.height = pixels.height;
  const context = canvas.getContext("2d", { alpha: false });
  context.imageSmoothingEnabled = false;
  context.putImageData(new ImageData(pixels.data, pixels.width, pixels.height), 0, 0);
  return pixels.width;
}
