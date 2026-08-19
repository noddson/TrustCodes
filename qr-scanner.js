const MAX_FRAME_WIDTH = 720;
const SCAN_INTERVAL_MS = 120;

let decoderPromise;

export function normalizeScannedSetupCode(value) {
  const text = String(value || "").trim();
  if (!text.startsWith("TC1-") || text.length > 20_000) return "";
  return text;
}

export function cameraErrorMessage(error, secureContext = globalThis.isSecureContext) {
  if (!secureContext) return "Camera scanning requires HTTPS or localhost.";
  if (error?.name === "NotAllowedError" || error?.name === "SecurityError") return "Camera access was not allowed. You can still paste the setup code.";
  if (error?.name === "NotFoundError" || error?.name === "OverconstrainedError") return "No compatible camera was found on this device.";
  if (error?.name === "NotReadableError" || error?.name === "AbortError") return "The camera is unavailable or already in use by another app.";
  return "The camera scanner could not start. You can still paste the setup code.";
}

async function localDecoder() {
  if (typeof globalThis.jsQR === "function") return globalThis.jsQR;
  decoderPromise ||= import("./vendor/jsQR.js").then(() => {
    if (typeof globalThis.jsQR !== "function") throw new Error("Local QR decoder unavailable.");
    return globalThis.jsQR;
  });
  return decoderPromise;
}

async function nativeDetector() {
  if (typeof globalThis.BarcodeDetector !== "function") return null;
  try {
    const supported = typeof globalThis.BarcodeDetector.getSupportedFormats === "function"
      ? await globalThis.BarcodeDetector.getSupportedFormats()
      : ["qr_code"];
    return supported.includes("qr_code") ? new globalThis.BarcodeDetector({ formats: ["qr_code"] }) : null;
  } catch {
    return null;
  }
}

export class QrCameraScanner {
  constructor({ video, canvas, onDetected, onStatus }) {
    this.video = video;
    this.canvas = canvas;
    this.onDetected = onDetected;
    this.onStatus = onStatus;
    this.stream = null;
    this.detector = null;
    this.decoder = null;
    this.frameRequest = 0;
    this.lastScan = 0;
    this.active = false;
  }

  async start() {
    if (this.active) return;
    if (!globalThis.isSecureContext || !navigator.mediaDevices?.getUserMedia) {
      throw new Error("Camera scanning requires HTTPS or localhost.");
    }
    this.onStatus("Requesting camera permission…");
    this.stream = await navigator.mediaDevices.getUserMedia({
      video: { facingMode: { ideal: "environment" }, width: { ideal: 1280 }, height: { ideal: 720 } },
      audio: false,
    });
    try {
      this.video.srcObject = this.stream;
      this.video.muted = true;
      await this.video.play();
      this.detector = await nativeDetector();
      if (!this.detector) this.decoder = await localDecoder();
      this.active = true;
      this.onStatus("Camera on · point it at a Trust Codes QR code");
      this.frameRequest = requestAnimationFrame((time) => this.scan(time));
    } catch (error) {
      this.stop();
      throw error;
    }
  }

  stop() {
    this.active = false;
    if (this.frameRequest) cancelAnimationFrame(this.frameRequest);
    this.frameRequest = 0;
    this.stream?.getTracks().forEach((track) => track.stop());
    this.stream = null;
    this.video.pause();
    this.video.srcObject = null;
  }

  async scan(time) {
    if (!this.active) return;
    if (time - this.lastScan < SCAN_INTERVAL_MS || !this.video.videoWidth) {
      this.frameRequest = requestAnimationFrame((next) => this.scan(next));
      return;
    }
    this.lastScan = time;
    try {
      let value = "";
      if (this.detector) {
        const results = await this.detector.detect(this.video);
        value = results[0]?.rawValue || "";
      } else {
        const scale = Math.min(1, MAX_FRAME_WIDTH / this.video.videoWidth);
        const width = Math.max(1, Math.round(this.video.videoWidth * scale));
        const height = Math.max(1, Math.round(this.video.videoHeight * scale));
        this.canvas.width = width;
        this.canvas.height = height;
        const context = this.canvas.getContext("2d", { willReadFrequently: true });
        context.drawImage(this.video, 0, 0, width, height);
        const image = context.getImageData(0, 0, width, height);
        value = this.decoder(image.data, width, height, { inversionAttempts: "attemptBoth" })?.data || "";
      }
      if (value && await this.onDetected(value)) return;
    } catch {
      this.onStatus("Still looking… hold the QR code steady and improve the lighting.");
    }
    if (this.active) this.frameRequest = requestAnimationFrame((next) => this.scan(next));
  }
}
