import {
  DEMO_SECRET,
  generateTOTP,
  parseInput,
  remainingSeconds,
} from "./totp.js";
import {
  buildShareUrl,
  parseHash,
  shareMessage,
  whatsappShareUrl,
} from "./share.js";

const els = {
  input: document.getElementById("secret-input"),
  accountName: document.getElementById("account-name"),
  error: document.getElementById("secret-error"),
  loadError: document.getElementById("load-error"),
  clear: document.getElementById("btn-clear"),
  demo: document.getElementById("btn-demo"),
  scan: document.getElementById("btn-scan"),
  upload: document.getElementById("btn-upload"),
  file: document.getElementById("qr-file"),
  code: document.getElementById("totp-code"),
  copy: document.getElementById("btn-copy"),
  copyLabel: document.getElementById("copy-label"),
  share: document.getElementById("btn-share"),
  sharePanel: document.getElementById("share-panel"),
  shareLink: document.getElementById("share-link"),
  copyLink: document.getElementById("btn-copy-link"),
  copyLinkLabel: document.getElementById("copy-link-label"),
  whatsapp: document.getElementById("btn-whatsapp"),
  meta: document.getElementById("code-meta"),
  issuer: document.getElementById("code-issuer"),
  seconds: document.getElementById("countdown-seconds"),
  ring: document.getElementById("ring-progress"),
  bar: document.getElementById("countdown-bar"),
  status: document.getElementById("live-status"),
  theme: document.getElementById("btn-theme"),
  modal: document.getElementById("camera-modal"),
  video: document.getElementById("camera-video"),
  cameraClose: document.getElementById("btn-camera-close"),
  cameraStatus: document.getElementById("camera-status"),
  titleEditor: document.getElementById("titulo-principal"),
  titleBuyer: document.getElementById("titulo-buyer"),
  buyerInstruction: document.getElementById("buyer-instruction"),
  buyerEditWrap: document.getElementById("buyer-edit-wrap"),
};

const RING_RADIUS = 26;
const RING_CIRCUMFERENCE = 2 * Math.PI * RING_RADIUS;

const MESSAGES = {
  "invalid-base32":
    "La clave no está en formato Base32. Quita espacios si hace falta y revisa que solo tenga letras A–Z y números 2–7.",
  "invalid-uri": "Ese enlace otpauth no se pudo leer. Revisa que esté completo.",
  "not-totp":
    "Este enlace no es de tipo TOTP. Esta herramienta solo genera códigos basados en el tiempo.",
  "missing-secret": "El enlace no trae una clave secreta.",
  "unsupported-algorithm":
    "Ese algoritmo no está soportado. Se aceptan SHA-1, SHA-256 y SHA-512.",
  "invalid-digits": "El enlace pide una cantidad de dígitos que no se puede usar (tiene que ser 6, 7 u 8).",
  "invalid-period": "El periodo del enlace no es válido.",
  empty: "Ingresa una clave secreta o un enlace otpauth:// para ver el código.",
  "invalid-link": "Este enlace no es válido o está incompleto.",
};

let config = null;
let lastCode = "";
let tickTimer = 0;
let copyTimer = 0;
let copyLinkTimer = 0;
let cameraStream = null;
let cameraLoop = 0;
let scanBusy = false;
let buyerMode = false;

function setTheme(theme) {
  const next = theme === "light" || theme === "dark" ? theme : null;
  if (next) {
    document.documentElement.setAttribute("data-theme", next);
    try {
      localStorage.setItem("codigo-2fa-theme", next);
    } catch {
      /* ignore quota / private mode */
    }
  } else {
    document.documentElement.removeAttribute("data-theme");
  }
  syncThemeButton();
}

function preferredTheme() {
  try {
    const saved = localStorage.getItem("codigo-2fa-theme");
    if (saved === "light" || saved === "dark") return saved;
  } catch {
    /* ignore */
  }
  return window.matchMedia("(prefers-color-scheme: dark)").matches
    ? "dark"
    : "light";
}

function syncThemeButton() {
  const current =
    document.documentElement.getAttribute("data-theme") || preferredTheme();
  const dark = current === "dark";
  els.theme.setAttribute("aria-pressed", dark ? "true" : "false");
  els.theme.setAttribute(
    "aria-label",
    dark ? "Cambiar a apariencia clara" : "Cambiar a apariencia oscura"
  );
  els.theme.title = dark ? "Apariencia clara" : "Apariencia oscura";
}

function announce(text) {
  els.status.textContent = text;
}

function showError(code) {
  const text = MESSAGES[code] || (buyerMode ? MESSAGES["invalid-link"] : "No se pudo leer esa clave.");
  const target = buyerMode ? els.loadError : els.error;
  const other = buyerMode ? els.error : els.loadError;
  target.textContent = text;
  target.hidden = false;
  other.textContent = "";
  other.hidden = true;
  if (!buyerMode) els.input.setAttribute("aria-invalid", "true");
}

function clearError() {
  els.error.textContent = "";
  els.error.hidden = true;
  els.loadError.textContent = "";
  els.loadError.hidden = true;
  els.input.removeAttribute("aria-invalid");
}

function formatCode(code) {
  if (code.length === 8) return `${code.slice(0, 4)} ${code.slice(4)}`;
  if (code.length === 7) return `${code.slice(0, 3)} ${code.slice(3)}`;
  if (code.length === 6) return `${code.slice(0, 3)} ${code.slice(3)}`;
  return code;
}

function formatMeta(cfg) {
  const parts = [];
  if (cfg.algorithm && cfg.algorithm !== "SHA-1") parts.push(cfg.algorithm);
  if (cfg.digits && cfg.digits !== 6) parts.push(`${cfg.digits} dígitos`);
  if (cfg.period && cfg.period !== 30) parts.push(`cada ${cfg.period} s`);
  return parts.join(" · ");
}

function displayLabel(cfg) {
  if (!cfg) return "";
  const name = (cfg.account || "").trim();
  const issuer = (cfg.issuer || "").trim();
  if (name && issuer && name !== issuer) return `${issuer} · ${name}`;
  return name || issuer;
}

function currentName() {
  return (els.accountName.value || "").trim();
}

function defaultCopyLabel() {
  return buyerMode ? "Copiar código" : "Copiar";
}

function setIdleCode() {
  lastCode = "";
  els.code.textContent = "••••••";
  els.code.classList.add("is-idle");
  els.copy.disabled = true;
  els.share.disabled = true;
  els.issuer.textContent = "";
  els.meta.textContent = "";
  els.seconds.textContent = "30";
  els.ring.style.strokeDashoffset = String(RING_CIRCUMFERENCE);
  els.bar.style.transform = "scaleX(0)";
  document.querySelector(".code-panel").classList.remove("is-urgent");
  els.copyLabel.textContent = defaultCopyLabel();
  els.copy.classList.remove("is-copied");
  if (!buyerMode) hideSharePanel();
}

function shareBase() {
  return `${location.origin}${location.pathname}`;
}

function currentShareUrl() {
  if (!config) return "";
  return buildShareUrl(config, shareBase());
}

function updateSharePanel() {
  if (!config) {
    hideSharePanel();
    return;
  }
  const url = currentShareUrl();
  els.shareLink.value = url;
  els.whatsapp.href = whatsappShareUrl(url, displayLabel(config) || currentName());
  els.whatsapp.hidden = false;
}

function hideSharePanel() {
  els.sharePanel.hidden = true;
  els.shareLink.value = "";
  els.whatsapp.href = "https://wa.me/";
  els.copyLinkLabel.textContent = "Copiar enlace";
  els.copyLink.classList.remove("is-copied");
}

function showSharePanel() {
  if (!config) return;
  updateSharePanel();
  els.sharePanel.hidden = false;
}

function updateBuyerInstruction() {
  const period = config && config.period ? config.period : 30;
  els.buyerInstruction.textContent =
    period === 30
      ? "Copia este código y pégalo donde te lo pidan. Cambia cada 30 segundos."
      : `Copia este código y pégalo donde te lo pidan. Cambia cada ${period} segundos.`;
}

function setBuyerMode(on, label = "") {
  buyerMode = Boolean(on);
  document.body.classList.toggle("is-buyer", buyerMode);
  els.titleEditor.hidden = buyerMode;
  els.titleBuyer.hidden = !buyerMode;
  els.buyerInstruction.hidden = !buyerMode;
  els.buyerEditWrap.hidden = !buyerMode;
  if (buyerMode) {
    els.titleBuyer.textContent = label || "Tu código de verificación";
    updateBuyerInstruction();
    hideSharePanel();
    els.copyLabel.textContent = defaultCopyLabel();
  } else {
    els.titleBuyer.textContent = "Tu código de verificación";
    els.copyLabel.textContent = defaultCopyLabel();
  }
}

async function applyConfig(next, { announceReady = false } = {}) {
  config = next;
  if (!config) {
    clearError();
    setIdleCode();
    return;
  }
  try {
    const code = await generateTOTP(config.secret, {
      algorithm: config.algorithm,
      digits: config.digits,
      period: config.period,
    });
    clearError();
    lastCode = code;
    els.code.textContent = formatCode(code);
    els.code.classList.remove("is-idle");
    els.copy.disabled = false;
    els.share.disabled = buyerMode;
    const label = displayLabel(config);
    els.issuer.textContent = label;
    els.meta.textContent = formatMeta(config);
    if (buyerMode) {
      els.titleBuyer.textContent = label || "Tu código de verificación";
      updateBuyerInstruction();
    }
    updateCountdown();
    if (!els.sharePanel.hidden) updateSharePanel();
    if (announceReady) {
      announce(
        label
          ? `Código generado para ${label}.`
          : "Código de verificación generado."
      );
    }
  } catch (err) {
    config = null;
    setIdleCode();
    showError(err.code || (buyerMode ? "invalid-link" : "invalid-base32"));
  }
}

function mergeTypedName(parsed) {
  if (!parsed) return parsed;
  const name = currentName();
  if (name) return { ...parsed, account: name };
  return parsed;
}

function readInput() {
  if (buyerMode) return;
  const raw = els.input.value;
  if (!String(raw).trim()) {
    clearError();
    applyConfig(null);
    return;
  }
  try {
    const parsed = mergeTypedName(parseInput(raw));
    applyConfig(parsed);
  } catch (err) {
    config = null;
    setIdleCode();
    showError(err.code || "invalid-base32");
  }
}

function onAccountNameInput() {
  if (buyerMode) return;
  if (!config) return;
  config = { ...config, account: currentName() };
  els.issuer.textContent = displayLabel(config);
  if (!els.sharePanel.hidden) updateSharePanel();
}

function updateCountdown() {
  if (!config) return;
  const period = config.period || 30;
  const remaining = remainingSeconds(period);
  const ratio = remaining / period;
  els.seconds.textContent = String(remaining);
  els.ring.style.strokeDashoffset = String(RING_CIRCUMFERENCE * (1 - ratio));
  els.bar.style.transform = `scaleX(${ratio})`;
  document
    .querySelector(".code-panel")
    .classList.toggle("is-urgent", remaining <= 5);
}

async function tick() {
  if (!config) {
    updateCountdown();
    return;
  }
  try {
    const code = await generateTOTP(config.secret, {
      algorithm: config.algorithm,
      digits: config.digits,
      period: config.period,
    });
    if (code !== lastCode) {
      lastCode = code;
      els.code.textContent = formatCode(code);
      announce("El código se actualizó.");
    }
    updateCountdown();
  } catch {
    /* already surfaced on input */
  }
}

async function copyText(value) {
  try {
    await navigator.clipboard.writeText(value);
  } catch {
    const tmp = document.createElement("textarea");
    tmp.value = value;
    tmp.setAttribute("readonly", "");
    tmp.style.position = "fixed";
    tmp.style.left = "-9999px";
    document.body.appendChild(tmp);
    tmp.select();
    document.execCommand("copy");
    tmp.remove();
  }
}

async function copyCode() {
  if (!lastCode) return;
  await copyText(lastCode);
  els.copy.classList.add("is-copied");
  els.copyLabel.textContent = "Copiado";
  announce("Código copiado al portapapeles.");
  window.clearTimeout(copyTimer);
  copyTimer = window.setTimeout(() => {
    els.copy.classList.remove("is-copied");
    els.copyLabel.textContent = defaultCopyLabel();
  }, 1800);
}

async function copyShareLink() {
  const url = els.shareLink.value || currentShareUrl();
  if (!url) return;
  await copyText(url);
  els.copyLink.classList.add("is-copied");
  els.copyLinkLabel.textContent = "Link copiado";
  announce("Enlace copiado al portapapeles.");
  window.clearTimeout(copyLinkTimer);
  copyLinkTimer = window.setTimeout(() => {
    els.copyLink.classList.remove("is-copied");
    els.copyLinkLabel.textContent = "Copiar enlace";
  }, 1800);
}

async function onShare() {
  if (!config) return;
  showSharePanel();
  const url = currentShareUrl();
  const label = displayLabel(config);
  if (typeof navigator.share === "function") {
    try {
      await navigator.share({
        title: label ? `Código 2FA · ${label}` : "Código 2FA",
        text: shareMessage(url, label),
        url,
      });
      announce("Enlace listo para compartir.");
      return;
    } catch (err) {
      if (err && err.name === "AbortError") return;
    }
  }
  await copyShareLink();
  const original = els.share.textContent;
  els.share.textContent = "Link copiado";
  els.share.classList.add("is-copied");
  window.setTimeout(() => {
    els.share.textContent = original || "Compartir";
    els.share.classList.remove("is-copied");
  }, 1800);
}

function fillSecret(value) {
  els.input.value = value;
  els.input.focus();
  readInput();
}

async function applyLocationHash() {
  let parsed = null;
  try {
    parsed = parseHash(location.hash);
  } catch (err) {
    setBuyerMode(true);
    config = null;
    setIdleCode();
    showError(err.code || "invalid-link");
    announce("No se pudo leer el enlace.");
    return;
  }

  if (!parsed) {
    if (buyerMode) {
      setBuyerMode(false);
      els.input.value = "";
      els.accountName.value = "";
      clearError();
      await applyConfig(null);
    }
    return;
  }

  // Do not put the secret in the input (buyer must not see it by default).
  els.input.value = "";
  els.accountName.value = "";
  setBuyerMode(true, displayLabel(parsed));
  await applyConfig(parsed, { announceReady: true });
}

async function decodeQrFromSource(source) {
  if ("BarcodeDetector" in window) {
    try {
      const detector = new BarcodeDetector({ formats: ["qr_code"] });
      const codes = await detector.detect(source);
      if (codes && codes.length && codes[0].rawValue) {
        return codes[0].rawValue;
      }
    } catch {
      /* fallback to jsQR */
    }
  }
  if (typeof window.jsQR !== "function") {
    return null;
  }
  const width =
    source.videoWidth || source.naturalWidth || source.width || 0;
  const height =
    source.videoHeight || source.naturalHeight || source.height || 0;
  if (!width || !height) return null;
  const canvas = document.createElement("canvas");
  canvas.width = width;
  canvas.height = height;
  const ctx = canvas.getContext("2d", { willReadFrequently: true });
  ctx.drawImage(source, 0, 0, width, height);
  const imageData = ctx.getImageData(0, 0, width, height);
  const result = window.jsQR(imageData.data, width, height, {
    inversionAttempts: "attemptBoth",
  });
  return result && result.data ? result.data : null;
}

async function loadImageFile(file) {
  const bitmapAllowed = typeof createImageBitmap === "function";
  if (bitmapAllowed) {
    try {
      return await createImageBitmap(file);
    } catch {
      /* fall through */
    }
  }
  const url = URL.createObjectURL(file);
  try {
    const img = new Image();
    img.src = url;
    await img.decode();
    return img;
  } finally {
    URL.revokeObjectURL(url);
  }
}

async function handleQrValue(value) {
  if (!value) throw Object.assign(new Error("qr-not-found"), { code: "qr-not-found" });
  fillSecret(value.trim());
  announce("Se leyó el código QR.");
}

async function onUpload(file) {
  if (!file) return;
  try {
    const image = await loadImageFile(file);
    const value = await decodeQrFromSource(image);
    if (image.close) image.close();
    if (!value) {
      els.error.textContent = "No se encontró un código QR en esa imagen.";
      els.error.hidden = false;
      announce("No se encontró un código QR en la imagen.");
      return;
    }
    await handleQrValue(value);
  } catch (err) {
    els.error.textContent =
      err.code === "qr-not-found"
        ? "No se encontró un código QR en esa imagen."
        : "No se pudo leer la imagen. Prueba con otra foto del código QR.";
    els.error.hidden = false;
  }
}

async function stopCamera() {
  if (cameraLoop) {
    cancelAnimationFrame(cameraLoop);
    cameraLoop = 0;
  }
  if (cameraStream) {
    for (const track of cameraStream.getTracks()) track.stop();
    cameraStream = null;
  }
  els.video.srcObject = null;
  els.modal.hidden = true;
  document.body.classList.remove("modal-open");
  els.scan.setAttribute("aria-expanded", "false");
}

async function scanFrame() {
  if (!cameraStream || scanBusy) {
    cameraLoop = requestAnimationFrame(scanFrame);
    return;
  }
  if (els.video.readyState >= 2) {
    scanBusy = true;
    try {
      const value = await decodeQrFromSource(els.video);
      if (value) {
        await handleQrValue(value);
        await stopCamera();
        scanBusy = false;
        return;
      }
    } catch {
      /* keep scanning */
    }
    scanBusy = false;
  }
  cameraLoop = requestAnimationFrame(scanFrame);
}

async function startCamera() {
  if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
    els.error.textContent = "Este dispositivo o navegador no permite usar la cámara.";
    els.error.hidden = false;
    return;
  }
  try {
    cameraStream = await navigator.mediaDevices.getUserMedia({
      video: { facingMode: { ideal: "environment" } },
      audio: false,
    });
  } catch {
    els.error.textContent =
      "No se pudo usar la cámara. Revisa el permiso del navegador e inténtalo de nuevo.";
    els.error.hidden = false;
    return;
  }
  clearError();
  els.modal.hidden = false;
  document.body.classList.add("modal-open");
  els.scan.setAttribute("aria-expanded", "true");
  els.video.srcObject = cameraStream;
  try {
    await els.video.play();
  } catch {
    /* autoplay may require a gesture; we already had one */
  }
  els.cameraStatus.textContent = "Encuadra el código QR dentro del recuadro.";
  els.cameraClose.focus();
  cameraLoop = requestAnimationFrame(scanFrame);
}

function initTheme() {
  try {
    const saved = localStorage.getItem("codigo-2fa-theme");
    if (saved === "light" || saved === "dark") {
      document.documentElement.setAttribute("data-theme", saved);
    }
  } catch {
    /* ignore */
  }
  syncThemeButton();
}

function onKey(event) {
  if (event.key === "Escape" && !els.modal.hidden) {
    event.preventDefault();
    stopCamera();
  }
}

els.input.addEventListener("input", readInput);
els.input.addEventListener("paste", () => {
  window.setTimeout(readInput, 0);
});
els.accountName.addEventListener("input", onAccountNameInput);
els.clear.addEventListener("click", () => {
  fillSecret("");
  els.input.focus();
  announce("Se limpió la clave.");
});
els.demo.addEventListener("click", () => {
  fillSecret(DEMO_SECRET);
  announce("Se cargó una clave de ejemplo. No la uses para una cuenta real.");
});
els.copy.addEventListener("click", copyCode);
els.share.addEventListener("click", onShare);
els.copyLink.addEventListener("click", copyShareLink);
els.shareLink.addEventListener("focus", () => els.shareLink.select());
els.upload.addEventListener("click", () => els.file.click());
els.file.addEventListener("change", () => {
  const file = els.file.files && els.file.files[0];
  els.file.value = "";
  onUpload(file);
});
els.scan.addEventListener("click", startCamera);
els.cameraClose.addEventListener("click", stopCamera);
els.modal.addEventListener("click", (event) => {
  if (event.target === els.modal) stopCamera();
});
els.theme.addEventListener("click", () => {
  const current =
    document.documentElement.getAttribute("data-theme") || preferredTheme();
  setTheme(current === "dark" ? "light" : "dark");
});
document.addEventListener("keydown", onKey);
window.addEventListener("pagehide", () => {
  stopCamera();
});
window.addEventListener("hashchange", () => {
  applyLocationHash();
});

initTheme();
els.ring.style.strokeDasharray = String(RING_CIRCUMFERENCE);
els.ring.style.strokeDashoffset = String(RING_CIRCUMFERENCE);
setIdleCode();
tickTimer = window.setInterval(tick, 200);
applyLocationHash();
