/**
 * Enlaces para compartir un código TOTP.
 * El secreto va solo en el fragmento (#), nunca en la query.
 */

import { mapAlgorithm, normalizeSecret, parseOtpauth } from "./totp.js";

const PAGE_ANCHORS = new Set([
  "inicio",
  "herramienta",
  "guia",
  "que-es",
  "como-funciona",
  "como-usarlo",
  "compatibilidad",
  "preguntas",
]);

function safeDecode(value) {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

function normalizeDigits(raw, fallback = 6) {
  const digits = raw == null || raw === "" ? fallback : parseInt(raw, 10);
  if (![6, 7, 8].includes(digits)) {
    throw Object.assign(new Error("invalid-digits"), { code: "invalid-digits" });
  }
  return digits;
}

function normalizePeriod(raw, fallback = 30) {
  const period = raw == null || raw === "" ? fallback : parseInt(raw, 10);
  if (!Number.isFinite(period) || period < 1 || period > 180) {
    throw Object.assign(new Error("invalid-period"), { code: "invalid-period" });
  }
  return period;
}

export function cleanBaseUrl(from) {
  const url = new URL(from);
  url.hash = "";
  url.search = "";
  if (url.pathname.endsWith("/index.html")) {
    url.pathname = url.pathname.slice(0, -"index.html".length);
  }
  return url.toString();
}

export function buildShareHash(config) {
  if (!config || !config.secret) {
    throw Object.assign(new Error("missing-secret"), { code: "missing-secret" });
  }
  const params = new URLSearchParams();
  params.set("k", normalizeSecret(config.secret));
  const name = String(config.account || config.label || "").trim();
  const issuer = String(config.issuer || "").trim();
  if (name) params.set("n", name);
  if (issuer) params.set("i", issuer);
  if (config.digits && config.digits !== 6) params.set("d", String(config.digits));
  if (config.period && config.period !== 30) params.set("p", String(config.period));
  if (config.algorithm && config.algorithm !== "SHA-1") {
    params.set("a", String(config.algorithm).replace(/-/g, ""));
  }
  return `#${params.toString()}`;
}

export function buildShareUrl(config, base) {
  return `${cleanBaseUrl(base)}${buildShareHash(config)}`;
}

export function shareMessage(url, name = "") {
  const label = String(name || "").trim();
  const intro = label
    ? `Aquí tienes tu código de verificación para ${label}.`
    : "Aquí tienes tu código de verificación.";
  return `${intro} Ábrelo y copia el número cuando te lo pidan:\n${url}`;
}

export function whatsappShareUrl(url, name = "") {
  return `https://wa.me/?text=${encodeURIComponent(shareMessage(url, name))}`;
}

export function parseHash(hash) {
  const raw = String(hash || "").replace(/^#/, "").trim();
  if (!raw) return null;

  const decoded = safeDecode(raw);
  if (PAGE_ANCHORS.has(raw) || PAGE_ANCHORS.has(decoded)) {
    return null;
  }
  if (!raw.includes("=") && !/^otpauth:\/\//i.test(decoded)) {
    return null;
  }

  if (/^otpauth:\/\//i.test(decoded)) {
    return parseOtpauth(decoded);
  }

  const params = new URLSearchParams(raw);
  const secret = params.get("k") || params.get("secret");
  if (!secret) return null;

  const name = (params.get("n") || params.get("name") || params.get("label") || "").trim();
  const issuer = (params.get("i") || params.get("issuer") || "").trim();

  return {
    secret: normalizeSecret(secret),
    issuer,
    account: name,
    algorithm: mapAlgorithm(params.get("a") || params.get("algorithm") || "SHA1"),
    digits: normalizeDigits(params.get("d") || params.get("digits")),
    period: normalizePeriod(params.get("p") || params.get("period")),
  };
}
