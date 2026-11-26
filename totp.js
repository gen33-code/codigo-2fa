/**
 * Generación TOTP según RFC 6238 (y truncado HOTP de RFC 4226),
 * usando solo la Web Crypto API del navegador o de Node.
 */

const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

export const DEMO_SECRET = "JBSWY3DPEHPK3PXP";

export function normalizeSecret(input) {
  return String(input || "").toUpperCase().replace(/[\s\-]/g, "");
}

export function base32Decode(input) {
  const cleaned = normalizeSecret(input).replace(/=+$/g, "");
  if (!cleaned) {
    throw Object.assign(new Error("empty"), { code: "empty" });
  }
  if (!/^[A-Z2-7]+$/.test(cleaned)) {
    throw Object.assign(new Error("invalid-base32"), { code: "invalid-base32" });
  }
  let bits = "";
  for (const char of cleaned) {
    bits += BASE32_ALPHABET.indexOf(char).toString(2).padStart(5, "0");
  }
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    bytes.push(parseInt(bits.slice(i, i + 8), 2));
  }
  if (!bytes.length) {
    throw Object.assign(new Error("invalid-base32"), { code: "invalid-base32" });
  }
  return new Uint8Array(bytes);
}

function mapAlgorithm(raw) {
  const key = String(raw || "SHA1")
    .toUpperCase()
    .replace(/-/g, "")
    .replace(/^SHA/, "SHA");
  const map = { SHA1: "SHA-1", SHA256: "SHA-256", SHA512: "SHA-512" };
  if (!map[key]) {
    throw Object.assign(new Error("unsupported-algorithm"), {
      code: "unsupported-algorithm",
    });
  }
  return map[key];
}

export function parseOtpauth(uri) {
  let url;
  try {
    url = new URL(String(uri).trim());
  } catch {
    throw Object.assign(new Error("invalid-uri"), { code: "invalid-uri" });
  }
  if (url.protocol !== "otpauth:") {
    throw Object.assign(new Error("invalid-uri"), { code: "invalid-uri" });
  }

  const type = (url.host || url.hostname || "").toLowerCase();
  if (type && type !== "totp") {
    throw Object.assign(new Error("not-totp"), { code: "not-totp" });
  }

  const params = url.searchParams;
  const secret = params.get("secret");
  if (!secret) {
    throw Object.assign(new Error("missing-secret"), { code: "missing-secret" });
  }

  const digits = parseInt(params.get("digits") || "6", 10);
  const period = parseInt(params.get("period") || "30", 10);
  if (![6, 7, 8].includes(digits)) {
    throw Object.assign(new Error("invalid-digits"), { code: "invalid-digits" });
  }
  if (!Number.isFinite(period) || period < 1 || period > 180) {
    throw Object.assign(new Error("invalid-period"), { code: "invalid-period" });
  }

  let label = "";
  try {
    label = decodeURIComponent(url.pathname.replace(/^\//, ""));
  } catch {
    label = url.pathname.replace(/^\//, "");
  }

  let issuer = params.get("issuer") || "";
  let account = label;
  const colon = label.indexOf(":");
  if (colon >= 0) {
    const maybeIssuer = label.slice(0, colon).trim();
    account = label.slice(colon + 1).trim();
    if (!issuer) issuer = maybeIssuer;
  }

  return {
    secret: normalizeSecret(secret),
    issuer,
    account,
    algorithm: mapAlgorithm(params.get("algorithm") || "SHA1"),
    digits,
    period,
  };
}

export function parseInput(raw) {
  const trimmed = String(raw || "").trim();
  if (!trimmed) return null;
  if (/^otpauth:\/\//i.test(trimmed)) {
    return parseOtpauth(trimmed);
  }
  return {
    secret: normalizeSecret(trimmed),
    issuer: "",
    account: "",
    algorithm: "SHA-1",
    digits: 6,
    period: 30,
  };
}

function counterToBytes(counter) {
  const buf = new ArrayBuffer(8);
  const view = new DataView(buf);
  const high = Math.floor(counter / 0x100000000);
  const low = counter >>> 0;
  view.setUint32(0, high, false);
  view.setUint32(4, low, false);
  return buf;
}

async function hmacSign(algorithm, keyBytes, data) {
  const key = await crypto.subtle.importKey(
    "raw",
    keyBytes,
    { name: "HMAC", hash: algorithm },
    false,
    ["sign"]
  );
  return new Uint8Array(await crypto.subtle.sign("HMAC", key, data));
}

export function truncate(hmacBytes, digits) {
  const offset = hmacBytes[hmacBytes.length - 1] & 0x0f;
  const bin =
    ((hmacBytes[offset] & 0x7f) << 24) |
    ((hmacBytes[offset + 1] & 0xff) << 16) |
    ((hmacBytes[offset + 2] & 0xff) << 8) |
    (hmacBytes[offset + 3] & 0xff);
  const otp = bin % 10 ** digits;
  return String(otp).padStart(digits, "0");
}

export async function generateTOTP(secret, options = {}) {
  const algorithm = options.algorithm || "SHA-1";
  const digits = options.digits ?? 6;
  const period = options.period ?? 30;
  const timestamp = options.timestamp ?? Date.now();
  const keyBytes = typeof secret === "string" ? base32Decode(secret) : secret;
  const seconds = Math.floor(timestamp / 1000);
  const counter = Math.floor(seconds / period);
  const mac = await hmacSign(algorithm, keyBytes, counterToBytes(counter));
  return truncate(mac, digits);
}

export function remainingSeconds(period = 30, timestamp = Date.now()) {
  const seconds = Math.floor(timestamp / 1000);
  const rem = period - (seconds % period);
  return rem === 0 ? period : rem;
}
