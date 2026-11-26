import {
  base32Decode,
  generateTOTP,
  parseInput,
  parseOtpauth,
  remainingSeconds,
} from "../totp.js";

const RFC_TIMES = [59, 1111111109, 1111111111, 1234567890, 2000000000, 20000000000];

const RFC_VECTORS = {
  "SHA-1": {
    secret: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
    expected: ["94287082", "07081804", "14050471", "89005924", "69279037", "65353130"],
  },
  "SHA-256": {
    secret: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA",
    expected: ["46119246", "68084774", "67062674", "91819424", "90698825", "77737706"],
  },
  "SHA-512": {
    secret:
      "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA",
    expected: ["90693936", "25091201", "99943326", "93441116", "38618901", "47863826"],
  },
};

const DEMO = "JBSWY3DPEHPK3PXP";
const DEMO_TIMES = [59, 1111111109, 1234567890, 1700000000];

let failed = 0;
let passed = 0;

function assert(cond, message) {
  if (cond) {
    passed += 1;
    console.log("  ok  " + message);
  } else {
    failed += 1;
    console.error("  FAIL  " + message);
  }
}

async function main() {
  console.log("RFC 6238 8-digit vectors");
  for (const [algorithm, { secret, expected }] of Object.entries(RFC_VECTORS)) {
    for (let i = 0; i < RFC_TIMES.length; i++) {
      const t = RFC_TIMES[i];
      const code = await generateTOTP(secret, {
        algorithm,
        digits: 8,
        period: 30,
        timestamp: t * 1000,
      });
      assert(
        code === expected[i],
        `${algorithm} T=${t} => ${code} (esperado ${expected[i]})`
      );
    }
  }

  console.log("\nCaso destacado: SHA-1 T=59");
  const highlight = await generateTOTP("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", {
    algorithm: "SHA-1",
    digits: 8,
    period: 30,
    timestamp: 59 * 1000,
  });
  assert(highlight === "94287082", `T=59 SHA-1 8 dígitos = ${highlight}`);

  console.log("\nParseo de entrada");
  const plain = parseInput(" jbswy3dpehpk3pxp ");
  assert(plain.secret === DEMO, "normaliza espacios y mayúsculas");
  assert(plain.algorithm === "SHA-1" && plain.digits === 6 && plain.period === 30, "valores por defecto");

  const uri = parseOtpauth(
    "otpauth://totp/GitHub:ada@example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&algorithm=SHA256&digits=8&period=60"
  );
  assert(uri.secret === DEMO, "lee secret del URI");
  assert(uri.issuer === "GitHub", "lee issuer");
  assert(uri.account === "ada@example.com", "lee cuenta de la etiqueta");
  assert(uri.algorithm === "SHA-256", "lee algoritmo SHA-256");
  assert(uri.digits === 8 && uri.period === 60, "lee dígitos y periodo");

  try {
    parseOtpauth("otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP");
    assert(false, "debe rechazar HOTP");
  } catch (err) {
    assert(err.code === "not-totp", "rechaza enlaces HOTP");
  }

  try {
    base32Decode("JBSWY3DPEHPK3PXP0");
    assert(false, "debe rechazar Base32 inválido");
  } catch (err) {
    assert(err.code === "invalid-base32", "rechaza caracteres fuera de Base32");
  }

  const rem = remainingSeconds(30, 59 * 1000);
  assert(rem === 1, `remainingSeconds en T=59 es ${rem}`);

  const codes = {};
  console.log("\nClave de ejemplo JBSWY3DPEHPK3PXP (6 dígitos, SHA-1, 30s)");
  for (const t of DEMO_TIMES) {
    codes[t] = await generateTOTP(DEMO, { timestamp: t * 1000 });
    console.log(`  T=${t} => ${codes[t]}`);
  }

  const now = Math.floor(Date.now() / 1000);
  codes.now = await generateTOTP(DEMO, { timestamp: now * 1000 });
  console.log(`  T=${now} (ahora) => ${codes.now}`);

  const { writeFileSync } = await import("node:fs");
  writeFileSync(
    new URL("./node-results.json", import.meta.url),
    JSON.stringify({ demoSecret: DEMO, times: DEMO_TIMES, codes, now }, null, 2)
  );

  console.log(`\nResultado: ${passed} ok, ${failed} fallos`);
  if (failed) process.exit(1);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
