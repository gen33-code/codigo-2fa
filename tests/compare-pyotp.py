#!/usr/bin/env python3
import json
from pathlib import Path
import pyotp

RFC_TIMES = [59, 1111111109, 1111111111, 1234567890, 2000000000, 20000000000]
RFC = {
    "SHA1": ("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", "SHA1"),
    "SHA256": ("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA", "SHA256"),
    "SHA512": (
        "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA",
        "SHA512",
    ),
}

print("RFC 6238 via pyotp")
rfc_ok = True
expected = {
    "SHA1": ["94287082", "07081804", "14050471", "89005924", "69279037", "65353130"],
    "SHA256": ["46119246", "68084774", "67062674", "91819424", "90698825", "77737706"],
    "SHA512": ["90693936", "25091201", "99943326", "93441116", "38618901", "47863826"],
}
for name, (secret, digest) in RFC.items():
    totp = pyotp.TOTP(secret, digits=8, digest=digest)
    for i, t in enumerate(RFC_TIMES):
        got = totp.at(t)
        exp = expected[name][i]
        ok = got == exp
        rfc_ok = rfc_ok and ok
        print(f"  {'ok' if ok else 'FAIL'}  {name} T={t} => {got} (esperado {exp})")

results_path = Path(__file__).with_name("node-results.json")
node = json.loads(results_path.read_text())
secret = node["demoSecret"]

# JBSWY3DPEHPK3PXP ("Hello!") es una clave de ejemplo clásica de 80 bits.
# pyotp reciente exige 112 bits por NIST SP 800-63B; bajamos el mínimo
# solo para comparar el algoritmo, no para relajar la librería en general.
class DemoTOTP(pyotp.TOTP):
    min_secret_length_bits = 80

totp = DemoTOTP(secret)
print("\nComparación con Node para JBSWY3DPEHPK3PXP")
demo_ok = True
for t in node["times"]:
    py = totp.at(t)
    js = node["codes"][str(t)]
    ok = py == js
    demo_ok = demo_ok and ok
    print(f"  {'ok' if ok else 'FAIL'}  T={t} pyotp={py} node={js}")

now = node["now"]
py_now = totp.at(now)
js_now = node["codes"]["now"]
ok_now = py_now == js_now
demo_ok = demo_ok and ok_now
print(f"  {'ok' if ok_now else 'FAIL'}  T={now} (ahora) pyotp={py_now} node={js_now}")

if not (rfc_ok and demo_ok):
    raise SystemExit(1)
print("\npyotp coincide con Node y con RFC 6238")
