# Código 2FA

Generador de códigos 2FA (TOTP) que funciona por completo en el navegador. Gratis, sin cuentas y sin enviar la clave secreta a ningún servidor.

**Sitio:** https://gen33-code.github.io/codigo-2fa/

## Qué hace

- Pega una clave Base32 o un enlace `otpauth://totp/…`.
- Muestra el código de 6 dígitos (o el que indique el enlace), con cuenta regresiva de 30 segundos y botón para copiar.
- Permite escanear un código QR con la cámara o subir una imagen.
- Calcula los tokens con la Web Crypto API, según RFC 6238 (SHA-1, SHA-256 o SHA-512).
- No guarda secretos, no usa analítica y sigue funcionando si te desconectas después de cargar la página.

Esta herramienta no sustituye guardar las claves de respaldo en un gestor de contraseñas.

## Compartir un código

Puedes generar un enlace para que otra persona vea el código en vivo, sin mostrarle la clave en pantalla. El secreto viaja solo en el fragmento de la URL (`#k=...`), nunca en la query, y no se envía al servidor.

Ejemplo: `https://gen33-code.github.io/codigo-2fa/#k=JBSWY3DPEHPK3PXP`

Quien tenga el enlace puede calcular el mismo código, así que compártelo solo con quien corresponda. Esta herramienta no sustituye guardar las claves de respaldo en un gestor de contraseñas.

## Uso local

Sirve la carpeta con cualquier servidor estático, por ejemplo:

```bash
python3 -m http.server 8080
```

Luego abre `http://localhost:8080`.

## Pruebas

Las pruebas comparan la implementación con los vectores de RFC 6238 y con [pyotp](https://github.com/pyauth/pyotp):

```bash
node tests/totp-test.mjs
python3 tests/compare-pyotp.py
```

## Dominio propio

Si más adelante quieres un dominio personalizado, se puede apuntar a esta misma publicación de GitHub Pages.

## Licencia

MIT. La librería `vendor/jsQR.js` conserva su propia licencia Apache-2.0 / licenciadores originales.
