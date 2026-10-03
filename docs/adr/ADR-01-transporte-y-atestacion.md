# ADR-01 — Transporte y atestación del plano de datos

- **Estado:** aceptado
- **Fecha:** 2026-10-02
- **Decisor:** Nuño Rodríguez Escarpenter
- **Relacionado:** `ADR-00-producto-unificado.md` (exposure y layering)

## Contexto

El plano de datos es navegador ↔ Hermes. El gateway es un Hermes full-tools que
**debe** leer el prompt en claro para inferir, ejecutar herramientas y razonar. Eso
hace que el gateway sea, por definición, un extremo del canal.

**Consecuencia que hay que decir en voz alta:** esto **no es E2EE en el sentido
estricto** — no es "solo los dos extremos descifran y el servicio no ve nada". Es
*"solo el enclave atestiguado ve el plaintext"*. La diferencia con un cloud normal
no es que nadie vea los datos: es **quién** los ve, y que eso sea **verificable**.

Escribir "E2EE" o "cifrado extremo a extremo" en superficie pública es una
afirmación no verificable y el primer cliente técnico la desmonta. La voz correcta
es: *el proveedor de infraestructura no puede leer tus datos; el enclave sí, y
puedes comprobar cuál es*.

## Decisión

Tres capas. Ninguna sola basta; juntas dan la garantía.

```
1. RA-TLS     TLS termina DENTRO del enclave (no en Cloudflare, no en ICP)
2. ATESTACIÓN el cliente verifica el enclave ANTES de hablar (JS/WASM)
3. E2E-APP    handshake X25519(+ML-KEM-768) ligado criptográficamente a la atestación
```

### Capa 1 — RA-TLS

Certificado y clave generados dentro del enclave, ligados al quote de hardware.
Ningún intermedio ve plaintext. **El túnel Cloudflare queda solo para dev.**

### Capa 2 — Atestación en el cliente

El navegador no verifica quotes TEE de forma nativa. Por eso:

- **Patrón 1 (CA-folded):** la atestación se verifica al emitir el certificado; el
  navegador acepta un certificado HTTPS normal. UX normal, verificación delegada.
- **Patrón 2 (verificador JS/WASM):** el cliente valida el quote contra las raíces
  del vendor. Más riguroso. **Elegido como vía de confianza.**

Se implementan **los dos** en defensa en profundidad: certificado normal dentro del
enclave para que el transporte sea HTTPS estándar (1), y verificación del quote a
nivel de aplicación (2). Si (2) falla, se aborta aunque (1) haya pasado.

### Capa 3 — Handshake de aplicación

Sobre el canal atestiguado, se deriva una clave de sesión **ligada a la evidencia
del enclave**. Este es el punto clave:

> Si el enclave no es genuino, la clave derivada es distinta y el handshake falla.
> La atestación no es un chequeo decorativo al principio: queda atada
> criptográficamente a la sesión.

## El contrato del handshake

**Paso 1 — el cliente pide atestación.**

```
GET /v1/attest?nonce=<nonce-cliente-32B-hex>
→ 200 {
    "quote": "<base64 del quote del vendor>",
    "vendor": "amd-sev-snp" | "intel-tdx" | "dev",
    "binary_hash": "<sha256 hex del binario del gateway>",
    "session_pub": "<base64 X25519 efímera del enclave>",
    "kem_pub": "<base64 ML-KEM-768 del enclave, opcional en v1>",
    "attestation_state": "attested" | "dev-unattested",
    "expires_at": <ns>
  }
```

**Paso 2 — el cliente verifica.** En este orden, y **cualquier fallo aborta**:

1. `vendor` ∈ raíces configuradas del cliente.
2. La cadena del quote encadena hasta la raíz del vendor.
3. `report_data` del quote contiene `sha256(nonce || binary_hash)` — ata el quote al
   binario **y** a esta sesión (frescura y anti-replay).
4. `binary_hash` coincide con el binario esperado (pinning del cliente).
5. `expires_at` en el futuro.
6. `attestation_state` es `attested`. (**Si es `dev-unattested`, la UI lo muestra y
   el usuario ha de aceptarlo explícitamente.**)

**Paso 3 — el cliente responde.**

```
POST /v1/session
{ "nonce": "<el mismo>", "client_pub": "<base64 X25519>", "kem_pub": "<opcional>" }
```

**Paso 4 — derivación.** Ambos calculan:

```
shared      = X25519(priv, peer_pub)          // + ML-KEM en F6
transcript  = nonce || client_pub || session_pub || report_data || vendor
session_key = HKDF-SHA256(ikm = shared || report_data, salt = transcript, info = "hermetik/v1")
```

`report_data` entra en el IKM: **si el enclave no es el que se atestiguó, la clave
no coincide**. El handshake falla en el primer mensaje cifrado, no al final.

**Paso 5 — canal.** Cifrado autenticado con contador por dirección. `nb2` se usa solo
en el establecimiento, no en cada mensaje. *Nota de implementación (v1):* WebCrypto
no expone ChaCha20-Poly1305 de forma nativa, así que la implementación usa
**AES-256-GCM** (contador en el IV, anti-replay por dirección). Se revisará a
híbrido PQ en F6.

## Abstracción del vendor

La elección AMD/Intel **no toca** `access` ni `vault`, y tampoco reescribe el
verificador. Se aísla en un módulo con dos piezas:

```
QuoteProvider    // emite: dev | sev-snp | tdx   (lado gateway)
QuoteVerifier    // valida: raíces + parseo + report_data  (lado cliente)
```

Cambiar de vendor = cambiar el módulo de raíces y el parser de quote. Nada más.

## Modos de atestación (y la regla que los gobierna)

| `attestation_state` | Cuándo | Qué hace el cliente |
|---|---|---|
| `attested` | Quote verificado contra raíz del vendor | Procede |
| `dev-unattested` | `DEV_ATTEST=1`, quote firmado con clave de desarrollo | **Procede solo con aceptación explícita del usuario, con aviso visible permanente** |

### Regla dura: el modo dev no es un fallback

**Nunca** hay degradación automática de `attested` a `dev-unattested`. Si la
verificación falla, se **aborta**; no se reintenta en modo dev. Un modo dev
indistinguible en logs de uno real reproduce exactamente el patrón de los dos
hallazgos altos de la auditoría (`hermetik-run-1`): **degradación silenciosa**.

- El gateway solo emite `dev-unattested` si arrancó con `DEV_ATTEST=1` explícita.
- La UI pinta el estado en todo momento, no solo al conectar.
- El evento queda registrado en el audit log del vault.

## Cómo se prueba sin TEE

La atestación es una **interfaz**, no una implementación. Eso permite probar el
90% sin hardware.

**Nivel 1 — mock completo (sin TEE, hoy).**
`QuoteProvider::Dev` emite quotes firmados con clave de desarrollo; el verificador
valida contra las raíces dev. **Todo el flujo — handshake, derivación, canal, chat —
funciona de punta a punta.** No se prueba que el enclave sea genuino; se prueba que
el protocolo es correcto.

**Nivel 2 — casos negativos del verificador (sin TEE, y es lo importante).**
Un verificador que acepta un mock es indistinguible de uno que dice "sí" a todo. Hay
que probar que **rechaza**:

- firma del quote corrupta → aborta
- `report_data` que no corresponde al binario → aborta
- `report_data` que no contiene el nonce de esta sesión → aborta (anti-replay)
- quote caducado (`expires_at` pasado) → aborta
- raíz desconocida / vendor no configurado → aborta
- nonce reutilizado de una sesión anterior → aborta
- `binary_hash` que no coincide con el pinning del cliente → aborta

Cada caso debe fallar. Esto se prueba hoy y es la mitad del valor del verificador.

**Nivel 3 — CI en máquina real (solo cierre).**
Cuando haya acceso a una instancia SEV-SNP o TDX (alquiler por horas), correr los
mismos tests contra un quote auténtico. Valida el eslabón que no se puede simular:
que las raíces del cliente son las correctas y que el formato de quote que emite el
build es el que espera el verificador.

## Consecuencias

- **Positivas:** el producto se puede cerrar entero y probar sin TEE; el vendor no
  condiciona el diseño; la garantía es verificable y honesta; la degradación es
  imposible por construcción.
- **Negativas:** sin TEE real, la propiedad no es completa — se prueba el protocolo,
  no la genuinidad del hardware. Eso hay que decirlo en la documentación interna
  mientras no haya Nivel 3.
- **Pendiente de decisión:** AMD SEV-SNP vs Intel TDX (afecta solo al módulo de
  raíces y al parser).

## Referencias

- `ADR-00-producto-unificado.md` — layering, exposure, ICP como directorio certificado
- `docs/plans/2026-10-02-hermetik-v3.1.md` — fases F4 y F6
- Plan PQ: `/opt/data/nebulock-chat-icp/docs/plans/2026-09-13-nebulock-pq.md`
- Auditoría: `~/security-audit-skill/hermetik/run-1/REPORT.md`
