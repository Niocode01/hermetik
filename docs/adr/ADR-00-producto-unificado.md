# ADR-00 — Producto unificado Hermetik v3.1

- **Estado:** aceptado
- **Fecha:** 2026-10-02
- **Decisor:** Nuño Rodríguez Escarpenter
- **Contexto previo:** `nebulock-chat-v2` (capa de control + UI) y `icp/hermetik-v3`
  (canister de datos). Los números v2/v3 numeraban **capas**, no versiones.

## Decisión

Un solo producto, un solo repo (**`hermetik`**), un solo flujo:

```
landing → login II → pago (ICP ICRC-1) → provisioning de un Hermes en contenedor
confidencial (TEE-CC) → chat E2E (navegador ↔ enclave) → historial + backup
memoria/skills + audit log → vault canister
```

Los cuatro canisters y la infra confidencial **no se fusionan**: tienen roles y
modelos de confianza distintos.

## Arquitectura

### Capa 1 — Borde ICP (plano de control + directorio certificado)
| Componente | Tipo | Rol |
|---|---|---|
| `landing` | assets | aterrizaje + alta |
| `access` | Rust | II + allowlist + credencial `nb2` (HMAC-SHA256) + entitlements + mapping II→contenedor + `request_provision` + verificación de pago ICRC-1 |
| `vault` | Motoko, **1 por usuario** | backup opaco cifrado (PBKDF2+AES-GCM cliente, chunks ≤1 MiB, ≤12 MiB, 3 versiones) + audit log hash-chain SHA-256 |
| `frontend` | assets | chat (bóveda AES-GCM, SSE gateway, voz, approvals, i18n) + pantalla de pago + estado de provisioning + verificador de atestación |

### Capa 2 — Infra confidencial (TEE-CC, fuera de ICP)
- `gateway` — Hermes single-tenant en contenedor confidencial (ya existe).
- `provisioner` — **NUEVO**. Recibe la orden de `access`, levanta/apaga el contenedor
  del cliente, le asigna subdominio y certificado RA-TLS, y devuelve URL + credenciales.
  Es el hueco más grande: no existe orquestador de contenedores TEE-CC.
  **v3.1 implementa el contrato completo + un mock funcional**; el hook real entra
  cuando exista la infra.

### Capa 3 — Pago
- **v3.1: solo ICP ICRC-1** (nativo; patrón ya probado en la factory con
  `admin_withdraw` + subcuentas). Stripe queda fuera de v3.1 (necesita HTTPS estable
  + webhooks off-ICP → puente más frágil, fase posterior).

## Exposure (sustituye al túnel Cloudflare)

- **El túnel Cloudflare queda solo para dev/test.** Termina TLS en su edge → ve el
  plaintext → es exactamente el middlebox que el producto promete eliminar.
- **Producción:** TLS termina **dentro del enclave** (RA-TLS) + subdominio por tenant
  (`https://<tenant>.hermetik.…`) + verificación de atestación en el navegador.
- El navegador no verifica quotes TEE nativamente → **patrón 2 (verificador JS/WASM)**
  para la confianza, **patrón 1 (cert CA-folded)** para que el transporte sea HTTPS normal.
  Defensa en profundidad: TLS en enclave + atestación app-level + payload E2E con la bóveda.
- **ICP NO transporta el data plane.** El gateway no puede ser canister (TEE-CC + GPU +
  runtime arbitrario); los boundary nodes terminan TLS; el streaming SSE no encaja en
  request/response. ICP aporta **certificación de respuestas** (firma BLS del subnet) →
  es el directorio de confianza que le dice al navegador dónde está su Hermes.

## TEE vendor

**Pendiente (AMD SEV-SNP vs Intel TDX).** Todo el diseño es **vendor-agnóstico**: la
abstracción de atestación vive en el verificador del frontend y en el contrato del
provisioner. Cambiar de vendor no toca `access` ni `vault`.

## Consecuencias

- Positivas: un producto, un flujo, un repo. ICP se usa donde aporta (control + certificación).
  El data plane es soberano y verificable. PQ es un cambio localizado, no una reescritura.
- Negativas: v3.1 no es desplegable a producción real (falta orquestador TEE-CC y RA-TLS real);
  el mock permite cerrar el producto entero y sustituir una sola pieza después.

## Referencias
- Plan de ejecución: `docs/plans/2026-10-02-hermetik-v3.1.md`
- Transporte y atestación del plano de datos: `docs/adr/ADR-01-transporte-y-atestacion.md`
- Log Proof-of-Control y fronteras de acceso: `docs/adr/ADR-02-log-poc-y-fronteras.md`
- Plan PQ: `/opt/data/nebulock-chat-icp/docs/plans/2026-09-13-nebulock-pq.md`
