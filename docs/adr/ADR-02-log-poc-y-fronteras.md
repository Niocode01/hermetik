# ADR-02 — Log Proof-of-Control, fronteras de acceso y capa overwatch

- **Estado:** aceptado
- **Fecha:** 2026-10-02
- **Decisor:** Nuño Rodríguez Escarpenter
- **Relacionado:** `ADR-00` (layering), `ADR-01` (transporte y atestación)
- **Norma:** AAI-Society `ov-poc-standard` v0.1 (draft hasta 30-oct-2026; 1.0 feb-2027)
  Clonado verificado en `/tmp/ov-poc`, commit `943f85d`.

## Decisión en una línea

El `vault` (1 por usuario) pasa a tener **dos fronteras de acceso independientes**: el
**backup** (privado del dueño, cifrado, nadie más lo lee) y el **log PoC** (legible por
una **allowlist de auditores**). `s7oui` desaparece: su rol lo absorbe el `vault`. La
emisión de evidencia desde Hermes se hace con una **capa overwatch** interpuesta.

---

## 1. Por qué dos fronteras y no una

Hoy el `vault` exige el mismo rol (`requireWriter`) para backup y log. Eso impide el
requisito 5: un auditor externo debe leer el log **sin** tocar el backup.

Se separa así:

| Recurso | Quién escribe | Quién lee | Qué ve |
|---|---|---|---|
| **Backup** | dueño o gateway (rol writer) | **solo el dueño** | blob cifrado; el canister nunca ve plaintext |
| **Log PoC** | gateway/overwatch (rol writer) | dueño **+ allowlist de auditores** | solo hashes, digests y metadatos de acción |

**Consecuencia que hay que asumir por escrito:** el log es legible por terceros de la
allowlist. Por eso el log **no puede contener datos de usuario** — solo digests y
metadatos. Tu diseño ya iba en esa dirección (`action_hash`, `caller_hash`); aquí se
convierte en **invariante verificada**, no en buena intención.

---

## 2. Por qué hace falta la capa overwatch

PoC C7.1.1 (nivel 3) exige que la evidencia la emita un **Action Interception Gateway
que corre como proceso separado del agente**, sin ruta de red ni de credenciales que lo
evite. Si Hermes emite su propia evidencia, la emisión es *auto-reportada*: un agente
comprometido puede sencillamente no emitir.

De ahí las tres formas de montarlo:

- **(a) In-process.** Hermes llama a `evidence.py` dentro de su propio proceso. Sin
  coste de infraestructura, pero **auto-reportado**: techo Tier 2, y el claim tiene que
  declararlo.
- **(b) Overwatch sidecar.** Proceso separado, mismo host, que intercepta las
  invocaciones de herramienta y emite la evidencia. **Recomendado.**
- **(c) Overwatch en host distinto.** Separación física. Máxima garantía, más coste.

**Decisión: implementar (b) con la interfaz preparada para (c).** El overwatch corre
como proceso separado que Hermes no puede esquivar, y su clave de firma vive fuera del
alcance del agente.

### Cómo encaja con lo que ya existe

Tu plan PoC ya tiene la Etapa A hecha: `gateway/evidence.py` con `EvidenceRecord`,
`EvidenceStore` y el hook 1/4 aplicado en `tools/registry.py::dispatch()`. **Eso es
modo (a).** La capa overwatch no tira nada de eso: convierte el emisor en un proceso
propio al que el dispatch le entrega el evento, en lugar de escribirlo él mismo.

Punto de corte natural: el `dispatch()` pasa de *escribir* a *notificar al overwatch*.
Los hooks 2-4 (approvals, `/v1/commands`, credenciales nb2) emiten al mismo sitio.

---

## 3. Formato del log: PoC canónico

Se adopta el esquema **normativo** de la spec (`schema/poc-evidence.cddl`), no uno
propio. Campos:

```
1     => iss                        ; servicio emisor
6     => iat                        ; epoch SEGUNDOS (nunca float)
10    => eat_nonce                  ; challenge del verificador (8..64 B)
265   => eat_profile                ; URI del perfil
-70001 => agent_id                  ; did:... o id estable
-70002 => principal_id              ; autoridad bajo la que actúa
-70003 => agbom_digest              ; digest del modelo/agente
-70004 => interception_point        ; ver abajo (1..8)
-70005 => step_index                ; monótono por agente, desde 0
-70006 => chain_head                ; digest del eslabón previo
-70007 => policy_bundle_hash
-70008 => target_resource
-70009 => canonical_snapshot_hash
-70010 => path_summary_hash
-70011 => verdict                   ; allow|deny|modify|escalate
-70012 => reason                    ; texto libre, NO relevante para seguridad
-70013 => alg_id                    ; COSE: eddsa -8, ml-dsa-65 -49, híbrido -1000
266   => { "attestation" => {...} }
```

**Los ocho puntos de intercepción** (`interception_point`), que sustituyen a mi
propuesta inicial de `before/during/after`:

```
1 task-init   2 context-assembly   3 plan-generation   4 pre-call-tool
5 post-call-tool   6 memory-write   7 subagent-delegation   8 task-completion
```

Tus "before/after" son los puntos **4** y **5**. Y hay uno que responde directísimo a tu
pregunta de cómo sube Hermes la memoria: el punto **6 `memory-write`** es exactamente el
hook de escritura de memoria.

### Reglas de canonicalización (obligatorias, C7.7.2)

- UTF-8 sin BOM, claves ordenadas por punto de código, sin espacios insignificantes.
- **Sin floats.** `iat` en segundos enteros.
- Digests **etiquetados** y en minúsculas: `sha-256:<hex>`. **Un digest sin etiqueta
  se RECHAZA**, nunca se asume SHA-256 — asumir el algoritmo es como una migración de
  hash sale mal.
- Ausente ≠ vacío: un campo opcional que no aplica se **omite**, no se pone `null` ni
  cadena vacía (producen bytes distintos y por tanto digests distintos).
- Claves duplicadas: **rechazo**, nunca "gana la última".
- El snapshot se canonicaliza con **RFC 8785** completo.

### Qué firma

Firma separada sobre el registro canónico **excluyendo** el campo `signature`. Y la
regla que ya costó un bug real en este proyecto: **fijar `alg` (y todo campo firmado)
ANTES de firmar** — firmar con `alg=""` y verificar con `alg="eddsa"` falla el 100% de
las firmas.

---

## 3b. Diseño para TEE desde hoy (sin TEE hoy)

**Principio que gobierna todo lo que sigue:** la evidencia la firma el **emisor**
(overwatch), no el TEE. El TEE **no firma evidencia**: atestigua *qué código corre y en
qué clave*. Lo que aporta es que la clave de firma **nace dentro del enclave** y que el
**quote compromete esa clave**. Cita normativa: **C7.2.4** exige que *"el digest de la
clave aparezca en el cuerpo del reporte atestiguado (`REPORT_DATA` en SEV-SNP, `REPORTDATA`
en TDX), de forma que un verificador establezca **esta clave corrió dentro de este entorno
medido**, en vez de recibir una medición y una clave que simplemente llegaron juntas"*.

Por eso **hay que separar hoy dos piezas** que se confunden con facilidad:

| Pieza | Qué es | Existe hoy | Con TEE |
|---|---|---|---|
| **Emisor** | El overwatch firma cada registro con una clave que él custodia | Sí | Igual, pero la clave nace *dentro* del enclave |
| **Atestador** | Prueba que el emisor es quien dice y corre el código que dice | **Mock explícito** | Quote real: el `REPORT_DATA` contiene el digest de la clave de firma |

**Si se mezclan ambas, el día que llegue el TEE hay que reescribir la firma.** Diseñadas
así, el TEE **se enchufa sin tocar el emisor**: solo se sustituye el módulo atestador.

### Componentes, con su modo actual y su modo TEE

1. **Clave de firma del overwatch** (`evidence_signing_key`).
   - *Hoy:* clave Ed25519 generada en el arranque del overwatch, guardada **fuera del
     alcance del agente** con permisos restringidos.
   - *Con TEE:* la clave se **deriva dentro del enclave** y nunca sale en claro. Su
     digest (no la clave) es lo que va en `REPORT_DATA`.
   - **C7.3.2** es lo que manda aquí: *"los registros se firman con claves custodiadas por
     el mecanismo generador, y **ni el operador ni el agente** pueden acceder a ellas"*.
     Hoy el operador **sí** tiene acceso físico a la clave → **ese es exactamente el
     motivo por el que el techo es Tier 2**, con cita (ver §5 bis).

2. **Algoritmo de firma** (`alg_id`, campo `-70013`).
   - *Hoy:* `eddsa` (`-8`) puro.
   - *Con TEE:* **híbrido** `-1000` (Ed25519 + ML-DSA-65). El valor va **fijado antes de
     firmar**, nunca después. Esto ya está alineado con la decisión de post-cuántico de
     Nebulock: el log de evidencia no puede ser el eslabón débil.

3. **Atestador** (módulo intercambiable).
   - *Hoy:* **modo `dev-unattested:` obligatorio y ruidoso.** Nada de fallback
     automático: si no hay TEE, el reporte sale **marcado** como no atestiguado, con un
     campo comprobable por el frontend y **pintado en la UI** ("enclave no atestiguado —
     modo desarrollo"). Un verificador que no lo vea fallará a propósito.
   - *Con TEE:* quote real de AMD SEV-SNP **o** Intel TDX. **El resto del código no
     cambia.** Lo único vendor-específico son dos funciones: `parseQuoteChain()` y
     `extractReportData()` — es decir, el módulo `verifier.ts` y las raíces de confianza
     del provisioner. Ese es todo el acoplamiento a vendor, y está ya aislado.

4. **Intervalo de refresco de atestación.**
   - **C7.2.3** obliga a que el claim declare un intervalo máximo de refresco (o un
     número máximo de acciones) tras el cual la evidencia dejaría de apoyarse en una
     medición anterior, y a que el mecanismo refresque dentro de él **o se detenga**.
   - **Dato de la spec que dimensiona esto** (medido en TDX sobre GCP C3): el pipeline de
     software cuesta ~162 µs por acción y correr dentro del dominio de confianza añade
     solo un 6%; **un solo quote cuesta 39,5 ms** — ~4.000× la sobrecarga del TD, y 2,6×
     todo el presupuesto de 15 ms por acción. **Atestiguar por acción es imposible**, no
     solo caro. De ahí que la atestación sea periódica y **el intervalo deba declararse**
     en vez de dejarse al azar de la implementación: cada acción posterior a un quote se
     apoya en una medición anterior.
   - *Diseño:* intervalo declarado como **parámetro del claim**, con el valor puesto en
     `get_attestation_ttl_ns()` que el canister `access` ya expone. Hoy ese TTL es una
     constante de desarrollo; con TEE pasa a ser el intervalo real, y **al expirar sin
     refresco, el emisor se detiene** (no degrada en silencio).

### Las tres capas se quedan aunque cambie el vendor

Esto es lo que permite decir "diseñado para TEE" sin mentir hoy:

- **Capa 1 — RA-TLS:** TLS donde el certificado del servidor va ligado al quote.
- **Capa 2 — Atestación del cliente:** el frontend verifica el quote contra raíces
  conocidas, con casos negativos ya probados (firma corrupta, `report_data` de otra
  sesión, quote caducado, raíz desconocida, vendor inesperado, binario distinto).
- **Capa 3 — Handshake ligado a evidencia:** X25519 + HKDF con el `report_data` en el
  IKM, sin fallback automático (un intento y aborta). Cierra el ataque de relay: si el
  enclave no es genuino, la clave de sesión sale distinta y **el handshake falla**.

Cambiar AMD ↔ Intel **no toca ninguna de las tres capas**: solo cambia el módulo
atestador y las raíces. Esa es la razón de haberlas separado desde el principio.

---

## 4. Cómo sube Hermes: memoria vs logs

Dos caminos, dos fronteras, dos niveles de cifrado:

### Memoria y skills → camino del BACKUP

1. Hermes cifra en el contenedor con la clave derivada del usuario (la clave de la
   bóveda vive en el navegador; para el backup automático se usa una **clave de respaldo
   derivada aparte**, que el usuario puede reconstruir).
2. Sube por chunks: `backup_begin(total)` → `backup_put(idx, ≤1 MiB)` → `backup_commit(sha)`.
3. El canister **nunca ve plaintext**. Retiene 3 versiones.
4. Recuperación: el usuario descifra en el navegador.

**El canister no puede leerlo. El auditor no puede leerlo. Solo el dueño.**

### Logs de acción → camino del LOG PoC

1. Cada punto de intercepción (4 y 5 para herramientas, 6 para memoria, etc.) produce
   un registro PoC.
2. El registro va **en claro pero sin datos de usuario**: digests y metadatos.
3. El **overwatch** lo firma y lo encadena antes de enviarlo al canister.
4. El `vault` lo almacena en su hash-chain (ya existente) extendido al formato PoC.

### Quién figura como actor (`principal_id`)

Decisión cerrada (Nuño): **opción C, sin construir nada nuevo de auth.** El gateway ya
sabe el II del usuario porque **el usuario se lo dice en cada request, autenticado**:

1. Login II en el frontend → el principal queda en estado (`app.tsx`).
2. El frontend pide `issue_credential` al canister `access`: el token nb2 lleva el
   principal dentro del mensaje firmado `nb2.<principal>.<expiry>.<epoch>.<nonce>.<tag>`.
3. Cada llamada al chat lleva `Authorization: Bearer *** `X-Nebulock-User: <principal>`.
4. El gateway exige 403 si `X-Nebulock-User` no es EXACTAMENTE el principal de la
   credencial (verificado por `verify_credential` en el canister: HMAC constante +
   expiración + época + allowlist).

Por tanto en el registro PoC:

- `agent_id` = principal del emisor (gateway/overwatch: quién emite la evidencia).
- `principal_id` = el `X-Nebulock-User` verificado contra nb2 (bajo qué autoridad actúa).
- Extensión `hermetik_credential_expiry_ns` = el `expiry_ns` del token que autorizaba
  la acción. El auditor comprueba `iat <= hermetik_credential_expiry_ns`: evidencia
  con credencial caducada no vale. Solo se serializa si > 0 (ausente ≠ 0); el CDDL
  permite `* tstr => any` como extensión, que verificadores ajenos ignoran.
- Sin `X-Nebulock-User` verificado no hay acción: `PendingAction` rechaza
  `principal_id` vacío y cualquier esquema distinto de `nb2`.

---

## 5. La frontera del auditor

**Allowlist de auditores** (decisión de Nuño). Consecuencias de diseño:

- Nueva lista en el `vault`: `auditors: Vec<Principal>`.
- `admin_add_auditor` / `admin_remove_auditor` / `admin_list_auditors` (solo admin).
- **Queries de log** (`get_entry`, `get_recent_entries`, `verify_chain`, inclusion
  proofs): autorizadas para **dueño ∪ auditores**.
- **Queries de backup** (`get_backup_chunk`, `list_backups`): autorizadas **solo para el
  dueño**. El auditor recibe rechazo, no una lista vacía.
- El auditor **nunca** ve: chunks de backup, tamaños, número de versiones, ni metadatos
  del backup.

### Lo que PoC exige a la lectura del auditor

Dos requisitos que se implementan junto con la frontera:

- **C7.6.4** — *"el acceso al almacén de evidencia aplica control por rol, y **cada
  lectura de evidencia escribe su propio registro de acceso** (quién, qué, cuándo)"*.
  Es decir: **el propio acto de auditar deja evidencia.** Va al mismo hash-chain.
- **C7.3.4** — **prueba de inclusión** contra una raíz publicada (Merkle RFC 6962), para
  que el auditor pueda probar que un registro concreto está en el log **sin** recibir el
  log entero. El tamaño de la prueba crece logarítmicamente.
- **C7.3.5** — prueba de **consistencia append-only** entre raíces publicadas en
  momentos distintos. Y el aviso de la spec que hay que respetar: un verificador que solo
  compara el **número** de registros acepta una historia reescrita; hay que comparar
  **la raíz recomputada** contra el valor anclado.

### Aviso de nivel (honestidad obligatoria)

**Tier 3 exige TEE real** (C7.2.4: el quote debe comprometer la clave de firma) **y**
anclaje externo con raíces publicadas. Sin eso, el techo es **Tier 2**.

---

## 5 bis. Por qué el techo es Tier 2, con cita (no es opinión)

No es una cautela mía: **es lo que dice la norma, y conviene tenerlo escrito con la
referencia exacta** para que el día que alguien quiera vender "Proof-of-Control" haya que
responder a esto.

**C8, tabla de mecanismos, lista de "criptográfico, y aún confías en una parte (Tier 2)":**

- *"Un sistema que firma sus propios logs o salidas con su propia clave. Confías en que el
  titular de la clave no mienta ni antidate."* ← **Esto es exactamente el overwatch hoy.**
- *"Una atestación de entorno de ejecución confiable cuya raíz de confianza es el servicio
  de atestación del fabricante de chips."* ← Tier 2 por sí sola.

**La tabla de la frontera binaria (Tiers 1–2 frente a 3–4) lo dice sin rodeos:**

| Documentación autenticada (Tiers 1–2, NO es Proof-of-Control) | Evidencia criptográfica (Tiers 3–4, SÍ es Proof-of-Control) |
|---|---|
| *"El operador produce logs o registros, luego los firma. La firma establece que el log no se alteró después de su creación; **no** establece que el log refleje con exactitud lo que ocurrió."* | *"El mecanismo criptográfico genera la evidencia **como subproducto de la propia ejecución**: (...) un informe de atestación TEE, un sello de tiempo de consenso, una prueba de cómputo verificable."* |

Y **C8.1.7** marca la salida, que es el diseño que hay que tener preparado: un claim que
se apoya en atestación vendor-rooted debe **o** registrarse en Tier 2, **o** componerse con
**anclaje independiente** (p. ej. reports de atestación comprometidos a un log de
transparencia público con monitores independientes) **antes** de registrarse en Tier 3.
Con el supuesto de confianza en el vendor **declarado** en los dos casos.

**Corolario operativo (los tres escalones, en orden):**

1. **Hoy** (overwatch firma, sin TEE, sin anclaje): emite evidencia conforme al esquema,
   verificable por auditor con acceso. **Claim público: Tier 2.** Y por **C7.1.5**, el claim
   **no puede afirmar que describe acciones ejecutadas** si no se cumple 7.1.4 (mediación
   del canal de efecto) — que es precisamente lo que aporta el overwatch.
2. **Con TEE, sin anclaje:** sigue siendo **Tier 2** (C8.1.7). El TEE por sí solo no cruza
   la línea.
3. **Con TEE + anclaje externo** (raíces publicadas + monitores independientes): **Tier 3.**
   Ahí, y solo ahí, se puede decir Proof-of-Control.

También conviene tener presente qué **no** da un claim Tier 3, para no venderlo mal:
*"En Tier 3 puedes verificar que los registros que tienes no fueron manipulados, y
**no** tienes garantía de que el registro esté completo. Un agente podría actuar fuera del
registro."* La garantía de completitud ("sin evidencia, la acción no ocurrió") es Tier 4,
y exige el gate *"no proof, no write"* (C8.3.3) con el halt aplicado **fuera del control
del operador** (C8.3.5).

### Mapa de qué falta para cada escalón

- **Para Tier 3:** (a) TEE real con la clave de firma en `REPORT_DATA` [C7.2.4]; (b) anclaje
  externo con raíces publicadas y monitores [C8.1.7, C7.3.3]; (c) procedimiento y tooling de
  verificación **publicados, versionados y usables sin NDA ni credenciales del operador**
  [C8.1.8]; (d) **una ejecución de verificación grabada hecha por un tercero sin
  credenciales del operador** [C8.1.5] — este último es el test que zanja el asunto, y hay
  que poder repetirlo delante del auditor.
- **Para Tier 4:** todo lo anterior **más** el gate mecánico de operación [C8.3.3], el halt
  fuera del control del operador [C8.3.5], inventario de interacciones por interacción
  [C8.3.1], y análisis de disponibilidad con recuperación **ejercitada** [C8.3.4].

**Regla de honestidad que se deriva y queda fijada:** hasta que existan (a) y (b), en
ningún material público — landing, README, deck, claim register — puede aparecer la frase
"Proof-of-Control" ni ninguna paráfrasis equivalente. Se dice **"evidencia conforme al
esquema PoC, verificable por auditor"**, que es verdad exacta hoy.

---

## 5 ter. Estado real de la implementación (actualizado 2026-10-02)

Tabla de lo que está verificado y lo que no. **Esta tabla es la fuente de verdad**: si el
código y esta tabla discrepan, manda esta tabla hasta que se corrija una de las dos.

| Componente | Fichero | Tests | Estado |
|---|---|---|---|
| Esquema canónico PoC | `gateway/poc_schema.py` | 62/62 | **Verificado**, incl. conformidad contra los 17 vectores de la norma |
| Atestador (emisor/atestador separados) | `gateway/attestation.py` | 15/15 | **Verificado**, sin fallback silencioso |
| Overwatch (emisor + cadena) | `gateway/overwatch.py` | 87/87 | **Verificado**, gate fail-closed |
| Merkle — inclusión | `gateway/merkle.py` | 40+ | **Verificado** exhaustivamente (tamaños 1..40 × todos los índices) |
| Merkle — inclusión | `gateway/merkle.py` | 2080/2080 | **Verificado** (tamaños 1..64 × todos los índices) |
| Merkle — consistencia | `gateway/merkle.py` | 2016/2016 + 190/190 vs Go | **Verificado.** Port de `transparency-dev/merkle`, idéntico al oráculo Go byte a byte |

### Merkle consistencia: cómo se cerró

La prueba de **consistencia** (C7.3.5) **está implementada y verificada**. Tras cinco
intentos fallidos de reimplementarla "a ojo" (funcionaba solo en potencias de dos
limpias), se **portó** `transparency-dev/merkle` (Go, la de Certificate
Transparency) a `gateway/merkle.py`, y se verificó de tres formas independientes:

1. La referencia Go pasa sus propios tests (`go test ./proof/... ./compact/...`: ok).
2. El port Python produce pruebas **byte a byte idénticas** a un oráculo Go
   (`cmd/oracle` en el clone `/tmp/tdmerkle`): **190/190 pares** (f, n) con n≤20.
3. Verificación cruzada constructores↔verificadores en Python: 2016/2016 (n≤64) y
   2080/2080 en inclusión.

Los dos bugs que costaron las iteraciones, escritos para no repetirlos:

- **`nodes_for`: el hermano se añade ANTES de subir al padre**, no después. El orden
  invertido da IDs distintos de la referencia y todo lo demás falla en cascada.
- **`Rehash` combina de izquierda a derecha** con `hash = HashChildren(h[i], hash)`
  (el nuevo a la IZQUIERDA del acumulado). Combinar al revés produce hashes que
  "parecen" válidos pero no coinciden con ninguna raíz real.

Lección ampliada (también en la skill): **portar la referencia no basta con leerla —
hace falta EJECUTARLA como oráculo** y comparar byte a byte. Leer `proof.go` no habría
cazado ninguno de los dos bugs; el oráculo los señaló en segundos.

**Nota de scope:** la verificación de consistencia contra raíces ancladas (C7.3.5, el
"comparar la raíz recomputada contra el valor anclado") es la pieza que queda cuando
haya anclaje externo. El mecanismo está verificado; el anclaje espera al TEE (C8.1.7).

Por tanto, mientras no haya TEE ni anclaje externo, el `vault` **no puede anunciar
Proof-of-Control**. Puede emitir evidencia conforme al esquema y ser verificable por un
auditor con acceso, pero el claim público tiene que decir Tier 2. Y por C7.1.5, **el
claim no puede afirmar que describe acciones ejecutadas** si no se cumple 7.1.4
(mediación del canal de efecto) — que es justo lo que da la capa overwatch.

---

## 6. Cómo se prueba sin TEE

- **Esquema y canonicalización:** los **vectores publicados** de la spec
  (`schema/vectors/`, incluidos los negativos: `duplicate-key`, `untagged-digest`,
  `float-timestamp`, `modify-unbound`, `wrong-profile`, `tree-size-too-small`).
  Un vector negativo rechazado **por el motivo equivocado no es un aprobado**.
- **Cadena:** encadenado + verificación programada + test de concurrencia (N hilos × M
  emisiones → cadena intacta, sin huecos de `step_index`).
- **Frontera del auditor:** tests negativos — el auditor **no** puede leer el backup; el
  no-auditor **no** puede leer el log; cada lectura de auditor deja su registro de acceso.
- **Inclusión y consistencia:** prueba de inclusión verificada contra raíz; prueba de
  consistencia entre dos raíces; y el caso que la spec señala — reescribir un registro
  histórico **y re-firmarlo** debe ser rechazado.

---

## 7. Consecuencias

- **Positivas:** `s7oui` desaparece y se elimina una pieza entera; el log pasa a ser
  verificable por terceros sin exponer datos; el backup queda con una sola puerta; la
  evidencia cumple un esquema normativo en vez de uno inventado.
- **Negativas:** el log es legible por la allowlist, así que todo dato que entre en él
  es, en la práctica, divulgable. Eso obliga a disciplina estricta de "solo digests".
- **Coste:** el overwatch es un proceso más que desplegar y supervisar. Sin él, el techo
  de claim baja y hay que declararlo.
- **Pendiente:** TEE (AMD/Intel) para poder reclamar Tier 3; anclaje externo con
  raíces publicadas + monitores (C8.1.7, C7.3.3); firma ML-DSA del overwatch (F6);
  retirar `verify_chain` público y el endpoint HTTP del `vault` (H-01: el enlace con
  token se elimina, no se sustituye por principal). El `principal_id` está cerrado
  (opción C, §4): viene de `X-Nebulock-User` verificado contra nb2, con su ventana
  en `hermetik_credential_expiry_ns`.

## Referencias

- Norma: `/tmp/ov-poc` (`AAI-Society/ov-poc-standard`), commit `943f85d`
  - `0.1/en/0x10-C07-Evidence-Generation-and-Properties.md`
  - `schema/poc-evidence.cddl`, `schema/canonicalization.md`, `schema/vectors/`
- Skill: `proof-of-control` (Tier 1/2, hooks, pitfalls de revisión)
- Plan previo: `/opt/data/.hermes/plans/2026-09-15_111600-proof-of-control-fase-final.md`
- Auditoría: `~/security-audit-skill/hermetik/run-1/REPORT.md`
