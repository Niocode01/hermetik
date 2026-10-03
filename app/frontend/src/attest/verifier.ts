/**
 * F4 — Verificador de atestación en el cliente (ADR-01, capa 2).
 *
 * PROPÓSITO: el navegador no verifica quotes TEE de forma nativa, así que el
 * frontend los valida aquí antes de establecer el canal. Si la verificación
 * falla, se ABORTA. No hay reintento en modo dev.
 *
 * REGLA DURA (ADR-01): el modo dev NO es un fallback. Un quote `dev-unattested`
 * solo se acepta si el llamante pide EXPLÍCITAMENTE aceptarlo, y en ese caso el
 * estado se devuelve para que la UI lo pinte de forma permanente. Nunca hay
 * degradación automática de `attested` a `dev-unattested`.
 *
 * El vendor (AMD SEV-SNP / Intel TDX) se aísla en `vendorRoots` y en el parser
 * de `report_data`: cambiar de vendor no toca nada más de este módulo.
 */

/** Estados de atestación. `dev-unattested` es visible y explícito, nunca silencioso. */
export type AttestationState = "attested" | "dev-unattested";

export interface AttestationQuote {
  /** Base64 del quote del vendor. */
  quote: string;
  vendor: string;
  /** SHA-256 hex del binario del gateway. */
  binary_hash: string;
  /** Clave pública X25519 efímera del enclave (base64). */
  session_pub: string;
  /** Clave pública ML-KEM-768 (base64). Ausente en v1 (llega en F6). */
  kem_pub?: string;
  attestation_state: AttestationState;
  expires_at: number;
}

export interface VerificationPolicy {
  /** Raíces de confianza del vendor, indexadas por nombre. */
  vendorRoots: Record<string, string[]>;
  /** Hash del binario esperado (pinning del cliente). */
  expectedBinaryHash: string;
  /** Vendor aceptado. */
  vendor: string;
  /** Tolerancia de expiración, en ns. */
  clockSkewNs?: number;
}

export type VerifyResult =
  | { ok: true; state: AttestationState; reportData: string }
  | { ok: false; reason: string };

export class AttestationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AttestationError";
  }
}

/** Marca de las referencias y quotes de desarrollo. Espejo de `DEV_ATTEST_PREFIX`. */
export const DEV_ATTEST_PREFIX = "dev-unattested:";

/** `true` si la referencia procede de un entorno de desarrollo. */
export function isDevAttestation(ref: string): boolean {
  return ref.startsWith(DEV_ATTEST_PREFIX);
}

/**
 * Calcula lo que DEBE contener `report_data`: `sha256(nonce || binary_hash)`.
 *
 * Esto ata el quote a DOS cosas a la vez: al binario concreto (no vale un
 * enclave cualquiera) y a ESTA sesión (el nonce hace el quote no reutilizable).
 * Sin el nonce, un quote capturado en una sesión anterior serviría para siempre.
 */
export async function expectedReportData(
  nonce: string,
  binaryHash: string,
): Promise<string> {
  const data = new TextEncoder().encode(`${nonce}${binaryHash}`);
  const digest = await crypto.subtle.digest("SHA-256", data);
  return [...new Uint8Array(digest)]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * Verifica un quote. Los pasos se aplican EN ORDEN y cualquier fallo aborta.
 *
 * @param quote    respuesta de `/v1/attest`
 * @param nonce    nonce que envió ESTE cliente
 * @param policy   raíces, pinning y vendor aceptado
 * @param now      marca actual en ns (inyectable para los tests)
 * @param acceptDev si `true`, acepta explícitamente un quote de desarrollo
 */
export async function verifyQuote(
  quote: AttestationQuote,
  nonce: string,
  policy: VerificationPolicy,
  now: number = Date.now() * 1_000_000,
  acceptDev: boolean = false,
): Promise<VerifyResult> {
  // --- Paso 0: forma básica. Un quote malformado no llega ni al parser.
  if (!quote || typeof quote.quote !== "string" || quote.quote.length === 0) {
    return { ok: false, reason: "quote ausente o vacio" };
  }
  if (!nonce || nonce.length < 32) {
    return { ok: false, reason: "nonce del cliente invalido o demasiado corto" };
  }

  // --- Paso 1: modo dev. Requiere aceptación EXPLÍCITA. Nunca es automático.
  if (quote.attestation_state === "dev-unattested") {
    if (!acceptDev) {
      return {
        ok: false,
        reason:
          "el enclave no esta atestiguado (modo desarrollo) y no se acepto explicitamente",
      };
    }
    if (!isDevAttestation(quote.quote)) {
      return {
        ok: false,
        reason:
          "el estado dice desarrollo pero el quote no lleva el prefijo de desarrollo",
      };
    }
    return {
      ok: true,
      state: "dev-unattested",
      reportData: await expectedReportData(nonce, quote.binary_hash),
    };
  }

  // --- Paso 2: vendor aceptado y con raíces configuradas.
  if (quote.vendor !== policy.vendor) {
    return { ok: false, reason: `vendor inesperado: ${quote.vendor}` };
  }
  const roots = policy.vendorRoots[policy.vendor];
  if (!roots || roots.length === 0) {
    return { ok: false, reason: `sin raices configuradas para ${policy.vendor}` };
  }

  // --- Paso 3: estructura del quote. Un quote sin formato de vendor no tiene
  // nada mas que comprobar, asi que este es el primer filtro real.
  const chain = parseQuoteChain(quote.quote);
  const actual = extractReportData(quote.quote);
  if (chain.length === 0 || actual === null) {
    return { ok: false, reason: "cadena del quote vacia o ilegible" };
  }

  // --- Paso 4: la cadena debe encadenar hasta una raiz conocida.
  if (!roots.includes(chain[chain.length - 1])) {
    return { ok: false, reason: "la cadena no encadena hasta una raiz conocida" };
  }

  // --- Paso 5: la firma debe ser valida.
  if (!verifySignature(quote.quote)) {
    return { ok: false, reason: "firma del quote invalida" };
  }

  // --- Paso 6: pinning del binario. Un enclave genuino de OTRO binario no vale.
  // Se comprueba ANTES del ligado de sesion: si el binario no es el esperado,
  // el motivo relevante es ese, no una discrepancia de report_data derivada.
  if (quote.binary_hash !== policy.expectedBinaryHash) {
    return { ok: false, reason: "el hash del binario no coincide con el esperado" };
  }

  // --- Paso 7: el quote debe estar ligado a ESTA sesion y a ESTE binario.
  const expected = await expectedReportData(nonce, quote.binary_hash);
  if (actual !== expected) {
    return {
      ok: false,
      reason: "report_data no corresponde al nonce de esta sesion y al binario",
    };
  }

  // --- Paso 8: frescura. Se comprueba al final para que un quote caducado
  // siga siendo rechazado por caducidad y no enmascarado por otro motivo.
  const skew = policy.clockSkewNs ?? 60_000_000_000;
  if (now - skew > quote.expires_at) {
    return { ok: false, reason: "quote caducado" };
  }

  return { ok: true, state: "attested", reportData: actual };
}

// --------------------------------------------------------------- internos
// Se aíslan aquí para que el cambio de vendor (AMD/Intel) toque SOLO estas dos
// funciones: `parseQuoteChain` y `extractReportData`.

/**
 * Decodifica el quote a su forma textual canónica.
 *
 * El quote llega en base64 (formato de cable). Si la decodificación falla o el
 * resultado no tiene el formato esperado, se devuelve `null` y el llamante lo
 * trata como "ilegible": NUNCA se intenta "arreglar" un quote malformado, que
 * es como se cuelan los bypass.
 *
 * Nota de testabilidad: se acepta también un quote ya en texto plano con el
 * formato correcto, para poder ejercitar el verificador sin TEE (ADR-01, Nivel 2).
 */
function decodeQuote(quoteRaw: string): string | null {
  let raw: string;
  try {
    raw = atob(quoteRaw);
  } catch {
    raw = quoteRaw; // puede ser texto plano en pruebas
  }
  const sep = raw.indexOf("|");
  if (sep <= 0) return null;
  const rd = raw.slice(0, sep).trim().toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(rd)) return null;
  return raw;
}

/**
 * Extrae la cadena de certificados del quote (de hoja a raiz).
 * La firma (`sig=...`) NO es parte de la cadena: se excluye explicitamente.
 * Incluirla hacia que la ultima entrada nunca coincidiera con una raiz conocida
 * y que todo quote fallara por el motivo equivocado.
 */
function parseQuoteChain(quoteRaw: string): string[] {
  const raw = decodeQuote(quoteRaw);
  if (raw === null) return [];
  const sep = raw.indexOf("|");
  return raw
    .slice(sep + 1)
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s.length > 0 && !s.startsWith("sig="));
}

/** Extrae `report_data` (hex) del quote. Específico del formato del vendor. */
function extractReportData(quoteRaw: string): string | null {
  const raw = decodeQuote(quoteRaw);
  if (raw === null) return null;
  return raw.slice(0, raw.indexOf("|")).trim().toLowerCase();
}

/** Verificación de firma. Sustituir por la real del vendor. */
function verifySignature(quoteRaw: string): boolean {
  const raw = decodeQuote(quoteRaw);
  if (raw === null) return false;
  return raw.includes("sig=") && !raw.includes("sig=invalid");
}

/**
 * Construye un quote de desarrollo. SOLO para tests y para el mock del gateway.
 * Lleva el prefijo obligatorio y una firma que el verificador acepta únicamente
 * por la vía de `acceptDev`.
 */
export async function buildDevQuote(
  nonce: string,
  binaryHash: string,
  sessionPub: string,
  expiresAt: number,
): Promise<AttestationQuote> {
  const rd = await expectedReportData(nonce, binaryHash);
  return {
    quote: `${DEV_ATTEST_PREFIX}${rd}|dev-root,sig=dev`,
    vendor: "dev",
    binary_hash: binaryHash,
    session_pub: sessionPub,
    attestation_state: "dev-unattested",
    expires_at: expiresAt,
  };
}

/** Construye un quote con forma de producción (para tests y para el Nivel 2). */
export function buildQuote(opts: {
  reportData: string;
  vendor: string;
  roots: string[];
  binaryHash: string;
  sessionPub: string;
  expiresAt: number;
  signatureValid?: boolean;
}): AttestationQuote {
  const sig = opts.signatureValid === false ? "sig=invalid" : "sig=ok";
  return {
    quote: `${opts.reportData}|${opts.roots.join(",")},${sig}`,
    vendor: opts.vendor,
    binary_hash: opts.binaryHash,
    session_pub: opts.sessionPub,
    attestation_state: "attested",
    expires_at: opts.expiresAt,
  };
}
