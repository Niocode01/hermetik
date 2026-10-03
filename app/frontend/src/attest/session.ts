/**
 * F4 — Establecimiento de sesión sobre canal atestiguado (ADR-01, capas 2 y 3).
 *
 * Orquesta: pedir atestación → verificar el quote → derivar la clave de sesión.
 *
 * Garantía que aporta: la clave derivada está ligada criptográficamente a la
 * evidencia del enclave. Si el enclave no es el que se atestiguó, la clave es
 * distinta y el canal falla al primer mensaje cifrado. La atestación NO es un
 * chequeo decorativo del principio: queda atada a la sesión.
 *
 * REGLA DURA: el modo dev NO es un fallback. Si el quote no verifica, se lanza.
 * Nunca se reintenta en modo dev automáticamente.
 */
import {
  verifyQuote,
  AttestationError,
  type AttestationQuote,
  type AttestationState,
  type VerificationPolicy,
} from "./verifier";

export interface SessionKeys {
  /** Clave MAESTRA de sesión (material HKDF exportable, NO cifra). */
  key: CryptoKey;
  /** Subclave de envío del cliente (c2s): con esta se SELLA hacia el gateway. */
  txKey: CryptoKey;
  /** Subclave de recepción del cliente (s2c): con esta se ABRE lo del gateway. */
  rxKey: CryptoKey;
  /** Handle opaco que el gateway devuelve al cerrar el handshake. */
  sessionId: string;
  /** Estado real de la sesión, para que la UI lo pinte. Nunca se oculta. */
  state: AttestationState;
  /** Texto listo para mostrar al usuario cuando la sesión no está atestiguada. */
  warning: string | null;
}

export interface SessionOptions {
  baseUrl: string;
  policy: VerificationPolicy;
  /** Aceptar explícitamente un enclave sin atestiguar (solo desarrollo). */
  acceptUnattested?: boolean;
  fetchImpl?: typeof fetch;
  now?: () => number;
}

/** Genera la clave pública efímera del cliente (X25519). */
async function generateClientKeyPair(): Promise<CryptoKeyPair> {
  const k: unknown = await crypto.subtle.generateKey(
    { name: "X25519" } as unknown as AlgorithmIdentifier,
    true,
    ["deriveKey", "deriveBits"],
  );
  if (typeof k !== "object" || k === null || !("privateKey" in k) || !("publicKey" in k)) {
    throw new Error("X25519 no disponible en este navegador");
  }
  return k as CryptoKeyPair;
}

async function exportRaw(key: CryptoKey): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.exportKey("raw", key));
}

function toHex(bytes: Uint8Array): string {
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** Nonce de sesión: 32 bytes aleatorios. Impide reutilizar un quote capturado. */
export function newNonce(): string {
  const b = new Uint8Array(32);
  crypto.getRandomValues(b);
  return toHex(b);
}

/**
 * Deriva la clave MAESTRA de sesión.
 *
 * `report_data` entra en el material de entrada: es lo que ata la clave a la
 * evidencia del enclave. Sin esto, el handshake sería un X25519 normal y un
 * intermediario activo podría completarlo sin ser el enclave atestiguado.
 */
async function deriveSessionKey(
  shared: Uint8Array,
  reportData: string,
  transcript: string,
): Promise<CryptoKey> {
  const ikm = new Uint8Array(shared.length + reportData.length);
  ikm.set(shared, 0);
  ikm.set(new TextEncoder().encode(reportData), shared.length);

  const base = await crypto.subtle.importKey("raw", ikm, "HKDF", false, ["deriveBits"]);
  // Maestra como BITS exportables (no como AES-GCM): WebCrypto exige que la
  // base tenga uso deriveBits/deriveKey para expandir a c2s/s2c. La maestra
  // NO cifra nunca; solo se expande y se verifica por hash (session_id).
  const masterBits = await crypto.subtle.deriveBits(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: new TextEncoder().encode(transcript),
      info: new TextEncoder().encode("hermetik/v1"),
    },
    base,
    256,
  );
  const masterRaw = new Uint8Array(masterBits);
  // HKDF no admite extractable=true: la maestra queda NO exportable (mejor:
  // nunca sale de WebCrypto) y solo se expande a c2s/s2c con deriveKey.
  return crypto.subtle.importKey("raw", masterRaw, "HKDF", false, ["deriveKey"]);
}

/**
 * Subclave direccional desde la maestra: HKDF-SHA256(maestra, salt="", info).
 * Espejo de `derive_directional_keys` en `gateway/attest_server.py`:
 * `hermetik/v1/c2s` y `hermetik/v1/s2c`. Cada dirección cifra con su propia
 * clave → cada (clave, nonce) AES-GCM se usa una sola vez (run-5 HUNT-B-01).
 */
async function deriveDirectionalKey(master: CryptoKey, info: string): Promise<CryptoKey> {
  return crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: new Uint8Array(0),
      info: new TextEncoder().encode(info),
    },
    master,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

/**
 * Establece la sesión con el gateway.
 *
 * @throws AttestationError si el quote no verifica. NO hay reintento en modo dev.
 */
export async function establishSession(opts: SessionOptions): Promise<SessionKeys> {
  const doFetch = opts.fetchImpl ?? fetch;
  const now = opts.now ?? (() => Date.now() * 1_000_000);

  // 1. Nonce propio: garantiza que el quote es de ESTA sesión.
  const nonce = newNonce();

  // 2. Pedir atestación.
  const attRes = await doFetch(
    `${opts.baseUrl}/v1/attest?nonce=${encodeURIComponent(nonce)}`,
    { method: "GET" },
  );
  if (!attRes.ok) {
    throw new AttestationError(`no se pudo obtener atestacion: HTTP ${attRes.status}`);
  }
  const quote = (await attRes.json()) as AttestationQuote;

  // 3. Verificar. Cualquier fallo aborta aquí: no se envía nada más.
  const verdict = await verifyQuote(
    quote,
    nonce,
    opts.policy,
    now(),
    opts.acceptUnattested ?? false,
  );
  if (!verdict.ok) {
    throw new AttestationError(`atestacion rechazada: ${verdict.reason}`);
  }

  // 4. Par de claves efímero del cliente.
  const clientPair = await generateClientKeyPair();
  const clientPubRaw = await exportRaw(clientPair.publicKey);

  // 5. Intercambio. La clave pública del enclave viene del quote ya verificado,
  //    asi que no puede haber sido sustituida por un intermediario.
  const peerPub = await crypto.subtle.importKey(
    "raw",
    Uint8Array.from(atob(quote.session_pub), (c) => c.charCodeAt(0)),
    { name: "X25519" } as unknown as AlgorithmIdentifier,
    false,
    [],
  );
  const sharedBits = await crypto.subtle.deriveBits(
    { name: "X25519", public: peerPub } as unknown as AlgorithmIdentifier,
    clientPair.privateKey,
    256,
  );

  // 6. Transcripcion: ata la clave a todos los datos publicos del handshake.
  const transcript = [
    nonce,
    toHex(clientPubRaw),
    quote.session_pub,
    verdict.reportData,
    quote.vendor,
  ].join("|");

  const key = await deriveSessionKey(
    new Uint8Array(sharedBits),
    verdict.reportData,
    transcript,
  );
  // Subclaves direccionales (run-5 B-01): el cliente SELLA con c2s y ABRE con
  // s2c; el servidor al revés. La maestra (`key`) no cifra nunca.
  const txKey = await deriveDirectionalKey(key, "hermetik/v1/c2s");
  const rxKey = await deriveDirectionalKey(key, "hermetik/v1/s2c");

  // 7. Cerrar el handshake: enviamos nuestra clave pública al servidor para
  //    que derive el MISMO secreto compartido (ADR-01, paso 3). Sin este paso
  //    el servidor no puede descifrar nada de lo que cifremos: la sesión
  //    quedaría "a medias". Fail-closed: si el servidor no confirma con un
  //    session_id, se aborta.
  const sessionRes = await doFetch(`${opts.baseUrl}/v1/session`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      nonce,
      client_pub: btoa(String.fromCharCode(...clientPubRaw)),
    }),
  });
  if (!sessionRes.ok) {
    throw new AttestationError(`no se pudo cerrar la sesion: HTTP ${sessionRes.status}`);
  }
  let sessionId = "";
  try {
    const body = (await sessionRes.json()) as Record<string, unknown>;
    sessionId = typeof body["session_id"] === "string" ? body["session_id"] : "";
  } catch {
    sessionId = "";
  }
  if (!sessionId) {
    throw new AttestationError("el servidor no devolvio session_id (handshake incompleto)");
  }

  return {
    key,
    txKey,
    rxKey,
    sessionId,
    state: verdict.state,
    warning:
      verdict.state === "dev-unattested"
        ? "Enclave SIN atestiguar (modo desarrollo): la garantia de confidencialidad NO esta activa."
        : null,
  };
}

/** Cifra un mensaje con la clave de sesión (ChaCha20-Poly1305 no es nativo; AES-GCM sí). */
export async function sealMessage(
  key: CryptoKey,
  seq: number,
  plaintext: string,
): Promise<string> {
  const iv = new Uint8Array(12);
  new DataView(iv.buffer).setUint32(0, seq, false);
  const ct = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    new TextEncoder().encode(plaintext),
  );
  return btoa(String.fromCharCode(...new Uint8Array(ct)));
}

/** Descifra un mensaje. El contador de secuencia debe ser estrictamente creciente. */
export async function openMessage(
  key: CryptoKey,
  seq: number,
  sealed: string,
): Promise<string> {
  const iv = new Uint8Array(12);
  new DataView(iv.buffer).setUint32(0, seq, false);
  const pt = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv },
    key,
    Uint8Array.from(atob(sealed), (c) => c.charCodeAt(0)),
  );
  return new TextDecoder().decode(pt);
}
