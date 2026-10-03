// Task 10 — Cifrado en reposo de notas de voz + bloques `[audio]` en el chat.
//
// - El blob grabado se cifra con AES-GCM-256 cuya clave deriva de la
//   contraseña de la bóveda (PBKDF2-SHA256 600k, mismos parámetros que la
//   bóveda: reutiliza `PBKDF2_ITERATIONS`, `SALT_LEN`, `IV_LEN` de vault).
//   El AAD liga vaultId + mime: descifrar bajo otro vaultId (o con el mime
//   manipulado) falla por autenticación GCM.
// - Transporte hacia el agente: al enviar, el blob descifrado se adjunta como
//   base64 dentro del texto del mensaje con el formato `[audio:mime;base64]`
//   (+ duración opcional). El agente lo transcribe con su tool Whisper; el
//   audio sale del dispositivo hacia el gateway (aviso visible en la UI).
// - Ojo costes: 600k iteraciones de PBKDF2 tardan ~1 s; los tests usan
//   `iterations` bajo vía opts. En producción la contraseña de la bóveda se
//   pide una vez por sesión y el cifrado de una nota lo paga una vez.

import { IV_LEN, SALT_LEN } from "../vault/schema";
import { PBKDF2_ITERATIONS, VAULT_MAGIC, VAULT_VERSION, b64encode, b64decode } from "../vault/crypto";
import { MAX_AUDIO_BYTES } from "./recorder";

const AUDIO_AAD_PREFIX = `${VAULT_MAGIC}/v${VAULT_VERSION}/audio`;

/** Nota de voz cifrada (reposo en IndexedDB). Sin bytes en claro. */
export interface EncryptedAudio {
  magic: "nebulock-audio";
  version: 1;
  vaultId: string;
  mime: string;
  durationMs: number;
  kdf: { algo: "PBKDF2-SHA256"; iterations: number; saltB64: string };
  cipher: { algo: "AES-GCM-256"; ivB64: string };
  ciphertextB64: string;
}

export interface EncryptAudioOpts {
  /** Override solo para tests rápidos (prod: PBKDF2_ITERATIONS = 600k). */
  iterations?: number;
  durationMs?: number;
}

function getSubtle(): SubtleCrypto {
  const c = globalThis.crypto;
  if (!c || !c.subtle) throw new Error("voz: WebCrypto no disponible");
  return c.subtle;
}

async function deriveAudioKey(password: string, salt: Uint8Array, iterations: number): Promise<CryptoKey> {
  const subtle = getSubtle();
  const base = await subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, [
    "deriveKey",
  ]);
  return subtle.deriveKey(
    { name: "PBKDF2", salt: salt as BufferSource, iterations, hash: "SHA-256" },
    base,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

function assertAudioMime(mime: string): void {
  const m = mime.split(";")[0].trim().toLowerCase();
  if (!m.startsWith("audio/")) throw new Error(`voz: mime no-audio rechazado (${mime})`);
}

/** AAD que liga el blob a su bóveda y a su mime. Exportado para inspección. */
export function audioAad(vaultId: string, mime: string): Uint8Array {
  return new TextEncoder().encode(`${AUDIO_AAD_PREFIX}/${vaultId}/${mime}`);
}

/** Cifra los bytes de la nota con la contraseña de la bóveda. */
export async function encryptAudio(
  password: string,
  vaultId: string,
  bytes: Uint8Array,
  mime: string,
  opts?: EncryptAudioOpts,
): Promise<EncryptedAudio> {
  if (!password) throw new Error("voz: contraseña vacía");
  if (!vaultId) throw new Error("voz: vaultId vacío");
  assertAudioMime(mime);
  if (bytes.byteLength > MAX_AUDIO_BYTES) {
    throw new Error(
      `voz: la nota supera el límite de 5 MiB (${(bytes.byteLength / 1048576).toFixed(1)} MiB)`,
    );
  }
  const iterations = opts?.iterations ?? PBKDF2_ITERATIONS;
  const salt = globalThis.crypto.getRandomValues(new Uint8Array(SALT_LEN));
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(IV_LEN));
  const key = await deriveAudioKey(password, salt, iterations);
  const aad = audioAad(vaultId, mime);
  const ct = await getSubtle().encrypt(
    { name: "AES-GCM", iv: iv as BufferSource, additionalData: aad as BufferSource },
    key,
    bytes as BufferSource,
  );
  return {
    magic: "nebulock-audio",
    version: 1,
    vaultId,
    mime,
    durationMs: opts?.durationMs ?? 0,
    kdf: { algo: "PBKDF2-SHA256", iterations, saltB64: b64encode(salt) },
    cipher: { algo: "AES-GCM-256", ivB64: b64encode(iv) },
    ciphertextB64: b64encode(new Uint8Array(ct)),
  };
}

/** Descifra una nota: re-deriva la clave y verifica el AAD (vaultId+mime). */
export async function decryptAudio(
  password: string,
  enc: EncryptedAudio,
): Promise<{ bytes: Uint8Array; mime: string; durationMs: number }> {
  if (enc.magic !== "nebulock-audio" || enc.version !== 1) {
    throw new Error("voz: envelope de audio no soportado");
  }
  if (!password) throw new Error("voz: contraseña vacía");
  assertAudioMime(enc.mime);
  const salt = b64decode(enc.kdf.saltB64);
  const iv = b64decode(enc.cipher.ivB64);
  const ct = b64decode(enc.ciphertextB64);
  const key = await deriveAudioKey(password, salt, enc.kdf.iterations);
  // El AAD se RECOMPUTA desde vaultId+mime declarados: manipularlos falla.
  const aad = audioAad(enc.vaultId, enc.mime);
  let plain: ArrayBuffer;
  try {
    plain = await getSubtle().decrypt(
      { name: "AES-GCM", iv: iv as BufferSource, additionalData: aad as BufferSource },
      key,
      ct as BufferSource,
    );
  } catch {
    throw new Error("voz: no se pudo descifrar la nota (clave incorrecta o datos manipulados)");
  }
  return { bytes: new Uint8Array(plain), mime: enc.mime, durationMs: enc.durationMs };
}

// --- Bloques `[audio:…]` embebidos en el texto del mensaje ---

/** Bloque de audio parseado desde el texto (ida o vuelta). */
export interface AudioBlock {
  /** mime tal cual (`audio/webm;codecs=opus` o `audio/mp4`). */
  mime: string;
  /** base64 crudo del audio. */
  base64: string;
  /** duración en segundos (0 si se desconoce). */
  durationSec: number;
}

// [audio:<mime>;base64,<b64>] o con duración [audio:<mime>;dur=<s>;base64,<b64>]
const AUDIO_BLOCK_RE = /\[audio:([^\];]+);(?:dur=(\d+);)?base64,([A-Za-z0-9+/=]+)\]/g;

/** Construye el bloque textual que viaja en el mensaje hacia el agente. */
export function buildAudioBlock(mime: string, base64: string, durationSec?: number): string {
  const dur = durationSec && durationSec > 0 ? `;dur=${Math.round(durationSec)}` : "";
  return `[audio:${mime}${dur};base64,${base64}]`;
}

/** Extrae todos los bloques de audio de un texto, en orden. */
export function parseAudioBlocks(text: string): AudioBlock[] {
  const out: AudioBlock[] = [];
  AUDIO_BLOCK_RE.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = AUDIO_BLOCK_RE.exec(text)) !== null) {
    out.push({ mime: m[1].trim(), base64: m[3], durationSec: m[2] ? Number(m[2]) : 0 });
  }
  return out;
}

/** true si el texto contiene al menos un bloque de audio. */
export function hasAudioBlock(text: string): boolean {
  AUDIO_BLOCK_RE.lastIndex = 0;
  return AUDIO_BLOCK_RE.test(text);
}

/** Segmento de render: texto plano o bloque de audio. */
export type AudioContentSegment =
  | { kind: "text"; text: string }
  | { kind: "audio"; block: AudioBlock };

/** Parte el contenido en segmentos texto/audio para el MessageList. */
export function splitAudioContent(text: string): AudioContentSegment[] {
  const segs: AudioContentSegment[] = [];
  AUDIO_BLOCK_RE.lastIndex = 0;
  let last = 0;
  let m: RegExpExecArray | null;
  while ((m = AUDIO_BLOCK_RE.exec(text)) !== null) {
    if (m.index > last) segs.push({ kind: "text", text: text.slice(last, m.index) });
    segs.push({
      kind: "audio",
      block: {
        mime: m[1].trim(),
        base64: m[3],
        durationSec: m[2] ? Number(m[2]) : 0,
      },
    });
    last = m.index + m[0].length;
  }
  if (last < text.length) segs.push({ kind: "text", text: text.slice(last) });
  if (segs.length === 0) segs.push({ kind: "text", text });
  return segs;
}

/** Estima los bytes de audio a partir del base64 (para mostrar tamaño). */
export function audioBytesFromB64(base64: string): number {
  const len = base64.length;
  if (len === 0) return 0;
  const pad = base64.endsWith("==") ? 2 : base64.endsWith("=") ? 1 : 0;
  return Math.floor((len * 3) / 4) - pad;
}
