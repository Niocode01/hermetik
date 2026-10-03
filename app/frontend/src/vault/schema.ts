// Task 8 — Bóveda cifrada: esquema del envelope `nebulock-vault` v1.
//
// El envelope contiene SOLO metadatos públicos + ciphertext. Nunca la clave.
// La clave derivada vive únicamente en memoria mientras la bóveda está
// desbloqueada y se borra con `lock()`.

/** Marca mágica del envelope. Rechazar cualquier otro valor. */
export const VAULT_MAGIC = "nebulock-vault" as const;

/** Versión actual del formato del envelope. */
export const VAULT_VERSION = 1 as const;

/** PBKDF2-SHA256 con 600k iteraciones (diseño probado del v1). */
export const PBKDF2_ITERATIONS = 600_000;

/** Longitud de sal (bytes) y de IV para AES-GCM (bytes). */
export const SALT_LEN = 16;
export const IV_LEN = 12;

/** Mensaje de chat guardado en la bóveda (historial local cifrado). */
export interface VaultMessage {
  role: "user" | "assistant" | "system";
  content: string;
  /** epoch ms */
  ts: number;
}

/** Payload en claro: TODO lo sensible vive aquí, serializado y cifrado. */
export interface VaultPayload {
  createdAt: string;
  updatedAt: string;
  /** URL pública del gateway (también espejada en localStorage, no secreta). */
  gatewayUrl: string;
  /** Historial legacy (una sola conversación). Se mantiene como espejo del
   *  chat activo para no romper lectores viejos; la fuente de verdad
   *  multi-chat son `chats` + `activeChatId` cuando existen. */
  messages: VaultMessage[];
  /** Decisiones `always` (Task 14): viven cifradas; revocar es solo UI. */
  alwaysApprovals?: import("../chat/approvals").AlwaysApprovalRule[];
  /** Multi-chat: cada chat = array de mensajes. Ausente en bóvedas legacy. */
  chats?: Record<string, VaultMessage[]>;
  /** Id del chat activo. Ausente en bóvedas legacy. */
  activeChatId?: string;
  /** Títulos por chat (auto: primeros ~40 chars del primer mensaje de usuario). */
  chatTitles?: Record<string, string>;
}

/** Envelope persistido en IndexedDB (sin secretos en claro). */
export interface VaultEnvelope {
  magic: typeof VAULT_MAGIC;
  version: typeof VAULT_VERSION;
  /** UUID v4 generado al crear la bóveda; ligado al AAD de AES-GCM. */
  vaultId: string;
  kdf: {
    algo: "PBKDF2-SHA256";
    iterations: number;
    saltB64: string;
  };
  cipher: {
    algo: "AES-GCM-256";
    ivB64: string;
  };
  /** AAD = utf8("nebulock-vault/v1/" + vaultId). */
  aadB64: string;
  ciphertextB64: string;
}

/** Valida la forma del envelope. Lanza si magic/version son inválidos. */
export function assertEnvelopeShape(env: VaultEnvelope): void {
  if (env.magic !== VAULT_MAGIC) {
    throw new Error(`vault: magic inválido (${String(env.magic)})`);
  }
  if (env.version !== VAULT_VERSION) {
    throw new Error(`vault: version no soportada (${String(env.version)})`);
  }
  // Reserva de auditoría (mainnet): el KDF se exige EXACTO, no "cualquiera
  // >0". Un envelope plantado con iterations:1000 degradaría la KDF.
  if (env.kdf.algo !== "PBKDF2-SHA256" || env.kdf.iterations !== PBKDF2_ITERATIONS) {
    throw new Error("vault: parámetros KDF inválidos");
  }
  // Longitudes exactas tras b64decode: sal 16 B, IV 12 B (AES-GCM-96).
  if (b64len(env.kdf.saltB64) !== SALT_LEN || b64len(env.cipher.ivB64) !== IV_LEN) {
    throw new Error("vault: sal/IV con longitud inválida");
  }
  if (env.cipher.algo !== "AES-GCM-256") {
    throw new Error("vault: algoritmo de cifra no soportado");
  }
  if (!env.vaultId || !env.kdf.saltB64 || !env.cipher.ivB64 || !env.ciphertextB64) {
    throw new Error("vault: envelope incompleto");
  }
}

/** Longitud en bytes de un base64 (sin decodificar del todo). */
function b64len(b64: string): number {
  const s = (b64 || "").replace(/\s+/g, "");
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(s) || s.length % 4 !== 0) return -1;
  const pad = s.endsWith("==") ? 2 : s.endsWith("=") ? 1 : 0;
  return (s.length / 4) * 3 - pad;
}
