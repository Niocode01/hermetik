// Task 8 — Criptografía de la bóveda (WebCrypto):
// PBKDF2-SHA256 600k iteraciones + AES-GCM-256.
// AAD = utf8("nebulock-vault/v1/" + vaultId): liga el ciphertext a su vaultId,
// así que clonar el ciphertext bajo otro vaultId NO descifra.

import {
  IV_LEN,
  PBKDF2_ITERATIONS,
  SALT_LEN,
  VAULT_MAGIC,
  VAULT_VERSION,
  assertEnvelopeShape,
  type VaultEnvelope,
  type VaultPayload,
} from "./schema";

// Re-exportados para consumidores/tests que solo importan de ./crypto.
export { VAULT_MAGIC, VAULT_VERSION, PBKDF2_ITERATIONS };

function getSubtle(): SubtleCrypto {
  const c = globalThis.crypto;
  if (!c || !c.subtle) throw new Error("vault: WebCrypto no disponible");
  return c.subtle;
}

export function b64encode(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

export function b64decode(b64: string): Uint8Array {
  const s = atob(b64);
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}

/** AAD ligado al vaultId. Exportado para tests/inspección. */
export function aadForVault(vaultId: string): Uint8Array {
  return new TextEncoder().encode(`${VAULT_MAGIC}/v${VAULT_VERSION}/${vaultId}`);
}

async function deriveKey(password: string, salt: Uint8Array): Promise<CryptoKey> {
  const subtle = getSubtle();
  const base = await subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveKey"],
  );
  return subtle.deriveKey(
    { name: "PBKDF2", salt: salt as BufferSource, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
    base,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

function newVaultId(): string {
  return globalThis.crypto.randomUUID();
}

/** Crea una bóveda nueva: genera salt/IV/vaultId, cifra el payload, devuelve el envelope. */
export async function createVault(
  password: string,
  payload: VaultPayload,
  opts?: { vaultId?: string },
): Promise<VaultEnvelope> {
  if (!password) throw new Error("vault: contraseña vacía");
  const vaultId = opts?.vaultId ?? newVaultId();
  const salt = globalThis.crypto.getRandomValues(new Uint8Array(SALT_LEN));
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(IV_LEN));
  const key = await deriveKey(password, salt);
  const aad = aadForVault(vaultId);
  const plain = new TextEncoder().encode(JSON.stringify(payload));
  const ct = await getSubtle().encrypt({ name: "AES-GCM", iv: iv as BufferSource, additionalData: aad as BufferSource }, key, plain);
  return {
    magic: VAULT_MAGIC,
    version: VAULT_VERSION,
    vaultId,
    kdf: { algo: "PBKDF2-SHA256", iterations: PBKDF2_ITERATIONS, saltB64: b64encode(salt) },
    cipher: { algo: "AES-GCM-256", ivB64: b64encode(iv) },
    aadB64: b64encode(aad),
    ciphertextB64: b64encode(new Uint8Array(ct)),
  };
}

/** Desbloquea: verifica forma, re-deriva la clave y descifra. Lanza si falla. */
export async function unlockVault(password: string, env: VaultEnvelope): Promise<VaultPayload> {
  assertEnvelopeShape(env);
  const salt = b64decode(env.kdf.saltB64);
  const iv = b64decode(env.cipher.ivB64);
  const ct = b64decode(env.ciphertextB64);
  // El AAD se RECOMPUTA desde el vaultId declarado (no se confía en aadB64):
  // si el vaultId fue manipulado, la autenticación GCM falla.
  const aad = aadForVault(env.vaultId);
  const key = await deriveKey(password, salt);
  let plain: ArrayBuffer;
  try {
    plain = await getSubtle().decrypt(
      { name: "AES-GCM", iv: iv as BufferSource, additionalData: aad as BufferSource },
      key,
      ct as BufferSource,
    );
  } catch {
    throw new Error("vault: no se pudo descifrar (contraseña incorrecta o datos manipulados)");
  }
  return JSON.parse(new TextDecoder().decode(plain)) as VaultPayload;
}

/** Re-cifra un payload con la misma contraseña (nuevo IV cada vez). */
export async function recryptVault(
  password: string,
  vaultId: string,
  payload: VaultPayload,
): Promise<VaultEnvelope> {
  if (!password) throw new Error("vault: contraseña vacía");
  const salt = globalThis.crypto.getRandomValues(new Uint8Array(SALT_LEN));
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(IV_LEN));
  const key = await deriveKey(password, salt);
  const aad = aadForVault(vaultId);
  const plain = new TextEncoder().encode(JSON.stringify(payload));
  const ct = await getSubtle().encrypt({ name: "AES-GCM", iv: iv as BufferSource, additionalData: aad as BufferSource }, key, plain);
  return {
    magic: VAULT_MAGIC,
    version: VAULT_VERSION,
    vaultId,
    kdf: { algo: "PBKDF2-SHA256", iterations: PBKDF2_ITERATIONS, saltB64: b64encode(salt) },
    cipher: { algo: "AES-GCM-256", ivB64: b64encode(iv) },
    aadB64: b64encode(aad),
    ciphertextB64: b64encode(new Uint8Array(ct)),
  };
}
