import { describe, expect, it, beforeEach } from "vitest";
import "fake-indexeddb/auto";
import { createVault, unlockVault, b64encode, b64decode, VAULT_MAGIC, VAULT_VERSION, PBKDF2_ITERATIONS } from "./crypto";
import type { VaultPayload } from "./schema";

// fake-indexeddb no provee localStorage: stub mínimo en memoria.
if (typeof localStorage === "undefined") {
  const mem = new Map<string, string>();
  (globalThis as Record<string, unknown>).localStorage = {
    getItem: (k: string) => (mem.has(k) ? mem.get(k)! : null),
    setItem: (k: string, v: string) => void mem.set(k, String(v)),
    removeItem: (k: string) => void mem.delete(k),
    clear: () => mem.clear(),
    key: (i: number) => [...mem.keys()][i] ?? null,
    get length() {
      return mem.size;
    },
  };
}

function samplePayload(): VaultPayload {
  return {
    createdAt: "2026-09-13T00:00:00.000Z",
    updatedAt: "2026-09-13T00:00:00.000Z",
    gatewayUrl: "http://localhost:18643",
    messages: [{ role: "user", content: "hola", ts: 1 }],
  };
}

describe("vault crypto (Task 8)", () => {
  it("roundtrip crear → desbloquear devuelve el payload", async () => {
    const env = await createVault("correcta-123", samplePayload());
    expect(env.magic).toBe(VAULT_MAGIC);
    expect(env.version).toBe(VAULT_VERSION);
    expect(env.kdf.iterations).toBe(PBKDF2_ITERATIONS);
    const back = await unlockVault("correcta-123", env);
    expect(back).toEqual(samplePayload());
  }, 60_000);

  it("contraseña incorrecta rechaza", async () => {
    const env = await createVault("correcta-123", samplePayload());
    await expect(unlockVault("otra-clave", env)).rejects.toThrow();
  }, 60_000);

  it("vaultId manipulado rechaza (AAD ligado a vaultId)", async () => {
    const env = await createVault("correcta-123", samplePayload());
    const tampered = { ...env, vaultId: "vault-impostor" };
    await expect(unlockVault("correcta-123", tampered)).rejects.toThrow();
  }, 60_000);

  it("ciphertext manipulado rechaza (integridad AES-GCM)", async () => {
    const env = await createVault("correcta-123", samplePayload());
    const raw = b64decode(env.ciphertextB64);
    raw[0] ^= 0xff;
    const tampered = { ...env, ciphertextB64: b64encode(raw) };
    await expect(unlockVault("correcta-123", tampered)).rejects.toThrow();
  }, 60_000);

  it("envelope con magic/version inválidos rechaza sin intentar descifrar", async () => {
    const env = await createVault("correcta-123", samplePayload());
    await expect(
      unlockVault("correcta-123", { ...env, magic: "otro" as never }),
    ).rejects.toThrow(/magic/);
    await expect(
      unlockVault("correcta-123", { ...env, version: 99 as never }),
    ).rejects.toThrow(/version/);
  }, 60_000);

  it("envelope con KDF degradado rechaza (iterations exactas)", async () => {
    const env = await createVault("correcta-123", samplePayload());
    await expect(
      unlockVault("correcta-123", { ...env, kdf: { ...env.kdf, iterations: 1000 } }),
    ).rejects.toThrow(/KDF/);
  }, 60_000);

  it("envelope con sal/IV de longitud mala rechaza", async () => {
    const env = await createVault("correcta-123", samplePayload());
    await expect(
      unlockVault("correcta-123", { ...env, kdf: { ...env.kdf, saltB64: b64encode(new Uint8Array(8)) } }),
    ).rejects.toThrow(/sal\/IV/);
    await expect(
      unlockVault("correcta-123", { ...env, cipher: { ...env.cipher, ivB64: b64encode(new Uint8Array(8)) } }),
    ).rejects.toThrow(/sal\/IV/);
  }, 60_000);
});

describe("vault store: IndexedDB (Task 8)", () => {
  beforeEach(() => {
    localStorage.clear();
  });

  it("persistencia roundtrip: guardar → cargar → desbloquear", async () => {
    const { saveEnvelope, loadEnvelope } = await import("./store");
    const env = await createVault("clave-idb", samplePayload());
    await saveEnvelope(env);
    const loaded = await loadEnvelope(env.vaultId);
    expect(loaded).toEqual(env);
    const back = await unlockVault("clave-idb", loaded!);
    expect(back.messages).toHaveLength(1);
  }, 60_000);

  it("loadEnvelope de vault inexistente devuelve null", async () => {
    const { loadEnvelope } = await import("./store");
    expect(await loadEnvelope("vault-que-no-existe")).toBeNull();
  });

  it("NO guarda secretos en localStorage (solo gatewayUrl pública)", async () => {
    const { VaultStore, loadEnvelope, GATEWAY_URL_KEY } = await import("./store");
    const store = new VaultStore();
    await store.create("clave-ls", samplePayload());
    const env = (await loadEnvelope(store.vaultId()!))!;
    // La URL del gateway sí puede ir en localStorage (pública, no secreta).
    expect(localStorage.getItem(GATEWAY_URL_KEY)).toBe("http://localhost:18643");
    // Pero ningún secreto: ni ciphertext, ni salt, ni iv.
    const dump = JSON.stringify(
      Object.fromEntries(
        Array.from({ length: localStorage.length }, (_, i) => {
          const k = localStorage.key(i)!;
          return [k, localStorage.getItem(k)];
        }),
      ),
    );
    expect(dump).not.toContain(env.ciphertextB64);
    expect(dump).not.toContain(env.kdf.saltB64);
    expect(dump).not.toContain(env.cipher.ivB64);
  }, 60_000);

  it("VaultStore: create → lock → unlock → update → lock", async () => {
    const { VaultStore } = await import("./store");
    const store = new VaultStore();
    expect(store.isUnlocked()).toBe(false);
    const id = await store.create("mi-clave", samplePayload());
    expect(store.isUnlocked()).toBe(true);
    expect(store.vaultId()).toBe(id);
    store.lock();
    expect(store.isUnlocked()).toBe(false);
    await store.unlock("mi-clave", id);
    expect(store.getPayload().messages).toHaveLength(1);
    await store.putMessage({ role: "assistant", content: "hola de vuelta", ts: 2 });
    expect(store.getPayload().messages).toHaveLength(2);
    store.lock();
    // Tras bloquear, la clave sale de memoria: re-desbloquear desde IndexedDB.
    const store2 = new VaultStore();
    await store2.unlock("mi-clave", id);
    expect(store2.getPayload().messages).toHaveLength(2);
  }, 120_000);
});
