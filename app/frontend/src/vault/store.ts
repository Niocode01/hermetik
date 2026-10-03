// Task 8 — Persistencia de la bóveda.
//
// - Secretos (envelope con salt/ciphertext): SOLO en IndexedDB (`nebulock-vaults`).
// - localStorage: SOLO la URL del gateway (pública, no secreta) para que el
//   frontend la recuerde desde el día 1 sin comprometer nada sensible.
// - La clave derivada vive solo en memoria dentro de `VaultStore` y `lock()`
//   la borra (referencia a null; el GC hace el resto).

import { recryptVault, createVault, unlockVault } from "./crypto";
import type { VaultEnvelope, VaultMessage, VaultPayload } from "./schema";
import type { ChatSummary } from "./chats";
import {
  FIRST_CHAT_ID,
  deriveChatTitle,
  ensureChats,
  nextChatId,
  summarizeChats,
} from "./chats";

export type { ChatSummary } from "./chats";

/** Clave de localStorage para la URL pública del gateway (NO secreta). */
export const GATEWAY_URL_KEY = "nebulock.gatewayUrl";

const IDB_NAME = "nebulock-vaults";
const IDB_STORE = "envelopes";
const IDB_VERSION = 1;

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(IDB_NAME, IDB_VERSION);
    req.onupgradeneeded = () => {
      req.result.createObjectStore(IDB_STORE, { keyPath: "vaultId" });
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error ?? new Error("vault: IndexedDB open falló"));
  });
}

/** Guarda/actualiza el envelope en IndexedDB + espeja gatewayUrl (pública) en localStorage. */
export async function saveEnvelope(env: VaultEnvelope): Promise<void> {
  const db = await openDb();
  try {
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction(IDB_STORE, "readwrite");
      tx.objectStore(IDB_STORE).put(structuredClone(env));
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error ?? new Error("vault: IndexedDB put falló"));
    });
  } finally {
    db.close();
  }
}

/** Carga el envelope desde IndexedDB. `null` si no existe. */
export async function loadEnvelope(vaultId: string): Promise<VaultEnvelope | null> {
  const db = await openDb();
  try {
    return await new Promise<VaultEnvelope | null>((resolve, reject) => {
      const tx = db.transaction(IDB_STORE, "readonly");
      const req = tx.objectStore(IDB_STORE).get(vaultId);
      req.onsuccess = () => resolve((req.result as VaultEnvelope | undefined) ?? null);
      req.onerror = () => reject(req.error ?? new Error("vault: IndexedDB get falló"));
    });
  } finally {
    db.close();
  }
}

/** Lista los vaultIds guardados en este navegador. */
export async function listVaultIds(): Promise<string[]> {
  const db = await openDb();
  try {
    return await new Promise<string[]>((resolve, reject) => {
      const tx = db.transaction(IDB_STORE, "readonly");
      const req = tx.objectStore(IDB_STORE).getAllKeys();
      req.onsuccess = () => resolve((req.result as IDBValidKey[]).map(String));
      req.onerror = () => reject(req.error ?? new Error("vault: IndexedDB keys falló"));
    });
  } finally {
    db.close();
  }
}

/** Lee la URL del gateway recordada (pública). */
export function getGatewayUrl(): string {
  try {
    return localStorage.getItem(GATEWAY_URL_KEY) ?? "";
  } catch {
    return "";
  }
}

/** Guarda la URL del gateway (pública, no secreta) en localStorage. */
export function setGatewayUrl(url: string): void {
  try {
    if (url) localStorage.setItem(GATEWAY_URL_KEY, url);
    else localStorage.removeItem(GATEWAY_URL_KEY);
  } catch {
    /* almacenamiento no disponible: no fatal */
  }
}

/** Estado en memoria de la bóveda desbloqueada. */
export class VaultStore {
  private password: string | null = null;
  private id: string | null = null;
  private payload: VaultPayload | null = null;

  isUnlocked(): boolean {
    return this.password !== null && this.payload !== null && this.id !== null;
  }

  vaultId(): string | null {
    return this.id;
  }

  /** Contraseña de la bóveda (solo en memoria): cifra las notas de voz en reposo. */
  vaultPassword(): string {
    if (!this.password) throw new Error("vault: bloqueada");
    return this.password;
  }

  getPayload(): VaultPayload {
    if (!this.payload) throw new Error("vault: bloqueada");
    return this.payload;
  }

  // ---------- Multi-chat ----------

  /** Garantiza forma multi-chat en memoria (migra legacy `messages` → `c1`). */
  private ensureMulti(): void {
    if (!this.payload) throw new Error("vault: bloqueada");
    const { payload } = ensureChats(this.payload);
    this.payload = payload;
  }

  /** Id del chat activo (migra legacy si hace falta). */
  activeChatId(): string {
    this.ensureMulti();
    return this.payload!.activeChatId!;
  }

  /** Mensajes del chat activo (copia). */
  activeMessages(): VaultMessage[] {
    this.ensureMulti();
    return [...(this.payload!.chats![this.payload!.activeChatId!] ?? [])];
  }

  /** Lista de chats para la sidebar (orden estable c1, c2, …). */
  listChats(): ChatSummary[] {
    this.ensureMulti();
    return summarizeChats(this.payload!);
  }

  /** Persiste el payload actual en memoria (nuevo IV) tras mutarlo. */
  private async persist(): Promise<void> {
    if (!this.password || !this.id || !this.payload) throw new Error("vault: bloqueada");
    const next: VaultPayload = { ...this.payload, updatedAt: new Date().toISOString() };
    const env = await recryptVault(this.password, this.id, next);
    await saveEnvelope(env);
    setGatewayUrl(next.gatewayUrl);
    this.payload = next;
  }

  /** Cambia de chat activo y lo persiste (para que la recarga lo recuerde). */
  async switchChat(id: string): Promise<VaultMessage[]> {
    if (!this.password || !this.id || !this.payload) throw new Error("vault: bloqueada");
    this.ensureMulti();
    if (!this.payload!.chats![id]) throw new Error(`vault: chat inexistente (${id})`);
    this.payload = {
      ...this.payload!,
      activeChatId: id,
      messages: [...this.payload!.chats![id]],
    };
    await this.persist();
    return this.activeMessages();
  }

  /** Crea un chat vacío, lo activa y lo persiste. Devuelve el nuevo id. */
  async newChat(): Promise<string> {
    if (!this.password || !this.id || !this.payload) throw new Error("vault: bloqueada");
    this.ensureMulti();
    const id = nextChatId(this.payload!.chats!);
    const n = Object.keys(this.payload!.chats!).length + 1;
    // Título provisional "Chat N" hasta el primer mensaje de usuario.
    this.payload = {
      ...this.payload!,
      chats: { ...this.payload!.chats!, [id]: [] },
      chatTitles: { ...this.payload!.chatTitles, [id]: `Chat ${n}` },
      activeChatId: id,
      messages: [],
    };
    await this.persist();
    return id;
  }

  /** Crea una bóveda nueva, la persiste y la deja desbloqueada. */
  async create(password: string, payload: VaultPayload): Promise<string> {
    const normalized = ensureChats({
      ...payload,
      messages: Array.isArray(payload.messages) ? payload.messages : [],
    }).payload;
    // Bóveda recién creada: arranca en el chat `c1`.
    normalized.activeChatId = FIRST_CHAT_ID;
    normalized.messages = [...(normalized.chats![FIRST_CHAT_ID] ?? [])];
    const env = await createVault(password, normalized);
    await saveEnvelope(env);
    setGatewayUrl(normalized.gatewayUrl);
    this.password = password;
    this.id = env.vaultId;
    this.payload = structuredClone(normalized);
    return env.vaultId;
  }

  /** Desbloquea una bóveda existente desde IndexedDB (migra legacy si toca). */
  async unlock(password: string, vaultId: string): Promise<VaultPayload> {
    const env = await loadEnvelope(vaultId);
    if (!env) throw new Error("vault: no existe");
    const raw = await unlockVault(password, env);
    const { payload, migrated } = ensureChats(raw);
    this.password = password;
    this.id = vaultId;
    this.payload = payload;
    if (migrated) {
      // Persiste la forma multi-chat para que la migración sea definitiva.
      await this.persist();
    }
    setGatewayUrl(this.payload.gatewayUrl);
    return structuredClone(this.payload);
  }

  /** Borra la clave y el payload de memoria. */
  lock(): void {
    this.password = null;
    this.payload = null;
    this.id = null;
  }

  /** Añade un mensaje al historial del CHAT ACTIVO y re-persiste (nuevo IV).
   *  `messages` legacy se mantiene como espejo del chat activo. */
  async putMessage(msg: VaultMessage): Promise<void> {
    if (!this.password || !this.id || !this.payload) throw new Error("vault: bloqueada");
    this.ensureMulti();
    const active = this.payload!.activeChatId!;
    const prev = this.payload!.chats![active] ?? [];
    const nextChat = [...prev, msg];
    const titles = { ...this.payload!.chatTitles };
    // Re-deriva el título al llegar el primer mensaje de usuario.
    if (msg.role === "user" && prev.every((m) => m.role !== "user")) {
      titles[active] = deriveChatTitle(nextChat, active);
    }
    this.payload = {
      ...this.payload!,
      chats: { ...this.payload!.chats!, [active]: nextChat },
      chatTitles: titles,
      messages: nextChat,
    };
    await this.persist();
  }

  /** Actualiza la URL del gateway (pública) y re-persiste. */
  async setGateway(url: string): Promise<void> {
    if (!this.password || !this.id || !this.payload) throw new Error("vault: bloqueada");
    const next: VaultPayload = { ...this.payload, updatedAt: new Date().toISOString(), gatewayUrl: url };
    const env = await recryptVault(this.password, this.id, next);
    await saveEnvelope(env);
    setGatewayUrl(url);
    this.payload = next;
  }

  /** Guarda las reglas `always` (Task 14) cifradas en la bóveda. */
  async setAlwaysApprovals(rules: import("../chat/approvals").AlwaysApprovalRule[]): Promise<void> {
    if (!this.password || !this.id || !this.payload) throw new Error("vault: bloqueada");
    const next: VaultPayload = { ...this.payload, updatedAt: new Date().toISOString(), alwaysApprovals: rules };
    const env = await recryptVault(this.password, this.id, next);
    await saveEnvelope(env);
    this.payload = next;
  }
}
