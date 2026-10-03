import { describe, expect, it, beforeEach } from "vitest";
import "fake-indexeddb/auto";
import { ensureChats, deriveChatTitle, nextChatId, summarizeChats } from "./chats";
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

function legacyPayload(): VaultPayload {
  return {
    createdAt: "2026-09-13T00:00:00.000Z",
    updatedAt: "2026-09-13T00:00:00.000Z",
    gatewayUrl: "http://localhost:18643",
    messages: [
      { role: "user", content: "hola, ¿qué es nebulock?", ts: 1 },
      { role: "assistant", content: "un chat privado", ts: 2 },
    ],
  };
}

describe("multi-chat: helpers (chats.ts)", () => {
  it("ensureChats migra legacy: messages → chat c1 con título auto", () => {
    const { payload, migrated } = ensureChats(legacyPayload());
    expect(migrated).toBe(true);
    expect(payload.activeChatId).toBe("c1");
    expect(payload.chats!.c1).toHaveLength(2);
    // Título = primeros ~40 chars del primer mensaje de usuario.
    expect(payload.chatTitles!.c1).toBe("hola, ¿qué es nebulock?");
    // Espejo legacy intacto.
    expect(payload.messages).toHaveLength(2);
  });

  it("ensureChats no re-migra un payload ya multi-chat", () => {
    const first = ensureChats(legacyPayload()).payload;
    const second = ensureChats(first);
    expect(second.migrated).toBe(false);
    expect(second.payload.chats!.c1).toHaveLength(2);
  });

  it("deriveChatTitle recorta a ~40 chars y cae a 'Chat N'", () => {
    expect(deriveChatTitle([], "c3")).toBe("Chat 3");
    const long = "x".repeat(100);
    const t = deriveChatTitle([{ role: "user", content: long, ts: 1 }], "c1");
    expect(t.length).toBeLessThanOrEqual(41);
    expect(t.endsWith("…")).toBe(true);
  });

  it("nextChatId + summarizeChats ordenan c1, c2, …", () => {
    expect(nextChatId({ c1: [], c2: [] })).toBe("c3");
    const { payload } = ensureChats(legacyPayload());
    payload.chats!.c2 = [];
    payload.chatTitles!.c2 = "Chat 2";
    const sums = summarizeChats(payload);
    expect(sums.map((s) => s.id)).toEqual(["c1", "c2"]);
    expect(sums[0].count).toBe(2);
    expect(sums[1].count).toBe(0);
  });
});

describe("multi-chat: VaultStore (store.ts)", () => {
  beforeEach(() => {
    localStorage.clear();
  });

  it("create arranca en c1; newChat/switch/putMessage aíslan historiales", async () => {
    const { VaultStore } = await import("./store");
    const store = new VaultStore();
    const id = await store.create("clave-multi", {
      createdAt: "2026-09-13T00:00:00.000Z",
      updatedAt: "2026-09-13T00:00:00.000Z",
      gatewayUrl: "http://localhost:18643",
      messages: [],
    });
    expect(store.activeChatId()).toBe("c1");
    expect(store.listChats()).toHaveLength(1);

    await store.putMessage({ role: "user", content: "mensaje en c1", ts: 1 });
    expect(store.activeMessages()).toHaveLength(1);
    expect(store.getPayload().messages).toHaveLength(1);
    // Título auto del primer mensaje de usuario.
    expect(store.listChats()[0].title).toBe("mensaje en c1");

    const c2 = await store.newChat();
    expect(c2).toBe("c2");
    expect(store.activeChatId()).toBe("c2");
    expect(store.activeMessages()).toHaveLength(0);
    await store.putMessage({ role: "user", content: "mensaje en c2", ts: 2 });

    const back = await store.switchChat("c1");
    expect(back).toHaveLength(1);
    expect(back[0].content).toBe("mensaje en c1");
    expect(store.getPayload().messages).toHaveLength(1);

    // Persistencia: re-desbloquear conserva ambos chats + activo c1.
    store.lock();
    const store2 = new VaultStore();
    await store2.unlock("clave-multi", id);
    expect(store2.listChats()).toHaveLength(2);
    expect(store2.activeChatId()).toBe("c1");
    await store2.switchChat("c2");
    expect(store2.activeMessages()[0].content).toBe("mensaje en c2");
  }, 120_000);

  it("unlock migra una bóveda legacy (sin chats) y la persiste", async () => {
    const { VaultStore } = await import("./store");
    const { createVault } = await import("./crypto");
    const { saveEnvelope } = await import("./store");
    // Bóveda legacy real: cifrar un payload SIN campos multi-chat.
    const env = await createVault("clave-legacy", legacyPayload());
    await saveEnvelope(env);

    const store = new VaultStore();
    const payload = await store.unlock("clave-legacy", env.vaultId);
    expect(payload.activeChatId).toBe("c1");
    expect(payload.chats!.c1).toHaveLength(2);
    expect(store.listChats()[0].title).toBe("hola, ¿qué es nebulock?");

    // La migración quedó persistida: re-desbloquear ya trae chats.
    store.lock();
    const store2 = new VaultStore();
    const payload2 = await store2.unlock("clave-legacy", env.vaultId);
    expect(payload2.chats!.c1).toHaveLength(2);
  }, 120_000);

  it("switchChat a id inexistente lanza", async () => {
    const { VaultStore } = await import("./store");
    const store = new VaultStore();
    await store.create("clave-x", {
      createdAt: "2026-09-13T00:00:00.000Z",
      updatedAt: "2026-09-13T00:00:00.000Z",
      gatewayUrl: "http://localhost:18643",
      messages: [],
    });
    await expect(store.switchChat("c99")).rejects.toThrow(/inexistente/);
  }, 120_000);
});
