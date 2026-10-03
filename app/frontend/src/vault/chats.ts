// Multi-chat: normalización, títulos e ids de chat.
//
// - Bóvedas legacy (sin `chats`): se migran moviendo `messages` al chat `c1`.
// - `messages` legacy se mantiene como espejo del chat activo.
// - Título auto = primeros ~40 chars del primer mensaje de usuario, o "Chat N".

import type { VaultMessage, VaultPayload } from "./schema";

export const FIRST_CHAT_ID = "c1";
export const TITLE_MAX = 40;

export interface ChatSummary {
  id: string;
  title: string;
  count: number;
  /** ts del último mensaje, o null si el chat está vacío. */
  updatedAt: number | null;
}

/** Nº del chat desde su id (`c1` → 1). -1 si no tiene forma `c<N>`. */
export function chatNumber(id: string): number {
  const m = /^c(\d+)$/.exec(id);
  return m ? parseInt(m[1], 10) : -1;
}

/** Siguiente id libre (`c<max+1>`). */
export function nextChatId(chats: Record<string, VaultMessage[]>): string {
  let max = 0;
  for (const id of Object.keys(chats)) {
    const n = chatNumber(id);
    if (n > max) max = n;
  }
  return `c${max + 1}`;
}

/** Título automático: primer mensaje de usuario recortado, o `Chat N`. */
export function deriveChatTitle(msgs: VaultMessage[], id: string): string {
  const first = msgs.find((m) => m.role === "user");
  if (first) {
    const flat = first.content.replace(/\s+/g, " ").trim();
    if (flat) return flat.length > TITLE_MAX ? flat.slice(0, TITLE_MAX) + "…" : flat;
  }
  const n = chatNumber(id);
  return n > 0 ? `Chat ${n}` : "New chat";
}

/** Orden estable: c1, c2, …; ids con otra forma al final (alfabético). */
export function sortChatIds(ids: string[]): string[] {
  return [...ids].sort((a, b) => {
    const na = chatNumber(a);
    const nb = chatNumber(b);
    if (na > 0 && nb > 0) return na - nb;
    if (na > 0) return -1;
    if (nb > 0) return 1;
    return a.localeCompare(b);
  });
}

/**
 * Normaliza un payload a forma multi-chat (sin mutar la entrada).
 * Devuelve el payload normalizado + si hubo migración legacy.
 */
export function ensureChats(payload: VaultPayload): { payload: VaultPayload; migrated: boolean } {
  if (payload.chats && payload.activeChatId && payload.chats[payload.activeChatId]) {
    // Ya es multi-chat: rellena títulos que falten, sin tocar nada más.
    const titles = { ...(payload.chatTitles ?? {}) };
    let touched = false;
    for (const [id, msgs] of Object.entries(payload.chats)) {
      if (!titles[id]) {
        titles[id] = deriveChatTitle(msgs, id);
        touched = true;
      }
    }
    if (!touched) return { payload, migrated: false };
    return { payload: { ...payload, chatTitles: titles }, migrated: false };
  }
  // Migración legacy: `messages` → chat `c1`.
  const legacy = Array.isArray(payload.messages) ? payload.messages : [];
  const chats: Record<string, VaultMessage[]> = { [FIRST_CHAT_ID]: [...legacy] };
  // Conserva chats parciales si la bóveda trae alguno sin activeChatId válido.
  if (payload.chats) {
    for (const [id, msgs] of Object.entries(payload.chats)) {
      if (id !== FIRST_CHAT_ID && Array.isArray(msgs)) chats[id] = [...msgs];
    }
  }
  const chatTitles: Record<string, string> = { ...(payload.chatTitles ?? {}) };
  for (const [id, msgs] of Object.entries(chats)) {
    if (!chatTitles[id]) chatTitles[id] = deriveChatTitle(msgs, id);
  }
  return {
    payload: {
      ...payload,
      messages: [...legacy],
      chats,
      activeChatId: FIRST_CHAT_ID,
      chatTitles,
    },
    migrated: true,
  };
}

/** Resúmenes ordenados para la sidebar. */
export function summarizeChats(payload: VaultPayload): ChatSummary[] {
  const chats = payload.chats ?? {};
  const titles = payload.chatTitles ?? {};
  return sortChatIds(Object.keys(chats)).map((id) => {
    const msgs = chats[id] ?? [];
    return {
      id,
      title: titles[id] ?? deriveChatTitle(msgs, id),
      count: msgs.length,
      updatedAt: msgs.length > 0 ? msgs[msgs.length - 1].ts : null,
    };
  });
}
