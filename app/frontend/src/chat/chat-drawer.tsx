// Task 9+ — Cajón de conversación con scroll propio + autoscroll inteligente.
//
// - El cajón (`section.chat-drawer`) tiene altura fija derivada del viewport
//   y `overflow` oculto; el `ol.messages` interno hace `overflow-y:auto`.
// - Autoscroll al fondo al llegar mensaje nuevo SOLO si el usuario ya estaba
//   abajo (umbral NEAR_BOTTOM_PX). Si ha subido a leer, no se roba el scroll
//   y aparece el botón flotante "{t("drawer.new")}" para bajar.
// - Respeta `prefers-reduced-motion`: sin scroll suave en ese caso.

import { useCallback, useEffect, useRef, useState } from "react";
import type { ReactNode, Ref } from "react";
import { MessageList } from "./message-list";
import { useI18n } from "../i18n";
import type { VaultMessage } from "../vault/schema";

const NEAR_BOTTOM_PX = 48;

export function ChatDrawer({ messages }: { messages: VaultMessage[] }) {
  const { t } = useI18n();
  const listRef = useRef<HTMLOListElement | null>(null);
  const stickRef = useRef(true);
  const [showJump, setShowJump] = useState(false);
  const reducedMotion =
    typeof window !== "undefined" &&
    typeof window.matchMedia === "function" &&
    window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  const scrollToBottom = useCallback(
    (smooth: boolean) => {
      const el = listRef.current;
      if (!el) return;
      el.scrollTo({ top: el.scrollHeight, behavior: smooth && !reducedMotion ? "smooth" : "auto" });
    },
    [reducedMotion],
  );

  const handleScroll = useCallback(() => {
    const el = listRef.current;
    if (!el) return;
    const nearBottom = el.scrollHeight - el.scrollTop - el.clientHeight <= NEAR_BOTTOM_PX;
    stickRef.current = nearBottom;
    setShowJump(!nearBottom && el.scrollHeight > el.clientHeight);
  }, []);

  // Al cambiar de chat (nº de mensajes puede bajar), re-evaluar posición.
  // Al llegar mensaje nuevo con stick activo, bajar al fondo.
  const prevLen = useRef(messages.length);
  useEffect(() => {
    const el = listRef.current;
    if (!el) return;
    const grew = messages.length >= prevLen.current;
    prevLen.current = messages.length;
    if (messages.length === 0) {
      stickRef.current = true;
      setShowJump(false);
      return;
    }
    if (grew && stickRef.current) {
      scrollToBottom(messages.length > 1);
    } else {
      handleScroll();
    }
  }, [messages, scrollToBottom, handleScroll]);

  // Al montar, empezar abajo si hay historial.
  useEffect(() => {
    scrollToBottom(false);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <section className="chat-drawer" aria-label={t("drawer.active")}>
      <ScrollableMessages messages={messages} listRef={listRef} onScroll={handleScroll} />
      {showJump && (
        <button
          type="button"
          className="scroll-jump"
          onClick={() => {
            stickRef.current = true;
            setShowJump(false);
            scrollToBottom(true);
          }}
          aria-label={t("drawer.scrollNew")}
        >
          {t("drawer.new")}
        </button>
      )}
    </section>
  );
}

function ScrollableMessages({
  messages,
  listRef,
  onScroll,
}: {
  messages: VaultMessage[];
  listRef: Ref<HTMLOListElement>;
  onScroll: () => void;
}): ReactNode {
  if (messages.length === 0) {
    return (
      <div className="chat-drawer-empty">
        <MessageList messages={messages} />
      </div>
    );
  }
  return <MessageList messages={messages} listRef={listRef} onScroll={onScroll} />;
}
