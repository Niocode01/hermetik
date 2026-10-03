// Task 9 — Lista de mensajes del chat (solo render; el estado vive en workspace).
import type { Ref } from "react";
import { hasAudioBlock } from "../voice/audio-store";
import { AudioMessage } from "../voice/audio-message";
import type { VaultMessage } from "../vault/schema";
import { useI18n } from "../i18n";

export function MessageList({
  messages,
  listRef,
  onScroll,
}: {
  messages: VaultMessage[];
  /** Ref al `ol.messages` para scroll propio + autoscroll (ChatDrawer). */
  listRef?: Ref<HTMLOListElement>;
  onScroll?: () => void;
}) {
  const { t } = useI18n();
  if (messages.length === 0) {
    return (
      <div className="empty-chat">
        <p className="eyebrow">{t("empty.brand")}</p>
        <h1>{t("empty.title")}</h1>
        <p>{t("empty.copy")}</p>
        <div className="mode-ghosts" aria-hidden="true">
          <span className="active">Gateway</span>
        </div>
        <div className="empty-detail">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
            <path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1 1 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z" />
            <path d="m9 12 2 2 4-4" />
          </svg>
          <span>{t("empty.encrypted")}<br />{t("empty.needConnection")}</span>
        </div>
      </div>
    );
  }
  return (
    <ol className="messages" aria-label={t("empty.list")} ref={listRef} onScroll={onScroll}>
      {messages.map((m, i) => (
        <li key={`${m.ts}-${i}`} className={`message ${m.role === "user" ? "user" : "assistant"}`}>
          <div className="message-label">
            {m.role === "user" ? t("empty.you") : m.role === "assistant" ? t("empty.agent") : t("empty.system")}
          </div>
          {m.role === "assistant" || hasAudioBlock(m.content) ? (
            <div className="message-text">
              <AudioMessage content={m.content} />
            </div>
          ) : (
            <div className="message-text">{m.content}</div>
          )}
        </li>
      ))}
    </ol>
  );
}
