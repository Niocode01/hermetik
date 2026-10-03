// Sidebar de chats: lista + botón "Nuevo chat".
//
// - Escritorio: columna fija junto al chat; el botón ✕/☰ vive en la barra
//   superior del chat (sidebar-fab en workspace.tsx).
// - Móvil (<=860px): cajón flotante sobre el chat + fondo que cierra.
// - Chat activo resaltado (`aria-current`).
// - Cada fila: título auto + nº de mensajes (+ fecha del último si existe).

import type { ChatSummary } from "../vault/chats";
import { useI18n } from "../i18n";

export function ChatSidebar({
  chats,
  activeId,
  busy,
  open,
  onToggle,
  onSelect,
  onNew,
}: {
  chats: ChatSummary[];
  activeId: string;
  busy: boolean;
  open: boolean;
  onToggle: () => void;
  onSelect: (id: string) => void;
  onNew: () => void;
}) {
  const { t } = useI18n();
  return (
    <aside className={`chats-sidebar${open ? " open" : ""}`} aria-label="Chats">
      <div className="chats-sidebar-head">
        <span className="nav-label chats-label">Chats</span>
        <button
          type="button"
          className="btn btn-sm sidebar-toggle"
          onClick={onToggle}
          aria-expanded={open}
          aria-label={open ? t("chat.hideList") : t("chat.showList")}
        >
          ✕
        </button>
      </div>
      <button
        type="button"
        className="new-chat"
        onClick={onNew}
        disabled={busy}
        aria-label={t("sidebar.newChatAria")}
      >
        {t("sidebar.newChat")}
      </button>
      {open && (
        chats.length === 0 ? (
          <p className="sidebar-hint">{t("sidebar.empty")}</p>
        ) : (
          <ol className="chats-list">
            {chats.map((c) => (
              <li key={c.id}>
                <button
                  type="button"
                  className={`chat-item${c.id === activeId ? " active" : ""}`}
                  aria-current={c.id === activeId ? "true" : undefined}
                  aria-label={`${t("sidebar.openChat")} ${c.title} (${c.count} ${t("sidebar.messages")})`}
                  onClick={() => onSelect(c.id)}
                  disabled={busy || c.id === activeId}
                >
                  <span className="chat-item-title">{c.title}</span>
                  <span className="chat-item-meta">
                    {c.count} {c.count === 1 ? "msg" : t("sidebar.messages")}
                    {c.updatedAt ? ` · ${new Date(c.updatedAt).toLocaleDateString()}` : ""}
                  </span>
                </button>
              </li>
            ))}
          </ol>
        )
      )}
    </aside>
  );
}
