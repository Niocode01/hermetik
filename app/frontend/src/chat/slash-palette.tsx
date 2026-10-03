// Paleta de slash commands: autocomplete sobre el composer + resultado efímero.
//
// - Al escribir "/" al inicio del composer se abre la lista filtrada
//   (SLASH_COMMANDS espeja la allowlist del server; el server decide: 403
//   command_not_allowed para el resto).
// - Enter/Tab/click ejecuta vía POST /v1/commands (dispatcher real, sin LLM).
// - El output se muestra como tarjeta de sistema EFÍMERA: no se guarda en la
//   bóveda ni entra al historial del LLM. Escape la cierra sin ejecutar.
// - Navegación: ↑/↓ + Enter para elegir, Escape para cerrar.
import { useEffect, useMemo, useRef } from "react";
import { SLASH_COMMANDS, type SlashCommandName } from "../gateway/types";
import { useI18n } from "../i18n";

export interface SlashPaletteProps {
  /** Texto actual del composer (para detectar "/" inicial y filtrar). */
  draft: string;
  /** El composer está ocupado con un stream (desactiva ejecución). */
  busy: boolean;
  /** Índice seleccionado controlado desde fuera (navegación por teclado). */
  selected: number;
  onSelectIndex: (i: number) => void;
  /** Ejecutar el comando elegido (el workspace hace el POST). */
  onPick: (command: string) => void;
  /** Cerrar sin ejecutar (Escape, blur). */
  onClose: () => void;
}

export function commandAtStart(draft: string): string | null {
  // Solo "/" al inicio del mensaje (con o sin texto de filtro detrás).
  // Sin espacios: "/who" sí, "/foo bar" no (sería texto normal con args).
  const m = /^\/([A-Za-z0-9_-]*)$/.exec(draft.trimStart());
  return m ? m[1].toLowerCase() : null;
}

export function SlashPalette({ draft, busy, selected, onSelectIndex, onPick, onClose }: SlashPaletteProps) {
  const { t } = useI18n();
  const filter = commandAtStart(draft);
  const listRef = useRef<HTMLUListElement>(null);

  const matches = useMemo(() => {
    if (filter === null) return [];
    if (!filter) return [...SLASH_COMMANDS];
    return SLASH_COMMANDS.filter((c) => c.startsWith(filter));
  }, [filter]);

  useEffect(() => {
    listRef.current?.querySelector<HTMLElement>(`[data-idx="${selected}"]`)?.scrollIntoView({ block: "nearest" });
  }, [selected]);

  // Escape global cuando la paleta está visible (el textarea también lo
  // maneja vía onSlashKey; esto cubre el foco en los botones de la lista).
  useEffect(() => {
    if (filter === null || matches.length === 0) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.preventDefault();
        onClose();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [filter, matches.length, onClose]);

  if (filter === null || matches.length === 0) return null;

  return (
    <div className="slash-palette" role="listbox" aria-label={t("cmd.palette")}>
      <ul ref={listRef} className="slash-list">
        {matches.map((cmd, i) => (
          <li key={cmd}>
            <button
              type="button"
              role="option"
              aria-selected={i === selected}
              data-idx={i}
              className={`slash-item${i === selected ? " selected" : ""}`}
              disabled={busy}
              onMouseEnter={() => onSelectIndex(i)}
              onClick={() => onPick(`/${cmd}`)}
            >
              <code>/{cmd}</code>
              <span className="slash-hint">{t(`cmd.desc.${cmd as SlashCommandName}`)}</span>
            </button>
          </li>
        ))}
      </ul>
      <p className="slash-foot">{t("cmd.foot")}</p>
    </div>
  );
}

/** Tarjeta de resultado efímero: output del dispatcher, fuera de la bóveda. */
export function SlashResult({ command, output, onDismiss }: { command: string; output: string; onDismiss: () => void }) {
  const { t } = useI18n();
  return (
    <div className="notice slash-result" role="status" aria-label={t("cmd.result")}>
      <div className="slash-result-head">
        <code>{command}</code>
        <button type="button" className="btn btn-sm" onClick={onDismiss} aria-label={t("cmd.dismiss")}>
          ✕
        </button>
      </div>
      <pre className="slash-output">{output || t("cmd.emptyOutput")}</pre>
    </div>
  );
}
