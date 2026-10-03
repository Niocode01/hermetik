// Task 9 — Workspace de chat contra el gateway (transporte OpenAI-SSE).
//
// - Lista mensajes + composer con enviar/cancelar.
// - Historial persistido en la bóveda cifrada vía VaultStore.putMessage.
// - Bóveda: crear/desbloquear con contraseña + Gateway URL (localStorage
//   recuerda la URL pública; el secreto nb2 NO se persiste: vive en estado y
//   se refresca vía issue_credential al expirar/401).
// - Re-conexión con credencial fresca: ante 401/403 se pide una nueva
//   credencial vía `refreshCredential()` (makeAccessActor + issue_credential
//   en app.tsx) y se reintenta el stream UNA vez. AbortController cancela.

import { useCallback, useEffect, useRef, useState } from "react";
import { VaultStore, getGatewayUrl } from "../vault/store";
import type { ChatSummary } from "../vault/chats";
import { streamChat, sendApproval, sendSlashCommand, uploadFile, GatewayError } from "../gateway/client";
import { SLASH_COMMANDS } from "../gateway/types";
import type { ChatMessage, ApprovalChoice, SlashCommandResult } from "../gateway/types";
import { fileToDataUrl, isImageFile, type ImageAttachment } from "./composer";
import type { VaultMessage } from "../vault/schema";
import { ChatDrawer } from "./chat-drawer";
import { ChatSidebar } from "./chat-sidebar";
import { Composer } from "./composer";
import { SlashPalette, SlashResult, commandAtStart } from "./slash-palette";
// VoiceComposer oculto de momento (voz pendiente: docs/plans/voice-transcribe-first.md).
// import { VoiceComposer } from "../voice/voice-composer";
import { ApprovalCard, AlwaysRulesSection } from "./approval-card";
import { useI18n, tr } from "../i18n";
import {
  addAlwaysRule,
  applyApprovalEvent,
  revokeAlwaysRule,
  type AlwaysApprovalRule,
  type PendingApproval,
} from "./approvals";

function defaultGatewayUrl(): string {
  // Producción: Gateway URL nb2 inyectada en build (VITE_GATEWAY_URL).
  // Sin URL quemada: si no hay variable ni valor guardado, cadena vacía y la
  // UI pide introducirla (el túnel quick de Cloudflare cambia en cada reinicio).
  const viteEnv = (import.meta as unknown as { env?: Record<string, string | undefined> }).env;
  return viteEnv?.VITE_GATEWAY_URL?.trim() ?? "";
}
const DEFAULT_GATEWAY_URL = defaultGatewayUrl();
const TOOL_PREFIX = "…";

/**
 * System prompt EFÍMERO (nunca se guarda en la bóveda) que convierte el texto
 * "/new" en el comando /new real del Hermes: resetea su sesión del servidor
 * (historial, sandbox, aprobaciones) igual que en Telegram. El turno viaja al
 * gateway como un mensaje normal con este system antepuesto.
 */
const getNewCommandPrompt = (): string => tr("newCommandPrompt");

export interface WorkspaceProps {
  user: string;
  initialCredential: string;
  /** Emite una credencial nb2 fresca (issue_credential on-canister). */
  refreshCredential: () => Promise<string>;
  onCredentialRefreshed?: (cred: string) => void;
}

type VaultPhase = "loading" | "locked" | "ready";

export function ChatWorkspace({ user, initialCredential, refreshCredential, onCredentialRefreshed }: WorkspaceProps) {
  const { t } = useI18n();
  const [store] = useState(() => new VaultStore());
  const [phase, setPhase] = useState<VaultPhase>("loading");
  const [gatewayUrl, setGatewayUrl] = useState<string>(() => getGatewayUrl() || DEFAULT_GATEWAY_URL);
  const [password, setPassword] = useState("");
  const [vaultIds, setVaultIds] = useState<string[]>([]);
  const [messages, setMessages] = useState<VaultMessage[]>([]);
  // Multi-chat: resúmenes para la sidebar + id activo + sidebar móvil.
  const [chats, setChats] = useState<ChatSummary[]>([]);
  const [activeChatId, setActiveChatId] = useState<string>("");
  const [sidebarOpen, setSidebarOpen] = useState<boolean>(
    () => typeof window === "undefined" || window.innerWidth > 860,
  );
  const [chatOpError, setChatOpError] = useState("");
  const [busy, setBusy] = useState(false);
  const [toolStatus, setToolStatus] = useState<string>("");
  const [error, setError] = useState("");
  // Tasks 12-14: cola de aprobaciones pendientes + reglas `always` + errores por tarjeta.
  const [pending, setPending] = useState<PendingApproval[]>([]);
  const [alwaysRules, setAlwaysRules] = useState<AlwaysApprovalRule[]>([]);
  const [approvalBusy, setApprovalBusy] = useState<Record<string, ApprovalChoice | null>>({});
  const [approvalErrors, setApprovalErrors] = useState<Record<string, string>>({});
  const credentialRef = useRef(initialCredential);
  const abortRef = useRef<AbortController | null>(null);
  // Paleta /: draft controlado + índice + resultado efímero (fuera de bóveda).
  const [draft, setDraft] = useState("");
  const [slashIndex, setSlashIndex] = useState(0);
  const [slashResult, setSlashResult] = useState<SlashCommandResult | null>(null);
  const [slashBusy, setSlashBusy] = useState(false);
  // Adjuntos: imágenes pendientes (data URL reescalada) + subida de docs.
  const [images, setImages] = useState<ImageAttachment[]>([]);
  const [attachBusy, setAttachBusy] = useState(false);

  credentialRef.current = initialCredential || credentialRef.current;

  // Lista vaultIds existentes (IndexedDB) para desbloquear.
  useEffect(() => {
    (async () => {
      try {
        const { listVaultIds } = await import("../vault/store");
        setVaultIds(await listVaultIds());
      } catch {
        setVaultIds([]);
      } finally {
        setPhase((p) => (p === "loading" ? "locked" : p));
      }
    })();
  }, []);

  /** Sincroniza el estado multi-chat desde el store (sidebar + activo). */
  const syncChats = useCallback(() => {
    try {
      setChats(store.listChats());
      setActiveChatId(store.activeChatId());
      setMessages(store.activeMessages());
    } catch {
      /* bóveda bloqueada: no hay chats que sincronizar */
    }
  }, [store]);

  const afterUnlock = useCallback((payload: { gatewayUrl: string; messages: VaultMessage[]; alwaysApprovals?: AlwaysApprovalRule[] }) => {
    // No pisar una URL recién escrita en el campo: si el usuario la cambió
    // antes de desbloquear (bóveda bloqueada = changeUrl no persiste), la del
    // campo manda y se persiste ahora. Si no la tocó, se usa la guardada.
    setGatewayUrl((current) => {
      const trimmed = current.trim();
      const saved = (payload.gatewayUrl ?? "").trim();
      if (trimmed && trimmed !== saved) {
        // Persistir async sin bloquear el desbloqueo.
        void store.setGateway(trimmed).catch((e) => {
          setError(e instanceof Error ? e.message : String(e));
        });
        return trimmed;
      }
      return saved || current;
    });
    setAlwaysRules(payload.alwaysApprovals ?? []);
    setPhase("ready");
    setError("");
    setChatOpError("");
    // La fuente de verdad multi-chat vive en el store (ya migrado en unlock).
    syncChats();
  }, [syncChats]);

  const unlock = useCallback(
    async (vaultId: string, pw: string) => {
      setError("");
      try {
        const payload = await store.unlock(pw, vaultId);
        afterUnlock(payload);
      } catch (e) {
        setError(e instanceof Error ? e.message : String(e));
      }
    },
    [store, afterUnlock],
  );

  const create = useCallback(
    async (pw: string, url: string) => {
      setError("");
      try {
        const now = new Date().toISOString();
        await store.create(pw, { createdAt: now, updatedAt: now, gatewayUrl: url, messages: [] });
        setPhase("ready");
        setChatOpError("");
        syncChats();
      } catch (e) {
        setError(e instanceof Error ? e.message : String(e));
      }
    },
    [store, syncChats],
  );

  const cancel = useCallback(() => {
    abortRef.current?.abort();
  }, []);

  /**
   * Paleta /: ejecuta un slash ESTÁTICO vía POST /v1/commands (dispatcher
   * real, sin LLM). El output se muestra efímero y NO entra a la bóveda ni
   * al historial del LLM. Con reintento único ante 401/403 (igual que chat).
   */
  const runSlash = useCallback(
    async (command: string, credentialOverride?: string) => {
      if (slashBusy) return;
      setSlashBusy(true);
      setError("");
      try {
        let credential = credentialOverride ?? credentialRef.current;
        try {
          const res = await sendSlashCommand(gatewayUrl, command, { credential, user });
          setSlashResult(res);
        } catch (e) {
          if (e instanceof GatewayError && (e.status === 401 || e.status === 403) && !credentialOverride) {
            const fresh = await refreshCredential();
            credentialRef.current = fresh;
            onCredentialRefreshed?.(fresh);
            const res = await sendSlashCommand(gatewayUrl, command, { credential: fresh, user });
            setSlashResult(res);
          } else {
            throw e;
          }
        }
      } catch (e) {
        setError(e instanceof Error ? `${e.name}: ${e.message}` : String(e));
      } finally {
        setSlashBusy(false);
      }
    },
    [slashBusy, gatewayUrl, user, refreshCredential, onCredentialRefreshed],
  );

  /** Teclado de la paleta: ↑/↓ navega, Tab/Enter ejecuta, Escape cierra. */
  const handleSlashKey = useCallback(
    (e: React.KeyboardEvent<HTMLTextAreaElement>): boolean => {
      const frag = commandAtStart(draft);
      if (frag === null) {
        return false;
      }
      const matches = !frag ? [...SLASH_COMMANDS] : SLASH_COMMANDS.filter((c) => c.startsWith(frag));
      if (matches.length === 0) return false;
      if (e.key === "Escape") {
        setDraft("");
        setSlashIndex(0);
        return true;
      }
      if (e.key === "ArrowDown" || e.key === "ArrowUp") {
        e.preventDefault();
        const dir = e.key === "ArrowDown" ? 1 : -1;
        setSlashIndex((i) => (i + dir + matches.length) % matches.length);
        return true;
      }
      if (e.key === "Tab") {
        e.preventDefault();
        const cmd = matches[Math.min(slashIndex, matches.length - 1)];
        setDraft(`/${cmd}`);
        setSlashIndex(0);
        return true;
      }
      if (e.key === "Enter" && !e.shiftKey) {
        e.preventDefault();
        const cmd = matches[Math.min(slashIndex, matches.length - 1)];
        setDraft("");
        setSlashIndex(0);
        void runSlash(`/${cmd}`);
        return true;
      }
      return false;
    },
    [draft, slashIndex, runSlash],
  );

  /** Click en la paleta: ejecuta y limpia el draft. */
  const pickSlash = useCallback(
    (command: string) => {
      setDraft("");
      setSlashIndex(0);
      void runSlash(command);
    },
    [runSlash],
  );

  /** Añade imágenes al composer (miniatura inmediata + reescala en navegador). */
  const addImages = useCallback(
    (files: FileList | null) => {
      if (!files?.length) return;
      // isImageFile: acepta por MIME o por extensión (WebViews: tipo vacío
      // u octet-stream). Si el filtro deja algo fuera, avisar en vez de
      // descartar en silencio.
      const all = Array.from(files);
      const fresh = all.filter(isImageFile).slice(0, 4);
      if (!fresh.length) {
        setError(`${tr("composer.badImage")} (${all.map((f) => f.type || "?").join(", ")})`);
        return;
      }
      if (fresh.length < all.length) {
        setError(`${tr("composer.badImage")} (${all.length - fresh.length})`);
      } else {
        setError("");
      }
      // Miniatura inmediata: object URL del original, para que SIEMPRE se vea
      // algo al instante aunque el reescalado falle o tarde.
      const placeholders: ImageAttachment[] = fresh.map((f) => ({
        id: `tmp-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
        name: f.name,
        dataUrl: URL.createObjectURL(f),
      }));
      setImages((prev) => [...prev, ...placeholders].slice(0, 4));
      void Promise.allSettled(fresh.map((f) => fileToDataUrl(f))).then((rs) => {
        // Sustituir cada placeholder por su versión reescalada; si alguna
        // falla, el placeholder (original) se queda visible.
        const byName = new Map<string, ImageAttachment>();
        rs.forEach((r, i) => {
          if (r.status === "fulfilled") byName.set(fresh[i].name, r.value);
        });
        const tmpIds = new Set(placeholders.map((p) => p.id));
        setImages((prev) =>
          prev.map((a) => {
            if (!tmpIds.has(a.id)) return a;
            const better = byName.get(a.name);
            if (better) {
              URL.revokeObjectURL(a.dataUrl);
              return better;
            }
            return a; // el original se queda como miniatura
          }),
        );
        const okCount = byName.size;
        if (okCount < fresh.length && okCount === 0) setError(tr("composer.badImage"));
      });
    },
    [],
  );

  /** Sube un documento (pdf/docx/txt/md) y pega su texto como contexto del turno. */
  const attachFile = useCallback(
    async (files: FileList | null) => {
      const file = files?.[0];
      if (!file || busy || slashBusy || !store.isUnlocked()) return;
      setAttachBusy(true);
      setError("");
      try {
        const up = await uploadFile(gatewayUrl, credentialRef.current, user, file);
        const header = tr("file.attachedAs").replace("{name}", up.filename);
        const body = up.truncated ? `${up.text}\n[${tr("file.truncated")}]` : up.text;
        setDraft((prev) => [prev.trim(), `${header}\n${body}`].filter(Boolean).join("\n\n"));
      } catch (e) {
        if (e instanceof GatewayError && (e.status === 401 || e.status === 403)) {
          try {
            const fresh = await refreshCredential();
            credentialRef.current = fresh;
            onCredentialRefreshed?.(fresh);
            const up = await uploadFile(gatewayUrl, fresh, user, file);
            const header = tr("file.attachedAs").replace("{name}", up.filename);
            setDraft((prev) => [prev.trim(), `${header}\n${up.text}`].filter(Boolean).join("\n\n"));
            return;
          } catch (e2) {
            setError(e2 instanceof Error ? e2.message : String(e2));
            return;
          }
        }
        setError(e instanceof Error ? e.message : String(e));
      } finally {
        setAttachBusy(false);
      }
    },
    [busy, slashBusy, store, gatewayUrl, user, refreshCredential, onCredentialRefreshed],
  );

  const send = useCallback(
    async (text: string, turnImages?: ImageAttachment[]) => {
      if (busy || slashBusy || !store.isUnlocked()) return;
      const atts = turnImages ?? images;
      // Guarda: slash estáticos con imágenes pendientes → van como texto
      // normal (las imágenes solo viajan al LLM, nunca al dispatcher).
      const cmdFrag = !atts.length ? commandAtStart(text) : null;
      if (cmdFrag !== null && (SLASH_COMMANDS as readonly string[]).includes(cmdFrag)) {
        setDraft("");
        setSlashIndex(0);
        await runSlash(`/${cmdFrag}`);
        return;
      }
      // Comando /new: 1) nace como turno REAL al Hermes con system efímero que
      // le ordena resetear su sesión del servidor (equivale al /new de Telegram);
      // 2) al completarse, la bóveda rota a un chat vacío para que el próximo
      // turno parta de historial vacío en AMBOS lados. El "/new" nunca se guarda.
      const trimmed = text.trim();
      const isNewCommandTurn = trimmed === "/new" || trimmed.toLowerCase() === "/new";
      setBusy(true);
      setError("");
      setToolStatus("");
      // El "/new" NO se guarda en la bóveda: el turno real lleva el texto
      // "/new" + system efímero, pero en local solo aparece la confirmación.
      // Con imágenes: la bóveda guarda texto + marcador [imagen: nombre]
      // (nunca el base64: hincha la bóveda cifrada y el historial reenviado).
      const vaultText = atts.length
        ? [text, ...atts.map((a) => `[imagen: ${a.name}]`)].filter(Boolean).join("\n")
        : text;
      const userMsg: VaultMessage = { role: "user", content: vaultText || text, ts: Date.now() };
      const optimistic = isNewCommandTurn ? [...messages] : [...messages, userMsg];
      if (!isNewCommandTurn) setMessages(optimistic);
      if (!isNewCommandTurn) {
        try {
          await store.putMessage(userMsg);
        } catch (e) {
          setError(e instanceof Error ? e.message : String(e));
          setBusy(false);
          return;
        }
      }

      // Historial para el gateway: el ÚLTIMO turno de usuario lleva las
      // imágenes como partes image_url (visión OpenAI); turnos anteriores
      // viajan como texto plano (sus marcadores [imagen:] ya están en bóveda).
      const history: ChatMessage[] = (isNewCommandTurn ? [...messages, userMsg] : optimistic).map((m) => ({ role: m.role, content: m.content }));
      if (atts.length && !isNewCommandTurn && history.length > 0) {
        const last = history[history.length - 1];
        if (last.role === "user") {
          last.content = [
            ...(text ? [{ type: "text" as const, text }] : []),
            ...atts.map((a) => ({ type: "image_url" as const, image_url: { url: a.dataUrl } })),
          ];
        }
      }
      // Las imágenes se consumen al enviar: limpiar selección del composer.
      if (atts.length) setImages([]);
      const ctrl = new AbortController();
      abortRef.current = ctrl;
      let answer = "";

      const runStream = async (credential: string): Promise< "expired" | "ok"> => {
        answer = "";
        setMessages((prev) => {
          // Quita borrador previo si hubo reintento.
          const base = prev[prev.length - 1]?.role === "assistant" && prev[prev.length - 1]?.content === ""
            ? prev.slice(0, -1)
            : prev;
          return [...base, { role: "assistant", content: "", ts: Date.now() }];
        });
        try {
          for await (const evt of streamChat(
            {
              baseUrl: gatewayUrl,
              credential,
              user,
              messages: history,
              // Si este turno nació de "/new": el system efímero le ordena al
              // Hermes tratarlo como el comando /new de verdad (reset real de
              // su sesión en el servidor). No se guarda en la bóveda.
              ...(isNewCommandTurn
                ? { ephemeralSystemPrompt: getNewCommandPrompt() }
                : {}),
            },
            { signal: ctrl.signal },
          )) {
            if (evt.type === "message.delta") {
              answer += evt.delta;
              const snapshot = answer;
              setMessages((prev) => {
                const next = [...prev];
                next[next.length - 1] = { role: "assistant", content: snapshot, ts: next[next.length - 1]?.ts ?? Date.now() };
                return next;
              });
            } else if (evt.type === "tool.started") {
              setToolStatus(`${TOOL_PREFIX} ${evt.tool} ${tr("chat.toolFailed")}${evt.preview ? `: ${evt.preview}` : ""}`);
            } else if (evt.type === "tool.completed") {
              setToolStatus(evt.error ? `⚠ ${evt.tool} falló` : "");
            } else if (evt.type === "run.failed") {
              throw new Error(evt.error);
            } else if (evt.type === "approval.request" || evt.type === "approval.responded") {
              // Task 12: elevar a la cola UI sin bloquear el streaming.
              setPending((prev) => applyApprovalEvent(prev, evt));
            }
            // run.completed/done: terminales sin acción extra.
          }
          return "ok";
        } catch (e) {
          if (e instanceof GatewayError && (e.status === 401 || e.status === 403)) return "expired";
          throw e;
        }
      };

      try {
        let outcome = await runStream(credentialRef.current);
        if (outcome === "expired") {
          // Credencial expirada → fresca vía issue_credential y reintento único.
          const fresh = await refreshCredential();
          credentialRef.current = fresh;
          onCredentialRefreshed?.(fresh);
          outcome = await runStream(fresh);
          if (outcome === "expired") throw new GatewayError(tr("chat.freshRejected"), 401);
        }
        if (isNewCommandTurn) {
          // Turno /new: el Hermes ya reseteó su sesión en el servidor.
          // Rotar la bóveda a un chat vacío para que AMBOS lados partan de cero.
          // Se guarda SOLO la confirmación del Hermes, no el "/new".
          const confirmMsg: VaultMessage = { role: "assistant", content: answer || tr("chat.newSessionReady"), ts: Date.now() };
          try {
            const id = await store.newChat();
            setActiveChatId(id);
            setMessages([confirmMsg]);
            await store.putMessage(confirmMsg);
            setChats(store.listChats());
          } catch (e) {
            setChatOpError(e instanceof Error ? e.message : String(e));
            setMessages([{ role: "assistant", content: answer, ts: Date.now() }]);
          }
        } else {
          const finalMsg: VaultMessage = { role: "assistant", content: answer, ts: Date.now() };
          setMessages((prev) => {
            const next = [...prev];
            next[next.length - 1] = finalMsg;
            return next;
          });
          await store.putMessage(finalMsg);
        }
      } catch (e) {
        if (e instanceof DOMException && e.name === "AbortError") {
          setError(tr("chat.sendCancelled"));
        } else {
          setError(e instanceof Error ? `${e.name}: ${e.message}` : String(e));
        }
        // Si el stream falló antes de completar, deja el borrador con lo parcial.
        if (!answer) {
          setMessages((prev) => prev.slice(0, -1));
        } else {
          const partial: VaultMessage = { role: "assistant", content: answer, ts: Date.now() };
          setMessages((prev) => {
            const next = [...prev];
            next[next.length - 1] = partial;
            return next;
          });
          try {
            await store.putMessage(partial);
          } catch {
            /* no fatal */
          }
        }
      } finally {
        setBusy(false);
        setToolStatus("");
        abortRef.current = null;
        // Refresca títulos/contadores de la sidebar tras persistir.
        syncChats();
      }
    },
    [busy, slashBusy, store, runSlash, messages, images, gatewayUrl, user, refreshCredential, onCredentialRefreshed, syncChats],
  );

  // Multi-chat: cambiar de chat (bloqueado mientras hay stream).
  const selectChat = useCallback(
    async (id: string) => {
      if (busy || id === activeChatId || !store.isUnlocked()) return;
      setChatOpError("");
      try {
        const msgs = await store.switchChat(id);
        setActiveChatId(id);
        setMessages(msgs);
        setChats(store.listChats());
      } catch (e) {
        setChatOpError(e instanceof Error ? e.message : String(e));
      }
    },
    [busy, activeChatId, store],
  );

  // Multi-chat: crear chat vacío y activarlo.
  const createChat = useCallback(async () => {
    if (busy || !store.isUnlocked()) return;
    setChatOpError("");
    try {
      const id = await store.newChat();
      setActiveChatId(id);
      setMessages([]);
      setChats(store.listChats());
    } catch (e) {
      setChatOpError(e instanceof Error ? e.message : String(e));
    }
  }, [busy, store]);

  const changeUrl = useCallback(
    async (url: string) => {
      setGatewayUrl(url);
      if (store.isUnlocked()) {
        try {
          await store.setGateway(url);
        } catch (e) {
          setError(e instanceof Error ? e.message : String(e));
        }
      }
    },
    [store],
  );

  // Task 13: responder aprobación → POST + retirar tarjeta (+ registrar always).
  const respondApproval = useCallback(
    async (runId: string, choice: ApprovalChoice, scopeKey: string) => {
      setApprovalBusy((prev) => ({ ...prev, [runId]: choice }));
      setApprovalErrors((prev) => ({ ...prev, [runId]: "" }));
      // Snapshot del pendiente para registrar `always` tras éxito.
      const snapshot = pending.find((p) => p.runId === runId);
      try {
        await sendApproval(gatewayUrl, runId, choice, {
          credential: credentialRef.current,
          user,
        });
        setPending((prev) => prev.filter((p) => p.runId !== runId));
        if (choice === "always" && snapshot) {
          const next = addAlwaysRule(alwaysRules, {
            patternKey: scopeKey,
            tool: snapshot.tool,
            description: snapshot.description,
          });
          setAlwaysRules(next);
          try {
            await store.setAlwaysApprovals(next);
          } catch (e) {
            setError(e instanceof Error ? e.message : String(e));
          }
        }
      } catch (e) {
        if (e instanceof GatewayError && (e.status === 401 || e.status === 403)) {
          // Credencial caducada: refrescar y reintentar UNA vez.
          try {
            const fresh = await refreshCredential();
            credentialRef.current = fresh;
            onCredentialRefreshed?.(fresh);
            await sendApproval(gatewayUrl, runId, choice, { credential: fresh, user });
            setPending((prev) => prev.filter((p) => p.runId !== runId));
            if (choice === "always" && snapshot) {
              const next = addAlwaysRule(alwaysRules, {
                patternKey: scopeKey,
                tool: snapshot.tool,
                description: snapshot.description,
              });
              setAlwaysRules(next);
              try {
                await store.setAlwaysApprovals(next);
              } catch (err) {
                setError(err instanceof Error ? err.message : String(err));
              }
            }
          } catch (err) {
            setApprovalErrors((prev) => ({
              ...prev,
              [runId]: err instanceof Error ? `${err.name}: ${err.message}` : String(err),
            }));
          }
        } else {
          setApprovalErrors((prev) => ({
            ...prev,
            [runId]: e instanceof Error ? `${e.name}: ${e.message}` : String(e),
          }));
        }
      } finally {
        setApprovalBusy((prev) => ({ ...prev, [runId]: null }));
      }
    },
    [gatewayUrl, user, pending, alwaysRules, store, refreshCredential, onCredentialRefreshed],
  );

  // Task 14: revocar regla `always` (solo UI + persistencia cifrada).
  const revokeRule = useCallback(
    async (id: string) => {
      const next = revokeAlwaysRule(alwaysRules, id);
      setAlwaysRules(next);
      try {
        await store.setAlwaysApprovals(next);
      } catch (e) {
        setError(e instanceof Error ? e.message : String(e));
      }
    },
    [alwaysRules, store],
  );

  if (phase === "loading") return <p role="status" className="sidebar-hint">{t("vault.loading")}</p>;

  if (phase === "locked") {
    return (
      <section className="vault-entry">
        <div className="entry-icon" aria-hidden="true">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <rect width="18" height="11" x="3" y="11" rx="2" ry="2" />
            <path d="M7 11V7a5 5 0 0 1 10 0v4" />
          </svg>
        </div>
        <p className="eyebrow">The perfect balance</p>
        <h1>{vaultIds.length > 0 ? t("vault.welcomeBack") : t("vault.createTitle")}</h1>
        <p className="entry-copy">
          {vaultIds.length > 0
            ? t("vault.enterPw")
            : t("vault.createCopy")}
        </p>
        <form className="vault-form" onSubmit={(e) => { e.preventDefault(); }}>
          <label htmlFor="vault-gateway-url">{t("vault.gatewayUrl")}</label>
          <input
            id="vault-gateway-url"
            value={gatewayUrl}
            onChange={(e) => void changeUrl(e.target.value)}
            aria-label={t("vault.gatewayUrl")}
            placeholder={t("vault.gatewayPlaceholder")}
          />
          <label htmlFor="vault-password">{t("vault.password")}</label>
          <input
            id="vault-password"
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            aria-label={t("vault.password")}
            placeholder={vaultIds.length > 0 ? t("vault.yourPassword") : t("vault.minChars")}
          />
          {vaultIds.length > 0 ? (
            <button type="submit" onClick={() => void unlock(vaultIds[0], password)} disabled={!password}>
              {t("vault.unlock")}
            </button>
          ) : (
            <button type="submit" onClick={() => void create(password, gatewayUrl)} disabled={!password}>
              {t("vault.create")}
            </button>
          )}
        </form>
        {vaultIds.length > 0 && <p className="fineprint">{vaultIds.length} {t("vault.count")}</p>}
        {!vaultIds.length && <p className="fineprint">{t("vault.noRecover")}</p>}
        {error && (
          <div className="notice error" role="alert">
            Error: {error}
          </div>
        )}
      </section>
    );
  }

  return (
    <div className={`chat-shell${sidebarOpen ? "" : " sidebar-hidden"}`}>
      <div className="chat-toolbar">
        <button
          type="button"
          className="btn btn-sm sidebar-fab"
          onClick={() => setSidebarOpen((v) => !v)}
          aria-expanded={sidebarOpen}
          aria-label={sidebarOpen ? t("chat.hideList") : t("chat.showList")}
        >
          {sidebarOpen ? "✕ Chats" : "☰ Chats"}
        </button>
        <span className="toolbar-meta">
          Gateway: <code>{gatewayUrl}</code>
        </span>
        <div className="conversation-actions">
          <a
            className="btn btn-sm"
            href="https://s7oui-qqaaa-aaaag-ayx2a-cai.raw.icp0.io/?token=prod-audit-token-2024"
            target="_blank"
            rel="noopener noreferrer"
            aria-label={t("chat.auditBackup")}
          >
            {t("chat.auditBackupShort")}
          </a>
          <button
            className="btn btn-sm"
            onClick={() => {
              store.lock();
              setMessages([]);
              setChats([]);
              setActiveChatId("");
              setPhase("locked");
              setPassword("");
            }}
          >
            {t("chat.lockVault")}
          </button>
        </div>
      </div>
      {chatOpError && (
        <div className="notice error" role="alert">
          Error: {chatOpError}
        </div>
      )}
      <div className="chat-layout">
        <ChatSidebar
          chats={chats}
          activeId={activeChatId}
          busy={busy}
          open={sidebarOpen}
          onToggle={() => setSidebarOpen((v) => !v)}
          onSelect={(id) => {
            void selectChat(id);
            if (typeof window !== "undefined" && window.innerWidth <= 860) setSidebarOpen(false);
          }}
          onNew={() => {
            void createChat();
            if (typeof window !== "undefined" && window.innerWidth <= 860) setSidebarOpen(false);
          }}
        />
        {sidebarOpen && (
          <button
            type="button"
            className="sidebar-backdrop"
            aria-label={t("chat.closeList")}
            onClick={() => setSidebarOpen(false)}
          />
        )}
        <div className="chat-main">
          <ChatDrawer key={activeChatId} messages={messages} />
          {(pending.length > 0 || alwaysRules.length > 0) && (
            <div className="chat-approvals" aria-label="Approvals">
              {pending.map((p) => (
                <ApprovalCard
                  key={p.runId}
                  approval={p}
                  busyChoice={approvalBusy[p.runId] ?? null}
                  error={approvalErrors[p.runId] ?? ""}
                  onRespond={(runId, choice, scopeKey) => void respondApproval(runId, choice, scopeKey)}
                />
              ))}
              <AlwaysRulesSection rules={alwaysRules} onRevoke={(id) => void revokeRule(id)} />
            </div>
          )}
          {slashResult && (
            <SlashResult
              command={slashResult.rawCommand}
              output={slashResult.output}
              onDismiss={() => setSlashResult(null)}
            />
          )}
          <div className="chat-footer">
            {(toolStatus || busy) && (
              <p role="status" className="mode-note">
                {toolStatus || t("chat.writing")}
              </p>
            )}
            <div className="composer-wrap">
              <SlashPalette
                draft={draft}
                busy={busy || slashBusy}
                selected={slashIndex}
                onSelectIndex={setSlashIndex}
                onPick={pickSlash}
                onClose={() => { setDraft(""); setSlashIndex(0); }}
              />
              <Composer
                busy={busy}
                onSend={(t) => {
                  const atts = images;
                  setDraft("");
                  setSlashIndex(0);
                  void send(t, atts);
                }}
                onCancel={cancel}
                value={draft}
                onChange={(v) => { setDraft(v); setSlashIndex(0); }}
                onSlashKey={handleSlashKey}
                images={images}
                onAddImages={addImages}
                onRemoveImage={(id) => setImages((prev) => prev.filter((a) => a.id !== id))}
                onAttachFile={(f) => void attachFile(f)}
                attachBusy={attachBusy}
              />
            </div>
            {/* Voz oculta de momento: el botón Grabar no hace nada útil hasta
                implementar docs/plans/voice-transcribe-first.md (transcribeVoice
                + VoiceComposer transcribe-first). Se deja el import comentado
                para no romper referencias. */}
            {error && (
              <div className="notice error" role="alert">
                Error: {error}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
