// Task 9 — Transporte OpenAI-SSE contra el gateway Nebulock.
//
// - normalizeUrl: recorta espacios/trailing slashes Y quita un /v1 colgado;
//   el cliente añade /v1 al endpoint (POST {base}/v1/chat/completions).
// - Cabeceras: Authorization: Bearer <credencial nb2> + X-Nebulock-User.
// - Parseo SSE: chunks OpenAI (delta.content) + evento custom
//   `event: hermes.tool.progress` + eventos estructurados de runs
//   (message.delta/tool.started/tool.completed/run.completed/run.failed).
// - AbortController: la señal externa cancela el fetch y el lector.

import type { ApprovalChoice, GatewayEvent, SlashCommandResult, StreamChatRequest } from "./types";
import { tr } from "../i18n";
import { APPROVAL_CHOICES, isApprovalChoice } from "./types";

export type { ApprovalChoice };
export { APPROVAL_CHOICES, isApprovalChoice };

export const DEFAULT_MODEL = "nebulock-confidential";
const MAX_RESPONSE_CHARS = 64_000;
const USER_RE = /^[A-Za-z0-9._-]{1,64}$/;

/** Base del gateway SIN trailing slash y SIN /v1 colgado. */
export function normalizeUrl(url: string): string {
  let u = url.trim().replace(/\/+$/, "");
  if (!/^https?:\/\//.test(u)) throw new Error(tr("gw.badUrl"));
  u = u.replace(/\/v1$/, "");
  if (!u) throw new Error(tr("gw.emptyUrl"));
  return u;
}

/** Cabeceras de auth del gateway (Bearer nb2 + X-Nebulock-User). */
export function buildHeaders(credential: string, user: string): Record<string, string> {
  const cred = credential.trim();
  if (!cred || cred.length > 4096) throw new Error(tr("gw.badCredential"));
  if (!USER_RE.test(user.trim())) throw new Error(tr("gw.badUser"));
  return {
    Authorization: `Bearer ${cred}`,
    "Content-Type": "application/json",
    "X-Nebulock-User": user.trim(),
  };
}

/** Error con status HTTP (401/403 → el workspace refresca credencial). */
export class GatewayError extends Error {
  status?: number;
  constructor(message: string, status?: number) {
    super(message);
    this.name = "GatewayError";
    this.status = status;
  }
}

// Superficie fetch mínima para poder inyectar un mock en tests.
export interface FetchInit {
  headers?: Record<string, string>;
  method?: string;
  body?: string | FormData;
  signal?: AbortSignal;
}
export type FetchLike = (url: string, init?: FetchInit) => Promise<Response>;
const defaultFetch: FetchLike = (url, init) => fetch(url, init as RequestInit);

/**
 * Transcribe un blob de audio en el gateway (Whisper local, gratis).
 * POST {base}/v1/audio/transcriptions multipart {file, language?} → {text}.
 * La auth es la misma del chat (Bearer nb2 + X-Nebulock-User).
 * Lanza GatewayError con status en 401/403 para refresco de credencial.
 */
export async function transcribeVoice(
  baseUrl: string,
  credential: string,
  user: string,
  blob: Blob,
  language?: string,
  opts: StreamOptions = {},
): Promise<string> {
  const fetchImpl = opts.fetchImpl ?? defaultFetch;
  const base = normalizeUrl(baseUrl);
  const cred = credential.trim();
  if (!cred || cred.length > 4096) throw new Error(tr("gw.badCredential"));
  if (!USER_RE.test(user.trim())) throw new Error(tr("gw.badUser"));
  const form = new FormData();
  form.append("file", blob, blob.type.includes("mp4") ? "note.m4a" : "note.webm");
  if (language === "es" || language === "en") form.append("language", language);
  const resp = await fetchImpl(`${base}/v1/audio/transcriptions`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${cred}`,
      "X-Nebulock-User": user.trim(),
    },
    body: form,
    ...(opts.signal ? { signal: opts.signal } : {}),
  });
  if (resp.status === 401 || resp.status === 403) {
    throw new GatewayError(
      resp.status === 401 ? tr("gw.expired401") : tr("gw.forbidden403"),
      resp.status,
    );
  }
  if (!resp.ok) throw new GatewayError(`${tr("gw.rejected")} (${resp.status})`, resp.status);
  let body: Record<string, unknown> = {};
  try {
    body = (await resp.json()) as Record<string, unknown>;
  } catch {
    body = {};
  }
  const text = typeof body["text"] === "string" ? body["text"].trim() : "";
  if (!text) throw new GatewayError(tr("voice.emptyTranscript"));
  return text;
}

// --- Parseo SSE ---

interface SseBlock {
  event?: string;
  data: string[];
}

function splitBlocks(text: string): SseBlock[] {
  const blocks: SseBlock[] = [];
  let cur: SseBlock = { data: [] };
  let hasContent = false;
  for (const rawLine of text.split("\n")) {
    const line = rawLine.replace(/\r$/, "");
    if (line === "") {
      if (hasContent) {
        blocks.push(cur);
        cur = { data: [] };
        hasContent = false;
      }
      continue;
    }
    if (line.startsWith(":")) {
      hasContent = true; // keepalive/comentario: marca bloque pero sin datos
      continue;
    }
    if (line.startsWith("event:")) {
      cur.event = line.slice(6).trim();
      hasContent = true;
      continue;
    }
    if (line.startsWith("data:")) {
      cur.data.push(line.slice(5).trim());
      hasContent = true;
      continue;
    }
    // línea desconocida: se ignora
  }
  if (hasContent) blocks.push(cur);
  return blocks;
}

function safeJson(s: string): unknown | undefined {
  try {
    return JSON.parse(s);
  } catch {
    return undefined;
  }
}

/** Convierte un bloque SSE en 0..n eventos normalizados. */
export function blockToEvents(block: SseBlock): GatewayEvent[] {
  if (block.data.length === 0) return []; // keepalive / comentario
  const raw = block.data.join("\n").trim();
  if (!raw) return [];
  if (raw === "[DONE]") return [{ type: "done" }];

  const json = safeJson(raw);
  if (json === undefined) return []; // keepalive no-JSON: se ignora
  if (typeof json !== "object" || json === null) return [];
  const obj = json as Record<string, unknown>;

  // Evento con nombre explícito (hermes.tool.progress o runs estructurados).
  const named = block.event ?? (typeof obj["event"] === "string" ? obj["event"] : undefined);
  if (named) {
    const evt = structuredEvent(named, obj);
    return evt ? [evt] : [];
  }

  // Chunk OpenAI sin event: → delta.content si lo hay.
  const delta = openAiDelta(obj);
  if (delta !== undefined) return [{ type: "message.delta", delta }];
  return [];
}

/** Evento estructurado (named): runs + hermes.tool.progress. */
function structuredEvent(name: string, obj: Record<string, unknown>): GatewayEvent | null {
  switch (name) {
    case "message.delta": {
      const d = typeof obj["delta"] === "string" ? obj["delta"] : openAiDelta(obj);
      return typeof d === "string" ? { type: "message.delta", delta: d } : null;
    }
    case "hermes.tool.progress": {
      // running → tool.started, completed/failed → tool.completed.
      const status = String(obj["status"] ?? "");
      const tool = String(obj["tool"] ?? obj["function"] ?? "tool");
      if (status === "running") {
        const preview = typeof obj["label"] === "string" ? obj["label"]
          : typeof obj["preview"] === "string" ? obj["preview"]
          : undefined;
        return preview !== undefined
          ? { type: "tool.started", tool, preview }
          : { type: "tool.started", tool };
      }
      if (status === "completed" || status === "failed" || status === "done" || status === "error") {
        return { type: "tool.completed", tool, error: status === "failed" || status === "error" };
      }
      return null;
    }
    case "tool.started":
      return {
        type: "tool.started",
        tool: String(obj["tool"] ?? "tool"),
        ...(typeof obj["preview"] === "string" ? { preview: obj["preview"] } : {}),
      };
    case "tool.completed":
      return {
        type: "tool.completed",
        tool: String(obj["tool"] ?? "tool"),
        error: obj["error"] === true,
      };
    case "run.completed":
      return { type: "run.completed", output: typeof obj["output"] === "string" ? obj["output"] : "" };
    case "run.failed":
      return { type: "run.failed", error: typeof obj["error"] === "string" ? obj["error"] : tr("gw.runFailed") };
    case "approval.request":
      return approvalRequestEvent(obj);
    case "approval.responded":
      return approvalRespondedEvent(obj);
    default:
      return null; // eventos desconocidos se ignoran sin romper el stream
  }
}

/** Extrae string no-vacío o undefined (tolerante: números/bool → String). */
function strField(obj: Record<string, unknown>, ...keys: string[]): string | undefined {
  for (const k of keys) {
    const v = obj[k];
    if (typeof v === "string" && v) return v;
    if (typeof v === "number" && Number.isFinite(v)) return String(v);
  }
  return undefined;
}

/**
 * Task 12 — `approval.request` del gateway.
 *
 * Contrato (api_server.py `_approval_notify` + tools/approval.py):
 *   { event, run_id, command, description?, pattern_key?, pattern_keys?,
 *     tool?, choices: ["once","session","always","deny"], timestamp }
 * Sin run_id o sin command legible NO se eleva evento (no hay nada que
 * aprobar ni run al que responder): se ignora sin romper el streaming.
 */
function approvalRequestEvent(obj: Record<string, unknown>): GatewayEvent | null {
  const runId = strField(obj, "run_id", "runId");
  const command = strField(obj, "command", "cmd");
  if (!runId || !command) return null;
  const keys = obj["pattern_keys"];
  const patternKeys = Array.isArray(keys)
    ? keys.filter((k): k is string => typeof k === "string" && !!k).slice(0, 32)
    : undefined;
  return {
    type: "approval.request",
    runId,
    command,
    ...(strField(obj, "tool", "function") ? { tool: strField(obj, "tool", "function") as string } : {}),
    ...(strField(obj, "description", "reason", "pattern_description") ? { description: strField(obj, "description", "reason", "pattern_description") as string } : {}),
    ...(strField(obj, "pattern_key", "patternKey") ? { patternKey: strField(obj, "pattern_key", "patternKey") as string } : {}),
    ...(patternKeys && patternKeys.length > 0 ? { patternKeys } : {}),
  };
}

/**
 * Task 13 — `approval.responded`: confirma que el run resolvió la espera.
 * `choice` inválido/ausente → se ignora (la tarjeta la retira el POST local).
 */
function approvalRespondedEvent(obj: Record<string, unknown>): GatewayEvent | null {
  const runId = strField(obj, "run_id", "runId");
  const raw = typeof obj["choice"] === "string" ? obj["choice"].trim().toLowerCase() : "";
  if (!runId || (raw !== "once" && raw !== "session" && raw !== "always" && raw !== "deny")) return null;
  const resolved = obj["resolved"];
  return {
    type: "approval.responded",
    runId,
    choice: raw as ApprovalChoice,
    ...(typeof resolved === "number" && Number.isFinite(resolved) ? { resolved } : {}),
  };
}

/** Extrae delta.content de un chunk chat.completion.chunk. */
function openAiDelta(obj: Record<string, unknown>): string | undefined {
  const choices = obj["choices"];
  if (!Array.isArray(choices) || choices.length === 0) return undefined;
  const first = choices[0] as Record<string, unknown>;
  const delta = first["delta"] as Record<string, unknown> | undefined;
  const content = delta?.["content"];
  return typeof content === "string" && content ? content : undefined;
}

/** Parseo síncrono de un texto SSE completo (tests + fallback no-stream). */
export function parseSseText(text: string): GatewayEvent[] {
  const out: GatewayEvent[] = [];
  for (const block of splitBlocks(text)) {
    out.push(...blockToEvents(block));
  }
  return out;
}

// --- Stream contra el gateway ---

export interface StreamOptions {
  fetchImpl?: FetchLike;
  signal?: AbortSignal;
}

/** Opciones del POST de aprobación (Task 13). Reutiliza cabeceras nb2. */
export interface ApprovalRequestOptions {
  fetchImpl?: FetchLike;
  signal?: AbortSignal;
  credential: string;
  user: string;
}

/** Respuesta de POST /v1/runs/{run_id}/approval. */
export interface ApprovalResponse {
  runId: string;
  choice: ApprovalChoice;
  resolved: number;
}

/**
 * Task 13 — Resuelve una aprobación pendiente.
 * POST {base}/v1/runs/{run_id}/approval con {"choice": ...}.
 * 404 → run desconocido; 409 → sin aprobación pendiente/activa.
 */
export async function sendApproval(
  baseUrl: string,
  runId: string,
  choice: ApprovalChoice,
  opts: ApprovalRequestOptions,
): Promise<ApprovalResponse> {
  if (!isApprovalChoice(choice)) throw new GatewayError(tr("gw.badChoice"));
  const run = runId.trim();
  if (!run || run.length > 256) throw new GatewayError(tr("gw.badRunId"));
  const fetchImpl = opts.fetchImpl ?? defaultFetch;
  const base = normalizeUrl(baseUrl);
  const headers = buildHeaders(opts.credential, opts.user);
  const resp = await fetchImpl(`${base}/v1/runs/${encodeURIComponent(run)}/approval`, {
    method: "POST",
    headers,
    body: JSON.stringify({ choice }),
    ...(opts.signal ? { signal: opts.signal } : {}),
  });
  if (resp.status === 401 || resp.status === 403) {
    throw new GatewayError(
      resp.status === 401 ? tr("gw.expired401") : tr("gw.forbidden403"),
      resp.status,
    );
  }
  if (resp.status === 404) throw new GatewayError(tr("gw.run404"), 404);
  if (resp.status === 409) throw new GatewayError(tr("gw.noPending409"), 409);
  if (!resp.ok) throw new GatewayError(`${tr("gw.approvalRejected")} (${resp.status})`, resp.status);
  let body: Record<string, unknown> = {};
  try {
    body = (await resp.json()) as Record<string, unknown>;
  } catch {
    body = {};
  }
  const back = typeof body["choice"] === "string" ? body["choice"].trim().toLowerCase() : choice;
  const resolved = typeof body["resolved"] === "number" && Number.isFinite(body["resolved"])
    ? body["resolved"]
    : 1;
  const echoed: ApprovalChoice = isApprovalChoice(back) ? back : choice;
  return { runId: run, choice: echoed, resolved };
}

/** Opciones del POST de comandos (misma auth nb2 que el resto). */
export interface SlashCommandOptions {
  fetchImpl?: FetchLike;
  signal?: AbortSignal;
  credential: string;
  user: string;
}

/**
 * Ejecuta un slash command ESTÁTICO por el dispatcher real del gateway.
 * POST {base}/v1/commands con {"command": "/whoami"} → {command, output}.
 * NO pasa por el LLM ni toca el historial: el output se renderiza como
 * mensaje de sistema efímero (no se guarda en la bóveda).
 * 401/403 → GatewayError con status (el workspace refresca credencial).
 * 403 command_not_allowed → el server rechaza comandos fuera de allowlist.
 */
export async function sendSlashCommand(
  baseUrl: string,
  command: string,
  opts: SlashCommandOptions,
): Promise<SlashCommandResult> {
  const cmd = command.trim();
  if (!cmd) throw new GatewayError(tr("cmd.empty"));
  if (cmd.length > 256) throw new GatewayError(tr("cmd.tooLong"));
  const fetchImpl = opts.fetchImpl ?? defaultFetch;
  const base = normalizeUrl(baseUrl);
  const headers = buildHeaders(opts.credential, opts.user);
  const resp = await fetchImpl(`${base}/v1/commands`, {
    method: "POST",
    headers,
    body: JSON.stringify({ command: cmd.startsWith("/") ? cmd : `/${cmd}` }),
    ...(opts.signal ? { signal: opts.signal } : {}),
  });
  if (resp.status === 401 || resp.status === 403) {
    throw new GatewayError(
      resp.status === 401 ? tr("gw.expired401") : tr("gw.forbidden403"),
      resp.status,
    );
  }
  if (!resp.ok) throw new GatewayError(`${tr("gw.rejected")} (${resp.status})`, resp.status);
  let body: Record<string, unknown> = {};
  try {
    body = (await resp.json()) as Record<string, unknown>;
  } catch {
    body = {};
  }
  return {
    command: typeof body["command"] === "string" ? body["command"] : cmd.replace(/^\//, ""),
    rawCommand: typeof body["raw_command"] === "string" ? body["raw_command"] : cmd,
    output: typeof body["output"] === "string" ? body["output"] : "",
    ephemeral: body["ephemeral"] === true,
  };
}

/**
 * Sube un documento al gateway para extracción de texto.
 * POST {base}/v1/files multipart {file, purpose?} → {filename, text, truncated}.
 * Misma auth nb2 que el resto. Límite server: 10 MiB; tipos: pdf/docx/txt/md.
 * 401/403 → GatewayError con status (el workspace refresca credencial).
 */
export async function uploadFile(
  baseUrl: string,
  credential: string,
  user: string,
  file: File,
  opts: StreamOptions = {},
): Promise<{ filename: string; text: string; truncated: boolean }> {
  const fetchImpl = opts.fetchImpl ?? defaultFetch;
  const base = normalizeUrl(baseUrl);
  const cred = credential.trim();
  if (!cred || cred.length > 4096) throw new Error(tr("gw.badCredential"));
  if (!USER_RE.test(user.trim())) throw new Error(tr("gw.badUser"));
  const form = new FormData();
  form.append("file", file, file.name);
  form.append("purpose", "extract");
  const resp = await fetchImpl(`${base}/v1/files`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${cred}`,
      "X-Nebulock-User": user.trim(),
    },
    body: form,
    ...(opts.signal ? { signal: opts.signal } : {}),
  });
  if (resp.status === 401 || resp.status === 403) {
    throw new GatewayError(
      resp.status === 401 ? tr("gw.expired401") : tr("gw.forbidden403"),
      resp.status,
    );
  }
  if (resp.status === 413) throw new GatewayError(tr("file.tooLarge"), 413);
  if (resp.status === 415) throw new GatewayError(tr("file.badType"), 415);
  if (!resp.ok) throw new GatewayError(`${tr("gw.rejected")} (${resp.status})`, resp.status);
  let body: Record<string, unknown> = {};
  try {
    body = (await resp.json()) as Record<string, unknown>;
  } catch {
    body = {};
  }
  const text = typeof body["text"] === "string" ? body["text"] : "";
  if (!text.trim()) throw new GatewayError(tr("file.emptyText"));
  return {
    filename: typeof body["filename"] === "string" ? body["filename"] : file.name,
    text,
    truncated: body["truncated"] === true,
  };
}

/**
 * POST {base}/v1/chat/completions (stream:true) → AsyncGenerator de eventos.
 * Lanza GatewayError con status en 401/403 para que el workspace refresque
 * la credencial vía issue_credential y reintente una vez.
 */
export async function* streamChat(
  req: StreamChatRequest,
  opts: StreamOptions = {},
): AsyncGenerator<GatewayEvent, void, void> {
  const fetchImpl = opts.fetchImpl ?? defaultFetch;
  const base = normalizeUrl(req.baseUrl);
  const headers = buildHeaders(req.credential, req.user);
  const model = (req.model ?? DEFAULT_MODEL).trim() || DEFAULT_MODEL;
  opts.signal?.throwIfAborted();

  const inner = new AbortController();
  const onOuterAbort = () => inner.abort();
  opts.signal?.addEventListener("abort", onOuterAbort, { once: true });

  let reader: ReadableStreamDefaultReader<Uint8Array> | null = null;
  let chars = 0;
  try {
    // System prompt efímero (p. ej. "/new como comando"): se antepone como
    // mensaje system SOLO en este POST, nunca se guarda en la bóveda.
    const outbound = req.ephemeralSystemPrompt?.trim()
      ? [{ role: "system", content: req.ephemeralSystemPrompt.trim() }, ...req.messages]
      : req.messages;
    const resp = await fetchImpl(`${base}/v1/chat/completions`, {
      method: "POST",
      headers,
      body: JSON.stringify({ model, messages: outbound, stream: true }),
      signal: inner.signal as AbortSignal,
    });
    if (resp.status === 401 || resp.status === 403) {
      throw new GatewayError(
        resp.status === 401 ? tr("gw.expired401") : tr("gw.forbidden403"),
        resp.status,
      );
    }
    if (!resp.ok) throw new GatewayError(`${tr("gw.rejected")} (${resp.status})`, resp.status);
    if (!resp.body) throw new GatewayError(tr("gw.emptyBody"));

    reader = resp.body.getReader();
    const decoder = new TextDecoder();
    let buffer = "";
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      // Extrae bloques completos (delimitados por línea vacía); deja el resto.
      let sep: number;
      while ((sep = buffer.search(/\n\r?\n/)) >= 0) {
        const chunk = buffer.slice(0, sep);
        buffer = buffer.slice(sep).replace(/^\n\r?\n/, "");
        for (const block of splitBlocks(chunk + "\n")) {
          for (const evt of blockToEvents(block)) {
            if (evt.type === "message.delta") {
              chars += evt.delta.length;
              if (chars > MAX_RESPONSE_CHARS) throw new GatewayError(tr("gw.tooLong"));
            }
            yield evt;
          }
        }
      }
    }
    // Resto sin trailing \n\n (respuestas sintéticas de tests).
    if (buffer.trim()) {
      for (const evt of parseSseText(buffer)) yield evt;
    }
  } catch (e) {
    if (inner.signal.aborted) {
      const aborted = new DOMException("request aborted", "AbortError");
      throw aborted;
    }
    throw e;
  } finally {
    opts.signal?.removeEventListener("abort", onOuterAbort);
    inner.abort();
    try {
      await reader?.cancel();
    } catch {
      /* lector ya cerrado */
    }
  }
}
