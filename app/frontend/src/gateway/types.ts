// Task 9 — Tipos del transporte OpenAI-SSE contra el gateway Nebulock.
//
// El gateway hereda del adapter api_server (OpenAI-compatible):
// - POST {base}/v1/chat/completions con stream:true → SSE de chunks
//   `chat.completion.chunk` con delta.content + evento custom
//   `event: hermes.tool.progress` para progreso de tools.
// - GET {base}/v1/runs/{run_id}/events → eventos estructurados
//   message.delta / tool.started / tool.completed / run.completed / run.failed
//   (misma forma que _make_run_event_callback + _text_cb en api_server.py).

/** Mensaje de chat estilo OpenAI enviado al gateway. content admite texto
 *  o lista de partes text/image_url (visión OpenAI Chat Completions). */
export interface ChatMessage {
  role: "user" | "assistant" | "system";
  content: string | ChatContentPart[];
}

/** Parte de contenido multimodal (texto o imagen inline). */
export type ChatContentPart =
  | { type: "text"; text: string }
  | { type: "image_url"; image_url: { url: string; detail?: string } };

/** Eventos normalizados que el cliente SSE eleva a la UI. */
export type GatewayEvent =
  | { type: "message.delta"; delta: string }
  | { type: "tool.started"; tool: string; preview?: string }
  | { type: "tool.completed"; tool: string; error: boolean }
  | { type: "run.completed"; output: string }
  | { type: "run.failed"; error: string }
  | { type: "approval.request"; runId: string; command: string; tool?: string; description?: string; patternKey?: string; patternKeys?: string[] }
  | { type: "approval.responded"; runId: string; choice: ApprovalChoice; resolved?: number }
  | { type: "done" };

/** Config para abrir un stream de chat. */
export interface StreamChatRequest {
  /** Base del gateway, con o sin /v1 (normalizeUrl la quita). */
  baseUrl: string;
  /** Credencial nb2 (Bearer). Se refresca vía issue_credential al expirar. */
  credential: string;
  /** Valor de X-Nebulock-User (propietario allowlisted, p. ej. "nuno"). */
  user: string;
  /** Modelo anunciado por el gateway. */
  model?: string;
  messages: ChatMessage[];
  /**
   * System prompt efímero: el gateway lo antepone al historial SIN persistirlo
   * en la bóveda (instrucciones de sesión como "/new como comando"). Solo se
   * envía en el turno que lo pide.
   */
  ephemeralSystemPrompt?: string;
}

/** Petición de aprobación de un run (Task 13 la usa; Task 9 solo la tipa). */
export type ApprovalChoice = "once" | "session" | "always" | "deny";

/** Choices aceptados por POST /v1/runs/{run_id}/approval (Task 12+13). */
export const APPROVAL_CHOICES: readonly ApprovalChoice[] = ["once", "session", "always", "deny"];

/**
 * Slash commands disponibles vía POST /v1/commands (dispatcher real del
 * gateway, sin LLM). Solo estáticos sin estado de sesión. El server es la
 * fuente de verdad (403 command_not_allowed para el resto); esta lista es
 * solo para la paleta/autocomplete del frontend.
 */
export type SlashCommandName = "help" | "commands" | "profile" | "whoami";
export const SLASH_COMMANDS: readonly SlashCommandName[] = ["help", "commands", "profile", "whoami"];

/** Respuesta de POST /v1/commands. */
export interface SlashCommandResult {
  command: string;
  rawCommand: string;
  output: string;
  ephemeral: boolean;
}

/** Guarda: true solo para los 4 choices del contrato (minúsculas exactas). */
export function isApprovalChoice(v: unknown): v is ApprovalChoice {
  return v === "once" || v === "session" || v === "always" || v === "deny";
}
