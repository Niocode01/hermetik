// Tasks 12+13+14 — Lógica pura de aprobaciones (sin React, testeable con Vitest).
//
// - PendingApproval: cola de aprobaciones pendientes por run_id (Task 12:
//   el stream SSE las eleva sin bloquear el texto; `approval.responded`
//   retira la tarjeta).
// - redactSecrets + truncateCommand (Task 13): la tarjeta muestra qué comando
//   y qué argumentos, recortados y sin secretos (misma idea que el gateway:
//   jamás mostrar valores de --password/--token/Bearer...).
// - APPROVAL_TIMEOUT_MS: el gateway espera `gateway_timeout` (300s por
//   defecto); pasado ese tiempo la tarjeta muestra timeout visible.
// - AlwaysApprovalRule (Task 14): decisiones `always` auditables; viven en
//   la bóveda cifrada (VaultPayload.alwaysApprovals), revocar es solo UI.

import type { ApprovalChoice, GatewayEvent } from "../gateway/types";
import { tr } from "../i18n";

/** Una aprobación pendiente de respuesta (una por run_id). */
export interface PendingApproval {
  runId: string;
  command: string;
  tool?: string;
  description?: string;
  patternKey?: string;
  /** epoch ms de cuando llegó el `approval.request`. */
  requestedAt: number;
}

/** Regla `always`: ámbito herramienta + patrón, con botón Revocar (Task 14). */
export interface AlwaysApprovalRule {
  id: string;
  patternKey: string;
  description?: string;
  tool?: string;
  /** ISO de cuando se aprobó como `always`. */
  createdAt: string;
}

/** Timeout visible: el gateway cierra la espera a los ~300s (gateway_timeout). */
export const APPROVAL_TIMEOUT_MS = 300_000;

/** Máximo de caracteres del comando mostrado en la tarjeta. */
export const MAX_COMMAND_CHARS = 400;

/** Cola máxima de pendientes (anti-spam: el gateway rara vez tiene >1). */
export const MAX_PENDING = 8;

function nowMs(now?: number): number {
  return typeof now === "number" ? now : Date.now();
}

/**
 * Inserta o refresca un pendiente por run_id (idempotente: el gateway puede
 * re-emitir `approval.request`; no duplica tarjetas).
 */
export function upsertApproval(
  list: PendingApproval[],
  evt: Extract<GatewayEvent, { type: "approval.request" }>,
  now?: number,
): PendingApproval[] {
  const entry: PendingApproval = {
    runId: evt.runId,
    command: evt.command,
    ...(evt.tool ? { tool: evt.tool } : {}),
    ...(evt.description ? { description: evt.description } : {}),
    ...(evt.patternKey ? { patternKey: evt.patternKey } : {}),
    requestedAt: nowMs(now),
  };
  const idx = list.findIndex((p) => p.runId === entry.runId);
  if (idx >= 0) {
    const next = [...list];
    // Refresco: conserva requestedAt original (el timeout cuenta desde el
    // primer request del gateway, no desde el re-emit).
    next[idx] = { ...entry, requestedAt: list[idx].requestedAt };
    return next;
  }
  const next = [...list, entry];
  return next.length > MAX_PENDING ? next.slice(next.length - MAX_PENDING) : next;
}

/** Retira el pendiente de un run (`approval.responded` o POST local con éxito). */
export function removeApproval(list: PendingApproval[], runId: string): PendingApproval[] {
  return list.filter((p) => p.runId !== runId);
}

/**
 * Aplica un GatewayEvent a la cola: `approval.request` inserta,
 * `approval.responded` retira. Resto de eventos → misma lista (sin copiar).
 */
export function applyApprovalEvent(
  list: PendingApproval[],
  evt: GatewayEvent,
  now?: number,
): PendingApproval[] {
  if (evt.type === "approval.request") return upsertApproval(list, evt, now);
  if (evt.type === "approval.responded") return removeApproval(list, evt.runId);
  return list;
}

/** true si el run lleva esperando más que el timeout del gateway. */
export function isApprovalTimedOut(p: PendingApproval, now?: number): boolean {
  return nowMs(now) - p.requestedAt >= APPROVAL_TIMEOUT_MS;
}

/** Segundos restantes (redondeados) antes del timeout; 0 si ya venció. */
export function approvalSecondsLeft(p: PendingApproval, now?: number): number {
  const left = APPROVAL_TIMEOUT_MS - (nowMs(now) - p.requestedAt);
  return left <= 0 ? 0 : Math.ceil(left / 1000);
}

// --- Redacción de secretos (Task 13) ---

// --flag=valor / --flag valor / -f valor / ENV=valor / "password": "valor"
// para nombres típicos de secreto. El VALOR se sustituye por ***; el nombre
// de la flag se conserva para que el usuario entienda qué pide el comando.
const SECRET_NAME = "password|passwd|pwd|secret|token|api[-_]?key|auth[-_]?token|access[-_]?token|refresh[-_]?token|bearer|session[-_]?key|private[-_]?key|client[-_]?secret|credentials?";
// 1. --nombre=valor / --nombre:valor (valor sin espacios)
const FLAG_RE = new RegExp(`(--?(?:${SECRET_NAME}))([=:])([^\\s'"]+)`, "gi");
// 2. --nombre "valor con espacios" / --nombre 'valor'
const FLAG_QUOTED_RE = new RegExp(`(--?(?:${SECRET_NAME}))([=:])(["'])(?:[^\\\\]|\\\\.)*?\\3`, "gi");
// 2b. --nombre valor (separado por espacio, valor sin espacios; el caso más
// común en CLI: `--password s3cr3t`, `--token abc123`).
const FLAG_SPACE_RE = new RegExp(`(--?(?:${SECRET_NAME}))(\\s+)([^\\s'";][^\\s;]*)`, "gi");
// 3. NOMBRE=valor en entorno shell (PASSWORD=..., export TOKEN=...)
const ENV_RE = new RegExp(`\\b(export\\s+)?(SUDO_PASSWORD|${SECRET_NAME})(=)([^\\s'";]+)`, "gi");
// 4. "nombre": "valor" en JSON inline
const JSON_RE = new RegExp(`(("(?:${SECRET_NAME})")\\s*:\\s*")([^"]*)(")`, "gi");
// 5. Bearer <token> suelto
const BEARER_RE = /\b(Bearer\s+)[A-Za-z0-9._~+/=-]{6,}/g;
// 6. nb2.<credencial> suelta (nuestras credenciales Bearer del gateway)
const NB2_RE = /\bnb2\.[A-Za-z0-9._~+/=-]{6,}/g;

/** Enmascara valores de secretos; conserva nombres de flags para contexto. */
export function redactSecrets(command: string): string {
  return command
    .replace(FLAG_QUOTED_RE, "$1$2$3***$3")
    .replace(FLAG_RE, "$1$2***")
    .replace(FLAG_SPACE_RE, "$1$2***")
    .replace(ENV_RE, "$1$2$3***")
    .replace(JSON_RE, "$1***$4")
    .replace(BEARER_RE, "$1***")
    .replace(NB2_RE, "nb2.***");
}

/** Recorta el comando para la tarjeta (con elipsis); "" → "(empty command)". */
export function truncateCommand(command: string, max = MAX_COMMAND_CHARS): string {
  const t = command.trim();
  if (!t) return tr("approval.emptyCommand");
  if (t.length <= max) return t;
  return t.slice(0, Math.max(0, max - 1)).trimEnd() + "…";
}

/** Lo que la tarjeta muestra: redactado + recortado (nunca el comando crudo). */
export function displayCommand(command: string, max = MAX_COMMAND_CHARS): string {
  return truncateCommand(redactSecrets(command), max);
}

// --- Reglas `always` (Task 14) ---

function ruleId(): string {
  try {
    return globalThis.crypto.randomUUID();
  } catch {
    return `always-${Date.now()}-${Math.floor(Math.random() * 1e9)}`;
  }
}

/**
 * Registra una decisión `always` (idempotente por patternKey+tool: no duplica
 * si el usuario aprueba `always` dos veces el mismo patrón).
 */
export function addAlwaysRule(
  rules: AlwaysApprovalRule[],
  input: { patternKey: string; description?: string; tool?: string },
  now?: number,
): AlwaysApprovalRule[] {
  const key = input.patternKey.trim();
  if (!key) return rules;
  const tool = input.tool?.trim() || undefined;
  const dup = rules.find((r) => r.patternKey === key && (r.tool ?? undefined) === tool);
  if (dup) return rules;
  const ts = new Date(nowMs(now)).toISOString();
  return [
    ...rules,
    {
      id: ruleId(),
      patternKey: key,
      ...(input.description?.trim() ? { description: input.description.trim().slice(0, 200) } : {}),
      ...(tool ? { tool } : {}),
      createdAt: ts,
    },
  ];
}

/** Revoca una regla `always` por id (solo UI: la próxima vez se vuelve a pedir). */
export function revokeAlwaysRule(rules: AlwaysApprovalRule[], id: string): AlwaysApprovalRule[] {
  return rules.filter((r) => r.id !== id);
}

/** Clave de ámbito para una decisión: patternKey > description > comando. */
export function scopeKeyForApproval(p: PendingApproval): string {
  const k = (p.patternKey ?? p.description ?? p.command).trim();
  return k.slice(0, 200) || p.runId;
}

/** Etiquetas de los 4 botones (POST choice). */
/** Etiquetas según idioma activo (el componente prefiere t() por choice). */
export function approvalButtons(): { choice: ApprovalChoice; label: string }[] {
  return [
    { choice: "once", label: tr("approval.once") },
    { choice: "session", label: tr("approval.session") },
    { choice: "always", label: tr("approval.always") },
    { choice: "deny", label: tr("approval.deny") },
  ];
}

/** @deprecated Usar approvalButtons() para respetar el idioma activo. */
export const APPROVAL_BUTTONS: readonly { choice: ApprovalChoice; label: string }[] = [
  { choice: "once", label: "Approve once" },
  { choice: "session", label: "Approve session" },
  { choice: "always", label: "Always" },
  { choice: "deny", label: "Deny" },
];
