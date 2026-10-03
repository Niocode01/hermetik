// i18n ES/EN — single source of truth for all user-visible strings.
//
// - `Lang = "es" | "en"`. Default: saved choice in localStorage, else
//   navigator.language (es-* → "es", anything else → "en").
// - `I18nProvider` holds the state; `useI18n()` returns { lang, setLang, t }.
// - Non-React code (gateway/client.ts, vault/chats.ts, recorder.ts) uses
//   `getLang()` + `tr(key)` — same dictionaries, no hooks.
// - Every user-visible literal lives here. Code files must use t.* / tr(),
//   never inline ES/EN strings.

import { createContext, useCallback, useContext, useMemo, useState } from "react";
import type { ReactNode } from "react";

export type Lang = "es" | "en";

const LS_KEY = "hermetik.lang.v1";

export function detectLang(): Lang {
  try {
    const saved = localStorage.getItem(LS_KEY);
    if (saved === "es" || saved === "en") return saved;
  } catch { /* storage unavailable */ }
  try {
    const nav = (navigator.language || "").toLowerCase();
    if (nav.startsWith("es")) return "es";
  } catch { /* no navigator */ }
  return "en";
}

/** Module-level mirror so non-React modules can translate without hooks. */
let currentLang: Lang = "es";

export function getLang(): Lang {
  return currentLang;
}

export function setLangGlobal(lang: Lang): void {
  currentLang = lang;
  try {
    localStorage.setItem(LS_KEY, lang);
  } catch { /* storage unavailable */ }
}

// ---------------------------------------------------------------------------
// Dictionaries. Keys are stable; values are the user-visible strings.
// ---------------------------------------------------------------------------

const es = {
  // Header
  "header.beta": "Chat / Beta técnica",
  "header.verified": "Conexión verificada",
  "header.verified1": "Verificada",
  "header.verified2": "conexión",
  "header.signOut": "Cerrar sesión",
  "header.verifying": "Verificando entorno…",
  "header.notConnected": "Sin conexión",
  "header.langLabel": "Idioma",
  // Landing (signed out)
  "landing.title": "Inteligencia de frontera, confidencialidad absoluta, totalmente soberana. Tu agente.",
  "landing.copy": "Entra con Internet Identity. Tu historial se cifra en tu bóveda local.",
  "landing.signIn": "Entrar con Internet Identity",
  "landing.opening": "Abriendo Internet Identity…",
  "landing.fineprint": "La verificación del proveedor no audita toda esta aplicación. Beta técnica; no es un servicio auditado.",
  "landing.aboutLabel": "Qué es Hermetik Agent",
  "landing.aboutTitle": "Tu agente Hermes confidencial.",
  "landing.aboutLead": "Hermetik Agent es un agente Hermes confidencial que aprende de ti y se automejora con el uso. Corre en su propio contenedor seguro sobre un TEE (entorno de ejecución confiable), con inferencia confidencial. Tus prompts viajan cifrados en reposo, en tránsito y durante el cómputo: solo tú puedes verlos, nadie más.",
  "landing.f1t": "Confidencial por diseño",
  "landing.f1d": "Cifrado extremo a extremo en reposo, tránsito y cómputo. Ni el operador ni la infraestructura pueden leer tus conversaciones.",
  "landing.f2t": "Criptografía a prueba de futuro",
  "landing.f2d": "Confianza anclada en blockchain, criptografía avanzada y esquemas post-cuánticos (PQ) que protegen tus datos, incluso frente a amenazas futuras.",
  "landing.f3t": "Auditoría inmutable",
  "landing.f3d": "Cada acción del agente queda registrada en un log de auditoría inmutable: siempre puedes verificar qué se hizo en tu nombre.",
  "landing.f4t": "Memoria totalmente on-chain",
  "landing.f4d": "La memoria persistente se respalda íntegramente on-chain: tu agente te recuerda sin confiar en bases de datos de terceros.",
  "landing.f5t": "Eficiente, ecológico, abierto",
  "landing.f5d": "El modelo frontera open-source más eficiente y ecológico: inteligencia de primer nivel a una fracción del coste y la energía.",
  "landing.f6t": "Prueba de control",
  "landing.f6d": "Una capa supervisora inteligente, protegida por computación confidencial, que vigila y gobierna el comportamiento del agente, el uso de datos, el cumplimiento y la alineación.",
  // Checking / denied / error
  "access.brand": "Hermetik Agent",
  "access.checking": "Comprobando acceso…",
  "access.checkingCopy": "Verificando tu principal contra la lista de acceso del canister.",
  "access.title": "Sin autorización.",
  "access.copy": "no está en la lista de acceso. Pide al administrador que lo autorice con:",
  "access.yourPrincipal": "Tu principal",
  "access.copyBtn": "Copiar principal",
  "access.retry": "Reintentar",
  "access.user": "Usuario:",
  "app.loginFailed": "login fallido (onError sin mensaje)",
  "app.noIdentity": "sin identidad: vuelve a entrar con Internet Identity",
  // Atestación (estado permanente del enclave, ADR-01 — nunca se oculta)
  "attest.attested": "Enclave atestiguado",
  "attest.devUnattested": "Enclave NO atestiguado (dev)",
  "attest.unknown": "Atestación sin verificar",
  "attest.devWarning": "Modo desarrollo: el enclave no está atestiguado por hardware. La garantía de confidencialidad NO está activa.",
  // Pago F2 (canister access: get_payment_info → ICRC-1 al ledger)
  "pay.brand": "Hermetik Agent",
  "pay.title": "Activa tu agente.",
  "pay.copy": "Un pago único en ICP activa tu contenedor personal durante 30 días. Envía el importe exacto a la subcuenta del canister de acceso.",
  "pay.amount": "Importe:",
  "pay.subaccount": "Subcuenta:",
  "pay.howto": "Desde tu wallet ICP haz una transferencia ICRC-1 del importe exacto a esta subcuenta del ledger. Después pulsa «Ya he pagado».",
  "pay.copySub": "Copiar subcuenta",
  "pay.ivePaid": "Ya he pagado",
  // Provisioning (request_provision → el provisioner activa tu contenedor)
  "prov.brand": "Hermetik Agent",
  "prov.title": "Preparando tu contenedor…",
  "prov.copy": "Tu pago está confirmado. Estamos levantando tu gateway personal; esto tarda unos minutos.",
  "prov.timeout": "Sigue sin estar listo tras 5 minutos. Pulsa reintentar: tu pago sigue registrado.",
  "prov.tier": "Plan:",
  "prov.retry": "Reintentar",
  // Vault (locked)
  "vault.loading": "Cargando bóveda…",
  "vault.welcomeBack": "Vuelve a tu espacio.",
  "vault.createTitle": "Una conversación empieza contigo.",
  "vault.enterPw": "Introduce la contraseña de tu bóveda local.",
  "vault.createCopy": "Crea una bóveda cifrada para tus conversaciones. El historial se cifra con esta contraseña.",
  "vault.gatewayUrl": "URL del gateway",
  "vault.gatewayPlaceholder": "https://tu-tunel.trycloudflare.com",
  "vault.password": "Contraseña de la bóveda",
  "vault.yourPassword": "Tu contraseña",
  "vault.minChars": "Al menos 12 caracteres",
  "vault.unlock": "Desbloquear",
  "vault.create": "Crear bóveda y probar",
  "vault.count": "bóveda(s) en este navegador.",
  "vault.noRecover": "No podemos recuperar esta contraseña. Conserva tu contraseña y una copia cifrada. Borrar los datos del navegador puede eliminar tu historial.",
  "vault.lock": "Bloquear bóveda",
  // Chat shell
  "chat.hideList": "Ocultar lista de chats",
  "chat.showList": "Mostrar lista de chats",
  "chat.closeList": "Cerrar lista de chats",
  "chat.lockVault": "Bloquear bóveda",
  "chat.auditBackup": "Abrir el audit log (ejemplo: dashboard en mainnet, se abre en pestaña nueva)",
  "chat.auditBackupShort": "⛓ Audit / Backup",
  "chat.writing": "Hermetik está escribiendo…",
  "chat.toolFailed": "falló",
  "chat.sendCancelled": "Envío cancelado.",
  "chat.newSessionReady": "Sesión nueva lista.",
  "chat.freshRejected": "gateway: la credencial fresca también fue rechazada",
  // Sidebar
  "sidebar.newChat": "+ Nuevo chat",
  "sidebar.newChatAria": "Crear un chat nuevo",
  "sidebar.empty": "Aún no hay chats.",
  "sidebar.openChat": "Abrir",
  "sidebar.messages": "mensajes",
  // Drawer / empty chat
  "drawer.active": "Conversación activa",
  "drawer.scrollNew": "Bajar a los mensajes nuevos",
  "drawer.new": "↓ nuevo",
  "empty.brand": "Hermetik Agent",
  "empty.title": "¿Qué tienes entre manos?",
  "empty.copy": "Conecta con el gateway de Hermes para usar búsqueda confidencial e inferencia privada.",
  "empty.encrypted": "Historial cifrado en este navegador.",
  "empty.needConnection": "La inferencia real requiere una conexión verificada.",
  "empty.list": "Conversación",
  "empty.you": "Tú",
  "empty.agent": "Hermetik",
  "empty.system": "Sistema",
  // Composer
  "composer.label": "Mensaje",
  "composer.placeholder": "Escribe tu mensaje…",
  "composer.hint": "Shift + Enter para una nueva línea",
  "composer.stop": "Detener respuesta",
  "composer.stopShort": "■ Detener",
  "composer.send": "Enviar mensaje",
  "composer.sendShort": "↑ Enviar",
  "composer.note": "Revisa las respuestas antes de utilizarlas. Beta técnica; no es un servicio auditado.",
  "composer.attachImage": "Adjuntar imágenes (máx 4)",
  "composer.attachFile": "Adjuntar documento (pdf/docx/txt/md)",
  "composer.attachedImages": "Imágenes adjuntas",
  "composer.removeImage": "Quitar imagen",
  "composer.maxImages": "Máximo 4 imágenes por mensaje",
  "composer.badImage": "Alguna imagen no se pudo leer",
  "composer.uploadingFile": "Subiendo y extrayendo documento…",
  "file.attachedAs": "📎 Documento {name}:",
  "file.truncated": "texto truncado a 32KB",
  "file.tooLarge": "el archivo supera 10 MiB",
  "file.badType": "tipo no soportado (pdf/docx/txt/md)",
  "file.emptyText": "no se extrajo texto del documento",
  // Approvals
  "approval.pending": "pendiente",
  "approval.fallbackTool": "comando",
  "approval.title": "⚠ El agente pide aprobación",
  "approval.timedOut": "Tiempo agotado: el run seguirá esperando hasta el timeout del gateway.",
  "approval.left": "Quedan ~",
  "approval.leftSuffix": "s para responder",
  "approval.refresh": "Actualizar cuenta atrás",
  "approval.sending": "Enviando…",
  "approval.alwaysTitle": "Siempre aprobados",
  "approval.alwaysSection": "Aprobaciones permanentes",
  "approval.alwaysCopy": "Decisiones",
  "approval.alwaysCopy2": ": la próxima vez no se preguntará. Revocar es solo UI (viven en tu bóveda cifrada).",
  "approval.revoke": "Revocar",
  "approval.once": "Aprobar una vez",
  "approval.session": "Aprobar sesión",
  "approval.always": "Siempre",
  "approval.deny": "Denegar",
  "approval.emptyCommand": "(comando vacío)",
  // Voice
  "voice.outboundNotice": "⚠️ El audio adjunto sale de este dispositivo hacia el gateway para su transcripción (Whisper del agente).",
  "voice.notePrefix": "Nota de voz:",
  "voice.unsupported": "🎙️ Grabación de voz no soportada en este navegador.",
  "voice.record": "Grabar nota de voz",
  "voice.recordShort": "🎙️ Grabar",
  "voice.stop": "Detener grabación",
  "voice.encryptedAtRest": "cifrada en reposo con la clave de la bóveda",
  "voice.context": "Contexto opcional:",
  "voice.contextPh": "¿Qué dice la nota? (opcional)",
  "voice.contextAria": "Contexto de la nota de voz",
  "voice.send": "Enviar nota de voz",
  "voice.discard": "Descartar",
  "voice.autoStopped": "La grabación se detuvo al llegar al límite de 2 min.",
  "voice.agentAudio": "Audio del agente",
  "voice.playback": "Velocidad de reproducción",
  "voice.listen": "Escuchar respuesta",
  "voice.stopReading": "Detener lectura",
  "voice.noSupport": "este navegador no soporta grabación",
  "voice.alreadyRecording": "ya hay una grabación en curso",
  "voice.noRecording": "no hay grabación en curso",
  "voice.overLimit": "grabación por encima del límite de 2 min",
  "voice.recFailed": "la grabación falló",
  "voice.emptyTranscript": "el gateway no devolvió transcripción",
  // Gateway errors (visible via setError)
  "gw.badUrl": "gateway: URL no válida (se espera http(s)://…)",
  "gw.emptyUrl": "gateway: URL vacía",
  "gw.badCredential": "gateway: credencial no válida",
  "gw.badUser": "gateway: X-Nebulock-User no válido",
  "gw.runFailed": "run fallido",
  "gw.badChoice": "gateway: choice de aprobación no válido",
  "gw.badRunId": "gateway: run_id no válido",
  "gw.expired401": "gateway: credencial expirada o inválida (401)",
  "gw.forbidden403": "gateway: prohibido (403)",
  "gw.run404": "gateway: run no encontrado (404)",
  "gw.noPending409": "gateway: sin aprobación pendiente (409)",
  "gw.approvalRejected": "gateway: aprobación rechazada",
  "gw.rejected": "gateway: rechazó la petición",
  "gw.emptyBody": "gateway: sin cuerpo de respuesta",
  "gw.tooLong": "gateway: respuesta excede el límite",
  // /new ephemeral system prompt (sent to the LLM, not stored)
  "newCommandPrompt": "El usuario ha emitido el comando de sesión /new. Trátalo EXACTAMENTE como el comando /new del gateway (no como texto a responder): reinicia tu sesión actual — descarta el historial de esta conversación, cierra recursos del sandbox anterior y parte de contexto vacío. Confirma con una línea breve (p. ej. «Sesión nueva lista.»).",
  // Slash palette (POST /v1/commands, dispatcher real sin LLM)
  "cmd.palette": "Comandos del gateway",
  "cmd.foot": "↑↓ navegar · Tab completar · Enter ejecutar · Esc cerrar",
  "cmd.result": "Resultado del comando",
  "cmd.dismiss": "Cerrar resultado",
  "cmd.empty": "El comando no puede estar vacío",
  "cmd.tooLong": "El comando es demasiado largo",
  "cmd.emptyOutput": "(sin salida)",
  "cmd.desc.help": "Lista de comandos disponibles",
  "cmd.desc.commands": "Todos los comandos y skills (paginado)",
  "cmd.desc.profile": "Perfil activo y directorio",
  "cmd.desc.whoami": "Tu acceso y comandos ejecutables",
};

export type I18nKey = keyof typeof es;

const en: Record<I18nKey, string> = {
  "header.beta": "Chat / Technical beta",
  "header.verified": "Verified connection",
  "header.verified1": "Verified",
  "header.verified2": "connection",
  "header.signOut": "Sign out",
  "header.verifying": "Verifying environment…",
  "header.notConnected": "Not connected",
  "header.langLabel": "Language",
  "landing.title": "Frontier intelligence, absolute confidentiality, fully sovereign. Your agent.",
  "landing.copy": "Sign in with Internet Identity. Your history stays encrypted in your local vault.",
  "landing.signIn": "Sign in with Internet Identity",
  "landing.opening": "Opening Internet Identity…",
  "landing.fineprint": "Provider verification does not audit this entire application. Technical beta; not an audited service.",
  "landing.aboutLabel": "What is Hermetik Agent",
  "landing.aboutTitle": "Your confidential Hermes agent.",
  "landing.aboutLead": "Hermetik Agent is a confidential Hermes agent that learns from you and improves itself with use. It runs in its own secure container on a TEE (Trusted Execution Environment), powered by a confidential inference API. Your prompts stay encrypted at rest, in transit, and during processing — visible only to you, and to nobody else.",
  "landing.f1t": "Confidential by design",
  "landing.f1d": "End-to-end encryption across rest, transit, and compute. Neither the operator nor the infrastructure can read your conversations.",
  "landing.f2t": "Future-proof cryptography",
  "landing.f2d": "Blockchain-anchored trust, advanced cryptography, and post-quantum (PQ) schemes keep your data safe — even against future threats.",
  "landing.f3t": "Immutable audit trail",
  "landing.f3d": "Every agent action is recorded in an immutable audit log, so you can always verify what was done on your behalf.",
  "landing.f4t": "Fully on-chain memory",
  "landing.f4d": "Persistent memory is backed up fully on chain: your agent remembers you without trusting a third-party database.",
  "landing.f5t": "Efficient, eco-friendly, open",
  "landing.f5d": "Most efficient eco-friendly open-sourced frontier model: top-tier intelligence at a fraction of the cost and energy.",
  "landing.f6t": "Proof of control",
  "landing.f6d": "An intelligent, confidential computing-protected supervisory layer that guards and governs agent behavior, data use, compliance and alignment.",
  "access.brand": "Hermetik Agent",
  "access.checking": "Checking access…",
  "access.checkingCopy": "Verifying your principal against the canister access list.",
  "access.title": "Not authorized.",
  "access.copy": "is not on the access list. Ask an administrator to authorize it with:",
  "access.yourPrincipal": "Your principal",
  "access.copyBtn": "Copy principal",
  "access.retry": "Retry",
  "access.user": "User:",
  "app.loginFailed": "login failed (onError without message)",
  "app.noIdentity": "no identity: please sign in again with Internet Identity",
  "attest.attested": "Attested enclave",
  "attest.devUnattested": "Enclave NOT attested (dev)",
  "attest.unknown": "Attestation unverified",
  "attest.devWarning": "Development mode: the enclave is not hardware-attested. The confidentiality guarantee is NOT active.",
  "pay.brand": "Hermetik Agent",
  "pay.title": "Activate your agent.",
  "pay.copy": "A one-time ICP payment activates your personal container for 30 days. Send the exact amount to the access canister subaccount.",
  "pay.amount": "Amount:",
  "pay.subaccount": "Subaccount:",
  "pay.howto": "From your ICP wallet make an ICRC-1 transfer of the exact amount to this ledger subaccount. Then press “I've paid”.",
  "pay.copySub": "Copy subaccount",
  "pay.ivePaid": "I've paid",
  "prov.brand": "Hermetik Agent",
  "prov.title": "Preparing your container…",
  "prov.copy": "Your payment is confirmed. We're spinning up your personal gateway; this takes a few minutes.",
  "prov.timeout": "Still not ready after 5 minutes. Press retry: your payment is still recorded.",
  "prov.tier": "Plan:",
  "prov.retry": "Retry",
  "vault.loading": "Loading vault…",
  "vault.welcomeBack": "Welcome back to your space.",
  "vault.createTitle": "A conversation starts with you.",
  "vault.enterPw": "Enter your local vault password.",
  "vault.createCopy": "Create an encrypted vault for your conversations. History is encrypted with this password.",
  "vault.gatewayUrl": "Gateway URL",
  "vault.gatewayPlaceholder": "https://your-tunnel.trycloudflare.com",
  "vault.password": "Vault password",
  "vault.yourPassword": "Your password",
  "vault.minChars": "At least 12 characters",
  "vault.unlock": "Unlock",
  "vault.create": "Create vault and start",
  "vault.count": "vault(s) in this browser.",
  "vault.noRecover": "We cannot recover this password. Keep your password and an encrypted backup. Clearing browser data may delete your history.",
  "vault.lock": "Lock vault",
  "chat.hideList": "Hide chat list",
  "chat.showList": "Show chat list",
  "chat.closeList": "Close chat list",
  "chat.lockVault": "Lock vault",
  "chat.auditBackup": "Open the audit log (example: mainnet dashboard, opens in a new tab)",
  "chat.auditBackupShort": "⛓ Audit / Backup",
  "chat.writing": "Hermetik is writing…",
  "chat.toolFailed": "failed",
  "chat.sendCancelled": "Send cancelled.",
  "chat.newSessionReady": "New session ready.",
  "chat.freshRejected": "gateway: fresh credential was also rejected",
  "sidebar.newChat": "+ New chat",
  "sidebar.newChatAria": "Create a new chat",
  "sidebar.empty": "No chats yet.",
  "sidebar.openChat": "Open",
  "sidebar.messages": "messages",
  "drawer.active": "Active conversation",
  "drawer.scrollNew": "Scroll to new messages",
  "drawer.new": "↓ new",
  "empty.brand": "Hermetik Agent",
  "empty.title": "What are you working on?",
  "empty.copy": "Connect to the Hermes gateway for confidential search and private inference.",
  "empty.encrypted": "History encrypted in this browser.",
  "empty.needConnection": "Real inference requires a verified connection.",
  "empty.list": "Conversation",
  "empty.you": "You",
  "empty.agent": "Hermetik",
  "empty.system": "System",
  "composer.label": "Message",
  "composer.placeholder": "Write your message…",
  "composer.hint": "Shift + Enter for a new line",
  "composer.stop": "Stop response",
  "composer.stopShort": "■ Stop",
  "composer.send": "Send message",
  "composer.sendShort": "↑ Send",
  "composer.note": "Review responses before using them. Technical beta; not an audited service.",
  "composer.attachImage": "Attach images (max 4)",
  "composer.attachFile": "Attach document (pdf/docx/txt/md)",
  "composer.attachedImages": "Attached images",
  "composer.removeImage": "Remove image",
  "composer.maxImages": "Max 4 images per message",
  "composer.badImage": "Some image could not be read",
  "composer.uploadingFile": "Uploading and extracting document…",
  "file.attachedAs": "📎 Document {name}:",
  "file.truncated": "text truncated to 32KB",
  "file.tooLarge": "file exceeds 10 MiB",
  "file.badType": "unsupported type (pdf/docx/txt/md)",
  "file.emptyText": "no text extracted from document",
  "approval.pending": "pending",
  "approval.fallbackTool": "command",
  "approval.title": "⚠ The agent requests approval",
  "approval.timedOut": "Timed out: the run will keep waiting until the gateway timeout.",
  "approval.left": "About ~",
  "approval.leftSuffix": "s left to respond",
  "approval.refresh": "Refresh countdown",
  "approval.sending": "Sending…",
  "approval.alwaysTitle": "Always approved",
  "approval.alwaysSection": "Permanent approvals",
  "approval.alwaysCopy": "",
  "approval.alwaysCopy2": ": you won't be asked next time. Revoking is UI-only (they live in your encrypted vault).",
  "approval.revoke": "Revoke",
  "approval.once": "Approve once",
  "approval.session": "Approve session",
  "approval.always": "Always",
  "approval.deny": "Deny",
  "approval.emptyCommand": "(empty command)",
  "voice.outboundNotice": "⚠️ The attached audio leaves this device for the gateway for transcription (agent's Whisper).",
  "voice.notePrefix": "Voice note:",
  "voice.unsupported": "🎙️ Voice recording is not supported in this browser.",
  "voice.record": "Record voice note",
  "voice.recordShort": "🎙️ Record",
  "voice.stop": "Stop recording",
  "voice.encryptedAtRest": "encrypted at rest with the vault key",
  "voice.context": "Optional context:",
  "voice.contextPh": "What does the note say? (optional)",
  "voice.contextAria": "Voice note context",
  "voice.send": "Send voice note",
  "voice.discard": "Discard",
  "voice.autoStopped": "Recording stopped at the 2 min limit.",
  "voice.agentAudio": "Agent audio",
  "voice.playback": "Playback speed",
  "voice.listen": "Listen to response",
  "voice.stopReading": "Stop reading",
  "voice.noSupport": "this browser does not support recording",
  "voice.alreadyRecording": "a recording is already in progress",
  "voice.noRecording": "no recording in progress",
  "voice.overLimit": "recording over the 2 min limit",
  "voice.recFailed": "recording failed",
  "voice.emptyTranscript": "the gateway returned no transcript",
  "gw.badUrl": "gateway: invalid URL (expected http(s)://…)",
  "gw.emptyUrl": "gateway: empty URL",
  "gw.badCredential": "gateway: invalid credential",
  "gw.badUser": "gateway: invalid X-Nebulock-User",
  "gw.runFailed": "run failed",
  "gw.badChoice": "gateway: invalid approval choice",
  "gw.badRunId": "gateway: invalid run_id",
  "gw.expired401": "gateway: expired or invalid credential (401)",
  "gw.forbidden403": "gateway: forbidden (403)",
  "gw.run404": "gateway: run not found (404)",
  "gw.noPending409": "gateway: no pending approval (409)",
  "gw.approvalRejected": "gateway: approval rejected",
  "gw.rejected": "gateway: request rejected",
  "gw.emptyBody": "gateway: empty response body",
  "gw.tooLong": "gateway: response exceeds the limit",
  "newCommandPrompt": "The user has issued the /new session command. Treat it EXACTLY like the gateway /new command (not as text to answer): restart your current session — discard this conversation history, close previous sandbox resources and start from empty context. Confirm with one short line (e.g. «New session ready.»).",
  // Slash palette (POST /v1/commands, real dispatcher without LLM)
  "cmd.palette": "Gateway commands",
  "cmd.foot": "↑↓ navigate · Tab complete · Enter run · Esc close",
  "cmd.result": "Command result",
  "cmd.dismiss": "Dismiss result",
  "cmd.empty": "Command cannot be empty",
  "cmd.tooLong": "Command is too long",
  "cmd.emptyOutput": "(no output)",
  "cmd.desc.help": "List available commands",
  "cmd.desc.commands": "All commands and skills (paginated)",
  "cmd.desc.profile": "Active profile and home directory",
  "cmd.desc.whoami": "Your access and runnable commands",
};

const dicts: Record<Lang, Record<I18nKey, string>> = { es, en };

/** Translate without hooks (non-React modules). */
export function tr(key: I18nKey): string {
  return dicts[currentLang][key] ?? dicts.en[key] ?? key;
}

// ---------------------------------------------------------------------------
// React context
// ---------------------------------------------------------------------------

interface I18nCtx {
  lang: Lang;
  setLang: (l: Lang) => void;
  t: (key: I18nKey) => string;
}

const Ctx = createContext<I18nCtx>({
  lang: "es",
  setLang: () => {},
  t: (k) => dicts.en[k] ?? k,
});

export function I18nProvider({ children }: { children: ReactNode }) {
  const [lang, setLangState] = useState<Lang>(() => {
    const initial = detectLang();
    currentLang = initial;
    return initial;
  });
  const setLang = useCallback((l: Lang) => {
    setLangGlobal(l);
    setLangState(l);
  }, []);
  const t = useCallback((key: I18nKey): string => dicts[lang][key] ?? dicts.en[key] ?? key, [lang]);
  const value = useMemo(() => ({ lang, setLang, t }), [lang, setLang, t]);
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useI18n(): I18nCtx {
  return useContext(Ctx);
}
