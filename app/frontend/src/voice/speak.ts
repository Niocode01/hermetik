// Task 11 — Fallback local de voz del agente con speechSynthesis.
//
// Cuando el agente NO devuelve audio propio (bloque [audio] TTS), el botón
// "escuchar respuesta" lee el texto en el propio navegador: gratis, sin
// servidor TTS. extractSpeakableText quita los bloques [audio] y colapsa
// espacios; habla como máximo maxChars caracteres.

import { parseAudioBlocks } from "./audio-store";

const DEFAULT_MAX_CHARS = 2_000;

function getSpeech(): SpeechSynthesis | null {
  try {
    if (typeof speechSynthesis !== "undefined" && speechSynthesis) return speechSynthesis;
  } catch {
    /* sin TTS local */
  }
  return null;
}

/** true cuando hay speechSynthesis local disponible. */
export function isSpeechSupported(): boolean {
  return getSpeech() !== null;
}

/** Texto limpio listo para leer: sin bloques [audio], espacios colapsados. */
export function extractSpeakableText(content: string, maxChars = DEFAULT_MAX_CHARS): string {
  let text = content;
  for (const b of parseAudioBlocks(content)) {
    void b;
  }
  // Quita los bloques [audio:...] por regex sobre el texto original.
  text = text.replace(/\[audio:[^\]]+\]/g, " ");
  text = text.replace(/\s+/g, " ").trim();
  if (text.length > maxChars) {
    const cut = text.slice(0, maxChars);
    const lastSpace = cut.lastIndexOf(" ");
    text = (lastSpace > maxChars * 0.5 ? cut.slice(0, lastSpace) : cut).trimEnd();
  }
  return text;
}

/**
 * Lee el texto en voz alta con la síntesis local.
 * Devuelve true si la lectura arrancó, false si no hay soporte o no hay texto.
 */
export function speakText(content: string, opts?: { lang?: string; rate?: number }): boolean {
  const synth = getSpeech();
  if (!synth) return false;
  const text = extractSpeakableText(content);
  if (!text) return false;
  try {
    synth.cancel();
    const utter = new SpeechSynthesisUtterance(text);
    if (opts?.lang) utter.lang = opts.lang;
    if (opts?.rate) utter.rate = opts.rate;
    synth.speak(utter);
    return true;
  } catch {
    return false;
  }
}

/** Detiene cualquier lectura en curso (no lanza nunca). */
export function cancelSpeech(): void {
  try {
    getSpeech()?.cancel();
  } catch {
    /* ignorar */
  }
}
