// Task 11 (TDD) — Tests de voz del agente: speak.ts (fallback speechSynthesis local).
import { describe, expect, it } from "vitest";
import { buildAudioBlock } from "./audio-store";
import { cancelSpeech, extractSpeakableText, isSpeechSupported, speakText } from "./speak";

describe("speak fallback local (Task 11)", () => {
  it("extractSpeakableText quita los bloques [audio] y deja el texto", () => {
    const content = `Hola, aquí está el audio:\n${buildAudioBlock("audio/webm", "QUJDRA==", 4)}\nSaludos.`;
    expect(extractSpeakableText(content)).toBe("Hola, aquí está el audio: Saludos.");
  });

  it("texto sin bloques pasa casi intacto (colapsa espacios)", () => {
    expect(extractSpeakableText("  hola   mundo\nnuevo  ")).toBe("hola mundo nuevo");
  });

  it("solo-audio → cadena vacía", () => {
    expect(extractSpeakableText(buildAudioBlock("audio/mp4", "eA==", 9))).toBe("");
  });

  it("trunca a maxChars sin cortar a mitad de palabra si puede", () => {
    const long = "palabra ".repeat(500);
    const got = extractSpeakableText(long, 100);
    expect(got.length).toBeLessThanOrEqual(100);
    expect(got).not.toMatch(/ $/);
  });

  it("en Node no hay speechSynthesis: isSpeechSupported false y speakText no lanza", () => {
    expect(isSpeechSupported()).toBe(false);
    expect(speakText("hola")).toBe(false);
    expect(() => cancelSpeech()).not.toThrow();
  });
});
