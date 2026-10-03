// Task 10 (TDD) — Tests de notas de voz del usuario:
// recorder (mime/size/duración) + audio-store (cifrado del blob + bloques).
import { describe, expect, it } from "vitest";
import {
  MAX_AUDIO_BYTES,
  MAX_RECORDING_MS,
  PREFERRED_MIMES,
  VoiceRecorder,
  base64ToBlob,
  blobToBase64,
  formatDuration,
  isOverDuration,
  pickMimeType,
  validateAudioSize,
} from "./recorder";
import {
  audioBytesFromB64,
  buildAudioBlock,
  decryptAudio,
  encryptAudio,
  hasAudioBlock,
  parseAudioBlocks,
  splitAudioContent,
} from "./audio-store";

describe("recorder pickMimeType (Task 10)", () => {
  it("prefiere audio/webm;codecs=opus cuando está soportado", () => {
    const got = pickMimeType(() => true);
    expect(got).toBe("audio/webm;codecs=opus");
  });

  it("fallback a audio/mp4 (Safari/iOS) cuando webm no está soportado", () => {
    const got = pickMimeType((m) => m === "audio/mp4");
    expect(got).toBe("audio/mp4");
  });

  it("devuelve cadena vacía cuando nada está soportado o no hay MediaRecorder", () => {
    expect(pickMimeType(() => false)).toBe("");
    expect(pickMimeType(undefined)).toBe("");
  });

  it("la lista de preferidos empieza por opus/webm e incluye mp4", () => {
    expect(PREFERRED_MIMES[0]).toBe("audio/webm;codecs=opus");
    expect(PREFERRED_MIMES).toContain("audio/mp4");
  });
});

describe("recorder límites (Task 10)", () => {
  it("límite de grabación: 2 min", () => {
    expect(MAX_RECORDING_MS).toBe(120_000);
    expect(isOverDuration(119_999)).toBe(false);
    expect(isOverDuration(120_000)).toBe(true);
    expect(isOverDuration(180_000)).toBe(true);
  });

  it("límite de tamaño: 5 MiB exactos pasan, un byte más rechaza", () => {
    expect(() => validateAudioSize(MAX_AUDIO_BYTES)).not.toThrow();
    expect(MAX_AUDIO_BYTES).toBe(5 * 1024 * 1024);
    expect(() => validateAudioSize(MAX_AUDIO_BYTES + 1)).toThrow(/5 MiB/);
    expect(() => validateAudioSize(0)).not.toThrow();
  });

  it("formatDuration m:ss", () => {
    expect(formatDuration(0)).toBe("0:00");
    expect(formatDuration(5_000)).toBe("0:05");
    expect(formatDuration(75_000)).toBe("1:15");
    expect(formatDuration(120_000)).toBe("2:00");
  });

  it("VoiceRecorder.isSupported() es false en Node (sin MediaRecorder)", () => {
    expect(VoiceRecorder.isSupported()).toBe(false);
  });
});

describe("recorder base64 (Task 10)", () => {
  it("blob → base64 → blob roundtrip conserva bytes y mime", async () => {
    const raw = new Uint8Array([0, 1, 2, 250, 255, 16, 32]);
    const blob = new Blob([raw as BlobPart], { type: "audio/webm" });
    const b64 = await blobToBase64(blob);
    const back = base64ToBlob(b64, "audio/webm");
    expect(back.type).toBe("audio/webm");
    expect(new Uint8Array(await back.arrayBuffer())).toEqual(raw);
  });
});

const TEST_ITERATIONS = 1_000; // rápido en tests; el path productivo usa 600k (ver último test)

describe("audio-store cifrado del blob (Task 10)", () => {
  const bytes = () => new Uint8Array([10, 20, 30, 40, 50, 60, 70, 80, 90, 100]);

  it("roundtrip cifrar → descifrar conserva bytes y mime", async () => {
    const enc = await encryptAudio("clave-boveda", "vault-1", bytes(), "audio/webm", {
      iterations: TEST_ITERATIONS,
    });
    expect(enc.vaultId).toBe("vault-1");
    expect(enc.mime).toBe("audio/webm");
    expect(enc.ciphertextB64).not.toContain("ChQe");
    const back = await decryptAudio("clave-boveda", enc);
    expect(back.mime).toBe("audio/webm");
    expect(back.bytes).toEqual(bytes());
  });

  it("contraseña incorrecta rechaza", async () => {
    const enc = await encryptAudio("clave-boveda", "vault-1", bytes(), "audio/webm", {
      iterations: TEST_ITERATIONS,
    });
    await expect(decryptAudio("otra-clave", enc)).rejects.toThrow(/descifrar/);
  });

  it("vaultId manipulado rechaza (AAD ligado a vaultId)", async () => {
    const enc = await encryptAudio("clave-boveda", "vault-1", bytes(), "audio/webm", {
      iterations: TEST_ITERATIONS,
    });
    await expect(decryptAudio("clave-boveda", { ...enc, vaultId: "vault-impostor" })).rejects.toThrow();
  });

  it("mime manipulado rechaza (AAD ligado al mime)", async () => {
    const enc = await encryptAudio("clave-boveda", "vault-1", bytes(), "audio/webm", {
      iterations: TEST_ITERATIONS,
    });
    await expect(decryptAudio("clave-boveda", { ...enc, mime: "audio/mp4" })).rejects.toThrow();
  });

  it("ciphertext manipulado rechaza (integridad AES-GCM)", async () => {
    const enc = await encryptAudio("clave-boveda", "vault-1", bytes(), "audio/webm", {
      iterations: TEST_ITERATIONS,
    });
    const raw = Uint8Array.from(atob(enc.ciphertextB64), (c) => c.charCodeAt(0));
    raw[0] ^= 0xff;
    let s = "";
    for (const b of raw) s += String.fromCharCode(b);
    await expect(decryptAudio("clave-boveda", { ...enc, ciphertextB64: btoa(s) })).rejects.toThrow();
  });

  it("cifrar por encima de 5 MiB rechaza antes de tocar WebCrypto", async () => {
    await expect(
      encryptAudio("clave-boveda", "vault-1", new Uint8Array(MAX_AUDIO_BYTES + 1), "audio/webm", {
        iterations: TEST_ITERATIONS,
      }),
    ).rejects.toThrow(/5 MiB/);
  });

  it("mime no-audio rechaza", async () => {
    await expect(
      encryptAudio("clave-boveda", "vault-1", bytes(), "video/mp4", { iterations: TEST_ITERATIONS }),
    ).rejects.toThrow(/mime/);
  });

  it("path productivo con iteraciones por defecto (PBKDF2 600k) roundtrip", async () => {
    const enc = await encryptAudio("clave-boveda", "vault-1", bytes(), "audio/mp4");
    const back = await decryptAudio("clave-boveda", enc);
    expect(back.bytes).toEqual(bytes());
  }, 90_000);
});

describe("audio-store bloques [audio] en texto (Task 10)", () => {
  it("build → parse roundtrip conserva mime, base64 y duración", () => {
    const block = buildAudioBlock("audio/webm", "QUJDRA==", 12);
    const blocks = parseAudioBlocks(`hola\n${block}\nchau`);
    expect(blocks).toHaveLength(1);
    expect(blocks[0].mime).toBe("audio/webm");
    expect(blocks[0].base64).toBe("QUJDRA==");
    expect(blocks[0].durationSec).toBe(12);
  });

  it("texto sin bloques → cero bloques; hasAudioBlock false", () => {
    expect(parseAudioBlocks("hola mundo")).toEqual([]);
    expect(hasAudioBlock("hola mundo")).toBe(false);
    expect(hasAudioBlock(buildAudioBlock("audio/mp4", "eA=="))).toBe(true);
  });

  it("splitAudioContent separa texto antes/después del bloque", () => {
    const block = buildAudioBlock("audio/webm", "QUJD", 5);
    const segs = splitAudioContent(`antes\n${block}\ndespués`);
    expect(segs.length).toBe(3);
    expect(segs[0]).toEqual({ kind: "text", text: "antes\n" });
    expect(segs[1].kind).toBe("audio");
    expect(segs[2]).toEqual({ kind: "text", text: "\ndespués" });
  });

  it("múltiples bloques se parsean todos en orden", () => {
    const text = `${buildAudioBlock("audio/webm", "QUE=", 3)}\nintermedio\n${buildAudioBlock("audio/mp4", "QlE=", 7)}`;
    const blocks = parseAudioBlocks(text);
    expect(blocks.map((b) => b.mime)).toEqual(["audio/webm", "audio/mp4"]);
    expect(blocks.map((b) => b.durationSec)).toEqual([3, 7]);
  });

  it("audioBytesFromB64 estima bytes del base64", () => {
    // "QUJD" = 3 bytes "ABC"
    expect(audioBytesFromB64("QUJD")).toBe(3);
    expect(audioBytesFromB64("QUI=")).toBe(2);
  });
});
