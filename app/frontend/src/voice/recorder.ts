import { tr } from "../i18n";

// Task 10 — Grabación de notas de voz (MediaRecorder, sin servidor STT propio).
//
// - Se prefiere `audio/webm;codecs=opus`; fallback a `audio/mp4` (Safari/iOS,
//   donde Opus/webm puede no estar). El agente transcribe ambos con Whisper.
// - Límites: 2 min de grabación / 5 MiB por nota.
// - Utilidades puras (pickMimeType, validateAudioSize, base64) testeables sin
//   micrófono; VoiceRecorder envuelve MediaRecorder + getUserMedia.

/** Máximo tamaño de una nota de voz: 5 MiB. */
export const MAX_AUDIO_BYTES = 5 * 1024 * 1024;


/** Máxima duración de grabación: 2 min (ms). */
export const MAX_RECORDING_MS = 120_000;

/** Mimes preferidos en orden (Opus/webm primero, mp4 para Safari/iOS). */
export const PREFERRED_MIMES = [
  "audio/webm;codecs=opus",
  "audio/webm",
  "audio/mp4",
] as const;

/**
 * Elige el primer mime soportado según `isSupported`.
 * `isSupported` ausente (sin MediaRecorder, p. ej. Node/tests) → "".
 */
export function pickMimeType(isSupported?: (mime: string) => boolean): string {
  if (!isSupported) return "";
  for (const m of PREFERRED_MIMES) {
    try {
      if (isSupported(m)) return m;
    } catch {
      /* probar el siguiente */
    }
  }
  return "";
}

/** Lanza si el blob supera los 5 MiB. */
export function validateAudioSize(sizeBytes: number): void {
  if (sizeBytes > MAX_AUDIO_BYTES) {
    throw new Error(
      `voz: la nota supera el límite de 5 MiB (${(sizeBytes / 1048576).toFixed(1)} MiB)`,
    );
  }
}

/** true cuando la duración en ms supera los 2 min. */
export function isOverDuration(elapsedMs: number): boolean {
  return elapsedMs >= MAX_RECORDING_MS;
}

/** Formato m:ss para el cronómetro de grabación. */
export function formatDuration(ms: number): string {
  const totalSec = Math.max(0, Math.floor(ms / 1000));
  return `${Math.floor(totalSec / 60)}:${String(totalSec % 60).padStart(2, "0")}`;
}

/** Blob → base64 crudo (sin prefijo data:). */
export async function blobToBase64(blob: Blob): Promise<string> {
  const buf = new Uint8Array(await blob.arrayBuffer());
  let s = "";
  const CHUNK = 0x8000;
  for (let i = 0; i < buf.length; i += CHUNK) {
    s += String.fromCharCode(...buf.subarray(i, i + CHUNK));
  }
  return btoa(s);
}

/** base64 crudo → Blob con el mime dado. */
export function base64ToBlob(b64: string, mime: string): Blob {
  const s = atob(b64);
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return new Blob([out as BlobPart], { type: mime });
}

export interface RecordingResult {
  blob: Blob;
  mime: string;
  durationMs: number;
}

/**
 * Envoltorio fino de MediaRecorder:
 * pide micro, graba con el mejor mime y auto-detiene a los 2 min.
 */
export class VoiceRecorder {
  static isSupported(): boolean {
    return (
      typeof MediaRecorder !== "undefined" &&
      typeof navigator !== "undefined" &&
      !!navigator.mediaDevices?.getUserMedia
    );
  }

  private rec: MediaRecorder | null = null;
  private stream: MediaStream | null = null;
  private chunks: Blob[] = [];
  private startedAt = 0;
  private timer: ReturnType<typeof setTimeout> | null = null;
  /** Se invoca cuando el auto-stop de 2 min dispara (la UI puede avisarlo). */
  onAutoStop: (() => void) | null = null;

  get recording(): boolean {
    return this.rec !== null;
  }

  async start(): Promise<void> {
    if (!VoiceRecorder.isSupported()) throw new Error(`voice: ${tr("voice.noSupport")}`);
    if (this.rec) throw new Error(`voice: ${tr("voice.alreadyRecording")}`);
    const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
    this.stream = stream;
    this.chunks = [];
    const mime = pickMimeType((m) => {
      try {
        return MediaRecorder.isTypeSupported(m);
      } catch {
        return false;
      }
    });
    const rec = mime ? new MediaRecorder(stream, { mimeType: mime }) : new MediaRecorder(stream);
    rec.ondataavailable = (e: BlobEvent) => {
      if (e.data && e.data.size > 0) this.chunks.push(e.data);
    };
    rec.start(250);
    this.rec = rec;
    this.startedAt = Date.now();
    this.timer = setTimeout(() => {
      this.onAutoStop?.();
      void this.stop().catch(() => {
        /* el error de stop lo recoge quien espera la promesa original */
      });
    }, MAX_RECORDING_MS);
  }

  stop(): Promise<RecordingResult> {
    const rec = this.rec;
    if (!rec) return Promise.reject(new Error(`voice: ${tr("voice.noRecording")}`));
    if (this.timer) {
      clearTimeout(this.timer);
      this.timer = null;
    }
    const durationMs = Date.now() - this.startedAt;
    return new Promise<RecordingResult>((resolve, reject) => {
      rec.onstop = () => {
        this.rec = null;
        for (const t of this.stream?.getTracks() ?? []) t.stop();
        this.stream = null;
        if (isOverDuration(durationMs + 1000)) {
          reject(new Error(`voice: ${tr("voice.overLimit")}`));
          return;
        }
        const mime = rec.mimeType || "audio/webm";
        const blob = new Blob(this.chunks, { type: mime });
        try {
          validateAudioSize(blob.size);
        } catch (e) {
          reject(e instanceof Error ? e : new Error(String(e)));
          return;
        }
        resolve({ blob, mime, durationMs });
      };
      rec.onerror = () => {
        this.rec = null;
        reject(new Error(`voice: ${tr("voice.recFailed")}`));
      };
      rec.stop();
    });
  }

  /** Cancela sin devolver audio (suelta el micro). */
  cancel(): void {
    if (this.timer) {
      clearTimeout(this.timer);
      this.timer = null;
    }
    try {
      this.rec?.stop();
    } catch {
      /* ya detenida */
    }
    this.rec = null;
    for (const t of this.stream?.getTracks() ?? []) t.stop();
    this.stream = null;
    this.chunks = [];
  }
}
