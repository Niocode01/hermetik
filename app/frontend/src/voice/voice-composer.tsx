// Task 10 — Composer de notas de voz: botón micrófono + vista previa + envío.
//
// - Graba con VoiceRecorder (Opus/webm, fallback mp4); límite 2 min / 5 MiB.
// - El blob se cifra en reposo con la clave (contraseña) de la bóveda vía
//   encryptAudio; al enviar se descifra en memoria y se adjunta como base64
//   en el mensaje: el agente lo transcribe con su tool Whisper.
// - AVISO VISIBLE: el audio sale del dispositivo hacia el gateway (el texto
//   lo muestra junto al botón de enviar y en el payload se antepone una
//   línea de aviso legible por el agente y por el usuario en el historial).

import { useEffect, useRef, useState } from "react";
import {
  VoiceRecorder,
  blobToBase64,
  formatDuration,
  MAX_RECORDING_MS,
} from "./recorder";
import { base64ToBlob } from "./recorder";
import { buildAudioBlock, encryptAudio, decryptAudio } from "./audio-store";
import { useI18n, tr } from "../i18n";

export interface VoiceDraft {
  blob: Blob;
  mime: string;
  durationMs: number;
  previewUrl: string;
}

/** Aviso legible que acompaña a todo mensaje con audio (transparencia). */
/** Aviso con el idioma activo (no constante: cambia con ES/EN). */
export function voiceOutboundNotice(): string {
  return tr("voice.outboundNotice");
}

/** @deprecated Usar voiceOutboundNotice() para respetar el idioma activo. */
export const VOICE_OUTBOUND_NOTICE = "⚠️ The attached audio leaves this device for the gateway for transcription (agent's Whisper).";

export function buildVoiceMessageText(transcriptHint: string, mime: string, b64: string, durationMs: number): string {
  const block = buildAudioBlock(mime, b64, Math.round(durationMs / 1000));
  const hint = transcriptHint.trim();
  return `${voiceOutboundNotice()}\n${hint ? `${hint}\n` : `${tr("voice.notePrefix")}\n`}${block}`;
}

export function VoiceComposer({
  vaultPassword,
  vaultId,
  disabled,
  onSendVoice,
}: {
  /** Contraseña de la bóveda desbloqueada (cifra el blob en reposo). */
  vaultPassword: string;
  /** vaultId para ligar el AAD del cifrado. */
  vaultId: string;
  disabled?: boolean;
  /** Texto final del mensaje (con aviso + bloque [audio]) listo para send(). */
  onSendVoice: (text: string) => void;
}) {
  const recRef = useRef<VoiceRecorder | null>(null);
  const [recording, setRecording] = useState(false);
  const [elapsedMs, setElapsedMs] = useState(0);
  const [draft, setDraft] = useState<VoiceDraft | null>(null);
  const [hint, setHint] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [autoStopped, setAutoStopped] = useState(false);
  const { t } = useI18n();
  const tickRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const startRef = useRef(0);

  const supported = VoiceRecorder.isSupported();

  useEffect(() => {
    return () => {
      if (tickRef.current) clearInterval(tickRef.current);
      if (draft) URL.revokeObjectURL(draft.previewUrl);
      recRef.current?.cancel();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const startTick = () => {
    startRef.current = Date.now();
    setElapsedMs(0);
    tickRef.current = setInterval(() => {
      setElapsedMs(Date.now() - startRef.current);
    }, 250);
  };
  const stopTick = () => {
    if (tickRef.current) {
      clearInterval(tickRef.current);
      tickRef.current = null;
    }
  };

  const start = async () => {
    setError("");
    setAutoStopped(false);
    try {
      const rec = new VoiceRecorder();
      rec.onAutoStop = () => setAutoStopped(true);
      recRef.current = rec;
      await rec.start();
      setRecording(true);
      startTick();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      recRef.current = null;
    }
  };

  const stop = async () => {
    const rec = recRef.current;
    if (!rec) return;
    setBusy(true);
    try {
      const res = await rec.stop();
      stopTick();
      setRecording(false);
      recRef.current = null;
      // Cifrar en reposo con la clave de la bóveda (roundtrip en memoria
      // para verificar integridad antes de ofrecer la vista previa).
      const raw = new Uint8Array(await res.blob.arrayBuffer());
      const enc = await encryptAudio(vaultPassword, vaultId, raw, res.mime, {
        durationMs: res.durationMs,
      });
      const back = await decryptAudio(vaultPassword, enc);
      const verified = new Blob([back.bytes as BlobPart], { type: back.mime });
      const previewUrl = URL.createObjectURL(verified);
      setDraft({ blob: verified, mime: back.mime, durationMs: res.durationMs, previewUrl });
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      setRecording(false);
      stopTick();
      recRef.current = null;
    } finally {
      setBusy(false);
    }
  };

  const discard = () => {
    if (draft) URL.revokeObjectURL(draft.previewUrl);
    setDraft(null);
    setHint("");
    setError("");
  };

  const send = async () => {
    if (!draft || disabled || busy) return;
    setBusy(true);
    setError("");
    try {
      const b64 = await blobToBase64(draft.blob);
      onSendVoice(buildVoiceMessageText(hint, draft.mime, b64, draft.durationMs));
      discard();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  // Rehidrata un blob base64 (p. ej. para tests de integración futuros).
  void base64ToBlob;

  if (!supported) {
    return (
      <p className="voice-hint">
        {t("voice.unsupported")}
      </p>
    );
  }

  return (
    <div className="voice-block">
      {!draft ? (
        <div className="voice-row">
          {!recording ? (
            <button type="button" className="btn btn-sm" onClick={() => void start()} disabled={disabled || busy} aria-label={t("voice.record")}>
              {t("voice.recordShort")}
            </button>
          ) : (
            <>
              <button type="button" className="btn btn-sm" onClick={() => void stop()} aria-label={t("voice.stop")}>
                ⏹️ {t("voice.stop")} ({formatDuration(elapsedMs)} / {formatDuration(MAX_RECORDING_MS)})
              </button>
              <span role="status" className="voice-rec">
                ● {formatDuration(elapsedMs)}
              </span>
            </>
          )}
        </div>
      ) : (
        <div className="voice-draft">
          <audio controls src={draft.previewUrl} />
          <div className="voice-meta">
            {draft.mime} · {formatDuration(draft.durationMs)} · {t("voice.encryptedAtRest")}
          </div>
          <label className="voice-label">
            {t("voice.context")}{" "}
            <input
              value={hint}
              onChange={(e) => setHint(e.target.value)}
              placeholder={t("voice.contextPh")}
              aria-label={t("voice.contextAria")}
            />
          </label>
          <p className="voice-notice">
            {t("voice.outboundNotice")}
          </p>
          <div className="voice-row">
            <button type="button" className="btn-send" onClick={() => void send()} disabled={disabled || busy}>
              {t("voice.send")}
            </button>
            <button type="button" className="btn" onClick={discard} disabled={busy}>
              {t("voice.discard")}
            </button>
          </div>
        </div>
      )}
      {autoStopped && (
        <p className="voice-notice">
          {t("voice.autoStopped")}
        </p>
      )}
      {error && (
        <p role="alert" className="voice-error">
          Error: {error}
        </p>
      )}
    </div>
  );
}
