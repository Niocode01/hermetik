// Task 11 — Reproductor inline del audio del agente + fallback local.
//
// - El agente devuelve audio como bloque `[audio:mime;base64]` en su texto
//   (generado con su tool TTS); aquí se renderiza como <audio controls> con
//   selector de velocidad 1x/1.5x/2x.
// - Sin audio del agente: botón "escuchar respuesta" con speechSynthesis
//   local (gratis, sin servidor TTS propio).

import { useEffect, useMemo, useRef, useState } from "react";
import { audioBytesFromB64, splitAudioContent, type AudioBlock } from "./audio-store";
import { cancelSpeech, extractSpeakableText, isSpeechSupported, speakText } from "./speak";
import { useI18n, getLang, tr } from "../i18n";

const SPEEDS = [1, 1.5, 2] as const;

function AgentAudio({ block, index }: { block: AudioBlock; index: number }) {
  const [speed, setSpeed] = useState<number>(1);
  const audioRef = useRef<HTMLAudioElement | null>(null);
  const src = useMemo(() => {
    try {
      const s = atob(block.base64);
      const bytes = new Uint8Array(s.length);
      for (let i = 0; i < s.length; i++) bytes[i] = s.charCodeAt(i);
      const blob = new Blob([bytes as BlobPart], { type: block.mime.split(";")[0] });
      return URL.createObjectURL(blob);
    } catch {
      return "";
    }
  }, [block]);

  useEffect(() => {
    return () => {
      if (src) URL.revokeObjectURL(src);
    };
  }, [src]);

  useEffect(() => {
    if (audioRef.current) audioRef.current.playbackRate = speed;
  }, [speed, src]);

  if (!src) return null;
  const kb = (audioBytesFromB64(block.base64) / 1024).toFixed(1);
  return (
    <figure className="audio-figure">
      <audio ref={audioRef} controls src={src} aria-label={`${tr("voice.agentAudio")} ${index + 1}`} />
      <figcaption>
        <span>
          🔊 {block.mime.split(";")[0]}
          {block.durationSec > 0 ? ` · ${block.durationSec}s` : ""} · {kb} KiB
        </span>
        <span role="group" aria-label={tr("voice.playback")}>
          {SPEEDS.map((s) => (
            <button
              key={s}
              type="button"
              onClick={() => setSpeed(s)}
              aria-pressed={speed === s}
              style={{ fontWeight: speed === s ? "bold" : "normal", marginLeft: "0.25rem" }}
            >
              {s}x
            </button>
          ))}
        </span>
      </figcaption>
    </figure>
  );
}

function ListenFallback({ content }: { content: string }) {
  const { t } = useI18n();
  const [speaking, setSpeaking] = useState(false);
  if (!isSpeechSupported()) return null;
  if (!extractSpeakableText(content)) return null;
  return (
    <div style={{ marginTop: "0.25rem" }}>
      {!speaking ? (
        <button
          type="button"
          className="listen-btn"
          onClick={() => {
            if (speakText(content, { lang: getLang() === "es" ? "es-ES" : "en-US" })) setSpeaking(true);
          }}
          aria-label={t("voice.listen")}
        >
          {t("voice.listen") && "🔊 "}{t("voice.listen")}
        </button>
      ) : (
        <button
          type="button"
          className="listen-btn"
          onClick={() => {
            cancelSpeech();
            setSpeaking(false);
          }}
          aria-label={t("voice.stopReading")}
        >
          {t("voice.stopReading") && "⏹️ "}{t("voice.stopReading")}
        </button>
      )}
    </div>
  );
}

/** Renderiza el contenido de un mensaje con reproductores inline de audio. */
export function AudioMessage({ content, showFallback = true }: { content: string; showFallback?: boolean }) {
  const segs = useMemo(() => splitAudioContent(content), [content]);
  const hasAudio = segs.some((s) => s.kind === "audio");
  let audioIdx = 0;
  return (
    <div>
      {segs.map((s, i) =>
        s.kind === "text" ? (
          s.text ? (
            <div key={i} style={{ whiteSpace: "pre-wrap", wordBreak: "break-word" }}>
              {s.text}
            </div>
          ) : null
        ) : (
          <AgentAudio key={i} block={s.block} index={audioIdx++} />
        ),
      )}
      {showFallback && !hasAudio && <ListenFallback content={content} />}
      {showFallback && hasAudio && <ListenFallback content={content} />}
    </div>
  );
}
