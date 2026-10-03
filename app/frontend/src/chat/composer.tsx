// Task 9 — Composer: caja de texto + enviar (+ cancelar mientras hay stream).
// El botón Enviar/Detener va DENTRO de la caja, a la derecha del textarea
// (una sola fila, sin banda inferior que ocupe altura vertical).
// Controlado: `value`/`onChange` para que el workspace detecte "/" inicial
// y abra la paleta de slash commands. No-controlado también vale (sin props).
import { useI18n } from "../i18n";
import { useRef, useState } from "react";

/** Adjuntos de imagen listos para enviar (data URL + miniatura). */
export interface ImageAttachment {
  id: string;
  name: string;
  dataUrl: string;
}

/** Extensiones de imagen aceptadas (fallback cuando el navegador no informa MIME). */
const IMAGE_EXT_RE = /\.(jpe?g|png|webp|gif)$/i;

export function isImageFile(f: File): boolean {
  if (f.type && f.type.startsWith("image/")) return true;
  // Algunos selectores devuelven application/octet-stream o vacío (WebViews):
  // aceptar por extensión en esos casos.
  if ((!f.type || f.type === "application/octet-stream") && IMAGE_EXT_RE.test(f.name)) return true;
  return false;
}
/** Lee un File de imagen, lo reescala (lado mayor ≤ 1568px) y devuelve data URL JPEG/PNG. */
export function fileToDataUrl(file: File, maxSide = 1568, quality = 0.85): Promise<ImageAttachment> {
  return new Promise((resolve, reject) => {
    const url = URL.createObjectURL(file);
    let settled = false;
    const done = (fn: () => void) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      fn();
    };
    // Fallback: si el navegador no decodifica el blob para reescalar
    // (algunas WebViews), adjuntar el original sin reescalar vía FileReader.
    const fallbackRaw = () => {
      try {
        const reader = new FileReader();
        reader.onload = () => {
          done(() =>
            resolve({
              id: `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
              name: file.name,
              dataUrl: String(reader.result ?? ""),
            }),
          );
        };
        reader.onerror = () => done(() => reject(new Error("unreadable image")));
        reader.readAsDataURL(file);
      } catch (err) {
        done(() => reject(err instanceof Error ? err : new Error(String(err))));
      }
    };
    // Blindaje: en algunas WebViews onload/onerror no disparan nunca
    // (JPEG progresivo, HEIC renombrado…). Sin timeout la promesa queda
    // colgada para siempre y la UI falla en silencio.
    const timer = setTimeout(() => {
      URL.revokeObjectURL(url);
      // Timeout: intentar adjuntar el original antes de rendirse.
      fallbackRaw();
      setTimeout(() => done(() => reject(new Error("image load timeout"))), 5000);
    }, 15000);
    const img = new Image();
    img.onload = () => {
      done(() => {
        URL.revokeObjectURL(url);
        try {
          const scale = Math.min(1, maxSide / Math.max(img.width, img.height));
          const w = Math.max(1, Math.round(img.width * scale));
          const h = Math.max(1, Math.round(img.height * scale));
          const canvas = document.createElement("canvas");
          canvas.width = w;
          canvas.height = h;
          const ctx = canvas.getContext("2d");
          if (!ctx) {
            reject(new Error("no 2d context"));
            return;
          }
          ctx.drawImage(img, 0, 0, w, h);
          const mime = file.type === "image/png" ? "image/png" : "image/jpeg";
          resolve({
            id: `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
            name: file.name,
            dataUrl: canvas.toDataURL(mime, quality),
          });
        } catch (err) {
          reject(err instanceof Error ? err : new Error(String(err)));
        }
      });
    };
    img.onerror = () => {
      URL.revokeObjectURL(url);
      // onerror: la imagen no se pudo decodificar para reescalar, pero el
      // archivo puede ser legible → adjuntar original antes de rendirse.
      if (!settled) {
        fallbackRaw();
        setTimeout(() => done(() => reject(new Error("unreadable image"))), 5000);
        return;
      }
      done(() => reject(new Error("unreadable image")));
    };
    img.src = url;
  });
}

export function Composer({
  busy,
  onSend,
  onCancel,
  value,
  onChange,
  onSlashKey,
  inputRef,
  images,
  onAddImages,
  onRemoveImage,
  onAttachFile,
  attachBusy,
}: {
  busy: boolean;
  onSend: (text: string) => void;
  onCancel: () => void;
  /** Controlado (paleta /): si se pasa, el textarea usa value/onChange. */
  value?: string;
  onChange?: (text: string) => void;
  /** Teclas para la paleta (ArrowUp/Down/Tab/Escape con "/" activo). */
  onSlashKey?: (e: React.KeyboardEvent<HTMLTextAreaElement>) => boolean;
  inputRef?: React.Ref<HTMLTextAreaElement>;
  /** Imágenes adjuntas pendientes de envío. */
  images?: ImageAttachment[];
  onAddImages?: (files: FileList | null) => void;
  onRemoveImage?: (id: string) => void;
  /** Documentos (pdf/docx/txt/md): subida + extracción vía POST /v1/files. */
  onAttachFile?: (files: FileList | null) => void;
  attachBusy?: boolean;
}) {
  const { t } = useI18n();
  const fileRef = useRef<HTMLInputElement>(null);
  const imgRef = useRef<HTMLInputElement>(null);
  const [imgError, setImgError] = useState("");
  const submit = (form: HTMLFormElement) => {
    const data = new FormData(form);
    // En modo controlado el value manda (FormData puede ir vacío tras reset).
    const raw = value !== undefined ? value : String(data.get("message") ?? "");
    const text = raw.trim();
    if ((!text && !(images ?? []).length) || busy) return;
    form.reset();
    if (onChange) onChange("");
    onSend(text);
  };

  return (
    <>
      {(images ?? []).length > 0 && (
        <div className="attach-preview" role="list" aria-label={t("composer.attachedImages")}>
          {(images ?? []).map((a) => (
            <div key={a.id} className="attach-thumb" role="listitem" title={a.name}>
              <img src={a.dataUrl} alt={a.name} />
              <button
                type="button"
                className="attach-remove"
                aria-label={`${t("composer.removeImage")}: ${a.name}`}
                disabled={busy}
                onClick={() => onRemoveImage?.(a.id)}
              >
                ×
              </button>
            </div>
          ))}
        </div>
      )}
      <form
        className="composer composer-inline"
        onSubmit={(e) => {
          e.preventDefault();
          submit(e.currentTarget);
        }}
      >
        <input
          ref={imgRef}
          type="file"
          accept="image/jpeg,image/png,image/webp,image/gif"
          multiple
          style={{ position: "absolute", width: 1, height: 1, opacity: 0, pointerEvents: "none" }}
          aria-hidden
          tabIndex={-1}
          onChange={(e) => {
            const input = e.target;
            const picked = input.files ? Array.from(input.files) : [];
            input.value = "";
            if (!picked.length) return;
            if ((images ?? []).length + picked.length > 4) {
              setImgError(t("composer.maxImages"));
              return;
            }
            setImgError("");
            // File[] directo (no FileList): evita que React Native/WebView
            // invalide la referencia antes de leerla.
            const dt = new DataTransfer();
            picked.forEach((f) => dt.items.add(f));
            onAddImages?.(dt.files);
          }}
        />
        <input
          ref={fileRef}
          type="file"
          accept=".pdf,.docx,.txt,.md,application/pdf,application/vnd.openxmlformats-officedocument.wordprocessingml.document,text/plain,text/markdown"
          style={{ position: "absolute", width: 1, height: 1, opacity: 0, pointerEvents: "none" }}
          aria-hidden
          tabIndex={-1}
          onChange={(e) => {
            const input = e.target;
            const picked = input.files ? Array.from(input.files) : [];
            input.value = "";
            if (!picked.length) return;
            const dt = new DataTransfer();
            picked.forEach((f) => dt.items.add(f));
            onAttachFile?.(dt.files);
          }}
        />
        <button
          type="button"
          className="btn-attach"
          aria-label={t("composer.attachImage")}
          title={t("composer.attachImage")}
          disabled={busy || attachBusy}
          onClick={() => imgRef.current?.click()}
        >
          📷
        </button>
        <button
          type="button"
          className="btn-attach"
          aria-label={t("composer.attachFile")}
          title={t("composer.attachFile")}
          disabled={busy || attachBusy}
          onClick={() => fileRef.current?.click()}
        >
          📎
        </button>
        <label className="sr-only" htmlFor="message">{t("composer.label")}</label>
        <textarea
          id="message"
          name="message"
          autoComplete="off"
          placeholder={t("composer.placeholder")}
          disabled={busy}
          aria-label={t("composer.label")}
          ref={inputRef}
          value={value}
          onChange={value !== undefined && onChange ? (e) => onChange(e.target.value) : undefined}
          onKeyDown={(e) => {
            const ta = e.currentTarget;
            // La paleta tiene prioridad: si consume la tecla, no enviar.
            if (onSlashKey && onSlashKey(e)) return;
            if (e.key === "Enter" && !e.shiftKey && !(e.nativeEvent as unknown as { isComposing?: boolean }).isComposing) {
              e.preventDefault();
              const form = ta.closest("form");
              if (form) submit(form);
            }
          }}
        />
        {busy ? (
          <button type="button" className="btn-send" onClick={onCancel} aria-label={t("composer.stop")}>
            {t("composer.stopShort")}
          </button>
        ) : (
          <button type="submit" className="btn-send" aria-label={t("composer.send")}>{t("composer.sendShort")}</button>
        )}
      </form>
      <p className="composer-note">{attachBusy ? t("composer.uploadingFile") : imgError || t("composer.note")}</p>
    </>
  );
}
