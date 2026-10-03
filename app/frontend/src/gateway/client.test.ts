import { describe, expect, it } from "vitest";
import { normalizeUrl, buildHeaders, parseSseText, streamChat, sendSlashCommand, uploadFile, GatewayError } from "./client";
import type { GatewayEvent } from "./types";
import { SLASH_COMMANDS } from "./types";
import { tr } from "../i18n";

describe("gateway normalizeUrl (Task 9)", () => {
  it("quita trailing slashes", () => {
    expect(normalizeUrl("http://127.0.0.1:18643/")).toBe("http://127.0.0.1:18643");
    expect(normalizeUrl("http://127.0.0.1:18643///")).toBe("http://127.0.0.1:18643");
  });

  it("quita /v1 colgado (el cliente añade /v1 al endpoint)", () => {
    expect(normalizeUrl("http://127.0.0.1:18643/v1")).toBe("http://127.0.0.1:18643");
    expect(normalizeUrl("http://127.0.0.1:18643/v1/")).toBe("http://127.0.0.1:18643");
  });

  it("deja la base sin /v1 tal cual (recorta espacios)", () => {
    expect(normalizeUrl("  http://127.0.0.1:18643  ")).toBe("http://127.0.0.1:18643");
  });

  it("rechaza esquema no-http y vacío", () => {
    expect(() => normalizeUrl("")).toThrow();
    expect(() => normalizeUrl("ftp://x/")).toThrow();
    expect(() => normalizeUrl("notaurl")).toThrow();
  });
});

describe("gateway buildHeaders (Task 9)", () => {
  it("emite Authorization Bearer + X-Nebulock-User + JSON", () => {
    const h = buildHeaders("nb2.abc123", "nuno");
    expect(h["Authorization"]).toBe("Bearer nb2.abc123");
    expect(h["X-Nebulock-User"]).toBe("nuno");
    expect(h["Content-Type"]).toBe("application/json");
  });

  it("rechaza credencial vacía o gigante", () => {
    expect(() => buildHeaders("  ", "nuno")).toThrow();
    expect(() => buildHeaders("x".repeat(5000), "nuno")).toThrow();
  });

  it("rechaza user con espacios o inyección de cabecera", () => {
    expect(() => buildHeaders("nb2.x", "")).toThrow();
    expect(() => buildHeaders("nb2.x", "nuno perez")).toThrow();
    expect(() => buildHeaders("nb2.x", "a:b")).toThrow();
    expect(() => buildHeaders("nb2.x", "a\nb")).toThrow();
  });
});

const OPENAI_CHUNK = (content: string) =>
  `data: ${JSON.stringify({
    id: "chatcmpl-1",
    object: "chat.completion.chunk",
    created: 1,
    model: "nebulock-confidential",
    choices: [{ index: 0, delta: { content }, finish_reason: null }],
  })}`;

describe("gateway parseSseText (Task 9)", () => {
  it("chunks OpenAI delta.content → message.delta; role-only se ignora", () => {
    const sse =
      `data: ${JSON.stringify({
        choices: [{ index: 0, delta: { role: "assistant" }, finish_reason: null }],
      })}\n\n` +
      OPENAI_CHUNK("Hola") +
      "\n\n" +
      OPENAI_CHUNK(" mundo") +
      "\n\n";
    const evts = parseSseText(sse);
    expect(evts).toEqual([
      { type: "message.delta", delta: "Hola" },
      { type: "message.delta", delta: " mundo" },
    ]);
  });

  it("evento con nombre hermes.tool.progress running/completed → tool.started/tool.completed", () => {
    const sse =
      `event: hermes.tool.progress\ndata: ${JSON.stringify({
        toolCallId: "c1",
        status: "running",
        tool: "terminal",
        label: "ejecutando",
      })}\n\n` +
      `event: hermes.tool.progress\ndata: ${JSON.stringify({
        toolCallId: "c1",
        status: "completed",
        tool: "terminal",
      })}\n\n`;
    const evts = parseSseText(sse);
    expect(evts).toEqual([
      { type: "tool.started", tool: "terminal", preview: "ejecutando" },
      { type: "tool.completed", tool: "terminal", error: false },
    ]);
  });

  it("eventos estructurados de runs (message.delta/tool.started/tool.completed/run.completed/run.failed)", () => {
    const sse =
      `event: message.delta\ndata: ${JSON.stringify({ event: "message.delta", delta: "ho" })}\n\n` +
      `event: tool.started\ndata: ${JSON.stringify({ event: "tool.started", tool: "whisper", preview: "x" })}\n\n` +
      `event: tool.completed\ndata: ${JSON.stringify({ event: "tool.completed", tool: "whisper", error: false })}\n\n` +
      `event: run.completed\ndata: ${JSON.stringify({ event: "run.completed", output: "listo" })}\n\n`;
    const evts = parseSseText(sse);
    expect(evts).toEqual([
      { type: "message.delta", delta: "ho" },
      { type: "tool.started", tool: "whisper", preview: "x" },
      { type: "tool.completed", tool: "whisper", error: false },
      { type: "run.completed", output: "listo" },
    ]);
  });

  it("run.failed → error; [DONE] → done; keepalive se ignora", () => {
    const sse =
      `: keepalive\n\n` +
      `event: run.failed\ndata: ${JSON.stringify({ event: "run.failed", error: "boom" })}\n\n` +
      `data: [DONE]\n\n`;
    expect(parseSseText(sse)).toEqual([
      { type: "run.failed", error: "boom" },
      { type: "done" },
    ]);
  });

  it("JSON roto se ignora sin romper el resto", () => {
    const evts = parseSseText(`data: {no-json\n\n` + OPENAI_CHUNK("ok") + `\n\n`);
    expect(evts).toEqual([{ type: "message.delta", delta: "ok" }]);
  });
});

// --- streamChat con fetch sintético ---

function sseResponse(chunks: string[], status = 200): Response {
  const enc = new TextEncoder();
  const stream = new ReadableStream<Uint8Array>({
    start(c) {
      for (const ch of chunks) c.enqueue(enc.encode(ch));
      c.close();
    },
  });
  return new Response(stream, { status, headers: { "Content-Type": "text/event-stream" } });
}

async function collect<T>(gen: AsyncGenerator<T>): Promise<T[]> {
  const out: T[] = [];
  for await (const v of gen) out.push(v);
  return out;
}

describe("gateway streamChat (Task 9)", () => {
  it("POST a {base}/v1/chat/completions con cabeceras y cuerpo stream:true", async () => {
    let seenUrl = "";
    let seenInit: Record<string, unknown> = {};
    const fetchImpl = async (url: string, init?: Record<string, unknown>) => {
      seenUrl = url;
      seenInit = init ?? {};
      return sseResponse([OPENAI_CHUNK("hi") + "\n\ndata: [DONE]\n\n"]);
    };
    const evts = await collect(
      streamChat(
        {
          baseUrl: "http://127.0.0.1:18643/v1/",
          credential: "nb2.test",
          user: "nuno",
          model: "nebulock-confidential",
          messages: [{ role: "user", content: "hola" }],
        },
        { fetchImpl: fetchImpl as never },
      ),
    );
    expect(seenUrl).toBe("http://127.0.0.1:18643/v1/chat/completions");
    const headers = seenInit["headers"] as Record<string, string>;
    expect(headers["Authorization"]).toBe("Bearer nb2.test");
    expect(headers["X-Nebulock-User"]).toBe("nuno");
    const body = JSON.parse(seenInit["body"] as string) as Record<string, unknown>;
    expect(body["stream"]).toBe(true);
    expect(body["model"]).toBe("nebulock-confidential");
    expect(evts).toContainEqual({ type: "message.delta", delta: "hi" });
    expect(evts[evts.length - 1]).toEqual({ type: "done" });
  });

  it("reensambla líneas partidas entre chunks de red", async () => {
    const full = OPENAI_CHUNK("abcdef") + "\n\n";
    const cut = Math.floor(full.length / 2);
    const fetchImpl = async () =>
      sseResponse([full.slice(0, cut), full.slice(cut), "data: [DONE]\n\n"]);
    const evts: GatewayEvent[] = await collect(
      streamChat(
        {
          baseUrl: "http://127.0.0.1:18643",
          credential: "nb2.test",
          user: "nuno",
          messages: [{ role: "user", content: "h" }],
        },
        { fetchImpl: fetchImpl as never },
      ),
    );
    expect(evts).toContainEqual({ type: "message.delta", delta: "abcdef" });
  });

  it("401 → GatewayError con status 401 (el workspace refresca credencial)", async () => {
    const fetchImpl = async () => new Response("unauthorized", { status: 401 });
    await expect(
      collect(
        streamChat(
          {
            baseUrl: "http://127.0.0.1:18643",
            credential: "nb2.expirada",
            user: "nuno",
            messages: [{ role: "user", content: "h" }],
          },
          { fetchImpl: fetchImpl as never },
        ),
      ),
    ).rejects.toMatchObject({ status: 401 });
  });

  it("señal abortada cancela el stream (AbortController)", async () => {
    const fetchImpl = async (_url: string, init?: { signal?: AbortSignal }) => {
      if (init?.signal?.aborted) throw new DOMException("aborted", "AbortError");
      return sseResponse([OPENAI_CHUNK("x") + "\n\n"]);
    };
    const ctrl = new AbortController();
    ctrl.abort();
    await expect(
      collect(
        streamChat(
          {
            baseUrl: "http://127.0.0.1:18643",
            credential: "nb2.test",
            user: "nuno",
            messages: [{ role: "user", content: "h" }],
          },
          { fetchImpl: fetchImpl as never, signal: ctrl.signal },
        ),
      ),
    ).rejects.toThrow();
    expect(GatewayError).toBeDefined();
  });
});

// --- sendSlashCommand (POST /v1/commands, dispatcher real sin LLM) ---

function jsonResponse(payload: unknown, status = 200): Response {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

describe("gateway sendSlashCommand (paleta /)", () => {
  it("POST a {base}/v1/commands con {command} y cabeceras nb2", async () => {
    let seenUrl = "";
    let seenInit: Record<string, unknown> = {};
    const fetchImpl = async (url: string, init?: Record<string, unknown>) => {
      seenUrl = url;
      seenInit = init ?? {};
      return jsonResponse({ object: "hermes.command.result", command: "whoami", raw_command: "/whoami", output: "You — test", ephemeral: false });
    };
    const res = await sendSlashCommand("http://127.0.0.1:18643/v1/", "/whoami", {
      credential: "nb2.test",
      user: "nuno",
      fetchImpl: fetchImpl as never,
    });
    expect(seenUrl).toBe("http://127.0.0.1:18643/v1/commands");
    const headers = seenInit["headers"] as Record<string, string>;
    expect(headers["Authorization"]).toBe("Bearer nb2.test");
    expect(headers["X-Nebulock-User"]).toBe("nuno");
    const body = JSON.parse(seenInit["body"] as string) as Record<string, unknown>;
    expect(body["command"]).toBe("/whoami");
    expect(res).toEqual({ command: "whoami", rawCommand: "/whoami", output: "You — test", ephemeral: false });
  });

  it("normaliza comando sin slash inicial", async () => {
    let seenBody = "";
    const fetchImpl = async (_url: string, init?: Record<string, unknown>) => {
      seenBody = String((init as Record<string, unknown>)["body"] ?? "");
      return jsonResponse({ command: "help", output: "x" });
    };
    await sendSlashCommand("http://127.0.0.1:18643", "help", {
      credential: "nb2.test",
      user: "nuno",
      fetchImpl: fetchImpl as never,
    });
    expect(JSON.parse(seenBody)["command"]).toBe("/help");
  });

  it("401/403 → GatewayError con status (el workspace refresca credencial)", async () => {
    for (const status of [401, 403]) {
      const fetchImpl = async () => new Response("denied", { status });
      await expect(
        sendSlashCommand("http://127.0.0.1:18643", "/whoami", {
          credential: "nb2.x",
          user: "nuno",
          fetchImpl: fetchImpl as never,
        }),
      ).rejects.toMatchObject({ status });
    }
  });

  it("comando vacío o gigante → GatewayError local (sin fetch)", async () => {
    let called = false;
    const fetchImpl = async () => {
      called = true;
      return jsonResponse({});
    };
    await expect(
      sendSlashCommand("http://127.0.0.1:18643", "   ", {
        credential: "nb2.test",
        user: "nuno",
        fetchImpl: fetchImpl as never,
      }),
    ).rejects.toThrow();
    await expect(
      sendSlashCommand("http://127.0.0.1:18643", `/${"x".repeat(300)}`, {
        credential: "nb2.test",
        user: "nuno",
        fetchImpl: fetchImpl as never,
      }),
    ).rejects.toThrow();
    expect(called).toBe(false);
  });

  it("SLASH_COMMANDS espeja la allowlist del server (help/commands/profile/whoami)", () => {
    expect([...SLASH_COMMANDS].sort()).toEqual(["commands", "help", "profile", "whoami"]);
  });
});

describe("gateway uploadFile (adjuntos)", () => {
  it("POST multipart a {base}/v1/files con auth nb2, devuelve texto", async () => {
    let seenUrl = "";
    let seenInit: Record<string, unknown> = {};
    const fetchImpl = async (url: string, init?: Record<string, unknown>) => {
      seenUrl = url;
      seenInit = init ?? {};
      return jsonResponse({ filename: "doc.pdf", text: "hola mundo", truncated: false });
    };
    const f = new File(["x"], "doc.pdf", { type: "application/pdf" });
    const res = await uploadFile("http://127.0.0.1:18643/", "nb2.test", "nuno", f, {
      fetchImpl: fetchImpl as never,
    });
    expect(seenUrl).toBe("http://127.0.0.1:18643/v1/files");
    const headers = seenInit["headers"] as Record<string, string>;
    expect(headers["Authorization"]).toBe("Bearer nb2.test");
    expect(seenInit["body"]).toBeInstanceOf(FormData);
    expect(res).toEqual({ filename: "doc.pdf", text: "hola mundo", truncated: false });
  });

  it("401/403 → GatewayError con status; 413/415 → errores locales", async () => {
    const f = new File(["x"], "doc.pdf", { type: "application/pdf" });
    for (const status of [401, 403]) {
      const fetchImpl = async () => new Response("denied", { status });
      await expect(
        uploadFile("http://127.0.0.1:18643", "nb2.x", "nuno", f, { fetchImpl: fetchImpl as never }),
      ).rejects.toMatchObject({ status });
    }
    for (const [status, key] of [[413, "file.tooLarge"], [415, "file.badType"]] as const) {
      const fetchImpl = async () => new Response("no", { status });
      await expect(
        uploadFile("http://127.0.0.1:18643", "nb2.x", "nuno", f, { fetchImpl: fetchImpl as never }),
      ).rejects.toThrow(tr(key));
    }
  });

  it("texto vacío → file.emptyText", async () => {
    const f = new File(["x"], "a.txt", { type: "text/plain" });
    const fetchImpl = async () => jsonResponse({ filename: "a.txt", text: "   " });
    await expect(
      uploadFile("http://127.0.0.1:18643", "nb2.x", "nuno", f, { fetchImpl: fetchImpl as never }),
    ).rejects.toThrow(tr("file.emptyText"));
  });
});

describe("gateway streamChat multimodal", () => {
  it("envía content como lista text+image_url sin romper el stream", async () => {
    let seenBody = "";
    const fetchImpl = async (_url: string, init?: Record<string, unknown>) => {
      seenBody = String((init as Record<string, unknown>)["body"] ?? "");
      return sseResponse(['data: {"choices":[{"delta":{"content":"veo"}}]}\n\ndata: [DONE]\n\n']);
    };
    const out: string[] = [];
    for await (const evt of streamChat(
      {
        baseUrl: "http://127.0.0.1:18643",
        credential: "nb2.test",
        user: "nuno",
        messages: [
          { role: "user", content: [{ type: "text", text: "qué ves" }, { type: "image_url", image_url: { url: "data:image/jpeg;base64,AAA" } }] },
        ],
      },
      { fetchImpl: fetchImpl as never },
    )) {
      if (evt.type === "message.delta") out.push(evt.delta);
    }
    const body = JSON.parse(seenBody) as Record<string, unknown>;
    const msgs = body["messages"] as Array<Record<string, unknown>>;
    const parts = msgs[0]["content"] as Array<Record<string, unknown>>;
    expect(parts[0]).toEqual({ type: "text", text: "qué ves" });
    expect((parts[1]["image_url"] as Record<string, string>)["url"]).toMatch(/^data:image\//);
    expect(out.join("")).toBe("veo");
  });
});
