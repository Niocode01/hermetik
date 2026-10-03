// Tasks 12+13+14 — Tests de aprobaciones (TDD, sin React/DOM).
//
// - Task 12: evento sintético `approval.request` → estado (upsert por run_id,
//   sin duplicar, sin bloquear el resto del stream; `approval.responded` retira).
// - Task 13: POST /v1/runs/{run_id}/approval con cada choice vía fetch mock
//   (+ redacción de secretos / recorte del comando mostrado en la tarjeta).
// - Task 14: reglas `always` (alta idempotente, revoke por id).

import { describe, expect, it } from "vitest";
import { parseSseText, sendApproval } from "../gateway/client";
import { tr } from "../i18n";
import {
  addAlwaysRule,
  applyApprovalEvent,
  approvalSecondsLeft,
  APPROVAL_TIMEOUT_MS,
  displayCommand,
  isApprovalTimedOut,
  redactSecrets,
  removeApproval,
  revokeAlwaysRule,
  scopeKeyForApproval,
  truncateCommand,
  upsertApproval,
} from "./approvals";

const REQ = (over: Record<string, unknown> = {}) =>
  `event: approval.request\ndata: ${JSON.stringify({
    event: "approval.request",
    run_id: "run-1",
    command: "rm -rf /tmp/x",
    description: "recursive delete",
    pattern_key: "recursive delete",
    tool: "terminal",
    choices: ["once", "session", "always", "deny"],
    ...over,
  })}\n\n`;

describe("Task 12: approval.request en SSE → estado", () => {
  it("eleva approval.request con run_id + command", () => {
    const evts = parseSseText(REQ());
    expect(evts).toHaveLength(1);
    expect(evts[0]).toMatchObject({ type: "approval.request", runId: "run-1", command: "rm -rf /tmp/x" });
  });

  it("no bloquea el streaming: deltas + approval conviven en orden", () => {
    const sse =
      `data: ${JSON.stringify({ choices: [{ index: 0, delta: { content: "hola" } }] })}\n\n` +
      REQ() +
      `data: ${JSON.stringify({ choices: [{ index: 0, delta: { content: " mundo" } }] })}\n\n`;
    const evts = parseSseText(sse);
    expect(evts).toEqual([
      { type: "message.delta", delta: "hola" },
      expect.objectContaining({ type: "approval.request", runId: "run-1" }),
      { type: "message.delta", delta: " mundo" },
    ]);
  });

  it("upsert por run_id: re-emit no duplica, conserva requestedAt original", () => {
    const [evt] = parseSseText(REQ());
    if (evt.type !== "approval.request") throw new Error("esperaba approval.request");
    const a = upsertApproval([], evt, 1000);
    const b = upsertApproval(a, evt, 2000);
    expect(b).toHaveLength(1);
    expect(b[0].requestedAt).toBe(1000);
  });

  it("colas por run: dos runs → dos pendientes", () => {
    const [e1] = parseSseText(REQ({ run_id: "run-1" }));
    const [e2] = parseSseText(REQ({ run_id: "run-2", command: "shutdown now" }));
    let list = applyApprovalEvent([], e1, 1000);
    list = applyApprovalEvent(list, e2, 1000);
    expect(list.map((p) => p.runId)).toEqual(["run-1", "run-2"]);
  });

  it("approval.responded retira el pendiente (el POST local también lo retira)", () => {
    const [e1] = parseSseText(REQ());
    let list = applyApprovalEvent([], e1, 1000);
    const [resp] = parseSseText(
      `event: approval.responded\ndata: ${JSON.stringify({ event: "approval.responded", run_id: "run-1", choice: "once", resolved: 1 })}\n\n`,
    );
    list = applyApprovalEvent(list, resp, 1000);
    expect(list).toEqual([]);
    // removeApproval directo (retiro optimista tras POST 200).
    list = applyApprovalEvent([], e1, 1000);
    expect(removeApproval(list, "run-1")).toEqual([]);
  });

  it("sin run_id o sin command se ignora sin romper el stream", () => {
    const evts = parseSseText(REQ({ run_id: "" }) + REQ({ run_id: "r2", command: "" }));
    expect(evts).toEqual([]);
  });

  it("timeout: pasado gateway_timeout la tarjeta lo marca; secondsLeft cuenta atrás", () => {
    const [evt] = parseSseText(REQ());
    const list = applyApprovalEvent([], evt, 0);
    expect(isApprovalTimedOut(list[0], APPROVAL_TIMEOUT_MS - 1)).toBe(false);
    expect(isApprovalTimedOut(list[0], APPROVAL_TIMEOUT_MS)).toBe(true);
    expect(approvalSecondsLeft(list[0], 0)).toBe(APPROVAL_TIMEOUT_MS / 1000);
    expect(approvalSecondsLeft(list[0], APPROVAL_TIMEOUT_MS)).toBe(0);
  });

  it("choice inválido en approval.responded se ignora", () => {
    const evts = parseSseText(
      `event: approval.responded\ndata: ${JSON.stringify({ event: "approval.responded", run_id: "r", choice: "maybe" })}\n\n`,
    );
    expect(evts).toEqual([]);
  });
});

describe("Task 13: tarjeta (redacción) + POST approval con cada choice", () => {
  it("redacta valores de secretos pero conserva el nombre de la flag", () => {
    expect(redactSecrets("cmd --password s3cr3t --user nuno")).toContain("--password ***");
    expect(redactSecrets("cmd --password s3cr3t")).not.toContain("s3cr3t");
    expect(redactSecrets("cmd --token=abc123")).toBe("cmd --token=***");
    expect(redactSecrets("export AWS_SECRET_ACCESS_KEY=*** run")).toBe("export AWS_SECRET_ACCESS_KEY=*** run");
    expect(redactSecrets('curl -H "Authorization: Bearer tok123456" x')).not.toContain("tok123456");
    expect(redactSecrets("usa nb2.abcdef123456 ya")).toContain("nb2.***");
    expect(redactSecrets('{"api_key": "shhh"}')).toBe('{"api_key": "***"}');
  });

  it("recorta comandos largos y nombra el vacío", () => {
    expect(truncateCommand("x".repeat(500))).toMatch(/…$/);
    expect(truncateCommand("x".repeat(500))).toHaveLength(400);
    expect(truncateCommand("  ")).toBe(tr("approval.emptyCommand"));
    expect(displayCommand("ls --token abc123")).not.toContain("abc123");
  });

  it("scopeKey prefiere patternKey > description > comando", () => {
    const base = { runId: "r", command: "rm -rf /", requestedAt: 0 };
    expect(scopeKeyForApproval({ ...base, patternKey: "k", description: "d" })).toBe("k");
    expect(scopeKeyForApproval({ ...base, description: "d" })).toBe("d");
    expect(scopeKeyForApproval(base)).toBe("rm -rf /");
  });

  it.each(["once", "session", "always", "deny"] as const)(
    "POST {base}/v1/runs/{run_id}/approval con choice=%s",
    async (choice) => {
      let seenUrl = "";
      let seenBody = "";
      const fetchImpl = (async (url: string, init?: { body?: string }) => {
        seenUrl = url;
        seenBody = init?.body ?? "";
        return new Response(JSON.stringify({ run_id: "run-9", choice, resolved: 1 }), { status: 200 });
      }) as never;
      const res = await sendApproval("http://127.0.0.1:18643/v1/", "run-9", choice, {
        fetchImpl,
        credential: "nb2.test",
        user: "nuno",
      });
      expect(seenUrl).toBe("http://127.0.0.1:18643/v1/runs/run-9/approval");
      expect(JSON.parse(seenBody)).toEqual({ choice });
      expect(res).toMatchObject({ runId: "run-9", choice, resolved: 1 });
    },
  );

  it("409 sin pendiente y 404 run desconocido → GatewayError con status", async () => {
    for (const status of [409, 404]) {
      const fetchImpl = (async () => new Response("no", { status })) as never;
      await expect(
        sendApproval("http://h", "run-x", "deny", { fetchImpl, credential: "nb2.t", user: "nuno" }),
      ).rejects.toMatchObject({ status });
    }
  });

  it("choice inválido no llega a la red", async () => {
    let called = false;
    const fetchImpl = (async () => {
      called = true;
      return new Response("{}", { status: 200 });
    }) as never;
    await expect(
      sendApproval("http://h", "r", "maybe" as never, { fetchImpl, credential: "nb2.t", user: "nuno" }),
    ).rejects.toThrow();
    expect(called).toBe(false);
  });
});

describe("Task 14: always revocables", () => {
  it("alta idempotente por patternKey+tool (no duplica)", () => {
    let rules = addAlwaysRule([], { patternKey: "recursive delete", tool: "terminal" }, 1000);
    expect(rules).toHaveLength(1);
    rules = addAlwaysRule(rules, { patternKey: "recursive delete", tool: "terminal" }, 2000);
    expect(rules).toHaveLength(1);
    // Misma key, otra tool → regla aparte.
    rules = addAlwaysRule(rules, { patternKey: "recursive delete", tool: "exec" }, 2000);
    expect(rules).toHaveLength(2);
  });

  it("revoke por id deja el resto intacto", () => {
    let rules = addAlwaysRule([], { patternKey: "a" }, 1000);
    rules = addAlwaysRule(rules, { patternKey: "b" }, 1000);
    const victim = rules[0].id;
    const rest = revokeAlwaysRule(rules, victim);
    expect(rest.map((r) => r.patternKey)).toEqual(["b"]);
    expect(revokeAlwaysRule(rest, "id-que-no-existe")).toEqual(rest);
  });
});
