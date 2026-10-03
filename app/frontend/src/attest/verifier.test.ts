/**
 * F4 — Casos NEGATIVOS del verificador de atestación (ADR-01, Nivel 2).
 *
 * Un verificador que acepta un mock es indistinguible de uno que dice "sí" a
 * todo. Estos tests existen para probar que RECHAZA, que es la mitad del valor
 * del verificador. Se ejecutan sin TEE: la atestación es una interfaz, así que
 * el formato del quote se puede simular.
 */
import { describe, it, expect } from "vitest";
import {
  buildDevQuote,
  buildQuote,
  expectedReportData,
  isDevAttestation,
  verifyQuote,
  DEV_ATTEST_PREFIX,
  type AttestationQuote,
  type VerificationPolicy,
} from "./verifier";

const NONCE = "a".repeat(64);
const BIN = "b".repeat(64);
const ROOT = "amd-root-2026";
const PUB = "c2Vzc2lvbi1wdWItYmFzZTY0";
const NOW = 1_000_000_000_000_000_000;
const FUTURE = NOW + 60_000_000_000;

function policy(over: Partial<VerificationPolicy> = {}): VerificationPolicy {
  return {
    vendorRoots: { "amd-sev-snp": [ROOT] },
    expectedBinaryHash: BIN,
    vendor: "amd-sev-snp",
    ...over,
  };
}

async function goodQuote(): Promise<AttestationQuote> {
  return buildQuote({
    reportData: await expectedReportData(NONCE, BIN),
    vendor: "amd-sev-snp",
    roots: [ROOT],
    binaryHash: BIN,
    sessionPub: PUB,
    expiresAt: FUTURE,
  });
}

describe("verificador de atestación — camino feliz", () => {
  it("acepta un quote bien formado y ligado a la sesión", async () => {
    const r = await verifyQuote(await goodQuote(), NONCE, policy(), NOW);
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.state).toBe("attested");
  });

  it("report_data depende del nonce (dos sesiones distintas no comparten quote)", async () => {
    const a = await expectedReportData(NONCE, BIN);
    const b = await expectedReportData("c".repeat(64), BIN);
    expect(a).not.toBe(b);
  });

  it("report_data depende del binario", async () => {
    const a = await expectedReportData(NONCE, BIN);
    const b = await expectedReportData(NONCE, "d".repeat(64));
    expect(a).not.toBe(b);
  });
});

describe("verificador de atestación — CASOS NEGATIVOS (debe rechazar)", () => {
  it("rechaza firma del quote corrupta", async () => {
    const q = await goodQuote();
    const bad = buildQuote({
      reportData: await expectedReportData(NONCE, BIN),
      vendor: "amd-sev-snp",
      roots: [ROOT],
      binaryHash: BIN,
      sessionPub: PUB,
      expiresAt: FUTURE,
      signatureValid: false,
    });
    expect((await verifyQuote(q, NONCE, policy(), NOW)).ok).toBe(true);
    const r = await verifyQuote(bad, NONCE, policy(), NOW);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toContain("firma");
  });

  it("rechaza report_data que no corresponde al binario", async () => {
    const q = await goodQuote();
    q.binary_hash = "e".repeat(64); // el pinning del cliente lo cazará
    const r = await verifyQuote(q, NONCE, policy(), NOW);
    expect(r.ok).toBe(false);
  });

  it("rechaza un quote capturado de OTRA sesion (anti-replay por nonce)", async () => {
    const q = await goodQuote(); // ligado a NONCE
    const r = await verifyQuote(q, "f".repeat(64), policy(), NOW);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toContain("report_data");
  });

  it("rechaza un quote caducado", async () => {
    const q = await goodQuote();
    q.expires_at = NOW - 1_000_000_000_000; // una hora atras
    const r = await verifyQuote(q, NONCE, policy(), NOW);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toContain("caducado");
  });

  it("rechaza una raiz desconocida", async () => {
    const q = await goodQuote();
    const r = await verifyQuote(q, NONCE, policy({ vendorRoots: { "amd-sev-snp": ["otra-raiz"] } }), NOW);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toContain("raiz");
  });

  it("rechaza si no hay raices configuradas", async () => {
    const q = await goodQuote();
    const r = await verifyQuote(q, NONCE, policy({ vendorRoots: {} }), NOW);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toContain("raices");
  });

  it("rechaza un vendor inesperado", async () => {
    const q = await goodQuote();
    q.vendor = "intel-tdx";
    const r = await verifyQuote(q, NONCE, policy(), NOW);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toContain("vendor");
  });

  it("rechaza un binario distinto (pinning)", async () => {
    const q = await goodQuote();
    const r = await verifyQuote(q, NONCE, policy({ expectedBinaryHash: "9".repeat(64) }), NOW);
    expect(r.ok).toBe(false);
  });

  it("rechaza un quote ausente o vacio", async () => {
    const r = await verifyQuote({} as AttestationQuote, NONCE, policy(), NOW);
    expect(r.ok).toBe(false);
  });

  it("rechaza un nonce demasiado corto", async () => {
    const r = await verifyQuote(await goodQuote(), "abc", policy(), NOW);
    expect(r.ok).toBe(false);
  });

  it("rechaza un quote cuya cadena es ilegible", async () => {
    const q = await goodQuote();
    q.quote = "texto-sin-formato-de-quote";
    const r = await verifyQuote(q, NONCE, policy(), NOW);
    expect(r.ok).toBe(false);
  });
});

describe("modo desarrollo — NO es un fallback", () => {
  it("rechaza un quote de desarrollo si no se acepta explicitamente", async () => {
    const q = await buildDevQuote(NONCE, BIN, PUB, FUTURE);
    const r = await verifyQuote(q, NONCE, policy(), NOW, /* acceptDev */ false);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toContain("no esta atestiguado");
  });

  it("acepta un quote de desarrollo solo con aceptacion explicita", async () => {
    const q = await buildDevQuote(NONCE, BIN, PUB, FUTURE);
    const r = await verifyQuote(q, NONCE, policy(), NOW, true);
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.state).toBe("dev-unattested");
  });

  it("un quote de desarrollo NUNCA se reporta como atestiguado", async () => {
    const q = await buildDevQuote(NONCE, BIN, PUB, FUTURE);
    const r = await verifyQuote(q, NONCE, policy(), NOW, true);
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.state).not.toBe("attested");
  });

  it("rechaza si el estado dice dev pero el quote no lleva el prefijo", async () => {
    const q = await goodQuote();
    q.attestation_state = "dev-unattested";
    const r = await verifyQuote(q, NONCE, policy(), NOW, true);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toContain("prefijo");
  });

  it("detecta el prefijo de desarrollo de forma inconfundible", () => {
    expect(isDevAttestation(DEV_ATTEST_PREFIX + "x")).toBe(true);
    expect(isDevAttestation("snp:" + "a".repeat(128))).toBe(false);
    expect(isDevAttestation("")).toBe(false);
  });
});
