import { describe, expect, it } from "vitest";
import { formatIcp, subaccountHex, deriveAttestationState } from "./app";

// F2 helpers puros: formato de ICP (e8s → "X[.yyy] ICP") y de subcuenta
// (bytes → hex minúsculas, 64 chars para 32 bytes).
describe("formatIcp", () => {
  it("formatea 5 ICP exactos", () => {
    expect(formatIcp(500_000_000n)).toBe("5 ICP");
  });
  it("formatea fracciones sin ceros a la derecha", () => {
    expect(formatIcp(1_25000000n)).toBe("1.25 ICP");
  });
  it("formatea 0 e8s", () => {
    expect(formatIcp(0n)).toBe("0 ICP");
  });
  it("formatea la unidad mínima (1 e8s)", () => {
    expect(formatIcp(1n)).toBe("0.00000001 ICP");
  });
});

describe("subaccountHex", () => {
  it("32 bytes a 64 hex minúsculas", () => {
    const sub = Array.from({ length: 32 }, (_, i) => i);
    expect(subaccountHex(sub)).toBe(
      "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    );
  });
  it("rellena con ceros a la izquierda", () => {
    expect(subaccountHex([0, 0, 255])).toBe("0000ff");
  });
  it("array vacío → cadena vacía", () => {
    expect(subaccountHex([])).toBe("");
  });
});

describe("deriveAttestationState", () => {
  it("referencia dev-unattested → dev-unattested", () => {
    expect(deriveAttestationState(["dev-unattested:abc123"])).toBe("dev-unattested");
  });
  it("referencia real (quote) → attested", () => {
    expect(deriveAttestationState(["q7lnu:some-real-quote-ref"])).toBe("attested");
  });
  it("sin referencia → unknown", () => {
    expect(deriveAttestationState([])).toBe("unknown");
  });
});
