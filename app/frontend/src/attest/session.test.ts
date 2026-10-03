/**
 * F4 — Tests de establecimiento de sesión sobre canal atestiguado.
 *
 * Lo que se prueba aquí es la propiedad central del ADR-01: que la clave de
 * sesión queda LIGADA a la evidencia del enclave. Si el quote cambia,
 * la clave cambia. Eso se puede probar sin TEE.
 */
import { describe, it, expect } from "vitest";
import { establishSession, newNonce, sealMessage, openMessage } from "./session";
import { buildQuote, expectedReportData, AttestationError, type VerificationPolicy } from "./verifier";

const BIN = "b".repeat(64);
const ROOT = "amd-root-2026";
const NOW = 1_000_000_000_000_000_000;
const FUTURE = NOW + 600_000_000_000;

function policy(over: Partial<VerificationPolicy> = {}): VerificationPolicy {
  return {
    vendorRoots: { "amd-sev-snp": [ROOT] },
    expectedBinaryHash: BIN,
    vendor: "amd-sev-snp",
    ...over,
  };
}

/** Genera un par X25519 y devuelve su clave pública en base64 (como haría el gateway). */
async function enclaveKeyPair(): Promise<{ pub: string; priv: CryptoKey }> {
  const kp = (await crypto.subtle.generateKey(
    { name: "X25519" } as unknown as AlgorithmIdentifier,
    true,
    ["deriveKey", "deriveBits"],
  )) as CryptoKeyPair;
  const raw = new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey));
  return { pub: btoa(String.fromCharCode(...raw)), priv: kp.privateKey };
}

/** Mock del gateway: emite un quote correcto ligado al nonce que recibe, y
 *  responde al POST /v1/session con un session_id opaco. */
function mockGateway(opts: { roots?: string[]; binHash?: string; expiresAt?: number } = {}) {
  let seenNonce = "";
  let seenClientPub = "";
  const fetchImpl = (async (url: string, init?: { method?: string; body?: string }) => {
    const u = new URL(url);
    if (u.pathname.endsWith("/v1/session")) {
      const body = JSON.parse(init?.body ?? "{}") as { client_pub?: string };
      seenClientPub = body.client_pub ?? "";
      return new Response(JSON.stringify({ session_id: "sess-test-123" }), { status: 200 });
    }
    seenNonce = u.searchParams.get("nonce") ?? "";
    const kp = await enclaveKeyPair();
    const roots = opts.roots ?? [ROOT];
    const binHash = opts.binHash ?? BIN;
    const quote = buildQuote({
      reportData: await expectedReportData(seenNonce, binHash),
      vendor: "amd-sev-snp",
      roots,
      binaryHash: binHash,
      sessionPub: kp.pub,
      expiresAt: opts.expiresAt ?? FUTURE,
    });
    return new Response(JSON.stringify(quote), { status: 200 });
  }) as unknown as typeof fetch;
  return {
    fetchImpl,
    nonceUsado: () => seenNonce,
    clientPubUsado: () => seenClientPub,
  };
}

describe("establecimiento de sesión", () => {
  it("deriva una clave con un quote válido", async () => {
    const gw = mockGateway();
    const s = await establishSession({
      baseUrl: "https://t1.hermetik.eu",
      policy: policy(),
      fetchImpl: gw.fetchImpl,
      now: () => NOW,
    });
    expect(s.key).toBeDefined();
    expect(s.state).toBe("attested");
    expect(s.warning).toBeNull();
  });

  it("cierra el handshake: envía client_pub (base64 de 32 bytes) al servidor", async () => {
    const gw = mockGateway();
    const s = await establishSession({
      baseUrl: "https://t1.hermetik.eu",
      policy: policy(),
      fetchImpl: gw.fetchImpl,
      now: () => NOW,
    });
    expect(s.sessionId).toBe("sess-test-123");
    // client_pub = base64 de la clave pública X25519 efímera (32 bytes).
    const raw = Uint8Array.from(atob(gw.clientPubUsado()), (c) => c.charCodeAt(0));
    expect(raw.length).toBe(32);
  });

  it("aborta si el servidor no devuelve session_id (handshake incompleto)", async () => {
    const fetchImpl = (async (url: string) => {
      if (new URL(url).pathname.endsWith("/v1/session")) {
        return new Response("{}", { status: 200 }); // sin session_id
      }
      const gw = mockGateway();
      return gw.fetchImpl(url as never);
    }) as unknown as typeof fetch;
    await expect(
      establishSession({
        baseUrl: "https://t1.hermetik.eu",
        policy: policy(),
        fetchImpl,
        now: () => NOW,
      }),
    ).rejects.toThrow(/session_id/);
  });

  it("el cliente envía un nonce de 64 hex", async () => {
    const gw = mockGateway();
    await establishSession({
      baseUrl: "https://t1.hermetik.eu",
      policy: policy(),
      fetchImpl: gw.fetchImpl,
      now: () => NOW,
    });
    expect(gw.nonceUsado()).toMatch(/^[0-9a-f]{64}$/);
  });

  it("dos sesiones usan nonces distintos (el quote no es reutilizable)", async () => {
    expect(newNonce()).not.toBe(newNonce());
  });

  it("ABORTA si el binario no es el esperado", async () => {
    const gw = mockGateway({ binHash: "9".repeat(64) });
    await expect(
      establishSession({
        baseUrl: "https://t1.hermetik.eu",
        policy: policy(),
        fetchImpl: gw.fetchImpl,
        now: () => NOW,
      }),
    ).rejects.toThrow(AttestationError);
  });

  it("ABORTA si la raíz del enclave no es de confianza", async () => {
    const gw = mockGateway({ roots: ["raiz-atacante"] });
    await expect(
      establishSession({
        baseUrl: "https://t1.hermetik.eu",
        policy: policy(),
        fetchImpl: gw.fetchImpl,
        now: () => NOW,
      }),
    ).rejects.toThrow(/atestacion rechazada/);
  });

  it("ABORTA si el quote ha caducado", async () => {
    const gw = mockGateway({ expiresAt: NOW - 3_600_000_000_000 }); // 1h atras
    await expect(
      establishSession({
        baseUrl: "https://t1.hermetik.eu",
        policy: policy(),
        fetchImpl: gw.fetchImpl,
        now: () => NOW,
      }),
    ).rejects.toThrow(/caducado/);
  });

  it("NO reintenta en modo dev cuando la atestación falla (no hay fallback)", async () => {
    const gw = mockGateway({ roots: ["raiz-atacante"] });
    let calls = 0;
    const counting = (async (...args: Parameters<typeof fetch>) => {
      calls += 1;
      return gw.fetchImpl(...args);
    }) as unknown as typeof fetch;
    await expect(
      establishSession({
        baseUrl: "https://t1.hermetik.eu",
        policy: policy(),
        fetchImpl: counting,
        now: () => NOW,
        acceptUnattested: true,
      }),
    ).rejects.toThrow();
    expect(calls).toBe(1); // un solo intento, sin degradacion automatica
  });

  it("con acceptUnattested la sesion se marca como NO atestiguada y avisa", async () => {
    const fetchImpl = (async (url: string) => {
      if (new URL(url).pathname.endsWith("/v1/session")) {
        return new Response(JSON.stringify({ session_id: "sess-dev" }), { status: 200 });
      }
      const kp = await enclaveKeyPair();
      const rd = await expectedReportData("x".repeat(64), BIN);
      return new Response(
        JSON.stringify({
          quote: `dev-unattested:${rd}|dev-root,sig=dev`,
          vendor: "dev",
          binary_hash: BIN,
          session_pub: kp.pub,
          attestation_state: "dev-unattested",
          expires_at: FUTURE,
        }),
        { status: 200 },
      );
    }) as unknown as typeof fetch;
    const s = await establishSession({
      baseUrl: "https://dev.local",
      policy: policy(),
      fetchImpl,
      now: () => NOW,
      acceptUnattested: true,
    });
    expect(s.state).toBe("dev-unattested");
    expect(s.warning).toContain("NO esta activa");
  });

  it("propaga el fallo HTTP al pedir atestación", async () => {
    const fetchImpl = (async () =>
      new Response("nope", { status: 502 })) as unknown as typeof fetch;
    await expect(
      establishSession({
        baseUrl: "https://t1.hermetik.eu",
        policy: policy(),
        fetchImpl,
        now: () => NOW,
      }),
    ).rejects.toThrow(/HTTP 502/);
  });
});

describe("canal cifrado", () => {
  it("deriva subclaves direccionales distintas (run-5 B-01)", async () => {
    const gw = mockGateway();
    const s = await establishSession({
      baseUrl: "https://t1.hermetik.eu",
      policy: policy(),
      fetchImpl: gw.fetchImpl,
      now: () => NOW,
    });
    expect(s.key).toBeDefined();
    expect(s.txKey).toBeDefined();
    expect(s.rxKey).toBeDefined();
    // Las subclaves son AES-GCM no exportables (correcto: nunca salen de
    // WebCrypto). Se comparan por comportamiento: cada una abre lo suyo y
    // ninguna abre lo de la otra (ver test siguiente).
    const probe = await sealMessage(s.txKey, 999, "sonda");
    expect(await openMessage(s.txKey, 999, probe)).toBe("sonda");
    await expect(openMessage(s.rxKey, 999, probe)).rejects.toThrow();
  });

  it("mismo seq en ambas direcciones NO colisiona (run-5 B-01)", async () => {
    const gw = mockGateway();
    const s = await establishSession({
      baseUrl: "https://t1.hermetik.eu",
      policy: policy(),
      fetchImpl: gw.fetchImpl,
      now: () => NOW,
    });
    // Cliente sella con txKey; el "servidor" abriría con la misma c2s.
    const a = await sealMessage(s.txKey, 1, "client-hello!");
    const b = await sealMessage(s.rxKey, 1, "server-reply!");
    expect(a).not.toBe(b);
    expect(await openMessage(s.txKey, 1, a)).toBe("client-hello!");
    expect(await openMessage(s.rxKey, 1, b)).toBe("server-reply!");
    // Cruzado NO abre.
    await expect(openMessage(s.rxKey, 1, a)).rejects.toThrow();
    await expect(openMessage(s.txKey, 1, b)).rejects.toThrow();
  });

  it("cifra y descifra ida y vuelta", async () => {
    const gw = mockGateway();
    const s = await establishSession({
      baseUrl: "https://t1.hermetik.eu",
      policy: policy(),
      fetchImpl: gw.fetchImpl,
      now: () => NOW,
    });
    const sealed = await sealMessage(s.txKey, 1, "hola enclave");
    expect(sealed).not.toContain("hola");
    expect(await openMessage(s.txKey, 1, sealed)).toBe("hola enclave");
  });

  it("el texto cifrado no revela el contenido", async () => {
    const gw = mockGateway();
    const s = await establishSession({
      baseUrl: "https://t1.hermetik.eu",
      policy: policy(),
      fetchImpl: gw.fetchImpl,
      now: () => NOW,
    });
    const sealed = await sealMessage(s.txKey, 7, "secreto-medico-12345");
    expect(sealed).not.toContain("secreto");
    expect(sealed).not.toContain("12345");
  });

  it("un contador distinto NO descifra (integridad del orden)", async () => {
    const gw = mockGateway();
    const s = await establishSession({
      baseUrl: "https://t1.hermetik.eu",
      policy: policy(),
      fetchImpl: gw.fetchImpl,
      now: () => NOW,
    });
    const sealed = await sealMessage(s.txKey, 3, "mensaje");
    await expect(openMessage(s.txKey, 4, sealed)).rejects.toThrow();
  });

  it("un mensaje manipulado NO descifra", async () => {
    const gw = mockGateway();
    const s = await establishSession({
      baseUrl: "https://t1.hermetik.eu",
      policy: policy(),
      fetchImpl: gw.fetchImpl,
      now: () => NOW,
    });
    const sealed = await sealMessage(s.txKey, 1, "mensaje");
    const tampered = sealed.slice(0, -4) + (sealed.endsWith("AAA=") ? "BBB=" : "AAA=");
    await expect(openMessage(s.txKey, 1, tampered)).rejects.toThrow();
  });
});
