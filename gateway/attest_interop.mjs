// Interop helper: replica EXACTAMENTE la derivación de clave de
// app/frontend/src/attest/session.ts (WebCrypto) para que el test de Python
// (`test_attest_server.py::test_interop_with_node_client`) verifique que el
// servidor deriva la MISMA clave que un cliente real.
//
// Entrada (argv[2], JSON): { nonce, binaryHash, sessionPubB64, vendor }
// Salida (stdout, JSON):  { clientPubB64, clientKeyHex }

import { webcrypto } from "node:crypto";

const crypto = webcrypto;

async function expectedReportData(nonce, binaryHash) {
  const data = new TextEncoder().encode(nonce + binaryHash);
  const digest = await crypto.subtle.digest("SHA-256", data);
  return [...new Uint8Array(digest)]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

async function main() {
  const inp = JSON.parse(process.argv[2]);

  // 1. Par de claves efímero del cliente.
  const clientPair = await crypto.subtle.generateKey(
    { name: "X25519" },
    true,
    ["deriveKey", "deriveBits"],
  );
  const clientPubRaw = new Uint8Array(
    await crypto.subtle.exportKey("raw", clientPair.publicKey),
  );
  const clientPubB64 = Buffer.from(clientPubRaw).toString("base64");

  // 2. report_data esperado.
  const reportData = await expectedReportData(inp.nonce, inp.binaryHash);

  // 3. Secreto compartido.
  const peerPub = await crypto.subtle.importKey(
    "raw",
    Buffer.from(inp.sessionPubB64, "base64"),
    { name: "X25519" },
    false,
    [],
  );
  const shared = new Uint8Array(
    await crypto.subtle.deriveBits(
      { name: "X25519", public: peerPub },
      clientPair.privateKey,
      256,
    ),
  );

  // 4. Transcript (orden EXACTO de session.ts).
  const transcript = [
    inp.nonce,
    Buffer.from(clientPubRaw).toString("hex"),
    inp.sessionPubB64,
    reportData,
    inp.vendor,
  ].join("|");

  // 5. HKDF-SHA256(ikm = shared || utf8(reportData), salt = transcript).
  const ikm = new Uint8Array(shared.length + reportData.length);
  ikm.set(shared, 0);
  ikm.set(new TextEncoder().encode(reportData), shared.length);
  const base = await crypto.subtle.importKey("raw", ikm, "HKDF", false, ["deriveBits"]);
  const keyRaw = new Uint8Array(
    await crypto.subtle.deriveBits(
      {
        name: "HKDF",
        hash: "SHA-256",
        salt: new TextEncoder().encode(transcript),
        info: new TextEncoder().encode("hermetik/v1"),
      },
      base,
      256, // bits → 32 B, idéntico a deriveKey(..., AES-GCM, length:256)
    ),
  );

  console.log(
    JSON.stringify({
      clientPubB64,
      clientKeyHex: Buffer.from(keyRaw).toString("hex"),
    }),
  );
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
